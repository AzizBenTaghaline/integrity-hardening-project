const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Joi = require('joi');
const crypto = require('crypto');

const app = express();
app.use(cors({
  origin: 'http://192.168.111.135:8080',
  credentials: true
}));
app.use(helmet());
app.use(express.json());

// Session securisee
app.use(session({
  secret: process.env.SESSION_SECRET || 'SuperSecret_2024!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000
  }
}));

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'appdb',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || 'postgres123'
});function computeChecksum(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}async function auditLog(action, userId, ip, details) {
  try {
    const logData = { action, userId, ip, details, timestamp: new Date().toISOString() };
    const checksum = computeChecksum(logData);
    await pool.query(
      'INSERT INTO audit_logs (action, user_id, ip_address, details, checksum) VALUES ($1, $2, $3, $4, $5)',
      [action, userId, ip, JSON.stringify(details), checksum]
    );
  } catch (err) {
    console.error('AuditLog error:', err.message);
  }
}
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    auditLog('unauthorized_access', null, req.ip, { url: req.originalUrl });
    return res.status(401).json({ error: 'Authentification requise' });
  }
  next();
}function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Authentification requise' });
  }
  if (req.session.user.role !== 'admin') {
    auditLog('forbidden_access', req.session.user.id, req.ip, { url: req.originalUrl });
    return res.status(403).json({ error: 'Acces refuse' });
  }
  next();
}const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: { error: 'Trop de tentatives, reessayez dans 15 minutes' }
});
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(128).required()
});app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: 'hardened' });
});app.post('/api/login', loginLimiter, async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    await auditLog('validation_failed', null, req.ip, { reason: error.details[0].message });
    return res.status(400).json({ error: 'Donnees invalides : ' + error.details[0].message });
  }
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) {
      await auditLog('login_failed', null, req.ip, { username });
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    const user = result.rows[0];
    let passwordOk = false;
   if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      passwordOk = await bcrypt.compare(password, user.password);
    } else {
      passwordOk = (password === user.password);
    }
    if (!passwordOk) {
      await auditLog('login_failed', user.id, req.ip, { username });
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    await auditLog('login_success', user.id, req.ip, { username });
    res.json({ success: true, user: { username: user.username, role: user.role } });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Erreur interne' });
  }
});
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur interne' });
  }
});
app.post('/api/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  return res.status(403).json({ error: 'Modification de role non autorisee' });
});
app.get('/api/search', requireAuth, async (req, res) => {
  const schema = Joi.object({ q: Joi.string().alphanum().max(50).required() });
  const { error } = schema.validate(req.query);
  if (error) {
    return res.status(400).json({ error: 'Parametre invalide' });
  }
  try {
    const result = await pool.query(
      'SELECT id, username, role FROM users WHERE username LIKE $1',
      ['%' + req.query.q + '%']
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur interne' });
  }
});
app.get('/api/admin/logs', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT action, ip_address, LEFT(checksum, 20) AS checksum, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 50'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur interne' });
  }
});app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Backend hardened demarre sur port ' + PORT);
});
