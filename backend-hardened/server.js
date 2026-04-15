const express     = require('express');
const { Pool }    = require('pg');
const session     = require('express-session');
const bcrypt      = require('bcrypt');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const Joi         = require('joi');
const cors        = require('cors');
const winston     = require('winston');
const crypto      = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: '/tmp/app.log' })
  ]
});

app.use(helmet());
app.use(cors({
  origin: 'http://192.168.111.135:8080',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'changeme',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600000
  }
}));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Trop de requetes' }
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives de connexion' },
  skipSuccessfulRequests: true
});


const pool = new Pool({
  host:     process.env.DB_HOST     || 'db',
  port:     parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME     || 'appdb',
  user:     process.env.DB_USER     || 'appuser',
  password: process.env.DB_PASS     || 'AppUser_SecureP@ss_2024!',
  max: 10
});

function computeChecksum(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    logger.warn({ event: 'unauthorized_access', path: req.path, ip: req.ip });
    // Logger aussi en base avec user_id = null
    const checksum = computeChecksum({ action: 'UNAUTHORIZED', path: req.path, ip: req.ip, ts: Date.now() });
    pool.query(
      'INSERT INTO audit_logs (user_id, action, target, ip_address, details, checksum) VALUES ($1,$2,$3,$4,$5,$6)',
      [null, 'UNAUTHORIZED_ACCESS', req.path, req.ip, JSON.stringify({ method: req.method }), checksum]
    ).catch(function() {});
    return res.status(401).json({ error: 'Authentification requise' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
    logger.warn({ event: 'privilege_escalation_attempt', user: req.session && req.session.user ? req.session.user.username : 'anonymous', path: req.path, ip: req.ip });
    return res.status(403).json({ error: err.message });
  }
}


const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(128).required()
});

const roleSchema = Joi.object({
  role: Joi.string().valid('user', 'admin').required()
});

const searchSchema = Joi.object({
  q: Joi.string().alphanum().min(1).max(50).required()
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    logger.warn({ event: 'validation_failed', path: '/api/login', ip: req.ip });
    const checksum = computeChecksum({ action: 'SQLI_ATTEMPT', ip: req.ip, ts: Date.now() });
    pool.query(
      'INSERT INTO audit_logs (user_id, action, target, ip_address, details, checksum) VALUES ($1,$2,$3,$4,$5,$6)',
      [null, 'SQLI_ATTEMPT_BLOCKED', '/api/login', req.ip, JSON.stringify({ reason: error.message }), checksum]
    ).catch(function() {});
    return res.status(400).json({ error: 'Donnees invalides' });
  }
  const { username, password } = value;
  try {
    const result = await pool.query(
      'SELECT id, username, role, password FROM users WHERE username = $1 AND active = TRUE',
      [username]
    );   if (result.rows.length === 0) {
      await bcrypt.compare(password, '$2b$12$invalidhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
      logger.info({ event: 'login_failed', username, ip: req.ip, reason: 'user_not_found' });
      return res.status(401).json({ error: 'Identifiants invalides' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logger.info({ event: 'login_failed', username, ip: req.ip, reason: 'wrong_password' });
      await auditLog(user.id, 'LOGIN_FAILED', username, req.ip, {});
      return res.status(401).json({ error: 'Identifiants invalides' });
    }
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    req.session.regenerate(function(err) {
      if (err) return res.status(500).json({ error: 'Erreur interne' });
      req.session.user = { id: user.id, username: user.username, role: user.role };
      logger.info({ event: 'login_success', username, ip: req.ip, role: 
 user.role });
      auditLog(user.id, 'LOGIN_SUCCESS', username, req.ip, {});
      return res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
    });
  } catch (err) {
    logger.error({ event: 'login_error', error: err.message });
    return res.status(500).json({ error: 'Erreur interne' });
  }
});


app.post('/api/logout', requireAuth, (req, res) => {
  const user = req.session.user;
  req.session.destroy(function() {
    logger.info({ event: 'logout', username: user.username, ip: req.ip });
    res.json({ success: true });
  });
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM v_users_safe ORDER BY id');
    await auditLog(req.session.user.id, 'LIST_USERS', null, req.ip, { count: result.rows.length });
    return res.json(result.rows);
  } catch (err) {
    logger.error({ event: 'list_users_error', error: err.message });
    return res.status(500).json({ error: 'Erreur interne' });
  }
});
app.post('/api/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) return res.status(400).json({ error: 'ID invalide' });
  const { error, value } = roleSchema.validate(req.body);
  if (error) return res.status(400).json({ error: 'Role invalide' });
  try {
    await pool.query('UPDATE users SET role = $1 WHERE id = $2', [value.role, userId]);
    logger.info({ event: 'role_changed', by: req.session.user.username, target_id: userId, new_role: value.role, ip: req.ip });
    await auditLog(req.session.user.id, 'ROLE_CHANGE', String(userId), req.ip, { new_role: value.role });
    return res.json({ success: true });
  } catch (err) {
    logger.error({ event: 'role_change_error', error: err.message });
    return res.status(500).json({ error: 'Erreur interne' });
  }
});

app.get('/api/admin/logs', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, user_id, action, target, ip_address, timestamp, checksum FROM audit_logs ORDER BY timestamp DESC LIMIT 100'
    );
    return res.json(result.rows);
  } catch (err) {
    logger.error({ event: 'logs_error', error: err.message });
    return res.status(500).json({ error: 'Erreur interne' });
  }
});

app.get('/api/search', requireAuth, async (req, res) => {
  const { error, value } = searchSchema.validate(req.query);
  if (error) return res.status(400).json({ error: 'Parametre invalide' });
  try {
    const result = await pool.query(
      'SELECT id, username, email, role FROM v_users_safe WHERE username LIKE $1',
      ['%' + value.q + '%']
    );
    return res.json(result.rows);
  } catch (err) {
    logger.error({ event: 'search_error', error: err.message });
    return res.status(500).json({ error: 'Erreur interne' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  return res.json({ user: req.session.user });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: 'hardened' });
});

app.use(function(req, res) {
  res.status(404).json({ error: 'Route introuvable' });
});

app.use(function(err, req, res, next) {
  logger.error({ event: 'unhandled_error', error: err.message });
  res.status(500).json({ error: 'Erreur interne' });
});

app.listen(PORT, '0.0.0.0', function() {
  logger.info({ event: 'server_start', port: PORT, version: 'hardened' });
});
