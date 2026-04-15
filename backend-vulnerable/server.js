const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const session = require('express-session');

const app = express();
app.use(cors({
  origin: 'http://192.168.111.135:8080',
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'appdb',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || 'postgres123'
});
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: 'vulnerable' });
});
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    console.log('Query:', query);
    const result = await pool.query(query);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.json({ success: true, user: { username: user.username, password: user.password, role: user.role } });
    } else {
      res.status(401).json({ error: 'Identifiants incorrects' });
    }
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, password, role FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/api/users/:id/role', async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  try {
    await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);
    res.json({ success: true, message: 'Role mis a jour' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/search', async (req, res) => {
  const q = req.query.q || '';
  try {
    const query = "SELECT id, username, role FROM users WHERE username LIKE '%" + q + "%'";
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/admin/logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50');
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Backend vulnerable demarre sur port ' + PORT);
});
