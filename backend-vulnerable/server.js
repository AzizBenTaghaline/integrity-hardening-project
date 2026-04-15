
const express = require('express');

const { Pool } = require('pg');

const session  = require('express-session');

const cors     = require('cors');



const app = express();



app.use(cors({ origin: '*', credentials: true }));

app.use(express.json());

app.use(express.urlencoded({ extended: true }));



app.use(session({

  secret: process.env.SESSION_SECRET || 'secret123',

  resave: false,

  saveUninitialized: true,

  cookie: { httpOnly: false, secure: false, maxAge: 86400000 }

}));



const pool = new Pool({

  host:     process.env.DB_HOST || 'db',

  port:     process.env.DB_PORT || 5432,

  database: process.env.DB_NAME || 'appdb',

  user:     process.env.DB_USER || 'postgres',

  password: process.env.DB_PASS || 'postgres123'

});



app.post('/api/login', async (req, res) => {

  const { username, password } = req.body;

  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  try {
    const result = await pool.query(query);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.json({ success: true, user });
    }
    return res.status(401).json({ success: false, message: 'Identifiants invalides' });
  } catch (err) {
    return res.status(500).json({ error: err.message, query: query });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id/role', async (req, res) => {
  const { id }   = req.params;
  const { role } = req.body;
  const query = "UPDATE users SET role = '" + role + "' WHERE id = " + id;
  try {
    await pool.query(query);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC');
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/search', async (req, res) => {
  const { q } = req.query;
  const query = "SELECT id, username, email, role FROM users WHERE username LIKE '%" + q + "%'";
  try {
    const result = await pool.query(query);
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', version: 'vulnerable' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('[VULNERABLE] Backend demarre port ' + PORT);
});
