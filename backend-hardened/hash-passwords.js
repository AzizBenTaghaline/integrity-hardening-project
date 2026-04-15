const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const pool = new Pool({
  host: 'db',
  port: 5432,
  database: 'appdb',
  user: 'postgres',
  password: 'RootDB_SecureP@ss_2024!'
});

const users = [
  { id: 1, password: 'admin123' },
  { id: 2, password: 'password' },
  { id: 3, password: '123456'   },
  { id: 4, password: 'charlie'  }
];

async function run() {
  for (const u of users) {
    const hash = await bcrypt.hash(u.password, 12);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, u.id]);
    console.log('Hash applique pour user id=' + u.id);
  }
  console.log('Tous les mots de passe sont haches avec bcrypt');
  await pool.end();
}

run().catch(console.error);
