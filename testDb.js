require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function testConnection() {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('Database connected! Current time:', res.rows[0].now);
    await pool.end();
  } catch (err) {
    console.error('Database connection failed:', err.message);
  }
}

testConnection();
