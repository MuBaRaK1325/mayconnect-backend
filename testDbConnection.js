import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  user: 'u0_a343',        // your PostgreSQL username
  host: 'localhost',
  database: 'mayconnect',
  password: '',            // leave empty if no password
  port: 5432,
});

async function testConnection() {
  try {
    const result = await pool.query('SELECT * FROM plans');
    console.log('Database connected! Plans:');
    console.log(result.rows);
  } catch (err) {
    console.error('Database connection failed:', err.message);
  } finally {
    await pool.end();
  }
}

testConnection();
