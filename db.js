import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  user: 'u0_a343',        // same as your working testDbConnection.js
  host: 'localhost',
  database: 'mayconnect',
  password: '',            // leave empty if no password
  port: 5432,
});

export default pool;
