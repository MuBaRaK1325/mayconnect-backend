import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import appRoutes from './app.js';

dotenv.config();
const { Pool } = pg;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT, 10),
});

pool.connect()
  .then(client => { console.log('Connected to PostgreSQL database'); client.release(); })
  .catch(err => { console.error('Database connection error:', err.stack); });

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Make pool available in routes
app.use((req, res, next) => { req.db = pool; next(); });

// Use backend routes
app.use('/', appRoutes);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
