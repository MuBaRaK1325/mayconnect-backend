const express = require("express");
const cors = require("cors");
const http = require("http");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const buyDataLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

console.log('SAFE BUILD: 2026-04-28');

app.use(cors());
app.use(express.json());

app.get('/api/ping', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.send('pong + db ok');
  } catch (err) {
    res.send('pong but db failed');
  }
});

app.get('/api/health', (req, res) => {
  res.send('ok');
});

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});