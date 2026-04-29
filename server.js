const express = require("express");
const cors = require("cors");
const http = require("http");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

console.log('ADDED WEBHOOK: 2026-04-28');

app.use(cors({
  origin: ['https://bnhabeeb-frontend.onrender.com'],
  credentials: true
}));

// CRITICAL: Raw body for Paystack, JSON for everything else
app.use((req, res, next) => {
  if (req.originalUrl === "/api/webhook") {
    express.raw({ type: "application/json" })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

app.get('/api/ping', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.send('pong + db ok');
  } catch (err) {
    res.send('pong but db failed');
  }
});

// PAYSTACK WEBHOOK
app.post('/api/webhook', (req, res) => {
  console.log('PAYSTACK WEBHOOK HIT');
  const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                     .update(req.body)
                     .digest('hex');
  
  if (hash !== req.headers['x-paystack-signature']) {
    return res.status(400).send('Invalid signature');
  }
  
  console.log('Webhook verified');
  res.status(200).send('ok');
});

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});