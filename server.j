// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // required for Neon
  }
});

app.use(bodyParser.json());

// ========== JWT AUTH MIDDLEWARE ==========
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Token missing" });

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ========== SIGNUP ==========
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users(name, email, password) VALUES($1, $2, $3) RETURNING id, email',
      [name, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '7d' });

    res.json({ message: "Signup successful", token });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { // unique violation
      res.status(400).json({ error: "Email already exists" });
    } else {
      res.status(500).json({ error: "Server error" });
    }
  }
});

// ========== LOGIN ==========
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "All fields required" });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '7d' });
    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ========== WALLET BALANCE ==========
app.get('/api/wallet', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT wallet_balance FROM users WHERE id=$1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });

    res.json({ balance: result.rows[0].wallet_balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ========== FUND WALLET ==========
app.post('/api/wallet/fund', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  if (!amount || isNaN(amount)) return res.status(400).json({ error: "Invalid amount" });

  try {
    // Update wallet balance
    await pool.query(
      'UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2',
      [amount, req.user.id]
    );

    // Insert transaction history
    await pool.query(
      'INSERT INTO transactions(user_id, type, amount, description) VALUES($1, $2, $3, $4)',
      [req.user.id, 'fund', amount, 'Wallet top-up']
    );

    // Return new balance
    const newBalanceResult = await pool.query('SELECT wallet_balance FROM users WHERE id=$1', [req.user.id]);
    res.json({ message: "Wallet funded successfully", new_balance: newBalanceResult.rows[0].wallet_balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ========== TRANSACTION HISTORY ==========
app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, type, amount, description, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ========== START SERVER ==========
app.listen(port, () => {
  console.log(`MayConnect Backend running on port ${port}`);
});

