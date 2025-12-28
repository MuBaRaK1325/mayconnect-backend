const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const base64url = require('base64url');
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ===== Middleware: Authenticate JWT =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ===== Middleware: Admin Check =====
function isAdmin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ===== USER ENDPOINTS =====
// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING id,email",
      [name, email, hashedPassword]
    );
    res.json({ message: "User registered", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login (supports PIN & optional biometric key)
app.post("/api/login", async (req, res) => {
  const { email, password, biometric_key } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    if (biometric_key) {
      if (biometric_key !== user.biometric_key)
        return res.status(400).json({ error: "Invalid biometric key" });
    } else {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Set Transfer PIN
app.post("/api/wallet/set-pin", authenticateToken, async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: "PIN required" });
  const hashedPin = await bcrypt.hash(pin, 10);

  try {
    await pool.query("UPDATE users SET pin=$1,pin_attempts=0,locked=false WHERE id=$2", [hashedPin, req.user.id]);
    res.json({ message: "PIN set successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to set PIN" });
  }
});
// ===== BIOMETRIC CHALLENGE =====
app.get('/api/auth/biometric-challenge', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query("SELECT id, biometric_key FROM users WHERE id=$1", [req.user.id]);
    if (!userResult.rows[0] || !userResult.rows[0].biometric_key) {
      return res.status(400).json({ error: "No biometric key registered" });
    }

    const challengeOptions = generateAuthenticationOptions({
      allowCredentials: [{
        id: base64url.toBuffer(userResult.rows[0].biometric_key),
        type: 'public-key',
      }],
      userVerification: 'preferred',
    });

    // Save challenge temporarily in memory or DB for verification
    await pool.query("UPDATE users SET temp_challenge=$1 WHERE id=$2", [challengeOptions.challenge, req.user.id]);

    res.json(challengeOptions);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error generating biometric challenge" });
  }
});

// ===== VERIFY BIOMETRIC =====
app.post('/api/auth/verify-biometric', authenticateToken, async (req, res) => {
  const { id, rawId, response, type } = req.body;

  try {
    const userResult = await pool.query(
      "SELECT id, biometric_key, temp_challenge FROM users WHERE id=$1",
      [req.user.id]
    );

    const user = userResult.rows[0];
    if (!user || !user.biometric_key || !user.temp_challenge)
      return res.status(400).json({ error: "No biometric registration found" });

    const verification = await verifyAuthenticationResponse({
      credential: req.body,
      expectedChallenge: user.temp_challenge,
      expectedOrigin: "https://your-frontend-domain.com", // replace with your frontend URL
      expectedRPID: "localhost", // or your domain if deployed
      authenticator: {
        credentialID: base64url.toBuffer(user.biometric_key),
        counter: 0, // store this in DB for increment checks
      },
    });

    if (verification.verified) {
      // Clear temporary challenge
      await pool.query("UPDATE users SET temp_challenge=NULL WHERE id=$1", [user.id]);
      res.json({ verified: true });
    } else {
      res.status(401).json({ verified: false, error: "Biometric verification failed" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error verifying biometric" });
  }
});
// ===== WALLET ENDPOINTS =====
// Get Balance
app.get("/api/wallet", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
    res.json({ balance: result.rows[0].wallet_balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch balance" });
  }
});

// Fund Wallet (internal / payment gateways handled separately)
app.post("/api/wallet/fund", authenticateToken, async (req, res) => {
  const { amount, pin } = req.body;
  if (!amount || !pin) return res.status(400).json({ error: "Amount and PIN required" });

  try {
    const userResult = await pool.query("SELECT pin, pin_attempts, locked, wallet_balance FROM users WHERE id=$1", [req.user.id]);
    const user = userResult.rows[0];

    if (user.locked) return res.status(403).json({ error: "Wallet locked due to multiple incorrect PIN attempts" });

    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      let attempts = user.pin_attempts + 1;
      let locked = attempts >= 3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3", [attempts, locked, req.user.id]);
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    const reference = `MC-${uuidv4()}`;
    const newBalance = parseFloat(user.wallet_balance) + parseFloat(amount);
    await pool.query("UPDATE users SET wallet_balance=$1,pin_attempts=0 WHERE id=$2", [newBalance, req.user.id]);
    await pool.query(
      "INSERT INTO transactions (user_id,type,amount,description,reference,status,details) VALUES ($1,'fund',$2,'Wallet funded',$3,'success',$4)",
      [req.user.id, amount, reference, { method: "wallet" }]
    );

    res.json({ message: "Wallet funded successfully", reference, balance: newBalance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Funding failed" });
  }
});

// Purchase Airtime/Data
app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, amount, details, pin } = req.body;
  if (!type || !amount || !pin) return res.status(400).json({ error: "Type, amount and PIN required" });

  try {
    const userResult = await pool.query("SELECT wallet_balance,pin,pin_attempts,locked FROM users WHERE id=$1", [req.user.id]);
    const user = userResult.rows[0];

    if (user.locked) return res.status(403).json({ error: "Wallet locked due to multiple incorrect PIN attempts" });
    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      let attempts = user.pin_attempts + 1;
      let locked = attempts >= 3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3", [attempts, locked, req.user.id]);
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    if (user.wallet_balance < amount) return res.status(400).json({ error: "Insufficient balance" });

    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query("UPDATE users SET wallet_balance=$1,pin_attempts=0 WHERE id=$2", [newBalance, req.user.id]);
    await pool.query(
      "INSERT INTO transactions (user_id,type,amount,description,reference,status,details) VALUES ($1,$2,$3,$4,$5,'success',$6)",
      [req.user.id, type, amount, type === 'airtime' ? 'Airtime purchase' : 'Data purchase', reference, details || null]
    );

    res.json({
      message: "Purchase successful",
      receipt: { reference, status: "success", type, amount, details, date: new Date() },
      balance: newBalance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Purchase failed" });
  }
});

// ===== TRANSACTION HISTORY =====
app.get("/api/wallet/transactions", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]);
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// ===== TRANSACTION REVERSAL =====
app.post("/api/wallet/transactions/reverse", authenticateToken, async (req, res) => {
  const { reference } = req.body;
  if (!reference) return res.status(400).json({ error: "Reference required" });

  try {
    const txnResult = await pool.query("SELECT * FROM transactions WHERE reference=$1 AND user_id=$2", [reference, req.user.id]);
    const txn = txnResult.rows[0];
    if (!txn) return res.status(404).json({ error: "Transaction not found" });
    if (txn.type === 'fund') return res.status(400).json({ error: "Cannot reverse funding transactions" });

    const newBalance = parseFloat(txn.amount) + parseFloat((await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id])).rows[0].wallet_balance);
    await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, req.user.id]);
    await pool.query("UPDATE transactions SET status='reversed' WHERE reference=$1", [reference]);

    res.json({ message: "Transaction reversed", balance: newBalance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Reversal failed" });
  }
});

// ===== PAYMENT GATEWAYS (Paystack & Flutterwave) =====
// Paste the Paystack and Flutterwave routes we discussed earlier here

// ===== ADMIN DASHBOARD =====
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC");
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get("/api/admin/transactions", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM transactions ORDER BY created_at DESC");
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
