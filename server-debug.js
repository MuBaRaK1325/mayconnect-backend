require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch'); // make sure installed
const base64url = require('base64url');
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();

/* ===================== CORS ===================== */
app.use(cors({
  origin: [
    "https://mayconnect-frontend.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.options("*", cors());
app.use(express.json());

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ===================== AUTH MIDDLEWARE ===================== */
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("JWT verify failed:", err.message);
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
  next();
}

/* ===================== AUTH ROUTES ===================== */

// SIGN UP
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    console.log("Signup failed: missing fields", req.body);
    return res.status(400).json({ error: "All fields required" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING id,email,is_admin",
      [name, email, hash]
    );

    if (!result.rows[0]) {
      console.log("Signup failed: no row returned from DB");
      return res.status(500).json({ error: "Signup failed" });
    }

    const token = jwt.sign(
      { id: result.rows[0].id, email, is_admin: result.rows[0].is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log("Signup success:", result.rows[0]);
    res.json({ token });
  } catch (err) {
    console.error("Signup DB error:", err.message);
    res.status(500).json({ error: "Signup failed", details: err.message });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password, biometric_key } = req.body;
  if (!email || (!password && !biometric_key)) {
    console.log("Login failed: missing credentials", req.body);
    return res.status(400).json({ error: "Email and password or biometric required" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) {
      console.log("Login failed: user not found", email);
      return res.status(400).json({ error: "Invalid credentials" });
    }

    if (biometric_key) {
      if (biometric_key !== user.biometric_key) {
        console.log("Login failed: biometric mismatch for", email);
        return res.status(400).json({ error: "Invalid biometric key" });
      }
    } else {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        console.log("Login failed: password mismatch for", email);
        return res.status(400).json({ error: "Invalid credentials" });
      }
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log("Login success:", email);
    res.json({ token });
  } catch (err) {
    console.error("Login DB error:", err.message);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

/* ===================== WALLET ===================== */
app.get("/api/wallet", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
    res.json({ balance: result.rows[0].wallet_balance });
  } catch (err) {
    console.error("Wallet fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch balance" });
  }
});

app.get("/api/wallet/transactions", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error("Transactions fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, amount, details, pin } = req.body;

  try {
    const userRes = await pool.query("SELECT wallet_balance,pin,pin_attempts,locked FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];

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
      [req.user.id, type, amount, type === "airtime" ? "Airtime purchase" : "Data purchase", reference, details || null]
    );

    res.json({
      message: "Purchase successful",
      receipt: { reference, type, amount, status: "success", details, date: new Date() },
      balance: newBalance
    });
  } catch (err) {
    console.error("Purchase error:", err.message);
    res.status(500).json({ error: "Purchase failed", details: err.message });
  }
});

/* ===================== ADMIN ===================== */
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC");
    res.json({ users: result.rows });
  } catch (err) {
    console.error("Admin fetch users error:", err.message);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get("/api/admin/transactions", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM transactions ORDER BY created_at DESC");
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error("Admin fetch transactions error:", err.message);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
console.log("JWT_SECRET is:", process.env.JWT_SECRET); // debug
app.listen(PORT, () => console.log(`✅ MAY-Connect full debug server running on port ${PORT}`));
