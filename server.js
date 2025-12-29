require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");
const base64url = require("base64url");
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();

/* ===================== CORS (FIXED & SAFE) ===================== */
app.use(
  cors({
    origin: [
      "https://mayconnect-frontend.onrender.com",
      "http://localhost:3000",
      "http://127.0.0.1:5500",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.options("*", cors());
app.use(express.json());

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ===================== AUTH MIDDLEWARE ===================== */
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

/* ===================== AUTH ===================== */

// SIGN UP
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields required" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING id,email,is_admin",
      [name, email, hash]
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email, is_admin: result.rows[0].is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password, biometric_key } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    if (biometric_key) {
      if (biometric_key !== user.biometric_key)
        return res.status(400).json({ error: "Invalid biometric key" });
    } else {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid)
        return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ===================== BIOMETRIC ===================== */

app.get(
  "/api/auth/biometric-challenge",
  authenticateToken,
  async (req, res) => {
    try {
      const userRes = await pool.query(
        "SELECT biometric_key FROM users WHERE id=$1",
        [req.user.id]
      );

      if (!userRes.rows[0]?.biometric_key)
        return res.status(400).json({ error: "No biometric registered" });

      const options = generateAuthenticationOptions({
        allowCredentials: [
          {
            id: base64url.toBuffer(userRes.rows[0].biometric_key),
            type: "public-key",
          },
        ],
        userVerification: "preferred",
      });

      await pool.query(
        "UPDATE users SET temp_challenge=$1 WHERE id=$2",
        [options.challenge, req.user.id]
      );

      res.json(options);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Biometric challenge failed" });
    }
  }
);

app.post(
  "/api/auth/verify-biometric",
  authenticateToken,
  async (req, res) => {
    try {
      const userRes = await pool.query(
        "SELECT biometric_key,temp_challenge FROM users WHERE id=$1",
        [req.user.id]
      );

      const user = userRes.rows[0];
      if (!user)
        return res.status(400).json({ error: "User not found" });

      const verification = await verifyAuthenticationResponse({
        credential: req.body,
        expectedChallenge: user.temp_challenge,
        expectedOrigin: "https://mayconnect-frontend.onrender.com",
        expectedRPID: "mayconnect-frontend.onrender.com",
        authenticator: {
          credentialID: base64url.toBuffer(user.biometric_key),
          counter: 0,
        },
      });

      if (!verification.verified)
        return res.status(401).json({ error: "Biometric failed" });

      await pool.query(
        "UPDATE users SET temp_challenge=NULL WHERE id=$1",
        [req.user.id]
      );

      res.json({ verified: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Biometric verification failed" });
    }
  }
);

/* ===================== WALLET ===================== */

app.get("/api/wallet", authenticateToken, async (req, res) => {
  const result = await pool.query(
    "SELECT wallet_balance FROM users WHERE id=$1",
    [req.user.id]
  );
  res.json({ balance: result.rows[0].wallet_balance });
});

app.get("/api/wallet/transactions", authenticateToken, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json({ transactions: result.rows });
});

app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, amount, details } = req.body;

  const userRes = await pool.query(
    "SELECT wallet_balance FROM users WHERE id=$1",
    [req.user.id]
  );

  if (userRes.rows[0].wallet_balance < amount)
    return res.status(400).json({ error: "Insufficient balance" });

  const reference = `MC-${uuidv4()}`;
  const newBalance = userRes.rows[0].wallet_balance - amount;

  await pool.query(
    "UPDATE users SET wallet_balance=$1 WHERE id=$2",
    [newBalance, req.user.id]
  );

  await pool.query(
    "INSERT INTO transactions (user_id,type,amount,reference,status,details) VALUES ($1,$2,$3,$4,'success',$5)",
    [req.user.id, type, amount, reference, details || null]
  );

  res.json({
    receipt: { reference, type, amount, status: "success", date: new Date() },
    balance: newBalance,
  });
});

/* ===================== TRANSACTION REVERSAL ===================== */

app.post(
  "/api/wallet/transactions/reverse",
  authenticateToken,
  async (req, res) => {
    const { reference } = req.body;
    if (!reference)
      return res.status(400).json({ error: "Reference required" });

    const txnRes = await pool.query(
      "SELECT * FROM transactions WHERE reference=$1 AND user_id=$2",
      [reference, req.user.id]
    );

    const txn = txnRes.rows[0];
    if (!txn) return res.status(404).json({ error: "Transaction not found" });

    const balRes = await pool.query(
      "SELECT wallet_balance FROM users WHERE id=$1",
      [req.user.id]
    );

    const newBalance = balRes.rows[0].wallet_balance + txn.amount;

    await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE id=$2",
      [newBalance, req.user.id]
    );
    await pool.query(
      "UPDATE transactions SET status='reversed' WHERE reference=$1",
      [reference]
    );

    res.json({ message: "Reversed", balance: newBalance });
  }
);

/* ===================== ADMIN ===================== */

app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC"
  );
  res.json({ users: result.rows });
});

app.get(
  "/api/admin/transactions",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    const result = await pool.query(
      "SELECT * FROM transactions ORDER BY created_at DESC"
    );
    res.json({ transactions: result.rows });
  }
);

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ MAY-Connect backend running on port ${PORT}`)
);
