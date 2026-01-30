require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // single bcrypt import
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

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
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
  next();
}

/* ===================== DATA PLAN ===================== */
const DATA_PLANS = {
  MTN_5GB_SME: {
    network: 1,        // Maitama MTN code
    plan_id: 158,      // Maitama plan ID
    name: "MTN 5GB SME",
    price: 1600,       // what user pays
    cost: 1400,        // what Maitama charges
    profit: 200,
    type: "SME",
    validity: "30 Days"
  }
};

/* ===================== AUTH ROUTES ===================== */

// SIGNUP
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
    res.status(500).json({ error: "Signup failed", details: err.message });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password, biometric_key } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Login failed" });

    if (biometric_key) {
      if (biometric_key !== user.biometric_key)
        return res.status(400).json({ error: "Invalid biometric key" });
    } else {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(400).json({ error: "Login failed" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});
const nodemailer = require("nodemailer"); // Make sure to npm install nodemailer

app.post("/api/forgot-pin", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    // Check if user exists
    const result = await pool.query("SELECT id, name FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    // Generate temporary reset token (expires in 15 min)
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });

    // Save token in DB (optional)
    await pool.query("UPDATE users SET reset_token=$1 WHERE id=$2", [token, user.id]);

    // Send email with reset instructions
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const resetLink = `https://mayconnect-frontend.onrender.com/reset-pin.html?token=${token}`;

    await transporter.sendMail({
      from: `"MAY Connect" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Reset Your Transaction PIN",
      html: `
        <p>Hello ${user.name},</p>
        <p>You requested to reset your transaction PIN. Click the link below to set a new PIN:</p>
        <a href="${resetLink}">Reset PIN</a>
        <p>This link expires in 15 minutes.</p>
      `
    });

    res.json({ success: true, message: "Reset instructions sent to your email" });

  } catch (err) {
    console.error("Forgot PIN error:", err);
    res.status(500).json({ error: "Failed to send reset instructions" });
  }
});

/* ===================== SET PIN ===================== */
app.post("/api/set-pin", authenticateToken, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin))
      return res.status(400).json({ success: false, message: "PIN must be 4 digits" });

    const hashedPin = await bcrypt.hash(pin, 10);

    await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hashedPin, req.user.id]);

    res.json({ success: true, message: "PIN set successfully" });
  } catch (err) {
    console.error("Set PIN error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ===================== WALLET & PURCHASE ===================== */
app.get("/api/wallet", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
    res.json({ balance: result.rows[0].wallet_balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch balance", details: err.message });
  }
});

app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, pin, details } = req.body;

  try {
    const userRes = await pool.query(
      "SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1",
      [req.user.id]
    );
    const user = userRes.rows[0];

    if (user.locked)
      return res.status(403).json({ error: "Wallet locked due to multiple incorrect PIN attempts" });

    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      let attempts = user.pin_attempts + 1;
      let locked = attempts >= 3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3", [attempts, locked, req.user.id]);
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    let amount = 0;
    if (type === "data") {
      amount = DATA_PLANS.MTN_5GB_SME.price;

      // Maitama API call
      const maitamaRes = await fetch("https://app.maitamadatahub.com/api/data", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.MAITAMA_API_TOKEN}`,
          Accept: "application/json"
        },
        body: JSON.stringify({
          mobile_number: details.mobile_number,
          plan: DATA_PLANS.MTN_5GB_SME.plan_id,
          network: DATA_PLANS.MTN_5GB_SME.network
        })
      });

      const apiResponse = await maitamaRes.json();
      if (!maitamaRes.ok || apiResponse.status !== "success") {
        return res.status(400).json({ error: apiResponse.api_response || "Maitama purchase failed" });
      }
    }

    if (user.wallet_balance < amount)
      return res.status(400).json({ error: "Insufficient balance" });

    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query("UPDATE users SET wallet_balance=$1, pin_attempts=0 WHERE id=$2", [newBalance, req.user.id]);
    await pool.query(
      "INSERT INTO transactions (user_id,type,amount,description,reference,status,details) VALUES ($1,$2,$3,$4,$5,'success',$6)",
      [req.user.id, type, amount, "Data purchase", reference, details]
    );

    res.json({
      message: "Purchase successful",
      receipt: { reference, type, amount, status: "success", details, date: new Date() },
      balance: newBalance
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Purchase failed", details: err.message });
  }
});

/* ===================== BIOMETRICS ===================== */
app.get("/api/biometric/challenge", authenticateToken, async (req, res) => {
  try {
    const options = generateAuthenticationOptions({
      userID: String(req.user.id),
      timeout: 60000,
      allowCredentials: [],
    });
    await pool.query("UPDATE users SET temp_challenge=$1 WHERE id=$2", [options.challenge, req.user.id]);
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate challenge", details: err.message });
  }
});

app.post("/api/biometric/verify", authenticateToken, async (req, res) => {
  const { response } = req.body;
  try {
    const userRes = await pool.query("SELECT temp_challenge FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];

    const verification = verifyAuthenticationResponse({
      response,
      expectedChallenge: user.temp_challenge,
      expectedOrigin: req.headers.origin || "http://localhost:3000",
      expectedRPID: req.hostname,
    });

    if (verification.verified) {
      await pool.query("UPDATE users SET biometric_key=$1 WHERE id=$2", [response.id, req.user.id]);
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Biometric verification failed", details: err.message });
  }
});

/* ===================== ADMIN ===================== */
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch users", details: err.message });
  }
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ MAY-Connect backend running on port ${PORT}`));
