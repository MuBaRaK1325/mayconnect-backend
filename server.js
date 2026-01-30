require("dotenv").config();
console.log("Maitama token loaded:", !!process.env.MAITAMA_API_TOKEN);
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");
const base64url = require("base64url");
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
  ssl: { rejectUnauthorized: false } // Required for Neon/Render
});

/* ===================== MIDDLEWARE ===================== */
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

  }
};
});

/* ===================== FETCH DATA PLANS ===================== */
app.get("/api/data/plans", (req, res) => {
  try {
    const plans = Object.keys(DATA_PLANS).map(key => ({
      key,
      name: DATA_PLANS[key].name,
      price: DATA_PLANS[key].price,
      network: "MTN",
      category: "SME"
    }));

    res.json({
      status: "success",
      plans
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to load plans" });
  }
});

/* ===================== MAITAMA API ===================== */
const MAITAMA_BASE_URL ="https://app.maitamadatahub.com ";
const MAITAMA_API_TOKEN = process.env.MAITAMA_API_TOKEN;

/* ===================== AUTH ROUTES ===================== */

// SIGN UP
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

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

// FORGOT PASSWORD
app.post("/api/forgot-password", async (req, res) => {
  const { email, new_password } = req.body;
  if (!email || !new_password) return res.status(400).json({ error: "All fields required" });

  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query("UPDATE users SET password=$1 WHERE email=$2", [hash, email]);
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to reset password", details: err.message });
  }
});

// SET PIN
app.post("/api/set-pin", authenticateToken, async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: "PIN required" });

  try {
    const hash = await bcrypt.hash(pin, 10);
    await pool.query("UPDATE users SET pin=$1, pin_attempts=0, locked=false WHERE id=$2", [hash, req.user.id]);
    res.json({ message: "PIN set successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to set PIN", details: err.message });
  }
});

/* ===================== WALLET ROUTES ===================== */
app.get("/api/wallet/transactions", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

app.get("/api/wallet", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
    res.json({ balance: result.rows[0].wallet_balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch balance", details: err.message });
  }
});

/* ===================== WALLET PURCHASE (MAITAMA DATA INTEGRATION) ===================== */
app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, planKey, details, pin } = req.body;

  try {
    /* ===================== VALIDATE PLAN ===================== */
    if (type !== "data") {
      return res.status(400).json({ error: "Invalid purchase type" });
    }

    const plan = DATA_PLANS[planKey];
    if (!plan) {
      return res.status(400).json({ error: "Invalid data plan selected" });
    }

    const amount = plan.price; // ✅ AUTO-CALCULATED HERE

    /* ===================== FETCH USER ===================== */
    const userRes = await pool.query(
      "SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1",
      [req.user.id]
    );
    const user = userRes.rows[0];

    if (user.locked) {
      return res.status(403).json({
        error: "Wallet locked due to multiple incorrect PIN attempts",
      });
    }

    /* ===================== PIN CHECK ===================== */
    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      const attempts = user.pin_attempts + 1;
      const locked = attempts >= 3;

      await pool.query(
        "UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3",
        [attempts, locked, req.user.id]
      );

      return res.status(400).json({ error: "Incorrect PIN" });
    }

    /* ===================== BALANCE CHECK ===================== */
    if (user.wallet_balance < amount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    /* ===================== MAITAMA API CALL ===================== */
    const maitamaRes = await fetch("https://app.maitamadatahub.com/api/data", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.MAITAMA_API_TOKEN}`,
        Accept: "application/json",
      },
      body: JSON.stringify({
        network: plan.network,
        plan_id: plan.plan_id,
        phone: details.phone,
      }),
    });

    const apiResponse = await maitamaRes.json();

    if (!maitamaRes.ok || apiResponse.status !== "success") {
      return res.status(400).json({
        error: apiResponse.api_response || "Maitama purchase failed",
      });
    }

    /* ===================== UPDATE WALLET ===================== */
    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query(
      "UPDATE users SET wallet_balance=$1, pin_attempts=0 WHERE id=$2",
      [newBalance, req.user.id]
    );

    await pool.query(
      `INSERT INTO transactions 
       (user_id, type, amount, description, reference, status, details)
       VALUES ($1,$2,$3,$4,$5,'success',$6)`,
      [
        req.user.id,
        "data",
        amount,
        plan.name,
        reference,
        details,
      ]
    );

    /* ===================== RESPONSE ===================== */
    res.json({
      message: "Purchase successful",
      receipt: {
        reference,
        type: "data",
        plan: plan.name,
        amount,
        status: "success",
        phone: details.phone,
        date: new Date(),
      },
      balance: newBalance,
      apiResponse,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Purchase failed",
      details: err.message,
    });
  }
});


    // Maitama API integration for data
    let apiResponse = null;
    if (type === "data") {
      const maitamaRes = await fetch(MAITAMA_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${MAITAMA_API_TOKEN}`,
          Accept: "application/json",
        },
        body: JSON.stringify(details),
      });

      apiResponse = await maitamaRes.json();

      if (!maitamaRes.ok || apiResponse.status !== "success") {
        return res.status(400).json({ error: apiResponse.api_response || "Maitama purchase failed" });
      }
    }

/* ===================== DATA PLANS (MAITAMA) ===================== */

const DATA_PLANS = {
  MTN_5GB_SME: {
    network: 1,            // Maitama MTN network code
    plan_id: 158,          // ✅ Correct Maitama plan ID
    name: "MTN 5GB SME",
    price: 1500,           // what customer pays (can be 1400–1600)
    cost: 1400             // Maitama cost (profit tracking)
  }
};

    // Deduct wallet & log transaction
    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query("UPDATE users SET wallet_balance=$1, pin_attempts=0 WHERE id=$2", [newBalance, req.user.id]);
    await pool.query(
      "INSERT INTO transactions (user_id,type,amount,description,reference,status,details) VALUES ($1,$2,$3,$4,$5,'success',$6)",
      [req.user.id, type, amount, type === "airtime" ? "Airtime purchase" : "Data purchase", reference, details || null]
    );

    res.json({
      message: "Purchase successful",
      receipt: {
        reference,
        type,
        amount,
        status: "success",
        details,
        date: new Date(),
      },
      balance: newBalance,
      apiResponse, // Maitama response for frontend reference
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Purchase failed", details: err.message });
  }
});

/* ===================== BIOMETRIC ROUTES ===================== */
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

/* ===================== ADMIN ROUTES ===================== */
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC");
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch users", details: err.message });
  }
});

app.post("/api/admin/transactions/reverse", authenticateToken, isAdmin, async (req, res) => {
  const { reference } = req.body;
  if (!reference) return res.status(400).json({ error: "Reference required" });

  try {
    const txRes = await pool.query("SELECT * FROM transactions WHERE reference=$1", [reference]);
    const tx = txRes.rows[0];
    if (!tx) return res.status(404).json({ error: "Transaction not found" });

    await pool.query("UPDATE transactions SET status='reversed' WHERE reference=$1", [reference]);
    await pool.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2", [tx.amount, tx.user_id]);

    res.json({ message: "Transaction reversed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to reverse transaction", details: err.message });
  }
});

/* ===================== WELCOME MESSAGE ===================== */
app.get("/api/welcome", (req, res) => {
  res.json({ message: "Welcome to MAY-Connect Dashboard!" });
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ MAY-Connect backend running on port ${PORT}`));
