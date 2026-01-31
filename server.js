require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const fetch = require("node-fetch");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

/* ================= DATABASE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

/* ================= AUTH MIDDLEWARE ================= */
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

/* ================= DATA PLANS ================= */
const DATA_PLANS = [
  /* ========= MAITAMA ========= */
  { plan_id: 153, provider: "maitama", network: "MTN", name: "MTN 5GB SME", price: 1500 },

  /* ========= SUBPADI – MTN ========= */
  { plan_id: 414, provider: "subpadi", network: "MTN", name: "2.5GB GIFTING", price: 600 },
  { plan_id: 413, provider: "subpadi", network: "MTN", name: "1GB GIFTING", price: 300 },
  { plan_id: 359, provider: "subpadi", network: "MTN", name: "2GB GIFTING", price: 500 },

  /* ========= SUBPADI – AIRTEL ========= */
  { plan_id: 415, provider: "subpadi", network: "AIRTEL", name: "3.2GB GIFTING", price: 1050 },
  { plan_id: 394, provider: "subpadi", network: "AIRTEL", name: "2GB GIFTING", price: 700 },
  { plan_id: 329, provider: "subpadi", network: "AIRTEL", name: "6.5GB SME", price: 1500 },
  { plan_id: 327, provider: "subpadi", network: "AIRTEL", name: "3.2GB SME", price: 700 },

  /* ========= MAITAMA – AIRTEL ========= */
  { plan_id: 37, provider: "maitama", network: "AIRTEL", name: "1GB", price: 300 },
  { plan_id: 38, provider: "maitama", network: "AIRTEL", name: "2GB", price: 600 },
  { plan_id: 39, provider: "maitama", network: "AIRTEL", name: "3GB", price: 600 },

  /* ========= SUBPADI – GLO ========= */
  { plan_id: 335, provider: "subpadi", network: "GLO", name: "9.8GB SME", price: 2450 },
  { plan_id: 334, provider: "subpadi", network: "GLO", name: "2.5GB SME", price: 700 },
  { plan_id: 261, provider: "subpadi", network: "GLO", name: "1.024GB CORPORATE", price: 500 },
  { plan_id: 195, provider: "subpadi", network: "GLO", name: "3.9GB GIFTING", price: 1050 },
  { plan_id: 194, provider: "subpadi", network: "GLO", name: "1.05GB GIFTING", price: 500 },

  /* ========= CHEAP DATA HUB ========= */
  { plan_id: 52, provider: "cheapdatahub", network: "AIRTEL", name: "5GB", price: 1650 }
];

/* ================= AUTO PIN UNLOCK ================= */
const PIN_LOCK_MINUTES = 15;

setInterval(async () => {
  await pool.query(`
    UPDATE users
    SET locked = false, pin_attempts = 0
    WHERE locked = true AND updated_at < NOW() - INTERVAL '${PIN_LOCK_MINUTES} minutes'
  `);
}, 5 * 60 * 1000);

/* ================= PURCHASE ROUTE ================= */
app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  const { type, pin, details, provider } = req.body;

  try {
    /* 1️⃣ VERIFY USER */
    const userRes = await pool.query(
      "SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1",
      [req.user.id]
    );
    const user = userRes.rows[0];

    if (!user.pin) return res.status(400).json({ error: "PIN not set" });
    if (user.locked) return res.status(403).json({ error: "Wallet locked. Try later." });

    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      const attempts = (user.pin_attempts || 0) + 1;
      const locked = attempts >= 3;
      await pool.query(
        "UPDATE users SET pin_attempts=$1, locked=$2, updated_at=NOW() WHERE id=$3",
        [attempts, locked, req.user.id]
      );
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    /* 2️⃣ FIND PLAN */
    const plan = DATA_PLANS.find(
      p => p.plan_id == details.plan && p.provider === provider
    );
    if (!plan) return res.status(400).json({ error: "Plan not found" });
    if (user.wallet_balance < plan.price)
      return res.status(400).json({ error: "Insufficient balance" });

    /* 3️⃣ PROVIDER ROUTING */
    if (provider === "maitama") {
      const r = await fetch("https://app.maitamadatahub.com/api/data", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.MAITAMA_API_TOKEN}`
        },
        body: JSON.stringify({
          mobile_number: details.mobile_number,
          plan: plan.plan_id
        })
      });
      const j = await r.json();
      if (!r.ok || j.status !== "success") throw new Error("Maitama failed");

    } else if (provider === "subpadi") {
      const r = await fetch("https://api.subpadi.com/data", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.SUBPADI_API_TOKEN}`
        },
        body: JSON.stringify({
          mobile_number: details.mobile_number,
          plan_id: plan.plan_id
        })
      });
      const j = await r.json();
      if (!r.ok || !j.success) throw new Error("Subpadi failed");

    } else if (provider === "cheapdatahub") {
      // Placeholder
    } else {
      return res.status(400).json({ error: "Unknown provider" });
    }

    /* 4️⃣ DEDUCT & LOG */
    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - plan.price;

    await pool.query(
      "UPDATE users SET wallet_balance=$1, pin_attempts=0 WHERE id=$2",
      [newBalance, req.user.id]
    );

    await pool.query(
      `INSERT INTO transactions
       (user_id,type,amount,provider,reference,status,details)
       VALUES ($1,$2,$3,$4,$5,'success',$6)`,
      [
        req.user.id,
        type,
        plan.price,
        provider,
        reference,
        JSON.stringify(details)
      ]
    );

    res.json({
      message: "Purchase successful",
      receipt: { reference, amount: plan.price, status: "success" },
      balance: newBalance
    });

  } catch (err) {
    console.error("Purchase error:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
