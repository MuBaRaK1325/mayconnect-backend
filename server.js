/* =================================================
   MAY-CONNECT — FULL SERVER.JS (STABLE)
================================================== */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch'); // v2
const { v4: uuidv4 } = require('uuid');
const cron = require('node-cron');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/* ================= HELPERS ================= */
async function retryOnce(fn, delayMs = 1500) {
  try {
    return await fn();
  } catch (err) {
    console.warn("⚠️ Retry once after failure:", err.message);
    await new Promise(r => setTimeout(r, delayMs));
    return await fn();
  }
}

async function autoUnlockIfExpired(userId, minutes = 10) {
  const res = await pool.query(`SELECT locked, locked_at FROM users WHERE id=$1`, [userId]);
  const user = res.rows[0];
  if (!user.locked || !user.locked_at) return;

  const diff = Date.now() - new Date(user.locked_at).getTime();
  if (diff > minutes * 60 * 1000) {
    await pool.query("UPDATE users SET locked=false, pin_attempts=0, locked_at=NULL WHERE id=$1", [userId]);
    console.log(`🔓 User ${userId} automatically unlocked`);
  }
}

/* ================= DATA PLANS ================= */
const DATA_PLANS = [
  /* MAITAMA */
  { plan_id: 153, provider: "maitama", network: "MTN", name: "MTN 5GB SME", price: 1500 },

  /* SUBPADI – MTN */
  { plan_id: 414, provider: "subpadi", network: "MTN", name: "2.5GB GIFTING", price: 600 },
  { plan_id: 413, provider: "subpadi", network: "MTN", name: "1GB GIFTING", price: 300 },
  { plan_id: 359, provider: "subpadi", network: "MTN", name: "2GB GIFTING", price: 500 },

  /* SUBPADI – AIRTEL */
  { plan_id: 415, provider: "subpadi", network: "AIRTEL", name: "3.2GB GIFTING", price: 1050 },
  { plan_id: 394, provider: "subpadi", network: "AIRTEL", name: "2GB GIFTING", price: 700 },
  { plan_id: 329, provider: "subpadi", network: "AIRTEL", name: "6.5GB SME", price: 1500 },
  { plan_id: 327, provider: "subpadi", network: "AIRTEL", name: "3.2GB SME", price: 700 },

  /* MAITAMA – AIRTEL */
  { plan_id: 37, provider: "maitama", network: "AIRTEL", name: "1GB", price: 300 },
  { plan_id: 38, provider: "maitama", network: "AIRTEL", name: "2GB", price: 600 },
  { plan_id: 39, provider: "maitama", network: "AIRTEL", name: "3GB", price: 600 },

  /* SUBPADI – GLO */
  { plan_id: 335, provider: "subpadi", network: "GLO", name: "9.8GB SME", price: 2450 },
  { plan_id: 334, provider: "subpadi", network: "GLO", name: "2.5GB SME", price: 700 },
  { plan_id: 261, provider: "subpadi", network: "GLO", name: "1.024GB CORPORATE", price: 500 },
  { plan_id: 195, provider: "subpadi", network: "GLO", name: "3.9GB GIFTING", price: 1050 },
  { plan_id: 194, provider: "subpadi", network: "GLO", name: "1.05GB GIFTING", price: 500 },

  /* CHEAP DATA HUB */
  { plan_id: 52, provider: "cheapdatahub", network: "AIRTEL", name: "5GB", price: 1650 }
];

/* ================= AUTH MIDDLEWARE ================= */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.sendStatus(401);
  const token = authHeader.split(' ')[1];
  // For demo: simple token check
  req.user = { id: token }; // replace with JWT verification in production
  next();
}

/* ================= WALLET PURCHASE ================= */
app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  let { type, pin, details, provider } = req.body;
  try {
    await autoUnlockIfExpired(req.user.id);

    const userRes = await pool.query("SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];

    if (!user.pin) return res.status(400).json({ error: "PIN not set" });
    if (user.locked) return res.status(403).json({ error: "Wallet locked" });

    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      const attempts = (user.pin_attempts || 0) + 1;
      const locked = attempts >= 3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2, locked_at=NOW() WHERE id=$3", [attempts, locked, req.user.id]);
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    const plan = DATA_PLANS.find(p => p.plan_id == details.plan && p.provider === provider);
    if (!plan) return res.status(400).json({ error: "Plan not found" });
    if (user.wallet_balance < plan.price) return res.status(400).json({ error: "Insufficient balance" });

    const reference = `MC-${uuidv4()}`;

    await pool.query(
      "INSERT INTO transactions (user_id,type,amount,reference,status,details) VALUES ($1,$2,$3,$4,'pending',$5)",
      [req.user.id, type, plan.price, reference, JSON.stringify({ ...details, provider })]
    );

    // PROVIDER CALL + FALLBACK
    let success = false;

    if (provider === "maitama") {
      try {
        await retryOnce(async () => {
          const r = await fetch("https://app.maitamadatahub.com/api/data", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.MAITAMA_API_TOKEN}` },
            body: JSON.stringify({ mobile_number: details.mobile_number, plan: plan.plan_id })
          });
          const j = await r.json();
          if (!r.ok || j.status !== "success") throw new Error("Maitama failed");
        });
        success = true;
      } catch {
        const fallback = DATA_PLANS.find(p => p.network === plan.network && p.provider === "subpadi");
        if (fallback) {
          provider = "subpadi";
          plan.plan_id = fallback.plan_id;
        } else {
          throw new Error("Maitama & fallback failed");
        }
      }
    }

    if (!success && provider === "subpadi") {
      await retryOnce(async () => {
        const r = await fetch("https://api.subpadi.com/data", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.SUBPADI_API_TOKEN}` },
          body: JSON.stringify({ mobile_number: details.mobile_number, plan_id: plan.plan_id })
        });
        const j = await r.json();
        if (!r.ok || !j.success) throw new Error("Subpadi failed");
      });
    }

    // FINALIZE TRANSACTION
    await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1, pin_attempts=0 WHERE id=$2", [plan.price, req.user.id]);
    await pool.query("UPDATE transactions SET status='success' WHERE reference=$1", [reference]);

    res.json({ message: "Purchase successful", receipt: { reference, amount: plan.price, status: "success" } });

  } catch (err) {
    console.error("❌ Purchase error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ================= ADMIN ANALYTICS ================= */
app.get("/api/admin/analytics", async (req, res) => {
  try {
    const txs = await pool.query("SELECT provider, COUNT(*) AS count, SUM(amount) AS total FROM transactions GROUP BY provider");
    res.json({ providerStats: txs.rows });
  } catch (err) {
    console.error("Analytics error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ================= BACKGROUND CRON JOB ================= */
// Reconcile pending → success every 2 minutes
cron.schedule("*/2 * * * *", async () => {
  try {
    const pendingTxs = await pool.query("SELECT * FROM transactions WHERE status='pending'");
    for (let tx of pendingTxs.rows) {
      console.log(`🔁 Reconciling TX ${tx.reference}`);
      // Here you can retry provider call or mark failed
      await pool.query("UPDATE transactions SET status='success' WHERE reference=$1", [tx.reference]);
    }
  } catch (err) {
    console.error("Cron reconciliation error:", err.message);
  }
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
