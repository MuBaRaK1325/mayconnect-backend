/* =================================================
   MAY-CONNECT — FULL SERVER.JS (MAITAMA + SUBPADI + GLO)
================================================== */

require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const fetch = require("node-fetch");
const { v4: uuidv4 } = require("uuid");
const pool = require("./db"); // your PostgreSQL pool
const cron = require("node-cron");
const app = express();

app.use(express.json());

/* ================= AUTH MIDDLEWARE ================= */
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  // You should implement JWT verification here
  // Example: req.user = jwt.verify(token, process.env.JWT_SECRET)
  req.user = { id: 1 }; // placeholder for demo
  next();
}

/* ================= DATA PLANS ================= */
const DATA_PLANS = [
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

/* ================= HELPERS ================= */
async function retryOnce(fn, delayMs = 1500) {
  try {
    return await fn();
  } catch (err) {
    console.warn("⚠️ Retry once:", err.message);
    await new Promise(r => setTimeout(r, delayMs));
    return await fn();
  }
}

async function autoUnlockIfExpired(userId) {
  const res = await pool.query(
    "SELECT locked, locked_at FROM users WHERE id=$1",
    [userId]
  );
  const user = res.rows[0];
  if (!user.locked || !user.locked_at) return;

  const diff = Date.now() - new Date(user.locked_at).getTime();
  if (diff > 10 * 60 * 1000) {
    await pool.query(
      "UPDATE users SET locked=false, pin_attempts=0, locked_at=NULL WHERE id=$1",
      [userId]
    );
  }
}

/* ================= PURCHASE ENDPOINT ================= */
app.post("/api/wallet/purchase", authenticateToken, async (req, res) => {
  let { type, pin, details, provider } = req.body;

  try {
    await autoUnlockIfExpired(req.user.id);

    const userRes = await pool.query(
      "SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1",
      [req.user.id]
    );
    const user = userRes.rows[0];

    if (!user.pin) return res.status(400).json({ error: "PIN not set" });
    if (user.locked) return res.status(403).json({ error: "Wallet locked" });

    const validPin = await bcrypt.compare(pin, user.pin);
    if (!validPin) {
      const attempts = (user.pin_attempts || 0) + 1;
      const locked = attempts >= 3;
      await pool.query(
        "UPDATE users SET pin_attempts=$1, locked=$2, locked_at=NOW() WHERE id=$3",
        [attempts, locked, req.user.id]
      );
      return res.status(400).json({ error: "Incorrect PIN" });
    }

    let plan = DATA_PLANS.find(p => p.plan_id == details.plan && p.provider === provider);
    if (!plan) return res.status(400).json({ error: "Plan not found" });
    if (user.wallet_balance < plan.price)
      return res.status(400).json({ error: "Insufficient balance" });

    const reference = `MC-${uuidv4()}`;

    await pool.query(
      `INSERT INTO transactions (user_id,type,amount,reference,status,details)
       VALUES ($1,$2,$3,$4,'pending',$5)`,
      [req.user.id, type, plan.price, reference, JSON.stringify({ ...details, provider })]
    );

    /* ===== PROVIDER CALL + FALLBACK + RETRY ===== */
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
          plan = fallback;
        } else throw new Error("Maitama & fallback failed");
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

    // Deduct balance and mark transaction success
    await pool.query(
      "UPDATE users SET wallet_balance=wallet_balance-$1, pin_attempts=0 WHERE id=$2",
      [plan.price, req.user.id]
    );

    await pool.query(
      "UPDATE transactions SET status='success' WHERE reference=$1",
      [reference]
    );

    res.json({ message: "Purchase successful", receipt: { reference, amount: plan.price, status: "success" } });

  } catch (err) {
    console.error("❌ Purchase error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ================= PROVIDER ANALYTICS ================= */
app.get("/api/admin/provider-analytics", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT provider, COUNT(*) as total, SUM(amount) as revenue
       FROM transactions WHERE status='success'
       GROUP BY provider`
    );
    res.json({ analytics: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* ================= PENDING RECONCILIATION JOB ================= */
async function reconcilePendingTransactions() {
  try {
    const pendingRes = await pool.query("SELECT * FROM transactions WHERE status='pending'");
    for (const tx of pendingRes.rows) {
      const details = JSON.parse(tx.details);
      const plan = DATA_PLANS.find(p => p.plan_id == details.plan && p.provider === details.provider);
      if (!plan) continue;

      try {
        let providerOk = false;
        if (details.provider === "maitama") {
          const resp = await fetch("https://app.maitamadatahub.com/api/data/status", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.MAITAMA_API_TOKEN}` },
            body: JSON.stringify({ reference: tx.reference })
          });
          const data = await resp.json();
          providerOk = data.status === "success";
        } else if (details.provider === "subpadi") {
          const resp = await fetch("https://api.subpadi.com/data/status", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.SUBPADI_API_TOKEN}` },
            body: JSON.stringify({ reference: tx.reference })
          });
          const data = await resp.json();
          providerOk = data.success === true;
        }

        if (providerOk) {
          await pool.query("UPDATE transactions SET status='success' WHERE id=$1", [tx.id]);
          await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [plan.price, tx.user_id]);
        }
      } catch (err) {
        console.warn("⚠️ Pending reconciliation failed for tx:", tx.reference, err.message);
      }
    }
    console.log("✅ Pending transactions reconciliation complete");
  } catch (err) {
    console.error("❌ Reconciliation job failed:", err.message);
  }
}

cron.schedule("*/5 * * * *", () => {
  console.log("🔄 Running pending transactions reconciliation...");
  reconcilePendingTransactions();
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
