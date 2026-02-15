const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const router = express.Router();

// -------------------------
// DATABASE POOL
// -------------------------
const pool = global.pool;

// -------------------------
// JWT HELPERS
// -------------------------
function token(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "Missing token" });

  jwt.verify(h.split(" ")[1], process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) return res.status(403).json({ error: "Bad token" });
    req.user = user;
    next();
  });
}

// -------------------------
// DATA PLANS
// -------------------------
const DATA_PLANS = [
  { plan_id: 153, network: "MTN", type: "MAITAMA", price_range: "₦1400-1500", size: "5 GB", duration: "1 month" },
  { plan_id: 415, network: "AIRTEL", type: "GIFTING", price_range: "₦999-1050", size: "3.2 GB", duration: "1 month" },
  { plan_id: 414, network: "MTN", type: "GIFTING", price_range: "₦540-600", size: "2.5 GB", duration: "1 month" },
  { plan_id: 413, network: "MTN", type: "GIFTING", price_range: "₦240-300", size: "1 GB", duration: "1 month" },
  { plan_id: 394, network: "AIRTEL", type: "GIFTING", price_range: "₦600-700", size: "2 GB", duration: "1 month" },
  { plan_id: 329, network: "AIRTEL", type: "SME", price_range: "₦1300-1500", size: "6.5 GB", duration: "1 month" },
  { plan_id: 327, network: "AIRTEL", type: "SME", price_range: "₦650-700", size: "3.2 GB", duration: "1 month" },
  { plan_id: 359, network: "MTN", type: "GIFTING", price_range: "₦408-500", size: "2 GB", duration: "1 month" },
  { plan_id: 335, network: "GLO", type: "SME", price_range: "₦2370-2450", size: "9.8 GB", duration: "1 month" },
  { plan_id: 334, network: "GLO", type: "SME", price_range: "₦600-700", size: "2.5 GB", duration: "1 month" },
  { plan_id: 261, network: "GLO", type: "CORPORATE GIFTING", price_range: "₦445-500", size: "1.024 GB", duration: "1 month" },
  { plan_id: 195, network: "GLO", type: "GIFTING", price_range: "₦969-1050", size: "3.9 GB", duration: "1 month" },
  { plan_id: 194, network: "GLO", type: "GIFTING", price_range: "₦473-500", size: "1.05 GB", duration: "1 month" },
  { plan_id: 52, network: "AIRTEL", type: "Cheap data hub", price_range: "₦1570-1650", size: "5 GB", duration: "7 Days" }
];

router.get("/plans", (req, res) => res.json(DATA_PLANS));

// -------------------------
// ADMIN RESET
// -------------------------
const ADMIN_EMAIL = "abubakarmubarak3456@gmail.com";

router.post("/admin/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;
  if (email !== ADMIN_EMAIL) return res.status(403).json({ error: "Unauthorized" });

  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query("UPDATE users SET password=$1 WHERE email=$2", [hash, email]);
  res.json({ success: true });
});

// -------------------------
// SIGNUP
// -------------------------
router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "Fill all fields" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await pool.query(
      "INSERT INTO users(name,email,password,wallet_balance) VALUES($1,$2,$3,0) RETURNING id",
      [name, email, hash]
    );
    res.json({ token: token(r.rows[0].id), name });
  } catch {
    res.status(400).json({ error: "Email exists" });
  }
});

// -------------------------
// LOGIN
// -------------------------
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query("SELECT id,name,password FROM users WHERE email=$1", [email]);

  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json({ token: token(r.rows[0].id), name: r.rows[0].name });
});

// -------------------------
// WALLET
// -------------------------
router.get("/wallet", auth, async (req, res) => {
  const r = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ balance: r.rows[0]?.wallet_balance || 0 });
});

// -------------------------
// SET PIN
// -------------------------
router.post("/set-pin", auth, async (req, res) => {
  const hash = await bcrypt.hash(req.body.pin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

// -------------------------
// PURCHASE
// -------------------------
router.post("/wallet/purchase", auth, async (req, res) => {
  const { pin, plan } = req.body;
  const u = await pool.query("SELECT wallet_balance,pin FROM users WHERE id=$1", [req.user.id]);

  if (!await bcrypt.compare(pin, u.rows[0].pin)) {
    return res.status(400).json({ error: "Wrong PIN" });
  }

  const p = DATA_PLANS.find(x => x.plan_id == plan);
  if (!p) return res.status(400).json({ error: "Plan missing" });

  const amount = parseInt(p.price_range.split("-")[0].replace(/[₦,]/g, ""));
  if (u.rows[0].wallet_balance < amount) return res.status(400).json({ error: "Insufficient funds" });

  const ref = "MC-" + uuidv4();
  await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [amount, req.user.id]);
  await pool.query("INSERT INTO transactions(user_id,amount,reference) VALUES($1,$2,$3)", [req.user.id, amount, ref]);

  res.json({ receipt: { reference: ref, amount, status: "success" } });
});

// -------------------------
// ANALYTICS
// -------------------------
router.get("/admin/analytics", async (req, res) => {
  const r = await pool.query("SELECT COUNT(*) total FROM transactions");
  res.json(r.rows[0]);
});

module.exports = router;
