require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const { Pool } = require("pg");
const cron = require("node-cron");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

// ================= DATABASE =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= JWT =================
const token = id => jwt.sign({ id }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });

const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "Missing token" });
  jwt.verify(h.split(" ")[1], process.env.JWT_SECRET || "secret", (e, u) => {
    if (e) return res.status(403).json({ error: "Bad token" });
    req.user = u;
    next();
  });
};

// ================= DATA PLANS =================
const DATA_PLANS = [
  { plan_id: 165, network: "MTN", type: "MAITAMA", price: 1400, size: "5 GB", duration: "1 month", profit: 50 },
  { plan_id: 415, network: "AIRTEL", type: "GIFTING", price: 999, size: "3.2 GB", duration: "1 month", profit: 50 },
  { plan_id: 414, network: "MTN", type: "GIFTING", price: 540, size: "2.5 GB", duration: "1 month", profit: 50 },
  { plan_id: 413, network: "MTN", type: "GIFTING", price: 240, size: "1 GB", duration: "1 month", profit: 50 },
  { plan_id: 394, network: "AIRTEL", type: "GIFTING", price: 600, size: "2 GB", duration: "1 month", profit: 50 },
  { plan_id: 329, network: "AIRTEL", type: "SME", price: 1300, size: "6.5 GB", duration: "1 month", profit: 60 },
  { plan_id: 327, network: "AIRTEL", type: "SME", price: 650, size: "3.2 GB", duration: "1 month", profit: 50 },
  { plan_id: 359, network: "MTN", type: "GIFTING", price: 408, size: "2 GB", duration: "1 month", profit: 50 },
  { plan_id: 335, network: "GLO", type: "SME", price: 2370, size: "9.8 GB", duration: "1 month", profit: 100 },
  { plan_id: 334, network: "GLO", type: "SME", price: 600, size: "2.5 GB", duration: "1 month", profit: 50 },
  { plan_id: 261, network: "GLO", type: "CORPORATE GIFTING", price: 445, size: "1.024 GB", duration: "1 month", profit: 50 },
  { plan_id: 195, network: "GLO", type: "GIFTING", price: 969, size: "3.9 GB", duration: "1 month", profit: 60 },
  { plan_id: 194, network: "GLO", type: "GIFTING", price: 473, size: "1.05 GB", duration: "1 month", profit: 50 },
  { plan_id: 52, network: "AIRTEL", type: "Cheap data hub", price: 1570, size: "5 GB", duration: "7 Days", profit: 50 }
];

// ================= PAYSTACK =================
async function sendProfit(amount) {
  if (!amount || amount <= 0) return;
  await axios.post(
    "https://api.paystack.co/transfer",
    { source: "balance", amount: amount * 100, recipient: process.env.PAYSTACK_RECIPIENT },
    { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` } }
  );
}

// ================= ROUTES =================

// Health check
app.get("/", (req, res) => res.send("MAY CONNECT RUNNING 🚀"));

// Plans
app.get("/api/plans", (req, res) => res.json(DATA_PLANS));

// Signup
app.post("/api/signup", async (req, res) => {
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

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password)))
    return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: token(r.rows[0].id), name: r.rows[0].name });
});

// Wallet balance
app.get("/api/wallet", auth, async (req, res) => {
  const r = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ balance: r.rows[0]?.wallet_balance || 0 });
});

// Set PIN
app.post("/api/set-pin", auth, async (req, res) => {
  const hash = await bcrypt.hash(req.body.pin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

// Change PIN
app.post("/api/change-pin", auth, async (req, res) => {
  const { currentPin, newPin } = req.body;
  const u = await pool.query("SELECT pin FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(currentPin, u.rows[0].pin)) return res.status(400).json({ error: "Wrong PIN" });
  const hash = await bcrypt.hash(newPin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

// Change password
app.post("/api/change-password", auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const u = await pool.query("SELECT password FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(currentPassword, u.rows[0].password)) return res.status(400).json({ error: "Wrong password" });
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

// Airtime purchase (min ₦50, no profit)
app.post("/api/airtime", auth, async (req, res) => {
  const { pin, amount, phone } = req.body;
  if (amount < 50) return res.status(400).json({ error: "Minimum airtime is ₦50" });

  const u = await pool.query("SELECT wallet_balance,pin FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(pin, u.rows[0].pin)) return res.status(400).json({ error: "Wrong PIN" });
  if (u.rows[0].wallet_balance < amount) return res.status(400).json({ error: "Low balance" });

  await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [amount, req.user.id]);
  res.json({ success: true });
});

// Purchase data
app.post("/api/purchase", auth, async (req, res) => {
  const { pin, plan } = req.body;
  const u = await pool.query("SELECT wallet_balance,pin FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(pin, u.rows[0].pin)) return res.status(400).json({ error: "Wrong PIN" });

  const p = DATA_PLANS.find(x => x.plan_id == plan);
  if (!p) return res.status(400).json({ error: "Plan missing" });
  if (u.rows[0].wallet_balance < p.price) return res.status(400).json({ error: "Low balance" });

  const ref = "MC-" + uuidv4();
  await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [p.price, req.user.id]);
  await pool.query("INSERT INTO transactions(user_id,amount,reference) VALUES($1,$2,$3)", [req.user.id, p.price, ref]);

  // Send profit to Paystack
  await sendProfit(p.profit);

  res.json({ reference: ref });
});

// ================= CRON =================
cron.schedule("0 0 * * *", async () => {
  await pool.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '30 days'");
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("MAY CONNECT LIVE 🚀", PORT));
