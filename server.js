require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());
app.use(cors());

// ================= DATABASE =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= JWT =================
function createToken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  jwt.verify(header.split(" ")[1], process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) return res.status(403).json({ error: "Bad token" });
    req.user = user;
    next();
  });
}

// ================= AUTH ROUTES =================
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const user = await pool.query(
      "INSERT INTO users(name,email,password,wallet_balance,admin_wallet,is_admin) VALUES($1,$2,$3,0,0,false) RETURNING id",
      [name, email, hash]
    );
    res.json({ token: createToken(user.rows[0].id), name });
  } catch {
    res.status(400).json({ error: "Email exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!user.rows.length) return res.status(401).json({ error: "Invalid login" });

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(401).json({ error: "Invalid login" });

  res.json({ token: createToken(user.rows[0].id), name: user.rows[0].name });
});

// ================= WALLET =================
app.get("/api/wallet", auth, async (req, res) => {
  const result = await pool.query("SELECT wallet_balance, admin_wallet FROM users WHERE id=$1", [req.user.id]);
  res.json(result.rows[0]);
});

// ================= PLANS =================
app.get("/api/plans", async (req, res) => {
  const plans = await pool.query("SELECT * FROM plans");
  res.json(plans.rows);
});

// ================= PURCHASE =================
app.post("/api/purchase", auth, async (req, res) => {
  const { plan } = req.body;
  const planData = await pool.query("SELECT * FROM plans WHERE plan_id=$1", [plan]);
  if (!planData.rows.length) return res.status(400).json({ error: "Invalid plan" });

  const planInfo = planData.rows[0];
  const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];

  const charge = user.is_admin ? planInfo.cost : planInfo.price;
  const profit = user.is_admin ? 0 : planInfo.price - planInfo.cost;
  const reference = "MC-" + uuidv4();

  if (user.wallet_balance < charge) return res.status(400).json({ error: "Low balance" });

  try {
    await pool.query("BEGIN");

    // Deduct from user wallet
    await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [charge, user.id]);

    // Credit profit to admin wallet
    if (!user.is_admin) {
      await pool.query("UPDATE users SET admin_wallet=admin_wallet+$1 WHERE is_admin=true", [profit]);
    }

    // Record transaction
    await pool.query(
      "INSERT INTO transactions(user_id,type,amount,profit,reference,details) VALUES($1,$2,$3,$4,$5,$6)",
      [user.id, "data", charge, profit, reference, JSON.stringify({ plan_id: planInfo.plan_id, network: planInfo.network })]
    );

    await pool.query("COMMIT");

    res.json({ success: true, reference, profit });
  } catch (err) {
    await pool.query("ROLLBACK");
    res.status(500).json({ error: "Transaction failed" });
  }
});

// ================= AIRTIME =================
app.post("/api/airtime", auth, async (req, res) => {
  const { amount } = req.body;
  if (amount < 50) return res.status(400).json({ error: "Minimum ₦50" });

  const userRes = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];
  if (user.wallet_balance < amount) return res.status(400).json({ error: "Low balance" });

  await pool.query("UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2", [amount, req.user.id]);
  await pool.query("INSERT INTO transactions(user_id,type,amount) VALUES($1,$2,$3)", [req.user.id, "airtime", amount]);

  res.json({ success: true });
});

// ================= PIN & PASSWORD =================
app.post("/api/set-pin", auth, async (req, res) => {
  const { pin } = req.body;
  const hash = await bcrypt.hash(pin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

app.post("/api/verify-pin", auth, async (req, res) => {
  const { pin } = req.body;
  const userRes = await pool.query("SELECT pin FROM users WHERE id=$1", [req.user.id]);
  const valid = await bcrypt.compare(pin, userRes.rows[0].pin);
  if (!valid) return res.status(401).json({ error: "Wrong PIN" });
  res.json({ success: true });
});

app.post("/api/change-password", auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userRes = await pool.query("SELECT password FROM users WHERE id=$1", [req.user.id]);
  const valid = await bcrypt.compare(currentPassword, userRes.rows[0].password);
  if (!valid) return res.status(400).json({ error: "Wrong password" });

  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.user.id]);
  res.json({ success: true });
});

// ================= ADMIN DASHBOARD =================
app.get("/api/admin/stats", auth, async (req, res) => {
  const adminRes = await pool.query("SELECT is_admin, admin_wallet FROM users WHERE id=$1", [req.user.id]);
  const admin = adminRes.rows[0];
  if (!admin.is_admin) return res.status(403).json({ error: "Forbidden" });

  const profitRes = await pool.query("SELECT SUM(profit) as total_profit FROM transactions");
  res.json({ total_profit: profitRes.rows[0].total_profit || 0, admin_wallet: admin.admin_wallet });
});

app.post("/api/admin/withdraw", auth, async (req, res) => {
  const adminRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const admin = adminRes.rows[0];
  if (!admin.is_admin) return res.status(403).json({ error: "Forbidden" });

  const amount = admin.admin_wallet;
  if (amount <= 0) return res.json({ message: "No profit to withdraw" });

  // Paystack transfer (replace with real recipient)
  await axios.post(
    "https://api.paystack.co/transfer",
    { source: "balance", amount: amount * 100, recipient: process.env.PAYSTACK_RECIPIENT },
    { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` } }
  );

  await pool.query("UPDATE users SET admin_wallet=0 WHERE id=$1", [req.user.id]);
  res.json({ success: true, withdrawn: amount });
});

// ================= PAYSTACK WEBHOOK =================
app.post("/api/paystack/webhook", async (req, res) => {
  const event = req.body;
  if (event.event === "charge.success") {
    const email = event.data.customer.email;
    const amount = event.data.amount / 100;
    await pool.query("UPDATE users SET wallet_balance=wallet_balance+$1 WHERE email=$2", [amount, email]);
  }
  res.sendStatus(200);
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));