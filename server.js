const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "mayconnect_secret";

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ================= AUTH ================= */

function auth(req, res, next) {

  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];

  try {

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch {

    res.status(401).json({ message: "Invalid token" });

  }
}

/* ================= SIGNUP ================= */

app.post("/api/signup", async (req, res) => {

  try {

    const { username, email, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await pool.query(
      `INSERT INTO users (username,email,password,balance)
       VALUES ($1,$2,$3,0)
       RETURNING id,username`,
      [username, email || null, hash]
    );

    res.json(user.rows[0]);

  } catch (err) {

    console.log(err);
    res.status(500).json({ message: "Signup error" });

  }

});

/* ================= LOGIN WITH USERNAME ================= */

app.post("/api/login", async (req, res) => {

  try {

    const { username, password } = req.body;

    const user = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (!user.rows.length) {
      return res.status(401).json({ message: "Invalid login" });
    }

    const valid = await bcrypt.compare(
      password,
      user.rows[0].password
    );

    if (!valid) {
      return res.status(401).json({ message: "Invalid login" });
    }

    const token = jwt.sign(
      {
        id: user.rows[0].id,
        username: user.rows[0].username
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      name: user.rows[0].username
    });

  } catch {

    res.status(500).json({ message: "Login error" });

  }

});

/* ================= WALLET ================= */

app.get("/api/wallet", auth, async (req, res) => {

  const result = await pool.query(
    "SELECT balance FROM users WHERE id=$1",
    [req.user.id]
  );

  res.json({
    balance: result.rows[0].balance
  });

});

/* ================= PLANS ================= */

app.get("/api/plans", async (req, res) => {

  const plans = await pool.query(
    "SELECT * FROM plans ORDER BY price ASC"
  );

  res.json(plans.rows);

});

/* ================= SET PIN ================= */

app.post("/api/set-pin", auth, async (req, res) => {

  const { pin } = req.body;

  const hash = await bcrypt.hash(pin, 10);

  await pool.query(
    "UPDATE users SET pin=$1 WHERE id=$2",
    [hash, req.user.id]
  );

  res.json({ message: "PIN set successfully" });

});

/* ================= VERIFY PIN ================= */

app.post("/api/verify-pin", auth, async (req, res) => {

  const { pin } = req.body;

  const user = await pool.query(
    "SELECT pin FROM users WHERE id=$1",
    [req.user.id]
  );

  if (!user.rows[0].pin) {
    return res.status(400).json({ message: "No PIN set" });
  }

  const valid = await bcrypt.compare(
    pin,
    user.rows[0].pin
  );

  if (!valid) {
    return res.status(401).json({ message: "Wrong PIN" });
  }

  res.json({ success: true });

});

/* ================= PURCHASE ================= */

app.post("/api/purchase", auth, async (req, res) => {

  const { planId, phone } = req.body;

  const plan = await pool.query(
    "SELECT * FROM plans WHERE id=$1",
    [planId]
  );

  if (!plan.rows.length) {
    return res.status(400).json({ message: "Invalid plan" });
  }

  const price = plan.rows[0].price;

  const user = await pool.query(
    "SELECT balance FROM users WHERE id=$1",
    [req.user.id]
  );

  if (user.rows[0].balance < price) {
    return res.status(400).json({ message: "Insufficient balance" });
  }

  await pool.query(
    "UPDATE users SET balance=balance-$1 WHERE id=$2",
    [price, req.user.id]
  );

  await pool.query(
    `INSERT INTO transactions(user_id,type,amount,phone)
     VALUES($1,'data',$2,$3)`,
    [req.user.id, price, phone]
  );

  res.json({ success: true });

});

/* ================= TRANSACTIONS ================= */

app.get("/api/transactions", auth, async (req, res) => {

  const tx = await pool.query(
    "SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );

  res.json(tx.rows);

});

/* ================= ADMIN WITHDRAW ================= */

app.post("/api/admin/withdraw", auth, async (req, res) => {

  const { amount } = req.body;

  const user = await pool.query(
    "SELECT username FROM users WHERE id=$1",
    [req.user.id]
  );

  if (user.rows[0].username !== "Admin User") {
    return res.status(403).json({ message: "Not admin" });
  }

  await pool.query(
    "UPDATE users SET balance=balance-$1 WHERE id=$2",
    [amount, req.user.id]
  );

  res.json({ message: "Withdrawal successful" });

});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});