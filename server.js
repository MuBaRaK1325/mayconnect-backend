require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const http = require("http");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

/* =========================
DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* =========================
WEBSOCKET SYSTEM
========================= */

const clients = new Map();

wss.on("connection", (ws, req) => {

  const url = new URL(req.url, "http://localhost");
  const token = url.searchParams.get("token");

  if (!token) return ws.close();

  try {

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    clients.set(decoded.id, ws);

    ws.on("close", () => {
      clients.delete(decoded.id);
    });

  } catch {
    ws.close();
  }

});

function sendWalletUpdate(userId, balance) {

  const ws = clients.get(userId);

  if (ws && ws.readyState === WebSocket.OPEN) {

    ws.send(JSON.stringify({
      type: "wallet_update",
      balance
    }));

  }

}

/* =========================
AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {

  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ message: "No token" });

  try {

    const token = header.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();

  } catch {

    res.status(401).json({ message: "Invalid token" });

  }

}

/* =========================
SIGNUP
========================= */

app.post("/api/signup", async (req, res) => {

  try {

    const { username, email, password } = req.body;

    const exists = await pool.query(
      "SELECT id FROM users WHERE username=$1",
      [username]
    );

    if (exists.rows.length)
      return res.status(400).json({ message: "Username already exists" });

    const hash = await bcrypt.hash(password, 10);

    const user = await pool.query(
      `INSERT INTO users(username,email,password)
       VALUES($1,$2,$3)
       RETURNING id,username,is_admin`,
      [username, email, hash]
    );

    const token = jwt.sign(
      user.rows[0],
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: user.rows[0]
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({ message: "Signup failed" });

  }

});

/* =========================
LOGIN
========================= */

app.post("/api/login", async (req, res) => {

  try {

    const { username, password } = req.body;

    const user = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (!user.rows.length)
      return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.rows[0].password);

    if (!valid)
      return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign({

      id: user.rows[0].id,
      username: user.rows[0].username,
      is_admin: user.rows[0].is_admin

    }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      username: user.rows[0].username,
      is_admin: user.rows[0].is_admin
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({ message: "Login failed" });

  }

});

/* =========================
PROFILE
========================= */

app.get("/api/me", auth, async (req, res) => {

  try {

    const user = await pool.query(
      "SELECT id,username,wallet_balance,admin_wallet,is_admin FROM users WHERE id=$1",
      [req.user.id]
    );

    res.json(user.rows[0]);

  } catch {

    res.status(500).json({ message: "Profile failed" });

  }

});

/* =========================
CHANGE PASSWORD
========================= */

app.post("/api/change-password", auth, async (req, res) => {

  const { currentPassword, newPassword } = req.body;

  const user = await pool.query(
    "SELECT password FROM users WHERE id=$1",
    [req.user.id]
  );

  const valid = await bcrypt.compare(currentPassword, user.rows[0].password);

  if (!valid)
    return res.status(400).json({ message: "Current password incorrect" });

  const hash = await bcrypt.hash(newPassword, 10);

  await pool.query(
    "UPDATE users SET password=$1 WHERE id=$2",
    [hash, req.user.id]
  );

  res.json({ message: "Password updated" });

});

/* =========================
PIN SYSTEM
========================= */

app.post("/api/set-pin", auth, async (req, res) => {

  const { pin } = req.body;

  const hash = await bcrypt.hash(pin, 10);

  await pool.query(
    "UPDATE users SET pin=$1 WHERE id=$2",
    [hash, req.user.id]
  );

  res.json({ message: "PIN saved" });

});

/* CHANGE PIN */

app.post("/api/change-pin", auth, async (req, res) => {

  const { currentPin, newPin } = req.body;

  const user = await pool.query(
    "SELECT pin FROM users WHERE id=$1",
    [req.user.id]
  );

  const valid = await bcrypt.compare(currentPin, user.rows[0].pin);

  if (!valid)
    return res.status(400).json({ message: "Wrong current PIN" });

  const hash = await bcrypt.hash(newPin, 10);

  await pool.query(
    "UPDATE users SET pin=$1 WHERE id=$2",
    [hash, req.user.id]
  );

  res.json({ message: "PIN updated" });

});

/* =========================
DATA PLANS
========================= */

app.get("/api/plans", auth, async (req, res) => {

  const { network } = req.query;

  const plans = await pool.query(
    "SELECT * FROM plans WHERE network=$1 ORDER BY price ASC",
    [network]
  );

  res.json(plans.rows);

});

/* =========================
BUY DATA
========================= */

app.post("/api/buy-data", auth, async (req, res) => {

  const client = await pool.connect();

  try {

    const { plan_id, phone, pin } = req.body;

    const userPin = await client.query(
      "SELECT pin,wallet_balance FROM users WHERE id=$1",
      [req.user.id]
    );

    const valid = await bcrypt.compare(pin, userPin.rows[0].pin);

    if (!valid)
      return res.status(400).json({ message: "Invalid PIN" });

    const plan = await client.query(
      "SELECT * FROM plans WHERE id=$1",
      [plan_id]
    );

    if (!plan.rows.length)
      return res.status(400).json({ message: "Plan not found" });

    const price = Number(plan.rows[0].price);
    const cost = Number(plan.rows[0].cost);

    if (userPin.rows[0].wallet_balance < price)
      return res.status(400).json({ message: "Insufficient balance" });

    const profit = price - cost;

    await client.query("BEGIN");

    await client.query(
      "UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
      [price, req.user.id]
    );

    await client.query(
      "UPDATE users SET admin_wallet=admin_wallet+$1 WHERE is_admin=true",
      [profit]
    );

    await client.query(
      `INSERT INTO transactions
       (user_id,type,amount,profit,phone,status)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [req.user.id, "data", price, profit, phone, "SUCCESS"]
    );

    await client.query("COMMIT");

    const balance = userPin.rows[0].wallet_balance - price;

    sendWalletUpdate(req.user.id, balance);

    res.json({ message: "Data purchase successful" });

  } catch (err) {

    await client.query("ROLLBACK");

    console.log(err);

    res.status(500).json({ message: "Transaction failed" });

  } finally {

    client.release();

  }

});

/* =========================
ADMIN USERS LIST
========================= */

app.get("/api/admin/users", auth, async (req, res) => {

  if (!req.user.is_admin)
    return res.status(403).json({ message: "Forbidden" });

  const users = await pool.query(
    "SELECT id,username,email,wallet_balance FROM users ORDER BY id DESC"
  );

  res.json(users.rows);

});

/* SEARCH USER */

app.get("/api/admin/search-user", auth, async (req, res) => {

  if (!req.user.is_admin)
    return res.status(403).json({ message: "Forbidden" });

  const { q } = req.query;

  const users = await pool.query(
    `SELECT id,username,email,wallet_balance
     FROM users
     WHERE username ILIKE $1`,
    [`%${q}%`]
  );

  res.json(users.rows);

});

/* DELETE USER */

app.delete("/api/admin/delete-user/:id", auth, async (req, res) => {

  if (!req.user.is_admin)
    return res.status(403).json({ message: "Forbidden" });

  await pool.query(
    "DELETE FROM users WHERE id=$1",
    [req.params.id]
  );

  res.json({ message: "User deleted" });

});

/* =========================
SERVER
========================= */

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {

  console.log("SERVER RUNNING ON PORT", PORT);

});