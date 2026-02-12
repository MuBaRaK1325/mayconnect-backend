// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cron = require("node-cron");
const { Pool } = require("pg");
const path = require("path");

// -------------------------
// CONFIG
// -------------------------
const ADMIN_EMAIL = "abubakarmubarak3456@gmail.com";

// -------------------------
// DATABASE POOL
// -------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Export pool so router.js can use it
module.exports.pool = pool;

// -------------------------
// EXPRESS SETUP
// -------------------------
const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

// -------------------------
// AUTO CREATE TABLES & ADMIN
// -------------------------
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      wallet_balance INT DEFAULT 0,
      pin TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions(
      id SERIAL PRIMARY KEY,
      user_id INT,
      amount INT,
      reference TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const hash = await bcrypt.hash("admin123", 10);

  await pool.query(
    `INSERT INTO users(name,email,password,wallet_balance)
     VALUES('ADMIN',$1,$2,0)
     ON CONFLICT(email) DO NOTHING`,
    [ADMIN_EMAIL, hash]
  );

  console.log("ADMIN READY");
})();

// -------------------------
// ROUTER (API)
// -------------------------
const router = require("./router");
app.use("/api", router);

// -------------------------
// HEALTH CHECK
// -------------------------
app.get("/", (req, res) => {
  res.send("MAY CONNECT BACKEND RUNNING 🚀");
});

// -------------------------
// CRON JOBS
// -------------------------
cron.schedule("0 0 * * *", async () => {
  await pool.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '30 days'");
  console.log("DAILY CLEANUP");
});

// -------------------------
// START SERVER
// -------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("🚀 MAY CONNECT LIVE", PORT));
