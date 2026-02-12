
// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cron = require("node-cron");
const { Pool } = require("pg");
const path = require("path");

// -------------------------
// IMPORT ROUTER
// -------------------------
const router = require("./router"); // ensure router.js is in the same folder

const app = express();

/* ================= CONFIG ================= */
const ADMIN_EMAIL = "abubakarmubarak3456@gmail.com";

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(cors({ origin: "*" }));

/* ================= DATABASE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://user:password@localhost:5432/dbname",
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// Make pool accessible to router.js if needed
app.locals.pool = pool;

// Test DB connection
pool.connect((err, client, release) => {
  if (err) console.error("Database connection error:", err.stack);
  else {
    console.log("Database connected successfully");
    release();
  }
});

/* ================= AUTO CREATE TABLES ================= */
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
  await pool.query(`
    INSERT INTO users(name,email,password,wallet_balance)
    VALUES('ADMIN',$1,$2,0)
    ON CONFLICT(email) DO NOTHING
  `, [ADMIN_EMAIL, hash]);

  console.log("ADMIN READY");
})();

/* ================= USE ROUTER ================= */
app.use("/api", router);

/* ================= CRON JOB ================= */
cron.schedule("0 0 * * *", async () => {
  await pool.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '30 days'");
  console.log("DAILY CLEANUP DONE");
});

/* ================= HEALTH CHECK ================= */
app.get("/", (req, res) => {
  res.send("MAY CONNECT BACKEND RUNNING 🚀");
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 MAY CONNECT LIVE ${PORT}`));
