require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cron = require("node-cron");
const { Pool } = require("pg");

// -------------------------
// ROUTER
// -------------------------
// Use absolute path so Node always finds router.js
const router = require("./router.js");

const app = express();

// -------------------------
// MIDDLEWARES
// -------------------------
app.use(express.json());
app.use(cors({ origin: "*" }));

// -------------------------
// DATABASE
// -------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Optional: attach pool to global for router.js access
global.pool = pool;

// -------------------------
// HEALTH CHECK
// -------------------------
app.get("/", (req, res) => {
  res.send("MAY CONNECT BACKEND RUNNING 🚀");
});

// -------------------------
// USE ROUTER
// -------------------------
app.use("/api", router);

// -------------------------
// CRON JOBS
// -------------------------
cron.schedule("0 0 * * *", async () => {
  await pool.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '30 days'");
  console.log("DAILY CLEANUP ✅");
});

// -------------------------
// START SERVER
// -------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 MAY CONNECT LIVE ${PORT}`));
