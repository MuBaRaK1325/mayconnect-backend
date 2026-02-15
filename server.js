require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const cron = require("node-cron");

// -------------------------
// ROUTER
// -------------------------
const router = require("./router"); // must match filename exactly

// -------------------------
// APP INIT
// -------------------------
const app = express();

// -------------------------
// MIDDLEWARES
// -------------------------
app.use(cors());
app.use(express.json()); // parse JSON bodies

// -------------------------
// DATABASE
// -------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
global.pool = pool;

// -------------------------
// HEALTH CHECK
// -------------------------
app.get("/", (req, res) => {
  res.send("🚀 MAY CONNECT BACKEND RUNNING");
});

// -------------------------
// ROUTES
// -------------------------
app.use("/api", router);

// -------------------------
// CRON JOB: CLEAN OLD TRANSACTIONS
// -------------------------
cron.schedule("0 0 * * *", async () => {
  try {
    await pool.query(
      "DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '30 days'"
    );
    console.log("DAILY CLEANUP ✅");
  } catch (err) {
    console.error("Cleanup error:", err);
  }
});

// -------------------------
// START SERVER
// -------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 MAY CONNECT LIVE ${PORT}`));

