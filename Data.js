// Data.js
import express from "express";
import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();
const router = express.Router();
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ✅ Fetch all available data plans
router.get("/plans", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM data_plans ORDER BY id ASC");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Purchase a data plan
router.post("/buy", async (req, res) => {
  const { user_id, plan_id } = req.body;

  try {
    const plan = await pool.query("SELECT * FROM data_plans WHERE id = $1", [plan_id]);
    if (plan.rows.length === 0) {
      return res.status(404).json({ error: "Data plan not found" });
    }

    const user = await pool.query("SELECT * FROM users WHERE id = $1", [user_id]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const price = plan.rows[0].price;

    // Example: deduct from user's balance
    if (user.rows[0].balance < price) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    await pool.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [price, user_id]);
    await pool.query(
      "INSERT INTO purchases (user_id, plan_id, amount) VALUES ($1, $2, $3)",
      [user_id, plan_id, price]
    );

    res.json({ message: "✅ Data purchase successful!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
