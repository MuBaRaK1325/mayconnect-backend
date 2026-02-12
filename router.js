const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const router = express.Router();

// Access shared pool
function getPool(req) {
  return req.app.locals.pool;
}

// JWT helper
function token(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "Missing token" });

  jwt.verify(h.split(" ")[1], process.env.JWT_SECRET || "secret", (e, u) => {
    if (e) return res.status(403).json({ error: "Bad token" });
    req.user = u;
    next();
  });
}

/* ================= DATA PLANS ================= */
const DATA_PLANS = [
  { plan_id: 153, network: "MTN", type: "MAITAMA", price_range: "₦1400-1500", size: "5GB", duration: "1 month" },
  { plan_id: 415, network: "AIRTEL", type: "GIFTING", price_range: "₦999-1050", size: "3.2 GB", duration: "1 month" },
  { plan_id: 414, network: "MTN", type: "GIFTING", price_range: "₦540-600", size: "2.5 GB", duration: "1 month" },
  { plan_id: 413, network: "MTN", type: "GIFTING", price_range: "₦240-300", size: "1.0 GB", duration: "1 month" },
  { plan_id: 394, network: "AIRTEL", type: "GIFTING", price_range: "₦600-700", size: "2.0 GB", duration: "1 month" },
  { plan_id: 329, network: "AIRTEL", type: "SME", price_range: "₦1300-1500", size: "6.5 GB", duration: "1 month" },
  { plan_id: 327, network: "AIRTEL", type: "SME", price_range: "₦650-700", size: "3.2 GB", duration: "1 month" },
  { plan_id: 359, network: "MTN", type: "GIFTING", price_range: "₦408-500", size: "2.0 GB", duration: "1 month" },
  { plan_id: 335, network: "GLO", type: "SME", price_range: "₦2370-2450", size: "9.8 GB", duration: "1 month" },
  { plan_id: 334, network: "GLO", type: "SME", price_range: "₦600-700", size: "2.5 GB", duration: "1 month" },
  { plan_id: 261, network: "GLO", type: "CORPORATE GIFTING", price_range: "₦445-500", size: "1.024 GB", duration: "1 month" },
  { plan_id: 195, network: "GLO", type: "GIFTING", price_range: "₦969-1050", size: "3.9 GB", duration: "1 month" },
  { plan_id: 194, network: "GLO", type: "GIFTING", price_range: "₦473-500", size: "1.05 GB", duration: "1 month" },
  { plan_id: 52, network: "AIRTEL", type: "Cheap data hub", price_range: "₦1570-1650", size: "5 GB", duration: "7 Days" }
];

// Get plans
router.get("/plans", (req, res) => res.json(DATA_PLANS));

/* ================= EXPORT ROUTER ================= */
module.exports = router;
