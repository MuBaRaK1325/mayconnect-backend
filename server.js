/*
 MAY Connect Backend – FIXED VERSION
 Permanent CORS Fix + Proper API Routes for Cloudflare Tunnel
*/

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "mayconnect_secret_key";

// ⭐ FIXED CORS — accept localhost + Cloudflare + future domains
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());

// In-memory users (temporary)
const users = [];

// 📱 Available data plans
const plans = [
  { name: "MTN Daily 100MB", price: 100, network: "MTN", type: "Daily" },
  { name: "MTN Daily 200MB", price: 200, network: "MTN", type: "Daily" },
  { name: "MTN Weekly 750MB", price: 500, network: "MTN", type: "Weekly" },
  { name: "MTN Weekly 1.5GB", price: 1000, network: "MTN", type: "Weekly" },
  { name: "MTN Monthly 3GB", price: 1500, network: "MTN", type: "Monthly" },
  { name: "MTN Monthly 6GB", price: 2500, network: "MTN", type: "Monthly" },

  { name: "Airtel Daily 100MB", price: 100, network: "Airtel", type: "Daily" },
  { name: "Airtel Daily 200MB", price: 150, network: "Airtel", type: "Daily" },
  { name: "Airtel Weekly 750MB", price: 500, network: "Airtel", type: "Weekly" },
  { name: "Airtel Monthly 6GB", price: 2500, network: "Airtel", type: "Monthly" },

  { name: "Glo Daily 100MB", price: 100, network: "Glo", type: "Daily" },
  { name: "Glo Daily 500MB", price: 200, network: "Glo", type: "Daily" },
  { name: "Glo Monthly 4.5GB", price: 1500, network: "Glo", type: "Monthly" },

  { name: "9mobile Daily 100MB", price: 100, network: "9mobile", type: "Daily" },
  { name: "9mobile Weekly 750MB", price: 500, network: "9mobile", type: "Weekly" },
  { name: "9mobile Monthly 6GB", price: 2500, network: "9mobile", type: "Monthly" }
];

// =============== API ROUTES ===============

// ✳️ SIGNUP
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "All fields are required." });

  const exists = users.find(u => u.email === email);
  if (exists)
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });

  res.json({ message: "Signup successful" });
});

// ✳️ LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user)
    return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok)
    return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "1h" });

  res.json({ 
    message: "Login successful",
    token 
  });
});

// ✳️ PROTECTED PLANS
app.get("/api/plans", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ error: "Missing token" });

  try {
    const token = auth.split(" ")[1];
    jwt.verify(token, SECRET);
    res.json(plans);
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// =============== START SERVER ===============
app.listen(PORT, () => {
  console.log(`🚀 MAY Connect backend running on port ${PORT}`);
});
