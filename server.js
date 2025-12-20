const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = "mayconnect_secret_key";

// Parse JSON
app.use(express.json());
app.use(cors());

// Temporary in-memory database
let users = [];

// ======================== DATA PLANS ========================
const dataPlans = [
  { name: "MTN 100MB Daily", price: 100, network: "MTN", type: "Data" },
  { name: "MTN 1.5GB Weekly", price: 1000, network: "MTN", type: "Data" },
  { name: "Airtel 100MB Daily", price: 100, network: "Airtel", type: "Data" },
  { name: "Glo 4.5GB Monthly", price: 1500, network: "Glo", type: "Data" },
];

const airtimePlans = [
  { name: "MTN ₦100 Airtime", price: 100, network: "MTN", type: "Airtime" },
  { name: "Airtel ₦200 Airtime", price: 200, network: "Airtel", type: "Airtime" },
  { name: "Glo ₦500 Airtime", price: 500, network: "Glo", type: "Airtime" },
];

// ======================== SIGNUP ========================
app.post("/api/signup", async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name)
    return res.status(400).json({ error: "All fields are required" });

  const exists = users.find(u => u.email === email);
  if (exists)
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed, name, wallet: 0 });

  res.json({ message: "Signup successful" });
});

// ======================== LOGIN ========================
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "All fields are required" });

  const user = users.find(u => u.email === email);
  if (!user)
    return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok)
    return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "2h" });

  res.json({ message: "Login successful", token, name: user.name });
});

// ======================== WALLET ========================

// Get wallet balance
app.get("/api/wallet", (req, res) => {
  const email = req.query.email;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ wallet: user.wallet });
});

// Fund wallet
app.post("/api/wallet/fund", (req, res) => {
  const { email, amount } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });
  if (amount <= 0) return res.status(400).json({ error: "Invalid amount" });

  user.wallet += amount;
  res.json({ message: "Wallet funded successfully", wallet: user.wallet });
});

// ======================== PLANS ========================

// Get all plans
app.get("/api/plans", (req, res) => {
  res.json({ dataPlans, airtimePlans });
});

// ======================== TRANSACTIONS ========================

// Buy a plan (deduct from wallet)
app.post("/api/buy", (req, res) => {
  const { email, type, name } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });

  let plan;
  if (type === "Data") plan = dataPlans.find(p => p.name === name);
  else if (type === "Airtime") plan = airtimePlans.find(p => p.name === name);

  if (!plan) return res.status(404).json({ error: "Plan not found" });
  if (user.wallet < plan.price)
    return res.status(400).json({ error: "Insufficient wallet balance" });

  user.wallet -= plan.price;
  res.json({ message: `${type} purchase successful`, wallet: user.wallet });
});

// ======================== START SERVER ========================
app.listen(PORT, () => {
  console.log(`MayConnect Backend running on port ${PORT}`);
});
