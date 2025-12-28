const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = "mayconnect_secret_key";

// Middleware
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// Persistent database files
const usersFile = path.join(__dirname, "users.json");
const transactionsFile = path.join(__dirname, "transactions.json");

// Load or create database
let users = fs.existsSync(usersFile) ? JSON.parse(fs.readFileSync(usersFile)) : [];
let transactions = fs.existsSync(transactionsFile) ? JSON.parse(fs.readFileSync(transactionsFile)) : [];

// Data plans
const plans = [
  { id: 1, name: "MTN Daily 100MB", price: 100, network: "MTN", type: "Data" },
  { id: 2, name: "MTN Weekly 1.5GB", price: 1000, network: "MTN", type: "Data" },
  { id: 3, name: "Airtel Daily 100MB", price: 100, network: "Airtel", type: "Data" },
  { id: 4, name: "Glo Monthly 4.5GB", price: 1500, network: "Glo", type: "Data" },
  { id: 5, name: "MTN 100 Naira Airtime", price: 100, network: "MTN", type: "Airtime" },
  { id: 6, name: "Airtel 100 Naira Airtime", price: 100, network: "Airtel", type: "Airtime" },
];

// ======================== SIGNUP ========================
app.post("/api/signup", async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: "All fields are required" });

  const exists = users.find(u => u.email === email);
  if (exists) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { fullName, email, password: hashed, wallet: 0 };
  users.push(newUser);

  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));

  res.json({ message: "Signup successful" });
});

// ======================== LOGIN ========================
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "All fields are required" });

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "2h" });
  res.json({ message: "Login successful", token, fullName: user.fullName });
});

// ======================== GET PLANS ========================
app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// ======================== WALLET ========================
app.get("/api/wallet/:email", (req, res) => {
  const { email } = req.params;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ wallet: user.wallet });
});

app.post("/api/wallet/fund", (req, res) => {
  const { email, amount } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });
  user.wallet += Number(amount);
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
  res.json({ message: "Wallet funded", wallet: user.wallet });
});

// ======================== PURCHASE ========================
app.post("/api/purchase", (req, res) => {
  const { email, planId } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });

  const plan = plans.find(p => p.id === planId);
  if (!plan) return res.status(404).json({ error: "Plan not found" });

  if (user.wallet < plan.price) return res.status(400).json({ error: "Insufficient wallet balance" });

  user.wallet -= plan.price;

  const transaction = {
    id: transactions.length + 1,
    email,
    planName: plan.name,
    price: plan.price,
    type: plan.type,
    date: new Date().toISOString()
  };
  transactions.push(transaction);

  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
  fs.writeFileSync(transactionsFile, JSON.stringify(transactions, null, 2));

  res.json({ message: "Purchase successful", wallet: user.wallet, transaction });
});

// ======================== GET TRANSACTIONS ========================
app.get("/api/transactions/:email", (req, res) => {
  const { email } = req.params;
  const userTransactions = transactions.filter(t => t.email === email);
  res.json(userTransactions);
});

// ======================== START SERVER ========================
app.listen(PORT, () => {
  console.log("Backend running on port " + PORT);
});
