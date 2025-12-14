const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "mayconnect_secret_key";

// MIDDLEWARE (order matters)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TEMP DATABASE
let users = [];

// DATA PLANS
const plans = [
  { name: "MTN 100MB Daily", price: 100, network: "MTN", type: "Daily" },
  { name: "MTN 1.5GB Weekly", price: 1000, network: "MTN", type: "Weekly" },
  { name: "Airtel 100MB Daily", price: 100, network: "Airtel", type: "Daily" },
  { name: "Glo 4.5GB Monthly", price: 1500, network: "Glo", type: "Monthly" },
];

// HEALTH CHECK (VERY IMPORTANT)
app.get("/", (req, res) => {
  res.json({ status: "MayConnect Backend is running" });
});

app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(400).json({ error: "User already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  const newUser = {
    name,
    email,
    password: hashed,
    wallet: 0
  };

  users.push(newUser);

  res.json({ message: "Signup successful" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    return res.status(400).json({ error: "Incorrect password" });
  }

  const token = jwt.sign({ email }, SECRET, { expiresIn: "2h" });

  res.json({
  message: "Login successful",
  token,
  user: {
    name: user.name,
    email: user.email,
    wallet: user.wallet
  }
});

// PLANS
app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// START SERVER
app.listen(PORT, () => {
  console.log(`🚀 MayConnect backend running on port ${PORT}`);
});
