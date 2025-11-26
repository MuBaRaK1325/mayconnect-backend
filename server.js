const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = "mayconnect_secret_key";

// Allow frontend
app.use(cors());
app.use(express.json());

// Temporary in-memory database
let users = [];

// Data plans
const plans = [
  { name: "MTN Daily 100MB", price: 100, network: "MTN", type: "Daily" },
  { name: "MTN Weekly 1.5GB", price: 1000, network: "MTN", type: "Weekly" },
  { name: "Airtel Daily 100MB", price: 100, network: "Airtel", type: "Daily" },
  { name: "Glo Monthly 4.5GB", price: 1500, network: "Glo", type: "Monthly" },
];

// ======================== SIGNUP ========================
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email & password required" });

  const exists = users.find(u => u.email === email);
  if (exists)
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);

  users.push({ email, password: hashed });

  res.json({ message: "Signup successful" });
});

// ======================== LOGIN ========================
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user)
    return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok)
    return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "2h" });

  res.json({ message: "Login successful", token });
});

// ======================== PLANS ========================
app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// Start Server
app.listen(PORT, () => {
  console.log("Backend running on port " + PORT);
});
