const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = "mayconnect_secret_key";

app.use(cors());
app.use(express.json());

// Temporary users storage
const users = [];

// SAMPLE DATA PLANS
const plans = [
  { name: "MTN Daily 100MB", price: 100, network: "MTN", type: "Daily" },
  { name: "Airtel Monthly 6GB", price: 2500, network: "Airtel", type: "Monthly" },
  { name: "Glo Daily 500MB", price: 200, network: "Glo", type: "Daily" },
  { name: "9mobile Weekly 750MB", price: 500, network: "9mobile", type: "Weekly" }
];

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "All fields required" });

  const exist = users.find(u => u.email === email);
  if (exist)
    return res.status(400).json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });

  res.json({ message: "Signup successful" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user)
    return res.status(400).json({ message: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok)
    return res.status(400).json({ message: "Incorrect password" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "1h" });

  res.json({
    message: "Login successful",
    token
  });
});

// GET PLANS (protected)
app.get("/api/plans", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ message: "Missing token" });

  try {
    const token = auth.split(" ")[1];
    jwt.verify(token, SECRET);
    res.json(plans);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
