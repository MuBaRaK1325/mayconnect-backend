const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "mayconnect_secret_key";

app.use(cors());
app.use(express.json());

// ======== Load Database ========
let db = { users: [] };

if (fs.existsSync("db.json")) {
  db = JSON.parse(fs.readFileSync("db.json"));
}

// Save DB helper
function saveDB() {
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
}

// ======== DATA PLANS ========
const plans = [
  { name: "MTN 100MB Daily", price: 100, network: "MTN", type: "Daily" },
  { name: "MTN 1.5GB Weekly", price: 1000, network: "MTN", type: "Weekly" },
  { name: "Airtel 100MB Daily", price: 100, network: "Airtel", type: "Daily" },
  { name: "Glo 4.5GB Monthly", price: 1500, network: "Glo", type: "Monthly" },
];

// ======== SIGNUP ========
app.post("/api/signup", async (req, res) => {
  const { email, password, username } = req.body;

  if (!email || !password || !username)
    return res.status(400).json({ error: "All fields are required" });

  const exists = db.users.find(u => u.email === email);
  if (exists)
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);

  db.users.push({
    email,
    username,
    password: hashed,
    wallet: 0
  });

  saveDB();

  res.json({ message: "Signup successful" });
});

// ======== LOGIN ========
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.users.find(u => u.email === email);
  if (!user)
    return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok)
    return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign(
    { email: user.email },
    SECRET,
    { expiresIn: "2h" }
  );

  res.json({
    message: "Login successful",
    token,
    username: user.username,
    wallet: user.wallet
  });
});

// ======== GET PLANS ========
app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// ======== GET USER DETAILS (for showing name at top) ========
app.get("/api/me", (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);

    const user = db.users.find(u => u.email === decoded.email);

    res.json({
      email: user.email,
      username: user.username,
      wallet: user.wallet
    });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Start
app.listen(PORT, () => {
  console.log("Backend running on port " + PORT);
});
