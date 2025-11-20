import express from "express";
import cors from "cors";
const cors = require("cors");
app.get("/api-url", (req, res) => {
  res.json({ url: process.env.PUBLIC_URL || "http://localhost:3000" });
});
app.use(cors({
  origin: "*",
  methods: "GET,POST,PUT,DELETE",
  allowedHeaders: "Content-Type, Authorization"
}));
const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Sample plans data
const plans = [
  { name: "Daily 100MB", price: 100, network: "MTN", duration: "Daily" },
  { name: "Daily 200MB", price: 150, network: "Airtel", duration: "Daily" },
  { name: "Weekly 1.5GB", price: 800, network: "Airtel", duration: "Weekly" },
  { name: "Monthly 5GB", price: 2000, network: "MTN", duration: "Monthly" },
];

// Define API route
app.get("/api/plans", (req, res) => {
  res.json(plans);
});

app.listen(PORT, () => {
  console.log(`✅ Backend running on http://localhost:${PORT}`);
});
