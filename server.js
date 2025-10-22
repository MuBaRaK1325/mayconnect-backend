// ===============================
// ✅ MayConnect Backend — Full Correct Version
// ===============================

import express from "express";
import cors from "cors";

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Test route
app.get("/", (req, res) => {
  res.send("✅ MayConnect Backend is running successfully!");
});

// Main API route for data plans
app.get("/api/plans", (req, res) => {
  const plans = [
    // Daily Plans
    { name: "Daily 100MB", price: 100, network: "MTN", type: "Daily" },
    { name: "Daily 200MB", price: 150, network: "Airtel", type: "Daily" },
    { name: "Daily 500MB", price: 200, network: "Glo", type: "Daily" },

    // Weekly Plans
    { name: "Weekly 750MB", price: 500, network: "MTN", type: "Weekly" },
    { name: "Weekly 1.5GB", price: 800, network: "Airtel", type: "Weekly" },
    { name: "Weekly 3GB", price: 1200, network: "Glo", type: "Weekly" },

    // Monthly Plans
    { name: "Monthly 2GB", price: 1000, network: "MTN", type: "Monthly" },
    { name: "Monthly 5GB", price: 2500, network: "Airtel", type: "Monthly" },
    { name: "Monthly 10GB", price: 4000, network: "9mobile", type: "Monthly" },

    // Unlimited
    { name: "Unlimited 20GB", price: 7000, network: "MTN", type: "Unlimited" },
    { name: "Unlimited 50GB", price: 15000, network: "Airtel", type: "Unlimited" }
  ];

  res.json(plans);
});

// Start server
app.listen(3000, "0.0.0.0", () => {
  console.log("✅ Server running on http://0.0.0.0:3000");
});
