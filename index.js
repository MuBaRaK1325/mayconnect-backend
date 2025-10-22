// MAY-Connect Backend
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./Auth.js";
import dataRoutes from "./Data.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/auth", authRoutes);
app.use("/data", dataRoutes);

app.get("/", (req, res) => {
  res.send("🚀 MAY-Connect Backend is running successfully!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
