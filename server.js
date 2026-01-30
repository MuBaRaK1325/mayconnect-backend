require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");
const nodemailer = require("nodemailer");
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const app = express();

/* ===================== CORS ===================== */
app.use(cors({
  origin: [
    "https://mayconnect-frontend.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ],
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.options("*", cors());
app.use(express.json());

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ===================== AUTH MIDDLEWARE ===================== */
function authenticateToken(req,res,next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if(!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err,user)=>{
    if(err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

function isAdmin(req,res,next){
  if(!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
  next();
}

/* ===================== DATA PLANS ===================== */
const DATA_PLANS = {
  MTN_5GB_SME: {
    network: 1,
    plan_id: 158,
    name: "MTN 5GB SME",
    price: 1500,
    cost: 1400,
    profit: 100,
    type: "SME",
    validity: "30 Days"
  }
};

/* ===================== AUTH ROUTES ===================== */
app.post("/api/signup", async (req,res)=>{
  const { name,email,password } = req.body;
  if(!name||!email||!password) return res.status(400).json({ error: "All fields required" });

  try{
    const hash = await bcrypt.hash(password,10);
    const result = await pool.query(
      "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING id,email,is_admin",
      [name,email,hash]
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email, is_admin: result.rows[0].is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch(err){
    console.error(err);
    res.status(500).json({ error: "Signup failed", details: err.message });
  }
});

app.post("/api/login", async (req,res)=>{
  const { email,password,biometric_key } = req.body;
  try{
    const result = await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    const user = result.rows[0];
    if(!user) return res.status(400).json({ error: "Login failed" });

    if(biometric_key){
      if(biometric_key !== user.biometric_key)
        return res.status(400).json({ error: "Invalid biometric key" });
    } else {
      const valid = await bcrypt.compare(password,user.password);
      if(!valid) return res.status(400).json({ error: "Login failed" });
    }

    const token = jwt.sign(
      { id:user.id, email:user.email, is_admin:user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn:"7d" }
    );
    res.json({ token });
  } catch(err){
    console.error(err);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

/* ===================== SET PIN ===================== */
app.post("/api/set-pin", authenticateToken, async (req,res)=>{
  try{
    const { pin } = req.body;
    if(!pin || pin.length !==4 || !/^\d{4}$/.test(pin))
      return res.status(400).json({ success:false, message:"PIN must be 4 digits" });

    const hashedPin = await bcrypt.hash(pin,10);
    await pool.query("UPDATE users SET pin=$1 WHERE id=$2",[hashedPin, req.user.id]);
    res.json({ success:true, message:"PIN set successfully" });
  } catch(err){
    console.error("Set PIN error:",err);
    res.status(500).json({ success:false, message:"Server error" });
  }
});

/* ===================== FORGOT PIN ===================== */
app.post("/api/forgot-pin", async (req,res)=>{
  try{
    const { email } = req.body;
    if(!email) return res.status(400).json({ error:"Email is required" });

    const result = await pool.query("SELECT id,email FROM users WHERE email=$1",[email]);
    const user = result.rows[0];
    if(!user) return res.status(400).json({ error:"No user with this email" });

    const token = uuidv4();
    await pool.query("UPDATE users SET pin_reset_token=$1 WHERE id=$2",[token,user.id]);

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const mailOptions = {
      from: '"MAY Connect" <no-reply@mayconnect.com>',
      to: email,
      subject: "Reset your PIN",
      text: `Use this token to reset your PIN: ${token}`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success:true, message:"Reset instructions sent to your email" });
  } catch(err){
    console.error("Forgot PIN error:",err);
    res.status(500).json({ error:"Failed to send reset instructions", details: err.message });
  }
});

/* ===================== WALLET ===================== */
app.get("/api/wallet", authenticateToken, async (req,res)=>{
  try{
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1",[req.user.id]);
    res.json({ balance: result.rows[0]?.wallet_balance || 0 });
  } catch(err){
    console.error(err);
    res.status(500).json({ error:"Failed to fetch balance", details: err.message });
  }
});

/* ===================== WALLET PURCHASE ===================== */
app.post("/api/wallet/purchase", authenticateToken, async (req,res)=>{
  const { type, pin, details } = req.body;

  try{
    const userRes = await pool.query(
      "SELECT wallet_balance, pin, pin_attempts, locked FROM users WHERE id=$1",
      [req.user.id]
    );
    const user = userRes.rows[0];

    if(!user?.pin) return res.status(400).json({ error:"PIN not set" });
    if(user.locked) return res.status(403).json({ error:"Wallet locked due to multiple incorrect PIN attempts" });

    const validPin = await bcrypt.compare(pin,user.pin);
    if(!validPin){
      const attempts = (user.pin_attempts || 0) + 1;
      const locked = attempts >= 3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3",[attempts,locked,req.user.id]);
      return res.status(400).json({ error:"Incorrect PIN" });
    }

    if(type !== "data") return res.status(400).json({ error:"Unsupported purchase type" });

    const plan = DATA_PLANS.MTN_5GB_SME;
    const amount = plan.price;

    if(user.wallet_balance < amount) return res.status(400).json({ error:"Insufficient balance" });

    // === Call Maitama API ===
    const maitamaRes = await fetch("https://app.maitamadatahub.com/api/data",{
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        Authorization:`Bearer ${process.env.MAITAMA_API_TOKEN}`,
        Accept:"application/json"
      },
      body: JSON.stringify({
        mobile_number: details.mobile_number,
        plan: plan.plan_id,
        network: plan.network
      })
    });

    const apiResponse = await maitamaRes.json();
    if(!maitamaRes.ok || apiResponse.status !== "success") {
      return res.status(400).json({ error: apiResponse.api_response || "Maitama purchase failed" });
    }

    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query("UPDATE users SET wallet_balance=$1,pin_attempts=0 WHERE id=$2",[newBalance,req.user.id]);
    await pool.query(
      `INSERT INTO transactions
       (user_id,type,amount,description,reference,status,details)
       VALUES ($1,$2,$3,$4,$5,'success',$6)`,
       [req.user.id,type,amount,"Data purchase",reference,details]
    );

    res.json({
      message:"Purchase successful",
      receipt:{ reference,type,amount,status:"success",date:new Date() },
      balance:newBalance
    });

  } catch(err){
    console.error("Purchase error:",err);
    res.status(500).json({ error:"Purchase failed", details:err.message });
  }
});

/* ===================== BIOMETRIC ===================== */
app.get("/api/biometric/challenge", authenticateToken, async (req,res)=>{
  try{
    const options = generateAuthenticationOptions({
      userID:String(req.user.id),
      timeout:60000,
      allowCredentials:[]
    });
    await pool.query("UPDATE users SET temp_challenge=$1 WHERE id=$2",[options.challenge,req.user.id]);
    res.json(options);
  } catch(err){
    console.error(err);
    res.status(500).json({ error:"Failed to generate challenge", details:err.message });
  }
});

app.post("/api/biometric/verify", authenticateToken, async (req,res)=>{
  const { response } = req.body;
  try{
    const userRes = await pool.query("SELECT temp_challenge FROM users WHERE id=$1",[req.user.id]);
    const user = userRes.rows[0];
    const verification = verifyAuthenticationResponse({
      response,
      expectedChallenge:user.temp_challenge,
      expectedOrigin:req.headers.origin || "http://localhost:3000",
      expectedRPID:req.hostname
    });

    if(verification.verified){
      await pool.query("UPDATE users SET biometric_key=$1 WHERE id=$2",[response.id,req.user.id]);
      res.json({ verified:true });
    } else {
      res.status(400).json({ verified:false });
    }
  } catch(err){
    console.error(err);
    res.status(500).json({ error:"Biometric verification failed", details:err.message });
  }
});

/* ===================== ADMIN ROUTES ===================== */
app.get("/api/admin/users", authenticateToken, isAdmin, async (req,res)=>{
  try{
    const result = await pool.query("SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC");
    res.json({ users: result.rows });
  } catch(err){
    console.error(err);
    res.status(500).json({ error:"Failed to fetch users", details:err.message });
  }
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`✅ MAY-Connect backend running on port ${PORT}`));
