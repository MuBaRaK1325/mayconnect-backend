require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const fetch = require("node-fetch");
const { v4: uuidv4 } = require("uuid");
const base64url = require("base64url");
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();

/* ===================== CORS FIXED ===================== */
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
app.options("*", cors()); // handle preflight

app.use(express.json());

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // For Render/Postgres SSL
});

/* ===================== MIDDLEWARE ===================== */
function authenticateToken(req,res,next){
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if(!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err,user)=>{
    if(err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function isAdmin(req,res,next){
  if(!req.user.is_admin) return res.status(403).json({error:"Admin only"});
  next();
}

/* ===================== AUTH ===================== */
// SIGNUP
app.post("/api/signup", async(req,res)=>{
  const {name,email,password} = req.body;
  if(!name||!email||!password) return res.status(400).json({error:"All fields required"});

  try{
    const hash = await bcrypt.hash(password,10);
    const result = await pool.query(
      "INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING id,email,is_admin",
      [name,email,hash]
    );

    const token = jwt.sign(
      {id: result.rows[0].id,email, is_admin: result.rows[0].is_admin},
      process.env.JWT_SECRET,
      {expiresIn:"7d"}
    );

    res.json({token});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Signup failed"});
  }
});

// LOGIN
app.post("/api/login", async(req,res)=>{
  const {email,password,biometric_key} = req.body;

  try{
    const result = await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    const user = result.rows[0];
    if(!user) return res.status(400).json({error:"Invalid credentials"});

    if(biometric_key){
      if(biometric_key !== user.biometric_key)
        return res.status(400).json({error:"Invalid biometric key"});
    }else{
      const valid = await bcrypt.compare(password,user.password);
      if(!valid) return res.status(400).json({error:"Invalid credentials"});
    }

    const token = jwt.sign(
      {id:user.id,email:user.email,is_admin:user.is_admin},
      process.env.JWT_SECRET,
      {expiresIn:"7d"}
    );

    res.json({token});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Login failed"});
  }
});

/* ===================== WALLET ===================== */
// Get wallet balance
app.get("/api/wallet", authenticateToken, async(req,res)=>{
  try{
    const result = await pool.query("SELECT wallet_balance FROM users WHERE id=$1",[req.user.id]);
    res.json({balance: result.rows[0].wallet_balance});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Failed to fetch balance"});
  }
});

// Get transaction history
app.get("/api/wallet/transactions", authenticateToken, async(req,res)=>{
  try{
    const result = await pool.query("SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC",[req.user.id]);
    res.json({transactions: result.rows});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Failed to fetch transactions"});
  }
});

// Fund wallet via Paystack
app.post("/api/wallet/deposit/paystack", authenticateToken, async(req,res)=>{
  const {amount,email} = req.body;
  if(!amount||!email) return res.status(400).json({error:"Amount and email required"});

  // Mock Paystack response
  const authorization_url = `https://paystack.com/pay/mock-${uuidv4()}`;
  res.json({authorization_url});
});

// Fund wallet via Flutterwave
app.post("/api/wallet/deposit/flutterwave", authenticateToken, async(req,res)=>{
  const {amount,email} = req.body;
  if(!amount||!email) return res.status(400).json({error:"Amount and email required"});

  // Mock Flutterwave response
  const link = `https://flutterwave.com/pay/mock-${uuidv4()}`;
  res.json({data:{link}});
});

// Purchase airtime/data
app.post("/api/wallet/purchase", authenticateToken, async(req,res)=>{
  const {type,amount,details,pin} = req.body;
  try{
    const userRes = await pool.query("SELECT wallet_balance,pin,pin_attempts,locked FROM users WHERE id=$1",[req.user.id]);
    const user = userRes.rows[0];

    if(user.locked) return res.status(403).json({error:"Wallet locked due to multiple incorrect PIN attempts"});

    const validPin = await bcrypt.compare(pin,user.pin);
    if(!validPin){
      let attempts = user.pin_attempts+1;
      let locked = attempts>=3;
      await pool.query("UPDATE users SET pin_attempts=$1, locked=$2 WHERE id=$3",[attempts,locked,req.user.id]);
      return res.status(400).json({error:"Incorrect PIN"});
    }

    if(user.wallet_balance < amount) return res.status(400).json({error:"Insufficient balance"});

    const reference = `MC-${uuidv4()}`;
    const newBalance = user.wallet_balance - amount;

    await pool.query("UPDATE users SET wallet_balance=$1,pin_attempts=0 WHERE id=$2",[newBalance,req.user.id]);
    await pool.query(
      "INSERT INTO transactions(user_id,type,amount,description,reference,status,details) VALUES($1,$2,$3,$4,$5,'success',$6)",
      [req.user.id,type,amount,type==='airtime'?'Airtime purchase':'Data purchase',reference,details||null]
    );

    res.json({message:"Purchase successful", receipt:{reference,type,amount,status:"success",details,date:new Date()}, balance:newBalance});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Purchase failed"});
  }
});

/* ===================== PIN / BIOMETRIC ===================== */
// Include your previous verify-pin, biometric-login, biometric-challenge routes here exactly as in old server.js

/* ===================== ADMIN ===================== */
app.get("/api/admin/users", authenticateToken, isAdmin, async(req,res)=>{
  try{
    const result = await pool.query("SELECT id,name,email,wallet_balance,created_at FROM users ORDER BY created_at DESC");
    res.json({users: result.rows});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Failed to fetch users"});
  }
});

app.get("/api/admin/transactions", authenticateToken, isAdmin, async(req,res)=>{
  try{
    const result = await pool.query("SELECT * FROM transactions ORDER BY created_at DESC");
    res.json({transactions: result.rows});
  }catch(err){
    console.error(err);
    res.status(500).json({error:"Failed to fetch transactions"});
  }
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`✅ Server running on port ${PORT}`));
