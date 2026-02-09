require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");
const { v4: uuidv4 } = require("uuid");
const cron = require("node-cron");
const { Pool } = require("pg");

const app = express();

/* ================= MIDDLEWARE ================= */

app.use(express.json());

app.use(cors({
  origin: "*",
  methods: ["GET","POST"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

/* ================= HEALTH CHECK ================= */

app.get("/", (req,res)=>{
  res.send("MAY CONNECT BACKEND RUNNING 🚀");
});

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:{ rejectUnauthorized:false }
});

/* ================= HELPERS ================= */

function token(id){
  return jwt.sign({id}, process.env.JWT_SECRET || "secret", {expiresIn:"7d"});
}

function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:"Missing token"});

  jwt.verify(h.split(" ")[1], process.env.JWT_SECRET || "secret", (err,user)=>{
    if(err) return res.status(403).json({error:"Invalid token"});
    req.user = user;
    next();
  });
}

async function retry(fn){
  try{ return await fn(); }
  catch{
    await new Promise(r=>setTimeout(r,1500));
    return await fn();
  }
}

/* ================= FULL DATA PLANS ================= */

const DATA_PLANS = [
  {plan_id:153,provider:"maitama",network:"MTN",name:"MTN 5GB SME",price:1500},
  {plan_id:414,provider:"subpadi",network:"MTN",name:"2.5GB GIFTING",price:600},
  {plan_id:413,provider:"subpadi",network:"MTN",name:"1GB GIFTING",price:300},
  {plan_id:359,provider:"subpadi",network:"MTN",name:"2GB GIFTING",price:500},
  {plan_id:415,provider:"subpadi",network:"AIRTEL",name:"3.2GB GIFTING",price:1050},
  {plan_id:394,provider:"subpadi",network:"AIRTEL",name:"2GB GIFTING",price:700},
  {plan_id:329,provider:"subpadi",network:"AIRTEL",name:"6.5GB SME",price:1500},
  {plan_id:327,provider:"subpadi",network:"AIRTEL",name:"3.2GB SME",price:700},
  {plan_id:37,provider:"maitama",network:"AIRTEL",name:"1GB",price:300},
  {plan_id:38,provider:"maitama",network:"AIRTEL",name:"2GB",price:600},
  {plan_id:39,provider:"maitama",network:"AIRTEL",name:"3GB",price:600},
  {plan_id:335,provider:"subpadi",network:"GLO",name:"9.8GB SME",price:2450},
  {plan_id:334,provider:"subpadi",network:"GLO",name:"2.5GB SME",price:700},
  {plan_id:261,provider:"subpadi",network:"GLO",name:"1.024GB CORPORATE",price:500},
  {plan_id:195,provider:"subpadi",network:"GLO",name:"3.9GB GIFTING",price:1050},
  {plan_id:194,provider:"subpadi",network:"GLO",name:"1.05GB GIFTING",price:500},
  {plan_id:52,provider:"cheapdatahub",network:"AIRTEL",name:"5GB",price:1650}
];
/* ================= ADMIN RESET ================= */

app.post("/api/admin/reset-password", async(req,res)=>{
 try{
  const {email,newPassword}=req.body;

  if(email!=="abubakarmubarak3456@gmail.com")
   return res.status(403).json({error:"Unauthorized"});

  const hash=await bcrypt.hash(newPassword,10);
  await pool.query("UPDATE users SET password=$1 WHERE email=$2",[hash,email]);

  res.json({success:true});
 }catch{
  res.status(500).json({error:"Server error"});
 }
});

/* ================= SIGNUP ================= */

app.post("/api/signup", async(req,res)=>{
 const {name,email,password}=req.body;
 if(!name||!email||!password)
  return res.status(400).json({error:"Missing fields"});

 const hash=await bcrypt.hash(password,10);

 try{
  const r=await pool.query(
   "INSERT INTO users(name,email,password,wallet_balance) VALUES($1,$2,$3,0) RETURNING id",
   [name,email,hash]
  );

  res.json({token:token(r.rows[0].id),name});
 }catch{
  res.status(400).json({error:"Email exists"});
 }
});

/* ================= LOGIN ================= */

app.post("/api/login", async(req,res)=>{
 const {email,password}=req.body;

 const r=await pool.query(
  "SELECT id,name,password FROM users WHERE email=$1",[email]
 );

 if(!r.rows.length)
  return res.status(401).json({error:"Invalid credentials"});

 if(!await bcrypt.compare(password,r.rows[0].password))
  return res.status(401).json({error:"Invalid credentials"});

 res.json({token:token(r.rows[0].id),name:r.rows[0].name});
});

/* ================= WALLET ================= */

app.get("/api/wallet",auth,async(req,res)=>{
 const r=await pool.query(
  "SELECT wallet_balance FROM users WHERE id=$1",[req.user.id]
 );
 res.json({balance:r.rows[0]?.wallet_balance||0});
});

/* ================= SET PIN ================= */

app.post("/api/set-pin",auth,async(req,res)=>{
 const hash=await bcrypt.hash(req.body.pin,10);
 await pool.query("UPDATE users SET pin=$1 WHERE id=$2",[hash,req.user.id]);
 res.json({success:true});
});

/* ================= PURCHASE ================= */

app.post("/api/wallet/purchase",auth,async(req,res)=>{
 const {pin,details,provider}=req.body;

 const u=await pool.query(
  "SELECT wallet_balance,pin FROM users WHERE id=$1",[req.user.id]
 );

 if(!await bcrypt.compare(pin,u.rows[0].pin))
  return res.status(400).json({error:"Wrong PIN"});

 let plan=DATA_PLANS.find(p=>p.plan_id==details.plan);
 if(!plan) return res.status(400).json({error:"Plan missing"});

 if(u.rows[0].wallet_balance<plan.price)
  return res.status(400).json({error:"Insufficient funds"});

 const ref="MC-"+uuidv4();

 await pool.query(
  "UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
  [plan.price,req.user.id]
 );

 res.json({receipt:{reference:ref,amount:plan.price,status:"success"}});
});

/* ================= ANALYTICS ================= */

app.get("/api/admin/analytics",async(req,res)=>{
 const r=await pool.query("SELECT COUNT(*) total FROM transactions");
 res.json(r.rows[0]);
});

/* ================= CRON ================= */

cron.schedule("*/2 * * * *",()=>console.log("cron running"));

/* ================= START ================= */

const PORT=process.env.PORT||5000;
app.listen(PORT,()=>console.log("🚀 MAY CONNECT LIVE",PORT));
