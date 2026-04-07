require("dotenv").config()
const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const axios = require("axios")
const crypto = require("crypto")
const { Pool } = require("pg")
const http = require("http")
const WebSocket = require("ws")
const { v4: uuidv4 } = require("uuid")

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

/* ================= CONFIG ================= */

const ADMIN_EMAILS = [
  "mayconnectofficial@gmail.com",
  "bashirahmadt11696@gmail.com",
  "abdullahihabibudanalhaji@gmail.com",
  "Sadeeqtukur765@gmailcom"
]

/* ================= MIDDLEWARE ================= */

app.use(cors({ origin: "*" }))
app.use(express.json())

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

/* ================= WEBSOCKET ================= */

const clients = new Map()

wss.on("connection", (ws, req) => {
  try {
    const token = new URL(req.url, "http://x").searchParams.get("token")
    const user = jwt.verify(token, process.env.JWT_SECRET)
    clients.set(user.id, ws)
    ws.on("close", () => clients.delete(user.id))
  } catch { ws.close() }
})

function sendWalletUpdate(userId, balance){
  const ws = clients.get(userId)
  if(ws && ws.readyState===1){
    ws.send(JSON.stringify({type:"wallet_update",balance}))
  }
}

/* ================= AUTH (🔥 UPDATED) ================= */

function auth(req,res,next){
  try{
    const token = req.headers.authorization.split(" ")[1]
    const user = jwt.verify(token,process.env.JWT_SECRET)

    // 🔥 COMPANY OVERRIDE FROM FRONTEND
    const company = req.headers["x-company"]

    req.user = {
      ...user,
      company: company || user.company
    }

    next()
  }catch{
    res.status(401).json({message:"Unauthorized"})
  }
}

/* ================= COMPANY ================= */

function detectCompany(email){
  if(email==="bashirahmadt11696@gmail.com") return "teeversh"
  if(email==="abdullahihabibudanalhaji@gmail.com") return "bnhabeeb"
  if(email==="Sadeeqtukur765@gmailcom") return "sadeeq"
  return "mayconnect"
}

/* ================= SIGNUP ================= */

app.post("/api/signup", async (req,res)=>{
  try{
    const {username,email,password,pin} = req.body

    const hash = await bcrypt.hash(password,10)
    const pinHash = await bcrypt.hash(pin,10)

    const isAdmin = ADMIN_EMAILS.includes(email)

    // 🔥 USE FRONTEND COMPANY FIRST
    const company = req.headers["x-company"] || detectCompany(email)

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [username,email,hash,pinHash,isAdmin,company]
    )

    /* PAYSTACK */
    const customer = await axios.post(
      "https://api.paystack.co/customer",
      { email, first_name: username },
      { headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET}`} }
    )

    const dva = await axios.post(
      "https://api.paystack.co/dedicated_account",
      { customer: customer.data.data.customer_code },
      { headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET}`} }
    )

    await pool.query(
      `UPDATE users SET customer_code=$1,account_number=$2,bank_name=$3 WHERE id=$4`,
      [
        customer.data.data.customer_code,
        dva.data.data.account_number,
        dva.data.data.bank.name,
        user.rows[0].id
      ]
    )

    const token = jwt.sign({
      id:user.rows[0].id,
      username:user.rows[0].username,
      is_admin:user.rows[0].is_admin,
      company:user.rows[0].company
    },process.env.JWT_SECRET)

    res.json({
      token,
      account_number:dva.data.data.account_number,
      bank_name:dva.data.data.bank.name
    })

  }catch(err){
    console.log(err)
    res.status(500).json({message:"Signup error"})
  }
})

/* ================= LOGIN ================= */

app.post("/api/login", async (req,res)=>{
  const {username,password}=req.body

  const user = await pool.query("SELECT * FROM users WHERE username=$1",[username])
  if(!user.rows.length) return res.status(400).json({message:"User not found"})

  const valid = await bcrypt.compare(password,user.rows[0].password)
  if(!valid) return res.status(400).json({message:"Wrong password"})

  const token = jwt.sign({
    id:user.rows[0].id,
    username:user.rows[0].username,
    is_admin:user.rows[0].is_admin,
    company:user.rows[0].company
  },process.env.JWT_SECRET)

  res.json({token,...user.rows[0]})
})

/* ================= TRANSACTIONS ================= */

app.get("/api/transactions",auth,async(req,res)=>{
  const tx = await pool.query(
    "SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  )

  const user = await pool.query(
    "SELECT wallet_balance FROM users WHERE id=$1",
    [req.user.id]
  )

  res.json(tx.rows.map(t=>({...t,wallet_balance:user.rows[0].wallet_balance})))
})

/* ================= PLANS ================= */

app.get("/api/plans",auth,async(req,res)=>{
  const plans = await pool.query(
    "SELECT * FROM plans WHERE company=$1",
    [req.user.company]
  )
  res.json(plans.rows)
})

/* ================= BUY DATA ================= */

app.post("/api/buy-data",auth,async(req,res)=>{
  try{
    const {plan_id,phone,pin} = req.body

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const valid = await bcrypt.compare(pin,user.rows[0].pin)
    if(!valid) return res.status(400).json({message:"Invalid PIN"})

    const plan = await pool.query("SELECT * FROM plans WHERE id=$1",[plan_id])
    const price = Number(plan.rows[0].price)

    if(user.rows[0].wallet_balance < price){
      return res.status(400).json({message:"Insufficient balance"})
    }

    const ref = "DATA-"+uuidv4()

    const newBalance = user.rows[0].wallet_balance - price

    await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE id=$2",
      [newBalance,req.user.id]
    )

    await pool.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status)
       VALUES($1,'DATA',$2,$3,$4,'SUCCESS')`,
      [req.user.id,price,phone,ref]
    )

    sendWalletUpdate(req.user.id,newBalance)

    res.json({success:true})

  }catch(err){
    res.status(500).json({message:"Data error"})
  }
})

/* ================= BUY AIRTIME ================= */

app.post("/api/buy-airtime",auth,async(req,res)=>{
  try{
    const {phone,amount,pin}=req.body

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const valid = await bcrypt.compare(pin,user.rows[0].pin)
    if(!valid) return res.status(400).json({message:"Invalid PIN"})

    if(user.rows[0].wallet_balance < amount)
      return res.status(400).json({message:"Insufficient balance"})

    const ref="AIRTIME-"+uuidv4()
    const newBalance = user.rows[0].wallet_balance - amount

    await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE id=$2",
      [newBalance,req.user.id]
    )

    await pool.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status)
       VALUES($1,'AIRTIME',$2,$3,$4,'SUCCESS')`,
      [req.user.id,amount,phone,ref]
    )

    sendWalletUpdate(req.user.id,newBalance)

    res.json({success:true})

  }catch{
    res.status(500).json({message:"Airtime error"})
  }
})

/* ================= CHANGE PASSWORD ================= */

app.post("/api/change-password",auth,async(req,res)=>{
  const {oldPass,newPass}=req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

  const valid = await bcrypt.compare(oldPass,user.rows[0].password)
  if(!valid) return res.json({message:"Wrong password"})

  const hash = await bcrypt.hash(newPass,10)

  await pool.query("UPDATE users SET password=$1 WHERE id=$2",[hash,req.user.id])

  res.json({message:"Password updated"})
})

/* ================= CHANGE PIN ================= */

app.post("/api/change-pin",auth,async(req,res)=>{
  const {oldPin,newPin}=req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

  const valid = await bcrypt.compare(oldPin,user.rows[0].pin)
  if(!valid) return res.json({message:"Wrong PIN"})

  const hash = await bcrypt.hash(newPin,10)

  await pool.query("UPDATE users SET pin=$1 WHERE id=$2",[hash,req.user.id])

  res.json({message:"PIN updated"})
})

/* ================= WITHDRAW ================= */

app.post("/api/withdraw",auth,async(req,res)=>{
  const {amount}=req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

  if(user.rows[0].wallet_balance < amount){
    return res.json({message:"Insufficient balance"})
  }

  const newBalance = user.rows[0].wallet_balance - amount

  await pool.query(
    "UPDATE users SET wallet_balance=$1 WHERE id=$2",
    [newBalance,req.user.id]
  )

  sendWalletUpdate(req.user.id,newBalance)

  res.json({message:"Withdrawal requested"})
})

/* ================= ADMIN ================= */

app.get("/api/admin/profits",auth,async(req,res)=>{
  if(!req.user.is_admin) return res.status(403).json({})

  const r = await pool.query(
    "SELECT SUM(amount) FROM transactions WHERE user_id IN (SELECT id FROM users WHERE company=$1)",
    [req.user.company]
  )

  res.json({total_profit:r.rows[0].sum||0})
})

app.post("/api/admin/credit",auth,async(req,res)=>{
  if(!req.user.is_admin) return res.status(403).json({})

  const {user_id,amount}=req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[user_id])

  const newBalance = user.rows[0].wallet_balance + amount

  await pool.query(
    "UPDATE users SET wallet_balance=$1 WHERE id=$2",
    [newBalance,user_id]
  )

  sendWalletUpdate(user_id,newBalance)

  res.json({success:true})
})

/* ================= PAYSTACK WEBHOOK ================= */

app.post("/api/paystack/webhook",async(req,res)=>{
  const hash = crypto.createHmac("sha512",process.env.PAYSTACK_SECRET)
  .update(JSON.stringify(req.body)).digest("hex")

  if(hash !== req.headers["x-paystack-signature"]) return res.sendStatus(401)

  const event = req.body

  if(event.event==="charge.success"){
    const email = event.data.customer.email
    const amount = event.data.amount/100

    const user = await pool.query("SELECT * FROM users WHERE email=$1",[email])

    const newBalance = user.rows[0].wallet_balance + amount

    await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE id=$2",
      [newBalance,user.rows[0].id]
    )

    sendWalletUpdate(user.rows[0].id,newBalance)
  }

  res.sendStatus(200)
})

/* ================= SERVER ================= */

server.listen(process.env.PORT||5000,()=>{
  console.log("🚀 SERVER RUNNING")
})