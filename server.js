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
  "abubakarmubarak3456@gmail.com",
  "bashirahmadt11696@gmail.com",
  "abdullahihabibudanalhaji@gmail.com",
  "Sadeeqtukur765@gmailcom"
]

app.use(cors({ origin: "*" }))
app.use(express.json())

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

/* ================= PAYSTACK SWITCH ================= */

function getPaystackKey(company){
  if(company==="teeversh") return process.env.PAYSTACK_TEEVERSH
  if(company==="bnhabeeb") return process.env.PAYSTACK_BNHABEEB
  if(company==="sadeeq") return process.env.PAYSTACK_SADEEQ
  return process.env.PAYSTACK_TEEVERSH
}

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

/* ================= AUTH ================= */

function auth(req,res,next){
  try{
    const token = req.headers.authorization.split(" ")[1]
    const user = jwt.verify(token,process.env.JWT_SECRET)

    req.user = user
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

    if(!username || !email || !password || !pin){
      return res.status(400).json({message:"All fields required"})
    }

    if(pin.length !== 4){
      return res.status(400).json({message:"PIN must be 4 digits"})
    }

    const existing = await pool.query(
      "SELECT * FROM users WHERE username=$1 OR email=$2",
      [username,email]
    )

    if(existing.rows.length){
      return res.status(400).json({message:"Username or Email exists"})
    }

    const hash = await bcrypt.hash(password,10)
    const pinHash = await bcrypt.hash(pin,10)

    const company = req.headers["x-company"] || detectCompany(email)
    const isAdmin = ADMIN_EMAILS.includes(email)

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [username,email,hash,pinHash,isAdmin,company]
    )

    let account_number=null, bank_name=null, customer_code=null

    try{
      const key = getPaystackKey(company)

      const customer = await axios.post(
        "https://api.paystack.co/customer",
        { email, first_name: username },
        { headers:{Authorization:`Bearer ${key}`} }
      )

      const dva = await axios.post(
        "https://api.paystack.co/dedicated_account",
        { customer: customer.data.data.customer_code },
        { headers:{Authorization:`Bearer ${key}`} }
      )

      account_number = dva.data.data.account_number
      bank_name = dva.data.data.bank.name
      customer_code = customer.data.data.customer_code

    }catch(e){
      console.log("Paystack error:", e.message)
    }

    await pool.query(
      "UPDATE users SET account_number=$1,bank_name=$2,customer_code=$3 WHERE id=$4",
      [account_number,bank_name,customer_code,user.rows[0].id]
    )

    const token = jwt.sign({
      id:user.rows[0].id,
      username:user.rows[0].username,
      is_admin:user.rows[0].is_admin,
      company:user.rows[0].company
    },process.env.JWT_SECRET)

    res.json({token,account_number,bank_name})

  }catch(err){
    console.log(err)
    res.status(500).json({message:"Signup failed"})
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

/* ================= BUY DATA (WITH PROFIT) ================= */

app.post("/api/buy-data",auth,async(req,res)=>{
  try{
    const {plan_id,phone,pin}=req.body

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const valid = await bcrypt.compare(pin,user.rows[0].pin)
    if(!valid) return res.status(400).json({message:"Invalid PIN"})

    const plan = await pool.query("SELECT * FROM plans WHERE id=$1",[plan_id])
    const price = Number(plan.rows[0].price)

    if(user.rows[0].wallet_balance < price){
      return res.status(400).json({message:"Insufficient balance"})
    }

    const profit = price * 0.1 // 🔥 10% profit
    const ref = "DATA-"+uuidv4()

    const newBalance = user.rows[0].wallet_balance - price

    await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE id=$2",
      [newBalance,req.user.id]
    )

    await pool.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status,company,profit)
       VALUES($1,'DATA',$2,$3,$4,'SUCCESS',$5,$6)`,
      [req.user.id,price,phone,ref,req.user.company,profit]
    )

    sendWalletUpdate(req.user.id,newBalance)

    res.json({success:true})

  }catch(err){
    console.log(err)
    res.status(500).json({message:"Data error"})
  }
})

/* ================= ADMIN PROFIT ================= */

app.get("/api/admin/profits",auth,async(req,res)=>{
  if(!req.user.is_admin) return res.status(403).json({})

  const r = await pool.query(
    "SELECT SUM(profit) FROM transactions WHERE company=$1",
    [req.user.company]
  )

  res.json({total_profit:r.rows[0].sum||0})
})

/* ================= SERVER ================= */

server.listen(process.env.PORT||5000,()=>{
  console.log("🚀 SERVER RUNNING (NEXT LEVEL)")
})