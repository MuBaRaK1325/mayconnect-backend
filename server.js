require("dotenv").config()
const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { Pool } = require("pg")
const http = require("http")
const WebSocket = require("ws")
const { v4: uuidv4 } = require("uuid")
const fs = require("fs")
const axios = require("axios")

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

/* ================= PAYSTACK KEYS ================= */

const PAYSTACK_KEYS = {
  mayconnect: process.env.PAYSTACK_MAYCONNECT,
  teeversh: process.env.PAYSTACK_TEEVERSH,
  sadeeq: process.env.PAYSTACK_SADEEQ,
  bnhabeeb: process.env.PAYSTACK_BNHABEEB
}

function getPaystackKey(company){
  return PAYSTACK_KEYS[company] || PAYSTACK_KEYS.mayconnect
}

/* ================= TOP USERS ================= */

let topUsers = []
try{
  const data = fs.readFileSync("./topUsers.json")
  topUsers = JSON.parse(data)
}catch{
  topUsers = []
}

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

/* ================= AUTH ================= */

function auth(req,res,next){
  try{
    const token = req.headers.authorization.split(" ")[1]
    req.user = jwt.verify(token,process.env.JWT_SECRET)
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

/* ================= AUTH ROUTES ================= */

app.post("/api/signup", async (req,res)=>{
  try{
    const {username,email,password,pin} = req.body

    if(!username || !email || !password || !pin){
      return res.status(400).json({message:"All fields required"})
    }

    const hash = await bcrypt.hash(password,10)
    const pinHash = await bcrypt.hash(pin,10)

    const company = (req.headers["x-company"] || detectCompany(email)).toLowerCase()
    const isAdmin = ADMIN_EMAILS.includes(email)
    const isTopUser = topUsers.includes(email)

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company,is_top_user)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [username,email,hash,pinHash,isAdmin,company,isTopUser]
    )

    const token = jwt.sign({
      id:user.rows[0].id,
      username:user.rows[0].username,
      is_admin:user.rows[0].is_admin,
      company:user.rows[0].company
    },process.env.JWT_SECRET)

    res.json({token,user:user.rows[0]})

  }catch(e){
    console.log(e)
    res.status(500).json({message:"Signup failed"})
  }
})

app.post("/api/login", async (req,res)=>{
  try{
    const {username,password}=req.body

    const user = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    )

    if(!user.rows.length){
      return res.status(400).json({message:"User not found"})
    }

    const valid = await bcrypt.compare(password,user.rows[0].password)
    if(!valid){
      return res.status(400).json({message:"Wrong password"})
    }

    const token = jwt.sign({
      id:user.rows[0].id,
      username:user.rows[0].username,
      is_admin:user.rows[0].is_admin,
      company:user.rows[0].company
    },process.env.JWT_SECRET)

    res.json({token,user:user.rows[0]})

  }catch{
    res.status(500).json({message:"Login error"})
  }
})

/* ================= PASSWORD ================= */

app.post("/api/forgot-password", async (req,res)=>{
  const {email,newPassword} = req.body

  const user = await pool.query("SELECT * FROM users WHERE email=$1",[email])

  if(!user.rows.length){
    return res.status(400).json({message:"Email not found"})
  }

  const hash = await bcrypt.hash(newPassword,10)

  await pool.query(
    "UPDATE users SET password=$1 WHERE email=$2",
    [hash,email]
  )

  res.json({message:"Password reset successful"})
})

app.post("/api/change-password",auth,async(req,res)=>{
  const {oldPass,newPass} = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

  const valid = await bcrypt.compare(oldPass,user.rows[0].password)
  if(!valid){
    return res.status(400).json({message:"Wrong old password"})
  }

  const hash = await bcrypt.hash(newPass,10)

  await pool.query(
    "UPDATE users SET password=$1 WHERE id=$2",
    [hash,req.user.id]
  )

  res.json({message:"Password updated"})
})

/* ================= PIN ================= */

app.post("/api/change-pin",auth,async(req,res)=>{
  const {oldPin,newPin} = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

  const valid = await bcrypt.compare(oldPin,user.rows[0].pin)
  if(!valid){
    return res.status(400).json({message:"Wrong old PIN"})
  }

  const hash = await bcrypt.hash(newPin,10)

  await pool.query(
    "UPDATE users SET pin=$1 WHERE id=$2",
    [hash,req.user.id]
  )

  res.json({message:"PIN updated"})
})

/* ================= BUY DATA ================= */

app.post("/api/buy-data",auth,async(req,res)=>{
  try{
    const {plan_id,phone,pin} = req.body

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const valid = await bcrypt.compare(pin,user.rows[0].pin)
    if(!valid) return res.status(400).json({message:"Invalid PIN"})

    const plan = await pool.query(
      "SELECT * FROM plans WHERE id=$1 AND company=$2",
      [plan_id,req.user.company]
    )

    if(!plan.rows.length){
      return res.status(400).json({message:"Invalid plan"})
    }

    const price = Number(plan.rows[0].price)

    if(user.rows[0].wallet_balance < price){
      return res.status(400).json({message:"Insufficient balance"})
    }

    const newBalance = user.rows[0].wallet_balance - price

    await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2",[newBalance,req.user.id])

    await pool.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status,company,profit)
       VALUES($1,'DATA',$2,$3,$4,'SUCCESS',$5,$6)`,
      [req.user.id,price,phone,"DATA-"+uuidv4(),req.user.company,price*0.1]
    )

    sendWalletUpdate(req.user.id,newBalance)

    res.json({success:true})

  }catch(e){
    console.log(e)
    res.status(500).json({message:"Data error"})
  }
})

/* ================= BUY AIRTIME (ONLY MAYCONNECT) ================= */

app.post("/api/buy-airtime",auth,async(req,res)=>{
  try{

    if(req.user.company !== "mayconnect"){
      return res.status(403).json({message:"Airtime only for Mayconnect"})
    }

    const {phone,amount,network,pin} = req.body

    if(!network) return res.status(400).json({message:"Select network"})

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const valid = await bcrypt.compare(pin,user.rows[0].pin)
    if(!valid) return res.status(400).json({message:"Invalid PIN"})

    const amt = Number(amount)

    if(user.rows[0].wallet_balance < amt){
      return res.status(400).json({message:"Insufficient balance"})
    }

    const newBalance = user.rows[0].wallet_balance - amt

    await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2",[newBalance,req.user.id])

    await pool.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status,company)
       VALUES($1,'AIRTIME',$2,$3,$4,'SUCCESS',$5)`,
      [req.user.id,amt,phone,"AIRTIME-"+uuidv4(),req.user.company]
    )

    sendWalletUpdate(req.user.id,newBalance)

    res.json({success:true})

  }catch(e){
    console.log(e)
    res.status(500).json({message:"Airtime error"})
  }
})

/* ================= PAYSTACK FUNDING ================= */

app.post("/api/fund/init",auth,async(req,res)=>{
  try{
    const {amount} = req.body

    const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

    const reference = "FUND-"+uuidv4()

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: user.rows[0].email,
        amount: Number(amount) * 100,
        reference
      },
      {
        headers:{
          Authorization:`Bearer ${getPaystackKey(req.user.company)}`
        }
      }
    )

    res.json({
      url: response.data.data.authorization_url,
      reference
    })

  }catch(e){
    console.log(e.response?.data || e.message)
    res.status(500).json({message:"Payment init failed"})
  }
})

/* VERIFY */
app.get("/api/fund/verify/:reference",auth,async(req,res)=>{
  try{
    const {reference} = req.params

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers:{
          Authorization:`Bearer ${getPaystackKey(req.user.company)}`
        }
      }
    )

    if(response.data.data.status === "success"){
      const amount = response.data.data.amount / 100

      const user = await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])

      const newBalance = Number(user.rows[0].wallet_balance) + amount

      await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2",[newBalance,req.user.id])

      sendWalletUpdate(req.user.id,newBalance)
    }

    res.json({success:true})

  }catch(e){
    res.status(500).json({message:"Verification failed"})
  }
})

/* ================= WEBHOOK ================= */

app.post("/api/paystack/webhook",async(req,res)=>{
  try{
    const event = req.body

    if(event.event === "charge.success"){
      console.log("Webhook received:", event.data.reference)
    }

    res.sendStatus(200)
  }catch{
    res.sendStatus(500)
  }
})

/* ================= ADMIN WITHDRAW ================= */

app.post("/api/admin/withdraw",auth,async(req,res)=>{
  try{
    if(!req.user.is_admin){
      return res.status(403).json({message:"Forbidden"})
    }

    const {username,amount} = req.body

    const user = await pool.query("SELECT * FROM users WHERE username=$1",[username])

    if(!user.rows.length){
      return res.status(400).json({message:"User not found"})
    }

    const amt = Number(amount)

    const newBalance = user.rows[0].wallet_balance - amt

    await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2",[newBalance,user.rows[0].id])

    sendWalletUpdate(user.rows[0].id,newBalance)

    res.json({success:true})

  }catch{
    res.status(500).json({message:"Withdraw error"})
  }
})

/* ================= SERVER ================= */

server.listen(process.env.PORT||5000,()=>{
  console.log("🚀 SERVER READY ✅")
})