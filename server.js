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

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

app.use(cors())
app.use(express.json())

/* =========================
DATABASE
========================= */

const pool = new Pool({
connectionString:process.env.DATABASE_URL,
ssl:{rejectUnauthorized:false}
})

/* =========================
WEBSOCKET SYSTEM
========================= */

const clients = new Map()

wss.on("connection",(ws,req)=>{

const token = req.url.split("token=")[1]

if(!token) return ws.close()

try{

const decoded = jwt.verify(token,process.env.JWT_SECRET)

clients.set(decoded.id,ws)

ws.on("close",()=>{
clients.delete(decoded.id)
})

}catch{
ws.close()
}

})

function sendWalletUpdate(userId,balance){

const ws = clients.get(userId)

if(ws && ws.readyState === WebSocket.OPEN){

ws.send(JSON.stringify({
type:"wallet_update",
balance
}))

}

}

/* =========================
HEALTH ROUTE
========================= */

app.get("/",(req,res)=>{
res.json({status:"MAY CONNECT API RUNNING"})
})

/* =========================
AUTH
========================= */

function auth(req,res,next){

const header = req.headers.authorization

if(!header) return res.status(401).json({message:"No token"})

try{

const token = header.split(" ")[1]
const decoded = jwt.verify(token,process.env.JWT_SECRET)

req.user = decoded

next()

}catch{

res.status(401).json({message:"Invalid token"})

}

}

/* =========================
SIGNUP
========================= */

app.post("/api/signup",async(req,res)=>{

try{

const {username,email,password} = req.body

const exists = await pool.query(
"SELECT id FROM users WHERE username=$1",
[username]
)

if(exists.rows.length>0){
return res.status(400).json({message:"Username exists"})
}

const hash = await bcrypt.hash(password,10)

const user = await pool.query(
`INSERT INTO users(username,email,password)
VALUES($1,$2,$3)
RETURNING id,username,is_admin`,
[username,email,hash]
)

const token = jwt.sign(user.rows[0],process.env.JWT_SECRET)

res.json({token,user:user.rows[0]})

}catch(err){

console.log(err)
res.status(500).json({message:"Signup failed"})

}

})

/* =========================
LOGIN
========================= */

app.post("/api/login",async(req,res)=>{

try{

const {username,password} = req.body

const user = await pool.query(
"SELECT * FROM users WHERE username=$1",
[username]
)

if(user.rows.length===0)
return res.status(400).json({message:"User not found"})

const valid = await bcrypt.compare(password,user.rows[0].password)

if(!valid)
return res.status(400).json({message:"Wrong password"})

const token = jwt.sign({
id:user.rows[0].id,
username:user.rows[0].username,
is_admin:user.rows[0].is_admin
},process.env.JWT_SECRET)

res.json({
token,
username:user.rows[0].username,
is_admin:user.rows[0].is_admin
})

}catch(err){

console.log(err)
res.status(500).json({message:"Login failed"})

}

})

/* =========================
PROFILE
========================= */

app.get("/api/me",auth,async(req,res)=>{

const user = await pool.query(
`SELECT id,username,wallet_balance,admin_wallet,is_admin
FROM users WHERE id=$1`,
[req.user.id]
)

res.json(user.rows[0])

})

/* =========================
SET PIN
========================= */

app.post("/api/set-pin",auth,async(req,res)=>{

const {pin} = req.body

const hash = await bcrypt.hash(pin,10)

await pool.query(
"UPDATE users SET pin=$1 WHERE id=$2",
[hash,req.user.id]
)

res.json({message:"PIN set"})

})

async function verifyPin(userId,pin){

const user = await pool.query(
"SELECT pin FROM users WHERE id=$1",
[userId]
)

if(!user.rows[0].pin) return false

return await bcrypt.compare(pin,user.rows[0].pin)

}

/* =========================
TRANSACTIONS
========================= */

app.get("/api/transactions",auth,async(req,res)=>{

const tx = await pool.query(
`SELECT id,type,amount,profit,phone,created_at
FROM transactions
WHERE user_id=$1
ORDER BY created_at DESC`,
[req.user.id]
)

res.json(tx.rows)

})

/* =========================
DATA PLANS
========================= */

app.get("/api/plans",auth,async(req,res)=>{

const {network} = req.query

let query="SELECT * FROM plans"
let values=[]

if(network){
query+=" WHERE network=$1"
values.push(network)
}

query+=" ORDER BY price ASC"

const plans=await pool.query(query,values)

res.json(plans.rows)

})

/* =========================
BUY DATA
========================= */

app.post("/api/buy-data",auth,async(req,res)=>{

try{

const {plan_id,phone,pin}=req.body

const validPin = await verifyPin(req.user.id,pin)

if(!validPin)
return res.status(400).json({message:"Invalid PIN"})

const plan = await pool.query(
"SELECT * FROM plans WHERE plan_id=$1",
[plan_id]
)

const price = Number(plan.rows[0].price)
const cost = Number(plan.rows[0].cost)

const user = await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(user.rows[0].wallet_balance < price)
return res.status(400).json({message:"Insufficient balance"})

const profit = price - cost

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[price,req.user.id]
)

await pool.query(
"UPDATE users SET admin_wallet=admin_wallet+$1 WHERE is_admin=true",
[profit]
)

await pool.query(
`INSERT INTO transactions(user_id,type,amount,profit,phone)
VALUES($1,$2,$3,$4,$5)`,
[req.user.id,"data",price,profit,phone]
)

sendWalletUpdate(req.user.id,user.rows[0].wallet_balance-price)

res.json({message:"Data successful"})

}catch(err){

console.log(err)
res.status(500).json({message:"Transaction failed"})

}

})

/* =========================
ADMIN DASHBOARD
========================= */

app.get("/api/admin/dashboard",auth,async(req,res)=>{

if(!req.user.is_admin)
return res.status(403).json({message:"Forbidden"})

const todayProfit = await pool.query(
`SELECT SUM(profit) FROM transactions
WHERE DATE(created_at)=CURRENT_DATE`
)

const totalProfit = await pool.query(
`SELECT SUM(profit) FROM transactions`
)

const users = await pool.query(
`SELECT COUNT(*) FROM users`
)

const todayTx = await pool.query(
`SELECT COUNT(*) FROM transactions
WHERE DATE(created_at)=CURRENT_DATE`
)

res.json({
today_profit:todayProfit.rows[0].sum||0,
total_profit:totalProfit.rows[0].sum||0,
total_users:users.rows[0].count,
today_transactions:todayTx.rows[0].count
})

})

/* =========================
WHITE LABEL BRAND
========================= */

app.get("/api/brand/:domain",async(req,res)=>{

const brand = await pool.query(
"SELECT * FROM brands WHERE domain=$1",
[req.params.domain]
)

res.json(brand.rows[0])

})

/* ========================= */

const PORT = process.env.PORT || 5000

server.listen(PORT,()=>{
console.log("MAY CONNECT SERVER RUNNING")
})