require("dotenv").config()

const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const axios = require("axios")
const crypto = require("crypto")
const { Pool } = require("pg")

const app = express()

app.use(cors())
app.use(express.json())

/* =========================
DATABASE
========================= */

const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl:{ rejectUnauthorized:false }
})

/* =========================
HEALTH ROUTE
========================= */

app.get("/",(req,res)=>{
res.json({status:"MAY CONNECT API RUNNING"})
})

app.get("/favicon.ico",(req,res)=>res.status(204))

/* =========================
AUTH MIDDLEWARE
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

return res.status(401).json({message:"Invalid token"})

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
return res.status(400).json({message:"Username already exists"})
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

if(user.rows.length===0){
return res.status(400).json({message:"User not found"})
}

const valid = await bcrypt.compare(password,user.rows[0].password)

if(!valid){
return res.status(400).json({message:"Wrong password"})
}

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
FROM users
WHERE id=$1`,
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

res.json({message:"PIN set successfully"})

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
TRANSACTION HISTORY
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
GET DATA PLANS
========================= */

app.get("/api/plans",auth,async(req,res)=>{

const {network} = req.query

let query = "SELECT * FROM plans"
let values = []

if(network){
query += " WHERE network=$1"
values.push(network)
}

query += " ORDER BY price ASC"

const plans = await pool.query(query,values)

res.json(plans.rows)

})

/* =========================
BUY DATA
========================= */

app.post("/api/buy-data",auth,async(req,res)=>{

try{

const {plan_id,phone,pin} = req.body

const plan = await pool.query(
"SELECT * FROM plans WHERE plan_id=$1",
[plan_id]
)

if(plan.rows.length===0){
return res.status(400).json({message:"Plan not found"})
}

const price = Number(plan.rows[0].price)
const cost = Number(plan.rows[0].cost)

const validPin = await verifyPin(req.user.id,pin)

if(!validPin){
return res.status(400).json({message:"Invalid PIN"})
}

const user = await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(user.rows[0].wallet_balance < price){
return res.status(400).json({message:"Insufficient balance"})
}

/* CALL DATA API */

const api = await axios.post(process.env.DATA_API,{
plan:plan_id,
phone
},{
headers:{Authorization:`Bearer ${process.env.DATA_TOKEN}`}
})

if(api.data.status !== "success"){
return res.status(400).json({message:"Data purchase failed"})
}

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

res.json({message:"Data purchase successful"})

}catch(err){

console.log(err)

res.status(500).json({message:"Transaction failed"})

}

})

/* =========================
BUY AIRTIME
========================= */

app.post("/api/buy-airtime",auth,async(req,res)=>{

try{

const {network,phone,amount,pin} = req.body

const validPin = await verifyPin(req.user.id,pin)

if(!validPin){
return res.status(400).json({message:"Invalid PIN"})
}

const user = await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(user.rows[0].wallet_balance < amount){
return res.status(400).json({message:"Insufficient balance"})
}

const api = await axios.post(
`${process.env.CHEAPDATA_URL}/airtime`,
{network,phone,amount},
{headers:{Authorization:`Bearer ${process.env.CHEAPDATA_KEY}`}}
)

if(api.data.status !== "success"){
return res.status(400).json({message:"Airtime purchase failed"})
}

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[amount,req.user.id]
)

await pool.query(
`INSERT INTO transactions(user_id,type,amount,profit,phone)
VALUES($1,$2,$3,$4,$5)`,
[req.user.id,"airtime",amount,0,phone]
)

res.json({message:"Airtime successful"})

}catch(err){

console.log(err)

res.status(500).json({message:"Airtime failed"})

}

})

/* =========================
PAYSTACK FUND WALLET
========================= */

app.post("/api/fund-wallet",auth,async(req,res)=>{

const {amount,email} = req.body

const pay = await axios.post(
"https://api.paystack.co/transaction/initialize",
{
amount:amount*100,
email
},
{
headers:{
Authorization:`Bearer ${process.env.PAYSTACK_SECRET}`,
"Content-Type":"application/json"
}
}
)

res.json(pay.data.data)

})

/* =========================
PAYSTACK WEBHOOK
========================= */

app.post("/api/paystack/webhook",express.raw({type:"application/json"}),(req,res)=>{

const hash = crypto
.createHmac("sha512",process.env.PAYSTACK_SECRET)
.update(req.body)
.digest("hex")

if(hash === req.headers["x-paystack-signature"]){

const event = JSON.parse(req.body)

if(event.event === "charge.success"){

const amount = event.data.amount / 100
const email = event.data.customer.email

pool.query(
"UPDATE users SET wallet_balance=wallet_balance+$1 WHERE email=$2",
[amount,email]
)

}

}

res.sendStatus(200)

})

/* =========================
RECIPIENTS (FOR TRANSFERS)
========================= */

app.post("/api/recipients",auth,async(req,res)=>{

const {name,bank,account_number} = req.body

await pool.query(
`INSERT INTO recipients(user_id,name,bank,account_number)
VALUES($1,$2,$3,$4)`,
[req.user.id,name,bank,account_number]
)

res.json({message:"Recipient saved"})

})

/* =========================
ADMIN PROFIT
========================= */

app.get("/api/admin/profit",auth,async(req,res)=>{

if(!req.user.is_admin){
return res.status(403).json({message:"Forbidden"})
}

const admin = await pool.query(
"SELECT admin_wallet FROM users WHERE id=$1",
[req.user.id]
)

res.json(admin.rows[0])

})

/* =========================
ADMIN WITHDRAW
========================= */

app.post("/api/admin/withdraw",auth,async(req,res)=>{

if(!req.user.is_admin){
return res.status(403).json({message:"Forbidden"})
}

const {amount,bank,account_number,account_name} = req.body

const admin = await pool.query(
"SELECT admin_wallet FROM users WHERE id=$1",
[req.user.id]
)

if(admin.rows[0].admin_wallet < amount){
return res.status(400).json({message:"Insufficient admin balance"})
}

await pool.query(
`INSERT INTO withdrawals(amount,bank,account_number,account_name)
VALUES($1,$2,$3,$4)`,
[amount,bank,account_number,account_name]
)

await pool.query(
"UPDATE users SET admin_wallet=admin_wallet-$1 WHERE id=$2",
[amount,req.user.id]
)

res.json({message:"Withdrawal recorded"})

})

/* ========================= */

const PORT = process.env.PORT || 5000

app.listen(PORT,()=>{
console.log("MAY CONNECT SERVER RUNNING")
})