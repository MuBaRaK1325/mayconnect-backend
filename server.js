require("dotenv").config()

const express=require("express")
const cors=require("cors")
const bcrypt=require("bcryptjs")
const jwt=require("jsonwebtoken")
const {Pool}=require("pg")
const http=require("http")
const WebSocket=require("ws")

const app=express()
const server=http.createServer(app)
const wss=new WebSocket.Server({server})

app.use(cors())
app.use(express.json())

const pool=new Pool({
connectionString:process.env.DATABASE_URL,
ssl:{rejectUnauthorized:false}
})

/* AUTH */

function auth(req,res,next){

const header=req.headers.authorization

if(!header) return res.status(401).json({status:false,message:"No token"})

try{

const token=header.split(" ")[1]

const decoded=jwt.verify(token,process.env.JWT_SECRET)

req.user=decoded

next()

}catch{

res.status(401).json({status:false,message:"Invalid token"})

}

}

/* HEALTH */

app.get("/",(req,res)=>{
res.json({status:true,message:"MAY CONNECT API RUNNING"})
})

/* PROFILE */

app.get("/api/me",auth,async(req,res)=>{

const user=await pool.query(
`SELECT id,username,wallet_balance,admin_wallet,is_admin
FROM users WHERE id=$1`,
[req.user.id]
)

res.json({status:true,user:user.rows[0]})

})

/* SET PIN */

app.post("/api/set-pin",auth,async(req,res)=>{

const {pin}=req.body

if(!pin) return res.json({status:false,message:"PIN required"})

const hash=await bcrypt.hash(pin,10)

await pool.query(
"UPDATE users SET pin=$1 WHERE id=$2",
[hash,req.user.id]
)

res.json({status:true,message:"PIN saved successfully"})

})

async function verifyPin(userId,pin){

const user=await pool.query(
"SELECT pin FROM users WHERE id=$1",
[userId]
)

if(!user.rows[0] || !user.rows[0].pin) return false

return await bcrypt.compare(pin,user.rows[0].pin)

}

/* DATA PLANS */

app.get("/api/plans",auth,async(req,res)=>{

const plans=await pool.query(
"SELECT * FROM plans ORDER BY price ASC"
)

res.json(plans.rows)

})

/* BUY DATA */

app.post("/api/buy-data",auth,async(req,res)=>{

try{

const {plan_id,phone,pin}=req.body

const validPin=await verifyPin(req.user.id,pin)

if(!validPin)
return res.json({status:false,message:"Invalid PIN"})

const plan=await pool.query(
"SELECT * FROM plans WHERE plan_id=$1 OR id=$1",
[plan_id]
)

if(plan.rows.length===0)
return res.json({status:false,message:"Plan not found"})

const price=Number(plan.rows[0].price)

const user=await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(Number(user.rows[0].wallet_balance)<price)
return res.json({status:false,message:"Insufficient balance"})

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[price,req.user.id]
)

await pool.query(
`INSERT INTO transactions(user_id,type,amount,phone)
VALUES($1,$2,$3,$4)`,
[req.user.id,"data",price,phone]
)

res.json({status:true,amount:price,message:"Data purchase successful"})

}catch{

res.json({status:false,message:"Transaction failed"})

}

})

/* BUY AIRTIME */

app.post("/api/buy-airtime",auth,async(req,res)=>{

try{

const {phone,amount,pin}=req.body

const validPin=await verifyPin(req.user.id,pin)

if(!validPin)
return res.json({status:false,message:"Invalid PIN"})

const user=await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(Number(user.rows[0].wallet_balance)<Number(amount))
return res.json({status:false,message:"Insufficient balance"})

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[amount,req.user.id]
)

await pool.query(
`INSERT INTO transactions(user_id,type,amount,phone)
VALUES($1,$2,$3,$4)`,
[req.user.id,"airtime",amount,phone]
)

res.json({status:true,amount,message:"Airtime successful"})

}catch{

res.json({status:false,message:"Airtime failed"})

}

})

const PORT=process.env.PORT||5000

server.listen(PORT,()=>{
console.log("MAY CONNECT SERVER RUNNING")
})