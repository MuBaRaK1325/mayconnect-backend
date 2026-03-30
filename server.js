require("dotenv").config();
const express=require("express");
const cors=require("cors");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const {Pool}=require("pg");
const http=require("http");
const WebSocket=require("ws");
const {v4:uuidv4}=require("uuid");

const app=express();
const server=http.createServer(app);
const wss=new WebSocket.Server({server});

app.use(cors());
app.use(express.json());

/* ================= DATABASE ================= */

const pool=new Pool({
connectionString:process.env.DATABASE_URL,
ssl:{rejectUnauthorized:false}
})

/* ================= WEBSOCKET ================= */

const clients=new Map()

wss.on("connection",(ws,req)=>{

const url=new URL(req.url,"http://localhost")
const token=url.searchParams.get("token")

if(!token) return ws.close()

try{

const decoded=jwt.verify(token,process.env.JWT_SECRET)

clients.set(decoded.id,ws)

ws.on("close",()=>{
clients.delete(decoded.id)
})

}catch{
ws.close()
}

})

function sendWalletUpdate(userId,balance){

const ws=clients.get(userId)

if(ws && ws.readyState===WebSocket.OPEN){

ws.send(JSON.stringify({
type:"wallet_update",
balance
}))

}

}

/* ================= AUTH ================= */

function auth(req,res,next){

const header=req.headers.authorization

if(!header)
return res.status(401).json({message:"No token"})

try{

const token=header.split(" ")[1]

const decoded=jwt.verify(token,process.env.JWT_SECRET)

req.user=decoded

next()

}catch{

res.status(401).json({message:"Invalid token"})

}

}

/* ================= SIGNUP ================= */

app.post("/api/signup",async(req,res)=>{

try{

const {username,email,password}=req.body

const exists=await pool.query(
"SELECT id FROM users WHERE username=$1",
[username]
)

if(exists.rows.length)
return res.status(400).json({message:"Username exists"})

const hash=await bcrypt.hash(password,10)

const user=await pool.query(
`INSERT INTO users(username,email,password)
VALUES($1,$2,$3)
RETURNING id,username,is_admin`,
[username,email,hash]
)

const token=jwt.sign(user.rows[0],process.env.JWT_SECRET,{expiresIn:"7d"})

res.json({token,user:user.rows[0]})

}catch{

res.status(500).json({message:"Signup failed"})

}

})

/* ================= LOGIN ================= */

app.post("/api/login",async(req,res)=>{

try{

const {username,password}=req.body

const user=await pool.query(
"SELECT * FROM users WHERE username=$1",
[username]
)

if(!user.rows.length)
return res.status(400).json({message:"User not found"})

const valid=await bcrypt.compare(password,user.rows[0].password)

if(!valid)
return res.status(400).json({message:"Wrong password"})

const token=jwt.sign({
id:user.rows[0].id,
username:user.rows[0].username,
is_admin:user.rows[0].is_admin
},process.env.JWT_SECRET,{expiresIn:"7d"})

res.json({
token,
username:user.rows[0].username,
is_admin:user.rows[0].is_admin
})

}catch{

res.status(500).json({message:"Login failed"})

}

})

/* ================= PROFILE ================= */

app.get("/api/me",auth,async(req,res)=>{

const user=await pool.query(
`SELECT id,username,email,wallet_balance,is_admin
FROM users WHERE id=$1`,
[req.user.id]
)

res.json(user.rows[0])

})

/* ================= DATA PLANS ================= */

app.get("/api/plans",async(req,res)=>{

const plans=await pool.query(
"SELECT * FROM plans ORDER BY price ASC"
)

res.json(plans.rows)

})

/* ================= BUY DATA ================= */

app.post("/api/buy-data",auth,async(req,res)=>{

const client=await pool.connect()

try{

const {plan_id,phone,pin}=req.body

await client.query("BEGIN")

const user=await client.query(
"SELECT wallet_balance,pin FROM users WHERE id=$1",
[req.user.id]
)

const valid=await bcrypt.compare(pin,user.rows[0].pin)

if(!valid) throw new Error("Invalid PIN")

const plan=await client.query(
"SELECT * FROM plans WHERE id=$1",
[plan_id]
)

if(!plan.rows.length)
throw new Error("Plan not found")

const price=Number(plan.rows[0].price)
const cost=Number(plan.rows[0].cost_price||price)

if(user.rows[0].wallet_balance < price)
throw new Error("Insufficient balance")

const profit=price-cost

const reference="DATA-"+uuidv4()

await client.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[price,req.user.id]
)

await client.query(
`INSERT INTO transactions
(user_id,type,amount,phone,reference,status)
VALUES($1,$2,$3,$4,$5,$6)`,
[req.user.id,"data",price,phone,reference,"SUCCESS"]
)

/* SAVE PROFIT */

await client.query(
`INSERT INTO profits(type,amount,reference)
VALUES($1,$2,$3)`,
["data",profit,reference]
)

await client.query("COMMIT")

sendWalletUpdate(req.user.id,user.rows[0].wallet_balance-price)

res.json({
success:true,
reference
})

}catch(err){

await client.query("ROLLBACK")

res.status(400).json({
success:false,
message:err.message
})

}finally{

client.release()

}

})

/* ================= BUY AIRTIME ================= */

app.post("/api/buy-airtime",auth,async(req,res)=>{

const client=await pool.connect()

try{

const {phone,amount,pin}=req.body

await client.query("BEGIN")

const user=await client.query(
"SELECT wallet_balance,pin FROM users WHERE id=$1",
[req.user.id]
)

const valid=await bcrypt.compare(pin,user.rows[0].pin)

if(!valid) throw new Error("Invalid PIN")

if(user.rows[0].wallet_balance < amount)
throw new Error("Insufficient balance")

const reference="AIRTIME-"+uuidv4()

await client.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[amount,req.user.id]
)

await client.query(
`INSERT INTO transactions
(user_id,type,amount,phone,reference,status)
VALUES($1,$2,$3,$4,$5,$6)`,
[req.user.id,"airtime",amount,phone,reference,"SUCCESS"]
)

/* PROFIT CALCULATION */

const profit=amount*0.03

await client.query(
`INSERT INTO profits(type,amount,reference)
VALUES($1,$2,$3)`,
["airtime",profit,reference]
)

await client.query("COMMIT")

sendWalletUpdate(req.user.id,user.rows[0].wallet_balance-amount)

res.json({
success:true,
reference
})

}catch(err){

await client.query("ROLLBACK")

res.status(400).json({
success:false,
message:err.message
})

}finally{

client.release()

}

})

/* ================= USER TRANSACTIONS ================= */

app.get("/api/transactions",auth,async(req,res)=>{

const trx=await pool.query(
`SELECT * FROM transactions
WHERE user_id=$1
ORDER BY created_at DESC`,
[req.user.id]
)

res.json(trx.rows)

})

/* ================= ADMIN PROFIT ================= */

app.get("/api/admin/profits",auth,async(req,res)=>{

if(!req.user.is_admin)
return res.status(403).json({message:"Forbidden"})

const profit=await pool.query(
`SELECT
SUM(amount) as total_profit
FROM profits`
)

res.json(profit.rows[0])

})

/* ================= ADMIN WALLET ================= */

app.post("/api/admin/credit-wallet",auth,async(req,res)=>{

if(!req.user.is_admin)
return res.status(403).json({message:"Forbidden"})

const {userId,amount}=req.body

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2",
[amount,userId]
)

const user=await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[userId]
)

sendWalletUpdate(userId,user.rows[0].wallet_balance)

res.json({message:"Wallet credited"})

})

/* ================= SERVER ================= */

const PORT=process.env.PORT||5000

server.listen(PORT,()=>{
console.log("SERVER RUNNING ON PORT",PORT)
})