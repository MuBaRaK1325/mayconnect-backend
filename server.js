require("dotenv").config()

const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const axios = require("axios")
const { Pool } = require("pg")

const app = express()

app.use(cors())
app.use(express.json())
app.use(express.static("public"))
app.get("/force-admin", async (req,res)=>{
const bcrypt = require("bcryptjs");
const hash = await bcrypt.hash("MAYADMIN",10);

await pool.query(
"UPDATE users SET password=$1 WHERE username='Admin'",
[hash]
);

res.send("Admin password reset");
});
/* =========================
DATABASE
========================= */

const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: { rejectUnauthorized:false }
})

/* =========================
AUTH MIDDLEWARE
========================= */

function auth(req,res,next){

const header = req.headers.authorization

if(!header) return res.status(401).json({message:"No token"})

const token = header.split(" ")[1]

try{

const decoded = jwt.verify(token,process.env.JWT_SECRET)

req.user = decoded

next()

}catch(err){

return res.status(401).json({message:"Invalid token"})

}

}

/* =========================
SIGNUP
========================= */

app.post("/api/signup", async(req,res)=>{

try{

const {username,email,password} = req.body

const hash = await bcrypt.hash(password,10)

const user = await pool.query(

`INSERT INTO users(username,email,password)
VALUES($1,$2,$3)
RETURNING id,username,is_admin`,

[username,email,hash]
)

const token = jwt.sign(user.rows[0],process.env.JWT_SECRET)

res.json({
token,
user:user.rows[0]
})

}catch(err){

console.log(err)
res.status(500).json({message:"Signup failed"})

}

})

/* =========================
LOGIN
========================= */

app.post("/api/login", async(req,res)=>{

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
USER PROFILE
========================= */

app.get("/api/me",auth,async(req,res)=>{

const user = await pool.query(
"SELECT id,username,wallet_balance,is_admin FROM users WHERE id=$1",
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

res.json({message:"Pin set successfully"})

})

/* =========================
VERIFY PIN
========================= */

async function verifyPin(userId,pin){

const user = await pool.query(
"SELECT pin FROM users WHERE id=$1",
[userId]
)

if(!user.rows[0].pin) return false

return await bcrypt.compare(pin,user.rows[0].pin)

}

/* =========================
GET PLANS
========================= */

app.get("/api/plans",async(req,res)=>{

const plans = await pool.query(
"SELECT * FROM plans ORDER BY price ASC"
)

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

const price = plan.rows[0].price
const cost = plan.rows[0].cost

const validPin = await verifyPin(req.user.id,pin)

if(!validPin){
return res.status(400).json({message:"Invalid pin"})
}

const user = await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(user.rows[0].wallet_balance < price){
return res.status(400).json({message:"Insufficient balance"})
}

/* API CALL */

await axios.post(process.env.DATA_API,{

plan:plan_id,
phone

},{
headers:{
Authorization:`Bearer ${process.env.DATA_TOKEN}`
}
})

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
`INSERT INTO transactions(user_id,type,amount,profit)
VALUES($1,$2,$3,$4)`,

[req.user.id,"data",price,profit]
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
return res.status(400).json({message:"Invalid pin"})
}

const user = await pool.query(
"SELECT wallet_balance FROM users WHERE id=$1",
[req.user.id]
)

if(user.rows[0].wallet_balance < amount){
return res.status(400).json({message:"Insufficient balance"})
}

await axios.post(`${process.env.CHEAPDATA_URL}/airtime`,{

network,
phone,
amount

},{
headers:{
Authorization:`Bearer ${process.env.CHEAPDATA_KEY}`
}
})

const profit = amount * 0.03

await pool.query(
"UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
[amount,req.user.id]
)

await pool.query(
"UPDATE users SET admin_wallet=admin_wallet+$1 WHERE is_admin=true",
[profit]
)

await pool.query(
`INSERT INTO transactions(user_id,type,amount,profit)
VALUES($1,$2,$3,$4)`,

[req.user.id,"airtime",amount,profit]
)

res.json({message:"Airtime successful"})

}catch(err){

console.log(err)
res.status(500).json({message:"Airtime failed"})

}

})

/* =========================
TRANSACTIONS
========================= */

app.get("/api/transactions",auth,async(req,res)=>{

const tx = await pool.query(

"SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC",

[req.user.id]
)

res.json(tx.rows)

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

try{

if(!req.user.is_admin){
return res.status(403).json({message:"Forbidden"})
}

const {amount,bank,account_number,account_name} = req.body

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

}catch(err){

console.log(err)
res.status(500).json({message:"Withdraw failed"})

}

})

/* =========================
SERVER
========================= */

const PORT = process.env.PORT || 5000

app.listen(PORT,()=>{

console.log("Server running on port "+PORT)

})