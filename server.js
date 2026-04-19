require("dotenv").config()
const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { Pool } = require("pg")
const http = require("http")
const WebSocket = require("ws")
const { v4: uuidv4 } = require("uuid")
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

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET

/* ================= MIDDLEWARE ================= */

app.use(cors({ origin: "*" }))
app.use(express.json())

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

/* ================= WS ================= */

const clients = new Map()

wss.on("connection", (ws, req) => {
  try {
    const token = new URL(req.url, "http://x").searchParams.get("token")
    const user = jwt.verify(token, process.env.JWT_SECRET)
    clients.set(user.id, ws)
    ws.on("close", () => clients.delete(user.id))
  } catch {
    ws.close()
  }
})

function sendWalletUpdate(userId, balance) {
  const ws = clients.get(userId)
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({ type: "wallet_update", balance }))
  }
}

/* ================= AUTH ================= */

function auth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1]
    req.user = jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ message: "Unauthorized" })
  }
}

/* ================= SIGNUP ================= */

app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, pin, company } = req.body

    const hash = await bcrypt.hash(password, 10)
    const pinHash = await bcrypt.hash(pin, 10)

    const isAdmin = ADMIN_EMAILS.includes(email)

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [username, email, hash, pinHash, isAdmin, company || "mayconnect"]
    )

    /* PAYSTACK CUSTOMER */
    const customer = await axios.post(
      "https://api.paystack.co/customer",
      { email, first_name: username },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    )

    const customer_code = customer.data.data.customer_code

    /* DEDICATED ACCOUNT */
    const account = await axios.post(
      "https://api.paystack.co/dedicated_account",
      { customer: customer_code },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    )

    const acc = account.data.data

    await pool.query(
      `UPDATE users SET customer_code=$1,account_number=$2,account_name=$3,bank_name=$4 WHERE id=$5`,
      [customer_code, acc.account_number, acc.account_name, acc.bank.name, user.rows[0].id]
    )

    const token = jwt.sign({
      id: user.rows[0].id,
      username: user.rows[0].username,
      is_admin: user.rows[0].is_admin,
      company: user.rows[0].company
    }, process.env.JWT_SECRET)

    res.json({ token })

  } catch (e) {
    console.log(e.response?.data || e.message)
    res.status(500).json({ message: "Signup failed" })
  }
})

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body

  const user = await pool.query("SELECT * FROM users WHERE username=$1", [username])

  if (!user.rows.length) return res.status(400).json({ message: "User not found" })

  const valid = await bcrypt.compare(password, user.rows[0].password)
  if (!valid) return res.status(400).json({ message: "Wrong password" })

  const token = jwt.sign({
    id: user.rows[0].id,
    username: user.rows[0].username,
    is_admin: user.rows[0].is_admin,
    company: user.rows[0].company
  }, process.env.JWT_SECRET)

  res.json({ token })
})

/* ================= USER ================= */

app.get("/api/me", auth, async (req, res) => {
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])
  res.json(user.rows[0])
})

/* ================= TRANSACTIONS ================= */

app.get("/api/transactions", auth, async (req, res) => {
  const tx = await pool.query(
    "SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  )
  res.json(tx.rows)
})

/* ================= PLANS ================= */

app.get("/api/plans", auth, async (req, res) => {
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  const plans = await pool.query(
    "SELECT * FROM plans WHERE company=$1 OR company IS NULL",
    [user.rows[0].company]
  )

  const result = plans.rows.map(p => ({
    ...p,
    price: user.rows[0].is_top_user ? (p.top_price || p.price) : p.price
  }))

  res.json(result)
})

/* ================= BUY DATA ================= */

app.post("/api/buy-data", auth, async (req, res) => {
  const { plan_id, phone, pin } = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  const valid = await bcrypt.compare(pin, user.rows[0].pin)
  if (!valid) return res.status(400).json({ message: "Invalid PIN" })

  const plan = await pool.query("SELECT * FROM plans WHERE id=$1", [plan_id])

  if (!plan.rows.length) return res.status(400).json({ message: "Plan not found" })

  const price = user.rows[0].is_top_user ? (plan.rows[0].top_price || plan.rows[0].price) : plan.rows[0].price

  if (user.rows[0].wallet_balance < price) {
    return res.status(400).json({ message: "Insufficient balance" })
  }

  const newBalance = user.rows[0].wallet_balance - price

  await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, req.user.id])

  const ref = "DATA-" + uuidv4()

  await pool.query(
    `INSERT INTO transactions(user_id,type,amount,phone,reference,status)
     VALUES($1,'DATA',$2,$3,$4,'SUCCESS')`,
    [req.user.id, price, phone, ref]
  )

  sendWalletUpdate(req.user.id, newBalance)

  res.json({ success: true })
})

/* ================= BUY AIRTIME (ONLY MAYCONNECT) ================= */

app.post("/api/buy-airtime", auth, async (req, res) => {
  const { phone, amount, pin } = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  if (user.rows[0].company !== "mayconnect") {
    return res.status(403).json({ message: "Airtime disabled for your company" })
  }

  const valid = await bcrypt.compare(pin, user.rows[0].pin)
  if (!valid) return res.status(400).json({ message: "Invalid PIN" })

  if (user.rows[0].wallet_balance < amount) {
    return res.status(400).json({ message: "Insufficient balance" })
  }

  const newBalance = user.rows[0].wallet_balance - amount

  await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, req.user.id])

  const ref = "AIRTIME-" + uuidv4()

  await pool.query(
    `INSERT INTO transactions(user_id,type,amount,phone,reference,status)
     VALUES($1,'AIRTIME',$2,$3,$4,'SUCCESS')`,
    [req.user.id, amount, phone, ref]
  )

  sendWalletUpdate(req.user.id, newBalance)

  res.json({ success: true })
})

/* ================= FUND INIT ================= */

app.post("/api/fund/init", auth, async (req, res) => {
  const { amount } = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  const reference = "FUND-" + uuidv4()

  const response = await axios.post(
    "https://api.paystack.co/transaction/initialize",
    {
      email: user.rows[0].email,
      amount: Number(amount) * 100,
      reference
    },
    { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
  )

  res.json({ url: response.data.data.authorization_url })
})

/* ================= WEBHOOK ================= */

app.post("/api/paystack/webhook", async (req, res) => {
  try {
    const event = req.body

    if (event.event === "charge.success") {
      const email = event.data.customer.email
      const amount = event.data.amount / 100

      const user = await pool.query("SELECT * FROM users WHERE email=$1", [email])

      if (user.rows.length) {
        const newBalance = Number(user.rows[0].wallet_balance) + amount

        await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.rows[0].id])

        sendWalletUpdate(user.rows[0].id, newBalance)
      }
    }

    res.sendStatus(200)
  } catch {
    res.sendStatus(500)
  }
})

/* ================= CHANGE PASSWORD ================= */

app.post("/api/change-password", auth, async (req, res) => {
  const { oldPass, newPass } = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  const valid = await bcrypt.compare(oldPass, user.rows[0].password)
  if (!valid) return res.status(400).json({ message: "Wrong old password" })

  const hash = await bcrypt.hash(newPass, 10)

  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.user.id])

  res.json({ message: "Password updated" })
})

/* ================= CHANGE PIN ================= */

app.post("/api/change-pin", auth, async (req, res) => {
  const { oldPin, newPin } = req.body

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])

  const valid = await bcrypt.compare(oldPin, user.rows[0].pin)
  if (!valid) return res.status(400).json({ message: "Wrong old PIN" })

  const hash = await bcrypt.hash(newPin, 10)

  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, req.user.id])

  res.json({ message: "PIN updated" })
})

/* ================= ADMIN WITHDRAW ================= */

app.post("/api/admin/withdraw", auth, async (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ message: "Forbidden" })

  const { username, amount } = req.body

  const user = await pool.query(
    "SELECT * FROM users WHERE username=$1 AND company=$2",
    [username, req.user.company]
  )

  if (!user.rows.length) return res.status(400).json({ message: "User not found" })

  if (user.rows[0].wallet_balance < amount) {
    return res.status(400).json({ message: "Insufficient balance" })
  }

  const newBalance = user.rows[0].wallet_balance - amount

  await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.rows[0].id])

  sendWalletUpdate(user.rows[0].id, newBalance)

  res.json({ message: "Withdraw successful" })
})

/* ================= TOP USERS ================= */

app.post("/api/admin/add-top-user", auth, async (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ message: "Forbidden" })

  const { email } = req.body

  await pool.query(
    "UPDATE users SET is_top_user=true WHERE email=$1 AND company=$2",
    [email, req.user.company]
  )

  res.json({ message: "Top user added" })
})

app.post("/api/admin/remove-top-user", auth, async (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ message: "Forbidden" })

  const { email } = req.body

  await pool.query(
    "UPDATE users SET is_top_user=false WHERE email=$1 AND company=$2",
    [email, req.user.company]
  )

  res.json({ message: "Top user removed" })
})

/* ================= REVERSAL ================= */

app.post("/api/admin/reverse", auth, async (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ message: "Forbidden" })

  const { reference } = req.body

  const tx = await pool.query("SELECT * FROM transactions WHERE reference=$1", [reference])

  if (!tx.rows.length) return res.status(400).json({ message: "Not found" })

  if (tx.rows[0].status === "REVERSED") {
    return res.status(400).json({ message: "Already reversed" })
  }

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [tx.rows[0].user_id])

  const newBalance = Number(user.rows[0].wallet_balance) + Number(tx.rows[0].amount)

  await pool.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.rows[0].id])

  await pool.query("UPDATE transactions SET status='REVERSED' WHERE reference=$1", [reference])

  sendWalletUpdate(user.rows[0].id, newBalance)

  res.json({ message: "Transaction reversed" })
})

/* ================= SERVER ================= */

server.listen(process.env.PORT || 5000, () => {
  console.log("🚀 SERVER READY ✅")
})