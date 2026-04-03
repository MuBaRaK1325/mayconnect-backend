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

app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}))

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
    const url = new URL(req.url, "http://localhost")
    const token = url.searchParams.get("token")

    if (!token) return ws.close()

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    clients.set(decoded.id, ws)

    ws.on("close", () => clients.delete(decoded.id))
  } catch {
    ws.close()
  }
})

function sendWalletUpdate(userId, balance) {
  const ws = clients.get(userId)
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "wallet_update", balance }))
  }
}

/* ================= AUTH ================= */

function auth(req, res, next) {
  const header = req.headers.authorization
  if (!header) return res.status(401).json({ message: "No token" })

  try {
    const token = header.split(" ")[1]
    req.user = jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ message: "Invalid token" })
  }
}

/* ================= HELPERS ================= */

function detectCompany(email) {
  if (email === "bashirahmadt11696@gmail.com") return "teeversh"
  if (email === "abdullahihabibudanalhaji@gmail.com") return "bnhabeeb"
  if (email === "Sadeeqtukur765@gmailcom") return "sadeeq"
  return "mayconnect"
}

/* ================= SIGNUP ================= */

app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, pin } = req.body

    if (!username || !email || !password || !pin)
      return res.status(400).json({ message: "All fields required" })

    if (!/^\d{4}$/.test(pin))
      return res.status(400).json({ message: "PIN must be 4 digits" })

    const exists = await pool.query(
      "SELECT id FROM users WHERE username=$1 OR email=$2",
      [username, email]
    )

    if (exists.rows.length)
      return res.status(400).json({ message: "User already exists" })

    const hash = await bcrypt.hash(password, 10)
    const pinHash = await bcrypt.hash(pin, 10)

    const isAdmin = ADMIN_EMAILS.includes(email)
    const company = detectCompany(email)

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,username,is_admin,company`,
      [username, email, hash, pinHash, isAdmin, company]
    )

    const token = jwt.sign(user.rows[0], process.env.JWT_SECRET, { expiresIn: "7d" })

    res.json({ token, user: user.rows[0] })

  } catch (err) {
    console.log("SIGNUP ERROR:", err)
    res.status(500).json({ message: err.message })
  }
})

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body

    const user = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    )

    if (!user.rows.length)
      return res.status(400).json({ message: "User not found" })

    const valid = await bcrypt.compare(password, user.rows[0].password)

    if (!valid)
      return res.status(400).json({ message: "Wrong password" })

    const token = jwt.sign({
      id: user.rows[0].id,
      username: user.rows[0].username,
      company: user.rows[0].company,
      is_admin: user.rows[0].is_admin
    }, process.env.JWT_SECRET, { expiresIn: "7d" })

    res.json({
      token,
      username: user.rows[0].username,
      wallet_balance: user.rows[0].wallet_balance,
      is_admin: user.rows[0].is_admin
    })

  } catch (err) {
    console.log("LOGIN ERROR:", err)
    res.status(500).json({ message: "Login error" })
  }
})

/* ================= GET PLANS (FIX FOR DASHBOARD) ================= */

app.get("/api/plans", auth, async (req, res) => {
  try {
    const plans = await pool.query(
      "SELECT * FROM plans WHERE company=$1",
      [req.user.company]
    )

    res.json(plans.rows)
  } catch (err) {
    console.log("PLANS ERROR:", err)
    res.status(500).json({ message: "Failed to load plans" })
  }
})

/* ================= BUY DATA ================= */

app.post("/api/buy-data", auth, async (req, res) => {
  const client = await pool.connect()

  try {
    const { plan_id, phone, pin } = req.body

    await client.query("BEGIN")

    const user = await client.query(
      "SELECT * FROM users WHERE id=$1",
      [req.user.id]
    )

    const valid = await bcrypt.compare(pin, user.rows[0].pin)
    if (!valid) throw new Error("Invalid PIN")

    const plan = await client.query(
      "SELECT * FROM plans WHERE id=$1",
      [plan_id]
    )

    if (!plan.rows.length) throw new Error("Invalid plan")

    const price = Number(plan.rows[0].price)

    if (user.rows[0].wallet_balance < price)
      throw new Error("Insufficient balance")

    const reference = "DATA-" + uuidv4()

    let provider = "unknown"

    try {
      if (user.rows[0].company === "mayconnect") {
        provider = "subpadi"

        await axios.post("https://subpadi.com/api/data/", {
          network: 1,
          mobile_number: phone,
          plan: plan.rows[0].plan_id,
          Ported_number: true
        }, {
          headers: {
            Authorization: `Token ${process.env.SUBPADI_TOKEN}`
          }
        })

      } else {
        provider = "maitama"

        await axios.post(process.env.VTU_ENDPOINT, {
          phone,
          plan: plan.rows[0].name
        })
      }

    } catch {
      provider = "cheapdata"

      await axios.post(
        "https://www.cheapdatahub.ng/api/v1/resellers/data/purchase/",
        {
          bundle_id: plan.rows[0].plan_id,
          phone_number: phone
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.CHEAPDATA_KEY}`
          }
        }
      )
    }

    await client.query(
      "UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
      [price, req.user.id]
    )

    await client.query(
      `INSERT INTO transactions(user_id,type,amount,phone,reference,status)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [req.user.id, "DATA", price, phone, reference, "PENDING"]
    )

    await client.query("COMMIT")

    sendWalletUpdate(req.user.id, user.rows[0].wallet_balance - price)

    res.json({ success: true, reference, provider })

  } catch (err) {
    await client.query("ROLLBACK")
    console.log("BUY ERROR:", err)
    res.status(400).json({ message: err.message })
  } finally {
    client.release()
  }
})

/* ================= STATUS CHECKER ================= */

app.get("/api/tx/:reference", auth, async (req, res) => {
  const { reference } = req.params

  const tx = await pool.query(
    "SELECT * FROM transactions WHERE reference=$1",
    [reference]
  )

  if (!tx.rows.length)
    return res.status(404).json({ message: "Transaction not found" })

  res.json(tx.rows[0])
})

/* ================= WEBHOOK ================= */

app.post("/api/webhook", async (req, res) => {
  try {
    const signature = req.headers["x-signature"]

    if (!signature) return res.sendStatus(400)

    const hash = crypto
      .createHmac("sha256", process.env.WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest("hex")

    if (signature !== hash) {
      console.log("INVALID SIGNATURE")
      return res.sendStatus(403)
    }

    const { reference, status } = req.body

    const tx = await pool.query(
      "SELECT * FROM transactions WHERE reference=$1",
      [reference]
    )

    if (!tx.rows.length) return res.sendStatus(404)

    await pool.query(
      "UPDATE transactions SET status=$1 WHERE reference=$2",
      [status.toUpperCase(), reference]
    )

    if (status.toLowerCase() === "failed") {
      await pool.query(
        "UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2",
        [tx.rows[0].amount, tx.rows[0].user_id]
      )

      sendWalletUpdate(tx.rows[0].user_id, tx.rows[0].amount)
    }

    res.sendStatus(200)

  } catch (err) {
    console.log("WEBHOOK ERROR:", err)
    res.sendStatus(500)
  }
})

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000

server.listen(PORT, () => {
  console.log("🚀 SERVER RUNNING ON PORT", PORT)
})