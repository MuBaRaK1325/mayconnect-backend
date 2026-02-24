require("dotenv").config()

const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { Pool } = require("pg")
const { v4: uuidv4 } = require("uuid")

const app = express()

app.use(cors())
app.use(express.json())

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

/* ================= JWT ================= */

function createToken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d"
  })
}

/* ================= AUTH ================= */

function auth(req, res, next) {

  const header = req.headers.authorization

  if (!header) return res.status(401).json({ error: "No token" })

  const token = header.split(" ")[1]

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {

    if (err) return res.status(403).json({ error: "Invalid token" })

    req.user = user

    next()
  })
}

/* ================= HEALTH ================= */

app.get("/", (req, res) => {
  res.send("MAYCONNECT API LIVE")
})

/* ================= SIGNUP ================= */

app.post("/api/signup", async (req, res) => {

  try {

    const { username, email, password } = req.body

    if (!username || !password)
      return res.status(400).json({ error: "Missing fields" })

    const hash = await bcrypt.hash(password, 10)

    const user = await pool.query(
      `INSERT INTO users (name,email,password)
       VALUES ($1,$2,$3)
       RETURNING id,name`,
      [username, email || null, hash]
    )

    res.json({
      token: createToken(user.rows[0].id),
      name: user.rows[0].name
    })

  } catch (err) {

    console.log(err)

    res.status(500).json({ error: "Signup failed" })

  }

})

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {

  try {

    const { username, password } = req.body

    const result = await pool.query(
      "SELECT * FROM users WHERE name=$1",
      [username]
    )

    if (!result.rows.length)
      return res.status(401).json({ error: "Invalid login" })

    const user = result.rows[0]

    const valid = await bcrypt.compare(password, user.password)

    if (!valid)
      return res.status(401).json({ error: "Invalid login" })

    res.json({
      token: createToken(user.id),
      name: user.name
    })

  } catch (err) {

    console.log(err)

    res.status(500).json({ error: "Login failed" })

  }

})

/* ================= WALLET ================= */

app.get("/api/wallet", auth, async (req, res) => {

  const result = await pool.query(
    `SELECT wallet_balance,admin_wallet,is_admin,name
     FROM users WHERE id=$1`,
    [req.user.id]
  )

  res.json(result.rows[0])

})

/* ================= PLANS ================= */

app.get("/api/plans", auth, async (req, res) => {

  const plans = await pool.query("SELECT * FROM plans ORDER BY network")

  res.json(plans.rows)

})

/* ================= SET PIN ================= */

app.post("/api/set-pin", auth, async (req, res) => {

  const { pin } = req.body

  const hash = await bcrypt.hash(pin, 10)

  await pool.query(
    "UPDATE users SET pin=$1 WHERE id=$2",
    [hash, req.user.id]
  )

  res.json({ success: true })

})

/* ================= VERIFY PIN ================= */

app.post("/api/verify-pin", auth, async (req, res) => {

  const { pin } = req.body

  const result = await pool.query(
    "SELECT pin FROM users WHERE id=$1",
    [req.user.id]
  )

  const valid = await bcrypt.compare(pin, result.rows[0].pin)

  if (!valid) return res.status(401).json({ error: "Wrong PIN" })

  res.json({ success: true })

})

/* ================= PURCHASE ================= */

app.post("/api/purchase", auth, async (req, res) => {

  try {

    const { plan } = req.body

    const planRes = await pool.query(
      "SELECT * FROM plans WHERE plan_id=$1",
      [plan]
    )

    if (!planRes.rows.length)
      return res.status(400).json({ error: "Invalid plan" })

    const planData = planRes.rows[0]

    const userRes = await pool.query(
      "SELECT * FROM users WHERE id=$1",
      [req.user.id]
    )

    const user = userRes.rows[0]

    const amount = user.is_admin
      ? planData.cost
      : planData.price

    if (user.wallet_balance < amount)
      return res.status(400).json({ error: "Insufficient funds" })

    const profit = user.is_admin
      ? 0
      : planData.price - planData.cost

    await pool.query("BEGIN")

    await pool.query(
      "UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
      [amount, user.id]
    )

    if (!user.is_admin) {

      await pool.query(
        "UPDATE users SET admin_wallet=admin_wallet+$1 WHERE is_admin=true",
        [profit]
      )

    }

    await pool.query(
      `INSERT INTO transactions
      (user_id,type,amount,profit,reference)
      VALUES ($1,$2,$3,$4,$5)`,
      [user.id, "data", amount, profit, uuidv4()]
    )

    await pool.query("COMMIT")

    res.json({ success: true })

  } catch (err) {

    await pool.query("ROLLBACK")

    console.log(err)

    res.status(500).json({ error: "Purchase failed" })

  }

})

/* ================= ADMIN WITHDRAW ================= */

app.post("/api/admin/withdraw", auth, async (req, res) => {

  const { amount, bank, account } = req.body

  const admin = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.user.id]
  )

  if (!admin.rows[0].is_admin)
    return res.status(403).json({ error: "Admin only" })

  if (admin.rows[0].admin_wallet < amount)
    return res.status(400).json({ error: "Not enough profit" })

  await pool.query(
    "UPDATE users SET admin_wallet=admin_wallet-$1 WHERE id=$2",
    [amount, req.user.id]
  )

  res.json({
    success: true,
    message: "Withdrawal requested"
  })

})

/* ================= TRANSACTIONS ================= */

app.get("/api/transactions", auth, async (req, res) => {

  const tx = await pool.query(
    "SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  )

  res.json(tx.rows)

})

/* ================= CRON JOB ================= */

setInterval(async () => {

  console.log("Cron running")

}, 1000 * 60 * 10)

/* ================= START ================= */

const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
  console.log("Server running")
})