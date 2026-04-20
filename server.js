require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const http = require("http");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

/* ================= CONFIG ================= */
const ADMIN_EMAILS = [
  "abubakarmubarak3456@gmail.com",
  "mayconnectofficial@gmail.com",
  "bashirahmadt11696@gmail.com",
  "abdullahihabibudanalhaji@gmail.com",
  "Sadeeqtukur765@gmail.com"
];

const PAYSTACK_KEYS = {
  mayconnect: {
    secret: process.env.PAYSTACK_SECRET_LIVE,
    public: process.env.PAYSTACK_PUBLIC_LIVE
  },
  teeversh: {
    secret: process.env.PAYSTACK_SECRET_TEEVERSH,
    public: process.env.PAYSTACK_PUBLIC_TEEVERSH
  },
  bnhabeeb: {
    secret: process.env.PAYSTACK_SECRET_BNHABEEB,
    public: process.env.PAYSTACK_PUBLIC_BNHABEEB
  },
  sadeeq: {
    secret: process.env.PAYSTACK_SECRET_SADEEQ,
    public: process.env.PAYSTACK_PUBLIC_SADEEQ
  }
};

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: "*" }));
// Use raw body for webhook signature verification
app.use((req, res, next) => {
  if (req.originalUrl === "/api/paystack/webhook") {
    express.raw({ type: "application/json" })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

/* ================= DATABASE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ================= HELPERS ================= */
const getCompanyAdmin = async (company) => {
  const admin = await pool.query(
    "SELECT id FROM users WHERE company=$1 AND is_admin=TRUE ORDER BY id ASC LIMIT 1",
    [company]
  );
  return admin.rows[0]?.id || null;
};

const getPaystackKey = (company, type = "secret") => {
  const keys = PAYSTACK_KEYS[company] || PAYSTACK_KEYS.mayconnect;
  return keys[type];
};

/* ================= WS ================= */
const clients = new Map();
wss.on("connection", (ws, req) => {
  try {
    const token = new URL(req.url, "http://x").searchParams.get("token");
    const user = jwt.verify(token, process.env.JWT_SECRET);
    clients.set(user.id, ws);
    ws.on("close", () => clients.delete(user.id));
  } catch {
    ws.close();
  }
});
function sendWalletUpdate(userId, balance) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "wallet_update", balance }));
}

/* ================= AUTH ================= */
function auth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ message: "Admin only" });
  next();
}

/* ================= SIGNUP ================= */
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, pin, company } = req.body;
    if (!username ||!email ||!password ||!pin)
      return res.status(400).json({ message: "All fields required" });

    const userCompany = company || "mayconnect";
    const hash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);
    const isAdmin = ADMIN_EMAILS.includes(email);

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [username, email, hash, pinHash, isAdmin, userCompany]
    );

    let customer_code = null, account_number = null, account_name = null, bank_name = null;

    try {
      const paystackSecret = getPaystackKey(userCompany, "secret");
      if (paystackSecret) {
        const customer = await axios.post(
          "https://api.paystack.co/customer",
          { email, first_name: username },
          { headers: { Authorization: `Bearer ${paystackSecret}` } }
        );
        customer_code = customer.data.data.customer_code;

        const account = await axios.post(
          "https://api.paystack.co/dedicated_account",
          { customer: customer_code, preferred_bank: "wema-bank" },
          { headers: { Authorization: `Bearer ${paystackSecret}` } }
        );

        const acc = account.data.data;
        account_number = acc.account_number;
        account_name = acc.account_name;
        bank_name = acc.bank.name;
      }
    } catch (e) {
      console.log("PAYSTACK ERROR:", e.response?.data || e.message);
    }

    await pool.query(
      `UPDATE users SET customer_code=$1, account_number=$2, account_name=$3, bank_name=$4 WHERE id=$5`,
      [customer_code, account_number, account_name, bank_name, user.rows[0].id]
    );

    const token = jwt.sign(
      { id: user.rows[0].id, username: user.rows[0].username, is_admin: user.rows[0].is_admin, company: user.rows[0].company },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } catch (e) {
    console.log("SIGNUP ERROR:", e.message);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* ================= LOGIN ================= */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  if (!user.rows.length) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign(
    { id: user.rows[0].id, username: user.rows[0].username, is_admin: user.rows[0].is_admin, company: user.rows[0].company },
    process.env.JWT_SECRET
  );
  res.json({ token });
});

/* ================= USER INFO ================= */
app.get("/api/me", auth, async (req, res) => {
  const user = await pool.query("SELECT id,username,email,wallet_balance,admin_wallet,is_admin,is_top_user,company,account_number,account_name,bank_name,created_at FROM users WHERE id=$1", [req.user.id]);
  res.json(user.rows[0]);
});

/* ================= TRANSACTIONS ================= */
app.get("/api/transactions", auth, async (req, res) => {
  const tx = await pool.query("SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC LIMIT 100", [req.user.id]);
  res.json(tx.rows);
});

/* ================= PLANS - WITH RESTRICTED LOGIC ================= */
app.get("/api/plans", auth, async (req, res) => {
  const user = await pool.query("SELECT is_top_user, company FROM users WHERE id=$1", [req.user.id]);
  const { is_top_user, company } = user.rows[0];

  const plans = await pool.query(
    `SELECT * FROM plans
     WHERE is_active = TRUE AND (restricted = FALSE OR company = $1)
     ORDER BY network, price ASC`,
    [company]
  );

  const result = plans.rows.map(p => ({
   ...p,
    price: is_top_user? (p.top_price || p.price) : p.price
  }));
  res.json(result);
});

/* ================= BUY DATA - WITH PROFIT SPLIT ================= */
app.post("/api/buy-data", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { plan_id, phone, pin } = req.body;

    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];

    if (!await bcrypt.compare(pin, user.pin)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Invalid PIN" });
    }

    const planRes = await client.query("SELECT * FROM plans WHERE id=$1 AND is_active=TRUE", [plan_id]);
    if (!planRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Plan not found or inactive" });
    }
    const plan = planRes.rows[0];

    // Check restricted plans
    if (plan.restricted && plan.company!== user.company) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Plan restricted to company users" });
    }

    const price = user.is_top_user? (plan.top_price || plan.price) : plan.price;
    if (Number(user.wallet_balance) < Number(price)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient balance" });
    }

    const newBalance = Number(user.wallet_balance) - Number(price);
    await client.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.id]);

    const ref = "DATA-" + uuidv4();
    const cost = plan.cost;

    const txRes = await client.query(
      `INSERT INTO transactions(user_id,plan_id,type,amount,cost,phone,network,reference,status)
       VALUES($1,$2,'DATA',$3,$4,$5,$6,$7,'SUCCESS') RETURNING *`,
      [user.id, plan.id, price, cost, phone, plan.network, ref]
    );

    // Credit profit to company admin_wallet
    const adminId = await getCompanyAdmin(user.company);
    const profit = Number(price) - Number(cost);
    if (adminId && profit > 0) {
      await client.query("UPDATE users SET admin_wallet = admin_wallet + $1 WHERE id=$2", [profit, adminId]);
      await client.query(
        `INSERT INTO profits(transaction_id,type,amount,reference,credited_to_user_id)
         VALUES($1,'sale',$2,$3,$4)`,
        [txRes.rows[0].id, profit, ref, adminId]
      );
    }

    await client.query("COMMIT");
    sendWalletUpdate(user.id, newBalance);
    res.json({ success: true, reference: ref, balance: newBalance });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("BUY DATA ERROR:", e.message);
    res.status(500).json({ message: "Purchase failed" });
  } finally {
    client.release();
  }
});

/* ================= BUY AIRTIME ================= */
app.post("/api/buy-airtime", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { phone, amount, network, pin } = req.body;

    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];

    if (user.company!== "mayconnect") {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Airtime disabled for your company" });
    }
    if (!await bcrypt.compare(pin, user.pin)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Invalid PIN" });
    }
    if (Number(user.wallet_balance) < Number(amount)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient balance" });
    }

    const newBalance = Number(user.wallet_balance) - Number(amount);
    await client.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.id]);

    const ref = "AIRTIME-" + uuidv4();
    const cost = Number(amount) * 0.98; // assume 2% profit

    const txRes = await client.query(
      `INSERT INTO transactions(user_id,type,amount,cost,phone,network,reference,status)
       VALUES($1,'AIRTIME',$2,$3,$4,$5,$6,'SUCCESS') RETURNING *`,
      [user.id, amount, cost, phone, network, ref]
    );

    const adminId = await getCompanyAdmin(user.company);
    const profit = Number(amount) - cost;
    if (adminId && profit > 0) {
      await client.query("UPDATE users SET admin_wallet = admin_wallet + $1 WHERE id=$2", [profit, adminId]);
      await client.query(
        `INSERT INTO profits(transaction_id,type,amount,reference,credited_to_user_id)
         VALUES($1,'sale',$2,$3,$4)`,
        [txRes.rows[0].id, profit, ref, adminId]
      );
    }

    await client.query("COMMIT");
    sendWalletUpdate(user.id, newBalance);
    res.json({ success: true, reference: ref, balance: newBalance });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("BUY AIRTIME ERROR:", e.message);
    res.status(500).json({ message: "Purchase failed" });
  } finally {
    client.release();
  }
});

/* ================= FUND INIT ================= */
app.post("/api/fund/init", auth, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ message: "Minimum funding is ₦100" });

  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const paystackSecret = getPaystackKey(user.rows[0].company, "secret");
  const reference = "FUND-" + uuidv4();

  try {
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: user.rows[0].email,
        amount: Number(amount) * 100,
        reference,
        metadata: { user_id: user.rows[0].id, company: user.rows[0].company }
      },
      { headers: { Authorization: `Bearer ${paystackSecret}` } }
    );
    res.json({ url: response.data.data.authorization_url, reference });
  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Unable to initialize payment" });
  }
});

/* ================= PAYSTACK WEBHOOK - MULTI COMPANY ================= */
app.post("/api/paystack/webhook", async (req, res) => {
  try {
    const hash = crypto.createHmac('sha512', getPaystackKey('mayconnect', 'secret'))
     .update(req.body)
     .digest('hex');

    // We can't know which company until we check metadata, so we verify against all
    const event = JSON.parse(req.body);

    if (event.event === "charge.success") {
      const { user_id, company } = event.data.metadata || {};
      const amount = event.data.amount / 100;
      const reference = event.data.reference;

      if (!user_id) return res.sendStatus(200);

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [user_id]);
        if (!userRes.rows.length) {
          await client.query("ROLLBACK");
          return res.sendStatus(200);
        }

        const newBalance = Number(userRes.rows[0].wallet_balance) + amount;
        await client.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user_id]);

        await client.query(
          `INSERT INTO transactions(user_id,type,amount,reference,status,description)
           VALUES($1,'WALLET_FUND',$2,$3,'SUCCESS','Wallet funding via Paystack')
           ON CONFLICT (reference) DO NOTHING`,
          [user_id, amount, reference]
        );

        await client.query("COMMIT");
        sendWalletUpdate(user_id, newBalance);
      } catch (e) {
        await client.query("ROLLBACK");
        console.log("WEBHOOK TX ERROR:", e.message);
      } finally {
        client.release();
      }
    }
    res.sendStatus(200);
  } catch (e) {
    console.log("WEBHOOK ERROR:", e.message);
    res.sendStatus(500);
  }
});

/* ================= CHANGE PASSWORD ================= */
app.post("/api/change-password", auth, async (req, res) => {
  const { oldPass, newPass } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(oldPass, user.rows[0].password)) return res.status(400).json({ message: "Wrong old password" });
  const hash = await bcrypt.hash(newPass, 10);
  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, user.rows[0].id]);
  res.json({ message: "Password updated" });
});

/* ================= CHANGE PIN ================= */
app.post("/api/change-pin", auth, async (req, res) => {
  const { oldPin, newPin } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(oldPin, user.rows[0].pin)) return res.status(400).json({ message: "Wrong old PIN" });
  const hash = await bcrypt.hash(newPin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, user.rows[0].id]);
  res.json({ message: "PIN updated" });
});

/* ================= ADMIN: PROFIT DASHBOARD ================= */
app.get("/admin/profit", auth, adminOnly, async (req, res) => {
  const { from, to, company } = req.query;
  const userCompany = req.user.company;

  let query = `
    SELECT DATE(t.created_at) as date,
           SUM(t.profit) as total_profit,
           COUNT(*) as total_sales,
           u.company
    FROM transactions t
    JOIN users u ON t.user_id = u.id
    WHERE t.status = 'SUCCESS' AND t.profit > 0
  `;
  const params = [];

  if (from) {
    params.push(from);
    query += ` AND t.created_at >= $${params.length}`;
  }
  if (to) {
    params.push(to);
    query += ` AND t.created_at <= $${params.length}`;
  }
  if (company) {
    params.push(company);
    query += ` AND u.company = $${params.length}`;
  } else {
    params.push(userCompany);
    query += ` AND u.company = $${params.length}`;
  }

  query += ` GROUP BY DATE(t.created_at), u.company ORDER BY date DESC`;

  const result = await pool.query(query, params);
  const adminWallet = await pool.query("SELECT admin_wallet FROM users WHERE id=$1", [req.user.id]);

  res.json({
    daily: result.rows,
    admin_wallet: adminWallet.rows[0].admin_wallet,
    total: result.rows.reduce((sum, r) => sum + Number(r.total_profit), 0)
  });
});

/* ================= ADMIN: TOP USERS MANAGEMENT ================= */
app.get("/admin/top-users", auth, adminOnly, async (req, res) => {
  const users = await pool.query("SELECT * FROM top_users WHERE id IN (SELECT id FROM users WHERE company=$1)", [req.user.company]);
  res.json(users.rows);
});

app.post("/admin/top-users/add", auth, adminOnly, async (req, res) => {
  const { email } = req.body;
  const result = await pool.query(
    "UPDATE users SET is_top_user=true WHERE email=$1 AND company=$2 RETURNING id,username,email",
    [email, req.user.company]
  );
  if (!result.rows.length) return res.status(404).json({ message: "User not found in your company" });
  res.json({ message: "Top user added", user: result.rows[0] });
});

app.delete("/admin/top-users/remove", auth, adminOnly, async (req, res) => {
  const { email } = req.body;
  const result = await pool.query(
    "UPDATE users SET is_top_user=false WHERE email=$1 AND company=$2 RETURNING id",
    [email, req.user.company]
  );
  if (!result.rows.length) return res.status(404).json({ message: "User not found in your company" });
  res.json({ message: "Top user removed" });
});

/* ================= ADMIN: WITHDRAW REQUEST ================= */
app.post("/admin/withdraw-request", auth, adminOnly, async (req, res) => {
  const { amount, bank_name, account_number, account_name } = req.body;
  const user = await pool.query("SELECT admin_wallet FROM users WHERE id=$1", [req.user.id]);

  if (Number(user.rows[0].admin_wallet) < Number(amount)) {
    return res.status(400).json({ message: "Insufficient admin wallet balance" });
  }

  const reference = "WD-" + uuidv4();
  await pool.query(
    `INSERT INTO withdrawals(user_id,amount,bank_name,account_number,account_name,reference,status)
     VALUES($1,$2,$3,$4,$5,$6,'PENDING')`,
    [req.user.id, amount, bank_name, account_number, account_name, reference]
  );

  res.json({ message: "Withdrawal request created", reference });
});

app.get("/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const wd = await pool.query("SELECT * FROM withdrawals WHERE user_id=$1 ORDER BY id DESC", [req.user.id]);
  res.json(wd.rows);
});

app.post("/admin/withdraw/approve", auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { reference } = req.body;

    const wd = await client.query("SELECT * FROM withdrawals WHERE reference=$1 AND user_id=$2 FOR UPDATE", [reference, req.user.id]);
    if (!wd.rows.length) throw new Error("Withdrawal not found");
    if (wd.rows[0].status!== 'PENDING') throw new Error("Already processed");

    const user = await client.query("SELECT admin_wallet FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    if (Number(user.rows[0].admin_wallet) < Number(wd.rows[0].amount)) throw new Error("Insufficient admin balance");

    await client.query("UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2", [wd.rows[0].amount, req.user.id]);
    await client.query("UPDATE withdrawals SET status='PAID', processed_at=NOW() WHERE reference=$1", [reference]);

    await client.query("COMMIT");
    res.json({ message: "Withdrawal approved and paid" });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ message: e.message });
  } finally {
    client.release();
  }
});

/* ================= ADMIN: OLD WITHDRAW - DEPRECATE ================= */
app.post("/api/admin/withdraw", auth, adminOnly, async (req, res) => {
  return res.status(410).json({ message: "Use /admin/withdraw-request instead" });
});

/* ================= ADMIN: OLD TOP USER ROUTES - DEPRECATE ================= */
app.post("/api/admin/add-top-user", auth, adminOnly, async (req, res) => {
  return res.status(410).json({ message: "Use /admin/top-users/add instead" });
});
app.post("/api/admin/remove-top-user", auth, adminOnly, async (req, res) => {
  return res.status(410).json({ message: "Use /admin/top-users/remove instead" });
});

/* ================= TRANSACTION REVERSAL ================= */
app.post("/api/admin/reverse", auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { reference } = req.body;
    const tx = await client.query("SELECT * FROM transactions WHERE reference=$1 FOR UPDATE", [reference]);
    if (!tx.rows.length) throw new Error("Transaction not found");
    if (tx.rows[0].status === "REVERSED") throw new Error("Already reversed");
    if (tx.rows[0].status!== "SUCCESS") throw new Error("Only SUCCESS tx can be reversed");

    const user = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [tx.rows[0].user_id]);
    const newBalance = Number(user.rows[0].wallet_balance) + Number(tx.rows[0].amount);

    await client.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.rows[0].id]);
    await client.query("UPDATE transactions SET status='REVERSED' WHERE reference=$1", [reference]);

    // Reverse profit from admin_wallet
    if (tx.rows[0].profit > 0) {
      const adminId = await getCompanyAdmin(user.rows[0].company);
      if (adminId) {
        await client.query("UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2", [tx.rows[0].profit, adminId]);
      }
    }

    await client.query("COMMIT");
    sendWalletUpdate(user.rows[0].id, newBalance);
    res.json({ message: "Transaction reversed" });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ message: e.message });
  } finally {
    client.release();
  }
});

/* ================= SERVER ================= */
server.listen(process.env.PORT || 5000, () => console.log("🚀 SERVER READY ✅"));