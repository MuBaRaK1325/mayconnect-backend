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
const rateLimit = require("express-rate-limit");

const app = express();
app.set('trust proxy', 1);

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

const PAYSTACK_KEYS = JSON.parse(process.env.PAYSTACK_KEYS || "{}");
console.log("Loaded Paystack keys for:", Object.keys(PAYSTACK_KEYS));

/* ================= VTU PROVIDER CONFIG - MULTI COMPANY ================= */
const VTU_PROVIDERS = {
  maitama: {
    base_url: process.env.MAITAMA_BASE_URL,
    tokens: {
      mayconnect: process.env.MAITAMA_TOKEN_MAYCONNECT,
      teeversh: process.env.MAITAMA_TOKEN_TEEVERSH,
      sadeeq: process.env.MAITAMA_TOKEN_SADEEQ,
      bnhabeeb: process.env.MAITAMA_TOKEN_BNHABEEB
    }
  },
  cheapdatahub: {
    data_url: process.env.CHEAPDATAHUB_DATA_URL,
    airtime_url: process.env.CHEAPDATAHUB_AIRTIME_URL,
    token: process.env.CHEAPDATAHUB_TOKEN,
    userid: process.env.CHEAPDATAHUB_USERID
  },
  subpadi: {
    base_url: process.env.SUBPADI_BASE_URL,
    api_key: process.env.SUBPADI_KEY
  }
};

/* ================= RATE LIMITERS ================= */
const buyDataLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { message: "Too many purchase attempts. Try again in 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

const fundInitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { message: "Too many funding requests. Try again in 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: "*" }));
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
  return keys?.[type] || null;
};

const getUser = async (id) => {
  const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return res.rows[0];
};

async function createDedicatedAccount(user) {
  const paystackSecret = getPaystackKey(user.company, "secret");
  if (!paystackSecret) return null;
  if (!user.phone) throw new Error("Phone number required to create virtual account. Please update your profile.");

  try {
    let customer_code;
    try {
      const existing = await axios.get(
        `https://api.paystack.co/customer/${user.email}`,
        { headers: { Authorization: `Bearer ${paystackSecret}` } }
      );
      customer_code = existing.data.data.customer_code;
      if (!existing.data.data.phone) {
        await axios.put(
          `https://api.paystack.co/customer/${customer_code}`,
          { phone: user.phone },
          { headers: { Authorization: `Bearer ${paystackSecret}` } }
        );
      }
    } catch (e) {
      if (e.response?.status === 404) {
        const newCustomer = await axios.post(
          "https://api.paystack.co/customer",
          { email: user.email, first_name: user.username, last_name: user.company, phone: user.phone },
          { headers: { Authorization: `Bearer ${paystackSecret}` } }
        );
        customer_code = newCustomer.data.data.customer_code;
      } else {
        throw e;
      }
    }

    const account = await axios.post(
      "https://api.paystack.co/dedicated_account",
      { customer: customer_code, preferred_bank: "wema-bank" },
      { headers: { Authorization: `Bearer ${paystackSecret}` } }
    );

    const acc = account.data.data;
    await pool.query(
      `UPDATE users SET customer_code=$1, account_number=$2, account_name=$3, bank_name=$4 WHERE id=$5`,
      [customer_code, acc.account_number, acc.account_name, acc.bank.name, user.id]
    );
    return acc;
  } catch (e) {
    const errData = e.response?.data || e.message;
    console.log("PAYSTACK CREATE ACCOUNT ERROR:", JSON.stringify(errData));
    throw new Error(errData?.message || "Failed to create Paystack account");
  }
}

/* ================= VTU API CALLS - MAITAMA FIXED ================= */
async function callMaitamaData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.maitama;
  const api_token = tokens[company];

  if (!api_token) throw new Error(`No Maitama token configured for ${company}`);

  const payload = {
    plan: Number(api_plan_id),
    mobile_number: String(phone),
    network: Number(network_id)
  };

  console.log(`[Maitama] ${company} REQUEST:`, {
    url: `${base_url}/api/data`,
    payload,
    token_exists:!!api_token
  });

  try {
    const res = await axios.post(
      `${base_url}/api/data`,
      payload,
      {
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": `Bearer ${api_token}`
        },
        timeout: 30000
      }
    );

    console.log(`[Maitama] ${company} SUCCESS:`, res.data);

    const status = res.data.Status || res.data.status;
    if (status?.toLowerCase()!== "successful" && status?.toLowerCase()!== "success") {
      throw new Error(res.data.api_response || res.data.message || "Maitama purchase failed");
    }

    return res.data;
  } catch (err) {
    console.log(`[Maitama] ${company} ERROR:`, err.response?.status, err.response?.data);
    throw new Error(err.response?.data?.api_response || err.response?.data?.message || err.message || "Maitama API error");
  }
}

async function callCheapDataHubData(phone, network_id, api_plan_id) {
  const { data_url, token, userid } = VTU_PROVIDERS.cheapdatahub;
  const res = await axios.post(
    data_url,
    { network: network_id, plan: api_plan_id, mobile_number: phone, Ported_number: true, userid, api_token: token }
  );
  if (res.data.status!== "successful") throw new Error(res.data.message || "CheapDataHub failed");
  return res.data;
}

async function callSubPadiData(phone, network_id, api_plan_id) {
  const { base_url, api_key } = VTU_PROVIDERS.subpadi;
  const res = await axios.post(
    `${base_url}/data`,
    { network: network_id, plan: api_plan_id, phone, api_key }
  );
  if (!res.data.status) throw new Error(res.data.message || "SubPadi failed");
  return res.data;
}

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

function broadcastTopUserUpdate(company) {
  for (const [userId, ws] of clients.entries()) {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: "top_user_update", company }));
    }
  }
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

/* ================= TEMP HASH GENERATOR - DELETE AFTER USE ================= */
app.get('/api/generate-hash', async (req, res) => {
  const hash = await bcrypt.hash('admin123', 10);
  res.json({
    password: 'admin123',
    hash: hash
  });
});

/* ================= DVA ROUTE - FIXED ================= */
app.post('/api/wallet/create-dva', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const userResult = await pool.query(
      'SELECT email, username, phone FROM users WHERE id = $1',
      [userId]
    );
    const user = userResult.rows[0];

    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.phone) return res.status(400).json({ error: 'Phone number missing. Update profile first.' });

    const response = await axios.post('https://api.paystack.co/dedicated_account', {
      customer: user.email,
      preferred_bank: 'wema-bank',
      phone: user.phone,
      first_name: user.username,
      last_name: 'VTU'
    }, {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const account = response.data.data;

    await pool.query(
      `UPDATE users SET
        dva_account_number = $1,
        dva_bank_name = $2,
        dva_account_name = $3
       WHERE id = $4`,
      [account.account_number, account.bank.name, account.account_name, userId]
    );

    res.json({
      success: true,
      account_number: account.account_number,
      bank_name: account.bank.name,
      account_name: account.account_name
    });

  } catch (error) {
    console.error('DVA Error:', error.response?.data || error.message);
    res.status(500).json({ error: error.response?.data?.message || 'Failed to create virtual account' });
  }
});

/* ================= SIGNUP ================= */
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, pin, phone, company } = req.body;
    if (!username ||!email ||!password ||!pin ||!phone)
      return res.status(400).json({ message: "All fields required including phone" });

    const userCompany = company || "mayconnect";
    const hash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);
    const isAdmin = ADMIN_EMAILS.includes(email);

    const user = await pool.query(
      `INSERT INTO users(username,email,password,pin,phone,is_admin,company)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [username, email, hash, pinHash, phone, isAdmin, userCompany]
    );

    try {
      await createDedicatedAccount(user.rows[0]);
    } catch (e) {
      console.log("PAYSTACK ERROR ON SIGNUP - continuing anyway:", e.message);
    }

    const updatedUser = await getUser(user.rows[0].id);
    const token = jwt.sign(
      { id: updatedUser.id, username: updatedUser.username, is_admin: updatedUser.is_admin, company: updatedUser.company },
      process.env.JWT_SECRET
    );
    res.json({ token, message: "Signup successful" });
  } catch (e) {
    console.log("SIGNUP ERROR:", e.message);
    if (e.code === "23505") return res.status(400).json({ message: "Username or email already exists" });
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
  try {
    let user = await getUser(req.user.id);
    if (!user.account_number && getPaystackKey(user.company, "secret") && user.phone) {
      try {
        await createDedicatedAccount(user);
        user = await getUser(req.user.id);
      } catch (e) {
        console.log("Account creation failed on /me:", e.message);
      }
    }
    delete user.password;
    delete user.pin;
    res.json(user);
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= GENERATE ACCOUNT ================= */
app.post("/api/generate-account", auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id);
    if (user.account_number) return res.json({ message: "Account already exists", account: user });
    if (!user.phone) return res.status(400).json({ message: "Please update your phone number in profile first" });
    const acc = await createDedicatedAccount(user);
    res.json({ message: "Account created", account: acc });
  } catch (e) {
    console.log("GENERATE ACCOUNT ERROR:", e.message);
    res.status(400).json({ message: e.message || "Failed to create account" });
  }
});

/* ================= TRANSACTIONS ================= */
app.get("/api/transactions", auth, async (req, res) => {
  const tx = await pool.query("SELECT * FROM transactions WHERE user_id=$1 ORDER BY id DESC LIMIT 100", [req.user.id]);
  res.json(tx.rows);
});

/* ================= PLANS - INSTANT TOP USER PRICING ================= */
app.get("/api/plans", auth, async (req, res) => {
  const user = await pool.query("SELECT is_top_user, company FROM users WHERE id=$1", [req.user.id]);
  const { is_top_user, company } = user.rows[0];

  const plans = await pool.query(
    `SELECT * FROM plans WHERE is_active = TRUE AND (restricted = FALSE OR company = $1) ORDER BY network, price ASC`,
    [company]
  );

  const result = plans.rows.map(p => ({
   ...p,
    price: is_top_user? (p.top_price || p.price) : p.price
  }));
  res.json(result);
});

/* ================= BUY DATA - WITH VTU ROUTING ================= */
app.post("/api/buy-data", auth, buyDataLimiter, async (req, res) => {
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

    if (plan.restricted && plan.company!== user.company) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Plan restricted to company users" });
    }

    if (!plan.provider ||!plan.network_id ||!plan.api_plan_id) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Plan not configured with provider. Contact admin." });
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

    try {
      if (plan.provider === "maitama") {
        await callMaitamaData(phone, plan.network_id, plan.api_plan_id, user.company);
      } else if (plan.provider === "cheapdatahub") {
        await callCheapDataHubData(phone, plan.network_id, plan.api_plan_id);
      } else if (plan.provider === "subpadi") {
        await callSubPadiData(phone, plan.network_id, plan.api_plan_id);
      } else {
        throw new Error("Unknown provider");
      }
    } catch (vtuErr) {
      console.log("VTU API ERROR:", vtuErr.message);
      await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2", [price, user.id]);
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Purchase failed: " + vtuErr.message });
    }

    const txRes = await client.query(
      `INSERT INTO transactions(user_id,plan_id,type,amount,cost,phone,network,reference,status)
       VALUES($1,$2,'DATA',$3,$4,$5,$6,$7,'SUCCESS') RETURNING *`,
      [user.id, plan.id, price, cost, phone, plan.network, ref]
    );

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
    const cost = Number(amount) * 0.98;

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
app.post("/api/fund/init", auth, fundInitLimiter, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ message: "Minimum funding is ₦100" });

  const user = await getUser(req.user.id);
  const paystackSecret = getPaystackKey(user.company, "secret");
  if (!paystackSecret) return res.status(500).json({ message: "Payment not configured for your company" });

  const reference = "FUND-" + uuidv4();

  try {
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: user.email,
        amount: Number(amount) * 100,
        reference,
        metadata: { user_id: user.id, company: user.company }
      },
      { headers: { Authorization: `Bearer ${paystackSecret}` } }
    );
    res.json({ url: response.data.data.authorization_url, reference });
  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Unable to initialize payment" });
  }
});

/* ================= PAYSTACK WEBHOOK ================= */
app.post("/api/paystack/webhook", async (req, res) => {
  try {
    const rawBody = req.body;
    const signature = req.headers["x-paystack-signature"];

    let isValid = false;
    for (const company of Object.keys(PAYSTACK_KEYS)) {
      const secret = PAYSTACK_KEYS[company]?.secret;
      if (!secret) continue;
      const hash = crypto.createHmac("sha512", secret).update(rawBody).digest("hex");
      if (hash === signature) {
        isValid = true;
        break;
      }
    }
    if (!isValid) return res.sendStatus(400);

    const event = JSON.parse(rawBody);
    if (event.event === "charge.success") {
      const { user_id } = event.data.metadata || {};
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

/* ================= CHANGE PASSWORD/PIN ================= */
app.post("/api/change-password", auth, async (req, res) => {
  const { oldPass, newPass } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(oldPass, user.rows[0].password)) return res.status(400).json({ message: "Wrong old password" });
  const hash = await bcrypt.hash(newPass, 10);
  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, user.rows[0].id]);
  res.json({ message: "Password updated" });
});

app.post("/api/change-pin", auth, async (req, res) => {
  const { oldPin, newPin } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  if (!await bcrypt.compare(oldPin, user.rows[0].pin)) return res.status(400).json({ message: "Wrong old PIN" });
  const hash = await bcrypt.hash(newPin, 10);
  await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, user.rows[0].id]);
  res.json({ message: "PIN updated" });
});

/* ================= ADMIN: PROFIT ================= */
app.get("/admin/profit", auth, adminOnly, async (req, res) => {
  const { from, to, company } = req.query;
  const userCompany = req.user.company;

  let query = `
    SELECT DATE(t.created_at) as date,
           SUM(p.amount) as total_profit,
           COUNT(*) as total_sales
    FROM transactions t
    JOIN profits p ON p.transaction_id = t.id
    JOIN users u ON t.user_id = u.id
    WHERE t.status = 'SUCCESS'
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
  params.push(company || userCompany);
  query += ` AND u.company = $${params.length}`;
  query += ` GROUP BY DATE(t.created_at) ORDER BY date DESC`;

  const result = await pool.query(query, params);
  const adminWallet = await pool.query("SELECT admin_wallet FROM users WHERE id=$1", [req.user.id]);

  res.json({
    daily: result.rows,
    admin_wallet: adminWallet.rows[0].admin_wallet,
    total: result.rows.reduce((sum, r) => sum + Number(r.total_profit), 0)
  });
});

/* ================= ADMIN: TOP USERS - WITH WS BROADCAST ================= */
app.get("/admin/top-users", auth, adminOnly, async (req, res) => {
  const users = await pool.query(
    `SELECT u.id,u.username,u.email,u.company,u.is_top_user,
            COALESCE(SUM(t.amount),0) as total_spent,
            COALESCE(SUM(p.amount),0) as total_profit_generated
     FROM users u
     LEFT JOIN transactions t ON t.user_id = u.id AND t.status='SUCCESS'
     LEFT JOIN profits p ON p.transaction_id = t.id
     WHERE u.company=$1
     GROUP BY u.id
     ORDER BY total_spent DESC`,
    [req.user.company]
  );
  res.json(users.rows);
});

app.post("/admin/top-users/add", auth, adminOnly, async (req, res) => {
  const { email } = req.body;
  const result = await pool.query(
    "UPDATE users SET is_top_user=true WHERE email=$1 AND company=$2 RETURNING id,username,email,company",
    [email, req.user.company]
  );
  if (!result.rows.length) return res.status(404).json({ message: "User not found in your company" });

  broadcastTopUserUpdate(req.user.company);

  res.json({ message: "Top user added", user: result.rows[0] });
});

app.delete("/admin/top-users/remove", auth, adminOnly, async (req, res) => {
  const { email } = req.body;
  const result = await pool.query(
    "UPDATE users SET is_top_user=false WHERE email=$1 AND company=$2 RETURNING id,company",
    [email, req.user.company]
  );
  if (!result.rows.length) return res.status(404).json({ message: "User not found in your company" });

  broadcastTopUserUpdate(req.user.company);

  res.json({ message: "Top user removed" });
});

/* ================= ADMIN: PLANS MANAGER ================= */
app.get("/admin/plans", auth, adminOnly, async (req, res) => {
  const plans = await pool.query(
    "SELECT * FROM plans WHERE company=$1 ORDER BY network, price",
    [req.user.company]
  );
  res.json(plans.rows);
});

app.post("/admin/plans", auth, adminOnly, async (req, res) => {
  const { plan_id, network, name, price, top_price, cost, validity, restricted, provider, network_id, api_plan_id } = req.body;
  if (!plan_id ||!network ||!name ||!price ||!cost ||!provider ||!network_id ||!api_plan_id) {
    return res.status(400).json({ message: "Missing required fields: plan_id, network, name, price, cost, provider, network_id, api_plan_id" });
  }
  try {
    const result = await pool.query(
      `INSERT INTO plans(plan_id,company,network,name,price,top_price,cost,validity,restricted,is_active,provider,network_id,api_plan_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,$10,$11,$12) RETURNING *`,
      [plan_id, req.user.company, network, name, price, top_price || price, cost, validity, restricted || false, provider, network_id, api_plan_id]
    );
    res.json({ message: "Plan added", plan: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(400).json({ message: "Plan ID already exists" });
    res.status(500).json({ message: "Failed to add plan" });
  }
});

app.put("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  const { id } = req.params;
  const fields = req.body;
  if (!Object.keys(fields).length) return res.status(400).json({ message: "No fields to update" });

  const set = Object.keys(fields).map((k, i) => `${k}=$${i + 1}`).join(",");
  const values = Object.values(fields);
  values.push(id, req.user.company);

  try {
    const result = await pool.query(
      `UPDATE plans SET ${set} WHERE id=$${values.length - 1} AND company=$${values.length} RETURNING *`,
      values
    );
    if (!result.rows.length) return res.status(404).json({ message: "Plan not found or not in your company" });
    res.json({ message: "Plan updated", plan: result.rows[0] });
  } catch (e) {
    console.log("UPDATE PLAN ERROR:", e.message);
    res.status(500).json({ message: "Failed to update plan" });
  }
});

app.delete("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  const { id } = req.params;
  const result = await pool.query(
    "UPDATE plans SET is_active=FALSE WHERE id=$1 AND company=$2 RETURNING id",
    [id, req.user.company]
  );
  if (!result.rows.length) return res.status(404).json({ message: "Plan not found" });
  res.json({ message: "Plan deactivated" });
});

/* ================= ADMIN: USERS ================= */
app.get("/admin/users", auth, adminOnly, async (req, res) => {
  const { search } = req.query;
  let query = `SELECT id,username,email,wallet_balance,is_top_user,company,created_at,phone FROM users WHERE company=$1`;
  const params = [req.user.company];
  if (search) {
    params.push(`%${search}%`);
    query += ` AND (username ILIKE $${params.length} OR email ILIKE $${params.length})`;
  }
  query += ` ORDER BY created_at DESC LIMIT 100`;
  const users = await pool.query(query, params);
  res.json(users.rows);
});

app.put("/admin/users/:id", auth, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { is_top_user, wallet_balance } = req.body;
  const updates = [];
  const values = [];
  let idx = 1;

  if (is_top_user!== undefined) {
    updates.push(`is_top_user=$${idx++}`);
    values.push(is_top_user);
  }
  if (wallet_balance!== undefined) {
    updates.push(`wallet_balance=$${idx++}`);
    values.push(wallet_balance);
  }

  if (!updates.length) return res.status(400).json({ message: "No fields to update" });

  values.push(id, req.user.company);
  const result = await pool.query(
    `UPDATE users SET ${updates.join(",")} WHERE id=$${idx} AND company=$${idx + 1} RETURNING id,username,email,is_top_user,wallet_balance,company`,
    values
  );
  if (!result.rows.length) return res.status(404).json({ message: "User not found" });

  if (is_top_user!== undefined) {
    broadcastTopUserUpdate(req.user.company);
  }

  res.json({ message: "User updated", user: result.rows[0] });
});



/* ================= ADMIN: WITHDRAWALS ================= */
app.get("/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const wds = await pool.query(
    "SELECT * FROM withdrawals WHERE admin_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(wds.rows);
});

app.post("/admin/withdraw-request", auth, adminOnly, async (req, res) => {
  const { amount, bank_name, account_number, account_name } = req.body;
  if (!amount ||!bank_name ||!account_number ||!account_name) {
    return res.status(400).json({ message: "All fields required" });
  }

  const user = await getUser(req.user.id);
  if (Number(user.admin_wallet) < Number(amount)) {
    return res.status(400).json({ message: "Insufficient admin wallet balance" });
  }

  const reference = "WD-" + uuidv4();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO withdrawals(admin_id,amount,bank_name,account_number,account_name,reference,status)
       VALUES($1,$2,$3,$4,$5,$6,'PENDING')`,
      [req.user.id, amount, bank_name, account_number, account_name, reference]
    );
    await client.query("UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2", [amount, req.user.id]);
    await client.query("COMMIT");
    res.json({ message: "Withdrawal request submitted", reference });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("WITHDRAW ERROR:", e.message);
    res.status(500).json({ message: "Withdrawal failed" });
  } finally {
    client.release();
  }
});

app.post("/admin/withdraw/approve", auth, adminOnly, async (req, res) => {
  const { reference } = req.body;
  const result = await pool.query(
    "UPDATE withdrawals SET status='PAID' WHERE reference=$1 AND admin_id=$2 RETURNING *",
    [reference, req.user.id]
  );
  if (!result.rows.length) return res.status(404).json({ message: "Withdrawal not found" });
  res.json({ message: "Marked as paid" });
});

/* ================= ADMIN: REVERSE ================= */
app.post("/api/admin/reverse", auth, adminOnly, async (req, res) => {
  const { reference } = req.body;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const tx = await client.query("SELECT * FROM transactions WHERE reference=$1 FOR UPDATE", [reference]);
    if (!tx.rows.length) throw new Error("Transaction not found");
    if (tx.rows[0].status === "REVERSED") throw new Error("Already reversed");

    const t = tx.rows[0];
    await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2", [t.amount, t.user_id]);
    await client.query("UPDATE transactions SET status='REVERSED' WHERE id=$1", [t.id]);

    const profit = await client.query("SELECT * FROM profits WHERE transaction_id=$1", [t.id]);
    if (profit.rows.length) {
      const p = profit.rows[0];
      await client.query("UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2", [p.amount, p.credited_to_user_id]);
      await client.query("DELETE FROM profits WHERE id=$1", [p.id]);
    }

    await client.query("COMMIT");
    const user = await getUser(t.user_id);
    sendWalletUpdate(t.user_id, user.wallet_balance);
    res.json({ message: "Transaction reversed" });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ message: e.message });
  } finally {
    client.release();
  }
});

// Add this for UptimeRobot
app.get("/", (req, res) => {
  res.send("MAYCONNECT API Live");
});
/* ================= START ================= */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on ${PORT}`));