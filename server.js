const express = require("express");
const path = require('path');
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
const webpush = require("web-push");

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.static('public'));
app.set('trust proxy', 1);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

/* ================= DATABASE - SINGLE INSTANCE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL + '?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('Error connecting to Postgres:', err.stack);
  } else {
    console.log('Connected to Postgres successfully');
    release();
  }
});

/* ================= CORS ================= */
app.use(cors({
  origin: [
    'https://teeversh-frontend.onrender.com',
    'https://mayconnect-frontend.onrender.com',
    'https://sadeeq-frontend.onrender.com',
    'https://bnhabeeb-frontend.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* ================= VAPID ================= */
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:support@teeversh.com', VAPID_PUBLIC, VAPID_PRIVATE);
}

/* ================= CONFIG ================= */
const ADMIN_EMAILS = [
  "abubakarmubarak3456@gmail.com",
  "mayconnectofficial@gmail.com",
  "bashirahmadt11696@gmail.com",
  "abdullahihabibudanalhaji@gmail.com",
  "Sadeeqtukur765@gmail.com"
];

const RP_ID = process.env.RP_ID || 'mayconnect-backend-1.onrender.com';
const RP_NAME = 'Mayconnect';
const ORIGIN = process.env.RP_ORIGIN || 'https://mayconnect-backend-1.onrender.com';

// PAYMENTPOINT CONFIG
const PAYMENTPOINT_BASE = process.env.PAYMENTPOINT_BASE || "https://api.paymentpoint.co";

console.log("[PAYMENTPOINT] Config loaded for:", ["teeversh", "sadeeq", "bnhabeeb", "mayconnect"]);

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
    base_url: "https://www.cheapdatahub.ng/api/v1/resellers",
    api_key: process.env.CHEAPDATAHUB_API_KEY
  },
  subpadi: {
    base_url: "https://api.subpadi.com",
    token: process.env.SUBPADI_TOKEN
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

/* ================= HELPERS ================= */
const getCompanyAdmin = async (company) => {
  const admin = await pool.query(
    "SELECT id FROM users WHERE company=$1 AND is_admin=TRUE ORDER BY id ASC LIMIT 1",
    [company.toLowerCase()]
  );
  return admin.rows[0]?.id || null;
};

const getUser = async (id) => {
  const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return res.rows[0];
};

const getPaymentPointCreds = (company) => {
  const c = company.toLowerCase();
  const credsMap = {
    mayconnect: {
      apiKey: process.env.PAYMENTPOINT_MAYCONNECT_API_KEY,
      bearer: process.env.PAYMENTPOINT_MAYCONNECT_SECRET_KEY,
      businessId: process.env.PAYMENTPOINT_MAYCONNECT_BUSINESS_ID
    },
    sadeeq: {
      apiKey: process.env.PAYMENTPOINT_SADEEQ_API_KEY,
      bearer: process.env.PAYMENTPOINT_SADEEQ_SECRET_KEY,
      businessId: process.env.PAYMENTPOINT_SADEEQ_BUSINESS_ID
    },
    teeversh: {
      apiKey: process.env.PAYMENTPOINT_TEEVERSH_API_KEY,
      bearer: process.env.PAYMENTPOINT_TEEVERSH_SECRET_KEY,
      businessId: process.env.PAYMENTPOINT_TEEVERSH_BUSINESS_ID
    },
    bnhabeeb: {
      apiKey: process.env.PAYMENTPOINT_BNHABEEB_API_KEY,
      bearer: process.env.PAYMENTPOINT_BNHABEEB_SECRET_KEY,
      businessId: process.env.PAYMENTPOINT_BNHABEEB_BUSINESS_ID
    }
  };
  return credsMap[c] || {};
}

async function createPaymentPointAccount(user) {
  const creds = getPaymentPointCreds(user.company);
  if (!creds.apiKey ||!creds.bearer ||!creds.businessId) {
    throw new Error(
      `PaymentPoint not configured for company: ${user.company}. ` +
      `Check PAYMENTPOINT_${user.company.toUpperCase()}_API_KEY, ` +
      `PAYMENTPOINT_${user.company.toUpperCase()}_SECRET_KEY, and ` +
      `PAYMENTPOINT_${user.company.toUpperCase()}_BUSINESS_ID`
    );
  }
  if (!user.phone) {
    throw new Error("Phone number required to create virtual account. Please update your profile.");
  }

  const payload = {
    email: user.email,
    name: user.fullname || user.username,
    phoneNumber: user.phone,
    bankCode: ["20946", "20897"],
    businessId: creds.businessId
  };

  const headers = {
    'Authorization': `Bearer ${creds.bearer}`,
    'api-key': creds.apiKey,
    'Content-Type': 'application/json'
  };

  const { data } = await axios.post(
    `${PAYMENTPOINT_BASE}/api/v1/createVirtualAccount`,
    payload,
    { headers, timeout: 30000 }
  );

  if (data.status!== "success") {
    throw new Error(data.message || "PaymentPoint account creation failed");
  }

  const bankAcc = data.bankAccounts[0];

  await pool.query(
    `UPDATE users SET
      account_number=$1,
      account_name=$2,
      bank_name=$3,
      paymentmethod='paymentpoint',
      reserved_account_id=$4,
      customer_id=$5
     WHERE id=$6`,
    [
      bankAcc.accountNumber,
      bankAcc.accountName,
      bankAcc.bankName,
      bankAcc.Reserved_Account_Id,
      data.customer_id,
      user.id
    ]
  );

  return {
    account_number: bankAcc.accountNumber,
    account_name: bankAcc.accountName,
    bank_name: bankAcc.bankName,
    reserved_account_id: bankAcc.Reserved_Account_Id
  };
}

module.exports = {
  getCompanyAdmin,
  getUser,
  getPaymentPointCreds,
  createPaymentPointAccount
};

/* ================= WEBSOCKET SETUP ================= */
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
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({ type: "wallet_update", balance }));
  }
}

function broadcastTopUserUpdate(company) {
  for (const [userId, ws] of clients.entries()) {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: "top_user_update", company }));
    }
  }
}

/* ================= PAYMENTPOINT WEBHOOK - MUST BE BEFORE express.json() ================= */
app.post("/api/paymentpoint/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const rawBody = req.body;
      const signature = req.headers["x-paymentpoint-signature"] || req.headers["paymentpoint-signature"];

      if (!rawBody ||!signature) {
        return res.sendStatus(400);
      }

      const event = JSON.parse(rawBody.toString());
      const customerEmail = event.customer?.email;
      const amount = Number(event.settlement_amount || event.amount_paid);
      const reference = event.transaction_id;

      if (!customerEmail ||!amount ||!reference) {
        return res.sendStatus(400);
      }

      if (event.notification_status!== "payment_successful" || event.transaction_status!== "success") {
        return res.sendStatus(200);
      }

      const userRes = await pool.query(
        "SELECT id, company FROM users WHERE lower(trim(email)) = lower(trim($1))",
        [customerEmail]
      );

      if (!userRes.rows.length) {
        return res.sendStatus(200);
      }

      const userId = userRes.rows[0].id;
      const company = userRes.rows[0].company;
      const creds = getPaymentPointCreds(company);

      if (!creds?.bearer) {
        return res.sendStatus(400);
      }

      const calculatedSignature = crypto
      .createHmac("sha256", creds.bearer)
      .update(rawBody)
      .digest("hex");

      if (calculatedSignature.length!== signature.length ||
        !crypto.timingSafeEqual(Buffer.from(calculatedSignature), Buffer.from(signature))) {
        return res.sendStatus(401);
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const existing = await client.query(
          "SELECT status FROM transactions WHERE reference=$1 FOR UPDATE",
          [reference]
        );
        if (existing.rows.length && existing.rows[0].status === "SUCCESS") {
          await client.query("ROLLBACK");
          return res.sendStatus(200);
        }

        const update = await client.query(
          "UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2 RETURNING wallet_balance",
          [amount, userId]
        );

        if (!existing.rows.length) {
          await client.query(
            `INSERT INTO transactions(user_id, type, amount, reference, status, gateway)
             VALUES($1, 'WALLET_FUND', $2, $3, 'SUCCESS', 'paymentpoint')`,
            [userId, amount, reference]
          );
        }

        await client.query("COMMIT");
        sendWalletUpdate(userId, Number(update.rows[0].wallet_balance));
      } catch (e) {
        await client.query("ROLLBACK");
        return res.sendStatus(500);
      } finally {
        client.release();
      }

      res.sendStatus(200);
    } catch (e) {
      res.sendStatus(500);
    }
  }
);

/* ================= BODY PARSERS - MUST BE AFTER WEBHOOK ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= PUSH NOTIFICATION ================= */
app.post('/api/save-push-sub', async (req, res) => {
  try {
    const {company, user_id, subscription} = req.body;
    if (!company ||!user_id ||!subscription) {
      return res.status(400).json({success: false, error: 'Missing data'});
    }

    await pool.query(
      `INSERT INTO push_subscriptions (company, user_id, subscription)
       VALUES ($1, $2, $3)
       ON CONFLICT (company, user_id)
       DO UPDATE SET subscription = $3, updated_at = NOW()`,
      [company, user_id, subscription]
    );
    res.json({success: true});
  } catch (err) {
    res.status(500).json({success: false});
  }
});

async function sendPushNotification(company, user_id, payload) {
  try {
    const result = await pool.query(
      'SELECT subscription FROM push_subscriptions WHERE company = $1 AND user_id = $2',
      [company, user_id]
    );
    if (result.rows.length === 0) return false;

    await webpush.sendNotification(
      result.rows[0].subscription,
      JSON.stringify(payload)
    );
    return true;
  } catch (err) {
    if (err.statusCode === 410 || err.statusCode === 404) {
      await pool.query(
        'DELETE FROM push_subscriptions WHERE company = $1 AND user_id = $2',
        [company, user_id]
      );
    }
    return false;
  }
}

app.post('/api/test-push', async (req, res) => {
  const {company, user_id} = req.body;
  await sendPushNotification(company, user_id, {
    title: `${company.toUpperCase()} Test`,
    body: 'Push notifications are working!',
    url: '/dashboard.html'
  });
  res.json({sent: true});
});

/* ================= VTU API CALLS ================= */
async function callMaitamaData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.maitama;
  const api_token = tokens[company];
  if (!api_token) throw new Error(`No Maitama token configured for ${company}`);

  const payload = {
    plan: Number(api_plan_id),
    mobile_number: String(phone),
    network: Number(network_id)
  };

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

  const status = res.data.Status || res.data.status;
  if (status?.toLowerCase()!== "successful" && status?.toLowerCase()!== "success") {
    throw new Error(res.data.api_response || res.data.message || "Maitama purchase failed");
  }
  return res.data;
}

async function callCheapDataHubData(phone, network_id, api_plan_id) {
  const { base_url, api_key } = VTU_PROVIDERS.cheapdatahub;
  const res = await axios.post(
    `${base_url}/data/purchase/`,
    {
      provider_id: network_id,
      phone_number: phone,
      bundle_id: api_plan_id
    },
    { headers: { Authorization: `Bearer ${api_key}` } }
  );
  if (res.data.status!== "true") throw new Error(res.data.message || "CheapDataHub failed");
  return res.data;
}

async function callCheapDataHubAirtime(phone, network_id, amount) {
  const { base_url, api_key } = VTU_PROVIDERS.cheapdatahub;
  const res = await axios.post(
    `${base_url}/airtime/purchase/`,
    {
      provider_id: network_id,
      phone_number: phone,
      amount: amount
    },
    { headers: { Authorization: `Bearer ${api_key}` } }
  );
  if (res.data.status!== "true") throw new Error(res.data.message || "CheapDataHub failed");
  return res.data;
}

async function callSubPadiData(phone, network_id, api_plan_id) {
  const { base_url, token } = VTU_PROVIDERS.subpadi;
  const res = await axios.post(
    `${base_url}/v1/data/`,
    {
      mobile_number: phone,
      network: network_id,
      plan: api_plan_id,
      Ported_number: false
    },
    { headers: { Authorization: `Token ${token}` } }
  );
  if (res.data.Status!== "successful") throw new Error(res.data.message || "SubPadi failed");
  return res.data;
}
/* ================= AUTH MIDDLEWARE ================= */
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

/* ================= WEBAUTHN - BIOMETRIC ================= */
const rpName = 'MAYCONNECT';

// Whitelist of allowed frontend domains
const ALLOWED_FRONTENDS = [
  'mayconnect-frontend.onrender.com',
  'teeversh-frontend.onrender.com',
  'bnhabeeb-frontend.onrender.com', 
  'sadeeq-frontend.onrender.com',
  'localhost'
];

// Helper to get rpID from request origin with validation
function getRpID(req) {
  if (process.env.NODE_ENV!== 'production') return 'localhost';

  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    const hostname = new URL(origin).hostname;
    if (ALLOWED_FRONTENDS.includes(hostname)) return hostname;
    throw new Error(`Unauthorized origin: ${hostname}`);
  }

  const host = req.headers.host;
  if (host && ALLOWED_FRONTENDS.includes(host)) return host;
  throw new Error('No origin or valid host header');
}

// Helper to get origin for verification - must match browser's origin exactly
function getExpectedOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) throw new Error('No origin header');
  return origin;
}

const { isoBase64URL } = require('@simplewebauthn/server/helpers');

/* ================= WEBAUTHN ROUTES ================= */
app.get('/api/auth/webauthn/check-enabled', auth, async (req, res) => {
  try {
    const rpId = getRpID(req);
    const creds = await pool.query(
      'SELECT id FROM webauthn_credentials WHERE user_id=$1 AND rp_id=$2',
      [req.user.id, rpId]
    );
    res.json({ enabled: creds.rows.length > 0 });
  } catch (e) {
    console.error('Check enabled error:', e.message);
    if (e.code === '42703') {
      return res.json({ enabled: false }); // column doesn't exist yet
    }
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/webauthn/register-start', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id);
    const userID = new TextEncoder().encode(user.id.toString());
    const rpId = getRpID(req);

    const existingCreds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND rp_id=$2',
      [user.id, rpId]
    );

    if (existingCreds.rows.length > 0) {
      return res.status(400).json({ error: 'Biometric already enabled for this device' });
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID: rpId, // v10+ uses rpID not rpId
      userID: userID,
      userName: user.email,
      userDisplayName: user.username || user.email,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform', // FORCE PHONE SENSOR - no QR code
        userVerification: 'required',
        residentKey: 'discouraged' // KEY FIX: prevents cross-device passkey
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ]
    });

    options.rpID = rpId; // v10+ expects rpID in response too

    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, user.id]);
    res.json(options);

  } catch (e) {
    console.error('Register start error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/webauthn/register-finish', auth, async (req, res) => {
  const user = await getUser(req.user.id);
  const rpId = getRpID(req);
  const expectedOrigin = getExpectedOrigin(req);

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: user.webauthn_challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpId,
      requireUserVerification: true // Set to true for fingerprint
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;
      
      if (!credential ||!credential.id ||!credential.publicKey) {
        return res.status(400).json({ verified: false, error: 'Incomplete credential data' });
      }

      // v10+ returns Buffer, convert to base64url
      const credentialID = Buffer.from(credential.id).toString('base64url');
      const publicKey = Buffer.from(credential.publicKey).toString('base64url');

      await pool.query(
        `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, rp_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (credential_id) DO UPDATE SET public_key=$3, counter=$4, rp_id=$5`,
        [user.id, credentialID, publicKey, credential.counter, rpId]
      );

      await pool.query('UPDATE users SET webauthn_challenge=NULL WHERE id=$1', [user.id]);
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false, error: 'Verification failed' });
    }
  } catch (e) {
    console.error('WebAuthn register error:', e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/webauthn/login-start', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (!user.rows.length) return res.status(400).json({ error: 'User not found' });

    const rpId = getRpID(req);

    const creds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND rp_id=$2',
      [user.rows[0].id, rpId]
    );
    if (!creds.rows.length) return res.status(400).json({ error: 'Biometric not enabled for this user' });

    const options = await generateAuthenticationOptions({
      rpID: rpId, // v10+ uses rpID
      userVerification: 'required', // Force fingerprint on login
      allowCredentials: creds.rows.map(c => ({
        id: c.credential_id, // v10+ accepts base64url string directly
        type: 'public-key',
        transports: ['internal'] // Force local device
      }))
    });

    options.rpID = rpId;

    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, user.rows[0].id]);
    res.json(options);

  } catch (e) {
    console.error('Login start error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/webauthn/login-finish', async (req, res) => {
  const { email,...authResponse } = req.body;
  const userRes = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = userRes.rows[0];
  if (!user) return res.status(400).json({ error: 'User not found' });

  const rpId = getRpID(req);
  const expectedOrigin = getExpectedOrigin(req);

  const cred = await pool.query(
    'SELECT * FROM webauthn_credentials WHERE credential_id=$1 AND user_id=$2 AND rp_id=$3',
    [authResponse.id, user.id, rpId]
  );

  if (!cred.rows.length) return res.status(400).json({ error: 'Credential not found' });

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: user.webauthn_challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpId,
      credential: {
        id: cred.rows[0].credential_id,
        publicKey: Buffer.from(cred.rows[0].public_key, 'base64url'),
        counter: cred.rows[0].counter
      },
      requireUserVerification: true
    });

    if (verification.verified) {
      const { authenticationInfo } = verification;

      await pool.query('UPDATE webauthn_credentials SET counter=$1 WHERE id=$2',
        [authenticationInfo.newCounter, cred.rows[0].id]);

      await pool.query('UPDATE users SET webauthn_challenge=NULL WHERE id=$1', [user.id]);

      const token = jwt.sign(
        { id: user.id, username: user.username, is_admin: user.is_admin, company: user.company },
        process.env.JWT_SECRET
      );
      res.json({ token });
    } else {
      res.status(400).json({ verified: false, error: 'Authentication failed' });
    }
  } catch (e) {
    console.error('WebAuthn login error:', e.message);
    res.status(400).json({ error: e.message });
  }
});



// 4. TEST ROUTE
app.get('/api/ping', (req, res) => {
  console.log('PING HIT');
  res.send('pong');
});

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

/* ================= FUND INIT ================= */
app.post("/api/fund/init", auth, fundInitLimiter, async (req, res) => {
  const { amount } = req.body;
  if (!amount || Number(amount) < 100) return res.status(400).json({ message: "Minimum funding is ₦100" });

  const user = await getUser(req.user.id);
  const reference = "FUND-" + uuidv4();

  try {
    let account = await pool.query(
      "SELECT account_number, bank_name, account_name, paymentmethod FROM users WHERE id=$1",
      [user.id]
    );

    if (!account.rows[0]?.account_number || account.rows[0].paymentmethod!== "paymentpoint") {
      account = { rows: [await createPaymentPointAccount(user)] };
    }

    res.json({
      bank_name: account.rows[0].bank_name,
      account_number: account.rows[0].account_number,
      account_name: account.rows[0].account_name,
      reference,
      method: "paymentpoint"
    });

  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Unable to initialize payment" });
  }
});

/* ================= DVA ROUTE ================= */
app.post('/api/wallet/create-dva', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.account_number && user.paymentmethod === "paymentpoint") {
      return res.json({
        message: "Account already exists",
        account: user,
        method: "paymentpoint"
      });
    }
    if (!user.phone) {
      return res.status(400).json({ error: 'Phone number missing. Update profile first.' });
    }

    const account = await createPaymentPointAccount(user);
    res.json({
      success: true,
      account_number: account.account_number,
      bank_name: account.bank_name,
      account_name: account.account_name,
      method: "paymentpoint"
    });

  } catch (error) {
    console.error('DVA Error:', error.response?.data || error.message);
    res.status(500).json({ error: error.message || 'Failed to create virtual account' });
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
      if (userCompany!== "sadeeq") {
        await createMonnifyAccount(user.rows[0]);
      }
    } catch (e) {
      console.log("ACCOUNT CREATE ERROR ON SIGNUP - continuing anyway:", e.message);
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

/* ================= USER INFO - WITH TIER CHECK ================= */
app.get("/api/me", auth, async (req, res) => {
  try {
    let user = await pool.query("SELECT id, username, email, wallet_balance, company, phone, is_admin, admin_wallet, account_number, bank_name, account_name FROM users WHERE id = $1", [req.user.id]);
    if (!user.rows.length) return res.status(404).json({ message: "User not found" });

    // Auto-create DVA if missing for Monnify companies
    if (!user.rows[0].account_number && user.rows[0].company!== "sadeeq" && user.rows[0].phone) {
      try {
        await createMonnifyAccount(user.rows[0]);
        user = await pool.query("SELECT id, username, email, wallet_balance, company, phone, is_admin, admin_wallet, account_number, bank_name, account_name FROM users WHERE id = $1", [req.user.id]);
      } catch (e) {
        console.log("Account creation failed on /me:", e.message);
      }
    }

    const [topCheck] = await Promise.all([
      pool.query("SELECT 1 FROM top_users WHERE id = $1", [req.user.id])
    ]);

    const userData = user.rows[0];
    userData.is_top_user = topCheck.rows.length > 0;
    userData.user_tier = userData.is_top_user? 'top' : 'default';

    delete userData.password;
    delete userData.pin;
    res.json(userData);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

/* ================= GENERATE ACCOUNT ================= */
app.post("/api/generate-account", auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id);

    if (user.account_number && user.paymentmethod === "paymentpoint") {
      return res.json({ 
        message: "PaymentPoint account already exists", 
        account: user,
        user_id: user.id 
      });
    }

    if (!user.phone) {
      return res.status(400).json({ message: "Please update your phone number in profile first" });
    }

    const paymentpointCompanies = ["teeversh", "sadeeq", "bnhabeeb", "mayconnect"];
    let acc;

    if (paymentpointCompanies.includes(user.company.toLowerCase())) {
      // Use PaymentPoint for these companies
      acc = await createPaymentPointAccount(user);
    } else {
      // Fallback to Monnify for other users
      acc = await createMonnifyAccount(user);
    }

    res.json({ 
      message: "Account created successfully", 
      account: acc,
      user_id: user.id,        // included for webhook debugging
      company: user.company    // included so you know which company it went to
    });

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

/* ================= PLANS - Company isolated with 3 tiers ================= */
app.get("/api/plans", auth, async (req, res) => {
  try {
    const userRes = await pool.query("SELECT company FROM users WHERE id = $1", [req.user.id]);
    if (!userRes.rows.length) return res.status(404).json({ message: "User not found" });

    const { company } = userRes.rows[0];
    const userId = req.user.id;

    const [topCheck, regularCheck] = await Promise.all([
      pool.query("SELECT 1 FROM top_users WHERE id = $1", [userId]),
      pool.query("SELECT 1 FROM regular_users WHERE user_id = $1", [userId])
    ]);

    let userTier = 'default';
    if (topCheck.rows.length > 0) userTier = 'top';
    else if (regularCheck.rows.length > 0) userTier = 'regular';

    const plans = await pool.query(
      `SELECT
         id, company, network, provider, name, validity,
         api_plan_id, network_id, cost, is_active, restricted,
         CASE
           WHEN $2 = 'top' THEN COALESCE(top_price, regular_price, price)
           WHEN $2 = 'regular' THEN COALESCE(regular_price, price)
           ELSE price
         END as price,
         price as default_price,
         regular_price,
         top_price
       FROM plans
       WHERE company = $1
         AND is_active = true
         AND (restricted = false OR $2 = 'top')
       ORDER BY network ASC, price ASC`,
      [company, userTier]
    );

    res.json(plans.rows);
  } catch (err) {
    console.error("Plans error:", err);
    res.status(500).json({ message: "Failed to fetch plans" });
  }
});
/* ================= BUY DATA - Multi-provider + BIOMETRIC ================= */
app.post("/api/buy-data", auth, buyDataLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { plan_id, phone, pin } = req.body;

    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];

    // BIOMETRIC BYPASS + NULL PIN CHECK - FIXED
    if (pin!== 'biometric_verified') {
      if (!user.pin) {
        await client.query("ROLLBACK");
        return res.status(400).json({ 
          message: "Transaction PIN not set. Please set your PIN in Profile first.",
          needPin: true 
        });
      }
      
      const validPin = await bcrypt.compare(String(pin), String(user.pin));
      if (!validPin) {
        await client.query("ROLLBACK");
        return res.status(400).json({ message: "Invalid PIN" });
      }
    }

    const planRes = await client.query("SELECT * FROM plans WHERE id=$1 AND is_active=TRUE", [plan_id]);
    if (!planRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Plan not found or inactive" });
    }
    const plan = planRes.rows[0];

    // COMPANY ISOLATION: User can only buy plans from their company or unrestricted plans
    if (plan.restricted && plan.company!== user.company) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Plan restricted to company users" });
    }

    if (!plan.provider ||!plan.network_id ||!plan.api_plan_id) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Plan not configured with provider. Contact admin." });
    }

    if ((plan.provider === "cheapdatahub" || plan.provider === "subpadi") && user.company!== "mayconnect") {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "This provider is only available for Mayconnect" });
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
  `INSERT INTO transactions(user_id,plan_id,type,amount,cost,phone,network,reference,status,plan_name)
   VALUES($1,$2,'DATA',$3,$4,$5,$6,$7,'SUCCESS',$8) RETURNING *`,
  [user.id, plan.id, price, cost, phone, plan.network, ref, plan.name]
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

    await sendPushNotification(user.company, user.id, {
      title: `${user.company.toUpperCase()} - Data Purchase`,
      body: `Your ${plan.name} purchase for ${phone} was successful`,
      url: '/dashboard.html'
    });

    res.json({ success: true, reference: ref, balance: newBalance });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("BUY DATA ERROR:", e.message);
    res.status(500).json({ message: "Purchase failed" });
  } finally {
    client.release();
  }
});

/* ================= BUY AIRTIME - CheapDataHub only for MAYCONNECT + BIOMETRIC ================= */
app.post("/api/buy-airtime", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { phone, amount, network, pin } = req.body;

    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];

    if (user.company!== "mayconnect") {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Airtime only available for Mayconnect" });
    }

    // BIOMETRIC BYPASS
    if (pin!== 'biometric_verified') {
      if (!await bcrypt.compare(pin, user.pin)) {
        await client.query("ROLLBACK");
        return res.status(400).json({ message: "Invalid PIN" });
      }
    }

    if (Number(user.wallet_balance) < Number(amount)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient balance" });
    }

    const newBalance = Number(user.wallet_balance) - Number(amount);
    await client.query("UPDATE users SET wallet_balance=$1 WHERE id=$2", [newBalance, user.id]);

    const ref = "AIRTIME-" + uuidv4();
    const cost = Number(amount) * 0.98;

    try {
      await callCheapDataHubAirtime(phone, network, amount);
    } catch (vtuErr) {
      console.log("VTU API ERROR:", vtuErr.message);
      await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2", [amount, user.id]);
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Purchase failed: " + vtuErr.message });
    }

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

    await sendPushNotification(user.company, user.id, {
      title: `${user.company.toUpperCase()} - Airtime Purchase`,
      body: `Your ₦${amount} airtime for ${phone} was successful`,
      url: '/dashboard.html'
    });

    res.json({ success: true, reference: ref, balance: newBalance });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("BUY AIRTIME ERROR:", e.message);
    res.status(500).json({ message: "Purchase failed" });
  } finally {
    client.release();
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
  try {
    const { oldPin, newPin } = req.body;

    if (!newPin || String(newPin).length < 4) {
      return res.status(400).json({ message: "New PIN must be at least 4 digits" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];

    // If user has a PIN, verify oldPin first
    if (user.pin) {
      if (!oldPin) {
        return res.status(400).json({ message: "Enter your current PIN" });
      }
      const validOldPin = await bcrypt.compare(String(oldPin), String(user.pin));
      if (!validOldPin) {
        return res.status(400).json({ message: "Wrong old PIN" });
      }
    }
    // If user.pin is NULL, skip oldPin check - allow setting for first time

    const hash = await bcrypt.hash(String(newPin), 10);
    await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, user.id]);
    res.json({ message: "PIN updated successfully" });
  } catch (e) {
    console.log("CHANGE PIN ERROR:", e.message);
    res.status(500).json({ message: "Failed to update PIN" });
  }
});


/* ================= ADMIN: WALLET TRANSACTIONS MANAGER ================= */

// GET admin wallet transactions log
app.get("/admin/wallet/transactions", auth, adminOnly, async (req, res) => {
  try {
    const { status, search } = req.query;
    const userCompany = req.user.company;

    let query = `
      SELECT
        t.id, t.type, t.amount, t.status, t.phone, t.reference,
        t.created_at, t.cost, t.network, t.provider_reference, t.description, t.metadata,
        u.username, u.email, u.company,
        CASE
          WHEN t.type = 'WALLET_FUND' THEN 'CREDIT'
          WHEN t.type = 'REVERSAL' THEN 'CREDIT'
          ELSE 'DEBIT'
        END AS display_type,
        CASE
          WHEN t.type = 'WALLET_FUND' THEN 'green'
          WHEN t.type = 'REVERSAL' THEN 'green'
          ELSE 'red'
        END AS display_color
      FROM transactions t
      JOIN users u ON u.id = t.user_id
      WHERE u.company = $1
    `;
    const params = [userCompany];
    let paramCount = 1;

    if (status) {
      paramCount++;
      query += ` AND t.status = $${paramCount}`;
      params.push(status.toUpperCase());
    }
    if (search) {
      paramCount++;
      query += ` AND (t.reference ILIKE $${paramCount}
                OR t.phone ILIKE $${paramCount}
                OR u.username ILIKE $${paramCount}
                OR u.email ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY t.created_at DESC LIMIT 200`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error("Admin wallet transactions error:", err.message);
    res.status(500).json({ message: "Failed to fetch transactions", error: err.message });
  }
});

// FORCE DEDUCT - manually deduct from user wallet for failed transaction
app.post("/admin/wallet/force-deduct", auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { reference, reason } = req.body;

    if (!reference ||!reason) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Reference and reason are required" });
    }

    // Get the transaction from transactions table
    const txRes = await client.query(
      "SELECT * FROM transactions WHERE reference = $1 FOR UPDATE",
      [reference]
    );
    if (!txRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Transaction not found" });
    }

    const tx = txRes.rows[0];
    if (tx.status!== "FAILED") {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Only FAILED transactions can be manually deducted" });
    }

    // Get user and check balance
    const userRes = await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [tx.user_id]);
    if (!userRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "User not found" });
    }

    const user = userRes.rows[0];
    if (Number(user.wallet_balance) < Number(tx.amount)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient wallet balance" });
    }

    // Deduct wallet
    const newBalance = Number(user.wallet_balance) - Number(tx.amount);
    await client.query("UPDATE users SET wallet_balance = $1 WHERE id = $2", [newBalance, user.id]);

    // Update transaction status
    await client.query(
      `UPDATE transactions
       SET status = 'SUCCESS', metadata = COALESCE(metadata, '{}') || $1
       WHERE reference = $2`,
      [JSON.stringify({ manual_deducted: true, manual_deducted_by: req.user.email, manual_deducted_reason: reason }), reference]
    );

    // Insert wallet transaction record for audit trail
    await client.query(
      `INSERT INTO wallet_transactions(company, type, amount, balance_after, reason, admin_email, reference, metadata)
       VALUES($1, 'debit', $2, $3, $4, $5, $6, $7)`,
      [user.company, tx.amount, newBalance, reason, req.user.email, `MANUAL-${reference}`, JSON.stringify({ original_ref: reference })]
    );

    await client.query("COMMIT");
    sendWalletUpdate(user.id, newBalance);

    res.json({ message: `Successfully deducted ₦${tx.amount} from ${user.username}` });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Force deduct error:", e);
    res.status(500).json({ message: "Server error during deduction: " + e.message });
  } finally {
    client.release();
  }
});

// REVERSE TRANSACTION - refund user wallet for successful transaction
app.post("/admin/wallet/reverse", auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { reference, reason } = req.body;

    if (!reference ||!reason) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Reference and reason are required" });
    }

    // Get the transaction from transactions table
    const txRes = await client.query(
      "SELECT * FROM transactions WHERE reference = $1 FOR UPDATE",
      [reference]
    );
    if (!txRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Transaction not found" });
    }

    const tx = txRes.rows[0];
    if (tx.status!== "SUCCESS") {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Only SUCCESS transactions can be reversed" });
    }

    // Get user and refund wallet
    const userRes = await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [tx.user_id]);
    if (!userRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "User not found" });
    }

    const user = userRes.rows[0];
    const newBalance = Number(user.wallet_balance) + Number(tx.amount);
    await client.query("UPDATE users SET wallet_balance = $1 WHERE id = $2", [newBalance, user.id]);

    // Update transaction status
    await client.query(
      `UPDATE transactions
       SET status = 'REVERSED', metadata = COALESCE(metadata, '{}') || $1
       WHERE reference = $2`,
      [JSON.stringify({ reversed: true, reversed_by: req.user.email, reversed_reason: reason }), reference]
    );

    // Insert wallet transaction record for audit trail
    await client.query(
      `INSERT INTO wallet_transactions(company, type, amount, balance_after, reason, admin_email, reference, metadata)
       VALUES($1, 'credit', $2, $3, $4, $5, $6, $7)`,
      [user.company, tx.amount, newBalance, reason, req.user.email, `REVERSAL-${reference}`, JSON.stringify({ original_ref: reference })]
    );

    await client.query("COMMIT");
    sendWalletUpdate(user.id, newBalance);

    res.json({ message: `Successfully reversed ₦${tx.amount} to ${user.username}` });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Reverse transaction error:", e);
    res.status(500).json({ message: "Server error during reversal: " + e.message });
  } finally {
    client.release();
  }
});
/* ================= ADMIN: USERS + TIERS ================= */
app.get("/admin/users", auth, adminOnly, async (req, res) => {
  try {
    const { search } = req.query;
    let query = `
      SELECT
        u.id, u.username, u.email, u.wallet_balance, u.company, u.created_at, u.phone,
        CASE
          WHEN t.id IS NOT NULL THEN 'top'
          WHEN ru.user_id IS NOT NULL THEN 'regular'
          ELSE 'default'
        END as user_tier
      FROM users u
      LEFT JOIN top_users t ON t.id = u.id
      LEFT JOIN regular_users ru ON ru.user_id = u.id
      WHERE u.company = $1
    `;
    const params = [req.user.company];
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (u.username ILIKE $${params.length} OR u.email ILIKE $${params.length})`;
    }
    query += ` ORDER BY u.created_at DESC LIMIT 100`;
    const users = await pool.query(query, params);
    res.json(users.rows);
  } catch (err) {
    console.error("Admin users error:", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

app.post("/admin/users/set-tier", auth, adminOnly, async (req, res) => {
  try {
    const { user_id, tier } = req.body;

    if (!['default', 'top', 'regular'].includes(tier)) {
      return res.status(400).json({ message: "Invalid tier. Only 'default', 'top', or 'regular' allowed" });
    }

    const check = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND company = $2",
      [user_id, req.user.company]
    );
    if (!check.rows.length) return res.status(404).json({ message: "User not found" });

    // Remove user from all tier tables first
    await pool.query("DELETE FROM top_users WHERE id = $1", [user_id]);
    await pool.query("DELETE FROM regular_users WHERE user_id = $1", [user_id]);

    // Add to the selected tier table
    if (tier === 'top') {
      await pool.query(
        `INSERT INTO top_users(id) VALUES($1) ON CONFLICT (id) DO NOTHING`,
        [user_id]
      );
    } else if (tier === 'regular') {
      await pool.query(
        `INSERT INTO regular_users(user_id) VALUES($1) ON CONFLICT (user_id) DO NOTHING`,
        [user_id]
      );
    }

    broadcastTopUserUpdate(req.user.company);
    res.json({ success: true, tier, message: `User tier updated to ${tier}` });
  } catch (err) {
    console.error("Set tier error:", err);
    res.status(500).json({ message: "Failed to update tier" });
  }
});

app.put("/admin/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { wallet_balance } = req.body;

    if (wallet_balance === undefined) {
      return res.status(400).json({ message: "No fields to update" });
    }

    const numBalance = Number(wallet_balance);
    if (isNaN(numBalance)) {
      return res.status(400).json({ message: "Wallet balance must be a valid number" });
    }

    const result = await pool.query(
      `UPDATE users SET wallet_balance=$1 WHERE id=$2 AND company=$3 RETURNING id,username,email,wallet_balance,company`,
      [numBalance, id, req.user.company]
    );
    if (!result.rows.length) return res.status(404).json({ message: "User not found" });

    // Only top_users table has wallet_balance column
    await pool.query(`UPDATE top_users SET wallet_balance=$1 WHERE id=$2`, [numBalance, id]);

    res.json({ message: "User updated", user: result.rows[0] });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ message: "Failed to update user" });
  }
});

/* ================= ADMIN: PLANS MANAGER - 3 Tier Pricing ================= */
app.get("/admin/plans", auth, adminOnly, async (req, res) => {
  try {
    res.set("Cache-Control", "no-store");
    const plans = await pool.query(
      "SELECT * FROM plans WHERE company = $1 ORDER BY network, price",
      [req.user.company]
    );
    res.json(plans.rows);
  } catch (err) {
    console.error("Get plans error:", err);
    res.status(500).json({ message: "Failed to fetch plans" });
  }
});

app.post("/admin/plans", auth, adminOnly, async (req, res) => {
  const { plan_id, network, name, price, regular_price, top_price, cost, validity, restricted, provider, network_id, api_plan_id } = req.body;

  if (!plan_id ||!network ||!name ||!price ||!cost ||!provider ||!network_id ||!api_plan_id) {
    return res.status(400).json({ message: "Missing required fields: plan_id, network, name, price, cost, provider, network_id, api_plan_id" });
  }

  // Parse validity to extract number from strings like "30 Days"
  const parseValidity = (val) => {
    if (val === '' || val === null || val === undefined) return null;
    const match = String(val).match(/(\d+)/);
    return match? Number(match[1]) : NaN;
  };

  const parsedValidity = parseValidity(validity);
  if (validity!== '' && validity!== null && validity!== undefined && isNaN(parsedValidity)) {
    return res.status(400).json({ message: "validity must contain a valid number" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO plans(plan_id, company, network, name, price, regular_price, top_price, cost, validity, restricted, is_active, provider, network_id, api_plan_id)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $11, $12, $13) RETURNING *`,
      [
        plan_id, req.user.company, network, name,
        Number(price),
        regular_price === '' || regular_price === null || regular_price === undefined? null : Number(regular_price),
        top_price === '' || top_price === null || top_price === undefined? null : Number(top_price),
        Number(cost),
        parsedValidity,
        restricted || false,
        provider, Number(network_id), api_plan_id
      ]
    );
    res.json({ message: "Plan added", plan: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(400).json({ message: "Plan ID already exists" });
    console.error("Add plan error:", e);
    res.status(500).json({ message: "Failed to add plan" });
  }
});

app.put("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  const { id } = req.params;
  const allowed = ['plan_id', 'network', 'name', 'price', 'regular_price', 'top_price', 'cost', 'validity', 'restricted', 'is_active', 'provider', 'network_id', 'api_plan_id'];

  const updates = {};
  for (const key of allowed) {
    const value = req.body[key];
    if (value === undefined) continue;

    // Handle numeric fields - only convert empty/null/undefined to null
    if (['price', 'regular_price', 'top_price', 'cost', 'network_id'].includes(key)) {
      if (value === '' || value === null || value === undefined) {
        updates[key] = null;
      } else {
        const numValue = Number(value);
        if (isNaN(numValue)) {
          return res.status(400).json({ message: `${key} must be a valid number` });
        }
        updates[key] = numValue;
      }
    }
    // Handle validity separately to parse "30 Days" -> 30
    else if (key === 'validity') {
      if (value === '' || value === null || value === undefined) {
        updates[key] = null;
      } else {
        const match = String(value).match(/(\d+)/);
        if (!match) {
          return res.status(400).json({ message: `validity must contain a valid number` });
        }
        updates[key] = Number(match[1]);
      }
    }
    else {
      updates[key] = value;
    }
  }

  if (!Object.keys(updates).length) return res.status(400).json({ message: "No fields to update" });

  const set = Object.keys(updates).map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = Object.values(updates);
  values.push(id, req.user.company);

  try {
    const result = await pool.query(
      `UPDATE plans SET ${set} WHERE id = $${values.length - 1} AND company = $${values.length} RETURNING *`,
      values
    );
    if (!result.rows.length) return res.status(404).json({ message: "Plan not found" });
    res.json({ message: "Plan updated", plan: result.rows[0] });
  } catch (e) {
    console.error("UPDATE PLAN ERROR:", e.message);
    res.status(500).json({ message: "Failed to update plan: " + e.message });
  }
});

app.delete("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "UPDATE plans SET is_active = FALSE WHERE id = $1 AND company = $2 RETURNING id",
      [id, req.user.company]
    );
    if (!result.rows.length) return res.status(404).json({ message: "Plan not found" });
    res.json({ message: "Plan deactivated" });
  } catch (err) {
    console.error("Delete plan error:", err);
    res.status(500).json({ message: "Failed to deactivate plan" });
  }
});





// Health check for UptimeRobot
app.get("/", (req, res) => {
  res.send("MAYCONNECT API Live");
});

/* ================= START ================= */
server.listen(PORT, () => console.log(`Server running on ${PORT}`));