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

const app = express();
app.use(express.static('public'));

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

app.set('trust proxy', 1);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

// 1. CORS
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

/* ================= DATABASE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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

const PAYSTACK_KEYS = JSON.parse(process.env.PAYSTACK_KEYS || "{}");
console.log("Loaded Paystack keys for:", Object.keys(PAYSTACK_KEYS));

/* ================= VTU PROVIDER CONFIG ================= */
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

/* ================= WEBSOCKET SETUP ================= */
const clients = new Map();
wss.on("connection", (ws, req) => {
  try {
    const token = new URL(req.url, "http://x").searchParams.get("token");
    const user = jwt.verify(token, process.env.JWT_SECRET);
    clients.set(user.id, ws);
    ws.on("close", () => clients.delete(user.id));
    console.log(`WS Connected: user ${user.id}`);
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
    console.error('Save push sub error:', err);
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
    console.error(`Push failed for ${company}:`, err.message);
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

  console.log(`[Maitama] ${company} REQUEST:`, { url: `${base_url}/api/data`, payload });

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

// 2. PAYSTACK WEBHOOK - MUST BE BEFORE express.json()
app.post("/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    console.log("PAYSTACK WEBHOOK HIT");
    try {
      const rawBody = req.body;
      const signature = req.headers["x-paystack-signature"];
      if (!rawBody ||!signature) {
        console.log("Missing rawBody or signature");
        return res.sendStatus(400);
      }
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
      if (!isValid) {
        console.log("❌ Invalid signature");
        return res.sendStatus(400);
      }
      const event = JSON.parse(rawBody.toString());
      if (event.event!== "charge.success") return res.sendStatus(200);
      const amount = event.data.amount / 100;
      const reference = event.data.reference;
      let user_id = event.data.metadata?.user_id;
      if (!user_id) {
        const email = event.data.customer?.email;
        if (email) {
          const u = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
          if (u.rows.length) user_id = u.rows[0].id;
        }
      }
      if (!user_id) {
        console.log("❌ USER NOT FOUND → NO CREDIT:", reference);
        return res.sendStatus(200);
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const existing = await client.query("SELECT status FROM transactions WHERE reference=$1 FOR UPDATE", [reference]);
        if (existing.rows.length && existing.rows[0].status === "SUCCESS") {
          await client.query("ROLLBACK");
          return res.sendStatus(200);
        }
        const update = await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2 RETURNING wallet_balance", [amount, user_id]);
        const newBalance = update.rows[0].wallet_balance;
        if (existing.rows.length) {
          await client.query("UPDATE transactions SET status='SUCCESS', amount=$2 WHERE reference=$1", [reference, amount]);
        } else {
          await client.query(`INSERT INTO transactions(user_id,type,amount,reference,status) VALUES($1,'WALLET_FUND',$2,$3,'SUCCESS')`, [user_id, amount, reference]);
        }
        await client.query("COMMIT");
        sendWalletUpdate(user_id, Number(newBalance));
        console.log(`✅ Wallet funded: ₦${amount} -> user ${user_id}`);
      } catch (e) {
        await client.query("ROLLBACK");
        console.log("WEBHOOK TX ERROR:", e.message);
      } finally {
        client.release();
      }
      res.sendStatus(200);
    } catch (e) {
      console.log("WEBHOOK ERROR:", e.message);
      res.sendStatus(500);
    }
  }
);

// 3. JSON PARSER - AFTER WEBHOOK ONLY
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  if (!amount || Number(amount) < 100) {
    return res.status(400).json({ message: "Minimum funding is ₦100" });
  }
  const user = await getUser(req.user.id);
  console.log("FUND INIT USER:", { id: user.id, email: user.email, company: user.company });
  const paystackSecret = getPaystackKey(user.company, "secret");
  if (!paystackSecret) {
    return res.status(500).json({ message: "Payment not configured for your company" });
  }
  const reference = "FUND-" + uuidv4();
  try {
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: user.email,
        amount: Number(amount) * 100,
        reference,
        metadata: {
          user_id: user.id,
          company: user.company
        }
      },
      {
        headers: {
          Authorization: `Bearer ${paystackSecret}`
        }
      }
    );
    console.log("PAYSTACK INIT METADATA:", { user_id: user.id, company: user.company });
    res.json({
      url: response.data.data.authorization_url,
      reference
    });
  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Unable to initialize payment" });
  }
});


/* ================= WEBAUTHN - BIOMETRIC ================= */
const rpName = 'TEEVERSH';

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

  // Fallback for Render: use host header
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
      rpId,
      userID: userID,
      userName: user.email,
      userDisplayName: user.username || user.email,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform', // FORCE PHONE SENSOR
        userVerification: 'preferred',
        residentKey: 'discouraged' // KEY FIX: tells Android not to make it discoverable
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ]
    });

    options.rpId = rpId;

    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, user.id]);
    res.json(options);

  } catch (e) {
    console.error('Register start error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

const { isoBase64URL } = require('@simplewebauthn/server/helpers');

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
      requireUserVerification: false
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;
      
      if (!credential || !credential.id || !credential.publicKey) {
        console.error('RegistrationInfo missing fields:', verification.registrationInfo);
        return res.status(400).json({ verified: false, error: 'Incomplete credential data' });
      }

      // FIX: Use Buffer to convert ArrayBuffer to base64url - works in all Node versions
      const credentialID = typeof credential.id === 'string' 
        ? credential.id 
        : Buffer.from(credential.id).toString('base64url');
      
      const publicKey = typeof credential.publicKey === 'string'
        ? credential.publicKey
        : Buffer.from(credential.publicKey).toString('base64url');

      await pool.query(
        `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, rp_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (credential_id) DO UPDATE SET public_key=$3, counter=$4, rp_id=$5`,
        [
          user.id,
          credentialID,
          publicKey,
          credential.counter,
          rpId
        ]
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
      rpId,
      userVerification: 'preferred',
      allowCredentials: creds.rows.map(c => ({
        id: c.credential_id,
        type: 'public-key',
        transports: ['internal']
      }))
    });

    // CRITICAL FIX: Ensure rpId is in the response
    options.rpId = rpId;

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
      response: authResponse, // v9+ accepts whole body
      expectedChallenge: user.webauthn_challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpId,
      credential: {
        id: cred.rows[0].credential_id,
        publicKey: Buffer.from(cred.rows[0].public_key, 'base64url'),
        counter: cred.rows[0].counter
      },
      requireUserVerification: false
    });

    if (verification.verified) {
      // FIX: v9 puts counter in authenticationInfo.newCounter
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

app.post('/api/auth/webauthn/verify-purchase', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id);
    const rpId = getRpID(req);

    const creds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND rp_id=$2',
      [user.id, rpId]
    );
    if (!creds.rows.length) return res.status(400).json({ error: 'Biometric not enabled' });

    const options = await generateAuthenticationOptions({
      rpId,
      userVerification: 'preferred',
      allowCredentials: creds.rows.map(c => ({
        id: c.credential_id,
        type: 'public-key',
        transports: ['internal']
      }))
    });

    // CRITICAL FIX: Ensure rpId is in the response
    options.rpId = rpId;

    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, user.id]);
    res.json(options);

  } catch (e) {
    console.error('Verify purchase error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/webauthn/verify-purchase-finish', auth, async (req, res) => {
  const user = await getUser(req.user.id);
  const rpId = getRpID(req);
  const expectedOrigin = getExpectedOrigin(req);

  const cred = await pool.query(
    'SELECT * FROM webauthn_credentials WHERE credential_id=$1 AND user_id=$2 AND rp_id=$3',
    [req.body.id, user.id, rpId]
  );

  if (!cred.rows.length) return res.status(400).json({ verified: false });

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body, // v9+ accepts whole body
      expectedChallenge: user.webauthn_challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpId,
      credential: {
        id: cred.rows[0].credential_id,
        publicKey: Buffer.from(cred.rows[0].public_key, 'base64url'),
        counter: cred.rows[0].counter
      },
      requireUserVerification: false
    });

    if (verification.verified) {
      const { authenticationInfo } = verification;

      await pool.query('UPDATE webauthn_credentials SET counter=$1 WHERE id=$2',
        [authenticationInfo.newCounter, cred.rows[0].id]);

      await pool.query('UPDATE users SET webauthn_challenge=NULL WHERE id=$1', [user.id]);
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (e) {
    console.error('WebAuthn purchase verify error:', e.message);
    res.status(400).json({ verified: false, error: e.message });
  }
});



/* ================= DVA ROUTE ================= */
app.post('/api/wallet/create-dva', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const userResult = await pool.query('SELECT email, username, phone FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.phone) return res.status(400).json({ error: 'Phone number missing. Update profile first.' });

    const paystackSecret = getPaystackKey(req.user.company, "secret");
    const response = await axios.post('https://api.paystack.co/dedicated_account', {
      customer: user.email,
      preferred_bank: 'wema-bank',
      phone: user.phone,
      first_name: user.username,
      last_name: 'VTU'
    }, {
      headers: {
        Authorization: `Bearer ${paystackSecret}`,
        'Content-Type': 'application/json'
      }
    });

    const account = response.data.data;
    await pool.query(
      `UPDATE users SET dva_account_number = $1, dva_bank_name = $2, dva_account_name = $3 WHERE id = $4`,
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

/* ================= ADMIN: USERS + TIERS ================= */
app.get("/admin/users", auth, adminOnly, async (req, res) => {
  try {
    const { search } = req.query;
    let query = `
      SELECT
        u.id, u.username, u.email, u.wallet_balance, u.company, u.created_at, u.phone,
        CASE
          WHEN t.id IS NOT NULL THEN 'top'
          WHEN r.user_id IS NOT NULL THEN 'regular'
          ELSE 'default'
        END as user_tier
      FROM users u
      LEFT JOIN top_users t ON t.id = u.id
      LEFT JOIN regular_users r ON r.user_id = u.id
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

    if (!['default', 'regular', 'top'].includes(tier)) {
      return res.status(400).json({ message: "Invalid tier" });
    }

    const check = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND company = $2",
      [user_id, req.user.company]
    );
    if (!check.rows.length) return res.status(404).json({ message: "User not found" });

    await pool.query("DELETE FROM top_users WHERE id = $1", [user_id]);
    await pool.query("DELETE FROM regular_users WHERE user_id = $1", [user_id]);

    if (tier === 'top') {
      await pool.query(
        `INSERT INTO top_users(id, username, email, wallet_balance) 
         SELECT id, username, email, wallet_balance FROM users WHERE id = $1`,
        [user_id]
      );
    } else if (tier === 'regular') {
      await pool.query("INSERT INTO regular_users(user_id) VALUES($1)", [user_id]);
    }

    broadcastTopUserUpdate(req.user.company);
    res.json({ success: true, tier });
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

    const result = await pool.query(
      `UPDATE users SET wallet_balance=$1 WHERE id=$2 AND company=$3 RETURNING id,username,email,wallet_balance,company`,
      [wallet_balance, id, req.user.company]
    );
    if (!result.rows.length) return res.status(404).json({ message: "User not found" });

    res.json({ message: "User updated", user: result.rows[0] });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ message: "Failed to update user" });
  }
});

/* ================= ADMIN: TOP USERS LIST ================= */
app.get("/admin/top-users", auth, adminOnly, async (req, res) => {
  try {
    const users = await pool.query(
      `SELECT u.id, u.username, u.email, u.company,
              COALESCE(SUM(t.amount), 0) as total_spent,
              COALESCE(SUM(p.amount), 0) as total_profit_generated
       FROM users u
       INNER JOIN top_users tu ON tu.id = u.id
       LEFT JOIN transactions t ON t.user_id = u.id AND t.status = 'SUCCESS'
       LEFT JOIN profits p ON p.transaction_id = t.id
       WHERE u.company = $1
       GROUP BY u.id, u.username, u.email, u.company
       ORDER BY total_spent DESC`,
      [req.user.company]
    );
    res.json(users.rows);
  } catch (err) {
    console.error("Top users error:", err);
    res.status(500).json({ message: "Failed to fetch top users" });
  }
});

app.post("/admin/top-users/add", auth, adminOnly, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query(
      "SELECT id, username, email, wallet_balance FROM users WHERE email = $1 AND company = $2",
      [email, req.user.company]
    );
    if (!user.rows.length) return res.status(404).json({ message: "User not found in your company" });

    await pool.query(
      `INSERT INTO top_users(id, username, email, wallet_balance) 
       VALUES($1, $2, $3, $4) 
       ON CONFLICT (id) DO UPDATE SET 
         username = EXCLUDED.username,
         email = EXCLUDED.email,
         wallet_balance = EXCLUDED.wallet_balance`,
      [user.rows[0].id, user.rows[0].username, user.rows[0].email, user.rows[0].wallet_balance]
    );
    await pool.query("DELETE FROM regular_users WHERE user_id = $1", [user.rows[0].id]);

    broadcastTopUserUpdate(req.user.company);
    res.json({ message: "Top user added" });
  } catch (err) {
    console.error("Add top user error:", err);
    res.status(500).json({ message: "Failed to add top user" });
  }
});

app.delete("/admin/top-users/remove", auth, adminOnly, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query(
      "SELECT id FROM users WHERE email = $1 AND company = $2",
      [email, req.user.company]
    );
    if (!user.rows.length) return res.status(404).json({ message: "User not found in your company" });

    const result = await pool.query("DELETE FROM top_users WHERE id = $1", [user.rows[0].id]);
    if (result.rowCount === 0) return res.status(404).json({ message: "User is not a top user" });

    broadcastTopUserUpdate(req.user.company);
    res.json({ message: "Top user removed" });
  } catch (err) {
    console.error("Remove top user error:", err);
    res.status(500).json({ message: "Failed to remove top user" });
  }
});

/* ================= ADMIN: REGULAR USERS LIST ================= */
app.get("/admin/regular-users", auth, adminOnly, async (req, res) => {
  try {
    const users = await pool.query(
      `SELECT u.id, u.username, u.email, u.company,
              COALESCE(SUM(t.amount), 0) as total_spent,
              COALESCE(SUM(p.amount), 0) as total_profit_generated
       FROM users u
       INNER JOIN regular_users ru ON ru.user_id = u.id
       LEFT JOIN transactions t ON t.user_id = u.id AND t.status = 'SUCCESS'
       LEFT JOIN profits p ON p.transaction_id = t.id
       WHERE u.company = $1
       GROUP BY u.id, u.username, u.email, u.company
       ORDER BY total_spent DESC`,
      [req.user.company]
    );
    res.json(users.rows);
  } catch (err) {
    console.error("Regular users error:", err);
    res.status(500).json({ message: "Failed to fetch regular users" });
  }
});

app.post("/admin/regular-users/add", auth, adminOnly, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query(
      "SELECT id FROM users WHERE email = $1 AND company = $2",
      [email, req.user.company]
    );
    if (!user.rows.length) return res.status(404).json({ message: "User not found in your company" });

    await pool.query(
      "INSERT INTO regular_users(user_id) VALUES($1) ON CONFLICT DO NOTHING",
      [user.rows[0].id]
    );
    await pool.query("DELETE FROM top_users WHERE id = $1", [user.rows[0].id]);

    broadcastTopUserUpdate(req.user.company);
    res.json({ message: "Regular user added" });
  } catch (err) {
    console.error("Add regular user error:", err);
    res.status(500).json({ message: "Failed to add regular user" });
  }
});

app.delete("/admin/regular-users/remove", auth, adminOnly, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query(
      "SELECT id FROM users WHERE email = $1 AND company = $2",
      [email, req.user.company]
    );
    if (!user.rows.length) return res.status(404).json({ message: "User not found in your company" });

    await pool.query("DELETE FROM regular_users WHERE user_id = $1", [user.rows[0].id]);

    broadcastTopUserUpdate(req.user.company);
    res.json({ message: "Regular user removed" });
  } catch (err) {
    console.error("Remove regular user error:", err);
    res.status(500).json({ message: "Failed to remove regular user" });
  }
});


/* ================= ADMIN: PLANS MANAGER - 3 Tier Pricing ================= */
app.get("/admin/plans", auth, adminOnly, async (req, res) => {
  try {
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

  try {
    const result = await pool.query(
      `INSERT INTO plans(plan_id, company, network, name, price, regular_price, top_price, cost, validity, restricted, is_active, provider, network_id, api_plan_id)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $11, $12, $13) RETURNING *`,
      [
        plan_id, req.user.company, network, name,
        price,
        regular_price || price,
        top_price || price,
        cost, validity, restricted || false,
        provider, network_id, api_plan_id
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
    if (req.body[key]!== undefined) updates[key] = req.body[key];
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
    res.status(500).json({ message: "Failed to update plan" });
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
/* ================= ADMIN: WITHDRAWALS ================= */

// 1. BANK CODES - Add at top of server.js or in separate file
const BANK_CODES = {
    // Commercial Banks
    "Access Bank": "044",
    "Citibank": "023",
    "Ecobank": "050",
    "Fidelity Bank": "070",
    "First Bank": "011",
    "FCMB": "214",
    "GTBank": "058",
    "GT Bank": "058",
    "Heritage Bank": "030",
    "Keystone Bank": "082",
    "Polaris Bank": "076",
    "Stanbic IBTC": "221",
    "Standard Chartered": "068",
    "Sterling Bank": "232",
    "Union Bank": "032",
    "UBA": "033",
    "Unity Bank": "215",
    "Wema Bank": "035",
    "Zenith Bank": "057",
    // Microfinance/Fintech
    "Kuda": "50211",
    "Opay": "999992",
    "Palmpay": "999991",
    "Moniepoint": "50515",
    "VFD Microfinance": "566",
    "Carbon": "565",
    "Rubies MFB": "125",
    "Sparkle": "51310"
};

function getBankCode(bankName) {
    if (!bankName) return null;
    const cleanName = bankName.trim();
    const lowerName = cleanName.toLowerCase();

    // Handle common variations
    if (lowerName.includes("gtb") || lowerName.includes("gtbank")) return "058";
    if (lowerName.includes("firstbank")) return "011";
    if (lowerName.includes("zenith")) return "057";
    if (lowerName.includes("access")) return "044";
    if (lowerName.includes("uba")) return "033";
    if (lowerName.includes("stanbic")) return "221";

    return BANK_CODES[cleanName] || null;
}

// 2. LIST WITHDRAWALS - unchanged but added transfer_code
app.get("/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const wds = await pool.query(
    "SELECT reference, amount, bank_name, account_number, account_name, status, transfer_code, created_at FROM withdrawals WHERE admin_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(wds.rows);
});

// 3. REQUEST WITHDRAWAL - add minimum check
app.post("/admin/withdraw-request", auth, adminOnly, async (req, res) => {
  const { amount, bank_name, account_number, account_name } = req.body;
  if (!amount ||!bank_name ||!account_number ||!account_name) {
    return res.status(400).json({ message: "All fields required" });
  }

  if (Number(amount) < 100) {
    return res.status(400).json({ message: "Minimum withdrawal is ₦100" });
  }

  const user = await getUser(req.user.id);
  if (Number(user.admin_wallet) < Number(amount)) {
    return res.status(400).json({ message: "Insufficient admin wallet balance" });
  }

  const bankCode = getBankCode(bank_name);
  if (!bankCode) {
    return res.status(400).json({ message: `Unsupported bank: ${bank_name}` });
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
    // Don't deduct wallet yet - only on successful transfer
    await client.query("COMMIT");
    res.json({ message: "Withdrawal request created", reference });
  } catch (e) {
    await client.query("ROLLBACK");
    console.log("WITHDRAW ERROR:", e.message);
    res.status(500).json({ message: "Withdrawal failed" });
  } finally {
    client.release();
  }
});

// 4. APPROVE WITHDRAWAL - NOW WITH PAYSTACK TRANSFER
app.post("/admin/withdraw/approve", auth, adminOnly, async (req, res) => {
  const { reference } = req.body;
  const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;

  if (!PAYSTACK_SECRET) {
    return res.status(500).json({ message: "Paystack key not configured" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Get withdrawal + lock row
    const wdRes = await client.query(
      "SELECT * FROM withdrawals WHERE reference=$1 AND admin_id=$2 FOR UPDATE",
      [reference, req.user.id]
    );

    if (!wdRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Withdrawal not found" });
    }

    const wd = wdRes.rows[0];
    if (wd.status!== 'PENDING') {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: `Already ${wd.status}` });
    }

    // Check admin wallet again
    const user = await getUser(req.user.id);
    if (Number(user.admin_wallet) < Number(wd.amount)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient admin wallet balance" });
    }

    const bankCode = getBankCode(wd.bank_name);
    if (!bankCode) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Unsupported bank code" });
    }

    // Step 1: Create Paystack recipient
    const recipientRes = await fetch("https://api.paystack.co/transferrecipient", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        type: "nuban",
        name: wd.account_name,
        account_number: wd.account_number,
        bank_code: bankCode,
        currency: "NGN"
      })
    });
    const recipientData = await recipientRes.json();

    if (!recipientData.status) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Bank validation failed: " + recipientData.message });
    }

    // Step 2: Initiate transfer
    const transferRes = await fetch("https://api.paystack.co/transfer", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        source: "balance",
        amount: Math.round(Number(wd.amount) * 100), // kobo
        recipient: recipientData.data.recipient_code,
        reason: `MayConnect Admin Payout ${reference}`
      })
    });
    const transferData = await transferRes.json();

    if (!transferData.status) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Transfer failed: " + transferData.message });
    }

    // Step 3: Only update DB if Paystack succeeded
    await client.query(
      "UPDATE withdrawals SET status='PAID', transfer_code=$1, paid_at=NOW() WHERE reference=$2",
      [transferData.data.transfer_code, reference]
    );
    await client.query(
      "UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2",
      [wd.amount, req.user.id]
    );

    await client.query("COMMIT");
    res.json({
      message: `₦${wd.amount} sent to ${wd.bank_name} ✅`,
      transfer_code: transferData.data.transfer_code
    });

  } catch (e) {
    await client.query("ROLLBACK");
    console.log("APPROVE WITHDRAW ERROR:", e);
    res.status(500).json({ message: "Server error during transfer" });
  } finally {
    client.release();
  }
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

    // Ensure reversal only within same company
    const txUser = await client.query("SELECT company FROM users WHERE id=$1", [t.user_id]);
    if (txUser.rows[0].company!== req.user.company) {
      throw new Error("Cannot reverse transaction from another company");
    }

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

// Health check for UptimeRobot
app.get("/", (req, res) => {
  res.send("MAYCONNECT API Live");
});

/* ================= START ================= */
server.listen(PORT, () => console.log(`Server running on ${PORT}`));