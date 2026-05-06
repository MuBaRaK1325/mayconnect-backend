const express = require("express");
const path = require('path');
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg"); // ONLY DECLARE THIS ONCE - AT THE TOP
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
  ssl: {
    rejectUnauthorized: false // Required for Render + Neon
  }
});

// Test connection on startup
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error connecting to Postgres:', err.stack);
  } else {
    console.log('Connected to Postgres successfully');
    release();
  }
});

// DON'T export pool here if you import it elsewhere. Remove this line:
// module.exports = pool;

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

// PAYMENT KEYS
const MONNIFY_KEYS = JSON.parse(process.env.MONNIFY_KEYS || "{}");
const FLW_KEYS = JSON.parse(process.env.FLW_KEYS || "{}");

const VTU_PROVIDERS = {
  maitama: { base_url: process.env.MAITAMA_BASE_URL, tokens: { mayconnect: process.env.MAITAMA_TOKEN_MAYCONNECT, teeversh: process.env.MAITAMA_TOKEN_TEEVERSH, sadeeq: process.env.MAITAMA_TOKEN_SADEEQ, bnhabeeb: process.env.MAITAMA_TOKEN_BNHABEEB } },
  cheapdatahub: { base_url: "https://www.cheapdatahub.ng/api/v1/resellers", api_key: process.env.CHEAPDATAHUB_API_KEY },
  subpadi: { base_url: "https://api.subpadi.com", token: process.env.SUBPADI_TOKEN }
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

const getMonnifyKey = (company, type = "secret") => {
  const keys = MONNIFY_KEYS[company] || MONNIFY_KEYS.mayconnect;
  return keys?.[type] || null;
};

const getMonnifyContract = (company) => {
  const keys = MONNIFY_KEYS[company] || MONNIFY_KEYS.mayconnect;
  return keys?.contract || null;
};

const getFLWKey = (company, type = "secret") => {
  const keys = FLW_KEYS[company] || FLW_KEYS.sadeeq;
  return keys?.[type] || null;
};

const getUser = async (id) => {
  const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return res.rows[0];
};

async function createMonnifyAccount(user) {
  const apiKey = getMonnifyKey(user.company, "api");
  const secretKey = getMonnifyKey(user.company, "secret");
  const contractCode = getMonnifyContract(user.company);
  if (!apiKey ||!secretKey ||!contractCode) throw new Error("Monnify not configured for your company");
  if (!user.phone) throw new Error("Phone number required to create virtual account. Please update your profile.");

  try {
    const auth = Buffer.from(`${apiKey}:${secretKey}`).toString('base64');
    const login = await axios.post('https://api.monnify.com/api/v1/auth/login', {}, {
      headers: { Authorization: `Basic ${auth}` }
    });
    const token = login.data.responseBody.accessToken;

    const acc = await axios.post('https://api.monnify.com/api/v2/bank-transfer/reserved-accounts', {
      accountReference: `${user.company.toUpperCase().slice(0,3)}_${user.id}_${Date.now()}`,
      accountName: user.username,
      currencyCode: "NGN",
      contractCode: contractCode,
      customerEmail: user.email,
      customerName: user.username,
      getAllAvailableBanks: true
    }, { headers: { Authorization: `Bearer ${token}` } });

    const account = acc.data.responseBody.accounts[0];
    await pool.query(
      `UPDATE users SET account_number=$1, account_name=$2, bank_name=$3 WHERE id=$4`,
      [account.accountNumber, account.accountName, account.bankName, user.id]
    );
    return account;
  } catch (e) {
    const errData = e.response?.data || e.message;
    console.log("MONNIFY CREATE ACCOUNT ERROR:", JSON.stringify(errData));
    throw new Error(errData?.message || "Failed to create Monnify account");
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

/* ================= MONNIFY WEBHOOK - MUST BE BEFORE express.json() ================= */
app.post("/api/monnify/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    console.log("MONNIFY WEBHOOK HIT");
    try {
      const rawBody = req.body;
      const signature = req.headers["monnify-signature"];
      if (!rawBody ||!signature) {
        return res.sendStatus(400);
      }

      const hash = crypto.createHmac("sha512", process.env.MONNIFY_SECRET_KEY).update(rawBody).digest("hex");
      if (hash!== signature) {
        return res.sendStatus(400);
      }

      const event = JSON.parse(rawBody.toString());
      if (event.eventType!== "SUCCESSFUL_TRANSACTION") return res.sendStatus(200);

      const amount = Number(event.eventData.amountPaid);
      const reference = event.eventData.paymentReference;
      const accountRef = event.eventData.accountReference;
      const userId = accountRef.split('_')[1];

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const existing = await client.query("SELECT status FROM transactions WHERE reference=$1 FOR UPDATE", [reference]);
        if (existing.rows.length && existing.rows[0].status === "SUCCESS") {
          await client.query("ROLLBACK");
          return res.sendStatus(200);
        }
        const update = await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2 RETURNING wallet_balance", [amount, userId]);
        const newBalance = update.rows[0].wallet_balance;
        if (!existing.rows.length) {
          await client.query(`INSERT INTO transactions(user_id,type,amount,reference,status) VALUES($1,'WALLET_FUND',$2,$3,'SUCCESS')`, [userId, amount, reference]);
        }
        await client.query("COMMIT");
        sendWalletUpdate(userId, Number(newBalance));
      } catch (e) {
        await client.query("ROLLBACK");
        console.log("MONNIFY WEBHOOK TX ERROR:", e.message);
      } finally {
        client.release();
      }
      res.sendStatus(200);
    } catch (e) {
      console.log("MONNIFY WEBHOOK ERROR:", e.message);
      res.sendStatus(500);
    }
  }
);

/* ================= FLUTTERWAVE WEBHOOK - MUST BE BEFORE express.json() ================= */
app.post("/api/flutterwave/webhook", async (req, res) => {
  console.log("FLUTTERWAVE WEBHOOK HIT");
  try {
    const signature = req.headers['verif-hash'];
    if (!signature || signature!== process.env.FLW_SECRET_HASH) {
      return res.sendStatus(401);
    }

    const event = req.body;
    if (event.status!== 'successful') return res.sendStatus(200);

    const amount = Number(event.amount);
    const reference = event.txRef;
    const email = event.customer?.email;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const userRes = await client.query("SELECT id FROM users WHERE email=$1 FOR UPDATE", [email]);
      if (!userRes.rows.length) {
        await client.query("ROLLBACK");
        return res.sendStatus(200);
      }
      const userId = userRes.rows[0].id;

      const existing = await client.query("SELECT status FROM transactions WHERE reference=$1 FOR UPDATE", [reference]);
      if (existing.rows.length && existing.rows[0].status === "SUCCESS") {
        await client.query("ROLLBACK");
        return res.sendStatus(200);
      }
      const update = await client.query("UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2 RETURNING wallet_balance", [amount, userId]);
      const newBalance = update.rows[0].wallet_balance;
      if (!existing.rows.length) {
        await client.query(`INSERT INTO transactions(user_id,type,amount,reference,status) VALUES($1,'WALLET_FUND',$2,$3,'SUCCESS')`, [userId, amount, reference]);
      }
      await client.query("COMMIT");
      sendWalletUpdate(userId, Number(newBalance));
    } catch (e) {
      await client.query("ROLLBACK");
      console.log("FLW WEBHOOK TX ERROR:", e.message);
    } finally {
      client.release();
    }
    res.sendStatus(200);
  } catch (e) {
    console.log("FLUTTERWAVE WEBHOOK ERROR:", e.message);
    res.sendStatus(500);
  }
});

/* ================= JSON PARSER - AFTER WEBHOOKS ONLY ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

/* ================= WEBAUTHN CONFIG ================= */
const CORS_ORIGINS = [
  'https://teeversh-frontend.onrender.com',
  'https://mayconnect-frontend.onrender.com',
  'https://sadeeq-frontend.onrender.com',
  'https://bnhabeeb-frontend.onrender.com',
  'http://localhost:3000',
  'http://localhost:5173'
];

function getWebAuthnConfig(origin) {
  if (!origin) origin = CORS_ORIGINS[0];
  const url = new URL(origin);
  return {
    rpID: url.hostname,
    rpName: 'Mayconnect',
    origin: origin
  };
}

function userIdToBuffer(userId) {
  return Buffer.from(String(userId), 'utf-8');
}

function toBase64URL(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toBase64(base64url) {
  if (!base64url || typeof base64url!== 'string') return '';
  const padding = '='.repeat((4 - base64url.length % 4) % 4);
  return (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
}

/* ================= WEBAUTHN ROUTES ================= */
app.get('/api/auth/webauthn/check-enabled', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT webauthn_enabled FROM users WHERE id = $1',
      [req.user.id]
    );
    const enabled = result.rows[0]?.webauthn_enabled === true;
    res.json({ enabled });
  } catch (err) {
    if (err.code === '42703') {
      return res.json({ enabled: false });
    }
    console.error('Check enabled error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start registration
app.post('/api/auth/webauthn/register-start', auth, async (req, res) => {
  try {
    const origin = req.headers.origin;
    if (!CORS_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    const { rpID, rpName } = getWebAuthnConfig(origin);

    const user = await getUser(req.user.id);
    const existingCreds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id = $1 AND credential_id IS NOT NULL',
      [user.id]
    );

    // Filter out empty/null credential_ids before mapping
    const validCreds = existingCreds.rows
     .map(c => c.credential_id)
     .filter(id => id && typeof id === 'string' && id.length > 0);

    const options = await generateRegistrationOptions({
      rpName: rpName,
      rpID: rpID,
      userID: userIdToBuffer(user.id),
      userName: user.username,
      userDisplayName: user.username,
      attestationType: 'none',
      excludeCredentials: validCreds.map(id => ({
        id: Buffer.from(toBase64(id), 'base64'),
        type: 'public-key',
      })),
    });

    await pool.query(
      'INSERT INTO webauthn_challenges(user_id, challenge) VALUES($1, $2) ON CONFLICT (user_id) DO UPDATE SET challenge = $2',
      [user.id, options.challenge]
    );

    res.json(options);
  } catch (err) {
    console.error('Register start error:', err);
    res.status(500).json({ error: 'Failed to start registration: ' + err.message });
  }
});

// Finish registration
app.post('/api/auth/webauthn/register-finish', auth, async (req, res) => {
  try {
    const origin = req.headers.origin;
    if (!CORS_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    const { rpID, origin: expectedOrigin } = getWebAuthnConfig(origin);

    const user = await getUser(req.user.id);
    const challengeRes = await pool.query(
      'SELECT challenge FROM webauthn_challenges WHERE user_id = $1',
      [user.id]
    );

    if (!challengeRes.rows.length) {
      return res.status(400).json({ error: 'Challenge not found' });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challengeRes.rows[0].challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;

      const credentialIdB64URL = toBase64URL(Buffer.from(credential.id).toString('base64'));
      const publicKeyB64URL = toBase64URL(Buffer.from(credential.publicKey).toString('base64'));

      await pool.query(
        `INSERT INTO webauthn_credentials(user_id, credential_id, public_key, counter)
         VALUES($1, $2, $3, $4)`,
        [user.id, credentialIdB64URL, publicKeyB64URL, credential.counter]
      );

      await pool.query('UPDATE users SET webauthn_enabled = TRUE WHERE id = $1', [user.id]);
      await pool.query('DELETE FROM webauthn_challenges WHERE user_id = $1', [user.id]);

      res.json({ verified: true });
    } else {
      res.json({ verified: false, error: 'Verification failed' });
    }
  } catch (err) {
    console.error('Register finish error:', err);
    res.status(500).json({ error: 'Failed to verify registration: ' + err.message });
  }
});

// Start login
app.post('/api/auth/webauthn/login-start', async (req, res) => {
  try {
    const origin = req.headers.origin;
    if (!CORS_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    const { rpID } = getWebAuthnConfig(origin);

    const { email } = req.body;
    const userRes = await pool.query('SELECT id, username FROM users WHERE email = $1', [email]);
    if (!userRes.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userRes.rows[0];

    const creds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id = $1 AND credential_id IS NOT NULL',
      [user.id]
    );

    const validCreds = creds.rows
     .map(c => c.credential_id)
     .filter(id => id && typeof id === 'string' && id.length > 0);

    const options = await generateAuthenticationOptions({
      rpID: rpID,
      allowCredentials: validCreds.map(id => ({
        id: Buffer.from(toBase64(id), 'base64'),
        type: 'public-key',
      })),
    });

    await pool.query(
      'INSERT INTO webauthn_challenges(user_id, challenge) VALUES($1, $2) ON CONFLICT (user_id) DO UPDATE SET challenge = $2',
      [user.id, options.challenge]
    );

    res.json(options);
  } catch (err) {
    console.error('Login start error:', err);
    res.status(500).json({ error: 'Failed to start login: ' + err.message });
  }
});

// Finish login
app.post('/api/auth/webauthn/login-finish', async (req, res) => {
  try {
    const origin = req.headers.origin;
    if (!CORS_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    const { rpID, origin: expectedOrigin } = getWebAuthnConfig(origin);

    const { email,...credential } = req.body;
    const userRes = await pool.query('SELECT id, username, company, is_admin FROM users WHERE email = $1', [email]);
    if (!userRes.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userRes.rows[0];

    const challengeRes = await pool.query(
      'SELECT challenge FROM webauthn_challenges WHERE user_id = $1',
      [user.id]
    );
    if (!challengeRes.rows.length) {
      return res.status(400).json({ error: 'Challenge not found' });
    }

    const credRes = await pool.query(
      'SELECT credential_id, public_key, counter FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2',
      [user.id, credential.id]
    );
    if (!credRes.rows.length) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const dbCredential = credRes.rows[0];

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challengeRes.rows[0].challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: Buffer.from(toBase64(dbCredential.credential_id), 'base64'),
        publicKey: Buffer.from(toBase64(dbCredential.public_key), 'base64'),
        counter: dbCredential.counter,
      },
    });

    if (verification.verified) {
      await pool.query(
        'UPDATE webauthn_credentials SET counter = $1 WHERE credential_id = $2',
        [verification.authenticationInfo.newCounter, credential.id]
      );

      await pool.query('DELETE FROM webauthn_challenges WHERE user_id = $1', [user.id]);

      const token = jwt.sign(
        { id: user.id, username: user.username, is_admin: user.is_admin, company: user.company },
        process.env.JWT_SECRET
      );
      res.json({ token });
    } else {
      res.json({ error: 'Verification failed' });
    }
  } catch (err) {
    console.error('Login finish error:', err);
    res.status(500).json({ error: 'Failed to verify login: ' + err.message });
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
    if (user.company === "sadeeq") {
      // FLUTTERWAVE
      const flwSecret = getFLWKey(user.company, "secret");
      if (!flwSecret) return res.status(500).json({ message: "Flutterwave not configured for your company" });

      const response = await axios.post("https://api.flutterwave.com/v3/payments", {
        tx_ref: reference,
        amount: Number(amount),
        currency: "NGN",
        redirect_url: `https://${user.company}-frontend.onrender.com/dashboard.html`,
        customer: { email: user.email, name: user.username }
      }, { headers: { Authorization: `Bearer ${flwSecret}` } });

      res.json({ url: response.data.link, reference });

    } else {
      // MONNIFY for mayconnect, bnhabeeb, teeversh
      let account = await pool.query("SELECT account_number, bank_name, account_name FROM users WHERE id=$1", [user.id]);
      if (!account.rows[0]?.account_number) {
        account = { rows: [await createMonnifyAccount(user)] };
      }
      res.json({
        bank_name: account.rows[0].bank_name,
        account_number: account.rows[0].account_number,
        account_name: account.rows[0].account_name,
        reference
      });
    }
  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Unable to initialize payment" });
  }
});

/* ================= DVA ROUTE - MONNIFY ================= */
app.post('/api/wallet/create-dva', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.company === "sadeeq") return res.status(400).json({ error: 'DVA not available for Sadeeq' });
    if (user.account_number) return res.json({ message: "Account already exists", account: user });
    if (!user.phone) return res.status(400).json({ error: 'Phone number missing. Update profile first.' });

    const account = await createMonnifyAccount(user);
    res.json({
      success: true,
      account_number: account.accountNumber,
      bank_name: account.bankName,
      account_name: account.accountName
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
    if (user.company === "sadeeq") return res.status(400).json({ message: "Sadeeq uses Flutterwave, no DVA" });
    if (user.account_number) return res.json({ message: "Account already exists", account: user });
    if (!user.phone) return res.status(400).json({ message: "Please update your phone number in profile first" });
    const acc = await createMonnifyAccount(user);
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

/* ================= ADMIN: TRANSACTIONS LIST ================= */
app.get("/admin/transactions", auth, adminOnly, async (req, res) => {
  try {
    const { status, provider, search, limit = 200 } = req.query;
    let query = `
      SELECT
        t.id, t.reference, t.type, t.amount, t.status, t.network, t.phone,
        t.created_at, t.metadata, t.description,
        u.id as user_id, u.username, u.email,
        p.name as plan_name, p.provider
      FROM transactions t
      JOIN users u ON u.id = t.user_id
      LEFT JOIN plans p ON p.id = t.plan_id
      WHERE u.company = $1
    `;
    const params = [req.user.company];
    let paramCount = 1;

    if (status) {
      paramCount++;
      query += ` AND t.status = $${paramCount}`;
      params.push(status);
    }
    if (provider) {
      paramCount++;
      query += ` AND p.provider = $${paramCount}`;
      params.push(provider);
    }
    if (search) {
      paramCount++;
      query += ` AND (t.reference ILIKE $${paramCount} OR u.email ILIKE $${paramCount} OR u.username ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${paramCount + 1}`;
    params.push(Number(limit));

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error("Admin transactions error:", err);
    res.status(500).json({ message: "Failed to fetch transactions" });
  }
});

/* ================= ADMIN: MANUAL DEDUCT ================= */
app.post("/admin/transactions/force-deduct", auth, adminOnly, async (req, res) => {
  const { reference, reason } = req.body;

  if (!reference) {
    return res.status(400).json({ message: "Transaction reference required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const txRes = await client.query(
      `SELECT t.id, t.user_id, t.amount, t.status, t.company, p.provider
       FROM transactions t
       LEFT JOIN plans p ON p.id = t.plan_id
       WHERE t.reference=$1 FOR UPDATE`,
      [reference]
    );

    if (!txRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Transaction not found" });
    }

    const tx = txRes.rows[0];

    // Restriction: Only mayconnect can use this for cheapdatahub/subpadi
    const allowedProviders = ['maitama'];
    if (req.user.company === 'mayconnect') {
      allowedProviders.push('cheapdatahub', 'subpadi');
    }
    if (!allowedProviders.includes(tx.provider)) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: `Manual deduction not allowed for ${tx.provider} on ${req.user.company}` });
    }

    if (tx.status === 'SUCCESS') {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Transaction is already marked as SUCCESS" });
    }

    // Check user balance
    const userRes = await client.query(
      "SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE",
      [tx.user_id]
    );
    if (!userRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "User not found" });
    }

    if (Number(userRes.rows[0].wallet_balance) < Number(tx.amount)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "User has insufficient wallet balance" });
    }

    // Deduct user wallet
    const update = await client.query(
      "UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id=$2 RETURNING wallet_balance",
      [tx.amount, tx.user_id]
    );

    // Update transaction status + add admin note in metadata
    await client.query(
      `UPDATE transactions
       SET status='SUCCESS', updated_at=NOW(), metadata = COALESCE(metadata, '{}') || $1
       WHERE reference=$2`,
      [JSON.stringify({
        manual_deducted: true,
        deducted_by: req.user.id,
        deducted_at: new Date().toISOString(),
        reason: reason || "Admin manual deduction - Provider delivered but API failed"
      }), reference]
    );

    await client.query("COMMIT");

    sendWalletUpdate(tx.user_id, Number(update.rows[0].wallet_balance));

    console.log(`ADMIN MANUAL DEDUCT: Admin ${req.user.id} deducted ₦${tx.amount} from user ${tx.user_id} for ${reference}`);

    res.json({
      message: `₦${tx.amount} deducted from user wallet successfully`,
      new_balance: update.rows[0].wallet_balance
    });

  } catch (e) {
    await client.query("ROLLBACK");
    console.error("FORCE DEDUCT ERROR:", e.message);
    res.status(500).json({ message: "Failed to deduct" });
  } finally {
    client.release();
  }
});

/* ================= ADMIN: TRANSACTION REVERSAL ================= */
app.post("/admin/transactions/reverse", auth, adminOnly, async (req, res) => {
  const { reference, reason } = req.body;

  if (!reference) {
    return res.status(400).json({ message: "Transaction reference required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const txRes = await client.query(
      `SELECT t.id, t.user_id, t.amount, t.status, t.company, p.provider
       FROM transactions t
       LEFT JOIN plans p ON p.id = t.plan_id
       WHERE t.reference=$1 FOR UPDATE`,
      [reference]
    );

    if (!txRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Transaction not found" });
    }

    const tx = txRes.rows[0];

    if (tx.status!== 'SUCCESS') {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Only SUCCESS transactions can be reversed" });
    }

    // Refund user wallet
    const update = await client.query(
      "UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2 RETURNING wallet_balance",
      [tx.amount, tx.user_id]
    );

    // Mark transaction as REVERSED
    await client.query(
      `UPDATE transactions
       SET status='REVERSED', updated_at=NOW(), metadata = COALESCE(metadata, '{}') || $1
       WHERE reference=$2`,
      [JSON.stringify({
        reversed: true,
        reversed_by: req.user.id,
        reversed_at: new Date().toISOString(),
        reason: reason || "Admin reversal"
      }), reference]
    );

    // Also reverse profit if exists
    await client.query("DELETE FROM profits WHERE transaction_id=$1", [tx.id]);

    await client.query("COMMIT");

    sendWalletUpdate(tx.user_id, Number(update.rows[0].wallet_balance));

    console.log(`ADMIN REVERSAL: Admin ${req.user.id} reversed ₦${tx.amount} for user ${tx.user_id} for ${reference}`);

    res.json({
      message: `₦${tx.amount} refunded to user wallet successfully`,
      new_balance: update.rows[0].wallet_balance
    });

  } catch (e) {
    await client.query("ROLLBACK");
    console.error("REVERSAL ERROR:", e.message);
    res.status(500).json({ message: "Failed to reverse transaction" });
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
          ELSE 'default'
        END as user_tier
      FROM users u
      LEFT JOIN top_users t ON t.id = u.id
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

    if (!['default', 'top'].includes(tier)) {
      return res.status(400).json({ message: "Invalid tier. Only 'default' or 'top' allowed" });
    }

    const check = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND company = $2",
      [user_id, req.user.company]
    );
    if (!check.rows.length) return res.status(404).json({ message: "User not found" });

    await pool.query("DELETE FROM top_users WHERE id = $1", [user_id]);

    if (tier === 'top') {
      await pool.query(
        `INSERT INTO top_users(id, username, email, wallet_balance)
         SELECT id, username, email, wallet_balance FROM users WHERE id = $1`,
        [user_id]
      );
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

// BANK CODES - for Monnify and Flutterwave
const BANK_CODES = {
    "Access Bank": "044", "Citibank": "023", "Ecobank": "050", "Fidelity Bank": "070",
    "First Bank": "011", "FCMB": "214", "GTBank": "058", "GT Bank": "058",
    "Heritage Bank": "030", "Keystone Bank": "082", "Polaris Bank": "076",
    "Stanbic IBTC": "221", "Standard Chartered": "068", "Sterling Bank": "232",
    "Union Bank": "032", "UBA": "033", "Unity Bank": "215", "Wema Bank": "035",
    "Zenith Bank": "057", "Kuda": "50211", "Opay": "999992", "Palmpay": "999991",
    "Moniepoint": "50515", "VFD Microfinance": "566", "Carbon": "565",
    "Rubies MFB": "125", "Sparkle": "51310"
};

function getBankCode(bankName) {
    if (!bankName) return null;
    const cleanName = bankName.trim();
    const lowerName = cleanName.toLowerCase();

    if (lowerName.includes("gtb") || lowerName.includes("gtbank")) return "058";
    if (lowerName.includes("firstbank")) return "011";
    if (lowerName.includes("zenith")) return "057";
    if (lowerName.includes("access")) return "044";
    if (lowerName.includes("uba")) return "033";
    if (lowerName.includes("stanbic")) return "221";

    return BANK_CODES[cleanName] || null;
}

// LIST WITHDRAWALS
app.get("/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const wds = await pool.query(
    "SELECT reference, amount, bank_name, account_number, account_name, status, transfer_code, created_at FROM withdrawals WHERE admin_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(wds.rows);
});

// REQUEST WITHDRAWAL
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
      `INSERT INTO withdrawals(admin_id,amount,bank_name,account_number,account_name,reference,status,company)
       VALUES($1,$2,$3,$4,$5,$6,'PENDING',$7)`,
      [req.user.id, amount, bank_name, account_number, account_name, reference, user.company]
    );
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

// APPROVE WITHDRAWAL - MONNIFY for 3 brands, FLUTTERWAVE for Sadeeq
app.post("/admin/withdraw/approve", auth, adminOnly, async (req, res) => {
  const { reference } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

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

    let transferCode = null;
    let transferStatus = null;

    if (user.company === "sadeeq") {
      // FLUTTERWAVE TRANSFER
      const flwSecret = getFLWKey(user.company, "secret");
      if (!flwSecret) throw new Error("Flutterwave key not configured");

      const recipientRes = await axios.post("https://api.flutterwave.com/v3/bank-transfer/beneficiaries", {
        account_number: wd.account_number,
        account_bank: bankCode,
        beneficiary_name: wd.account_name
      }, { headers: { Authorization: `Bearer ${flwSecret}` } });

      const recipientCode = recipientRes.data.id;

      const transferRes = await axios.post("https://api.flutterwave.com/v3/transfers", {
        account_bank: bankCode,
        account_number: wd.account_number,
        amount: Number(wd.amount),
        currency: "NGN",
        narration: `Sadeeq Admin Payout ${reference}`,
        beneficiary_name: wd.account_name,
        beneficiary_id: recipientCode
      }, { headers: { Authorization: `Bearer ${flwSecret}` } });

      transferCode = transferRes.data.id;
      transferStatus = transferRes.data.status;

    } else {
      // MONNIFY TRANSFER for mayconnect, bnhabeeb, teeversh
      const apiKey = getMonnifyKey(user.company, "api");
      const secretKey = getMonnifyKey(user.company, "secret");
      if (!apiKey ||!secretKey) throw new Error("Monnify key not configured");

      const auth = Buffer.from(`${apiKey}:${secretKey}`).toString('base64');
      const login = await axios.post('https://api.monnify.com/api/v1/auth/login', {}, {
        headers: { Authorization: `Basic ${auth}` }
      });
      const token = login.data.responseBody.accessToken;

      const transferRes = await axios.post('https://api.monnify.com/api/v2/disbursements/single', {
        amount: Number(wd.amount),
        reference: reference,
        narration: `Admin Payout ${reference}`,
        destinationBankCode: bankCode,
        destinationAccountNumber: wd.account_number,
        currency: "NGN"
      }, { headers: { Authorization: `Bearer ${token}` } });

      transferCode = transferRes.data.responseBody.transactionReference;
      transferStatus = transferRes.data.requestSuccessful;
    }

    if (!transferCode || transferStatus === false) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Transfer failed" });
    }

    await client.query(
      "UPDATE withdrawals SET status='PAID', transfer_code=$1, paid_at=NOW() WHERE reference=$2",
      [transferCode, reference]
    );
    await client.query(
      "UPDATE users SET admin_wallet = admin_wallet - $1 WHERE id=$2",
      [wd.amount, req.user.id]
    );

    await client.query("COMMIT");
    res.json({
      message: `₦${wd.amount} sent to ${wd.bank_name} ✅`,
      transfer_code: transferCode
    });

  } catch (e) {
    await client.query("ROLLBACK");
    console.log("APPROVE WITHDRAW ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: "Server error during transfer: " + (e.response?.data?.message || e.message) });
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