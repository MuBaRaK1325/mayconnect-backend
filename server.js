const express = require("express");
const path = require('path');
const cors = require("cors");
const helmet = require("helmet");
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
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();

/* ================= SECURITY ================= */
app.use(helmet());
app.set('trust proxy', 1);


/* ================= PAYMENTPOINT WEBHOOK - MUST BE FIRST, BEFORE ANY BODY PARSERS ================= */
app.post("/api/paymentpoint/webhook",
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      const rawBody = req.body; // Buffer from express.raw
      const event = JSON.parse(rawBody.toString('utf8'));
      const signature = req.headers["paymentpoint-signature"];

      console.log('[PaymentPoint Webhook] Headers:', JSON.stringify(req.headers));
      console.log('[PaymentPoint Webhook] Payload:', JSON.stringify(event));

      if (!rawBody ||!signature) {
        console.log('[Webhook] Missing body or signature');
        return res.sendStatus(400);
      }

      const amount = Number(event.settlement_amount || event.amount_paid);
      const reference = event.transaction_id;
      const customerEmail = event.customer?.email;
      const notificationStatus = event.notification_status;
      const transactionStatus = event.transaction_status;

      if (!amount ||!reference ||!customerEmail) {
        console.log('[Webhook] Missing required fields:', { amount, reference, customerEmail });
        return res.sendStatus(400);
      }

      if (notificationStatus!== "payment_successful" || transactionStatus!== "success") {
        return res.sendStatus(200);
      }

      const userRes = await pool.query(
        "SELECT id, company FROM users WHERE lower(trim(email)) = lower(trim($1))",
        [customerEmail]
      );

      if (!userRes.rows.length) {
        console.log('[Webhook] No user found for email:', customerEmail);
        return res.sendStatus(200);
      }

      const userId = userRes.rows[0].id;
      const company = userRes.rows[0].company;
      const creds = getPaymentPointCreds(company);

      if (!creds?.secretKey) {
        return res.sendStatus(400);
      }

      const calculatedSignature = crypto
    .createHmac("sha256", creds.secretKey)
    .update(rawBody)
    .digest("hex");

      if (calculatedSignature!== signature) {
        console.log('[Webhook] Signature mismatch. Expected:', calculatedSignature, 'Got:', signature);
        return res.sendStatus(401);
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const existing = await client.query(
          "SELECT status FROM transactions WHERE reference = $1 FOR UPDATE",
          [reference]
        );

        if (existing.rows.length && existing.rows[0].status === "SUCCESS") {
          await client.query("ROLLBACK");
          return res.sendStatus(200);
        }

        const update = await client.query(
          "UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2 RETURNING wallet_balance",
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
        console.log('[Webhook] Credited user', userId, 'amount', amount);

      } catch (e) {
        await client.query("ROLLBACK");
        console.error('[Webhook] DB Error:', e);
        return res.sendStatus(500);
      } finally {
        client.release();
      }

      res.sendStatus(200);

    } catch (e) {
      console.error('[Webhook] Fatal Error:', e);
      res.sendStatus(500);
    }
  }
);
/* ================== ALRAHUZ WEBHOOK ================== */
app.post("/webhooks/alrahuz", async (req, res) => {
    try {
        const data = req.body; // This works because express.json() runs later
        console.log('[Alrahuz Webhook] Payload:', JSON.stringify(data));

        const { transaction_id, status, reference, plan, phone } = data;

        // Update your DB here - uncomment and adjust when ready
        // await pool.query(
        // `UPDATE transactions
        // SET status = $1, api_response = $2, updated_at = NOW()
        // WHERE reference = $3 AND provider = 'alrahuz'`,
        // [status, JSON.stringify(data), reference || transaction_id]
        // );

        return res.status(200).json({ received: true });
    } catch (error) {
        console.error('[Alrahuz Webhook] Error:', error);
        return res.status(200).json({ error: true }); // Still return 200
    }
});


/* ================== MAITAMA TEST ROUTE ================== */
app.get("/test-maitama-ip", async (req, res) => {
  let renderIP = 'unknown';
  try {
    const ipRes = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
    renderIP = ipRes.data.ip;
    
    const uniqueRef = `test-${Date.now()}`;
    // Test Airtel = 2
    const maitamaTest = await callMaitamaAirtime("09121243474", "airtel", 50, "sadeeq", uniqueRef);
    
    res.json({ 
      success: true, 
      renderIP,
      maitamaResponse: maitamaTest,
      networkUsed: 'airtel -> 2'
    });
  } catch (e) {
    res.json({ 
      success: false,
      renderIP,
      error: e.message,
      status: e.response?.status,
      data: e.response?.data || 'EMPTY - CHECK IP WHITELIST'
    });
  }
});


/* ================= GLOBAL MIDDLEWARE - AFTER WEBHOOK ================= */
app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

/* ================= DATABASE ================= */
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
app.use(session({
  store: new pgSession({
    pool: pool, // yana amfani da pool ɗinka da ke wanzu
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'change-this-random-string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));

app.use(cors({
  origin: '*', // Allow everything including mobile apps
  credentials: false, // Must be false if origin is '*'
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* ================= RATE LIMITERS ================= */
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { message: "Too many login attempts, try again later" },
  standardHeaders: true,
  legacyHeaders: false
});

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
  "Sadeeqtukur765@gmail.com",
  "msdatasub1@gmail.com"
];

/* ================= MULTI COMPANY WEBAUTHN CONFIG ================= */
const RP_CONFIG = {
'https://www.mayconnectdataplug.com.ng': {
rpID: 'www.mayconnectdataplug.com.ng',
rpName: 'MAYCONNECT DATA PLUG'
},

'https://www.sadeeqdatahub.com.ng': {
rpID: 'www.sadeeqdatahub.com.ng',
rpName: 'SADEEQ DATA HUB'
},

'https://teevershdataplug.com.ng': {
rpID: 'teevershdataplug.com.ng',
rpName: 'TEEVERSH DATA PLUG'
},

'https://bnhabeebdatahub.com.ng': {
rpID: 'bnhabeebdatahub.com.ng',
rpName: 'BN HABEEB DATA HUB'
},

'https://www.msdatasub.com.ng': {
rpID: 'www.msdatasub.com.ng',
rpName: 'MSDATASUB'
}
};

function getWebAuthnConfig(req) {
const origin = req.get('origin');

const config = RP_CONFIG[origin];

if (!config) {
throw new Error(`Unsupported origin: ${origin}`);
}

return {
RP_ID: config.rpID,
RP_NAME: config.rpName,
EXPECTED_ORIGIN: origin
};
}
// PAYMENTPOINT CONFIG
const PAYMENTPOINT_BASE = process.env.PAYMENTPOINT_BASE || "https://api.paymentpoint.co";

console.log("[PAYMENTPOINT] Config loaded for:", ["teeversh", "sadeeq", "bnhabeeb", "mayconnect", "msdatasub"]);

const VTU_PROVIDERS = {
  maitama: {
    base_url: process.env.MAITAMA_BASE_URL,
    tokens: {
      mayconnect: process.env.MAITAMA_TOKEN_MAYCONNECT,
      teeversh: process.env.MAITAMA_TOKEN_TEEVERSH,
      sadeeq: process.env.MAITAMA_TOKEN_SADEEQ,
      bnhabeeb: process.env.MAITAMA_TOKEN_BNHABEEB,
      MSDATASUB: process.env.MAITAMA_TOKEN_MSDATASUB
    }
  },
  cheapdatahub: {
    base_url: "https://www.cheapdatahub.ng/api/v1/resellers",
    api_key: process.env.CHEAPDATAHUB_API_KEY
  },
  subpadi: {
    base_url: "https://api.subpadi.com",
    tokens: {
      mayconnect: process.env.SUBPADI_TOKEN_MAYCONNECT,
      teeversh: process.env.SUBPADI_TOKEN_TEEVERSH,
      sadeeq: process.env.SUBPADI_TOKEN_SADEEQ,
      bnhabeeb: process.env.SUBPADI_TOKEN_BNHABEEB,
      MSDATASUB: process.env.SUBPADI_TOKEN_MSDATASUB
    }
  },
  arrahuz: {
    base_url: "https://alrahuzdata.com.ng",
    tokens: {
      mayconnect: process.env.ARRAHUZ_TOKEN_MAYCONNECT,
      teeversh: process.env.ARRAHUZ_TOKEN_TEEVERSH,
      sadeeq: process.env.ARRAHUZ_TOKEN_SADEEQ,
      bnhabeeb: process.env.ARRAHUZ_TOKEN_BNHABEEB,
      MSDATASUB: process.env.ARRAHUZ_TOKEN_MSDATASUB
    }
  },

 
jjdatasub: {
    base_url: "https://jjdatasub.com/api",
    tokens: {
      mayconnect: process.env.JJDATASUB_TOKEN_MAYCONNECT,
      teeversh: process.env.JJDATASUB_TOKEN_TEEVERSH,
      sadeeq: process.env.JJDATASUB_TOKEN_SADEEQ,
      bnhabeeb: process.env.JJDATASUB_TOKEN_BNHABEEB,
      msdatasub: process.env.JJDATASUB_TOKEN_MSDATASUB
    }
  }, // <-- ADD COMMA HERE
  alihsandatasub: {
    base_url: "https://alihsandatasub.com.ng",
    tokens: {
      mayconnect: process.env.ALIHSAN_TOKEN_MAYCONNECT,
      teeversh: process.env.ALIHSAN_TOKEN_TEEVERSH,
      sadeeq: process.env.ALIHSAN_TOKEN_SADEEQ,
      bnhabeeb: process.env.ALIHSAN_TOKEN_BNHABEEB,
      MSDATASUB: process.env.ALIHSAN_TOKEN_MSDATASUB
    }
  }
}; // <-- ONLY ONE CLOSING }; AT THE VERY END OF VTU_PROVIDERS

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
  return {
    apiKey: (process.env[`PAYMENTPOINT_${c.toUpperCase()}_API_KEY`] || "").trim(),
    secretKey: (process.env[`PAYMENTPOINT_${c.toUpperCase()}_SECRET_KEY`] || "").trim(),
    businessId: (process.env[`PAYMENTPOINT_${c.toUpperCase()}_BUSINESS_ID`] || "").trim()
  };
};

async function createPaymentPointAccount(user, kycData = {}) {
  const creds = getPaymentPointCreds(user.company);

  console.log(`[PaymentPoint] Creating account for ${user.username}, company: ${user.company}`);

  if (!creds.apiKey ||!creds.secretKey ||!creds.businessId) {
    throw new Error(`PaymentPoint not configured for company: ${user.company}`);
  }
  if (!user.phone) {
    throw new Error("Phone number is NULL/empty in DB.");
  }
  if (!user.email) {
    throw new Error("Email is NULL/empty in DB.");
  }

  // Normalize to 11 digits starting with 0
  let phoneNumber = String(user.phone).replace(/\D/g, '');
  if (phoneNumber.startsWith('234')) {
    phoneNumber = '0' + phoneNumber.slice(3);
  }
  if (phoneNumber.length === 10) {
    phoneNumber = '0' + phoneNumber;
  }
  if (phoneNumber.length!== 11 ||!phoneNumber.startsWith('0')) {
    throw new Error(`Invalid phone format for Paymentpoint: ${phoneNumber}. Must be 11 digits starting with 0`);
  }

  const payload = {
    email: user.email.trim().toLowerCase(),
    name: user.username.trim(),
    phoneNumber: phoneNumber,
    bankCode: ['20946'], // Start with Palmpay only. Add '20897' after it works
    businessId: creds.businessId
  };

  // v1 PaymentPoint: send bvn/nin directly in createVirtualAccount
  if (kycData.bvn) {
    const cleanBvn = String(kycData.bvn).replace(/\D/g, '');
    if (cleanBvn.length!== 11) {
      throw new Error('BVN must be exactly 11 digits');
    }
    payload.bvn = cleanBvn;
  } else if (kycData.nin) {
    const cleanNin = String(kycData.nin).replace(/\D/g, '');
    if (cleanNin.length!== 11) {
      throw new Error('NIN must be exactly 11 digits');
    }
    payload.nin = cleanNin;
  }

  const headers = {
    'Authorization': `Bearer ${creds.secretKey}`,
    'api-key': creds.apiKey,
    'Content-Type': 'application/json'
  };

  console.log('[PaymentPoint] Sending payload:', JSON.stringify({
   ...payload,
    bvn: payload.bvn? '***' + payload.bvn.slice(-4) : undefined,
    nin: payload.nin? '***' + payload.nin.slice(-4) : undefined
  }));

  try {
    const { data } = await axios.post(
      `${PAYMENTPOINT_BASE}/api/v1/createVirtualAccount`,
      payload,
      { headers, timeout: 30000 }
    );

    console.log('[PaymentPoint] Full response:', JSON.stringify(data));

    // Log specific case: customer created but no bank accounts
    if (data.status === "success" && (!data.bankAccounts || data.bankAccounts.length === 0)) {
      console.log('[PaymentPoint] WARNING: Customer created but no bank accounts. Errors:', data.errors);
    }

    return data;

  } catch (err) {
    console.log('[PaymentPoint] Error details:', {
      message: err.message,
      code: err.code,
      status: err.response?.status,
      data: err.response?.data
    });

    if (err.code === 'ECONNABORTED') {
      throw new Error('PaymentPoint API timeout. Customer may have been created. Please try again in 30 seconds.');
    }

    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      throw new Error('Cannot connect to PaymentPoint. Check PAYMENTPOINT_BASE URL.');
    }

    // Return PP error response so route can handle it
    if (err.response?.data) {
      return err.response.data;
    }

    throw err;
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

/* ================= VTU API CALLS - MAITAMA CLEAN + DANMALAMA + JJDATASUB ================= */
// MAITAMA NETWORK MAP: 1=MTN, 2=AIRTEL, 3=GLO, 4=9MOBILE
const MAITAMA_NETWORK_MAP_NAME_TO_ID = {
  'mtn': 1,
  'airtel': 2,
  'glo': 3,
  '9mobile': 4,
};

const MAITAMA_NETWORK_MAP_ID_TO_NAME = {
 1: 'mtn',
 2: 'airtel',
 3: 'glo',
 4: '9mobile'
};

// ARRAHUZ NETWORK MAP: 1=MTN, 2=GLO, 3=9MOBILE, 4=AIRTEL
const ARRAHUZ_NETWORK_MAP_ID_TO_NAME = {
 1: 'mtn',
 2: 'glo',
 3: '9mobile',
 4: 'airtel'
};

const ARRAHUZ_NETWORK_MAP_NAME_TO_ID = {
  'mtn': 1,
  'glo': 2,
  '9mobile': 3,
  'airtel': 4,
};

// DANMALAMA NETWORK MAP: 1=MTN, 2=GLO, 3=AIRTEL, 4=9MOBILE
const DANMALAMA_NETWORK_MAP_ID_TO_NAME = {
 1: 'MTN',
 2: 'GLO',
 3: 'AIRTEL',
 4: '9MOBILE'
};

// JJDATASUB NETWORK MAP: 1=MTN, 2=AIRTEL, 3=GLO, 4=9MOBILE
const JJDATASUB_NETWORK_MAP_ID_TO_NAME = {
 1: 'mtn',
 2: 'airtel',
 3: 'glo',
 4: '9mobile'
};

function getMaitamaNetworkId(networkName) {
  return MAITAMA_NETWORK_MAP_NAME_TO_ID[String(networkName).toLowerCase()] || null;
}

function getMaitamaNetworkName(networkId) {
  const id = Number(networkId);
  return MAITAMA_NETWORK_MAP_ID_TO_NAME[id] || null;
}

function getArrahuzNetworkId(networkName) {
  return ARRAHUZ_NETWORK_MAP_NAME_TO_ID[String(networkName).toLowerCase()] || null;
}

function getArrahuzNetworkName(networkId) {
  const id = Number(networkId);
  return ARRAHUZ_NETWORK_MAP_ID_TO_NAME[id] || null;
}

function getDanmalamaNetworkName(networkId) {
  const id = Number(networkId);
  return DANMALAMA_NETWORK_MAP_ID_TO_NAME[id] || null;
}

function formatPhoneForDanmalama(phone) {
  let p = String(phone).replace(/\s+/g, '').trim();
  if (p.startsWith('0')) p = '234' + p.slice(1);
  if (p.startsWith('+234')) p = p.slice(1);
  return p;
}

function getJJDataSubNetworkName(networkId) {
  const id = Number(networkId);
  return JJDATASUB_NETWORK_MAP_ID_TO_NAME[id] || null;
}

function formatPhoneForMaitama(phone) {
  let p = String(phone).replace(/\D/g, '');
  if (p.startsWith('234')) p = '0' + p.slice(3);
  if (p.length === 10) p = '0' + p;
  return p;
}

// MAITAMA AIRTIME - Uses network ID
async function callMaitamaAirtime(phone, network, amount, company, uniqueRef = null) {
  const { base_url, tokens } = VTU_PROVIDERS.maitama;
  const api_token = tokens[company];
  if (!api_token) throw new Error(`No Maitama token configured for ${company}`);

  let networkId;
  if (typeof network === 'string') {
    networkId = getMaitamaNetworkId(network);
    if (!networkId) throw new Error(`Invalid network: ${network}. Use: mtn, airtel, glo, 9mobile`);
  } else {
    networkId = Number(network);
  }

  const amountNum = Number(amount);
  if (amountNum < 50 || amountNum > 5000) {
    throw new Error(`Amount must be between ₦50 and ₦5,000. Got: ₦${amountNum}`);
  }

  const formattedPhone = formatPhoneForMaitama(phone);

  const payload = {
    network: networkId,
    amount: amountNum,
    mobile_number: formattedPhone
  };

  let endpoint = `${base_url}/api/topup`;
  if (uniqueRef) {
    endpoint = `${base_url}/api/topup/${uniqueRef}`;
  }

  console.log('MAITAMA AIRTIME REQUEST:', { endpoint, payload, company, networkId });

  try {
    const res = await axios.post(
      endpoint,
      payload,
      {
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": `Bearer ${api_token}`,
          "User-Agent": "MUSTYKNK/1.0"
        },
        timeout: 180000, // FIX 1: 3 minutes instead of 60s
      }
    );

    console.log('MAITAMA AIRTIME RESPONSE:', res.data);

    const status = res.data?.data?.Status || res.data?.Status;
    const api_response = res.data?.data?.api_response || res.data?.api_response || res.data?.message;

    if (status?.toLowerCase() === "successful" || status?.toLowerCase() === "success") {
      return res.data?.data || res.data;
    }

    if (status?.toLowerCase() === "pending") {
      return {...res.data?.data || res.data, _pending: true };
    }

    throw new Error(api_response || "Maitama airtime failed");

  } catch (err) {
    if (err.response?.status === 403) { // FIX 2: Catch IP Block
      throw new Error(`IP_BLOCKED: ${err.response.data?.message || 'IP not whitelisted'}`);
    }
    if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
      console.error('MAITAMA TIMEOUT:', { uniqueRef, payload });
      throw new Error('TIMEOUT_FAILED'); // FIX 3: REFUND instead of POSSIBLE_SUCCESS
    }
    throw err;
  }
}

// MAITAMA DATA - Uses network ID - WORKING VERSION
async function callMaitamaData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.maitama;
  const api_token = tokens[company];
  if (!api_token) throw new Error(`No Maitama token configured for ${company}`);

  const payload = {
    plan: Number(api_plan_id),
    mobile_number: formatPhoneForMaitama(phone),
    network: Number(network_id) // Uses ID as per working version
  };

  console.log('MAITAMA DATA REQUEST:', { payload, company });

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
        timeout: 180000 // FIX 1: 3 minutes instead of 60s
      }
    );

    console.log('MAITAMA DATA RESPONSE:', res.data);

    const data = res.data?.data || res.data;
    const status = data?.Status || data?.status;

    if (status?.toLowerCase() === "successful" || status?.toLowerCase() === "success") {
      return data;
    }
    if (status?.toLowerCase() === "pending") {
      return {...data, _pending: true };
    }

    throw new Error(data?.api_response || data?.message || "Maitama purchase failed");
  } catch (err) {
    if (err.response?.status === 403) { // FIX 2: Catch IP Block
      throw new Error(`IP_BLOCKED: ${err.response.data?.message || 'IP not whitelisted'}`);
    }
    if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
      throw new Error('TIMEOUT_FAILED'); // FIX 3: REFUND instead of hanging
    }
    throw err;
  }
}

// CHEAPDATAHUB DATA - KEPT
async function callCheapDataHubData(phone, network_id, api_plan_id) {
  const { base_url, api_key } = VTU_PROVIDERS.cheapdatahub;
  if (!api_key) throw new Error("No CheapDataHub API key configured");

  const res = await axios.post(
    `${base_url}/data/purchase/`,
    {
      provider_id: Number(network_id),
      phone_number: String(phone),
      bundle_id: Number(api_plan_id)
    },
    {
      headers: {
        Authorization: `Bearer ${api_key}`,
        "Content-Type": "application/json"
      },
      timeout: 30000
    }
  );

  if (res.data.status!== "true") throw new Error(res.data.message || "CheapDataHub failed");
  return res.data;
}

async function callCheapDataHubAirtime(phone, network_id, amount) {
  const { base_url, api_key } = VTU_PROVIDERS.cheapdatahub;
  if (!api_key) throw new Error("No CheapDataHub API key configured");

  const res = await axios.post(
    `${base_url}/airtime/purchase/`,
    {
      provider_id: Number(network_id),
      phone_number: String(phone),
      amount: Number(amount)
    },
    {
      headers: {
        Authorization: `Bearer ${api_key}`,
        "Content-Type": "application/json"
      },
      timeout: 30000
    }
  );

  if (res.data.status!== "true") throw new Error(res.data.message || "CheapDataHub failed");
  return res.data;
}

// SUBPADI DATA - KEPT
async function callSubPadiData(phone, product_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.subpadi;
  const token = tokens[company];
  if (!token) throw new Error(`No SubPadi token configured for ${company}`);
  if (!product_id) throw new Error("No SubPadi product_id configured for this plan");

  const res = await axios.post(
    `${base_url}/v1/data/`,
    {
      product_id: Number(product_id),
      phone: String(phone)
    },
    {
      headers: {
        Authorization: `Token ${token}`,
        "Content-Type": "application/json"
      },
      timeout: 60000
    }
  );

  const status = res.data.status || res.data.Status;
  if (!["success", "successful", "pending"].includes(status?.toLowerCase())) {
    throw new Error(res.data.message || res.data.error || "SubPadi purchase failed");
  }
  return res.data;
}

// ARRAHUZ DATA - Uses network ID as per working version
async function callArrahuzData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.arrahuz;
  const token = tokens[company];
  if (!token) throw new Error(`No Arrahuz token configured for ${company}`);
  if (!api_plan_id) throw new Error("No Arrahuz plan_id configured for this plan");

  const payload = {
    network: Number(network_id), // 1=MTN, 2=Glo, 3=9mobile, 4=Airtel
    mobile_number: String(phone),
    plan: Number(api_plan_id),
    Ported_number: true
  };

  console.log('ARRAHUZ DATA REQUEST:', { payload, company });

  const res = await axios.post(
    `${base_url}/api/data/`,
    payload,
    {
      headers: {
        "Authorization": `Token ${token}`,
        "Content-Type": "application/json"
      },
      timeout: 60000
    }
  );

  const status = res.data?.Status || res.data?.status;
  if (res.data && status &&!["success", "successful", "pending"].includes(status?.toLowerCase())) {
    throw new Error(res.data.message || res.data.error || "Arrahuz purchase failed");
  }

  return res.data || { status: "success", message: "Request sent to Arrahuz" };
}

// ARRAHUZ AIRTIME
async function callArrahuzAirtime(phone, network_id, amount, company) {
  const { base_url, tokens } = VTU_PROVIDERS.arrahuz;
  const token = tokens[company];
  if (!token) throw new Error(`No Arrahuz token configured for ${company}`);

  const payload = {
    network: Number(network_id), // 1=MTN, 2=Glo, 3=9mobile, 4=Airtel
    amount: Number(amount),
    mobile_number: String(phone),
    Ported_number: true,
    airtime_type: "VTU"
  };

  console.log('ARRAHUZ AIRTIME REQUEST:', { payload, company });

  const res = await axios.post(
    `${base_url}/api/topup/`,
    payload,
    {
      headers: {
        "Authorization": `Token ${token}`,
        "Content-Type": "application/json"
      },
      timeout: 60000
    }
  );

  const status = res.data?.Status || res.data?.status;
  if (res.data && status &&!["success", "successful", "pending"].includes(status?.toLowerCase())) {
    throw new Error(res.data.message || res.data.error || "Arrahuz airtime failed");
  }

  return res.data || { status: "success", message: "Request sent to Arrahuz" };
}

// DANMALAMA DATA - Uses network ID: 1=MTN, 2=GLO, 3=AIRTEL, 4=9MOBILE
async function callDanmalamaData(phone, network_id, planId) {
  const { base_url, api_key } = VTU_PROVIDERS.DANMALAMA; // FIXED: ALL CAPS
  if (!api_key) throw new Error("No Danmalama API key configured");
  if (!base_url) throw new Error("No Danmalama BASE_URL configured");

  const network = getDanmalamaNetworkName(network_id);
  if (!network) throw new Error(`Invalid network_id: ${network_id}. Must be 1-4`);

  const formattedPhone = formatPhoneForDanmalama(phone);

  const payload = {
    network,
    phone: formattedPhone,
    planId: String(planId),
    api_key
  };

  const res = await axios.post(`${base_url}/data`, payload, { timeout: 60000 });
  return res.data;
}

// JJDATASUB DATA - Uses network ID: 1=MTN, 2=AIRTEL, 3=GLO, 4=9MOBILE
async function callJJDataSubData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.jjdatasub;
  const token = tokens[company];
  if (!token) throw new Error(`No JJDataSub token configured for ${company}`);

  const payload = {
    mobile_number: formatPhoneForMaitama(phone),
    network: Number(network_id), // 1=MTN, 2=Airtel, 3=Glo, 4=9mobile
    plan: Number(api_plan_id),
    Ported_number: true
  };

  console.log('JJDATASUB DATA REQUEST:', { payload, company });

  const res = await axios.post(
    `${base_url}/api/data/`,
    payload,
    {
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Token ${token}`
      },
      timeout: 60000
    }
  );

  const status = res.data?.Status || res.data?.status;
  if (!["success", "successful", "pending"].includes(status?.toLowerCase())) {
    throw new Error(res.data.api_response || res.data.message || "JJDataSub purchase failed");
  }
  return res.data;
}

// JJDATASUB AIRTIME
async function callJJDataSubAirtime(phone, network_id, amount, company) {
  const { base_url, tokens } = VTU_PROVIDERS.jjdatasub;
  const token = tokens[company];
  if (!token) throw new Error(`No JJDataSub token configured for ${company}`);

  const payload = {
    mobile_number: formatPhoneForMaitama(phone),
    network: Number(network_id),
    amount: Number(amount)
  };

  const res = await axios.post(
    `${base_url}/api/topup/`,
    payload,
    {
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Token ${token}`
      },
      timeout: 60000
    }
  );

  const status = res.data?.Status || res.data?.status;
  if (!["success", "successful", "pending"].includes(status?.toLowerCase())) {
    throw new Error(res.data.api_response || res.data.message || "JJDataSub airtime failed");
  }
  return res.data;
}
/* ================= ALIHSANDATASUB NETWORK MAP ================= */
// ALIHSANDATASUB NETWORK MAP: 1=MTN, 2=AIRTEL, 3=GLO, 4=9MOBILE
const ALIHSANDATA_NETWORK_MAP_ID_TO_NAME = {
 1: 'mtn',
 2: 'airtel',
 3: '9mobile',
 4: 'Glo'
};

function getAlihsanNetworkName(networkId) {
  const id = Number(networkId);
  return ALIHSANDATA_NETWORK_MAP_ID_TO_NAME[id] || null;
}

// ALIHSANDATASUB DATA - Direct Topup
async function callAlihsanData(phone, network_id, api_plan_id, company) {
  const { base_url, tokens } = VTU_PROVIDERS.alihsandatasub;
  const token = tokens[company];
  if (!token) throw new Error(`No AlihsanDataSub token configured for ${company}`);
  if (!api_plan_id) throw new Error("No Alihsan plan_id configured for this plan");

  const payload = {
    network: String(network_id), // 1=MTN, 2=Airtel, 4=Glo, 3=9mobile
    plan_id: String(api_plan_id),
    mobile_number: String(phone), // 11 digits
    request_id: "BH" + Date.now() + Math.floor(Math.random()*1000) // unique
  };

  console.log('ALIHSANDATASUB DATA REQUEST:', { payload, company });

  const res = await axios.post(
    `${base_url}/api/v1/data.php`,
    payload,
    {
      headers: {
        "Authorization": token, // NOT Bearer
        "Content-Type": "application/json"
      },
      timeout: 60000
    }
  );

  if (res.data?.success!== "true") {
    throw new Error(res.data?.desc || "AlihsanDataSub purchase failed");
  }

  return {
    status: res.data.info?.status?.toLowerCase() || "success",
    trans_id: res.data.info?.trans_id,
    previous_balance: res.data.info?.previous_balance,
    new_balance: res.data.info?.new_balance,
    amount_deducted: res.data.info?.amount_deducted,
    plan: res.data.info?.plan,
    raw: res.data
  };
}

// ALIHSANDATASUB DATACARD / CG DATA
async function callAlihsanDataCard(phone, network_id, api_plan_id, company, quantity = 1) {
  const { base_url, tokens } = VTU_PROVIDERS.alihsandatasub;
  const token = tokens[company];
  if (!token) throw new Error(`No AlihsanDataSub token configured for ${company}`);
  if (!api_plan_id) throw new Error("No Alihsan plan_id configured for this plan");

  const payload = {
    network: String(network_id), // 1=MTN, 2=Airtel, 4=Glo, 3=9mobile
    plan_id: String(api_plan_id),
    amount: String(quantity), // quantity of cards
    request_id: "BHC" + Date.now() + Math.floor(Math.random()*1000) // unique
  };

  console.log('ALIHSANDATASUB DATACARD REQUEST:', { payload, company });

  const res = await axios.post(
    `${base_url}/api/v1/datacard.php`,
    payload,
    {
      headers: {
        "Authorization": token, // NOT Bearer
        "Content-Type": "application/json"
      },
      timeout: 60000
    }
  );

  if (res.data?.success!== "true") {
    throw new Error(res.data?.desc || "AlihsanDataSub datacard failed");
  }

  return {
    status: res.data.info?.status?.toLowerCase() || "success",
    trans_id: res.data.info?.trans_id,
    previous_balance: res.data.info?.previous_balance,
    new_balance: res.data.info?.new_balance,
    amount_deducted: res.data.info?.amount_deducted,
    plan: res.data.info?.plan,
    raw: res.data
  };
}
/* ================= AUTH MIDDLEWARE ================= */
function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader ||!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: "Unauthorized - No token provided" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (e) {
    console.error('Auth error:', e.message);
    res.status(401).json({ message: "Unauthorized - Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user ||!req.user.is_admin) {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
}



/* ================= WEBAUTHN - BIOMETRIC PASSKEYS - PASSWORDLESS 100% ================= */

function getCompanyConfig(origin) {

  switch (origin) {

    case 'https://www.mayconnectdataplug.com.ng':
    case 'https://mayconnectdataplug.com.ng':
      return {
        rpID: 'www.mayconnectdataplug.com.ng',
        rpName: 'MAYCONNECT DATA PLUG',
        expectedOrigin: 'https://www.mayconnectdataplug.com.ng',
        company: 'mayconnect',
        icon: 'https://www.mayconnectdataplug.com.ng/images/logo.png'
      };

    case 'https://www.sadeeqdatahub.com.ng':
    case 'https://sadeeqdatahub.com.ng':
      return {
        rpID: 'www.sadeeqdatahub.com.ng',
        rpName: 'SADEEQ DATA HUB',
        expectedOrigin: 'https://www.sadeeqdatahub.com.ng',
        company: 'sadeeq',
        icon: 'https://www.sadeeqdatahub.com.ng/images/logo.png'
      };

    case 'https://www.teevershdataplug.com.ng':
    case 'https://teevershdataplug.com.ng':
      return {
        rpID: 'teevershdataplug.com.ng',
        rpName: 'TEEVERSH DATA PLUG',
        expectedOrigin: 'https://teevershdataplug.com.ng',
        company: 'teeversh',
        icon: 'https://teevershdataplug.com.ng/images/logo.png'
      };

    case 'https://www.bnhabeebdatahub.com.ng':
    case 'https://bnhabeebdatahub.com.ng':
      return {
        rpID: 'bnhabeebdatahub.com.ng',
        rpName: 'BN HABEEB DATA HUB',
        expectedOrigin: 'https://bnhabeebdatahub.com.ng',
        company: 'bnhabeeb',
        icon: 'https://bnhabeebdatahub.com.ng/images/logo.png'
      };

    case 'https://www.msdatasub.com.ng':
    case 'https://msdatasub.com.ng':
      return {
        rpID: 'www.msdatasub.com.ng',
        rpName: 'MSDATASUB',
        expectedOrigin: 'https://www.msdatasub.com.ng',
        company: 'msdatasub',
        icon: 'https://www.msdatasub.com.ng/images/ms.png'
      };

    default:
      return {
        rpID: 'www.mayconnectdataplug.com.ng',
        rpName: 'MAYCONNECT DATA PLUG',
        expectedOrigin: 'https://www.mayconnectdataplug.com.ng',
        company: 'mayconnect',
        icon: 'https://www.mayconnectdataplug.com.ng/images/logo.png'
      };

  }

}

/* ================= WEBAUTHN REGISTER START ================= */

app.post('/api/auth/webauthn/register-start', auth, async (req, res) => {
  try {

    const config = getCompanyConfig(req.headers.origin);

    const RP_ID = config.rpID;
    const RP_NAME = config.rpName;

    const userId = Number(req.user?.id || 0);

    if (!userId) {
      return res.status(401).json({
        error: 'Unauthorized'
      });
    }

    const userRes = await pool.query(
      `
      SELECT email, username
      FROM users
      WHERE id = $1
      `,
      [userId]
    );

    const user = userRes.rows[0];

    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    console.log(
      '=== REGISTER START ===',
      'UserID:',
      userId,
      'RP_ID:',
      RP_ID
    );

    // Remove old passkey for this site only
    await pool.query(
      `
      DELETE FROM webauthn_credentials
      WHERE user_id = $1
      AND rp_id = $2
      `,
      [userId, RP_ID]
    );

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,

      userID: new TextEncoder().encode(
        userId.toString()
      ),

      userName: user.email,

      userDisplayName:
        user.username || user.email,

      attestationType: 'none',

      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required'
      },

      supportedAlgorithmIDs: [-7, -257],

      timeout: 60000
    });

    await pool.query(
      `
      UPDATE users
      SET webauthn_challenge = $1
      WHERE id = $2
      `,
      [options.challenge, userId]
    );

    console.log(
      'Register challenge saved:',
      options.challenge.substring(0, 20) + '...'
    );

    return res.json(options);

  } catch (e) {

    console.error(
      'Register start error:',
      e
    );

    return res.status(500).json({
      error: e.message
    });

  }
});

/* ================= WEBAUTHN REGISTER FINISH ================= */

app.post('/api/auth/webauthn/register-finish', auth, async (req, res) => {

  const userId = Number(req.user?.id || 0);

  if (!userId) {
    return res.status(401).json({
      verified: false,
      error: 'Unauthorized'
    });
  }

  const config = getCompanyConfig(req.headers.origin);

  console.log(
    '=== REGISTER FINISH === UserID:',
    userId,
    'RP:',
    config.rpID
  );

  try {

    const userRes = await pool.query(
      'SELECT webauthn_challenge FROM users WHERE id=$1',
      [userId]
    );

    const challenge = userRes.rows[0]?.webauthn_challenge;

    if (!challenge) {
      return res.status(400).json({
        verified: false,
        error: 'Challenge expired'
      });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: true
    });

    console.log(
      'Verification result:',
      verification.verified
    );

    if (
      !verification.verified ||
      !verification.registrationInfo
    ) {
      return res.status(400).json({
        verified: false,
        error: 'Backend verification failed'
      });
    }

    const regInfo = verification.registrationInfo;

    const credentialID = regInfo.credential.id;
    const credentialPublicKey = regInfo.credential.publicKey;
    const counter = Number(
      regInfo.credential.counter || 0
    );

    if (!credentialID || !credentialPublicKey) {
      throw new Error('Credential data missing');
    }

    console.log(
      'Credential ID sample:',
      credentialID.substring(0, 30)
    );

    console.log('Counter:', counter);

    await pool.query(
      `
      INSERT INTO webauthn_credentials
      (
        user_id,
        credential_id,
        public_key,
        counter,
        rp_id,
        company
      )
      VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (credential_id)
      DO UPDATE SET
        public_key = EXCLUDED.public_key,
        counter = EXCLUDED.counter,
        rp_id = EXCLUDED.rp_id,
        company = EXCLUDED.company
      `,
      [
        userId,
        credentialID,
        Buffer.from(
          credentialPublicKey
        ).toString('base64url'),
        counter,
        config.rpID,
        config.company
      ]
    );

    await pool.query(
      'UPDATE users SET webauthn_challenge=NULL WHERE id=$1',
      [userId]
    );

    console.log(
      'SUCCESS: Credential saved for user',
      userId,
      'Company:',
      config.company
    );

    return res.json({
      verified: true,
      message: 'Biometric registered successfully'
    });

  } catch (e) {

    console.error(
      'Register finish error:',
      e.message,
      e.stack
    );

    return res.status(400).json({
      verified: false,
      error: e.message || 'Registration failed'
    });

  }

});

/* ================= WEBAUTHN LOGIN START ================= */

app.post('/api/auth/webauthn/login-start', async (req, res) => {
  try {
    const config = getCompanyConfig(req.headers.origin);
    console.log('=== LOGIN START === RP_ID:', config.rpID);

    const credsRes = await pool.query(
      `SELECT credential_id FROM webauthn_credentials WHERE rp_id = $1`,
      [config.rpID]
    );

    const allowCredentials = credsRes.rows.map(row => ({
      id: row.credential_id,
      type: 'public-key',
      transports: ['internal', 'hybrid']
    }));

    console.log('AllowCredentials found:', allowCredentials.length);
    if (allowCredentials.length > 0) {
      console.log('First cred id sample:', allowCredentials[0].id.substring(0, 30));
    }

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined
    });

    await pool.query(
      `INSERT INTO webauthn_challenges (challenge, expires_at) VALUES ($1, NOW() + INTERVAL '5 minutes')`,
      [options.challenge]
    );

    console.log('Login challenge saved');
    return res.json(options);

  } catch (e) {
    console.error('Login start error:', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});

/* ================= WEBAUTHN LOGIN FINISH ================= */

app.post('/api/auth/webauthn/login-finish', async (req, res) => {
  try {
    const config = getCompanyConfig(req.headers.origin);

    console.log('=== LOGIN FINISH START ===');
    console.log('RP_ID:', config.rpID);
    console.log('EXPECTED_ORIGIN:', config.expectedOrigin);

    const credentialId = req.body.id;

    if (!credentialId) {
      return res.status(400).json({
        error: 'No credential ID'
      });
    }

    console.log(
      'Browser credential ID:',
      credentialId.substring(0, 30) + '...'
    );

    // Find credential
    const credRes = await pool.query(
      `
      SELECT
        user_id,
        credential_id,
        public_key,
        counter,
        transports
      FROM webauthn_credentials
      WHERE credential_id = $1
      `,
      [credentialId]
    );

    if (!credRes.rows.length) {
      console.log('Passkey not found');

      return res.status(400).json({
        error: 'Passkey not found'
      });
    }

    const cred = credRes.rows[0];

    console.log(
      'DB credential ID:',
      cred.credential_id.substring(0, 30) + '...'
    );

    // Latest challenge
    const challengeRes = await pool.query(
      `
      SELECT challenge
      FROM webauthn_challenges
      WHERE expires_at > NOW()
      ORDER BY created_at DESC
      LIMIT 1
      `
    );

    if (!challengeRes.rows.length) {
      return res.status(400).json({
        error: 'Challenge expired'
      });
    }

    const challenge = challengeRes.rows[0].challenge;

    // Find user
    const userRes = await pool.query(
      `
      SELECT
        id,
        username,
        email,
        company,
        is_admin,
        wallet_balance,
        status
      FROM users
      WHERE id = $1
      `,
      [cred.user_id]
    );

    if (!userRes.rows.length) {
      return res.status(400).json({
        error: 'User not found'
      });
    }

    const user = userRes.rows[0];

    if (user.status === 'blocked') {
      return res.status(403).json({
        error: 'Account blocked'
      });
    }

    // Verify passkey
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: Number(cred.counter || 0),
        transports: cred.transports || ['internal', 'hybrid']
      },
      requireUserVerification: true
    });

    console.log(
      'Verification result:',
      verification.verified
    );

    if (!verification.verified) {
      return res.status(400).json({
        verified: false,
        error: 'Authentication failed'
      });
    }

    // Update counter
    await pool.query(
      `
      UPDATE webauthn_credentials
      SET counter = $1,
          last_used = NOW()
      WHERE credential_id = $2
      `,
      [
        verification.authenticationInfo.newCounter,
        cred.credential_id
      ]
    );

    // Delete challenge
    await pool.query(
      `
      DELETE FROM webauthn_challenges
      WHERE challenge = $1
      `,
      [challenge]
    );

    // IMPORTANT: SAME PAYLOAD AS PASSWORD LOGIN - EMAIL ADDED
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin,
        role: user.is_admin? 'admin' : 'user',
        company: user.company
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    console.log(
      '=== AUTHENTICATE SUCCESS === User:',
      user.id
    );

    return res.json({
      verified: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        company: user.company,
        is_admin: user.is_admin,
        wallet_balance: user.wallet_balance
      }
    });

  } catch (e) {

    console.error('=== LOGIN FINISH ERROR ===');
    console.error(e);

    return res.status(400).json({
      verified: false,
      error: e.message
    });

  }
});

app.get('/api/auth/webauthn/check-enabled', auth, async (req, res) => {
  try {
    const config = getCompanyConfig(req.headers.origin);
    const userId = Number(req.user?.id || 0);
    
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    console.log('=== CHECK ENABLED === User:', userId, 'RP:', config.rpID);

    const result = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND rp_id=$2 LIMIT 1',
      [userId, config.rpID]
    );

    res.json({ enabled: result.rows.length > 0 });
  } catch (e) {
    console.error('Check enabled error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post("/api/auth/webauthn/verify-purchase", auth, async (req, res) => {
  try {

    const cfg = getCompanyConfig(req.get('origin'));

    const credRes = await pool.query(
      `
      SELECT
        credential_id,
        public_key,
        counter
      FROM webauthn_credentials
      WHERE user_id = $1
      AND rp_id = $2
      `,
      [
        req.user.id,
        cfg.rpID
      ]
    );

    if (!credRes.rows.length) {
      return res.status(400).json({
        error: 'No biometric setup found'
      });
    }

    const options = await generateAuthenticationOptions({
      rpID: cfg.rpID,

      allowCredentials: credRes.rows.map(c => ({
        id: c.credential_id,
        type: 'public-key',
        transports: ['internal', 'hybrid']
      })),

      userVerification: 'required'
    });

    await pool.query(
      `
      INSERT INTO webauthn_challenges
      (
        challenge,
        expires_at
      )
      VALUES
      (
        $1,
        NOW() + INTERVAL '5 minutes'
      )
      `,
      [options.challenge]
    );

    res.json(options);

  } catch (e) {

    console.error(e);

    res.status(500).json({
      error: e.message
    });

  }
});
app.post("/api/auth/webauthn/verify-purchase-finish", auth, async (req, res) => {
  try {

    const cfg = getCompanyConfig(req.get('origin'));

    const challengeRes = await pool.query(
      `
      SELECT challenge
      FROM webauthn_challenges
      WHERE expires_at > NOW()
      ORDER BY created_at DESC
      LIMIT 1
      `
    );

    if (!challengeRes.rows.length) {
      return res.json({
        verified: false,
        error: 'Challenge expired'
      });
    }

    const expectedChallenge = challengeRes.rows[0].challenge;

    const credRes = await pool.query(
      `
      SELECT
        credential_id,
        public_key,
        counter,
        transports
      FROM webauthn_credentials
      WHERE user_id = $1
      AND credential_id = $2
      `,
      [
        req.user.id,
        req.body.id
      ]
    );

    if (!credRes.rows.length) {
      return res.json({
        verified: false,
        error: 'Credential not found'
      });
    }

    const cred = credRes.rows[0];

    const verification = await verifyAuthenticationResponse({

      response: req.body,

      expectedChallenge,

      expectedOrigin: cfg.expectedOrigin,

      expectedRPID: cfg.rpID,

      credential: {

        id: cred.credential_id,

        publicKey: Buffer.from(
          cred.public_key,
          'base64url'
        ),

        counter: Number(cred.counter || 0),

        transports:
          cred.transports ||
          ['internal', 'hybrid']

      },

      requireUserVerification: true

    });

    if (!verification.verified) {

      return res.json({
        verified: false
      });

    }

    await pool.query(
      `
      UPDATE webauthn_credentials
      SET counter = $1
      WHERE credential_id = $2
      `,
      [
        verification.authenticationInfo.newCounter,
        cred.credential_id
      ]
    );

    await pool.query(
      `
      DELETE FROM webauthn_challenges
      WHERE challenge = $1
      `,
      [expectedChallenge]
    );

    res.json({
      verified: true
    });

  } catch (e) {

    console.error(e);

    res.json({
      verified: false,
      error: e.message
    });

  }
});
app.get('/api/ping', (req, res) => res.send('pong'));

/* ================= FUND INIT ================= */
app.post("/api/fund/init", auth, fundInitLimiter, async (req, res) => {
  const { amount } = req.body;
  if (!amount || Number(amount) < 100) return res.status(400).json({ message: "Minimum funding is ₦100" });

  const user = await getUser(req.user.id);
  const reference = "FUND-" + uuidv4();

  try {
    let accountData = await pool.query(
      "SELECT account_number, bank_name, account_name, paymentmethod FROM users WHERE id=$1",
      [user.id]
    );

    if (!accountData.rows[0]?.account_number || accountData.rows[0].paymentmethod!== "paymentpoint") {
      const ppResponse = await createPaymentPointAccount(user);

      if (ppResponse.status === "success" && ppResponse.bankAccounts?.length > 0) {
        const newAccount = ppResponse.bankAccounts[0];
        await pool.query(
          `UPDATE users SET
            account_number = $1,
            account_name = $2,
            bank_name = $3,
            paymentmethod = 'paymentpoint',
            customer_id = $4
           WHERE id = $5`,
          [
            newAccount.accountNumber,
            newAccount.accountName,
            newAccount.bankName,
            ppResponse.customer?.customer_id || null,
            user.id
          ]
        );

        accountData = {
          rows: [{
            account_number: newAccount.accountNumber,
            bank_name: newAccount.bankName,
            account_name: newAccount.accountName,
            paymentmethod: "paymentpoint"
          }]
        };
      } else {
        throw new Error(ppResponse.errors?.join("; ") || "Failed to create virtual account");
      }
    }

    res.json({
      bank_name: accountData.rows[0].bank_name,
      account_number: accountData.rows[0].account_number,
      account_name: accountData.rows[0].account_name,
      reference,
      method: "paymentpoint"
    });

  } catch (e) {
    console.log("FUND INIT ERROR:", e.response?.data || e.message);
    res.status(500).json({ message: e.message || "Unable to initialize payment" });
  }
});

/* ================= DVA ROUTE - FINAL VERSION ================= */
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Use Redis in production. This Set is only for single-instance
const generatingUsers = new Set();

app.post('/api/wallet/create-dva', auth, async (req, res) => {
  const userId = req.user.id;
  const lockKey = `gen_dva_${userId}`;

  if (generatingUsers.has(lockKey)) {
    return res.status(429).json({
      success: false,
      error: 'Account generation in progress. Please wait 1-2 minutes...'
    });
  }
  generatingUsers.add(lockKey);
  setTimeout(() => generatingUsers.delete(lockKey), 90000);

  try {
    const user = await getUser(userId);
    if (!user) {
      generatingUsers.delete(lockKey);
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (user.account_number && user.paymentmethod === "paymentpoint") {
      generatingUsers.delete(lockKey);
      return res.status(200).json({
        success: true,
        message: "Account already exists",
        account_number: user.account_number,
        bank_name: user.bank_name,
        account_name: user.account_name
      });
    }

    if (!user.phone || String(user.phone).trim().length < 10) {
      generatingUsers.delete(lockKey);
      return res.status(400).json({
        success: false,
        error: 'Phone number missing or invalid. Update your profile first.'
      });
    }

    if (!user.email) {
      generatingUsers.delete(lockKey);
      return res.status(400).json({
        success: false,
        error: 'Email missing. Update your profile first.'
      });
    }

    if (!user.company) {
      generatingUsers.delete(lockKey);
      return res.status(400).json({
        success: false,
        error: 'Company not set for user. Contact support.'
      });
    }

    const { bvn, nin } = req.body;

    if (!bvn &&!nin) {
      generatingUsers.delete(lockKey);
      return res.status(422).json({
        success: false,
        requireKyc: true,
        message: 'Valid BVN or NIN is required to generate account'
      });
    }

    if ((bvn &&!/^\d{11}$/.test(bvn)) || (nin &&!/^\d{11}$/.test(nin))) {
      generatingUsers.delete(lockKey);
      return res.status(422).json({
        success: false,
        error: 'BVN/NIN must be 11 digits'
      });
    }

    console.log(`[User ${userId}] Waiting 20s for PaymentPoint warmup...`);
    await sleep(20000);

    const creds = getPaymentPointCreds(user.company);
    let attempts = 0;
    const maxAttempts = 3;
    let ppResponse = null;
    let lastError = null;

    while (attempts < maxAttempts) {
      attempts++;
      console.log(`[User ${userId}] PaymentPoint attempt ${attempts}/${maxAttempts}`);

      try {
        ppResponse = await createPaymentPointAccount(user, { bvn, nin });
        console.log('[DVA Route] PP Response:', JSON.stringify(ppResponse));

        if (ppResponse.status === "success" && ppResponse.bankAccounts?.length > 0) {
          break;
        }

        if (ppResponse.status === "success" && (!ppResponse.bankAccounts || ppResponse.bankAccounts.length === 0)) {
          const errorString = ppResponse.errors?.join(" ").toLowerCase() || "";

          if (errorString.includes('reserved account') || errorString.includes('failed to create')) {
            console.log('[DVA Route] No accounts yet, waiting 10s for PP provisioning...');
            await sleep(10000);

            try {
              const { data: fetchRes } = await axios.get(
                `${PAYMENTPOINT_BASE}/api/v1/customer?email=${encodeURIComponent(user.email)}`,
                {
                  headers: {
                    'Authorization': `Bearer ${creds.secretKey}`,
                    'api-key': creds.apiKey,
                    'Content-Type': 'application/json'
                  },
                  timeout: 60000
                }
              );
              console.log('[DVA Route] Refetch response:', JSON.stringify(fetchRes));

              if (fetchRes.bankAccounts?.length > 0) {
                ppResponse = fetchRes;
                break;
              }
            } catch (e) {
              console.log('[DVA Route] Refetch failed:', e.message);
            }
          }
        }

        lastError = ppResponse.errors?.join("; ") || 'No accounts returned';

      } catch (err) {
        console.error(`[User ${userId}] Attempt ${attempts} failed:`, err.message);
        lastError = err.message;

        if (err.message.includes('BVN') || err.message.includes('NIN') || err.message.includes('Phone')) {
          break;
        }
      }

      if (attempts < maxAttempts) {
        await sleep(10000);
      }
    }

    if (!ppResponse?.bankAccounts || ppResponse.bankAccounts.length === 0) {
      generatingUsers.delete(lockKey);
      const errorString = ppResponse?.errors?.join(" ").toLowerCase() || "";

      if (errorString.includes('kyc') ||
          errorString.includes('bvn') ||
          errorString.includes('nin') ||
          errorString.includes('verification') ||
          errorString.includes('reserved account') ||
          errorString.includes('failed to create')) {

        return res.status(200).json({
          success: false,
          requireKyc: true,
          message: 'BVN or NIN required, or account still provisioning. Please wait 30s and try again.',
          pp: ppResponse
        });
      }

      return res.status(400).json({
        success: false,
        error: lastError || 'Bank temporarily unavailable. Try again later.'
      });
    }

    const account = ppResponse.bankAccounts[0];
    if (!account?.accountNumber) {
      generatingUsers.delete(lockKey);
      return res.status(500).json({
        success: false,
        error: 'PaymentPoint returned no account details'
      });
    }

    await pool.query(
      `UPDATE users SET
        account_number = $1,
        account_name = $2,
        bank_name = $3,
        paymentmethod = 'paymentpoint',
        customer_id = $4,
        bvn = COALESCE($5, bvn),
        nin = COALESCE($6, nin),
        updated_at = NOW()
       WHERE id = $7`,
      [
        account.accountNumber,
        account.accountName,
        account.bankName,
        ppResponse.customer?.customer_id || null,
        bvn || null,
        nin || null,
        userId
      ]
    );

    generatingUsers.delete(lockKey);
    return res.status(200).json({
      success: true,
      account_number: account.accountNumber,
      bank_name: account.bankName,
      account_name: account.accountName,
      method: "paymentpoint"
    });

  } catch (error) {
    console.error('DVA Error:', error.message, error.stack);
    generatingUsers.delete(lockKey);

    if (error.message.includes('BVN must be') ||
        error.message.includes('NIN must be') ||
        error.message.includes('Phone number') ||
        error.message.includes('Email') ||
        error.message.includes('PaymentPoint not configured') ||
        error.message.includes('timeout')) {
      return res.status(400).json({
        success: false,
        error: error.message
      });
    }

    res.status(500).json({
      success: false,
      error: error.message || 'Failed to create virtual account. Please try again.'
    });
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
      const paymentpointCompanies = ["teeversh", "sadeeq", "bnhabeeb", "mayconnect", "msdatasub"];
      if (paymentpointCompanies.includes(userCompany.toLowerCase())) {
        const ppResponse = await createPaymentPointAccount(user.rows[0]);
        if (ppResponse.status === "success" && ppResponse.bankAccounts?.length > 0) {
          const account = ppResponse.bankAccounts[0];
          await pool.query(
            `UPDATE users SET
              account_number = $1,
              account_name = $2,
              bank_name = $3,
              paymentmethod = 'paymentpoint',
              customer_id = $4
             WHERE id = $5`,
            [
              account.accountNumber,
              account.accountName,
              account.bankName,
              ppResponse.customer?.customer_id || null,
              user.rows[0].id
            ]
          );
        }
      }
    } catch (e) {
      console.log("ACCOUNT CREATE ERROR ON SIGNUP - continuing anyway:", e.message);
    }

    const updatedUser = await getUser(user.rows[0].id);
    const token = jwt.sign(
      { id: updatedUser.id, username: updatedUser.username, is_admin: updatedUser.is_admin, company: updatedUser.company },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, message: "Signup successful" });
  } catch (e) {
    console.log("SIGNUP ERROR:", e.message);
    if (e.code === "23505") return res.status(400).json({ message: "Username or email already exists" });
    res.status(500).json({ message: "Signup failed" });
  }
});



/* ================= LOGIN - USERNAME OR EMAIL ================= */
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { username, email, password, login } = req.body;

    const loginIdentifier = login || username || email;

    if (!loginIdentifier ||!password) {
      return res.status(400).json({ message: "Username/Email and password are required" });
    }
    if (typeof loginIdentifier!== 'string' || typeof password!== 'string') {
      return res.status(400).json({ message: "Invalid input type" });
    }

    const trimmedLogin = loginIdentifier.trim().toLowerCase();

    const userRes = await pool.query(
      "SELECT * FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1",
      [trimmedLogin]
    );

    if (!userRes.rows.length) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({ message: "Account blocked. Contact support." });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        is_admin: user.is_admin,
        role: user.is_admin? 'admin' : 'user',
        company: user.company
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        company: user.company,
        is_admin: user.is_admin,
        wallet_balance: user.wallet_balance
      }
    });
  } catch (e) {
    console.error("LOGIN ERROR:", e);
    res.status(500).json({ message: "Login failed. Try again later." });
  }
});

/* ================= USER INFO - WITH TIER CHECK ================= */
app.get("/api/me", auth, async (req, res) => {
  try {
    if (!req.user ||!req.user.id) {
      return res.status(401).json({ message: "Unauthorized - req.user missing" });
    }

    let user = await getUser(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // DON'T AWAIT THIS - Let it run in background
    const paymentpointCompanies = ["teeversh", "sadeeq", "bnhabeeb", "mayconnect", "msdatasub"];
    if (!user.account_number && paymentpointCompanies.includes(user.company?.toLowerCase()) && user.phone) {
      createPaymentPointAccount(user).then(async (ppResponse) => {
        if (ppResponse.status === "success" && ppResponse.bankAccounts?.length > 0) {
          const account = ppResponse.bankAccounts[0];
          await pool.query(
            `UPDATE users SET account_number=$1, account_name=$2, bank_name=$3, paymentmethod='paymentpoint', customer_id=$4 WHERE id=$5`,
            [account.accountNumber, account.accountName, account.bankName, ppResponse.customer?.customer_id || null, user.id]
          );
          console.log('[BG] PaymentPoint account created for user', user.id);
        }
      }).catch(e => {
        console.log("Account creation failed on /me:", e.message);
      });
    }

    const [topCheck] = await Promise.all([pool.query("SELECT 1 FROM top_users WHERE id=$1", [req.user.id])]);
    const userData = {...user };
    userData.is_top_user = topCheck.rows.length > 0;
    userData.user_tier = userData.is_top_user? 'top' : 'default';
    delete userData.password;
    delete userData.pin;

    res.json(userData); // SEND IMMEDIATELY - don't wait for PP
  } catch (err) {
    console.error('/api/me error:', err);
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
        account: {
          account_number: user.account_number,
          bank_name: user.bank_name,
          account_name: user.account_name
        },
        user_id: user.id
      });
    }

    if (!user.phone || user.phone.trim().length < 10) {
      return res.status(400).json({ message: "Please update your phone number in profile first" });
    }

    const paymentpointCompanies = ["teeversh", "sadeeq", "bnhabeeb", "mayconnect", "msdatasub"];
    if (!paymentpointCompanies.includes(user.company.toLowerCase())) {
      return res.status(400).json({ message: "Account creation not supported for this company" });
    }

    const ppResponse = await createPaymentPointAccount(user);

    if (ppResponse.status!== "success" ||!ppResponse.bankAccounts?.length) {
      throw new Error(ppResponse.errors?.join("; ") || "Failed to create virtual account");
    }

    const account = ppResponse.bankAccounts[0];
    await pool.query(
      `UPDATE users SET
        account_number = $1,
        account_name = $2,
        bank_name = $3,
        paymentmethod = 'paymentpoint',
        customer_id = $4
       WHERE id = $5`,
      [
        account.accountNumber,
        account.accountName,
        account.bankName,
        ppResponse.customer?.customer_id || null,
        user.id
      ]
    );

    res.json({
      message: "Account created successfully",
      account: {
        account_number: account.accountNumber,
        bank_name: account.bankName,
        account_name: account.accountName
      },
      user_id: user.id,
      company: user.company
    });

  } catch (e) {
    console.log("GENERATE ACCOUNT ERROR:", e.message);
    res.status(400).json({ message: e.message || "Failed to create account" });
  }
});

/* ================= TRANSACTIONS ================= */
app.get("/api/transactions", auth, async (req, res) => {
  try {
    console.log("User ID:", req.user.id);

    const tx = await pool.query(
      `
      SELECT *
      FROM transactions
      WHERE user_id = $1
      ORDER BY id DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    console.log("Transactions found:", tx.rows.length);

    // Show latest transaction in terminal
    console.log(tx.rows[0]);

    res.json(tx.rows);

  } catch (err) {
    console.error("TRANSACTION ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});
/* ================= PLANS - Grouped by plan_type: SME, SME2, GIFTING, CORPORATE_GIFTING ================= */
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

    // 1. Force these 4 tabs - ADDED GIFTING BACK
    const planTypes = ['SME', 'SME2', 'GIFTING', 'CORPORATE_GIFTING'];

    // 2. Get plans grouped by plan_type
    const groupedPlans = {};
    for (let type of planTypes) {
      const plansResult = await pool.query(
        `SELECT
           id, company, network, provider, name, validity, plan_type,
           api_plan_id, network_id, cost, is_active, restricted,
           CASE
             WHEN $3 = 'top' THEN COALESCE(top_price, regular_price, price)
             WHEN $3 = 'regular' THEN COALESCE(regular_price, price)
             ELSE price
           END as price,
           price as default_price,
           regular_price,
           top_price
         FROM plans
         WHERE company ILIKE $1
           AND plan_type = $2
           AND is_active = true
           AND (restricted = false OR $3 = 'top')
         ORDER BY price ASC`,
        [company, type, userTier]
      );
      groupedPlans[type] = plansResult.rows; // will be [] if no plans
    }

    res.json({ success: true, data: groupedPlans, planTypes });
  } catch (err) {
    console.error("Plans error:", err);
    res.status(500).json({ message: "Failed to fetch plans" });
  }
});

/* ================= BUY DATA - Multi-provider + BIOMETRIC + DANMALAMA + JJDATASUB ================= */
app.post("/api/buy-data", auth, buyDataLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    const { plan_id, phone, pin } = req.body;

    if (!plan_id ||!phone) {
      return res.status(400).json({ message: "plan_id and phone are required" });
    }
    if (!/^\d{10,15}$/.test(String(phone))) {
      return res.status(400).json({ message: "Invalid phone number. Use 11 digits like 08101234567" });
    }

    await client.query("BEGIN");
    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];
    if (!user) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "User not found" });
    }

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

    if (plan.restricted && plan.company!== user.company) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Plan restricted to company users" });
    }

    if (!plan.provider) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Plan not configured with provider. Contact admin." });
    }

    // Provider-specific validation
    if (plan.provider === "subpadi") {
      if (!plan.api_plan_id) {
        await client.query("ROLLBACK");
        return res.status(400).json({ message: "Plan not configured with product_id. Contact admin." });
      }
    } else {
      if (!plan.api_plan_id || plan.network_id === null || plan.network_id === undefined) {
        await client.query("ROLLBACK");
        return res.status(400).json({ message: "Plan not configured with provider plan ID or network_id. Contact admin." });
      }

      const netId = Number(plan.network_id);
      if (isNaN(netId) || netId < 1 || netId > 4) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          message: `Invalid network_id: ${plan.network_id}. Must be numeric 1-4`
        });
      }
    }

    const tierRes = await client.query("SELECT 1 FROM top_users WHERE id=$1", [user.id]);
    const isTopUser = tierRes.rows.length > 0;
    const price = isTopUser? (plan.top_price || plan.price) : plan.price;
    const balanceNum = Number(user.wallet_balance);
    const priceNum = Number(price);
    const cost = Number(plan.cost);

    if (balanceNum < priceNum) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        message: `Insufficient balance. You have ₦${balanceNum.toFixed(2)}, this plan costs ₦${priceNum.toFixed(2)}`
      });
    }

    const balanceBefore = Number(balanceNum);
    const balanceAfterDeduct = Number(balanceBefore) - Number(priceNum); // DEDUCT FIRST
    const ref = "DATA-" + uuidv4();

    // 1. DEBIT WALLET FIRST + INSERT PENDING TRANSACTION
    await client.query("UPDATE users SET wallet_balance=$1::numeric, updated_at=NOW() WHERE id=$2", [balanceAfterDeduct, user.id]);

    const txRes = await client.query(
      `INSERT INTO transactions(user_id,plan_id,type,amount,cost,phone,network,reference,status,plan_name,provider,balance_before,balance_after)
       VALUES($1,$2,'DATA',$3::numeric,$4::numeric,$5,$6,$7,'PENDING',$8,$9,$10::numeric,$11::numeric) RETURNING *`,
      [user.id, plan.id, priceNum, cost, phone, plan.network, ref, plan.name, plan.provider, balanceBefore, balanceAfterDeduct]
    );
    const txId = txRes.rows[0].id;
    await client.query("COMMIT");

    // 2. CALL PROVIDER API - WAJEN TRANSACTION
    let apiResponse = null;
    let finalStatus = 'FAILED';
    let responseMsg = 'Unknown error';

    try {
      if (plan.provider === "maitama") {
        apiResponse = await callMaitamaData(phone, plan.network_id, plan.api_plan_id, user.company);
      } else if (plan.provider === "cheapdatahub") {
        apiResponse = await callCheapDataHubData(phone, plan.network_id, plan.api_plan_id);
      } else if (plan.provider === "subpadi") {
        apiResponse = await callSubPadiData(phone, plan.api_plan_id, user.company);
      } else if (plan.provider === "arrahuz") {
        apiResponse = await callArrahuzData(phone, plan.network_id, plan.api_plan_id, user.company);
    } else if (plan.provider === "jjdatasub") {
        apiResponse = await callJJDataSubData(phone, plan.network_id, plan.api_plan_id, user.company);
      } else if (plan.provider === "alihsandatasub") {
        apiResponse = await callAlihsanData(phone, plan.network_id, plan.api_plan_id, user.company);
      } else {
        throw new Error("Unknown provider");
      }

      // Check success
      if (apiResponse.status === 'success' || apiResponse.code === 200 || apiResponse.Status?.toLowerCase() === 'successful') {
        finalStatus = 'SUCCESS';
        responseMsg = 'Transaction successful';
      } else if (apiResponse.status === 'pending' || apiResponse.Status?.toLowerCase() === 'pending') {
        finalStatus = 'PENDING';
        responseMsg = 'Transaction pending. Will be delivered shortly.';
      } else {
        finalStatus = 'FAILED';
        responseMsg = apiResponse.message || apiResponse.api_response || 'Provider rejected transaction';
      }
    } catch (vtuErr) {
      finalStatus = 'FAILED';
      responseMsg = vtuErr.response?.data?.message || vtuErr.response?.data?.api_response || vtuErr.message || 'API timeout';
      apiResponse = vtuErr.response?.data || { error: vtuErr.message };

      if (vtuErr.response?.data?.errors) {
        const errs = vtuErr.response.data.errors;
        if (errs.network) responseMsg = `Network error: ${errs.network[0]}`;
        else if (errs.plan) responseMsg = `Plan error: ${errs.plan[0]}`;
        else if (errs.mobile_number) responseMsg = `Phone error: ${errs.mobile_number[0]}`;
      }

      if (vtuErr.message === 'TIMEOUT_POSSIBLE_SUCCESS' || vtuErr.code === 'ECONNABORTED') {
        finalStatus = 'PENDING';
        responseMsg = 'Request submitted. Delivery pending.';
      }
    }

    // 3. UPDATE TRANSACTION + HANDLE REFUND IF FAILED
    await client.query("BEGIN");
    let finalBalance = balanceAfterDeduct;

    if (finalStatus === 'FAILED') {
      // REFUND WALLET
      finalBalance = Number(balanceBefore);
      await client.query("UPDATE users SET wallet_balance=$1::numeric, updated_at=NOW() WHERE id=$2", [finalBalance, user.id]);
    }

    // ADMIN PROFIT ONLY ON SUCCESS
    if (finalStatus === 'SUCCESS') {
      const adminId = await getCompanyAdmin(user.company);
      const profit = Number(priceNum) - Number(cost);
      if (adminId && profit > 0) {
        await client.query("UPDATE users SET admin_wallet = admin_wallet + $1::numeric, updated_at=NOW() WHERE id=$2", [profit, adminId]);
        await client.query(
          `INSERT INTO profits(transaction_id,type,amount,reference,credited_to_user_id)
           VALUES($1,'sale',$2::numeric,$3,$4)`,
          [txId, profit, ref, adminId]
        );
      }
    }

    await client.query(`
      UPDATE transactions
      SET status = $1, response_msg = $2, api_response = $3, updated_at = NOW(),
          balance_after = $5::numeric
      WHERE id = $4
    `, [finalStatus, responseMsg, JSON.stringify(apiResponse), txId, Number(finalBalance)]);

    await client.query("COMMIT");

    sendWalletUpdate(user.id, finalBalance);

    // 4. RETURN RESPONSE
    if (finalStatus === 'FAILED') {
      return res.status(400).json({
        success: false,
        message: responseMsg,
        reference: ref,
        status: 'FAILED',
        balance_before: Number(balanceBefore),
        balance_after: Number(finalBalance),
        phone: phone,
        network: plan.network,
        plan_name: plan.name,
        amount: Number(priceNum),
        created_at: new Date().toISOString()
      });
    }

    await sendPushNotification(user.company, user.id, {
      title: `${user.company.toUpperCase()} - Data Purchase`,
      body: `Your ${plan.name} purchase for ${phone} was ${finalStatus.toLowerCase()}`,
      url: '/dashboard.html'
    });

    res.json({
      success: true,
      reference: ref,
      status: finalStatus,
      balance: Number(finalBalance),
      balance_before: Number(balanceBefore),
      balance_after: Number(finalBalance),
      tier: isTopUser? 'top' : 'default',
      phone: phone,
      network: plan.network,
      plan_name: plan.name,
      amount: Number(priceNum),
      created_at: new Date().toISOString()
    });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("BUY DATA ERROR:", e);
    res.status(500).json({ message: "Purchase failed. Try again later." });
  } finally {
    client.release();
  }
});
/* ================= BUY AIRTIME - Maitama: 1=MTN, 2=GLO, 3=9MOBILE, 4=AIRTEL ================= */
const MAITAMA_NETWORK_MAP = {
  'mtn': 1,
  'glo': 3, // FIXED: was airtel
  '9mobile': 4,
  '9m': 6,
  'etisalat': 5,
  'airtel': 2 // FIXED: was 2
};

function getMaitamaNetworkId(networkName) {
  const net = String(networkName).toLowerCase().trim();
  return MAITAMA_NETWORK_MAP[net] || null;
}

function formatPhoneForMaitama(phone) {
  let p = String(phone).replace(/\D/g, '');
  if (p.startsWith('234')) p = '0' + p.slice(3);
  if (p.length === 10) p = '0' + p;
  return p;
}

async function callMaitamaAirtime(phone, network, amount, company, uniqueRef = null) {
  const { base_url, tokens } = VTU_PROVIDERS.maitama;
  const api_token = tokens[company];
  if (!api_token) throw new Error(`No Maitama token configured for ${company}`);

  let networkId;
  if (typeof network === 'string') {
    networkId = getMaitamaNetworkId(network);
    if (!networkId) throw new Error(`Invalid network: ${network}. Use: mtn, airtel, glo, 9mobile`);
  } else {
    networkId = Number(network);
  }

  if (![1, 2, 3, 4].includes(networkId)) {
    throw new Error(`Invalid Maitama network_id: ${networkId}. Must be 1=MTN, 2=Glo, 3=9mobile, 4=Airtel`);
  }

  const amountNum = Number(amount);
  if (amountNum < 50 || amountNum > 5000) {
    throw new Error(`Amount must be between ₦50 and ₦5,000. Got: ₦${amountNum}`);
  }

  const formattedPhone = formatPhoneForMaitama(phone);
  const payload = { network: networkId, amount: amountNum, mobile_number: formattedPhone };
  let endpoint = uniqueRef? `${base_url}/api/topup/${uniqueRef}` : `${base_url}/api/topup`;

  console.log(`MAITAMA AIRTIME REQUEST:`, { endpoint, payload, company });

  try {
    const res = await axios.post(endpoint, payload, {
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": `Bearer ${api_token}`,
        "User-Agent": "MUSTYKNK/1.0"
      },
      timeout: 180000, // 3 minutes
    });

    const data = res.data?.data || res.data;
    const status = data?.Status;

    if (status?.toLowerCase() === "successful" || status?.toLowerCase() === "success") {
      return data;
    }
    if (status?.toLowerCase() === "pending") {
      return {...data, _pending: true };
    }
    throw new Error(data?.api_response || data?.message || "Maitama airtime failed");
  } catch (err) {
    if (err.response?.status === 403) {
      throw new Error(`IP_BLOCKED: ${err.response.data?.message}`);
    }
    if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
      throw new Error('TIMEOUT_FAILED'); // REFUND
    }
    throw err;
  }
}

app.get("/api/test-maitama", async (req, res) => {
  try {
    const response = await axios.get("https://app.maitamadatahub.com", {
      timeout: 15000,
      validateStatus: () => true
    });

    res.json({
      success: true,
      status: response.status,
      message: "Render can connect to Maitama"
    });
  } catch (error) {
    res.json({
      success: false,
      code: error.code,
      message: error.message
    });
  }
});

app.get("/api/test-outbound-ip", async (req, res) => {
  try {
    const response = await axios.get("https://api.ipify.org?format=json", {
      timeout: 10000
    });

    res.json({
      success: true,
      render_outbound_ip: response.data.ip
    });
  } catch (error) {
    res.json({
      success: false,
      code: error.code,
      message: error.message
    });
  }
});

app.get("/api/test-maitama-ip", async (req, res) => {
  try {
    const response = await axios.get("https://46.202.128.25", {
      timeout: 15000,
      validateStatus: () => true,
      httpsAgent: new (require("https").Agent)({
        rejectUnauthorized: false
      }),
      headers: {
        Host: "app.maitamadatahub.com"
      }
    });

    res.json({
      success: true,
      status: response.status,
      message: "Render reached Maitama IP"
    });
  } catch (error) {
    res.json({
      success: false,
      code: error.code,
      errno: error.errno || null,
      message: error.message
    });
  }
});

app.get("/api/test-maitama-tcp", async (req, res) => {
  const net = require("net");

  const socket = new net.Socket();

  const timeout = setTimeout(() => {
    socket.destroy();
    res.json({
      success: false,
      stage: "TCP",
      message: "TCP connection to 46.202.128.25:443 timed out"
    });
  }, 15000);

  socket.connect(443, "46.202.128.25", () => {
    clearTimeout(timeout);
    socket.destroy();

    res.json({
      success: true,
      stage: "TCP",
      message: "TCP connection to 46.202.128.25:443 succeeded"
    });
  });

  socket.on("error", (error) => {
    clearTimeout(timeout);

    if (!res.headersSent) {
      res.json({
        success: false,
        stage: "TCP",
        code: error.code || null,
        message: error.message
      });
    }
  });
});

app.get("/api/test-external-https", async (req, res) => {
  try {
    const start = Date.now();

    const response = await axios.get("https://example.com", {
      timeout: 15000
    });

    res.json({
      success: true,
      status: response.status,
      elapsed_ms: Date.now() - start
    });
  } catch (error) {
    res.json({
      success: false,
      code: error.code || null,
      message: error.message
    });
  }
});


app.post("/api/buy-airtime", auth, buyDataLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    const { phone, amount, network, pin } = req.body;

    if (!phone ||!amount ||!network) {
      return res.status(400).json({ message: "phone, amount, and network are required" });
    }

    const amt = Number(amount);
    if (isNaN(amt) || amt < 50 || amt > 5000) {
      return res.status(400).json({ message: "Amount must be between ₦50 and ₦5,000" });
    }

    const networkKey = String(network).toLowerCase();
    const networkId = getMaitamaNetworkId(networkKey);

    if (!networkId) {
      return res.status(400).json({ message: "Invalid network. Use MTN, Airtel, Glo, or 9mobile" });
    }

    const formattedPhone = formatPhoneForMaitama(phone);
    if (formattedPhone.length!== 11 ||!formattedPhone.startsWith('0')) {
      return res.status(400).json({ message: "Phone must be 11 digits starting with 0" });
    }

    await client.query("BEGIN");
    const userRes = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const user = userRes.rows[0];
    if (!user) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "User not found" });
    }

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

    if (Number(user.wallet_balance) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient balance" });
    }

    const balanceBefore = Number(user.wallet_balance);
    const ref = "AIRTIME-" + uuidv4();
    const cost = Number(amt) * 0.98;

    // 1. INSERT PENDING - NO DEBIT YET
    const txRes = await client.query(
      `INSERT INTO transactions(
        user_id, type, amount, cost, phone, network,
        reference, status, provider, gateway, balance_before, balance_after
      ) VALUES($1,'AIRTIME',$2::numeric,$3::numeric,$4,$5,$6,'PENDING','maitama','maitama',$7::numeric,$7::numeric) RETURNING *`,
      [user.id, amt, cost, formattedPhone, networkKey, ref, balanceBefore]
    );
    const txId = txRes.rows[0].id;
    await client.query("COMMIT");

    // 2. CALL API
    let maitamaRes;
    let finalStatus = 'FAILED';
    let responseMsg = 'Unknown error';

    try {
      maitamaRes = await callMaitamaAirtime(formattedPhone, networkId, amt, user.company, ref);
      finalStatus = maitamaRes?._pending? 'PENDING' : 'SUCCESS';
      responseMsg = finalStatus === 'SUCCESS'? 'Airtime delivered' : 'Processing';
    } catch (vtuErr) {
      finalStatus = 'FAILED';
      responseMsg = vtuErr.message || 'API error';
      maitamaRes = vtuErr.response?.data || { error: vtuErr.message };

      if (vtuErr.message === 'TIMEOUT_FAILED') {
        finalStatus = 'FAILED';
        responseMsg = 'Network timeout. Amount not deducted. Please try again.';
      }
      if (vtuErr.message.includes('IP_BLOCKED')) {
        finalStatus = 'FAILED';
        responseMsg = 'Server IP not whitelisted on Maitama. Contact admin.';
      }
    }

    // 3. UPDATE + DEBIT ONLY IF SUCCESS
    let balanceAfter = Number(balanceBefore);

    await client.query("BEGIN");

    if (finalStatus === 'SUCCESS') {
      balanceAfter = Number(balanceBefore) - Number(amt);
      await client.query("UPDATE users SET wallet_balance=$1::numeric, updated_at=NOW() WHERE id=$2", [balanceAfter, user.id]);

      const adminId = await getCompanyAdmin(user.company);
      const profit = Number(amt) - Number(cost);
      if (adminId && profit > 0) {
        await client.query("UPDATE users SET admin_wallet = admin_wallet + $1::numeric, updated_at=NOW() WHERE id=$2", [profit, adminId]);
        await client.query(
          `INSERT INTO profits(transaction_id,type,amount,reference,credited_to_user_id)
           VALUES($1,'sale',$2::numeric,$3,$4)`,
          [txId, profit, ref, adminId]
        );
      }
    }

    await client.query(`
      UPDATE transactions
      SET status = $1, response_msg = $2, api_response = $3, updated_at = NOW(),
          balance_after = $5::numeric
      WHERE id = $4
    `, [finalStatus, responseMsg, JSON.stringify(maitamaRes), txId, Number(balanceAfter)]);

    await client.query("COMMIT");

    // 4. HANDLE FAILED
    if (finalStatus === 'FAILED') {
      sendWalletUpdate(user.id, balanceBefore);
      return res.status(400).json({
        success: false,
        message: responseMsg,
        reference: ref,
        status: 'FAILED',
        balance_before: Number(balanceBefore),
        balance_after: Number(balanceBefore),
        phone: formattedPhone,
        network: networkKey,
        amount: Number(amt),
        created_at: new Date().toISOString()
      });
    }

    sendWalletUpdate(user.id, balanceAfter);

    await sendPushNotification(user.company, user.id, {
      title: `${user.company.toUpperCase()} - Airtime Purchase`,
      body: `Your ₦${amt} airtime for ${formattedPhone} was ${finalStatus.toLowerCase()}`,
      url: '/dashboard.html'
    });

    res.json({
      success: true,
      reference: ref,
      status: finalStatus,
      balance: Number(balanceAfter),
      balance_before: Number(balanceBefore),
      balance_after: Number(balanceAfter),
      provider: 'maitama',
      network_id: networkId,
      phone: formattedPhone,
      network: networkKey,
      amount: Number(amt),
      created_at: new Date().toISOString()
    });

  } catch (e) {
    await client.query("ROLLBACK");
    console.error("BUY AIRTIME ERROR:", e);
    res.status(500).json({ message: "Purchase failed. Try again later." });
  } finally {
    client.release();
  }
});

/* ================= CHANGE PASSWORD/PIN ================= */
app.post("/api/change-password", auth, async (req, res) => {
  try {
    const { oldPass, newPass } = req.body;
    if (!oldPass ||!newPass) {
      return res.status(400).json({ message: "oldPass and newPass are required" });
    }
    if (newPass.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!(await bcrypt.compare(oldPass, user.password))) {
      return res.status(400).json({ message: "Wrong old password" });
    }

    const hash = await bcrypt.hash(newPass, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, user.id]);
    res.json({ message: "Password updated" });
  } catch (e) {
    console.error("CHANGE PASSWORD ERROR:", e);
    res.status(500).json({ message: "Failed to update password" });
  }
});

app.post("/api/change-pin", auth, buyDataLimiter, async (req, res) => {
  try {
    const { oldPin, newPin } = req.body;

    if (!newPin || String(newPin).length < 4) {
      return res.status(400).json({ message: "New PIN must be at least 4 digits" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });

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

    const hash = await bcrypt.hash(String(newPin), 10);
    await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, user.id]);
    res.json({ message: "PIN updated successfully" });
  } catch (e) {
    console.error("CHANGE PIN ERROR:", e);
    res.status(500).json({ message: "Failed to update PIN" });
  }
});

/* ================= FORGOT PIN ================= */
app.post("/api/reset-pin", auth, buyDataLimiter, async (req, res) => {
  try {
    const { password, newPin } = req.body;

    if (!password) {
      return res.status(400).json({ message: "Enter your login password" });
    }
    if (!newPin || String(newPin).length!== 4 || isNaN(newPin)) {
      return res.status(400).json({ message: "New PIN must be exactly 4 digits" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });

    // Verify login password instead of old PIN
    const validPassword = await bcrypt.compare(String(password), String(user.password));
    if (!validPassword) {
      return res.status(400).json({ message: "Wrong login password" });
    }

    // Hash and save new PIN
    const hash = await bcrypt.hash(String(newPin), 10);
    await pool.query("UPDATE users SET pin=$1 WHERE id=$2", [hash, user.id]);
    res.json({ message: "PIN reset successfully" });
  } catch (e) {
    console.error("RESET PIN ERROR:", e);
    res.status(500).json({ message: "Failed to reset PIN" });
  }
});
// 1. ADMIN: Create reset link for a user - multi-domain support
app.post('/api/admin/create-reset-link', async (req, res) => {
  const { username, domain } = req.body;

  if (!username) {
    return res.status(400).json({ message: 'Username or email required' });
  }

  // Whitelist your domains
  const allowedDomains = [
    'mayconnectdataplug.com.ng',
    'teevershdataplug.com.ng',
    'sadeeqdatahub.com.ng',
    'bnhabeebdatahub.com.ng',
    'msdatadatahub.com.ng'
  ];

  const targetDomain = domain && allowedDomains.includes(domain)
   ? domain
    : 'mayconnectdataplug.com.ng'; // default fallback

  try {
    const result = await pool.query(
      'SELECT id, email, username FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 1000 * 60 * 60; // 1 hour

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [token, expires, user.id]
    );

    // Build URL with the correct domain
    const resetUrl = `https://${targetDomain}/reset-password.html?token=${token}&email=${encodeURIComponent(user.email)}`;

    res.json({
      success: true,
      message: 'Reset link created',
      resetUrl: resetUrl,
      username: user.username,
      domain: targetDomain,
      expires_in: '1 hour'
    });

  } catch (err) {
    console.error('Create reset link error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 2. USER: Set new password - same as before, works for all domains
app.post('/api/reset-password', async (req, res) => {
  const { email, token, password } = req.body;

  if (!email ||!token ||!password) {
    return res.status(400).json({ message: 'Email, token and password required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  try {
    const result = await pool.query(
      'SELECT id, reset_token_expires FROM users WHERE email = $1 AND reset_token = $2',
      [email, token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid reset link' });
    }

    const user = result.rows[0];

    if (Date.now() > Number(user.reset_token_expires)) {
      return res.status(400).json({ message: 'Reset link expired. Contact support for a new one.' });
    }

    const hash = await bcrypt.hash(password, 12);

    // Change to password_hash if that's your column name
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hash, user.id]
    );

    res.json({ success: true, message: 'Password updated successfully' });

  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Server error' });
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
        t.created_at, t.updated_at, t.cost, t.network, t.provider,
        t.provider_reference, t.description, t.metadata,
        t.response_msg, t.api_response,
        u.username, u.email, u.company,
        CASE
          WHEN t.type = 'WALLET_FUND' THEN 'CREDIT'
          WHEN t.type = 'REVERSAL' THEN 'CREDIT'
          WHEN t.type = 'REFUND' THEN 'CREDIT'
          ELSE 'DEBIT'
        END AS display_type,
        CASE
          WHEN t.type = 'WALLET_FUND' THEN 'green'
          WHEN t.type = 'REVERSAL' THEN 'green'
          WHEN t.type = 'REFUND' THEN 'green'
          WHEN t.status = 'SUCCESS' THEN 'red'
          WHEN t.status = 'FAILED' THEN 'orange'
          WHEN t.status = 'PENDING' THEN 'yellow'
          ELSE 'gray'
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
                OR u.email ILIKE $${paramCount}
                OR t.response_msg ILIKE $${paramCount})`;
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

// FORCE DEDUCT - manually approve failed transaction that was actually delivered
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
      return res.status(400).json({ message: "Only FAILED transactions can be manually approved" });
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
      return res.status(400).json({ message: "Insufficient wallet balance to re-deduct" });
    }

    // Deduct wallet again since we refunded before
    const newBalance = Number(user.wallet_balance) - Number(tx.amount);
    await client.query("UPDATE users SET wallet_balance = $1 WHERE id = $2", [newBalance, user.id]);

    // Update transaction status
    await client.query(
      `UPDATE transactions
       SET status = 'SUCCESS',
           response_msg = $1,
           metadata = COALESCE(metadata, '{}') || $2,
           updated_at = NOW()
       WHERE reference = $3`,
      [
        `Manually approved by admin: ${reason}`,
        JSON.stringify({
          manual_approved: true,
          manual_approved_by: req.user.email,
          manual_approved_reason: reason,
          manual_approved_at: new Date().toISOString()
        }),
        reference
      ]
    );

    // Insert wallet transaction record for audit trail
    await client.query(
      `INSERT INTO wallet_transactions(company, type, amount, balance_after, reason, admin_email, reference, metadata)
       VALUES($1, 'debit', $2, $3, $4, $5, $6, $7)`,
      [
        user.company,
        tx.amount,
        newBalance,
        `Manual approval: ${reason}`,
        req.user.email,
        `MANUAL-${reference}`,
        JSON.stringify({ original_ref: reference, tx_id: tx.id })
      ]
    );

    await client.query("COMMIT");
    sendWalletUpdate(user.id, newBalance);

    res.json({ message: `Successfully approved ₦${tx.amount} for ${user.username}` });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Force deduct error:", e);
    res.status(500).json({ message: "Server error during approval: " + e.message });
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
       SET status = 'REVERSED',
           response_msg = $1,
           metadata = COALESCE(metadata, '{}') || $2,
           updated_at = NOW()
       WHERE reference = $3`,
      [
        `Manually reversed by admin: ${reason}`,
        JSON.stringify({
          reversed: true,
          reversed_by: req.user.email,
          reversed_reason: reason,
          reversed_at: new Date().toISOString()
        }),
        reference
      ]
    );

    // Insert wallet transaction record for audit trail
    await client.query(
      `INSERT INTO wallet_transactions(company, type, amount, balance_after, reason, admin_email, reference, metadata)
       VALUES($1, 'credit', $2, $3, $4, $5, $6, $7)`,
      [
        user.company,
        tx.amount,
        newBalance,
        `Reversal: ${reason}`,
        req.user.email,
        `REVERSAL-${reference}`,
        JSON.stringify({ original_ref: reference, tx_id: tx.id })
      ]
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
  const client = await pool.connect();
  try {
    const { user_id, tier } = req.body;

    if (!['default', 'top', 'regular'].includes(tier)) {
      return res.status(400).json({ message: "Invalid tier. Only 'default', 'top', or 'regular' allowed" });
    }

    const check = await client.query(
      "SELECT id FROM users WHERE id = $1 AND company = $2",
      [user_id, req.user.company]
    );
    if (!check.rows.length) {
      await client.release();
      return res.status(404).json({ message: "User not found" });
    }

    await client.query("BEGIN");

    // Remove user from all tier tables first
    await client.query("DELETE FROM top_users WHERE id = $1", [user_id]);
    await client.query("DELETE FROM regular_users WHERE user_id = $1", [user_id]);

    // Add to the selected tier table
    if (tier === 'top') {
      await client.query(
        `INSERT INTO top_users(id) VALUES($1) ON CONFLICT (id) DO NOTHING`,
        [user_id]
      );
    } else if (tier === 'regular') {
      await client.query(
        `INSERT INTO regular_users(user_id) VALUES($1) ON CONFLICT (user_id) DO NOTHING`,
        [user_id]
      );
    }

    await client.query("COMMIT");
    broadcastTopUserUpdate(req.user.company);
    res.json({ success: true, tier, message: `User tier updated to ${tier}` });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Set tier error:", err);
    res.status(500).json({ message: "Failed to update tier" });
  } finally {
    client.release();
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
      `UPDATE users SET wallet_balance=$1, updated_at=NOW()
       WHERE id=$2 AND company=$3
       RETURNING id,username,email,wallet_balance,company`,
      [numBalance, id, req.user.company]
    );
    if (!result.rows.length) return res.status(404).json({ message: "User not found" });

    // Removed: top_users table doesn't have wallet_balance column
    // If you need to sync balance there, add the column first

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
      "SELECT * FROM plans WHERE company ILIKE $1 ORDER BY network, price",
      [req.user.company]
    );
    res.json(plans.rows);
  } catch (err) {
    console.error("Get plans error:", err);
    res.status(500).json({ message: "Failed to fetch plans" });
  }
});

app.post("/admin/plans", auth, adminOnly, async (req, res) => {
  const { plan_id, network, name, price, regular_price, top_price, user_price, cost, validity, restricted, provider, network_id, api_plan_id } = req.body;

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
      `INSERT INTO plans(plan_id, company, network, name, price, regular_price, top_price, user_price, cost, validity, restricted, is_active, provider, network_id, api_plan_id)
       VALUES($1, UPPER($2), $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, $12, $13, $14) RETURNING *`,
      [
        plan_id, req.user.company, network, name,
        Number(price),
        regular_price === '' || regular_price === null || regular_price === undefined? null : Number(regular_price),
        top_price === '' || top_price === null || top_price === undefined? null : Number(top_price),
        user_price === '' || user_price === null || user_price === undefined? null : Number(user_price),
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
  const allowed = ['plan_id', 'network', 'name', 'price', 'regular_price', 'top_price', 'user_price', 'cost', 'validity', 'restricted', 'is_active', 'provider', 'network_id', 'api_plan_id'];

  const updates = {};
  for (const key of allowed) {
    const value = req.body[key];
    if (value === undefined) continue;

    if (['price', 'regular_price', 'top_price', 'user_price', 'cost', 'network_id'].includes(key)) {
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
      `UPDATE plans SET ${set} WHERE id = $${values.length - 1} AND company ILIKE $${values.length} RETURNING *`,
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
      "UPDATE plans SET is_active = FALSE WHERE id = $1 AND company ILIKE $2 RETURNING id",
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