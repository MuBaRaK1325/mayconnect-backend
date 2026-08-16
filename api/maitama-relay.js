const axios = require("axios");

module.exports = async (req, res) => {
// Allow only POST
if (req.method !== "POST") {
return res.status(405).json({
success: false,
message: "Method not allowed"
});
}

try {
// ================= RELAY SECRET =================
const relaySecret = process.env.MAITAMA_RELAY_SECRET;

if (!relaySecret) {
  return res.status(500).json({
    success: false,
    message: "MAITAMA_RELAY_SECRET is not configured"
  });
}

// Protect the relay
if (req.headers["x-relay-secret"] !== relaySecret) {
  return res.status(401).json({
    success: false,
    message: "Unauthorized"
  });
}

// ================= REQUEST BODY =================
const {
  company,
  type,
  phone,
  network,
  amount,
  plan_id,
  reference
} = req.body || {};

if (!company || !type) {
  return res.status(400).json({
    success: false,
    message: "company and type are required"
  });
}

// ================= COMPANY VALIDATION =================
const companyKey = String(company).toLowerCase().trim();

const allowedCompanies = [
  "mayconnect",
  "teeversh",
  "bnhabeeb",
  "sadeeq",
  "msdatasub"
];

if (!allowedCompanies.includes(companyKey)) {
  return res.status(400).json({
    success: false,
    message: "Invalid company",
    allowed_companies: allowedCompanies
  });
}

// ================= MAITAMA CONFIG =================
const baseUrl =
  process.env.MAITAMA_BASE_URL ||
  "https://app.maitamadatahub.com";

// ================= CONNECTION TEST =================
// Does NOT require a Maitama API token.
if (type === "test") {
  const testUrl = `${baseUrl}/`;

  console.log("MAITAMA CONNECTION TEST:", {
    company: companyKey,
    endpoint: testUrl
  });

  const testResponse = await axios.get(testUrl, {
    headers: {
      Accept: "application/json",
      "User-Agent": "MAYCONNECT-RELAY/1.0"
    },
    timeout: 30000,
    validateStatus: () => true
  });

  return res.status(200).json({
    success: true,
    stage: "VERCEL_TO_MAITAMA",
    company: companyKey,
    maitama_status: testResponse.status,
    message: "Vercel successfully reached Maitama"
  });
}

// ================= COMPANY TOKENS =================
const tokens = {
  mayconnect: process.env.MAITAMA_TOKEN_MAYCONNECT,
  teeversh: process.env.MAITAMA_TOKEN_TEEVERSH,
  bnhabeeb: process.env.MAITAMA_TOKEN_BNHABEEB,
  sadeeq: process.env.MAITAMA_TOKEN_SADEEQ,
  msdatasub: process.env.MAITAMA_TOKEN_MSDATASUB
};

const maitamaToken = tokens[companyKey];

if (!maitamaToken) {
  return res.status(500).json({
    success: false,
    message: `Maitama token is not configured for company: ${companyKey}`
  });
}

let endpoint;
let payload;

// ================= AIRTIME =================
if (type === "airtime") {
  if (!phone || !network || !amount) {
    return res.status(400).json({
      success: false,
      message: "phone, network and amount are required for airtime"
    });
  }

  let formattedPhone = String(phone).replace(/\D/g, "");

  if (formattedPhone.startsWith("234")) {
    formattedPhone = "0" + formattedPhone.slice(3);
  }

  if (formattedPhone.length === 10) {
    formattedPhone = "0" + formattedPhone;
  }

  if (!/^0\d{10}$/.test(formattedPhone)) {
    return res.status(400).json({
      success: false,
      message: "Invalid Nigerian phone number"
    });
  }

  const networkId = Number(network);
  const amountNum = Number(amount);

  if (![1, 2, 3, 4].includes(networkId)) {
    return res.status(400).json({
      success: false,
      message: "Invalid Maitama network ID. Must be 1, 2, 3 or 4."
    });
  }

  if (
    !Number.isFinite(amountNum) ||
    amountNum < 50 ||
    amountNum > 5000
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid airtime amount. Must be between ₦50 and ₦5,000."
    });
  }

  payload = {
    network: networkId,
    amount: amountNum,
    mobile_number: formattedPhone
  };

  endpoint = reference
    ? `${baseUrl}/api/topup/${encodeURIComponent(reference)}`
    : `${baseUrl}/api/topup`;
}

// ================= DATA =================
else if (type === "data") {
  if (!phone || !network || !plan_id) {
    return res.status(400).json({
      success: false,
      message: "phone, network and plan_id are required for data"
    });
  }

  let formattedPhone = String(phone).replace(/\D/g, "");

  if (formattedPhone.startsWith("234")) {
    formattedPhone = "0" + formattedPhone.slice(3);
  }

  if (formattedPhone.length === 10) {
    formattedPhone = "0" + formattedPhone;
  }

  if (!/^0\d{10}$/.test(formattedPhone)) {
    return res.status(400).json({
      success: false,
      message: "Invalid Nigerian phone number"
    });
  }

  const networkId = Number(network);

  if (!Number.isInteger(networkId) || networkId < 1 || networkId > 4) {
    return res.status(400).json({
      success: false,
      message: "Invalid Maitama network ID"
    });
  }

  payload = {
    network: networkId,
    mobile_number: formattedPhone,
    plan: plan_id
  };

  endpoint = `${baseUrl}/api/data`;
}

// ================= INVALID TYPE =================
else {
  return res.status(400).json({
    success: false,
    message: "Invalid type. Use airtime, data or test"
  });
}

// ================= MAITAMA REQUEST =================
console.log("MAITAMA RELAY REQUEST:", {
  type,
  company: companyKey,
  endpoint,
  payload
});

const response = await axios.post(endpoint, payload, {
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
    Authorization: `Bearer ${maitamaToken}`,
    "User-Agent": "MAYCONNECT-RELAY/1.0"
  },
  timeout: 180000,
  validateStatus: () => true
});

console.log("MAITAMA RELAY RESPONSE:", {
  status: response.status,
  data: response.data
});

return res.status(response.status).json({
  success: response.status >= 200 && response.status < 300,
  status: response.status,
  company: companyKey,
  data: response.data
});

} catch (error) {
console.error("MAITAMA RELAY ERROR:", {
code: error.code,
message: error.message,
status: error.response?.status,
response: error.response?.data
});

return res.status(502).json({
  success: false,
  code: error.code || null,
  message:
    error.response?.data?.message ||
    error.response?.data?.api_response ||
    error.message ||
    "Maitama connection failed",
  maitama_status: error.response?.status || null,
  maitama_response: error.response?.data || null
});

}
};