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

    const companyKey = String(company).toLowerCase().trim();

    const tokens = {
      mayconnect: process.env.MAITAMA_TOKEN_MAYCONNECT,
      teeversh: process.env.MAITAMA_TOKEN_TEEVERSH,
      bnhabeeb: process.env.MAITAMA_TOKEN_BNHABEEB,
      sadeeq: process.env.MAITAMA_TOKEN_SADEEQ,
      msdatasub: process.env.MAITAMA_TOKEN_MSDATASUB
    };

    const maitamaToken = tokens[companyKey];

    if (!maitamaToken) {
      return res.status(400).json({
        success: false,
        message: `No Maitama token configured for company: ${companyKey}`
      });
    }

    const baseUrl =
      process.env.MAITAMA_BASE_URL ||
      "https://app.maitamadatahub.com";

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
          message: "Invalid Maitama network ID"
        });
      }

      if (!Number.isFinite(amountNum) || amountNum < 50 || amountNum > 5000) {
        return res.status(400).json({
          success: false,
          message: "Invalid airtime amount"
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

      payload = {
        network: Number(network),
        mobile_number: formattedPhone,
        plan: plan_id
      };

      endpoint = `${baseUrl}/api/data`;
    }

    else {
      return res.status(400).json({
        success: false,
        message: "Invalid type. Use airtime or data"
      });
    }

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
      timeout: 180000
    });

    console.log("MAITAMA RELAY RESPONSE:", response.data);

    return res.status(response.status).json({
      success: true,
      status: response.status,
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