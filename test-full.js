const fetch = require("node-fetch");
const BASE_URL = "http://localhost:3000";

let USER_TOKEN = "";
let ADMIN_TOKEN = ""; // Set your admin token here if you want to test admin routes
let TEST_EMAIL = `testuser_${Date.now()}@example.com`;

(async function test() {
  console.log("\n--- SIGNUP ---");
  try {
    let res = await fetch(`${BASE_URL}/api/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Test User", email: TEST_EMAIL, password: "123456" })
    });
    let data = await res.json();
    console.log("Signup response:", data);
    USER_TOKEN = data.token;

    if (!USER_TOKEN) {
      console.log("Signup failed, trying login...");
      res = await fetch(`${BASE_URL}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: TEST_EMAIL, password: "123456" })
      });
      data = await res.json();
      console.log("Login response (fallback):", data);
      USER_TOKEN = data.token;
    }
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- LOGIN ---");
  try {
    let res = await fetch(`${BASE_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: TEST_EMAIL, password: "123456" })
    });
    const data = await res.json();
    console.log("Login response:", data);
    USER_TOKEN = data.token || USER_TOKEN;
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- SET PIN ---");
  try {
    let res = await fetch(`${BASE_URL}/api/set-pin`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Bearer ${USER_TOKEN}`
      },
      body: JSON.stringify({ pin: "1234" })
    });
    const data = await res.json();
    console.log("Set PIN response:", data);
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- FORGOT PASSWORD ---");
  try {
    let res = await fetch(`${BASE_URL}/api/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: TEST_EMAIL, new_password: "new123456" })
    });
    const data = await res.json();
    console.log("Forgot password response:", data);
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- WALLET BALANCE ---");
  try {
    let res = await fetch(`${BASE_URL}/api/wallet`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${USER_TOKEN}` }
    });
    const data = await res.json();
    console.log("Wallet balance:", data);
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- WALLET PURCHASE ---");
  try {
    let res = await fetch(`${BASE_URL}/api/wallet/purchase`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${USER_TOKEN}`
      },
      body: JSON.stringify({ type: "airtime", amount: 0, pin: "1234" })
    });
    const data = await res.json();
    console.log("Purchase response:", data);
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- BIOMETRIC CHALLENGE ---");
  try {
    let res = await fetch(`${BASE_URL}/api/biometric/challenge`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${USER_TOKEN}` }
    });
    const data = await res.json();
    console.log("Biometric challenge response:", data);
  } catch (err) {
    console.error(err);
  }

  console.log("\n--- BIOMETRIC VERIFY ---");
  try {
    let res = await fetch(`${BASE_URL}/api/biometric/verify`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Bearer ${USER_TOKEN}`
      },
      body: JSON.stringify({ response: { id: "dummy-biometric" } })
    });
    const data = await res.json();
    console.log("Biometric verify response:", data);
  } catch (err) {
    console.error(err);
  }

  if (ADMIN_TOKEN) {
    console.log("\n--- ADMIN: FETCH USERS ---");
    try {
      let res = await fetch(`${BASE_URL}/api/admin/users`, {
        method: "GET",
        headers: { "Authorization": `Bearer ${ADMIN_TOKEN}` }
      });
      const data = await res.json();
      console.log("Admin users response:", data);
    } catch (err) {
      console.error(err);
    }

    console.log("\n--- ADMIN: REVERSE TRANSACTION ---");
    try {
      let res = await fetch(`${BASE_URL}/api/admin/transactions/reverse`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${ADMIN_TOKEN}`
        },
        body: JSON.stringify({ reference: "MC-xxxx" })
      });
      const data = await res.json();
      console.log("Admin reverse transaction response:", data);
    } catch (err) {
      console.error(err);
    }
  } else {
    console.log("\nAdmin token not set, skipping admin tests.");
  }

  console.log("\n✅ All tests completed!");
})();
