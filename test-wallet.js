import fetch from "node-fetch";

const BASE_URL = "http://localhost:3000";
const TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaXNfYWRtaW4iOmZhbHNlLCJpYXQiOjE3Njc0OTI2ODIsImV4cCI6MTc2ODA5NzQ4Mn0.T25gq25N1EX8PGK7YEEedb2mdHK9tSqKVtiatRDM96M";

async function testWallet() {
  try {
    // 1️⃣ Check current balance
    let res = await fetch(`${BASE_URL}/api/wallet`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    let data = await res.json();
    console.log("💰 Current balance:", data);

    // 2️⃣ Make a purchase (airtime)
    res = await fetch(`${BASE_URL}/api/wallet/purchase`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`
      },
      body: JSON.stringify({
        type: "airtime",
        amount: 10,
        pin: "1234"
      }),
    });
    data = await res.json();
    console.log("📦 Purchase response:", data);

    // 3️⃣ Check balance again
    res = await fetch(`${BASE_URL}/api/wallet`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    data = await res.json();
    console.log("💰 Balance after purchase:", data);

  } catch (err) {
    console.error("❌ Test failed:", err);
  }
}

testWallet();
