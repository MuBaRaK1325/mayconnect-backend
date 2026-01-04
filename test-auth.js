const fetch = require('node-fetch'); // <- import node-fetch

const BASE_URL = "https://mayconnect-backend-1.onrender.com";

async function test() {
  try {
    // Signup
    let res = await fetch(`${BASE_URL}/api/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Test User",
        email: "testuser@example.com",
        password: "123456"
      })
    });
    let data = await res.json();
    console.log("Signup:", data);

    // Login
    res = await fetch(`${BASE_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "testuser@example.com",
        password: "123456"
      })
    });
    data = await res.json();
    console.log("Login:", data);
  } catch (err) {
    console.error("Test failed:", err);
  }
}

test();
