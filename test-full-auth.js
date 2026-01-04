require('dotenv').config();
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const BASE_URL = `http://localhost:${process.env.PORT || 3000}`;

function randomEmail() {
  return `user${Math.floor(Math.random() * 100000)}@example.com`;
}

async function test() {
  try {
    const email = randomEmail();
    const password = '123456';

    console.log('--- SIGNUP ---');
    let res = await fetch(`${BASE_URL}/api/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test User', email, password })
    });
    let data = await res.json();
    console.log('Signup response:', data);

    const token = data.token;
    if (!token) throw new Error('Signup failed: no token returned');

    console.log('\n--- LOGIN ---');
    res = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    data = await res.json();
    console.log('Login response:', data);

    const loginToken = data.token;
    if (!loginToken) throw new Error('Login failed: no token returned');

    console.log('\n--- SET PIN ---');
    res = await fetch(`${BASE_URL}/api/set-pin`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${loginToken}`
      },
      body: JSON.stringify({ pin: '1234' })
    });
    data = await res.json();
    console.log('Set PIN response:', data);

    console.log('\n--- CHECK WALLET ---');
    res = await fetch(`${BASE_URL}/api/wallet`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${loginToken}` }
    });
    data = await res.json();
    console.log('Wallet response:', data);

    console.log('\n✅ All routes tested successfully!');
  } catch (err) {
    console.error('❌ Test failed:', err);
  }
}

test();
