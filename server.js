const express = require("express");
const cors = require("cors");
const http = require("http");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");
const webpush = require("web-push");

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const wss = new WebSocketServer({ server });

// ADD WEB-PUSH - DECLARED ONCE
const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(
    'mailto:admin@mayconnect.com',
    VAPID_PUBLIC,
    VAPID_PRIVATE
  );
  console.log('Web-push configured');
}

console.log('ADDED WEB-PUSH: 2026-04-28');

app.use(cors());
app.use(express.json());

wss.on("connection", (ws, req) => {
  console.log('WebSocket client connected');
  ws.send('connected to server');
});

app.get('/api/ping', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.send('pong + db ok');
  } catch (err) {
    res.send('pong but db failed');
  }
});

app.get('/api/vapid-public-key', (req, res) => {
  if (!VAPID_PUBLIC) return res.status(500).send('VAPID not configured');
  res.send(VAPID_PUBLIC);
});

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});