const express = require("express");
const cors = require("cors");
const http = require("http");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ADD WEBSOCKET - DECLARED ONCE
const wss = new WebSocketServer({ server });

console.log('ADDED WEBSOCKET: 2026-04-28');

app.use(cors());
app.use(express.json());

wss.on("connection", (ws, req) => {
  console.log('WebSocket client connected');
  ws.send('connected to server');
  ws.on('close', () => console.log('Client disconnected'));
});

app.get('/api/ping', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.send('pong + db ok');
  } catch (err) {
    res.send('pong but db failed');
  }
});

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});