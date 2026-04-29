const express = require("express");
const cors = require("cors");
const http = require("http");

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

console.log('TEST BUILD: 2026-04-28');

app.use(cors());
app.use(express.json());

app.get('/api/ping', (req, res) => {
  res.send('pong');
});

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});