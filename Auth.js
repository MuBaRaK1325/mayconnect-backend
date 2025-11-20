// backend/Auth.js
import fs from "fs";
import path from "path";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const usersFilePath = path.resolve("users.json");
const SECRET_KEY = process.env.SECRET_KEY || "mayconnect_secret_key";

// ✅ Helper function: read users from file
function readUsers() {
  if (!fs.existsSync(usersFilePath)) return [];
  const data = fs.readFileSync(usersFilePath, "utf8");
  return JSON.parse(data || "[]");
}

// ✅ Helper function: save users to file
function saveUsers(users) {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
}

// 🧩 Signup function
export function signup(req, res) {
  const { email, password } = req.body;
  const users = readUsers();

  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { email, password: hashedPassword };
  users.push(newUser);
  saveUsers(users);

  res.json({ message: "Signup successful" });
}

// 🧩 Login function
export function login(req, res) {
  const { email, password } = req.body;
  const users = readUsers();

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: "Incorrect password" });
  }

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
}
