/****************************************************
 UNSECURE Node.js API Example (intentionally vulnerable)
 DO NOT USE IN PRODUCTION
 For learning security code review only
****************************************************/

const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;

// ❌ Weak hard-coded secret
const SECRET = "12345";

app.use(express.json());
app.use(cookieParser());

// ❌ Insecure in-memory users (plaintext passwords)
const users = [];

/***********************************************
 * Register user (NO validation, NO hashing)
***********************************************/
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  // ❌ blindly trust user input
  users.push({ username, password });

  console.log("User registered:", req.body); // ❌ leaks data
  res.send(`User ${username} registered`);
});

/***********************************************
 * Login user (no rate limit, insecure compare)
***********************************************/
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // ❌ linear search, insecure string compare
  const user = users.find((u) => u.username == username);

  if (!user || user.password !== password) {
    return res.status(401).send("Invalid credentials");
  }

  // ❌ JWT never expires
  const token = jwt.sign(
    { user: username },
    SECRET // ❌ weak secret
  );

  // ❌ insecure cookie (no httpOnly/secure flags)
  res.cookie("auth", token);

  res.send("Logged in");
});

/***********************************************
 * UNSECURE auth middleware
***********************************************/
function authMiddleware(req, res, next) {
  const token = req.cookies.auth;

  // ❌ token not validated properly
  try {
    jwt.verify(token, SECRET);
    next();
  } catch (err) {
    res.status(401).send("Unauthorized");
  }
}

/***********************************************
 * Protected route (reflect user input → XSS risk)
***********************************************/
app.get("/dashboard", authMiddleware, (req, res) => {
  // ❌ vulnerable to stored/reflected XSS
  res.send(`
    <h1>Dashboard</h1>
    <p>Welcome user: ${req.query.name}</p> 
  `);
});

/***********************************************/
app.listen(PORT, () => {
  console.log("UNSECURE server running on port", PORT);
});
