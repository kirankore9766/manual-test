/******************************************************
 Secure Node.js API Example
 Includes: JWT auth, bcrypt, rate limit,
 input validation, helmet headers,
 HTTPS redirect middleware,
 centralized error handling
******************************************************/

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const Joi = require("joi"); // secure validation library
require("dotenv").config();

const app = express();
const PORT = 3000;
const SECRET = process.env.JWT_SECRET;

app.use(express.json());
app.use(cookieParser());
app.use(helmet()); // security headers

/***********************************************
 * HTTPS enforcement middleware (secure)
***********************************************/
app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] !== "https") {
    return res.status(400).json({ error: "HTTPS required" });
  }
  next();
});

/***********************************************
 * Rate Limiting to avoid brute force
***********************************************/
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/login", limiter);

/***********************************************
 * Input validation schema
***********************************************/
const userSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  password: Joi.string().min(8).required(),
});

/***********************************************
 * Mock in-memory users database
***********************************************/
const users = []; // Do not use in production!

/***********************************************
 * Register user securely
***********************************************/
app.post("/register", async (req, res, next) => {
  try {
    const { error } = userSchema.validate(req.body);
    if (error) return res.status(400).json({ error: "Invalid input" });

    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    users.push({
      username: req.body.username,
      password: hashedPassword,
    });

    res.status(201).json({ message: "User created securely" });
  } catch (err) {
    next(err);
  }
});

/***********************************************
 * Login user + sign JWT
***********************************************/
app.post("/login", async (req, res, next) => {
  try {
    const { error } = userSchema.validate(req.body);
    if (error) return res.status(400).json({ error: "Invalid input" });

    const user = users.find((u) => u.username === req.body.username);
    if (!user) return res.status(401).json({ error: "Unauthorized" });

    const isValid = await bcrypt.compare(req.body.password, user.password);

    if (!isValid) return res.status(401).json({ error: "Unauthorized" });

    const token = jwt.sign({ user: user.username }, SECRET, {
      expiresIn: "1h",
    });

    // Secure cookie
    res.cookie("auth", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 3600000,
    });

    res.json({ message: "Logged in" });
  } catch (err) {
    next(err);
  }
});

/***********************************************
 * JWT auth middleware
***********************************************/
function authMiddleware(req, res, next) {
  const token = req.cookies.auth;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    jwt.verify(token, SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

/***********************************************
 * Protected route
***********************************************/
app.get("/dashboard", authMiddleware, (req, res) => {
  res.json({ secret: "sensitive dashboard data" });
});

/***********************************************
 * Secure error handler
***********************************************/
app.use((err, req, res, next) => {
  console.error("Internal error:", err);
  res.status(500).json({ error: "Internal server error" });
});

/***********************************************/
app.listen(PORT, () => {
  console.log("Secure server running");
});
