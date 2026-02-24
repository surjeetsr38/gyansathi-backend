const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const admin = require("firebase-admin");
const helmet = require("helmet");

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
});

const app = express();
app.use(helmet());
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json({ limit: "200kb" }));

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 30);
const USER_DAILY_QUOTA = Number(process.env.USER_DAILY_QUOTA || 100);
const MAX_PROMPT_CHARS = Number(process.env.MAX_PROMPT_CHARS || 4000);
const LOG_PROMPTS = (process.env.LOG_PROMPTS || "true").toLowerCase() === "true";

const quotaStore = new Map();

const generateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again shortly." },
});

// function getRequesterId(req) {
//   const rawHeader = String(req.headers["x-user-id"] || "").trim();
//   if (/^[A-Za-z0-9_-]{6,128}$/.test(rawHeader)) {
//     return `uid:${rawHeader}`;
//   }
//   return `ip:${req.ip || "unknown"}`;
// }

function getPromptText(body) {
  if (!body || !Array.isArray(body.contents)) return "";
  const texts = [];

  body.contents.forEach((content) => {
    if (!content || !Array.isArray(content.parts)) return;
    content.parts.forEach((part) => {
      if (typeof part?.text === "string") texts.push(part.text);
    });
  });

  return texts.join("\n").trim();
}

function validateRequestShape(req, res, next) {
  if (!req.body || !Array.isArray(req.body.contents)) {
    return res.status(400).json({ error: "Invalid request format. 'contents' array required." });
  }
  next();
}

function abusePrevention(req, res, next) {
  const promptText = getPromptText(req.body);

  if (!promptText) {
    return res.status(400).json({ error: "Prompt cannot be empty." });
  }

  if (promptText.length > MAX_PROMPT_CHARS) {
    return res.status(400).json({ error: `Prompt too long. Max ${MAX_PROMPT_CHARS} chars.` });
  }

  if (/<\s*script|<\/\s*script\s*>/i.test(promptText)) {
    return res.status(400).json({ error: "Unsafe input detected." });
  }

  if (/(.)\1{99,}/.test(promptText)) {
    return res.status(400).json({ error: "Abusive repeated input detected." });
  }

  if (/[\x00-\x08\x0E-\x1F]/.test(promptText)) {
    return res.status(400).json({ error: "Invalid control characters in input." });
  }

  req.promptText = promptText;
  next();
}
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized. No token." });
  }

  const idToken = authHeader.split("Bearer ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token." });
  }
}


async function userQuotaGuard(req, res, next) {
  const uid = req.user.uid;
  const today = new Date().toISOString().slice(0, 10);

  const userRef = admin.firestore().collection("users").doc(uid);
  const doc = await userRef.get();

  let data = doc.exists ? doc.data() : {};
  let usageDate = data.lastUsageDate || today;
  let count = data.aiUsageToday || 0;

  if (usageDate !== today) {
    count = 0;
  }

  if (count >= USER_DAILY_QUOTA) {
    return res.status(429).json({ error: "Daily AI quota exceeded." });
  }

  await userRef.set({
    aiUsageToday: count + 1,
    lastUsageDate: today,
    email: req.user.email
  }, { merge: true });

  req.remainingQuota = USER_DAILY_QUOTA - (count + 1);
  next();
}

async function promptLogger(req, _res, next) {
  if (!LOG_PROMPTS) return next();

  try {
    await admin.firestore().collection("ai_logs").add({
      uid: req.user.uid,
      email: req.user.email,
      chars: req.promptText.length,
      preview: req.promptText.slice(0, 300),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ip: req.ip
    });
  } catch (err) {
    console.error("Log failed", err);
  }

  next();
}

app.post(
  "/generate",
  generateLimiter,
  verifyFirebaseToken,
  validateRequestShape,
  abusePrevention,
  userQuotaGuard,
  promptLogger,
  async (req, res) => {
  try {
    const GEMINI_KEY = process.env.GEMINI_KEY;

    if (!GEMINI_KEY) {
      return res.status(500).json({ error: "API key missing" });
    }

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req.body),
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.setHeader("X-RateLimit-User-Remaining", String(req.remainingQuota));
    res.json(data);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT;

app.listen(PORT, '0.0.0.0', () => {
  console.log("Server running on port " + PORT);
});