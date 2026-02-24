const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const admin = require("firebase-admin");
require("dotenv").config();

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 30);
const USER_DAILY_QUOTA = Number(process.env.USER_DAILY_QUOTA || 100);
const MAX_PROMPT_CHARS = Number(process.env.MAX_PROMPT_CHARS || 4000);
const LOG_PROMPTS = (process.env.LOG_PROMPTS || "true").toLowerCase() === "true";
const PORT = Number(process.env.PORT || 5000);

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT environment variable.");
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (error) {
  console.error("Invalid FIREBASE_SERVICE_ACCOUNT JSON.");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(helmet());
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "200kb" }));

const generateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    return res.status(429).json({
      code: "RATE_LIMIT_HIT",
      error: "Too many requests. Please slow down.",
      retryAfterSec: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
  },
});

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

function getTodayKeyUTC() {
  return new Date().toISOString().slice(0, 10);
}

function getNextResetAtISO() {
  const now = new Date();
  const nextUtcMidnight = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0)
  );
  return nextUtcMidnight.toISOString();
}

function normalizeQuotaDoc(data) {
  const today = getTodayKeyUTC();
  const isToday = data?.lastUsageDate === today;
  const used = isToday ? Number(data?.aiUsageToday || 0) : 0;
  const total = Number(data?.dailyQuotaTotal || USER_DAILY_QUOTA);
  const remaining = Math.max(0, total - used);
  const resetAt = isToday && data?.quotaResetAt ? data.quotaResetAt : getNextResetAtISO();

  return { used, total, remaining, resetAt };
}

async function readQuota(uid) {
  const userRef = db.collection("users").doc(uid);
  const doc = await userRef.get();
  const data = doc.exists ? doc.data() : null;
  return normalizeQuotaDoc(data);
}

async function consumeQuota(uid, email) {
  const userRef = db.collection("users").doc(uid);

  return db.runTransaction(async (tx) => {
    const snap = await tx.get(userRef);
    const data = snap.exists ? snap.data() : null;

    const today = getTodayKeyUTC();
    const isToday = data?.lastUsageDate === today;
    const usedBefore = isToday ? Number(data?.aiUsageToday || 0) : 0;
    const total = Number(data?.dailyQuotaTotal || USER_DAILY_QUOTA);

    if (usedBefore >= total) {
      return {
        allowed: false,
        quota: {
          used: usedBefore,
          total,
          remaining: 0,
          resetAt: isToday && data?.quotaResetAt ? data.quotaResetAt : getNextResetAtISO(),
        },
      };
    }

    const usedAfter = usedBefore + 1;
    const quotaResetAt = getNextResetAtISO();

    tx.set(
      userRef,
      {
        email: email || null,
        aiUsageToday: usedAfter,
        lastUsageDate: today,
        dailyQuotaTotal: total,
        quotaResetAt,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    return {
      allowed: true,
      quota: {
        used: usedAfter,
        total,
        remaining: Math.max(0, total - usedAfter),
        resetAt: quotaResetAt,
      },
    };
  });
}

function validateRequestShape(req, res, next) {
  if (!req.body || !Array.isArray(req.body.contents)) {
    return res.status(400).json({
      code: "INVALID_REQUEST",
      error: "Invalid request format. 'contents' array required.",
    });
  }
  return next();
}

function abusePrevention(req, res, next) {
  const promptText = getPromptText(req.body);

  if (!promptText) {
    return res.status(400).json({ code: "EMPTY_PROMPT", error: "Prompt cannot be empty." });
  }
  if (promptText.length > MAX_PROMPT_CHARS) {
    return res.status(400).json({
      code: "PROMPT_TOO_LONG",
      error: `Prompt too long. Max ${MAX_PROMPT_CHARS} chars.`,
    });
  }
  if (/<\s*script|<\/\s*script\s*>/i.test(promptText)) {
    return res.status(400).json({ code: "UNSAFE_INPUT", error: "Unsafe input detected." });
  }
  if (/(.)\1{99,}/.test(promptText)) {
    return res.status(400).json({
      code: "ABUSIVE_PATTERN",
      error: "Abusive repeated input detected.",
    });
  }
  if (/[\x00-\x08\x0E-\x1F]/.test(promptText)) {
    return res.status(400).json({
      code: "INVALID_CONTROL_CHARS",
      error: "Invalid control characters in input.",
    });
  }

  req.promptText = promptText;
  return next();
}

async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ code: "NO_TOKEN", error: "Unauthorized. No token." });
  }

  const idToken = authHeader.split("Bearer ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    return next();
  } catch (_err) {
    return res.status(401).json({ code: "INVALID_TOKEN", error: "Invalid token." });
  }
}

async function userQuotaGuard(req, res, next) {
  try {
    const result = await consumeQuota(req.user.uid, req.user.email);
    if (!result.allowed) {
      return res.status(429).json({
        code: "DAILY_QUOTA_EXCEEDED",
        error: "Daily AI quota exceeded.",
        quota: result.quota,
      });
    }
    req.quota = result.quota;
    return next();
  } catch (error) {
    console.error("Quota guard failed:", error);
    return res.status(500).json({ code: "QUOTA_GUARD_FAILED", error: "Server error" });
  }
}

async function promptLogger(req, _res, next) {
  if (!LOG_PROMPTS) return next();

  try {
    await db.collection("ai_logs").add({
      uid: req.user.uid,
      email: req.user.email || null,
      chars: req.promptText.length,
      preview: req.promptText.slice(0, 300),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ip: req.ip,
    });
  } catch (error) {
    console.error("Log failed:", error);
  }

  return next();
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    limits: {
      RATE_LIMIT_WINDOW_MS,
      RATE_LIMIT_MAX,
      USER_DAILY_QUOTA,
      MAX_PROMPT_CHARS,
    },
  });
});

app.get("/quota", verifyFirebaseToken, async (req, res) => {
  try {
    const quota = await readQuota(req.user.uid);
    return res.json({ quota });
  } catch (error) {
    console.error("Quota read failed:", error);
    return res.status(500).json({ code: "QUOTA_READ_FAILED", error: "Server error" });
  }
});

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
        return res.status(500).json({ code: "MISSING_GEMINI_KEY", error: "API key missing" });
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
        if (response.status === 429) {
          return res.status(429).json({
            code: "UPSTREAM_GEMINI_429",
            error: data?.error?.message || "Gemini rate limit reached.",
            quota: req.quota,
          });
        }
        return res.status(response.status).json({
          code: "UPSTREAM_GEMINI_ERROR",
          error: data?.error?.message || "Gemini request failed.",
          quota: req.quota,
        });
      }

      res.setHeader("X-RateLimit-User-Remaining", String(req.quota.remaining));
      return res.json({ ...data, quota: req.quota });
    } catch (error) {
      console.error("Generate failed:", error);
      return res.status(500).json({ code: "SERVER_ERROR", error: "Server error" });
    }
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(
    `Limits => windowMs=${RATE_LIMIT_WINDOW_MS}, max=${RATE_LIMIT_MAX}, dailyQuota=${USER_DAILY_QUOTA}, maxPromptChars=${MAX_PROMPT_CHARS}`
  );
});

