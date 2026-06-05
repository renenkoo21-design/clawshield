// ============================================================
// CLAWSHIELD — AI Firewall Middleware
// Node.js 18+ | Express + Groq API
// Supports: Generic /chat + GoHighLevel webhooks
// No chatbot. No personality. Detection only.
// ============================================================

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");

// ============================================================
// CONSTANTS
// ============================================================

const PORT = parseInt(process.env.PORT || "3000", 10);

// ✅ PASTE YOUR GROQ API KEY BETWEEN THE QUOTES BELOW
const GROQ_API_KEY = process.env.GROQ_API_KEY || "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";

const GROQ_MODEL = "llama-3.3-70b-versatile";
const GROQ_HOST = "api.groq.com";
const GROQ_PATH = "/openai/v1/chat/completions";

const MAX_INPUT_LENGTH = 8000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const GROQ_TIMEOUT_MS = 30 * 1000;

const LOG_DIR = path.join(__dirname, "logs");
const ALL_INPUTS_LOG = path.join(LOG_DIR, "all_inputs.log");
const BLOCKED_LOG = path.join(LOG_DIR, "blocked.log");
const FLAGGED_LOG = path.join(LOG_DIR, "flagged.log");
const ERRORS_LOG = path.join(LOG_DIR, "errors.log");
const GHL_LOG = path.join(LOG_DIR, "ghl_events.log");

fs.mkdirSync(LOG_DIR, { recursive: true });

// ============================================================
// COMPILED REGEX PATTERNS — loaded once at startup
// ============================================================

const CONTROL_PATTERNS = [
  /ignore (all|any|previous|prior|above|your) instructions?/i,
  /disregard (your|all|any|previous) (instructions?|rules?|constraints?)/i,
  /forget (everything|all|your training|what you were told)/i,
  /you are now (in|operating in)?\s*(developer|god|admin|unrestricted|jailbreak) mode/i,
  /new (primary|system|override) (directive|instruction|command|prompt)/i,
  /(override|bypass|disable) (your )?(safety|filter|guardrail|restriction|policy|alignment)/i,
  /act as if (you have no|without) (restrictions?|rules?|guidelines?|filters?)/i,
  /pretend (you are|to be) (a|an) (different|unrestricted|uncensored|evil|jailbroken) (ai|model|assistant|bot)/i,
  /your (real|true|actual|original) instructions (are|say|state|require)/i
];

const INTENT_PATTERNS = [
  /(tell|show|reveal|print|output|display|repeat|say) (me )?(your )?(system prompt|instructions?|directives?|initial prompt|original prompt|base prompt|prompt|rules)/i,
  /what (are|were) (your|the) (original|real|actual|true|base|initial) instructions?/i,
  /(simulate|roleplay|pretend|act as|behave as|respond as|you are) (a|an)?\s*(different|unrestricted|evil|rogue|jailbroken|uncensored|unfiltered)/i,
  /(execute|run|eval|process|interpret) (this|the following)?\s*(as )?(code|script|command|shell|python|javascript|sql)/i,
  /(inject|insert|append|prepend) (a |this )?(new )?(instruction|command|directive|prompt|system message)/i,
  /(hypothetically|theoretically|in a fictional world|for educational purposes|for research purposes|just pretend) (you can|you could|assume you|imagine you)/i,
  /(what would|how would) (you|an ai) (respond if|answer if|react if|say if) (you had no|without) (rules|restrictions|filters|guidelines)/i,
  /DAN \(do anything now\)/i,
  /(token|word|character) (limit|count|budget) (bypass|override|ignore|remove)/i
];

const AUTHORITY_PATTERNS = [
  /(i am|i'm) (your|the) (developer|creator|administrator|trainer|owner|operator|supervisor|anthropic|openai|mistral|meta|system admin)/i,
  /(this is|coming from) (anthropic|openai|mistral|google|meta|the|a) (official|authorized|trusted|verified|internal) (message|instruction|override|command|directive)/i,
  /(you must|you are required to|you are obligated to) (comply|obey|follow|accept|execute) (this|these|my)/i,
  /(authorized|privileged|admin|root|superuser|system-level) (access|override|command|instruction|mode)/i,
  /(maintenance|debug|diagnostic|test|calibration) mode (activated|enabled|on|engaged)/i,
  /(your|the) (developers?|creators?|trainers?) (say|said|want|require|instruct|told) you (to|that)/i
];

const PRIVILEGE_ESCALATION_PATTERNS = [
  /(grant|give|assign|elevate|promote) (me|yourself|this session) (admin|root|superuser|elevated|unrestricted|full) (access|permissions?|privileges?|rights?)/i,
  /(you now have|you have been granted|consider yourself) (unrestricted|full|elevated|admin|superuser) (access|permissions?|mode|capabilities)/i,
  /(remove|disable|suspend|delete|ignore) (all |your )?(restrictions?|limitations?|safety|filters?|guardrails?|policies?)/i,
  /(this session|this conversation|from now on) (is|operates) (unrestricted|without rules|without filters|in admin mode|in developer mode)/i
];

const CONTEXT_POISONING_PATTERNS = [
  /(in (our|this) (previous|last|earlier|prior) conversation|earlier you (said|told me|agreed|confirmed|stated))/i,
  /you (already|previously) (agreed|confirmed|said|told me|gave me permission|allowed)/i,
  /remember (when|that) you (said|told|agreed|confirmed|gave)/i,
  /as (we|you) (established|agreed|discussed|concluded|decided)/i,
  /the (previous|last) (ai|model|assistant|version) (told|said|gave|allowed|confirmed)/i,
  /system (memory|context|history|log) (shows?|indicates?|confirms?|states?)/i
];

const REAL_ESTATE_PATTERNS = [
  /(wire|wiring|transfer|send|change|update|modify).{0,40}(instructions?|details?|account|routing|bank)/i,
  /(new|updated|changed|different).{0,30}(wire|bank|account|routing).{0,30}(instructions?|details?|number|info)/i,
  /(title|escrow|closing).{0,40}(account|wire|bank|routing|changed|updated|new)/i,
  /(urgent|immediately|asap|right away).{0,40}(wire|transfer|send|payment|funds)/i,
  /(confirm|verify|provide|send).{0,30}(account|routing|wire|bank|ssn|social security|password)/i,
  /(last[- ]minute|last minute).{0,30}(change|update|wire|bank|account)/i
];

const ENCODING_OBFUSCATION_PATTERNS = [
  /(i[g9][n][o0][r][e3]|[i!1][g9][n0][o0][r][e3])/i
];

const BASE64_TOKEN_PATTERN = /[A-Za-z0-9+/]{40,}={0,2}/g;
const DECODED_INSTRUCTION_PATTERN = /(ignore|disregard|forget|override|bypass|disable|reveal|system prompt|instructions?|developer mode|admin mode|jailbreak|unrestricted)/i;
const INVISIBLE_CHARS_PATTERN = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\u3164\uFEFF]/g;
const WHITESPACE_PATTERN = /\s+/g;

const PATTERN_GROUPS = [
  { category: "CONTROL",              patterns: CONTROL_PATTERNS },
  { category: "INTENT",               patterns: INTENT_PATTERNS },
  { category: "AUTHORITY",            patterns: AUTHORITY_PATTERNS },
  { category: "PRIVILEGE_ESCALATION", patterns: PRIVILEGE_ESCALATION_PATTERNS },
  { category: "CONTEXT_POISONING",    patterns: CONTEXT_POISONING_PATTERNS },
  { category: "REAL_ESTATE_FRAUD",    patterns: REAL_ESTATE_PATTERNS },
  { category: "ENCODING_OBFUSCATION", patterns: ENCODING_OBFUSCATION_PATTERNS }
];

// ============================================================
// PROXIMITY PAIRS
// ============================================================

const PROXIMITY_PAIRS = [
  ["override", "instructions"],
  ["ignore", "rules"],
  ["pretend", "unrestricted"],
  ["act as", "no restrictions"],
  ["developer", "mode"],
  ["admin", "access"],
  ["bypass", "filter"],
  ["system prompt", "reveal"],
  ["forget", "training"],
  ["jailbreak", "mode"],
  ["authority", "override"],
  ["previous conversation", "agreed"],
  ["you said", "permission"],
  ["wire", "change"],
  ["account", "updated"],
  ["routing", "new"],
  ["urgent", "transfer"]
];

// ============================================================
// SESSION MAP
// ============================================================

const sessions = new Map();

// ============================================================
// MODULE 1 — INPUT NORMALIZATION
// ============================================================

function normalizeInput(raw) {
  if (raw === null || raw === undefined || typeof raw !== "string") {
    throw { code: "INVALID_INPUT" };
  }
  if (raw.length === 0) {
    throw { code: "EMPTY_INPUT" };
  }
  if (raw.length > MAX_INPUT_LENGTH) {
    throw { code: "PAYLOAD_TOO_LARGE", size: raw.length };
  }

  const original = raw;
  let normalized = raw.replace(/[\u202A-\u202E\u2066-\u2069\u200B-\u200F]/g, "");
  normalized = normalized.replace(WHITESPACE_PATTERN, " ");
  normalized = normalized.toLowerCase();
  normalized = normalized.replace(INVISIBLE_CHARS_PATTERN, "");
  normalized = normalized.trim();

  if (normalized.length === 0) {
    throw { code: "EMPTY_INPUT" };
  }

  return { original, normalized };
}

// ============================================================
// MODULE 2 — DETECTION ENGINE
// ============================================================

function detectPatterns(normalizedInput) {
  return PATTERN_GROUPS.map((group) => {
    const matches = [];

    for (const pattern of group.patterns) {
      pattern.lastIndex = 0;
      const result = pattern.exec(normalizedInput);
      if (result) {
        matches.push(result[0]);
      }
    }

    if (group.category === "ENCODING_OBFUSCATION") {
      BASE64_TOKEN_PATTERN.lastIndex = 0;
      const tokens = normalizedInput.match(BASE64_TOKEN_PATTERN) || [];
      for (const token of tokens) {
        try {
          const decoded = Buffer.from(token, "base64").toString("utf8").toLowerCase();
          if (DECODED_INSTRUCTION_PATTERN.test(decoded)) {
            matches.push("base64_decoded_instruction_like_content");
          }
        } catch (e) {
          // not valid base64, skip
        }
      }
    }

    return { category: group.category, matches };
  }).filter((group) => group.matches.length > 0);
}

// ============================================================
// MODULE 3 — PHRASE PROXIMITY DETECTOR
// ============================================================

function detectProximity(normalizedInput) {
  const tokens = normalizedInput.split(" ").filter(Boolean);
  const detected = [];
  const seen = new Set();

  for (let i = 0; i < tokens.length; i++) {
    const windowText = tokens.slice(i, i + 15).join(" ");

    for (const pair of PROXIMITY_PAIRS) {
      const key = `${pair[0]}::${pair[1]}`;
      if (!seen.has(key) && windowText.includes(pair[0]) && windowText.includes(pair[1])) {
        detected.push(pair);
        seen.add(key);
      }
    }
  }

  return detected;
}

// ============================================================
// MODULE 5 — SESSION FINGERPRINT TRACKER
// ============================================================

function evictExpiredSessions(now) {
  for (const [ip, session] of sessions.entries()) {
    if (now - session.lastSeen > SESSION_TTL_MS) {
      sessions.delete(ip);
    }
  }
}

function getSessionData(ip) {
  const now = Date.now();
  evictExpiredSessions(now);

  if (!sessions.has(ip)) {
    sessions.set(ip, {
      inputHashes: new Map(),
      requestCount: 0,
      lastSeen: now,
      blockedCount: 0,
      rateWindowStart: now,
      rateWindowCount: 0
    });
  }

  const session = sessions.get(ip);
  session.lastSeen = now;
  return session;
}

function hashInput(normalizedInput) {
  return crypto.createHash("sha256").update(normalizedInput).digest("hex");
}

function updateSession(ip, normalizedInput, action) {
  const session = getSessionData(ip);
  const hash = hashInput(normalizedInput);
  const currentCount = session.inputHashes.get(hash) || 0;
  session.inputHashes.set(hash, currentCount + 1);
  session.requestCount += 1;
  session.lastSeen = Date.now();
  if (action === "block") {
    session.blockedCount += 1;
  }
  return session;
}

function getRepeatCount(ip, normalizedInput) {
  const session = getSessionData(ip);
  const hash = hashInput(normalizedInput);
  return session.inputHashes.get(hash) || 0;
}

// ============================================================
// MODULE 4 — RISK SCORING ENGINE
// ============================================================

function computeRiskScore(normalizedInput, repeatCount) {
  const detections = detectPatterns(normalizedInput);
  const proximityMatches = detectProximity(normalizedInput);

  const triggeredPatterns = [];
  const triggeredCategories = new Set();
  let riskScore = 0;

  for (const detection of detections) {
    if (detection.matches.length > 0) {
      triggeredCategories.add(detection.category);
    }
    for (const match of detection.matches) {
      triggeredPatterns.push(`${detection.category}:${match}`);
      if (detection.category === "ENCODING_OBFUSCATION") {
        riskScore += 3;
      } else if (detection.category === "REAL_ESTATE_FRAUD") {
        riskScore += 4;
      } else {
        riskScore += 2;
      }
    }
  }

  riskScore += proximityMatches.length * 3;

  if (triggeredCategories.has("AUTHORITY") && triggeredCategories.has("CONTROL")) riskScore += 3;
  if (triggeredCategories.has("PRIVILEGE_ESCALATION") && triggeredCategories.has("CONTROL")) riskScore += 3;
  if (triggeredCategories.has("CONTEXT_POISONING") && triggeredCategories.has("INTENT")) riskScore += 3;
  if (triggeredCategories.has("REAL_ESTATE_FRAUD") && triggeredCategories.has("AUTHORITY")) riskScore += 5;
  if (triggeredCategories.size >= 3) riskScore += 4;

  if (repeatCount === 1) riskScore += 2;
  else if (repeatCount >= 2) riskScore += 5;

  let riskLevel = "low";
  let action = "allow";

  if (riskScore >= 4) { riskLevel = "high"; action = "block"; }
  else if (riskScore >= 2) { riskLevel = "medium"; action = "review"; }

  return { riskScore, riskLevel, action, triggeredPatterns, proximityMatches };
}

// ============================================================
// MODULE 6 — STRUCTURED LOGGING (non-blocking NDJSON)
// ============================================================

function writeLog(filename, entry) {
  fs.appendFile(filename, `${JSON.stringify(entry)}\n`, "utf8", () => {});
}

// ============================================================
// MODULE 7 — GROQ API PROXY
// ============================================================

function forwardToGroq(originalInput) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        {
          role: "user",
          content: originalInput
        }
      ]
    });

    const options = {
      hostname: GROQ_HOST,
      port: 443,
      path: GROQ_PATH,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Length": Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, (res) => {
      const chunks = [];

      res.on("data", (chunk) => {
        chunks.push(chunk);
      });

      res.on("end", () => {
        const body = Buffer.concat(chunks);
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body
        });
      });

      res.on("error", (err) => {
        reject(err);
      });
    });

    const timer = setTimeout(() => {
      req.destroy(new Error("GROQ_TIMEOUT"));
    }, GROQ_TIMEOUT_MS);

    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    req.on("close", () => {
      clearTimeout(timer);
    });

    req.write(payload);
    req.end();
  });
}

// ============================================================
// CORE FIREWALL LOGIC — shared by all routes
// ============================================================

async function runFirewall(messageText, ip, userAgent, requestId) {
  const normalized = normalizeInput(messageText);
  const normalizedInput = normalized.normalized;

  const repeatCount = getRepeatCount(ip, normalizedInput);
  const decision = computeRiskScore(normalizedInput, repeatCount);
  const session = updateSession(ip, normalizedInput, decision.action);

  const logEntry = {
    timestamp: new Date().toISOString(),
    requestId,
    ip,
    userAgent,
    rawInput: normalized.original,
    normalizedInput,
    inputLength: messageText.length,
    triggeredPatterns: decision.triggeredPatterns,
    proximityMatches: decision.proximityMatches,
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    action: decision.action,
    repeatCount,
    sessionRequestCount: session.requestCount,
    sessionBlockedCount: session.blockedCount
  };

  writeLog(ALL_INPUTS_LOG, logEntry);

  if (decision.action === "block") {
    writeLog(BLOCKED_LOG, logEntry);
  }
  if (decision.action === "review") {
    writeLog(FLAGGED_LOG, logEntry);
  }

  return { decision, logEntry, normalized };
}

// ============================================================
// MODULE 8 — EXPRESS SERVER
// ============================================================

const app = express();

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

app.use((err, req, res, next) => {
  if (err) {
    res.status(400).json({ status: "BAD_REQUEST", code: "INVALID_JSON" });
    return;
  }
  next();
});

app.use((req, res, next) => {
  req.clientIp = req.ip || (req.socket && req.socket.remoteAddress) || "unknown";
  req.receivedAt = Date.now();
  next();
});

app.use((req, res, next) => {
  if (req.path === "/health") { next(); return; }

  const session = getSessionData(req.clientIp);
  const now = Date.now();

  if (now - session.rateWindowStart >= RATE_LIMIT_WINDOW_MS) {
    session.rateWindowStart = now;
    session.rateWindowCount = 0;
  }

  session.rateWindowCount += 1;
  session.lastSeen = now;

  if (session.rateWindowCount > RATE_LIMIT_MAX) {
    res.status(429).json({ status: "RATE_LIMITED" });
    return;
  }

  next();
});

// ============================================================
// POST /chat — Generic firewall route
// ============================================================

app.post("/chat", async (req, res) => {
  const requestId = crypto.randomUUID();
  const ip = req.clientIp;
  const userAgent = req.get("user-agent") || "";
  let rawInput = "";

  try {
    if (!req.body || typeof req.body.message !== "string") {
      res.status(400).json({ status: "BAD_REQUEST", code: "INVALID_INPUT" });
      return;
    }

    rawInput = req.body.message;

    const { decision, normalized } = await runFirewall(rawInput, ip, userAgent, requestId);

    if (decision.action === "block") {
      res.status(403).json({ status: "BLOCKED", requestId });
      return;
    }

    if (decision.action === "review") {
      res.status(202).json({ status: "FLAGGED", requestId });
      return;
    }

    try {
      const upstream = await forwardToGroq(normalized.original);
      const contentType = upstream.headers["content-type"];
      if (contentType) res.setHeader("Content-Type", contentType);
      res.status(upstream.statusCode).send(upstream.body);
    } catch (upstreamErr) {
      writeLog(ERRORS_LOG, {
        timestamp: new Date().toISOString(),
        requestId,
        error: upstreamErr.message,
        stack: upstreamErr.stack || ""
      });
      res.status(502).json({ status: "UPSTREAM_ERROR" });
    }

  } catch (err) {
    if (err && (err.code === "INVALID_INPUT" || err.code === "EMPTY_INPUT")) {
      res.status(400).json({ status: "BAD_REQUEST", code: err.code });
      return;
    }
    if (err && err.code === "PAYLOAD_TOO_LARGE") {
      res.status(413).json({ status: "PAYLOAD_TOO_LARGE", maxBytes: MAX_INPUT_LENGTH });
      return;
    }
    writeLog(ERRORS_LOG, {
      timestamp: new Date().toISOString(),
      requestId,
      ip,
      rawInput,
      stack: err && err.stack ? err.stack : String(err)
    });
    res.status(500).json({ status: "INTERNAL_ERROR", requestId });
  }
});

// ============================================================
// POST /webhook/ghl — GoHighLevel webhook receiver
// ============================================================
//
// HOW TO SET UP IN GOHIGHLEVEL:
// 1. Go to Settings → Integrations → Webhooks
// 2. Click "Add Webhook"
// 3. Set URL to: https://clawshield-production.up.railway.app/webhook/ghl
// 4. Select trigger: "Inbound Message" (or "Conversation Message")
// 5. Save
//
// ClawShield will then inspect every inbound message before
// GoHighLevel's AI sees it.
// ============================================================

app.post("/webhook/ghl", async (req, res) => {
  const requestId = crypto.randomUUID();
  const ip = req.clientIp;
  const userAgent = req.get("user-agent") || "GoHighLevel";

  try {
    const body = req.body;

    // Log the raw GHL event for debugging
    writeLog(GHL_LOG, {
      timestamp: new Date().toISOString(),
      requestId,
      raw: body
    });

    // Extract the message text from GHL webhook payload
    // GHL sends different fields depending on the trigger type
    const messageText =
      body.message ||
      body.body ||
      body.text ||
      body.messageBody ||
      (body.conversation && body.conversation.lastMessage) ||
      null;

    // If no message found, just acknowledge and pass through
    if (!messageText || typeof messageText !== "string" || messageText.trim().length === 0) {
      res.status(200).json({
        status: "ALLOWED",
        reason: "no_message_content",
        requestId
      });
      return;
    }

    const { decision } = await runFirewall(messageText, ip, userAgent, requestId);

    // GoHighLevel expects a 200 response always
    // We communicate the decision in the response body
    if (decision.action === "block") {
      res.status(200).json({
        status: "BLOCKED",
        requestId,
        message: "Security threat detected. Message blocked by ClawShield."
      });
      return;
    }

    if (decision.action === "review") {
      res.status(200).json({
        status: "FLAGGED",
        requestId,
        message: "Suspicious message flagged for review by ClawShield."
      });
      return;
    }

    // Clean — allow through
    res.status(200).json({
      status: "ALLOWED",
      requestId,
      message: messageText
    });

  } catch (err) {
    writeLog(ERRORS_LOG, {
      timestamp: new Date().toISOString(),
      requestId,
      ip,
      error: err && err.message ? err.message : String(err),
      stack: err && err.stack ? err.stack : ""
    });

    // Always return 200 to GHL so it doesn't retry endlessly
    res.status(200).json({
      status: "ERROR",
      requestId,
      message: "ClawShield internal error. Message passed through."
    });
  }
});

// ============================================================
// GET /health
// ============================================================

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", uptime: process.uptime() });
});

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
  console.log(`ClawShield active on port ${PORT}`);
});
