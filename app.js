import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import crypto from "crypto";
import { MongoClient } from "mongodb";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Basic security headers and rate limit ---
app.set("trust proxy", 1);

const rateBuckets = new Map(); // ip -> { count, ts }
const warnings = new Map(); // ip -> count
const blacklist = new Map(); // ip -> banUntil
const RATE_LIMIT = { windowMs: 60 * 1000, limit: 120 };
const BAN_DURATION = 20 * 60 * 1000; // 20 minutes
app.use((req, res, next) => {
  const ip = (req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim() || "anon";
  const banUntil = blacklist.get(ip);
  const now = Date.now();

  // If previously blacklisted and expired, clear warnings
  if (banUntil && banUntil <= now) {
    blacklist.delete(ip);
    warnings.delete(ip);
  }
  if (banUntil && banUntil > now) {
    return res.status(403).json({ ok: false, message: "Blacklisted. Retry after cooldown." });
  }

  const bucket = rateBuckets.get(ip) || { count: 0, ts: now };
  if (now - bucket.ts > RATE_LIMIT.windowMs) {
    bucket.count = 0;
    bucket.ts = now;
  }
  bucket.count += 1;
  rateBuckets.set(ip, bucket);
  if (bucket.count > RATE_LIMIT.limit) {
    const warn = (warnings.get(ip) || 0) + 1;
    warnings.set(ip, warn);
    if (warn >= 3) {
      blacklist.set(ip, now + BAN_DURATION);
      warnings.delete(ip);
      return res.status(403).json({ ok: false, message: "Blacklisted for repeated abuse." });
    }
    return res.status(429).json({ ok: false, message: "Too many requests (warning " + warn + "/3)" });
  }
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline' https://*.hcaptcha.com https://hcaptcha.com",
      "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://*.hcaptcha.com https://hcaptcha.com",
      "frame-src https://*.hcaptcha.com https://hcaptcha.com",
      "connect-src 'self' https://*.hcaptcha.com https://hcaptcha.com",
    ].join("; ")
  );
  next();
});

// --- Database (MongoDB Atlas) ---
const mongoCfg = {
  uri: process.env.MONGO_URI || process.env.MONGODB_URI || "",
  dbName: process.env.MONGO_DB || "jx",
  colKeys: process.env.MONGO_COL_KEYS || "keys",
  colRequests: process.env.MONGO_COL_REQUESTS || "requests",
  colSettings: process.env.MONGO_COL_SETTINGS || "settings",
  colStats: process.env.MONGO_COL_STATS || "stats",
};

let mongoClient = null;
let cols = {};
let useDb = false;

async function initMongo() {
  if (!mongoCfg.uri) {
    console.warn("[DB] MONGO_URI not set. Running in memory-only mode.");
    return;
  }
  try {
    mongoClient = new MongoClient(mongoCfg.uri, {
      serverSelectionTimeoutMS: 8000,
      tls: true,
      retryWrites: true,
    });
    await mongoClient.connect();
    const db = mongoClient.db(mongoCfg.dbName);
    cols.keys = db.collection(mongoCfg.colKeys);
    cols.requests = db.collection(mongoCfg.colRequests);
    cols.settings = db.collection(mongoCfg.colSettings);
    cols.stats = db.collection(mongoCfg.colStats);
    useDb = true;
    console.log("[DB] Mongo connected");
  } catch (e) {
    console.warn("[DB] Mongo connect failed:", e.message);
    useDb = false;
  }
}
// start DB then bootstrap settings/stats
(async () => {
  await initMongo();
  await bootstrapFromDb();
})();

async function dbGet(colName, id) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  const doc = await col.findOne({ _id: id });
  return doc || null;
}

async function dbUpsert(colName, id, content) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  await col.updateOne({ _id: id }, { $set: { ...content, _id: id } }, { upsert: true });
  return true;
}

async function dbDelete(colName, id) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  await col.deleteOne({ _id: id });
}

// --- In-memory stores (fallback) ---
const settings = {
  prefix: process.env.KEY_PREFIX || "JX_",
  checkpoints: 3,
  expirationHours: 12,
  keyless: false,
};

const stats = {
  totalGenerated: 0,
};

const keys = new Map(); // key -> { key, hwid, tier, expiresAt, createdAt }
const requests = new Map(); // id -> { hwid, createdAt, expiresAt }
const pending2fa = new Map(); // nonce -> { code, expiresAt }
const sessions = new Map(); // token -> { user, expiresAt }
const cpSessions = new Map(); // hwid -> { hwid, checkpoint, service, start, nonce, rid }
const cpWarnings = new Map(); // ip -> { count, banUntil }

const REQUEST_TTL = 20 * 60 * 1000;
const SESSION_TTL = 60 * 60 * 1000; // 1 hour
const BASE_URL = process.env.PUBLIC_URL || process.env.BASE_URL || "https://getjx.onrender.com";
const LINKVERTISE_ANTI_BYPASS_TOKEN =
  process.env.LINKVERTISE_ANTI_BYPASS_TOKEN ||
  "cd15534581c81cc4151c9487aca4197c72727153eca4445f38a6a690f976e846";
const LINKVERTISE_API_CODE = process.env.LINKVERTISE_API_CODE || "1334688";
const LOOTLABS_API_TOKEN =
  process.env.LOOTLABS_API_TOKEN || "b5ccf172298380bff73fa279c38762498a13be475028e07043e1959e08bea71f";
const LOOTLABS_BASE_URL = process.env.LOOTLABS_BASE_URL || "https://loot-link.com/s?jHg1pj5r";
const MAX_CHECKPOINT = 3;
const EXPIRATION_HOURS = () => {
  const h = settings.expirationHours;
  if (h === "lifetime") return "lifetime";
  const n = Number(h);
  if (Number.isFinite(n) && n > 0) return n;
  return 12;
};

const BYPASS_BAN_AFTER = 3;
const BYPASS_BAN_DURATION = 30 * 60 * 1000; // 30 minutes

function getBaseUrl(req) {
  if (req) {
    const protocol = req.headers["x-forwarded-proto"] || req.protocol || "https";
    const host = req.headers["host"] || req.headers["x-forwarded-host"] || BASE_URL.replace(/^https?:\/\//, "");
    return `${protocol}://${host}`;
  }
  return BASE_URL;
}

function renderBanPage(banUntil) {
  return `
    <html><body style="font-family: Arial; text-align: center; padding: 50px;">
      <h1>You Have Been Blacklisted!</h1>
      <p>Reason: Bypassing</p>
      <p id="timer" style="font-size:2.5rem;margin-top:20px;font-weight:700;"></p>
      <script>
        const end = ${banUntil};
        function fmt(ms) {
          const total = Math.floor(ms / 1000);
          const m = Math.floor(total / 60);
          const s = total % 60;
          return m + 'm ' + s.toString().padStart(2,'0') + 's';
        }
        function tick() {
          const diff = end - Date.now();
          if (diff <= 0) { location.reload(); return; }
          document.getElementById('timer').textContent = 'Time remaining: ' + fmt(diff);
        }
        tick();
        setInterval(tick, 1000);
      </script>
    </body></html>
  `;
}

function handleBypass(req, res, hwid) {
  const ip = (req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim() || "anon";
  const now = Date.now();
  const warn = cpWarnings.get(ip) || { count: 0, banUntil: 0 };
  if (warn.banUntil && warn.banUntil <= now) {
    warn.count = 0;
    warn.banUntil = 0;
  }
  warn.count += 1;
  if (warn.count >= BYPASS_BAN_AFTER) {
    warn.banUntil = now + BYPASS_BAN_DURATION;
    blacklist.set(ip, warn.banUntil);
    warn.count = 0;
  }
  cpWarnings.set(ip, warn);
  const sess = cpSessions.get(hwid);
  const rid = sess?.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
  cpSessions.delete(hwid); // force restart
  return res.status(400).send(`
    <html><body style="font-family: Arial; text-align: center; padding: 50px;">
      <h1>Restarting checkpoints</h1>
      <p>Please complete the task normally. Redirecting...</p>
      <script>
        setTimeout(()=>{ location.href = '/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=0&reset=1${rid}'; }, 1200);
      </script>
    </body></html>
  `);
}

function buildLinkvertiseUrl(hwid, checkpoint, baseUrl) {
  const callbackUrl = `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}`;
  const randomId = Math.floor(Math.random() * 1000);
  const token = crypto.randomBytes(16).toString("hex");
  const encodedUrl = Buffer.from(callbackUrl).toString("base64");
  return `https://link-to.net/${LINKVERTISE_API_CODE}/${randomId}/dynamic/?_r=${token}&r=${encodedUrl}`;
}

async function verifyHash(hash) {
  try {
    const response = await axios.post(
      "https://publisher.linkvertise.com/api/v1/anti_bypassing",
      { token: LINKVERTISE_ANTI_BYPASS_TOKEN, hash },
      { headers: { "Content-Type": "application/json" }, timeout: 10000 }
    );
    return response.data?.status === true;
  } catch (err) {
    return false;
  }
}

async function buildLootLabsUrl(hwid, checkpoint, baseUrl, nonce) {
  try {
    const callbackUrl = `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}&checkpoint=${checkpoint}&hash=${encodeURIComponent(nonce)}`;
    const params = new URLSearchParams({
      destination_url: callbackUrl,
      api_token: LOOTLABS_API_TOKEN,
    }).toString();
    const response = await axios.get(`https://be.lootlabs.gg/api/lootlabs/url_encryptor?${params}`, { timeout: 10000 });
    const encrypted = response?.data?.message;
    if (!encrypted) throw new Error("No encrypted data returned");
    return `${LOOTLABS_BASE_URL}&data=${encrypted}`;
  } catch (err) {
    return `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}`;
  }
}

async function bootstrapFromDb() {
  if (!useDb) return;
  try {
    const cfg = await dbGet(mongoCfg.colSettings, "settings");
    if (cfg?.settings) {
      Object.assign(settings, cfg.settings);
    }
  } catch (e) {
    console.warn("[DB] settings load failed:", e.message);
  }
  try {
    const st = await dbGet(mongoCfg.colStats, "stats");
    if (st?.stats?.totalGenerated) {
      stats.totalGenerated = st.stats.totalGenerated;
    }
  } catch (e) {
    console.warn("[DB] stats load failed:", e.message);
  }
}
bootstrapFromDb();

// --- Helpers ---
async function cleanup() {
  const now = Date.now();

  // expire keys (in-memory)
  for (const [k, v] of keys.entries()) {
    if (v.expiresAt && v.expiresAt <= now) {
      keys.delete(k);
      if (useDb) dbDelete(mongoCfg.colKeys, k);
    }
  }

  // expire requests (in-memory)
  for (const [id, req] of requests.entries()) {
    if (req.expiresAt && req.expiresAt <= now) {
      requests.delete(id);
      if (useDb) dbDelete(mongoCfg.colRequests, id);
    }
  }

  // expire 2fa
  for (const [nonce, data] of pending2fa.entries()) {
    if (data.expiresAt <= now) pending2fa.delete(nonce);
  }

  // expire sessions
  for (const [token, data] of sessions.entries()) {
    if (data.expiresAt <= now) sessions.delete(token);
  }
}
setInterval(cleanup, 60 * 1000);

function randKeyString(len = 20) {
  return crypto
    .randomBytes(Math.ceil(len * 0.75))
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, len);
}

async function generateKey({ hwid, tier = "free", hours = settings.expirationHours }) {
  const key = `${settings.prefix}${randKeyString(20)}`;
  const now = Date.now();
  const effectiveHours =
    hours === "lifetime"
      ? null
      : Number.isFinite(Number(hours))
      ? Number(hours)
      : Number.isFinite(Number(settings.expirationHours))
      ? Number(settings.expirationHours)
      : 12;
  const expiresAt = effectiveHours === null ? null : now + effectiveHours * 60 * 60 * 1000;
  const bindProof = crypto.randomBytes(24).toString("hex");
  const record = { key, hwid, tier, createdAt: now, expiresAt, bindProof };
  keys.set(key, record);
  stats.totalGenerated += 1;
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
      await dbUpsert(mongoCfg.colStats, "stats", { stats });
    } catch (e) {
      console.warn("[DB] upsert key failed", e.message);
    }
  }
  return record;
}

async function fetchKeyFromDb(key) {
  if (!useDb) return null;
  try {
    const doc = await dbGet(mongoCfg.colKeys, key);
    if (doc?.key) {
      keys.set(key, doc);
      return doc;
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function queryKeys(filter = "all") {
  const isUnbound = (hwid) =>
    !hwid || hwid === "unbound" || hwid === "unbound-hwid" || (typeof hwid === "string" && hwid.trim() === "");
  if (!useDb) {
    const now = Date.now();
    return Array.from(keys.values())
      .map(formatKeySummary)
      .filter((k) => {
        if (filter !== "unused" && isUnbound(k.hwid)) return false;
        if (filter === "active") return !k.expiresAt || k.expiresAt > now;
        if (filter === "free") return k.tier === "free";
        if (filter === "premium") return k.tier === "premium";
        if (filter === "expired") return !!k.expiresAt && k.expiresAt <= now;
        if (filter === "unused") return isUnbound(k.hwid) && (!k.expiresAt || k.expiresAt > now);
        return true;
      });
  }
  const nowMs = Date.now();
  const col = cols[mongoCfg.colKeys];
  if (!col) return [];
  const query = {};
  if (filter === "active") query.$or = [{ expiresAt: null }, { expiresAt: { $gt: nowMs } }];
  if (filter === "free") query.tier = "free";
  if (filter === "premium") query.tier = "premium";
  if (filter === "expired") query.expiresAt = { $ne: null, $lte: nowMs };
  if (filter === "unused") {
    query.$and = [
      { $or: [{ hwid: "unbound" }, { hwid: "unbound-hwid" }, { hwid: "" }, { hwid: { $exists: false } }, { hwid: null }] },
      { $or: [{ expiresAt: null }, { expiresAt: { $gt: nowMs } }] },
    ];
  } else {
    query.$and = [
      { hwid: { $nin: ["unbound", "unbound-hwid", "", null] } },
    ];
  }
  const rows = await col.find(query).toArray();
  return rows.map((r) => {
    const status = r.expiresAt && r.expiresAt <= nowMs ? "expired" : "active";
    return { key: r.key || r._id, hwid: r.hwid, tier: r.tier, expiresAt: r.expiresAt, createdAt: r.createdAt, status };
  });
}

async function loadExistingKeyForHwid(hwid) {
  const now = Date.now();
  const mem = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > now));
  if (mem) return mem;
  if (!useDb) return null;
  const col = cols[mongoCfg.colKeys];
  if (!col) return null;
  const rec = await col.findOne({
    hwid,
    $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
  });
  if (rec) {
    const bindProof = rec.bindProof || crypto.randomBytes(24).toString("hex");
    const record = {
      key: rec.key || rec._id,
      hwid: rec.hwid,
      tier: rec.tier,
      expiresAt: rec.expiresAt,
      createdAt: rec.createdAt,
      bindProof,
    };
    keys.set(record.key, record);
    // persist bindProof if newly generated
    if (!rec.bindProof) {
      try {
        await dbUpsert(mongoCfg.colKeys, record.key, record);
      } catch (e) {
        console.warn("[DB] add bindProof failed", e.message);
      }
    }
    return record;
  }
  return null;
}

const DISCORD_WEBHOOK_URL =
  process.env.DISCORD_WEBHOOK_URL ||
  "https://discord.com/api/webhooks/1439462164443299932/9wXvlg_6Rmmn_nND-K8JwS2JBZSzhCSTdoqwWtAKkhIGXvmL8tNyc3Gb6gH2P4JoKEGr";

async function sendDiscord2FA(code) {
  const webhook = DISCORD_WEBHOOK_URL;
  if (!webhook) {
    console.warn("[2FA] DISCORD_WEBHOOK_URL missing. Code:", code);
    return;
  }
  try {
    await axios.post(
      webhook,
      { content: `🔐 JX Dashboard 2FA code: **${code}** (expires in 5 minutes)` },
      { timeout: 8000 }
    );
  } catch (err) {
    console.error("[2FA] Failed to post to Discord webhook:", err.message);
  }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ ok: false, message: "Unauthorized" });
  }
  const session = sessions.get(token);
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ ok: false, message: "Session expired" });
  }
  req.session = session;
  next();
}

function formatKeySummary(record) {
  return {
    key: record.key,
    hwid: record.hwid,
    tier: record.tier,
    expiresAt: record.expiresAt,
    createdAt: record.createdAt,
    status: record.expiresAt && record.expiresAt <= Date.now() ? "expired" : "active",
  };
}

// --- Views ---
app.get("/", (req, res) => {
  res.render("index", { settings });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/dashboard", (req, res) => {
  res.render("dashboard", { settings });
});

app.get("/checkpoint", (req, res) => {
  const hwid = (req.query.hwid || "").trim();
  const rid = (req.query.rid || "").trim();
  const serviceParam = (req.query.service || "").toLowerCase();
  if (!hwid) return res.redirect("/");

  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || 1);
  let sess = cpSessions.get(hwid);
  if (!sess) {
    sess = { hwid, checkpoint: 1, service: serviceParam || "linkvertise", start: 0, nonce: null, rid };
    cpSessions.set(hwid, sess);
  }
  if (rid) sess.rid = rid;
  // sync service if user explicitly picked a different one
  const validService = ["linkvertise", "lootlabs"].includes(serviceParam) ? serviceParam : null;
  if (validService && validService !== sess.service) {
    // mid-progress service change -> reset flow to selection
    const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    cpSessions.delete(hwid);
    return res.redirect(
      `/checkpoint?hwid=${encodeURIComponent(hwid)}${ridPart}&cp=0&reset=1${validService ? `&service=${encodeURIComponent(validService)}` : ""}`
    );
  }
  if (validService) {
    sess.service = validService;
  }

  const requestedCp = Number(typeof req.query.cp !== "undefined" ? req.query.cp || 0 : 0);
  // Prevent falling back to service selection after progress has started (causes false bypass/reset)
  if (requestedCp === 0 && (sess.checkpoint || 1) > 1 && req.query.reset !== "1") {
    const targetCp = sess.checkpoint || 1;
    const service = sess.service || "linkvertise";
    const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    return res.redirect(`/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${targetCp}&service=${encodeURIComponent(service)}${ridPart}`);
  }
  if (req.query.reset === "1") {
    sess = { hwid, checkpoint: 1, service: serviceParam || sess.service || "linkvertise", start: 0, nonce: null, rid: sess.rid || rid };
    cpSessions.set(hwid, sess);
  }

  // cp=0: service selection screen
  if (requestedCp === 0) {
    return res.render("checkpoint", {
      hwid,
      checkpoint: 0,
      maxCheckpoint,
      rid: sess.rid || "",
      baseUrl: getBaseUrl(req),
      service: sess.service || "linkvertise",
    });
  }

  // Enforce order
  const expected = sess.checkpoint || 1;
  if (requestedCp && requestedCp !== expected) {
    return handleBypass(req, res, hwid);
  }

  return res.render("checkpoint", {
    hwid,
    checkpoint: expected || 1,
    maxCheckpoint,
    rid: sess.rid || "",
    baseUrl: getBaseUrl(req),
    service: sess.service || "linkvertise",
  });
});

// External task redirector (Linkvertise/LootLabs)
app.get("/goto", async (req, res) => {
  const hwid = (req.query.hwid || "").trim();
  const cpParam = Number(req.query.checkpoint || 0);
  const serviceParam = (req.query.service || "").toLowerCase();
  const baseUrl = getBaseUrl(req);
  if (!hwid) return res.redirect("/");

  const sess = cpSessions.get(hwid);
  const expected = sess?.checkpoint || 1;
  const cp = cpParam || expected;
  const service = serviceParam && ["linkvertise", "lootlabs"].includes(serviceParam) ? serviceParam : sess?.service || "linkvertise";
  if (sess && service !== sess.service) {
    cpSessions.set(hwid, { ...sess, service });
  }
  if (!sess || cp !== expected) {
    return handleBypass(req, res, hwid);
  }

  let redirectUrl;
  if (service === "linkvertise") {
    redirectUrl = buildLinkvertiseUrl(hwid, expected, baseUrl);
    cpSessions.set(hwid, { ...sess, start: Date.now() });
  } else {
    const nonce = crypto.randomBytes(16).toString("hex");
    redirectUrl = await buildLootLabsUrl(hwid, expected, baseUrl, nonce);
    cpSessions.set(hwid, { ...sess, start: Date.now(), nonce });
  }
  return res.redirect(redirectUrl);
});

// Callback after external task completes
app.get("/callback", async (req, res) => {
  const hwid = (req.query.hwid || "").trim();
  const cpParam = Number(req.query.checkpoint || 0);
  const hash = (req.query.hash || "").trim();
  const serviceParam = (req.query.service || "").toLowerCase();
  if (!hwid) return res.redirect("/");

  let sess = cpSessions.get(hwid);
  if (serviceParam && ["linkvertise", "lootlabs"].includes(serviceParam) && sess) {
    sess = { ...sess, service: serviceParam };
    cpSessions.set(hwid, sess);
  }
  const service = sess?.service || "linkvertise";
  const expected = sess?.checkpoint || 1;
  const currentCheckpoint = cpParam || expected;

  if (!sess || currentCheckpoint !== expected) {
    const ridPart = sess?.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    return res.redirect(
      `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${expected}&service=${encodeURIComponent(service)}${ridPart}`
    );
  }

  if (service === "linkvertise") {
    if (!hash || !(await verifyHash(hash))) {
      const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
      return res.redirect(
        `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${expected}&service=${encodeURIComponent(service)}${ridPart}`
      );
    }
  } else {
    if (!hash || !sess.nonce || hash !== sess.nonce) {
      const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
      return res.redirect(
        `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${expected}&service=${encodeURIComponent(service)}${ridPart}`
      );
    }
  }

  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || MAX_CHECKPOINT);
  let nextCheckpoint = currentCheckpoint + 1;
  if (currentCheckpoint >= maxCheckpoint) {
    return res.redirect(`/reward?hwid=${encodeURIComponent(hwid)}${sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : ""}`);
  }
  cpSessions.set(hwid, { ...sess, checkpoint: nextCheckpoint, start: 0, nonce: null });
  return res.redirect(
    `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${nextCheckpoint}&service=${encodeURIComponent(service)}${
      sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : ""
    }`
  );
});

// Reward page: generate/show key
app.get("/reward", async (req, res) => {
  const hwid = (req.query.hwid || "").trim();
  const rid = (req.query.rid || "").trim();
  if (!hwid) return res.redirect("/");

  const sess = cpSessions.get(hwid);
  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || MAX_CHECKPOINT);

  // Allow reload if an active key already exists, otherwise enforce completion
  const now = Date.now();
  let existing = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > now));
  if (!existing && useDb) {
    existing = await loadExistingKeyForHwid(hwid);
  }
  if (!existing) {
    if (!sess || (sess.checkpoint || 0) < maxCheckpoint) {
      return handleBypass(req, res, hwid);
    }
  }

  // Remove pending request if exists
  if (rid && requests.has(rid)) {
    requests.delete(rid);
    if (useDb) dbDelete(mongoCfg.colRequests, rid);
  }

  const keyRecord = existing || (await generateKey({ hwid, tier: "free", hours: EXPIRATION_HOURS() }));
  const expiresAt = keyRecord.expiresAt || null;
  const expMs = expiresAt ? expiresAt - Date.now() : null;
  const baseUrl = getBaseUrl(req);

  // Clear session
  cpSessions.delete(hwid);

  res.send(`
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Your Key</title>
        <style>
          body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(circle at 20% 20%,rgba(76,175,80,0.25),transparent 35%),linear-gradient(135deg,#0f172a,#111827);color:#e5e7eb;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:24px;}
          .card{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:28px;max-width:520px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.35);text-align:center;}
          h1{margin:0 0 8px;font-size:26px;}
          .timer{font-size:18px;color:#a5b4fc;margin:4px 0 18px;}
          .key-box{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);padding:14px;border-radius:12px;font-size:18px;letter-spacing:0.5px;display:flex;align-items:center;justify-content:space-between;gap:12px;}
          .key-text{font-weight:700;color:#fff;word-break:break-all;}
          .copy-btn{background:#22c55e;border:none;color:#0b0f19;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer;transition:transform .15s ease,box-shadow .15s ease;}
          .copy-btn:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(34,197,94,0.35);}
          .pill{display:inline-block;padding:6px 10px;border-radius:999px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);font-weight:600;font-size:13px;color:#cbd5e1;margin-bottom:10px;}
          .cta{margin-top:18px;color:#9ca3af;font-size:14px;}
        </style>
      </head>
      <body>
        <div class="card">
          <div class="pill">Expires in ${settings.expirationHours || 12}h</div>
          <h1>Your Key is Ready</h1>
          <div class="timer" id="timer">${expMs ? "Loading timer..." : "Lifetime"}</div>
          <div class="key-box">
            <span class="key-text" id="keyText">${keyRecord.key}</span>
            <button class="copy-btn" id="copyBtn">Copy</button>
          </div>
          <div class="cta">Thank you for completing all checkpoints.</div>
        </div>
        <script>
          const expiresAt = ${expiresAt ? expiresAt : "null"};
          const timerEl = document.getElementById('timer');
          const STORAGE_KEY = '__jx_saved_key_${hwid.replace(/[^a-zA-Z0-9_-]/g,"")}';
          function tick(){
            if(!expiresAt){ timerEl.textContent = 'Lifetime'; return; }
            const diff = expiresAt - Date.now();
            if(diff <= 0){ timerEl.textContent = 'Expired'; return; }
            const sec = Math.floor(diff/1000)%60;
            const min = Math.floor(diff/60000)%60;
            const hr = Math.floor(diff/3600000);
            timerEl.textContent = 'Time left: ' + hr + 'h ' + String(min).padStart(2,'0') + 'm ' + String(sec).padStart(2,'0') + 's';
          }
          tick(); setInterval(tick, 1000);
          // Persist key silently so user can reopen later within expiry
          try{
            const payload = { key: '${keyRecord.key}', hwid: '${hwid}', expiresAt: expiresAt || null, savedAt: Date.now() };
            localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
          }catch(e){}
          document.getElementById('copyBtn').addEventListener('click', ()=>{
            const txt = document.getElementById('keyText').textContent;
            navigator.clipboard.writeText(txt).then(()=>{
              const btn = document.getElementById('copyBtn');
              btn.textContent = 'Copied!';
              setTimeout(()=>{ btn.textContent = 'Copy'; }, 1600);
            });
          });
        </script>
      </body>
    </html>
  `);
});

// HWID reset (API)
app.post("/api/jx/key/reset-hwid", async (req, res) => {
  const key = (req.body.key || "").trim();
  if (!key) return res.status(400).json({ ok: false, message: "Key required" });

  await cleanup();

  let record = keys.get(key);
  if (!record && useDb) {
    record = await fetchKeyFromDb(key);
  }
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });

  const now = Date.now();
  if (record.lastResetAt && now - record.lastResetAt < 24 * 60 * 60 * 1000) {
    const remaining = record.lastResetAt + 24 * 60 * 60 * 1000 - now;
    return res
      .status(429)
      .json({ ok: false, message: "HWID reset cooldown. Try again later.", remainingMs: remaining });
  }

  record.lastResetAt = now;
  record.hwid = "unbound";
  keys.set(key, record);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
    } catch (e) {
      return res.status(500).json({ ok: false, message: "Failed to reset HWID" });
    }
  }
  return res.json({ ok: true, message: "HWID reset. Use the key again to bind to a device." });
});

// HWID reset form (public)
app.get("/key/reset-hwid", (req, res) => {
  res.send(`
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Reset HWID</title>
        <style>
          *{box-sizing:border-box;}
          body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(circle at 20% 20%,rgba(99,102,241,0.18),transparent 30%),linear-gradient(135deg,#0f172a,#111827);color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px;}
          .card{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:28px;max-width:520px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.35);}
          h1{margin:0 0 10px;font-size:26px;}
          p{margin:0 0 18px;color:#cbd5e1;}
          .input{width:100%;padding:14px 16px;border-radius:12px;border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);color:#fff;font-size:15px;outline:none;transition:border .2s;}
          .input:focus{border-color:#a78bfa;}
          .btn{margin-top:14px;width:100%;padding:14px 16px;border:none;border-radius:12px;background:linear-gradient(135deg,#6366f1,#a855f7);color:#0b0f19;font-weight:700;font-size:15px;cursor:pointer;box-shadow:0 12px 30px rgba(99,102,241,0.35);transition:transform .15s ease,box-shadow .15s ease;}
          .btn:hover{transform:translateY(-1px);box-shadow:0 14px 36px rgba(99,102,241,0.45);}
          .status{margin-top:12px;font-size:14px;color:#e5e7eb;min-height:20px;}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Reset HWID</h1>
          <p>Enter your key to unbind it. After reset, use the key again on a new device (it will bind on first verify).</p>
          <input id="keyInput" class="input" placeholder="Your key" />
          <button id="resetBtn" class="btn">Reset HWID</button>
          <div id="status" class="status"></div>
        </div>
        <script>
          const btn = document.getElementById('resetBtn');
          const input = document.getElementById('keyInput');
          const status = document.getElementById('status');
          const CD_KEY = '__jx_reset_cooldown';
          const ONE_DAY = 24 * 60 * 60 * 1000;
          function setCooldown(){
            try{ localStorage.setItem(CD_KEY, String(Date.now())); }catch(e){}
          }
          function getRemaining(){
            try{
              const raw = localStorage.getItem(CD_KEY);
              if(!raw) return 0;
              const ts = Number(raw);
              if(!Number.isFinite(ts)) return 0;
              const diff = ONE_DAY - (Date.now() - ts);
              return diff > 0 ? diff : 0;
            }catch(e){ return 0; }
          }
          function formatMs(ms){
            const sec = Math.floor(ms/1000)%60;
            const min = Math.floor(ms/60000)%60;
            const hr = Math.floor(ms/3600000);
            return hr + 'h ' + String(min).padStart(2,'0') + 'm ' + String(sec).padStart(2,'0') + 's';
          }
          function maybeLock(){
            const remain = getRemaining();
            if(remain > 0){
              btn.disabled = true;
              status.textContent = 'Cooldown: ' + formatMs(remain);
              setTimeout(maybeLock, 1000);
              return true;
            }
            btn.disabled = false;
            return false;
          }
          maybeLock();
          btn.addEventListener('click', async ()=>{
            if(maybeLock()) return;
            const key = (input.value || '').trim();
            if(!key){ status.textContent = 'Please enter a key.'; return; }
            btn.disabled = true; status.textContent = 'Resetting...';
            try{
              const res = await fetch('/api/jx/key/reset-hwid',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ key })});
              const data = await res.json();
              if(data.ok){
                status.textContent = '✅ Key Has Been Sucessfully Reset. You can reuse the key on another device.';
                setCooldown();
              }else{
                status.textContent = '❌ ' + (data.message || 'Reset failed');
              }
            }catch(e){
              status.textContent = '❌ Network error';
            }finally{
              btn.disabled = false;
            }
          });
        </script>
      </body>
    </html>
  `);
});

// --- Public config ---
app.get("/api/jx/public/config", (req, res) => {
  res.json({
    ok: true,
    settings: {
      prefix: settings.prefix,
      checkpoints: settings.checkpoints,
      expirationHours: settings.expirationHours,
      keyless: settings.keyless,
    },
  });
});

// --- Auth ---
app.post("/api/jx/auth/pin", async (req, res) => {
  const pin = (req.body.pin || "").trim();
  const targetPin = process.env.ADMIN_PIN;
  if (!targetPin) return res.status(500).json({ ok: false, message: "Admin PIN not configured" });
  if (pin !== targetPin) return res.status(401).json({ ok: false, message: "Invalid PIN" });

  const nonce = crypto.randomBytes(16).toString("hex");
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  pending2fa.set(nonce, { code, expiresAt });
  await sendDiscord2FA(code);
  res.json({ ok: true, nonce, expiresAt });
});

app.post("/api/jx/auth/2fa", (req, res) => {
  const { nonce, code } = req.body || {};
  const entry = nonce ? pending2fa.get(nonce) : null;
  if (!entry || entry.expiresAt <= Date.now() || entry.code !== String(code || "").trim()) {
    return res.status(401).json({ ok: false, message: "Invalid or expired code" });
  }
  pending2fa.delete(nonce);
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { user: "admin", expiresAt: Date.now() + SESSION_TTL });
  res.json({ ok: true, token, expiresAt: Date.now() + SESSION_TTL });
});

// --- Dashboard metrics ---
app.get("/api/jx/dashboard/metrics", requireAuth, (req, res) => {
  cleanup();
  const now = Date.now();
  const activeKeys = Array.from(keys.values()).filter((k) => !k.expiresAt || k.expiresAt > now).length;
  res.json({
    ok: true,
    stats: {
      totalGenerated: stats.totalGenerated,
      activeKeys,
      requestCount: requests.size,
    },
  });
});

// --- Key requests / Roblox bridge ---
app.post("/api/jx/keys/request", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });

  await cleanup();

  // reuse active key for this hwid
  const existingMem = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > Date.now()));
  let existing = existingMem;
  if (!existing && useDb) existing = await loadExistingKeyForHwid(hwid);
  if (existing) {
    return res.json({
      ok: true,
      requestId: null,
      key: existing.key,
      bindProof: existing.bindProof,
      tier: existing.tier,
      expiresAt: existing.expiresAt,
      reused: true,
    });
  }

  const requestId = crypto.randomUUID();
  const expiresAt = Date.now() + REQUEST_TTL;
  const reqRecord = { hwid, createdAt: Date.now(), expiresAt };
  requests.set(requestId, reqRecord);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colRequests, requestId, reqRecord);
    } catch (e) {
      console.warn("[DB] save request failed", e.message);
    }
  }

  const checkpointUrl = `${BASE_URL || ""}/checkpoint?hwid=${encodeURIComponent(hwid)}&rid=${requestId}`;
  res.json({
    ok: true,
    requestId,
    checkpointUrl,
  });
});

// Claim key after checkpoint
app.post("/api/jx/keys/claim", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const rid = (req.body.requestId || "").trim();
  if (!hwid || !rid) return res.status(400).json({ ok: false, message: "HWID and requestId required" });
  await cleanup();
  const reqRec = requests.get(rid);
  if (!reqRec || reqRec.hwid !== hwid || (reqRec.expiresAt && reqRec.expiresAt <= Date.now())) {
    return res.status(400).json({ ok: false, message: "Request not found/expired" });
  }
  requests.delete(rid);
  if (useDb) dbDelete(mongoCfg.colRequests, rid);
  const record = await generateKey({ hwid, tier: "free", hours: settings.expirationHours });
  res.json({ ok: true, key: record.key, bindProof: record.bindProof, expiresAt: record.expiresAt, tier: record.tier });
});

// Verify key (Roblox)
app.post("/api/jx/keys/verify", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const key = (req.body.key || "").trim();
  const bindProof = (req.body.bindProof || "").trim();

  await cleanup();

  if (settings.keyless) {
    return res.json({ ok: true, valid: true, mode: "keyless" });
  }

  if (!hwid || !key) return res.status(400).json({ ok: false, valid: false, message: "HWID and key required" });
  let record = keys.get(key);
  if (!record && useDb) {
    record = await fetchKeyFromDb(key);
  }
  if (!record) {
    return res.json({ ok: false, valid: false, message: "Key not found" });
  }
  if (!record.bindProof) {
    return res.json({ ok: false, valid: false, message: "Bind proof required. Please get a fresh key.", code: "bind_proof_missing" });
  }
  if (!bindProof || bindProof !== record.bindProof) {
    return res.json({ ok: false, valid: false, message: "Bind proof mismatch. Re-acquire key.", code: "bind_proof_mismatch" });
  }
  if (!record.hwid || record.hwid === "unbound" || record.hwid === "unbound-hwid") {
    record.hwid = hwid;
    keys.set(key, record);
    if (useDb) {
      try {
        await dbUpsert(mongoCfg.colKeys, key, record);
      } catch (e) {
        console.warn("[DB] bind hwid failed", e.message);
      }
    }
  }
  if (record.hwid !== hwid) {
    return res.json({ ok: false, valid: false, message: "Key not bound to this HWID" });
  }
  if (record.expiresAt && record.expiresAt <= Date.now()) {
    return res.json({ ok: false, valid: false, message: "Key expired" });
  }
  return res.json({ ok: true, valid: true, tier: record.tier, expiresAt: record.expiresAt });
});

// Get active key for HWID
app.get("/api/jx/keys/for-hwid", async (req, res) => {
  const hwid = (req.query.hwid || "").trim();
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  await cleanup();
  let existing = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > Date.now()));
  if (!existing && useDb) existing = await loadExistingKeyForHwid(hwid);
  if (!existing) return res.status(404).json({ ok: false, message: "No active key" });
  return res.json({ ok: true, key: existing.key, expiresAt: existing.expiresAt, tier: existing.tier });
});

// --- Admin keys ---
app.get("/api/jx/keys", requireAuth, async (req, res) => {
  const filter = (req.query.filter || "all").toLowerCase();
  const list = await queryKeys(filter);
  res.json({ ok: true, keys: list });
});

app.post("/api/jx/keys/generate", requireAuth, async (req, res) => {
  const { hwid, tier = "premium", hours, mode } = req.body || {};
  const boundedHours =
    mode === "lifetime" || hours === "lifetime" ? "lifetime" : Number(hours || settings.expirationHours);
  const record = await generateKey({ hwid: hwid || "unbound", tier, hours: boundedHours });
  res.json({ ok: true, key: record.key, expiresAt: record.expiresAt, tier: record.tier, hwid: record.hwid });
});

app.patch("/api/jx/keys/:key", requireAuth, async (req, res) => {
  const key = req.params.key;
  const { extendHours, expiresAt, mode } = req.body || {};
  const record = keys.get(key);
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });

  if (mode === "lifetime" || expiresAt === "lifetime") {
    record.expiresAt = null;
  } else if (extendHours) {
    const hrs = Number(extendHours);
    record.expiresAt = (record.expiresAt || Date.now()) + hrs * 60 * 60 * 1000;
  }
  if (expiresAt && expiresAt !== "lifetime") {
    record.expiresAt = Number(expiresAt);
  }
  keys.set(key, record);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
    } catch (e) {
      console.warn("[DB] update key failed", e.message);
    }
  }
  res.json({ ok: true, key: formatKeySummary(record) });
});

app.delete("/api/jx/keys/:key", requireAuth, (req, res) => {
  const key = req.params.key;
  keys.delete(key);
  if (useDb) dbDelete(mongoCfg.colKeys, key);
  res.json({ ok: true });
});

// --- Settings ---
app.get("/api/jx/settings", requireAuth, (req, res) => {
  res.json({ ok: true, settings });
});

app.post("/api/jx/settings", requireAuth, (req, res) => {
  const { prefix, checkpoints, expirationHours, keyless } = req.body || {};
  if (prefix) settings.prefix = prefix.trim();
  if (checkpoints) settings.checkpoints = Number(checkpoints);
  if (expirationHours) settings.expirationHours = Number(expirationHours);
  if (typeof keyless !== "undefined") settings.keyless = keyless === true || keyless === "true";
  if (useDb) dbUpsert(mongoCfg.colSettings, "settings", { settings });
  res.json({ ok: true, settings });
});

// --- Requests listing ---
app.get("/api/jx/requests", requireAuth, (req, res) => {
  cleanup();
  res.json({
    ok: true,
    requests: Array.from(requests.entries()).map(([id, r]) => ({
      id,
      hwid: r.hwid,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
    })),
  });
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ JX Key System server running on ${PORT}`);
  console.log("🔗 Dashboard: /dashboard | Login: /login");
});
