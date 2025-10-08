// server.js
// Fast App Store Connect refresh service with concurrency, keep-alive, JWT cache, retries, and once-per-day alerts.

import fs from "fs";
import path from "path";
import http from "http";
import https from "https";
import url from "url";

import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

// -------------------------------
// ENV / CONFIG
// -------------------------------
const PORT = Number(process.env.PORT || 3000);

// App Store Connect (ASC) creds
const ASC_ISSUER_ID = process.env.ASC_ISSUER_ID || "";
const ASC_KEY_ID = process.env.ASC_KEY_ID || "";
const ASC_PRIVATE_KEY_TEXT = resolvePrivateKeyText();
const ASC_BASE = "https://api.appstoreconnect.apple.com";

// Tuning knobs
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS || 15 * 60 * 1000); // 15 min
const ASC_CONCURRENCY = Number(process.env.ASC_CONCURRENCY || 8);
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);

// Storage file
const DATA_FILE = process.env.DATA_FILE || path.join(process.cwd(), "store.json");

// Email (optional)
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";
const REQUEST_EMAIL_TO = process.env.REQUEST_EMAIL_TO || "";

// -------------------------------
/** Resolve ASC private key from one of:
 *  - ASC_PRIVATE_KEY (raw text with header/footer),
 *  - ASC_PRIVATE_KEY_B64 (base64-encoded),
 *  - ASC_PRIVATE_KEY_PATH (file path)
 */
function resolvePrivateKeyText() {
  if (process.env.ASC_PRIVATE_KEY) return process.env.ASC_PRIVATE_KEY;
  if (process.env.ASC_PRIVATE_KEY_B64) {
    return Buffer.from(process.env.ASC_PRIVATE_KEY_B64, "base64").toString("utf8");
  }
  if (process.env.ASC_PRIVATE_KEY_PATH) {
    try {
      return fs.readFileSync(process.env.ASC_PRIVATE_KEY_PATH, "utf8");
    } catch (e) {
      console.warn("Could not read ASC_PRIVATE_KEY_PATH:", e.message);
    }
  }
  return "";
}

function hasAscCreds() {
  return Boolean(ASC_ISSUER_ID && ASC_KEY_ID && ASC_PRIVATE_KEY_TEXT);
}

// -------------------------------
// Minimal persistent store
// -------------------------------
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    }
  } catch (e) {
    console.warn("Failed to read store:", e.message);
  }
  return { items: [], meta: { last_refresh: null, alerts: {} } };
}
function saveData(obj) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(obj, null, 2));
  } catch (e) {
    console.warn("Failed to write store:", e.message);
  }
}

const store = loadData();

// -------------------------------
// Optional email transporter
// -------------------------------
let transporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS && REQUEST_EMAIL_TO) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  transporter.verify().then(
    () => console.log("SMTP ready."),
    (err) => console.warn("SMTP not ready:", err?.message || err)
  );
} else {
  console.warn("SMTP not configured — alert emails disabled.");
}

// -------------------------------
// Keep-alive HTTP agents + Axios
// -------------------------------
const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 64,
  maxFreeSockets: 16,
  keepAliveMsecs: 15_000,
});

const ascHttp = axios.create({
  baseURL: ASC_BASE,
  timeout: HTTP_TIMEOUT_MS,
  httpsAgent,
});

// -------------------------------
// ASC JWT (cached)
// -------------------------------
let _ascTokenCache = { token: null, expMs: 0 };
function ascToken() {
  if (!hasAscCreds()) {
    throw new Error("Missing ASC credentials. Set ASC_ISSUER_ID, ASC_KEY_ID, and a private key.");
  }
  const now = Date.now();
  if (_ascTokenCache.token && now < _ascTokenCache.expMs - 30_000) {
    return _ascTokenCache.token;
  }
  const payload = { iss: ASC_ISSUER_ID, exp: Math.floor(now / 1000) + 20 * 60, aud: "appstoreconnect-v1" };
  const header = { kid: ASC_KEY_ID, alg: "ES256", typ: "JWT" };
  const token = jwt.sign(payload, ASC_PRIVATE_KEY_TEXT, { algorithm: "ES256", header });
  _ascTokenCache = { token, expMs: now + 20 * 60 * 1000 };
  return token;
}

// Attach token per request
ascHttp.interceptors.request.use((cfg) => {
  cfg.headers = cfg.headers || {};
  cfg.headers.Authorization = `Bearer ${ascToken()}`;
  return cfg;
});

// Simple retry with backoff for 429/5xx/timeouts
async function withRetry(fn, { tries = 3, baseDelay = 500 } = {}) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status === 429 || (status >= 500 && status < 600) || err.code === "ECONNABORTED") {
        await new Promise((r) => setTimeout(r, baseDelay * Math.pow(2, i)));
        continue;
      }
      break;
    }
  }
  throw lastErr;
}

// -------------------------------
// ASC helpers (paginated)
// -------------------------------
async function ascGet(url, params = {}) {
  const { data } = await withRetry(() => ascHttp.get(url, { params }));
  return data;
}

async function listAllApps() {
  let data = await ascGet("/v1/apps", { limit: 200 });
  const apps = [...data.data];
  let next = data.links?.next;
  while (next) {
    const { data: page } = await withRetry(() => ascHttp.get(next));
    apps.push(...page.data);
    next = page.links?.next;
  }
  return apps;
}

async function listBuilds(appId) {
  let data = await ascGet(`/v1/apps/${appId}/builds`, {
    limit: 200,
    "fields[builds]": "version,uploadedDate,expirationDate,expired,processingState",
  });
  const builds = [...data.data];
  let next = data.links?.next;
  while (next) {
    const { data: page } = await withRetry(() => ascHttp.get(next));
    builds.push(...page.data);
    next = page.links?.next;
  }
  return builds;
}

// -------------------------------
// Utility helpers
// -------------------------------
function daysLeft(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const ms = d.getTime() - Date.now();
  return Math.ceil(ms / (24 * 3600 * 1000));
}

function pickLatestReady(builds) {
  // Prefer a "ready for testing" / processed build; fallback to most recent uploaded
  const arr = Array.isArray(builds) ? builds : [];
  const sorted = [...arr].sort((a, b) => {
    const ad = new Date(a?.attributes?.uploadedDate || 0).getTime();
    const bd = new Date(b?.attributes?.uploadedDate || 0).getTime();
    return bd - ad;
  });
  // If processingState exists, prefer the earliest READY among newest
  const ready = sorted.find((b) => (b?.attributes?.processingState || "").toLowerCase() === "processed");
  return ready || sorted[0] || null;
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let idx = 0;
  const workers = Array(Math.min(concurrency, items.length))
    .fill(0)
    .map(async () => {
      while (true) {
        const i = idx++;
        if (i >= items.length) break;
        results[i] = await worker(items[i], i);
      }
    });
  await Promise.all(workers);
  return results;
}

// -------------------------------
// Refresh Pipeline
// -------------------------------
async function refreshData() {
  if (!hasAscCreds()) {
    console.warn("ASC creds missing — skipping refresh.");
    return;
  }

  console.time("refreshData");
  const apps = await listAllApps();

  const prevMap = new Map((store.items || []).map((i) => [i.bundle_id, i]));
  store.meta = store.meta || {};
  store.meta.alerts = store.meta.alerts || {};
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  const rows = await mapWithConcurrency(apps, ASC_CONCURRENCY, async (appd) => {
    const appId = appd.id;
    const name = appd.attributes?.name;
    const bid = appd.attributes?.bundleId;

    const builds = await listBuilds(appId);
    if (!builds.length) return null;

    const b = pickLatestReady(builds);
    if (!b) return null;

    const a = b.attributes || {};
    const exp = a.expirationDate || null;
    const left = daysLeft(exp);
    const isExpired = !!a.expired;
    const status = a.processingState || null;
    const uploaded = a.uploadedDate || null;
    const version = a.version || null;

    // Preserve manual stash; auto-unstash if now live/non-expiring
    let stashed = prevMap.get(bid)?.stashed ? 1 : 0;
    if (stashed && !isExpired) {
      stashed = 0;
      console.log(`Auto-unstashed: ${name} (${bid})`);
    }

    const bucket = stashed
      ? "Stashed / Unused"
      : isExpired
      ? "Expired"
      : left !== null && left <= 14
      ? "Expiring ≤14 days"
      : "Live";

    // Once-per-day expiry alert (if SMTP configured)
    if (transporter && left !== null && left <= 10 && !isExpired) {
      const alertKey = `${bid}_${version}`;
      const lastSent = store.meta.alerts[alertKey]?.lastSent || null;
      if (lastSent !== today) {
        try {
          const subject = `⚠️ TestFlight build expiring in ${left} days: ${name}`;
          const body =
            `App: ${name}\nBundle: ${bid}\nVersion: ${version}\n` +
            `Expires: ${exp}\nDays left: ${left}\nStatus: ${status || "n/a"}`;
          await transporter.sendMail({
            from: SMTP_USER,
            to: REQUEST_EMAIL_TO,
            subject,
            text: body,
          });
          store.meta.alerts[alertKey] = { lastSent: today };
          saveData(store);
        } catch (err) {
          console.warn(`Alert mail failed for ${name}:`, err.message);
        }
      }
    }

    return {
      bundle_id: bid,
      app_name: name,
      version,
      uploaded,
      expires: exp,
      days_left: left,
      asc_status: status,
      expired: isExpired ? 1 : 0,
      bucket,
      stashed,
      updated_at: new Date().toISOString(),
    };
  });

  const out = rows.filter(Boolean);

  // Stable sort: Expired → Expiring → Live → Stashed
  const orderRank = (x) =>
    x.bucket === "Expired" ? 0 : x.bucket.startsWith("Expiring") ? 1 : x.bucket === "Live" ? 2 : 3;
  store.items = out.sort((a, b) => {
    const ra = orderRank(a),
      rb = orderRank(b);
    if (ra !== rb) return ra - rb;
    if ((a.days_left ?? 999) !== (b.days_left ?? 999)) return (a.days_left ?? 999) - (b.days_left ?? 999);
    return (a.app_name || "").localeCompare(b.app_name || "");
  });

  store.meta.last_refresh = new Date().toISOString();
  saveData(store);
  console.timeEnd("refreshData");
}

// -------------------------------
// Express app
// -------------------------------
const app = express();
app.set("etag", "strong");
// Optional gzip (doesn't crash if not installed)
try {
  const { default: compression } = await import("compression");
  app.use(compression());
  console.log("Using gzip compression.");
} catch {
  console.warn("compression not installed — skipping gzip (npm i compression)");
}

app.use(express.json());

// Health
app.get("/health", (_req, res) => res.json({ ok: true, last_refresh: store.meta?.last_refresh || null }));

// Current app/build view
app.get("/api/apps", (_req, res) => {
  res.json({
    items: store.items || [],
    meta: store.meta || {},
  });
});

// Manual refresh trigger
app.post("/api/refresh", async (_req, res) => {
  try {
    await refreshData();
    res.json({ ok: true, last_refresh: store.meta?.last_refresh || null, count: store.items?.length || 0 });
  } catch (e) {
    console.error("Manual refresh failed:", e?.message || e);
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Toggle stash (optional helper)
app.post("/api/stash/:bundleId", (req, res) => {
  const bid = req.params.bundleId;
  const item = (store.items || []).find((x) => x.bundle_id === bid);
  if (!item) return res.status(404).json({ ok: false, error: "Bundle not found" });
  item.stashed = item.stashed ? 0 : 1;
  item.bucket = item.stashed ? "Stashed / Unused" : "Live";
  item.updated_at = new Date().toISOString();
  saveData(store);
  res.json({ ok: true, item });
});

// -------------------------------
// Boot
// -------------------------------
app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
  // Kick off an initial refresh shortly after boot
  setTimeout(() => {
    refreshData().catch((e) => console.warn("Initial refresh failed:", e?.message || e));
  }, 1000);
  // Schedule periodic refresh
  setInterval(() => {
    refreshData().catch((e) => console.warn("Scheduled refresh failed:", e?.message || e));
  }, REFRESH_INTERVAL_MS);
});
