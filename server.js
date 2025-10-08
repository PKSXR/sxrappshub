// server.js (ESM) — Optimized for faster TestFlight detection
import fs from "fs";
import path from "path";
import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { fileURLToPath } from "url";
import "dotenv/config";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ---------------------------
   ENV / CONFIG
--------------------------- */
const PORT = process.env.PORT || 8080;

// ⚡ OPTIMIZED: Much faster refresh intervals
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS || 5 * 60 * 1000); // 5 min default
const QUICK_CHECK_INTERVAL_MS = Number(process.env.QUICK_CHECK_INTERVAL_MS || 2 * 60 * 1000); // 2 min for changed apps
const MAX_PARALLEL_REQUESTS = Number(process.env.MAX_PARALLEL_REQUESTS || 5); // parallel API calls

const ONLY_LATEST_PER_APP = true;

const ASC_BASE = "https://api.appstoreconnect.apple.com";
const ASC_ISSUER_ID = process.env.ASC_ISSUER_ID || "";
const ASC_KEY_ID    = process.env.ASC_KEY_ID || "";

// Private key: accept raw text, base64, or a file path
const ASC_PRIVATE_KEY_BASE64 = process.env.ASC_PRIVATE_KEY_BASE64 || "";
const PRIVATE_KEY_P8_PATH    = process.env.ASC_PRIVATE_KEY_P8_PATH || "keys/AuthKey_ABC123XYZ.p8";
let   PRIVATE_KEY_TEXT       = process.env.ASC_PRIVATE_KEY_P8 || "";

if (!PRIVATE_KEY_TEXT && ASC_PRIVATE_KEY_BASE64) {
  try { PRIVATE_KEY_TEXT = Buffer.from(ASC_PRIVATE_KEY_BASE64, "base64").toString("utf8"); } catch {}
}
if (!PRIVATE_KEY_TEXT && PRIVATE_KEY_P8_PATH) {
  try { PRIVATE_KEY_TEXT = fs.readFileSync(path.join(__dirname, PRIVATE_KEY_P8_PATH), "utf-8"); } catch {}
}

// Email (SMTP)
const REQUEST_EMAIL_TO = process.env.REQUEST_EMAIL_TO || "dev@satorixr.com";
const SMTP_HOST   = process.env.SMTP_HOST || "";
const SMTP_PORT   = Number(process.env.SMTP_PORT || 587);
const SMTP_USER   = process.env.SMTP_USER || "";
const SMTP_PASS   = process.env.SMTP_PASS || "";
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false") === "true";

const transporter = (SMTP_HOST && REQUEST_EMAIL_TO)
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
      tls: { ciphers: "TLSv1.2" }
    })
  : null;

// Data file
const DATA_DIR  = process.env.DATA_DIR || (process.env.WEBSITE_INSTANCE_ID ? "/home/data" : __dirname);
try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const DATA_PATH = path.join(DATA_DIR, "data.json");

function loadData() {
  if (!fs.existsSync(DATA_PATH)) return { meta: { alerts: {}, requests: [], watchlist: {} }, items: [] };
  try {
    const j = JSON.parse(fs.readFileSync(DATA_PATH, "utf-8"));
    j.meta = j.meta || {};
    j.meta.alerts = j.meta.alerts || {};
    j.meta.requests = j.meta.requests || [];
    j.meta.watchlist = j.meta.watchlist || {}; // track recently updated apps
    j.items = j.items || [];
    return j;
  } catch {
    return { meta: { alerts: {}, requests: [], watchlist: {} }, items: [] };
  }
}
function saveData(data) {
  try { fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2)); } catch {}
}
let store = loadData();

// ⚡ Request queue and cache
const requestCache = new Map(); // cache recent requests
const CACHE_TTL = 30 * 1000; // 30 seconds
let isRefreshing = false;
let lastFullRefresh = 0;

/* ---------------------------
   EXPRESS BOOTSTRAP
--------------------------- */
const app = express();
app.use(express.json());
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

app.use("/public", express.static(path.join(__dirname, "public"), { maxAge: "7d" }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/healthz", (_req, res) => res.send("ok"));
app.get("/favicon.ico", (_req, res) => res.status(204).end());

/* ---------------------------
   ASC HELPERS (with caching)
--------------------------- */
function hasAscCreds() {
  return Boolean(ASC_ISSUER_ID && ASC_KEY_ID && PRIVATE_KEY_TEXT);
}

function ascToken() {
  if (!hasAscCreds()) throw new Error("Set ASC_ISSUER_ID, ASC_KEY_ID and a private key.");
  const payload = { iss: ASC_ISSUER_ID, exp: Math.floor(Date.now()/1000) + 20*60, aud: "appstoreconnect-v1" };
  const header  = { kid: ASC_KEY_ID, alg: "ES256", typ: "JWT" };
  return jwt.sign(payload, PRIVATE_KEY_TEXT, { algorithm: "ES256", header });
}

async function ascGet(url, params = {}, useCache = true) {
  const cacheKey = `${url}?${JSON.stringify(params)}`;
  
  if (useCache && requestCache.has(cacheKey)) {
    const cached = requestCache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
  }

  const token = ascToken();
  const r = await axios.get(ASC_BASE + url, { 
    headers: { Authorization: `Bearer ${token}` }, 
    params, 
    timeout: 30000 
  });
  
  requestCache.set(cacheKey, { data: r.data, timestamp: Date.now() });
  return r.data;
}

function daysLeft(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  const today = new Date();
  const utc0 = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  const utcD = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  return Math.round((utcD - utc0) / 86400000);
}

async function listAllApps() {
  let data = await ascGet("/v1/apps", { limit: 200 });
  const apps = [...data.data];
  let next = data.links?.next;
  while (next) {
    const r = await axios.get(next, { headers: { Authorization: `Bearer ${ascToken()}` } });
    data = r.data;
    apps.push(...data.data);
    next = data.links?.next;
  }
  return apps;
}

async function listBuilds(appId, useCache = true) {
  let data = await ascGet(`/v1/apps/${appId}/builds`, {
    limit: 200,
    "fields[builds]": "version,uploadedDate,expirationDate,expired,processingState"
  }, useCache);
  const builds = [...data.data];
  let next = data.links?.next;
  while (next) {
    const r = await axios.get(next, { headers: { Authorization: `Bearer ${ascToken()}` } });
    data = r.data;
    builds.push(...data.data);
    next = data.links?.next;
  }
  return builds;
}

function pickLatestReady(builds) {
  const ready = builds.filter(b => b.attributes?.processingState === "VALID");
  const pool = (ONLY_LATEST_PER_APP && ready.length) ? ready : builds;
  if (!pool.length) return null;
  return pool.sort((a, b) => (b.attributes?.uploadedDate || "").localeCompare(a.attributes?.uploadedDate || ""))[0];
}

/* ---------------------------
   ⚡ PARALLEL PROCESSING
--------------------------- */
async function processAppsInParallel(apps, maxParallel = MAX_PARALLEL_REQUESTS) {
  const results = [];
  const queue = [...apps];
  
  async function worker() {
    while (queue.length > 0) {
      const app = queue.shift();
      if (!app) continue;
      
      try {
        const result = await processApp(app);
        if (result) results.push(result);
      } catch (err) {
        console.error(`Error processing ${app.attributes?.bundleId}:`, err.message);
      }
    }
  }
  
  const workers = Array(Math.min(maxParallel, apps.length))
    .fill(null)
    .map(() => worker());
  
  await Promise.all(workers);
  return results;
}

async function processApp(appd, forceRefresh = false) {
  const appId = appd.id;
  const name  = appd.attributes?.name;
  const bid   = appd.attributes?.bundleId;

  const builds = await listBuilds(appId, !forceRefresh);
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

  // Check if this is a new version
  const prevItem = (store.items || []).find(i => i.bundle_id === bid);
  const isNewVersion = prevItem && prevItem.version !== version;
  
  // Preserve "stashed", but auto-unstash if it goes live/expiring
  let stashed = prevItem?.stashed ? 1 : 0;
  if (stashed && !isExpired) {
    stashed = 0;
    console.log(`🔓 Auto-unstashed: ${name} (${bid}) now Live/Expiring`);
  }

  const bucket = stashed
    ? "Stashed / Unused"
    : (isExpired ? "Expired" : (left !== null && left <= 14 ? "Expiring ≤14 days" : "Live"));

  // ⚡ Add to watchlist if version changed
  if (isNewVersion) {
    store.meta.watchlist = store.meta.watchlist || {};
    store.meta.watchlist[bid] = {
      lastCheck: Date.now(),
      version,
      checkCount: 0
    };
    console.log(`🆕 New version detected: ${name} ${version}`);
  }

  // Email alert logic
  const today = new Date().toISOString().slice(0, 10);
  if (transporter && left !== null && left <= 10 && !isExpired) {
    const alertKey = `${bid}_${version}`;
    const lastSent = store.meta.alerts[alertKey]?.lastSent || null;

    if (lastSent !== today) {
      try {
        const subject = `⚠️ TestFlight build expiring in ${left} days: ${name}`;
        const body = `App: ${name}\nBundle: ${bid}\nVersion: ${version}\nExpires: ${exp}\nDays left: ${left}`;
        await transporter.sendMail({
          from: SMTP_USER,
          to: REQUEST_EMAIL_TO,
          subject,
          text: body
        });
        console.log(`📧 Alert email sent for ${name}`);
        store.meta.alerts[alertKey] = { lastSent: today };
      } catch (err) {
        console.warn(`Alert mail failed for ${name}:`, err.message);
      }
    }
  }

  return {
    bundle_id: bid,
    app_name: name,
    version, uploaded, expires: exp,
    days_left: left, asc_status: status,
    expired: isExpired ? 1 : 0,
    bucket, stashed,
    updated_at: new Date().toISOString()
  };
}

/* ---------------------------
   ⚡ SMART REFRESH STRATEGIES
--------------------------- */

// Full refresh - all apps
async function refreshData(forceRefresh = false) {
  if (!hasAscCreds()) {
    console.warn("ASC creds missing — skipping refresh.");
    return;
  }

  if (isRefreshing && !forceRefresh) {
    console.log("⏭️  Refresh already in progress, skipping...");
    return;
  }

  isRefreshing = true;
  const startTime = Date.now();

  try {
    console.log(`🔄 Starting ${forceRefresh ? 'forced' : 'scheduled'} refresh...`);
    
    const apps = await listAllApps();
    console.log(`📱 Found ${apps.length} apps`);
    
    // Process apps in parallel
    const out = await processAppsInParallel(apps);

    // Sort: Expired → Expiring → Live → Stashed
    const orderRank = (x) =>
      x.bucket === "Expired" ? 0 :
      x.bucket.startsWith("Expiring") ? 1 :
      x.bucket === "Live" ? 2 : 3;

    store.items = out.sort((a, b) => {
      const ra = orderRank(a), rb = orderRank(b);
      if (ra !== rb) return ra - rb;
      if ((a.days_left ?? 999) !== (b.days_left ?? 999)) return (a.days_left ?? 999) - (b.days_left ?? 999);
      return (a.app_name || "").localeCompare(b.app_name || "");
    });

    store.meta.last_refresh = new Date().toISOString();
    lastFullRefresh = Date.now();
    saveData(store);

    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✅ Refresh completed in ${duration}s (${out.length} builds processed)`);
  } catch (err) {
    console.error("❌ Refresh failed:", err.message);
  } finally {
    isRefreshing = false;
  }
}

// Quick check - only recently updated apps
async function quickCheckWatchlist() {
  if (!hasAscCreds() || isRefreshing) return;

  const watchlist = store.meta.watchlist || {};
  const bundleIds = Object.keys(watchlist);
  
  if (bundleIds.length === 0) return;

  console.log(`⚡ Quick check for ${bundleIds.length} watched apps...`);

  try {
    const apps = await listAllApps();
    const watchedApps = apps.filter(a => 
      bundleIds.includes(a.attributes?.bundleId)
    );

    for (const app of watchedApps) {
      const bid = app.attributes?.bundleId;
      const watch = watchlist[bid];
      
      // Stop watching after 10 checks or 30 minutes
      if (watch.checkCount > 10 || (Date.now() - watch.lastCheck) > 30 * 60 * 1000) {
        delete watchlist[bid];
        continue;
      }

      const result = await processApp(app, true); // force fresh data
      if (result) {
        const existing = store.items.findIndex(i => i.bundle_id === bid);
        if (existing >= 0) {
          store.items[existing] = result;
        }
      }

      watch.checkCount++;
      watch.lastCheck = Date.now();
    }

    saveData(store);
  } catch (err) {
    console.error("Quick check failed:", err.message);
  }
}

/* ---------------------------
   ⚡ SCHEDULING
--------------------------- */

// Full refresh interval
if (hasAscCreds()) {
  setInterval(() => {
    refreshData().catch(e => console.error("Scheduled refresh failed:", e.message));
  }, REFRESH_INTERVAL_MS);

  // Quick check interval for watchlist
  setInterval(() => {
    quickCheckWatchlist().catch(e => console.error("Quick check failed:", e.message));
  }, QUICK_CHECK_INTERVAL_MS);
}

/* ---------------------------
   ROUTES
--------------------------- */
app.get("/api/apps", (_req, res) => {
  res.json({ 
    last_refresh: store.meta?.last_refresh || null, 
    items: store.items || [],
    watching: Object.keys(store.meta?.watchlist || {}).length
  });
});

app.post("/api/stash", (req, res) => {
  const { bundle_id, stashed } = req.body || {};
  if (!bundle_id) return res.status(400).json({ error: "bundle_id required" });

  let updated = null;
  store.items = (store.items || []).map(i => {
    if (i.bundle_id !== bundle_id) return i;
    const newStashed = stashed ? 1 : 0;
    const bucket = newStashed
      ? "Stashed / Unused"
      : (i.expired ? "Expired" : (i.days_left !== null && i.days_left <= 14 ? "Expiring ≤14 days" : "Live"));
    updated = { ...i, stashed: newStashed, bucket, updated_at: new Date().toISOString() };
    return updated;
  });
  saveData(store);
  return res.json({ ok: true, item: updated });
});

app.post("/api/request", async (req, res) => {
  const { bundle_id, comments, requester } = req.body || {};
  if (!bundle_id || !comments) return res.status(400).json({ error: "bundle_id and comments are required" });
  if (!transporter) return res.status(500).json({ error: "Email transporter not configured." });

  const appItem = (store.items || []).find(i => i.bundle_id === bundle_id);
  const appName = appItem?.app_name || "(Unknown App)";
  const version = appItem?.version || "-";
  const bucket  = appItem?.bucket || "-";
  const expires = appItem?.expires ? new Date(appItem.expires).toISOString().slice(0,10) : "-";
  const daysLeft = appItem?.days_left ?? "-";

  store.meta.requests = store.meta.requests || [];
  store.meta.requests.push({
    at: new Date().toISOString(),
    bundle_id, app_name: appName, version, bucket,
    requester: requester || "",
    comments
  });
  saveData(store);

  const subject = `TestFlight Request: ${appName} (${bundle_id})`;
  const lines = [
    `App: ${appName}`,
    `Bundle ID: ${bundle_id}`,
    `Version: ${version}`,
    `Status: ${bucket}`,
    `Expires: ${expires} (Days left: ${daysLeft})`,
    requester ? `Requester: ${requester}` : null,
    `---`,
    `Comments:`,
    comments
  ].filter(Boolean);

  try {
    await transporter.sendMail({
      from: SMTP_USER || "testflight-requests@yourdomain.com",
      to: REQUEST_EMAIL_TO,
      subject,
      text: lines.join("\n")
    });
    return res.json({ ok: true, sent: true });
  } catch (e) {
    console.error("Request email failed:", e.message);
    return res.status(500).json({ error: "Failed to send email" });
  }
});

// ⚡ Enhanced refresh endpoint
app.post("/api/refresh", async (req, res) => {
  const { bundle_id } = req.body || {};
  
  try {
    if (bundle_id) {
      // Refresh specific app
      console.log(`🎯 Targeted refresh for ${bundle_id}`);
      const apps = await listAllApps();
      const targetApp = apps.find(a => a.attributes?.bundleId === bundle_id);
      
      if (targetApp) {
        const result = await processApp(targetApp, true);
        if (result) {
          const idx = store.items.findIndex(i => i.bundle_id === bundle_id);
          if (idx >= 0) {
            store.items[idx] = result;
          } else {
            store.items.push(result);
          }
          saveData(store);
          return res.json({ ok: true, refreshed: store.meta?.last_refresh, target: bundle_id });
        }
      }
      return res.status(404).json({ error: "App not found" });
    } else {
      // Full refresh
      await refreshData(true);
      res.json({ ok: true, refreshed: store.meta?.last_refresh });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ---------------------------
   START
--------------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`⚙️  Full refresh: every ${REFRESH_INTERVAL_MS/1000}s`);
  console.log(`⚡ Quick check: every ${QUICK_CHECK_INTERVAL_MS/1000}s`);
  console.log(`🔀 Parallel requests: ${MAX_PARALLEL_REQUESTS}`);
  
  if (hasAscCreds()) {
    refreshData().catch(err => console.warn("Initial refresh failed:", err.message));
  }
});