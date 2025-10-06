// server.js (no native modules, persists to data.json)
import fs from "fs";
import path from "path";
import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { fileURLToPath } from "url";
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === Config via .env or environment ===
const ASC_ISSUER_ID = process.env.ASC_ISSUER_ID || "";
const ASC_KEY_ID    = process.env.ASC_KEY_ID || "";
const PRIVATE_KEY_P8_PATH = process.env.ASC_PRIVATE_KEY_P8_PATH || "keys/AuthKey_ABC123XYZ.p8";
const PRIVATE_KEY_TEXT = process.env.ASC_PRIVATE_KEY_P8 || fs.readFileSync(path.join(__dirname, PRIVATE_KEY_P8_PATH), "utf-8");

const ONLY_LATEST_PER_APP = true;
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS || 6 * 60 * 60 * 1000); // 6h
const PORT = process.env.PORT || 8080;

const ASC_BASE = "https://api.appstoreconnect.apple.com";

// === Email config
const REQUEST_EMAIL_TO = process.env.REQUEST_EMAIL_TO || "dev@satorixr.com";
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false") === "true";

const transporter = (SMTP_HOST && REQUEST_EMAIL_TO)
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    })
  : null;

// === Data file (simple JSON store; use /home on Azure if available)
const DATA_DIR = process.env.DATA_DIR || (process.env.WEBSITE_INSTANCE_ID ? "/home/data" : __dirname);
if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {} }
const DATA_PATH = path.join(DATA_DIR, "data.json");

function loadData(){
  if (!fs.existsSync(DATA_PATH)) return { meta:{ alerts:{}, requests:[] }, items:[] };
  try {
    const j = JSON.parse(fs.readFileSync(DATA_PATH, "utf-8"));
    j.meta = j.meta || {};
    j.meta.alerts = j.meta.alerts || {};
    j.meta.requests = j.meta.requests || [];
    j.items = j.items || [];
    return j;
  } catch {
    return { meta:{ alerts:{}, requests:[] }, items:[] };
  }
}
function saveData(data){
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
}
let store = loadData();

// === Express
const app = express();
app.use(express.json());
// Stop caching API responses
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
// Serve static files (index.html, etc.)
app.use(express.static(__dirname));
// Quiet favicon
app.get("/favicon.ico", (req, res) => res.status(204).end());

// === ASC helpers
function ascToken() {
  if (!ASC_ISSUER_ID || !ASC_KEY_ID || !PRIVATE_KEY_TEXT) {
    throw new Error("Set ASC_ISSUER_ID, ASC_KEY_ID and ASC_PRIVATE_KEY_P8(_PATH)");
  }
  const payload = { iss: ASC_ISSUER_ID, exp: Math.floor(Date.now()/1000) + 20*60, aud: "appstoreconnect-v1" };
  const header  = { kid: ASC_KEY_ID, alg: "ES256", typ: "JWT" };
  return jwt.sign(payload, PRIVATE_KEY_TEXT, { algorithm: "ES256", header });
}
async function ascGet(url, params={}){
  const token = ascToken();
  const r = await axios.get(ASC_BASE + url, { headers:{Authorization:`Bearer ${token}`}, params, timeout:30000 });
  return r.data;
}
function daysLeft(iso){
  if (!iso) return null;
  const d = new Date(iso);
  const today = new Date();
  const utc0 = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  const utcD = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  return Math.round((utcD - utc0) / 86400000);
}
async function listAllApps(){
  let data = await ascGet("/v1/apps", { limit:200 });
  const apps = [...data.data];
  let next = data.links?.next;
  while (next){
    const r = await axios.get(next, { headers:{Authorization:`Bearer ${ascToken()}`}});
    data = r.data;
    apps.push(...data.data);
    next = data.links?.next;
  }
  return apps;
}
async function listBuilds(appId){
  let data = await ascGet(`/v1/apps/${appId}/builds`, {
    limit:200,
    "fields[builds]":"version,uploadedDate,expirationDate,expired,processingState"
  });
  const builds = [...data.data];
  let next = data.links?.next;
  while (next){
    const r = await axios.get(next, { headers:{Authorization:`Bearer ${ascToken()}`}});
    data = r.data;
    builds.push(...data.data);
    next = data.links?.next;
  }
  return builds;
}
function pickLatestReady(builds){
  const ready = builds.filter(b => b.attributes?.processingState === "VALID");
  const pool = ready.length ? ready : builds;
  if (!pool.length) return null;
  return pool.sort((a,b)=>(b.attributes?.uploadedDate||"").localeCompare(a.attributes?.uploadedDate||""))[0];
}

// === Refresh logic
async function refreshData(){
  const apps = await listAllApps();
  const prevMap = new Map((store.items || []).map(i => [i.bundle_id, i]));
  const out = [];

  for (const appd of apps){
    const appId = appd.id;
    const name  = appd.attributes?.name;
    const bid   = appd.attributes?.bundleId;

    const builds = await listBuilds(appId);
    if (!builds.length) continue;

    const b = pickLatestReady(builds);
    if (!b) continue;

    const a = b.attributes || {};
    const exp = a.expirationDate || null;
    const left = daysLeft(exp);
    const isExpired = !!a.expired;
    const status = a.processingState || null;
    const uploaded = a.uploadedDate || null;
    const version = a.version || null;

    // Preserve stashed across refresh; auto-unstash when app is not expired anymore
    let stashed = prevMap.get(bid)?.stashed ? 1 : 0;
    if (stashed && !isExpired) {
      stashed = 0;
      console.log(`Auto-unstashed: ${name} (${bid}) now Live/Expiring`);
    }

    const bucket = stashed
      ? "Stashed / Unused"
      : (isExpired ? "Expired" : (left !== null && left <= 14 ? "Expiring ≤14 days" : "Live"));

    out.push({
      bundle_id: bid,
      app_name: name,
      version, uploaded, expires: exp,
      days_left: left, asc_status: status,
      expired: isExpired ? 1 : 0,
      bucket, stashed,
      updated_at: new Date().toISOString()
    });
  }

  // sort: Expired → Expiring → Live → Stashed
  const orderRank = (x) =>
    x.bucket === "Expired" ? 0 :
    x.bucket.startsWith("Expiring") ? 1 :
    x.bucket === "Live" ? 2 : 3;
  store.items = out.sort((a,b)=>{
    const ra=orderRank(a), rb=orderRank(b);
    if (ra!==rb) return ra-rb;
    if ((a.days_left??999) !== (b.days_left??999)) return (a.days_left??999)-(b.days_left??999);
    return (a.app_name||"").localeCompare(b.app_name||"");
  });

  store.meta = store.meta || {};
  store.meta.last_refresh = new Date().toISOString();
  store.meta.alerts = store.meta.alerts || {};
  saveData(store);
}

// schedule periodic refresh
setInterval(()=>refreshData().catch(e=>console.error("Refresh failed:", e.message)), REFRESH_INTERVAL_MS);

// === Routes
app.get("/", (req,res)=> res.sendFile(path.join(__dirname,"index.html")));

app.get("/api/apps", (req,res)=>{
  res.json({ last_refresh: store.meta?.last_refresh || null, items: store.items || [] });
});

// stash / unstash
app.post("/api/stash", (req,res)=>{
  const { bundle_id, stashed } = req.body || {};
  if (!bundle_id) return res.status(400).json({error:"bundle_id required"});
  let updated = null;
  store.items = (store.items||[]).map(i => {
    if (i.bundle_id !== bundle_id) return i;
    const newStashed = stashed ? 1 : 0;
    const bucket = newStashed
      ? "Stashed / Unused"
      : (i.expired ? "Expired" : (i.days_left !== null && i.days_left <= 14 ? "Expiring ≤14 days" : "Live"));
    updated = { ...i, stashed: newStashed, bucket, updated_at: new Date().toISOString() };
    return updated;
  });
  saveData(store);
  return res.json({ ok:true, item: updated });
});

// NEW: raise request → email dev@satorixr.com
app.post("/api/request", async (req, res) => {
  const { bundle_id, comments, requester } = req.body || {};
  if (!bundle_id || !comments) {
    return res.status(400).json({ error: "bundle_id and comments are required" });
  }
  if (!transporter) {
    return res.status(500).json({ error: "Email transporter not configured (SMTP)." });
  }

  // find app info
  const app = (store.items || []).find(i => i.bundle_id === bundle_id);
  const appName = app?.app_name || "(Unknown App)";
  const version = app?.version || "-";
  const bucket = app?.bucket || "-";
  const expires = app?.expires ? new Date(app.expires).toISOString().slice(0,10) : "-";
  const daysLeft = app?.days_left ?? "-";

  // save a minimal record for trace
  store.meta.requests = store.meta.requests || [];
  const record = {
    at: new Date().toISOString(),
    bundle_id, app_name: appName, version, bucket,
    requester: requester || "",
    comments
  };
  store.meta.requests.push(record);
  saveData(store);

  // send email
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
      text: lines.join("\n"),
    });
    return res.json({ ok: true, sent: true });
  } catch (e) {
    console.error("Request email failed:", e.message);
    return res.status(500).json({ error: "Failed to send email" });
  }
});

app.post("/api/refresh", async (req,res)=>{
  await refreshData();
  res.json({ ok:true, refreshed: store.meta?.last_refresh || null });
});

app.listen(PORT, ()=>{
  console.log(`Server running: http://127.0.0.1:${PORT}`);
  refreshData().catch(()=>{});
});
