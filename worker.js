// SKD Portal — Cloudflare Worker (LIVE + AI reports)
// Live SKD data + secure Claude proxy + MPA locked-format report generation.

/* ════════════════════════ SECURITY SHIELD (build shield-1) ════════════════════════
   A hardening layer on top of the working portal — behaviour is unchanged.
     1. Security headers + Content-Security-Policy on every response: only our own
        code and the allow-listed CDNs below can ever run in the browser. Injected
        scripts, hostile iframes and clickjacking are blocked.
     2. Stronger login cookie (__Host- prefix), timing-safe signature compare,
        stricter Google token checks (issuer + expiry + audience).
     3. Rate limits: sign-in attempts per IP; AI / report / upload calls per user.
     4. Role fences on every claim endpoint (case-full, report, report-mpa,
        questionnaire, upload); /api/raw-open is now admin-only.
     5. Upload guard: real-PDF signature check, 15 MB/file, 60 MB/batch, clean names.
     6. AI proxy locked to the approved model with a hard token cap.
     7. Backend/config files can never be downloaded, even with a valid login.
   If a page ever fails to load a NEW library, add its host to CSP below.
   ────────────────────────────────────────────────────────────────────────────── */
const AI_ALLOWED_MODELS = ["claude-haiku-4-5", "claude-sonnet-4-6"];   // v26.3 — "Claude use only this Haiku 4.5": the cheaper one first
const Q_MODEL = "claude-haiku-4-5";   // questionnaires run on the lowest-cost model
const AI_MAX_TOKENS = 4000;

// Content-Security-Policy — the browser refuses scripts/styles/frames from any
// host not on this list. Add a host here BEFORE using a new CDN in the front end.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com https://accounts.google.com",
  "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://accounts.google.com https://fonts.googleapis.com",
  "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com",
  "img-src 'self' data: blob: https:",
  "connect-src 'self' https://accounts.google.com https://skd-portal.gpsk-ts.workers.dev",
  "frame-src 'self' https://accounts.google.com",
  "frame-ancestors 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "manifest-src 'self'",
  "media-src 'self'",
  "worker-src 'self' blob:",
  "upgrade-insecure-requests"
].join("; ");

function withSecurityHeaders(request, resp) {
  const h = new Headers(resp.headers);
  h.set("X-Content-Type-Options", "nosniff");                       // no MIME sniffing
  h.set("X-Frame-Options", "SAMEORIGIN");                           // no clickjacking
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  /* VIDEO CALL — v20.3, 02-Sep-2026. Sujit: "check the video call section."
     This line used to read camera=(), microphone=() — an EMPTY allowlist, which DISABLES both
     in the portal page. A child frame can never re-enable a feature its parent has disabled,
     so the desk iframe's allow="camera; microphone" (app.js) was inert: getUserMedia in
     /call/desk was refused before any prompt, the host never reached call.start(), and the
     guest's phone sat on "Connecting…" for ever.
     It worked in August because, until run_worker_first landed on 31-Aug, /portal.html was
     served straight off the CDN without this header at all. (self) keeps every OTHER origin
     out and lets our own desk — and the Acefone phone on the portal page — open the mic. */
  h.set("Permissions-Policy", "camera=(self), microphone=(self), geolocation=(), payment=()");
  h.set("Cross-Origin-Opener-Policy", "same-origin-allow-popups");  // popups (Google) still work
  h.set("Cross-Origin-Resource-Policy", "same-origin");             // other sites cannot embed our files
  h.set("X-Permitted-Cross-Domain-Policies", "none");
  h.set("Origin-Agent-Cluster", "?1");
  h.set("X-Robots-Tag", "noindex, nofollow");                       // keep the portal out of Google
  const ct = h.get("Content-Type") || "";
  if (ct.indexOf("text/html") !== -1) h.set("Content-Security-Policy", CSP);
  let path = "";
  try { path = new URL(request.url).pathname; } catch (e) {}
  if (path.indexOf("/api/") === 0) h.set("Cache-Control", "no-store");
  /* v20.5 — Sujit, 3-Sep 7:52 am, a screenshot of the OLD admin page and the OLD two-bar
     Analytics twenty minutes after the new files were live: "still it is there, you can
     check." The files on the server were new; his browser was showing the copies it had
     kept. A page (HTML) is now told to be re-checked on every open, and app.js / styles.css
     / the admin page are re-validated too — the server answers 304 in a few milliseconds
     when nothing changed, so nothing is slower, and nobody has to know what a hard refresh
     is to see a version the sidebar already claims. */
  if (ct.indexOf("text/html") !== -1 || /\.(js|css)$/i.test(path)) h.set("Cache-Control", "no-cache");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

// Files that must never be served, even to signed-in users.
const BLOCKED_PATHS = [
  /^\/worker\.js$/i, /^\/wrangler\.toml$/i, /^\/package(-lock)?\.json$/i,
  /^\/functions(\/|$)/i, /^\/\.(git|env|dev)/i, /^\/readme/i, /\.(md|toml|txt)$/i
];
/* THE ADDRESS IS READ IN EVERY SPELLING IT CAN ARRIVE IN, not just the plain one.

   wrangler.toml publishes this whole folder as the website ([assets] directory = "./"), so
   Cloudflare's own file server will happily hand out worker.js unless we refuse it first —
   and it undoes percent-signs, doubled slashes and /./ steps BEFORE it looks on disk. A check
   that only read the address exactly as typed therefore let all of these straight through:

       /%77orker.js      · w written as %77
       /%2577orker.js    · the % itself written as %25, so one decode is not enough
       /%2Fworker.js     · the slash written as %2F
       //worker.js       · a doubled slash
       /./worker.js  ·  /x/../worker.js  ·  /worker.js/
       /worker.js%00.png · a hidden end-of-text marker with a harmless name pinned after it

   So the address is unwound first — up to three times, because the trick can be layered —
   the slashes are tidied, and BOTH the tidied form and the raw form are checked. Anything
   carrying an end-of-text marker is refused outright; no honest address has one. */
function normalizePath(p) {
  let s = String(p == null ? "" : p);
  for (let i = 0; i < 3 && /%[0-9a-f]{2}/i.test(s); i++) {
    let d;
    try { d = decodeURIComponent(s); } catch (e) { break; }   // malformed % — leave it as it is
    if (d === s) break;
    s = d;
  }
  s = s.replace(/\\/g, "/").replace(/\/{2,}/g, "/");          // back-slashes and doubled slashes
  while (/\/\.\//.test(s)) s = s.replace(/\/\.\//g, "/");     // /./ steps
  if (s.length > 1) s = s.replace(/\/+$/, "");                // trailing slash, however many
  return s || "/";
}
function isBlockedPath(p) {
  const raw = String(p == null ? "" : p);
  const norm = normalizePath(raw);
  if (raw.indexOf("\u0000") !== -1 || norm.indexOf("\u0000") !== -1) return true;
  return BLOCKED_PATHS.some(re => re.test(raw) || re.test(norm));
}

// Best-effort in-memory rate limiter (per Worker instance; resets on redeploy).
const RATE = new Map();
function allowRate(key, max, windowMs) {
  const now = Date.now();
  if (RATE.size > 5000) RATE.clear();
  const e = RATE.get(key);
  if (!e || now > e.reset) { RATE.set(key, { n: 1, reset: now + windowMs }); return true; }
  if (e.n >= max) return false;
  e.n++;
  return true;
}

// Constant-time string compare (session signature check).
function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Can this user touch this claim? admin/boss: everything. coordinator/manager: only their slice.
/* Claim numbers arrive in different writing styles — the client writes 5573/2600000045/TP
   while SKD stores 5573-2600000045-TP. claimKey() ignores / - . ( ) and spaces, and
   findCaseByClaim() maps whatever was typed or pasted to the EXACT case SKD knows. */
function claimKey(s) { return String(s == null ? "" : s).replace(/[^a-z0-9]/gi, "").toLowerCase(); }
// Every field name SKD might use for the insured's phone ("Contact number" on the old portal's case page)
const CONTACT_KEYS = ["contactNumber", "contact_no", "contactNo", "contact", "mobileNumber", "mobileNo", "mobile", "phoneNumber", "phoneNo", "phone", "insuredContact", "insuredMobile", "insuredPhone", "insuredContactNumber", "customerContact", "customerMobile", "laContactNumber", "laContact", "laMobile", "claimantContact", "claimantMobile"];
// Hunt for a contact number anywhere in a raw SKD case JSON (top level or nested one/two levels deep)
function contactFromCaseJson(o, depth) {
  depth = depth || 0;
  if (!o || typeof o !== "object" || depth > 2) return "";
  if (Array.isArray(o)) { for (const v of o) { const r = contactFromCaseJson(v, depth + 1); if (r) return r; } return ""; }
  for (const k of CONTACT_KEYS) { const v = o[k]; if (v != null && String(v).replace(/[^\d]/g, "").length >= 10) return String(v); }
  for (const k in o) { const v = o[k]; if (v && typeof v === "object") { const r = contactFromCaseJson(v, depth + 1); if (r) return r; } }
  return "";
}
function findCaseByClaim(cases, claim) {
  let hit = cases.find(c => c.claimNo === claim);
  if (hit) return hit;
  const k = claimKey(claim);
  if (k.length < 6) return null;
  return cases.find(c => claimKey(c.claimNo) === k) || null;
}
/* ══ THE REGISTER IS THE WHOLE BOOK FOR WHOEVER HOLDS ITS TICK — v34.5, 25-Sep-2026 ═══════
   Sujit, 9:35 am, the register open: "For whom I'm giving this access, they want to get all
   cases — need to be showed for them. I don't want only their cases … They want to get all the
   cases, whatever I am reflecting, this cases need to be showed for them — only for this."
   The people he gives the Document Register to are the desk that applies for the RTI and the
   134 and puts them up, and that desk works the WHOLE open Motor TP book, not one manager's
   slice or one coordinator's states. So on this page — and only this page — the fence is
   lifted for every post that holds the tick. The one exception is an insurer login
   (client-manager): that is the client's own login, and another insurer's cases are never
   its to see. Dashboard, Cases, Analytics and the rest keep their fences exactly as before. */
function docRegWide(me) { return !!me && !isClientRole(me) && canAccess(me, "docreg"); }
async function claimScopeCheck(env, me, claim) {
  if (!me || me.role === "admin" || me.role === "boss") return { allowed: true, notFound: false };
  const d = await getCases(env);
  const found = findCaseByClaim(d.cases, claim);
  if (!found) return { allowed: false, notFound: true };
  const foMap = me.role === "coordinator" ? await getFoStateMap(env) : null;
  return { allowed: scopeCases([found], me, foMap).length > 0, notFound: false, claimNo: found.claimNo };
}
/* ════════════════ FIREWALL LAYER (shield-3 additions) ════════════════
   A WAF-style layer in front of everything:
     - Probe detection: requests for known hack paths (/wp-admin, .php, /.env,
       /.git, /phpmyadmin, path traversal …) get the requesting IP banned for
       1 hour, and the event is written to the Security Log.
     - Security Log: notable events (failed sign-ins, rate-limit hits, blocked
       uploads, blocked cross-scope attempts, probe bans, admin actions) are
       stored in KV for 7 days — visible in Admin → Security log.
     - CSRF shield: any POST whose Origin header is another website is refused.
     - Session↔browser binding: the login cookie is tied to the browser it was
       created in; a stolen cookie used from another browser is dead.
     - KV-backed login rate limit: brute-force cap that survives restarts.
     - Claim-number validation on every claim URL.                              */

const ATTACK_PATHS = [
  /\.php(\?|$)/i, /^\/wp-/i, /^\/wordpress/i, /^\/\.env/i, /^\/\.git/i, /^\/\.aws/i,
  /^\/phpmyadmin/i, /^\/xmlrpc/i, /^\/cgi-bin\//i, /\.(asp|aspx|jsp|cgi)(\?|$)/i,
  /^\/vendor\/phpunit/i, /^\/config\.(json|yml|yaml|php|ini)$/i, /^\/(backup|dump|db|database)\.(sql|zip|tar|gz)$/i,
  /^\/(actuator|solr|jenkins|manager\/html|owa|autodiscover)/i, /\.\.\//, /%2e%2e/i, /%00/i
];
function isAttackPath(pathname) {
  let dec = pathname;
  try { dec = decodeURIComponent(pathname); } catch (e) {}
  return ATTACK_PATHS.some(re => re.test(pathname) || re.test(dec));
}
const BANNED_IPS = new Map(); // ip -> banned-until timestamp (per Worker instance)
const BAN_MS = 60 * 60 * 1000;
function banIP(ip) { if (!ip) return; if (BANNED_IPS.size > 5000) BANNED_IPS.clear(); BANNED_IPS.set(ip, Date.now() + BAN_MS); }
function isBanned(ip) { const t = ip && BANNED_IPS.get(ip); if (!t) return false; if (Date.now() > t) { BANNED_IPS.delete(ip); return false; } return true; }

// Security Log — events kept 7 days in KV (key sorts newest-first), viewed in Admin.
let SECLOG_LAST = 0;
/* v17.8 — THE SECURITY LOG MOVED TO D1. It writes on every sign-in, every admin action and
   every refusal: on a busy day that is hundreds of the portal's 1,000 free KV writes, spent
   on bookkeeping, and on 31-Aug it helped lock the whole company out of its own front door.
   One row per event in its own table — no read-modify-write, so two events at the same
   instant can never overwrite each other, which the old style could not promise either.
   Nothing here may ever throw: a log line is not worth an action. */
let secLogReady = false;
async function secLog(env, type, who, detail, important) {
  try {
    const now = Date.now();
    if (!important && now - SECLOG_LAST < 3000) return; // flood guard, unchanged
    SECLOG_LAST = now;
    if (!env.DB) return;
    if (!secLogReady) {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS portal_seclog (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT, who TEXT, detail TEXT)").run();
      try { await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_seclog_ts ON portal_seclog(ts)").run(); } catch (e) {}
      secLogReady = true;
    }
    await env.DB.prepare("INSERT INTO portal_seclog (ts, type, who, detail) VALUES (?1,?2,?3,?4)")
      .bind(now, String(type).slice(0, 40), String(who || "").slice(0, 80), String(detail || "").slice(0, 180)).run();
    /* keep a week, swept now and again — a DELETE on every login is the same mistake in a
       different cupboard */
    if (Math.random() < 0.02) { try { await env.DB.prepare("DELETE FROM portal_seclog WHERE ts < ?1").bind(now - 7 * 24 * 3600 * 1000).run(); } catch (e) {} }
  } catch (e) {}
}

// Durable login rate limit (KV bucket per IP per 10 minutes) — survives restarts.
/* v17.8 — the cross-edge login counter, moved off KV. It wrote on EVERY sign-in attempt,
   exactly the frequent write KV cannot afford; and note the shape of the old failure — a
   counter that could not be written was forgiven here (return true), but the OTHER writes
   in the same request were not, so the login died anyway. D1 now, and soft. */
async function kvLoginAllowed(env, ip) {
  if (!env.DB) return true;
  try {
    const key = "rl:login:" + ip + ":" + Math.floor(Date.now() / 600000);
    const cur = parseInt((await stGet(env, key)) || "0", 10);
    if (cur >= 30) return false;
    await stSoft(env, key, String(cur + 1));
    return true;
  } catch (e) { return true; }
}

// Session ↔ browser binding: hash of the browser's User-Agent baked into the cookie.
async function uaHash(request) {
  try {
    const ua = request.headers.get("User-Agent") || "";
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ua));
    return Array.from(new Uint8Array(d)).slice(0, 6).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (e) { return ""; }
}

// Claim numbers in URLs: letters/digits and - _ / ( ) . space, 3–60 chars.
function validClaim(c) { return typeof c === "string" && c.length >= 3 && c.length <= 60 && /^[\w()\/\-. ]+$/.test(c); }
/* ══════════════════════ end SECURITY SHIELD helpers ══════════════════════ */

// ============================================================================
//  UPLOAD DOCUMENTS ENDPOINT  (Praveen's "4. Upload Claim Documents" API)
//  Set via a Worker variable SKD_UPLOAD_PATH (recommended) or here. Accepts EITHER
//  a full URL or a bare path; use {claim} or {claim-number} for the claim number.
//  Full URL   : https://skdhealth.net/o/corinsoft/cases/claim/{claim-number}/upload-docs
//  Bare path  : /cases/claim/{claim}/upload-docs   (base URL is prepended automatically)
//  (Praveen's 29-Jul-2026 change: /cases/... became /cases/claim/... — an old-style value
//   still works, the worker rewrites it on the way out.)
//  Method POST, multipart/form-data, field "claimDocs", max 10 PDFs (PDF only).
//  Until this is set, the Upload button shows a friendly "not configured" note.
// ============================================================================
/* THE CM REVIEWED HISTORY. SKD serves only the last two days of closed cases — probed
   17-Aug-2026 with and without date parameters and the answer was byte-identical both
   times. So the history is carried in cm-archive.tsv and unioned in below. The module
   imports nothing from here, so there is no cycle. */
import { archiveInWindow, mergeArchive, archiveStats } from "./cm-archive-index.js";
/* v24.0 — the AI queue: in Connector mode the report and the questionnaire are queued for Claude through the TAASEN connector instead of calling the API */
import { aiEngine, queueJob, docsToText, keySetup, noteEngineUse, keyEnvName, ENGINE_NAME, KEYED, claudeModel, listDoorOf, cleanModelList, priceFor } from "./ai-queue-index.js";
import { keepSweep } from "./cm-keep-index.js";
import { resendSend as otpResend, mailDomain as otpMailDomain } from "./mail-index.js";   /* v34.9 — the OTP mail can go by Resend too */
/* v26.7 — the questionnaire typeset as real PDF bytes, so the same file downloads AND uploads */
import { questionnairePdf, questionnaireFileName, paperOf } from "./questionnaire-doc.js";
/* v31.7 — the papers HE ticks, and the pages inside them. No file is chosen by its name. */
import { listCaseDocs, findDoc, parsePicks, parsePages, peekPages, blocksForPicks, docLineFor, MAX_PICK_PAGES, MAX_PICK_PAPERS } from "./qdocs-index.js";
import { pdfText as qPdfText, pdfPageImages as qPdfPageImages } from "./pdf-text.js";
/* v31.8 — the same Word readers the resume screen has used since September: .docx is a zip
   of XML, old .doc is an OLE compound file. One paper in six on MOT17974710 is a .docx. */
import { docxText as qDocxText, _joinTest as qJoin } from "./join-index.js";
const qWordRead = async (bytes, kind) => (kind === "doc" ? qJoin.docText(bytes) : qDocxText(bytes));
/* v26.8 — his trigger / sub-trigger table, and the rule that the doubt is never said out loud */
import { TRIGGERS, triggerOf, subOf, triggerList, groundFor, INDIRECT_RULE, SUB_MARK } from "./questionnaire-triggers.js";
/* v30.3 — HIS PROMPT, PER SUB TRIGGER (18-Sep-2026). "Whichever prompt it will be there means
   that only regarding that question will we be asking." His sheet's column C writes the insured
   paper and column D the doctor paper, word for word; the bill paper keeps his seven standing
   points. Others — a sub trigger he names himself, with the prompt he types — lives in D1. */
import { subsFor, promptFor, saveSubPrompt, groundFromPrompt, promptSideFor, sheetSubs, groundFromPrompts, triggersFor, saveTrigger, triggerAny, deleteTrigger, subCountFor} from "./questionnaire-prompts.js";
/* v26.9 — the upload door: 1,674 documents refused with the same 403, so the portal goes and finds the way in */
import { DOOR_KEY, FIELD_NAMES, hasAltIdentity, doorPlan, doorLabel, doorValid, probePdf, probeName, istStamp, readAnswer } from "./skd-door-index.js";
/* v27.0 — the document register: every open Motor TP case, and which papers are actually on it */
import { DOC_COLS, DOC_KEYS, docRegSweep, docRegOne, docRegRows, cellWord, colOfName, ensureDocRegSchema, driveIndexFor, docRegPrune, docRegPick } from "./docreg-index.js";
/* v30.4 — HIS SELECTION IS THE WORK LIST. "I will select all, or I will select whichever
   need to upload... I don't want [the night job] to work, because we are going to manual."
   The charge sheet is never sendable; the FIR is sendable but starts unticked. */
import { SEND_COLS, SEND_DEFAULT, SEND_NEVER, SEND_DONE, sendable, sendPlan, queueSend, sendQueue, sendState, markSent, unqueue, alreadyGone } from "./docreg-index.js";
/* v33.0 — is the Drive script alive, and what a push log line really says */
import { scriptHealth, humanGap, logVerdict, countLog, sendVerdict, SCRIPT_SILENT_MS } from "./docreg-index.js";
/* v33.1 — the send list is the permission: nothing goes up that he did not tick */
import { queuedFor, mayPush } from "./docreg-index.js";
import { batchFor } from "./docreg-index.js";   /* v33.6 — the collector is paced as the sweep is */
import { CHASE_COLS, NOT_PUT, notPutFor, needed, triage, chaseStats } from "./docreg-index.js";   /* v34.4 — pending · to upload · uploaded, RTI and 134 */
/* v33.6 — THE PORTAL COLLECTS THE PAPER ITSELF. Sujit, 24-Sep: "I will not babysit Apps
   Script triggers. Fix the design, not the trigger." The Worker asks the all-in-one web app
   for the file by Drive id ('drive-get'), uploads it through the door, and marks the row only
   when SKD accepted. No timer in Google's account is on the path. */
import { docSendRun, collectorState, pressWords, pingWebApp, sendCounts, ensureSendSchema } from "./docsend-index.js";
import { newsTick, readDay, daysHeld, ymdOf, NEWS_TOPICS, NEWS_FEEDS, NEWS_YT } from "./news-index.js";
/* v32.8 — "Fraud/genuinely add". The investigation's own finding, on the case. */
import { VERDICTS, isVerdict, verdictLabel, needsReason, canMarkVerdict, canClearVerdict,
  setVerdict, clearVerdict, verdictFor, verdictMap, verdictHistory, ensureVerdictSchema } from "./verdict-index.js";

const SKD_UPLOAD_PATH_DEFAULT = "";

/* ══════════ THE DRIVE FOLDER'S CLAIM DOCUMENTS — the name reading ══════════════════════
   v13.5, 22-Aug-2026. See the /api/drive-docs/push route for the whole story; these are the
   three pieces it stands on: every way one claim number can be written, an index of the live
   book keyed by all of them, and the cut that finds where the claim ends and the document's
   own name begins. */
const DDOC_KV_KEY = "drivedocs:cfg";
/* v33.0 — the Drive script's heartbeat, in D1 (his rule: nothing on a hot path in KV, and
   this is stamped on every poll). lastRun in the cfg only moves when the script actually
   SENDS a file, so a healthy script polling an empty list looks dead. This is the honest
   signal: the last time the script spoke to this portal at all. */
const DDOC_ASK_KEY = "ddoc:lastAsk";
/* v33.4 — THE SCRIPT HAS TWO HALVES AND THEY FAIL SEPARATELY. 22-Sep 3:48 pm, with the
   register showing "last listed 09-22 11:52 IST" beside a red bar reading "the Drive script
   has not called in for 4 days": both were true. The LISTING half ran that morning; the
   SENDING half had not asked for the work list since 18-Sep. One stamp could not tell those
   apart, so the bar sent him to look at the wrong trigger. Two stamps now. */
const DDOC_LIST_KEY = "ddoc:lastList";
async function ddocBeat(env) { try { await stSoft(env, DDOC_ASK_KEY, String(Date.now())); } catch (e) {} }
async function ddocListBeat(env) { try { await stSoft(env, DDOC_LIST_KEY, String(Date.now())); } catch (e) {} }
async function ddocLastAsk(env) { try { return parseInt(await stGet(env, DDOC_ASK_KEY), 10) || 0; } catch (e) { return 0; } }
async function ddocLastList(env) { try { return parseInt(await stGet(env, DDOC_LIST_KEY), 10) || 0; } catch (e) { return 0; } }
async function ddocHealth(env, waiting) {
  let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
  return scriptHealth({ lastAsk: await ddocLastAsk(env), lastRun: cfg.lastRun || 0,
    lastList: await ddocLastList(env), waiting, now: Date.now() });
}
const DDOC_LOG_KEY = "drivedocs:log";
const DDOC_CHK_KEY = "drivedocs:chk";      // claim -> when the folder was last searched for it
const DDOC_LOG_MAX = 5000;
/* THE NIGHT WINDOW — 10 pm to 8 am India time, his instruction of 22-Aug-2026, because SKD's
   server is already crashing under the daytime load. Both ends of the clock are configurable
   from the portal; the default is his. The hour is read in IST (UTC + 5:30) and never from
   the machine's own clock, which on Cloudflare is UTC and would open the gate at the wrong
   time of day. */
function ddocNightNow(cfg) {
  const from = (cfg && cfg.fromHour != null) ? cfg.fromHour : 22;
  const to = (cfg && cfg.toHour != null) ? cfg.toHour : 8;
  const h = new Date(Date.now() + 19800000).getUTCHours();
  return from > to ? (h >= from || h < to) : (h >= from && h < to);   // 22→8 wraps midnight
}
function ddocWinText(cfg) {
  const from = (cfg && cfg.fromHour != null) ? cfg.fromHour : 22;
  const to = (cfg && cfg.toHour != null) ? cfg.toHour : 8;
  const p = h => (h === 0 ? "12 am" : h < 12 ? h + " am" : h === 12 ? "12 pm" : (h - 12) + " pm");
  return p(from) + " and " + p(to);
}
/* "OC-26-1502-1801-00000748(309603)" is ONE claim written with a second reference in
   brackets — SKD carries it under either half depending on the screen, so all three forms
   are indexed: the whole thing, what is inside the brackets, and what is left without them. */
function ddocVariants(raw) {
  const out = {};
  const s = String(raw == null ? "" : raw).trim();
  const full = claimKey(s); if (full) out[full] = 1;
  const m = s.match(/\(([^)]+)\)/);
  if (m) {
    const inside = claimKey(m[1]); if (inside) out[inside] = 1;
    const without = claimKey(s.replace(/\([^)]*\)/g, "")); if (without) out[without] = 1;
  }
  return Object.keys(out);
}
function ddocIndex(cases) {
  const ix = {};
  for (const c of (cases || [])) {
    for (const v of ddocVariants(c.claimNo)) { if (v.length >= 5 && !ix[v]) ix[v] = c; }
  }
  return ix;
}
/* THE CUT. The file name is tried at every space, the LONGEST possible claim number first,
   and the first left-hand side that is a real live case wins — so "MOT17361398 RTO RTI"
   reads as claim MOT17361398 carrying the document "RTO RTI", while
   "OC-27-1602-1890-00000018 (318434) RTI" reads as that whole bracketed claim carrying
   "RTI". Drive's own duplicate marker — the " (1)" it adds when the same name is uploaded
   twice — is taken off first, or it would be read as part of the document's name. */
function ddocSplit(fileName, index) {
  let base = String(fileName == null ? "" : fileName).replace(/\.pdf$/i, "").trim();
  base = base.replace(/\s*\((\d{1,2})\)\s*$/, "").trim();              // Drive's "(1)", "(2)"…
  /* AN UNDERSCORE IS A SPACE (v27.2, 16-Sep-2026). His "All separated PDF" folder names its
     papers 3379516663_RTI.pdf, 500000000080764_134.pdf, 600000000194572-1_RTI.pdf — with an
     underscore, not a space. Split on whitespace alone and the whole name is ONE token, so the
     claim reads as "3379516663_RTI", matches nothing, and the file is filed as nomatch with no
     document type. That is why every RTI and 134 column in the Document Register was showing a
     dash while the papers sat in the folder. A claim number is digits, letters, - / ( ) and
     spaces — never an underscore — so the underscore can only ever be a separator. */
  const toks = base.split(/[\s_]+/).filter(Boolean);
  /* TWO PASSES, and the ORDER is the whole fix (14-Sep-2026, found while building the document
     register). "OC-26-1501-1803-00000337(310417) RTI.pdf" used to come back with the claim
     right and the DOCUMENT NAME EMPTY: the longest candidate — the whole string, RTI and all —
     matched on the bracket contents alone (310417), so the cut fell after "RTI" and the label
     was blank. Every bracketed claim lost its document type that way, and a register that
     reads these labels would show an empty column for a paper we actually hold. So the FULL
     spelling is tried first, longest to shortest; only when nothing matches at all is the
     bracket read as a claim in its own right. */
  for (let pass = 0; pass < 2; pass++) {
    for (let i = toks.length; i >= 1; i--) {
      const cand = toks.slice(0, i).join(" ");
      const vs = pass === 0 ? [claimKey(cand)] : ddocVariants(cand);
      for (const v of vs) {
        if (v && v.length >= 5 && index[v]) return { hit: index[v], claim: cand, label: toks.slice(i).join(" ") };
      }
    }
  }
  /* nothing matched — say WHAT was read as the claim rather than nothing at all, because the
     usual fix is a typo in that very word */
  return { hit: null, claim: "", readAs: toks[0] || "", label: toks.slice(1).join(" ") };
}
/* The push to SKD's own case file, using the same configured address and the same field name
   as the Upload Docs page a person clicks — one code path, so a document that arrives by hand
   and a document that arrives from the Drive folder land in exactly the same place. */
/* THE DOOR, once found, is written down and used by everything — the Send button and the
   nightly Drive push alike. Read through a short memo so a 200-document night does not make
   200 trips to D1; the record changes about once in the life of the portal. */
/* A FILE NAME SKD WILL ACCEPT: no path separators, no control characters, never endless.
   Written character by character rather than with an escape class, because this name travels
   into a multipart header where one stray control byte splits the request in two. */
function safeDocName(n) {
  const s = String(n);
  let out = "";
  for (let i = 0; i < s.length && out.length < 120; i++) {
    const c = s.charCodeAt(i);
    out += (c < 32 || c === 47 || c === 92 || c === 127) ? "_" : s.charAt(i);
  }
  return out;
}
let DOOR_MEMO = { at: 0, val: null };
const DOOR_DEFAULT = { who: "main", field: "claimDocs", extra: {} };
async function doorGet(env) {
  if (DOOR_MEMO.val && Date.now() - DOOR_MEMO.at < 60000) return DOOR_MEMO.val;
  let d = null;
  try { const raw = await stGet(env, DOOR_KEY); if (raw) d = JSON.parse(raw); } catch (e) { d = null; }
  if (!doorValid(d)) d = null;
  DOOR_MEMO = { at: Date.now(), val: d };
  return d;
}
async function doorPut(env, d) {
  DOOR_MEMO = { at: Date.now(), val: doorValid(d) ? d : null };
  await stSoft(env, DOOR_KEY, JSON.stringify(d));
}
/* THE UPLOAD ADDRESS, worked out the same way wherever the call comes from. */
function skdUploadTarget(env, claimNo) {
  const cfgPath = (env.SKD_UPLOAD_PATH || SKD_UPLOAD_PATH_DEFAULT || "").trim();
  if (!cfgPath) return { error: "the SKD upload address is not set on this Worker (SKD_UPLOAD_PATH)" };
  let claimOut = String(claimNo || "");
  if (/[\/]/.test(claimOut)) claimOut = claimOut.replace(/\//g, "-");     // SKD's own writing style
  let filled = cfgPath.replace("{claim-number}", encodeURIComponent(claimOut)).replace("{claim}", encodeURIComponent(claimOut));
  /* Praveen's 29-Jul-2026 change, applied automatically: an old-style /cases/{claim}/... value is
     rewritten to /cases/claim/{claim}/... so nothing needs editing in the Cloudflare dashboard.
     Proven live 14-Sep-2026: the new shape answers 405 to a GET (the route is there, it just does
     not take GET), the old one answers 404 (it is gone). */
  if (/\/cases\//i.test(filled) && !/\/cases\/claim\//i.test(filled)) filled = filled.replace(/\/cases\//i, "/cases/claim/");
  return { url: /^https?:\/\//i.test(filled) ? filled : (env.SKD_API_BASE + filled), claimOut };
}
/* ONE push, built to whatever shape the door record says. opts.door overrides the stored one,
   which is how the finder tries a shape without committing the portal to it. */
async function skdUploadDocs(env, claimNo, items, opts) {
  const t = skdUploadTarget(env, claimNo);
  if (t.error) return { ok: false, error: t.error };
  const door = (opts && opts.door && doorValid(opts.door)) ? opts.door : ((await doorGet(env)) || DOOR_DEFAULT);
  const build = () => {
    const out = new FormData();
    for (const k in (door.extra || {})) out.append(k, k === "claimNumber" ? t.claimOut : String(door.extra[k]));
    for (const it of items) out.append(door.field, it.file, safeDocName(it.name));
    return out;
  };
  try {
    let token = await getToken(env, false, door.who);
    let r = await fetch(t.url, { method: "POST", headers: { "Authorization": "Bearer " + token, "Accept": "application/json" }, body: build() });
    if (r.status === 401) { token = await getToken(env, true, door.who); r = await fetch(t.url, { method: "POST", headers: { "Authorization": "Bearer " + token, "Accept": "application/json" }, body: build() }); }
    const txt = (await r.text()).slice(0, 300);
    if (r.status < 200 || r.status >= 300) return { ok: false, status: r.status, body: txt, error: "HTTP " + r.status + " " + txt };
    return { ok: true, status: r.status, body: txt, msg: items.length + " document" + (items.length === 1 ? "" : "s") + " uploaded to the case at SKD." };
  } catch (e) { return { ok: false, error: String(e && e.message ? e.message : e) }; }
}

// ============================================================================
//  GET ALL FO DETAILS  (Praveen's "5. Get All FO Details" API — GET)
//  Set via Worker variable SKD_FO_PATH (recommended) or here. Full URL or path.
//  Note: this list has NO State/Region yet, so the portal keeps the baked-in
//  FO directory as a fallback and only overlays whatever the API provides.
// ============================================================================
const SKD_FO_PATH_DEFAULT = "";

const DEMO_CASES = [
  { claimNo:"TN-1001", client:"Demo", subProduct:"Motor TP", insured:"Demo", officerName:"R. Kumar", tat:"5D", status:"FO Completed", createdOn:"2026-07-01", trigger:"Demo", rtaFlag:true, product:"TP" }
];

/* THE CASE FILE AS DATA, not as a Response — the register reads hundreds of these and has no
   use for the envelope. Throws in words when SKD sends something that is not case data. */
async function skdGetCaseDoc(env, claim) {
  const r = await skdGetCase(env, claim);
  const t = await r.text();
  try { return JSON.parse(t); }
  catch (e) { throw new Error("SKD did not send case data for " + claim + " (HTTP " + r.status + ")"); }
}
/* ONE BITE OF THE REGISTER. Wired here rather than in the module so the module imports
   nothing from this file and there is no cycle — the same shape as keepSweep and foChangeSweep.
   Motor TP only, by his instruction; read-only; never throws. */
/* ══════════ WHICH CLAIMS ARE OPEN THIS SECOND — v27.4 ═══════════════════════════════════
   The register shows the live Motor TP book and nothing else (his 16-Sep 4:27 am note). The
   live feed is the truth; the copy kept in D1 is only for the minute SKD is down, so the
   screen narrows to the same claims instead of silently widening back out to closed cases —
   which is the one failure he would not see, because a wrong row looks exactly like a right
   one. Kept at every sweep, read here. */
/* ══════════ A CONNECTED PAIR IS ONE ACCIDENT — v27.8, 16-Sep-2026 ═══════════════════════
   Sujit, 6:17 am, SKD's own case screen for 3379515052 open beside the register:

     "3379515052 — this case is collected. This is the main case 3379515046. If we have sent
      it on the main case, you have to mention in that line, yes — this is collected, we have
      sent the RTI or 134 on 3379515046. You have to mention like this. If not, you have to
      mention that for the main case also we have not sent."

   HE IS DESCRIBING A FACT ABOUT THE WORLD, NOT A DISPLAY PREFERENCE. One accident produces
   ONE police record. When two claimants come off the same crash, SKD opens a second case and
   writes "Connected With 3379515046" in its trigger — but the RTI reply, the FIR and the
   charge sheet are filed once, on whichever of the two the officer worked. The register was
   reading each case on its own, so the second one showed seven dashes and looked like work
   nobody had started, when in truth every paper for that accident was already in hand.

   3379515052 is exactly that: seven dashes, while 3379515046 next to it holds the RTI in
   Drive, the FIR and the charge sheet.

   THE PAIRING IS UNDIRECTED, and that is deliberate. SKD writes the connection on the NEW
   case only — 3379515046's own trigger never mentions 3379515052 — so reading it one way
   would only ever help the newer half of each pair. The accident does not care which file
   the clerk opened first. A paper found on either side is shown on both, and the mark always
   names the claim the paper actually sits on, so nothing is hidden behind the sharing.      */
function docRegPairs(cases) {
  const byKey = new Map(), pairs = {};
  for (const c of (cases || [])) { const k = trigKey(c && c.claimNo); if (k && !byKey.has(k)) byKey.set(k, c.claimNo); }
  const join = (a, b) => { if (!a || !b || a === b) return;
    (pairs[a] = pairs[a] || []); if (pairs[a].indexOf(b) < 0) pairs[a].push(b); };
  for (const c of (cases || [])) {
    if (!c || !c.claimNo || !c.trigger) continue;
    for (const L of trigClaimsOf(c.trigger, c.claimNo)) {
      /* the claim number AS SKD WRITES IT wherever we hold that case, so the screen shows him
         a number he can search for; the raw token only when we have never seen the case */
      const other = byKey.get(L.key) || L.no;
      join(c.claimNo, other); join(other, c.claimNo);
    }
  }
  return pairs;
}

async function docRegLive(env) {
  try {
    const d = await getCases(env);
    const open = (d.cases || []).filter(c => c && c.claimNo && typeOfSub(c.subProduct) === "TP").map(c => c.claimNo);
    /* the pairs are read from the WHOLE open feed, not the TP slice: a connected case can sit
       under another product, and its papers are still the same accident's papers */
    const pairs = docRegPairs(d.cases || []);
    /* ── v30.5 · THE AGE OF EACH CASE, FOR THE REGISTER'S TAT COLUMN ────────────────────
       Sujit, 18-Sep 7:25 am, on the register: "You have to add TAT — I need that from lower
       to higher." The register knew which papers a case has and nothing about how old it is,
       so the oldest case missing its RTI looked exactly like one opened yesterday. The days
       come off SKD's own TAT on the live book, the same figure Out of TAT counts, so the two
       screens can never disagree about a case's age. */
    const tat = {};
    for (const c of (d.cases || [])) {
      if (!c || !c.claimNo) continue;
      const dh = tatDH(c.tat);
      const days = parseInt(dh[0], 10);
      if (isFinite(days)) tat[c.claimNo] = days;
    }
    if (open.length) { await stSoft(env, "docreg:live", JSON.stringify({ at: Date.now(), claims: open, pairs, tat })); return { claims: open, pairs, tat, live: true }; }
  } catch (e) { }
  try {
    const kept = JSON.parse(await stGet(env, "docreg:live") || "null");
    if (kept && Array.isArray(kept.claims) && kept.claims.length) return { claims: kept.claims, pairs: kept.pairs || {}, tat: kept.tat || {}, live: false, at: kept.at || 0 };
  } catch (e) { }
  return { claims: null, pairs: {}, tat: {}, live: false };
}

/* the daily gathering, called from the cron in entry.js */
export async function newsDailyTick(env, now) {
  return newsTick(env, { now: now || Date.now(), fetch: (...a) => fetch(...a) });
}

export async function docRegTick(env, opts) {
  const r = await docRegSweep(env, getCases, skdGetCaseDoc,
    Object.assign({ isTP: c => typeOfSub(c && c.subProduct) === "TP" }, opts || {}));
  await stSoft(env, "docreg:last", JSON.stringify(Object.assign({ ts: Date.now() }, r)));
  return r;
}

/* ══════════ THE COLLECTOR — v33.6, 24-Sep-2026 ═══════════════════════════════════════
   One run of the send list: pull each ticked paper from Drive through the all-in-one web
   app, upload it through the door (skdUploadDocs — the same call the Send button, the
   questionnaire and the push door use, so the door shape found once serves all), and write
   SKD's verdict on the row. A case whose paper landed is re-read at once so its column turns
   from amber to green without waiting for the sweep. Wired here, not in the module, so the
   module imports nothing from this file — the same shape as docRegTick. */
async function docSendNow(env, opts) {
  return docSendRun(env, {
    upload: (e, claim, items) => skdUploadDocs(e, claim, items),
    afterSent: async (claim) => {
      let live = null;
      try { const d = await getCases(env); live = findCaseByClaim(d.cases, claim) || null; } catch (e) { live = null; }
      await docRegOne(env, skdGetCaseDoc, live, claim);
    }
  }, opts);
}
/* the cron's bite — on BOTH firings, paced as the register sweep is (a proper batch between
   10 pm and 8 am IST, a handful by day: his 22-Aug word on SKD's daytime load). The time
   budget follows the same clock. Never throws. */
export async function docSendTick(env, now) {
  const at = now || Date.now();
  const n = batchFor(at);
  const h = new Date(at + 19800000).getUTCHours();
  const night = (h >= 22 || h < 8);
  try { return await docSendNow(env, { max: n, budgetMs: night ? 180000 : 45000, taker: "cron", now: at }); }
  catch (e) { return { ok: false, why: String((e && e.message) || e) }; }
}

/* ---------- Auth: Basic-Auth login -> jwtToken (cached) ---------- */
let TOKEN = { value: "", exp: 0 };
/* ── THE MORNING OF 7-AUG-2026, AND WHY EVERY SKD CALL NOW WEARS A WATCH ─────────────────
   SKD's server started answering "error code: 524" — Cloudflare's way of saying the origin
   took longer than 100 seconds and the line was cut. Our worker sat waiting the full 100
   seconds on EVERY call, then choked on the error page ("Unexpected token 'e' ... is not
   valid JSON"), and the whole portal read as dead: skeletons for half an hour, people
   pressing reload, every reload starting another 100-second wait against a server that was
   already drowning. Three rules now:
     1. We give up FIRST. Every SKD call carries its own timeout — well under Cloudflare's
        100s — so the portal answers in seconds, not minutes, whatever their server does.
     2. Their error pages are read as sentences, not parsed as JSON. "error code: 524"
        becomes "SKD's server took too long — this is on the SKD side", which is the truth,
        instead of a token error that reads like OUR site broke.
     3. The last good answer is kept, and served — clearly marked with its time — while
        their server is down. A portal showing this morning's list, and saying so, beats a
        portal showing skeletons.                                                          */
function skdTmo(env, key, dflt) { const v = Number(env && env[key]); return (isFinite(v) && v > 0) ? v : dflt; }
async function fetchT(url, init, ms) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch (e) { } }, ms);
  try {
    const r = await fetch(url, Object.assign({}, init, { signal: ctl.signal }));
    /* v34.3, 25-Sep-2026 — THE GUARD COVERS THE BODY TOO. Until now the timer was cleared the
       moment the HEADERS arrived, and the body — for /cases/open-cases the whole open book as
       one JSON — was read with no limit at all. SKD answers the headers in a second and then
       builds the body slowly, so on a bad morning /api/open-cases sat for four minutes (measured
       25-Sep 7:55 am: 4 min 18 s and still waiting) while the strip promised "25 seconds". The
       body is read here, inside the same window, and handed on as a plain Response, so every
       reader's .text() / .json() is instant and the whole transfer is bounded by `ms`. */
    const buf = await r.arrayBuffer();
    /* the bytes are already decoded; a copied content-encoding/length would describe the wire, not `buf` */
    const h = new Headers(r.headers); h.delete("content-encoding"); h.delete("content-length");
    return new Response(buf, { status: r.status, statusText: r.statusText, headers: h });
  } catch (e) {
    if (ctl.signal.aborted) throw new Error("SKD did not answer within " + Math.round(ms / 1000) + " seconds — their server is too slow right now. This is on the SKD side.");
    throw e;
  } finally { clearTimeout(t); }
}
/* read an SKD answer as JSON — and when it is NOT JSON, say in words what it actually was */
async function readSkdJson(r, what) {
  const text = await r.text();
  try { return JSON.parse(text); }
  catch (e) {
    const m = text.match(/error code:\s*(\d{3})/i);
    const tail = what ? " (" + what + ")" : "";
    if (m && m[1] === "524") throw new Error("SKD's server took too long to answer (their error 524 — over 100 seconds) and the line was cut. This is on the SKD side, not the portal" + tail + ".");
    if (m) throw new Error("SKD's server answered with their error " + m[1] + " instead of data. This is on the SKD side" + tail + ".");
    throw new Error("SKD sent something that is not case data (HTTP " + r.status + ")" + tail + ".");
  }
}
/* THE SECOND SIGN-IN, and why there is one (v26.9, 14-Sep-2026).
   The portal signs in to SKD as Operation_Head (4745857). That login writes to SKD perfectly
   well — the FO Requests register is full of "Case limit set to 17 in SKD", 12, 13, 20, this
   week — so it is not a read-only account. upload-docs ALONE refuses it, 1,674 times. His own
   operations people attach documents on the corinsoft screen every day, so a login that MAY
   attach exists; it is just not the one in the Worker.
   Set SKD_UPLOAD_USER and SKD_UPLOAD_PASS and uploads — and ONLY uploads — knock with that
   one instead. Reading never changes hands. Unset, everything behaves exactly as before. */
let TOKEN_ALT = { value: "", exp: 0 };
function skdCreds(env, who) {
  return (who === "alt" && hasAltIdentity(env))
    ? { user: String(env.SKD_UPLOAD_USER).trim(), pass: String(env.SKD_UPLOAD_PASS).trim(), slot: "alt" }
    : { user: env.SKD_USERNAME, pass: env.SKD_PASSWORD, slot: "main" };
}
async function getToken(env, force, who) {
  const c = skdCreds(env, who);
  const cache = c.slot === "alt" ? TOKEN_ALT : TOKEN;
  const now = Date.now();
  if (!force && cache.value && now < cache.exp) return cache.value;
  const basic = "Basic " + btoa(c.user + ":" + c.pass);
  const res = await fetchT(env.SKD_API_BASE + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json", "Authorization": basic },
    body: JSON.stringify({ userName: c.user, password: c.pass, deviceId: env.SKD_DEVICE_ID })
  }, skdTmo(env, "SKD_TIMEOUT_MS", 20000));
  const j = await readSkdJson(res, "login");
  const token = j.jwtToken || j.token || j.accessToken || "";
  if (!token) throw new Error("Login failed (status " + res.status + ")");
  const rec = { value: token, exp: Date.now() + 25 * 60 * 1000 };
  if (c.slot === "alt") TOKEN_ALT = rec; else TOKEN = rec;
  return token;
}
async function skdGet(env, path, opts) {
  const ms = (opts && opts.timeoutMs) || skdTmo(env, "SKD_TIMEOUT_MS", 25000);
  let token = await getToken(env);
  let r = await fetchT(env.SKD_API_BASE + path, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } }, ms);
  if (r.status === 401 || r.status === 403) {
    token = await getToken(env, true);
    r = await fetchT(env.SKD_API_BASE + path, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } }, ms);
  }
  return r;
}

/* PRAVEEN'S URL CHANGE (his mail of 29 Jul 2026) — the single-case address moved:
     OLD   /cases/{claim-number}                 NEW   /cases/claim/{claim-number}
     OLD   /cases/{claim-number}/upload-docs     NEW   /cases/claim/{claim-number}/upload-docs
   Every case-detail read in this worker goes through here.

   PROVEN LIVE (29 Jul 2026, claim 226010715100): the new address can answer 200 OK with an
   EMPTY questionSet even while the old address still carries the uploaded documents — DS.pdf
   and all. A status-code fallback is therefore not enough. The rule here is: ask the NEW
   address first, and if its answer has no documents in it, quietly ask the OLD address too —
   then hand back whichever answer actually CARRIES the documents. If neither does, the new
   answer is passed through untouched (an empty case is then the truth, not a routing hole).
   A {data:{...}}-wrapped answer is unwrapped so every reader keeps seeing the old shape. */
async function skdGetCase(env, claim) {
  const enc = encodeURIComponent(claim);
  const caseish = o => o && typeof o === "object" && !Array.isArray(o)
    && (Array.isArray(o.questionSet) || o.claimNumber || o.claimNo || o.caseDetails || o.caseHistory || o.patientName);
  const grab = async (path) => {
    try {
      const r = await skdGet(env, path);
      const text = await r.text();
      let j = null; try { j = JSON.parse(text); } catch (e) { }
      let c = null;
      if (r.status >= 200 && r.status < 300 && j) {
        if (caseish(j)) c = j;
        else if (caseish(j.data)) c = j.data;   // a {data:{...}} wrapper, unwrapped
        else if (caseish(j.case)) c = j.case;
      }
      const hasDocs = !!(c && Array.isArray(c.questionSet) && c.questionSet.length > 0);
      return { status: r.status, text, c, hasDocs };
    } catch (e) { return { status: 0, text: JSON.stringify({ ok: false, error: String(e && e.message || e) }), c: null, hasDocs: false }; }
  };
  const asResponse = c => new Response(JSON.stringify(c), { status: 200, headers: { "Content-Type": "application/json" } });
  const nu = await grab("/cases/claim/" + enc);
  if (nu.hasDocs) return asResponse(nu.c);
  const old = await grab("/cases/" + enc);
  if (old.hasDocs) return asResponse(old.c);            // the documents still live on the old address
  if (nu.c) return asResponse(nu.c);                    // no documents anywhere — the new answer is the truth
  if (old.c) return asResponse(old.c);
  return new Response(nu.text || old.text || "{}", { status: nu.status || old.status || 502, headers: { "Content-Type": "application/json" } });
}

/* ── THE TYPE A BROWSER NEEDS TO OPEN IT ────────────────────────────────────────────────
   SKD's own answer wins whenever it says something real. "application/octet-stream", the
   empty string and "binary/octet-stream" are not real answers — they are the server saying
   "some bytes" — and passing one on with Content-Disposition: inline is exactly how a PDF
   ends up as a blank tab. The file name is the one thing always in hand, so the extension
   decides in that case. Anything unrecognised stays octet-stream and downloads, which is
   honest: better a file in the Downloads folder than a blank tab. */
const FILE_TYPES = {
  pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
  webp: "image/webp", heic: "image/heic", bmp: "image/bmp", tif: "image/tiff", tiff: "image/tiff",
  mp4: "video/mp4", mov: "video/quicktime", avi: "video/x-msvideo", mkv: "video/x-matroska",
  webm: "video/webm", "3gp": "video/3gpp", mp3: "audio/mpeg", m4a: "audio/mp4", wav: "audio/wav",
  ogg: "audio/ogg", opus: "audio/ogg", aac: "audio/aac", txt: "text/plain; charset=utf-8",
  csv: "text/csv; charset=utf-8", html: "text/html; charset=utf-8", json: "application/json",
  doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  zip: "application/zip", rar: "application/vnd.rar", eml: "message/rfc822"
};
function fileTypeFor(name, fromSkd) {
  const said = String(fromSkd || "").trim().toLowerCase();
  const vague = !said || said.indexOf("octet-stream") >= 0 || said === "application/binary" || said === "*/*" || said.indexOf("text/plain") === 0 && /\.(pdf|jpe?g|png|mp4)$/i.test(String(name || ""));
  if (!vague) return fromSkd;
  const m = /\.([A-Za-z0-9]{1,5})$/.exec(String(name || ""));
  const ext = m ? m[1].toLowerCase() : "";
  return FILE_TYPES[ext] || "application/octet-stream";
}

/* ── A DOCUMENT THAT WILL NOT OPEN MUST SAY WHY, ON THE SCREEN ──────────────────────────
   This route is always opened in a new tab, never by a script reading JSON. Answering a tab
   with {"ok":false,...} shows the person a line of code, and answering it with nothing shows
   a blank page — both read as "the portal is broken" when the truth is usually "SKD refused
   this one file". So the reason is printed, in words, with the claim and the file on it, so
   it can be read out or sent on. */
function fileProblem(headline, detail, claim, fname) {
  const esc = s => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const body = "<!doctype html><meta charset=utf-8><title>Document not available</title>" +
    "<style>body{font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;background:#F5F8FC;color:#0B2540;margin:0;padding:40px 24px}" +
    ".c{max-width:620px;margin:0 auto;background:#fff;border:1px solid #D7E2EF;border-radius:14px;padding:24px 26px}" +
    "h1{font-size:18px;margin:0 0 10px;color:#A3271B}p{margin:8px 0}code{background:#F0F3F7;padding:2px 6px;border-radius:5px;font-size:12.5px;word-break:break-all}" +
    ".m{color:#5A708C;font-size:13px;margin-top:16px;border-top:1px solid #EEF3F9;padding-top:12px}</style>" +
    "<div class=c><h1>" + esc(headline) + "</h1>" +
    (fname ? "<p><b>" + esc(fname) + "</b></p>" : "") +
    (claim ? "<p>Claim <code>" + esc(claim) + "</code></p>" : "") +
    "<p class=m>" + esc(detail) + "</p>" +
    "<p class=m>The paper itself is unharmed — this is only about fetching it. Close this tab and carry on; " +
    "if it keeps happening on the same document, send this page on so the reason travels with it.</p></div>";
  return new Response(body, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

/* ---- Field-doc file fetch: SKD's download route may accept a DIFFERENT auth style than the JSON API.
   Try Bearer -> Basic -> token-in-URL -> open, remember whichever works, report every status if none do. ---- */
let FILE_AUTH_MODE = null;
async function fetchSkdFile(env, fid) {
  const fileUrl = env.SKD_API_BASE + "/cases/download/" + fid;
  async function attempt(mode) {
    if (mode === "bearer") {
      let t = await getToken(env);
      let r = await fetch(fileUrl, { headers: { "Authorization": "Bearer " + t, "Accept": "*/*" } });
      if (r.status === 401 || r.status === 403) { t = await getToken(env, true); r = await fetch(fileUrl, { headers: { "Authorization": "Bearer " + t, "Accept": "*/*" } }); }
      return r;
    }
    if (mode === "hdrToken") { const t = await getToken(env); return fetch(fileUrl, { headers: { "token": t, "Accept": "*/*" } }); }
    if (mode === "hdrJwt") { const t = await getToken(env); return fetch(fileUrl, { headers: { "jwtToken": t, "Accept": "*/*" } }); }
    if (mode === "queryToken") { const t = await getToken(env); return fetch(fileUrl + "?token=" + encodeURIComponent(t), { headers: { "Accept": "*/*" } }); }
    if (mode === "queryJwt") { const t = await getToken(env); return fetch(fileUrl + "?jwtToken=" + encodeURIComponent(t), { headers: { "Accept": "*/*" } }); }
    if (mode === "rawAuth") { const t = await getToken(env); return fetch(fileUrl, { headers: { "Authorization": t, "Accept": "*/*" } }); }
    if (mode === "basic") return fetch(fileUrl, { headers: { "Authorization": "Basic " + btoa(env.SKD_USERNAME + ":" + env.SKD_PASSWORD), "Accept": "*/*" } });
    return fetch(fileUrl, { headers: { "Accept": "*/*" } });
  }
  const all = ["bearer", "hdrToken", "hdrJwt", "queryToken", "queryJwt", "rawAuth", "basic", "open"];
  const order = FILE_AUTH_MODE ? [FILE_AUTH_MODE].concat(all.filter(m => m !== FILE_AUTH_MODE)) : all;
  const tried = [];
  for (const m of order) {
    try {
      const r = await attempt(m);
      if (r.ok) { FILE_AUTH_MODE = m; return { ok: true, r }; }
      tried.push(m + ":" + r.status);
    } catch (e) { tried.push(m + ":ERR"); }
  }
  return { ok: false, detail: tried.join("  ") };
}

/* ---- Fetch ONE uploaded case document, whatever shape its link arrives in.
   PROVEN LIVE (29 Jul 2026, claim 226010715100): after corinsoft's URL change the file links
   come as plain http:// — e.g. http://skdhealth.net/o/corinsoft/cases/download/21164048 —
   and a Worker's fetch DROPS the Authorization header when it follows the http→https hop.
   The download then answers 401, and the questionnaire believed there was no DS at all,
   while the document viewer (which goes through fetchSkdFile) kept working perfectly.
   So: pull the file id out of the link and go through fetchSkdFile() — the proven road with
   its multi-auth retries. Only a link with no id in it is fetched directly, upgraded to
   https so the token survives. */
async function fetchCaseDocBuf(env, fl) {
  const url = String(fl.url || "");
  const m = url.match(/\/cases\/download\/([\w.-]+)/);
  const fid = fl.id || (m ? m[1] : null);
  if (fid) {
    try { const got = await fetchSkdFile(env, fid); if (got.ok) return await got.r.arrayBuffer(); } catch (e) { }
  }
  if (url) {
    try {
      const token = await getToken(env);
      const rr = await fetch(url.replace(/^http:\/\//i, "https://"), { headers: { "Authorization": "Bearer " + token, "Accept": "*/*" } });
      if (rr.ok) return await rr.arrayBuffer();
    } catch (e) { }
  }
  return null;
}

/* ---------- Normalize case list ---------- */
// first non-empty value among candidate key names (SKD field names are guesses until /api/raw-open confirms them)
function pick(c, keys) { for (const k of keys) { const v = c[k]; if (v != null && v !== "") return v; } return ""; }

/* ── THE INSURED'S PHONE, WHEREVER SKD NESTED IT ─────────────────────────────────────────
   Sujit, 13-Aug-2026, holding the case drawer (number showing) against the Appointment page
   (box empty) for the SAME claim: "The number is visible inside that file — I need the
   number put in Appointment automatically. Also for Feedback Calling."

   The Appointment and Feedback lists were already TRYING: phone = saved || contactNo. The
   fault was upstream — contactNo came from pick(), which reads the TOP LEVEL of the feed
   row only, while SKD often parks the number one level down. The drawer never had
   the problem because app.js digContact() digs nested objects; this is that dig, worker-side,
   and normalize() now falls back to it, which fills Appointment, Feedback, the drawer's
   quick view and the Analytics phone map in one move.

   THE ONE RULE THAT MATTERS HERE: never present somebody else's phone as the insured's. A
   case row can carry the FIELD OFFICER'S mobile inside its officer objects, and a dug-up
   wrong number does not look wrong on screen — it gets CALLED. So the dig refuses to enter
   any key that smells of officer, stakeholder or manager, and depth stops at 2. If that
   means no number is found, an empty box that asks to be typed in beats a confident box
   that rings the wrong person. */
function digContactW(o, depth) {
  depth = depth || 0;
  if (!o || typeof o !== "object" || depth > 2) return "";
  if (Array.isArray(o)) { for (const it of o) { const r = digContactW(it, depth + 1); if (r) return r; } return ""; }
  for (const k of CONTACT_KEYS) { const v = o[k]; if (v != null && String(v).replace(/[^\d]/g, "").length >= 10) return String(v); }
  for (const k in o) {
    if (/officer|stake|manager|agent|^fos?$/i.test(k)) continue;
    const w = o[k];
    if (w && typeof w === "object") { const r = digContactW(w, depth + 1); if (r) return r; }
  }
  return "";
}
/* ===== Ported from analytics.html: FO directory (State/Region) + sub-product Type map.
   Lets the server build the "Today (TP)" sheet export with the SAME ST (State) and Type
   classification the Analytics screen uses. ===== */
const FO_DIRECTORY = {"abbas ali": {"state": "TamilNadu","region": "Thanjavur"},"abhishek kl": {"state": "Karnataka","region": "Mysuru"},"abhishek manoj gawali": {"state": "Maharashtra","region": "Pune"},"adithyan byju": {"state": "Kerala","region": "Idukki"},"ajesh mathew": {"state": "Karnataka","region": "Bengaluru"},"ajin r": {"state": "Kerala","region": "Malappuram"},"akshay kota": {"state": "Maharashtra","region": "Mumbai"},"allasampath rahul": {"state": "Telungana","region": "Hyderabad"},"anand raj": {"state": "TamilNadu","region": "Tirunelveli"},"anand v": {"state": "TamilNadu","region": "Vellore"},"anantha narayana": {"state": "Karnataka","region": "Hospet"},"anil kumar kadappa": {"state": "Andra Pradesh","region": "Kadappa"},"venkata narasaiah c": {"state": "Andra Pradesh","region": "Kadappa"},"arjun br": {"state": "Karnataka","region": "Hassan"},"arumugam kumar": {"state": "Karnataka","region": "Bengaluru"},"arunkumar pd": {"state": "Karnataka","region": "Bengaluru"},"bala murugan": {"state": "TamilNadu","region": "Pondicherry"},"balasubramaniyan bala": {"state": "TamilNadu","region": "Pondicherry"},"bandaru raju": {"state": "Andra Pradesh","region": "Anantapur"},"basavaraj m": {"state": "Karnataka","region": "Kalaburagi"},"berclinjose s": {"state": "Kerala","region": "Kottayam"},"berlin berlin": {"state": "Kerala","region": "Ernakulam"},"bhanu chandra": {"state": "Telungana","region": "Karimnagar"},"bhavana muniraj": {"state": "Karnataka","region": "Bengaluru"},"bimal pt": {"state": "Karnataka","region": "Bengaluru"},"boddepalli kurma rao": {"state": "Andra Pradesh","region": "Visakhapatnam"},"chaitanya malge": {"state": "Maharashtra","region": "Nanded"},"chandan kr": {"state": "Karnataka","region": "Bengaluru"},"chandan p": {"state": "Karnataka","region": "Mysuru"},"chandrasekhar c": {"state": "Karnataka","region": "Bengaluru"},"datta bhargava v": {"state": "Telungana","region": "Hyderabad"},"deepika s": {"state": "Karnataka","region": "Mangalore"},"dilip arjun arjun patil": {"state": "Maharashtra","region": "Mumbai"},"dilip k": {"state": "Karnataka","region": "Kalaburagi"},"dinesh s": {"state": "TamilNadu","region": "Madurai"},"eera prashanth": {"state": "Telungana","region": "Warangal"},"franklin sahayam": {"state": "Kerala","region": "Thrissur"},"girish kumar": {"state": "Kerala","region": "Kasaragod"},"girishanth giri": {"state": "TamilNadu","region": "Vellore"},"gladwin rayappan": {"state": "Karnataka","region": "Bengaluru"},"gopalakrishnan trichy": {"state": "TamilNadu","region": "Tiruchirappalli"},"guthula nagaprasad": {"state": "Andra Pradesh","region": "East Godavari"},"ishwar patil": {"state": "Karnataka","region": "Vijayapura"},"jeeva j": {"state": "TamilNadu","region": "Salem"},"jeremiah samson": {"state": "TamilNadu","region": "Chennai"},"jilla prasanth": {"state": "Telungana","region": "Warangal"},"jilla sunil": {"state": "Telungana","region": "Hyderabad"},"jino sobitha singh": {"state": "Kerala","region": "Thiruvananthapuram"},"jithuka srikanth": {"state": "Telungana","region": "Hyderabad"},"kalyana sundaram": {"state": "Karnataka","region": "Bengaluru"},"kalyankumar cn": {"state": "TamilNadu","region": "Vellore"},"kanna anand babu": {"state": "Andra Pradesh","region": "Guntur"},"karthick nani": {"state": "Andra Pradesh","region": "Chittoor"},"karthik gangaiah": {"state": "Maharashtra","region": "Mumbai"},"karthikeyan rg": {"state": "TamilNadu","region": "Chennai"},"keerthy j": {"state": "Kerala","region": "Malappuram"},"ketan kp": {"state": "Maharashtra","region": "Sangli"},"kiran nimmala": {"state": "Maharashtra","region": "Mumbai"},"kirubanithi v": {"state": "TamilNadu","region": "Chennai"},"kranthi kumar": {"state": "Karnataka","region": "Bengaluru"},"krishna gutty": {"state": "Karnataka","region": "Ballari"},"kumar g": {"state": "Karnataka","region": "Bengaluru"},"libin p": {"state": "Kerala","region": "Ernakulam"},"lokesh ashok karegore": {"state": "Maharashtra","region": "Nagpur"},"lokesh shivaji lamani": {"state": "Karnataka","region": "Bengaluru"},"maddiletti hyderabad": {"state": "Andra Pradesh","region": "Kurnool"},"madiwalayya siddhayya hiremath": {"state": "Maharashtra","region": "Sholapur"},"mahender singh": {"state": "Telungana","region": "Nizamabad"},"mahesh sudam somvanshi": {"state": "Maharashtra","region": "Aurangabad"},"mani muthu": {"state": "TamilNadu","region": "Coimbatore"},"manikandan p": {"state": "TamilNadu","region": "Salem"},"manikanta k": {"state": "Karnataka","region": "Davangere"},"manjunath p": {"state": "Karnataka","region": "Shimoga"},"manoj kumar p": {"state": "TamilNadu","region": "Madurai"},"manu rex": {"state": "Kerala","region": "Kollam"},"milton vemu": {"state": "Andra Pradesh","region": "Vijayawada"},"mithun raj": {"state": "Karnataka","region": "Davangere"},"mohan raj k": {"state": "TamilNadu","region": "Erode"},"mohana rao boddepalli": {"state": "Telungana","region": "Hyderabad"},"murali m": {"state": "TamilNadu","region": "Madurai"},"musunuru vijaykumar": {"state": "Andra Pradesh","region": "Nellore"},"muthyam reddy": {"state": "Telungana","region": "Hyderabad"},"nagaraj gowda": {"state": "Karnataka","region": "Bengaluru"},"naresh mailaram": {"state": "Telungana","region": "Nizamabad"},"naveen kumar": {"state": "TamilNadu","region": "Coimbatore"},"naveen lv": {"state": "Karnataka","region": "Bengaluru"},"nivedh ak": {"state": "Kerala","region": "Kannur"},"panyam prasad pg": {"state": "Andra Pradesh","region": "Kadappa"},"pavan lokesh": {"state": "Karnataka","region": "Bengaluru"},"peruri lakshmi naga suresh": {"state": "Telungana","region": "Hyderabad"},"pottanna kurnool": {"state": "Telungana","region": "Kurnool"},"prabhakaran madurai": {"state": "TamilNadu","region": "Erode"},"prakash madurai": {"state": "TamilNadu","region": "Madurai"},"prasad naik": {"state": "Karnataka","region": "Belgaum"},"prasanna kumar": {"state": "Andra Pradesh","region": "Bhimavaram"},"prashanth gulbarga": {"state": "Karnataka","region": "Kalaburagi"},"prashanth p": {"state": "Karnataka","region": "Bengaluru"},"pratapa somappa malgi": {"state": "Karnataka","region": "Hospet"},"praveen gouder": {"state": "Karnataka","region": "Belgaum"},"prem kumar t": {"state": "Karnataka","region": "Hubli"},"premkumar s": {"state": "TamilNadu","region": "Chennai"},"pullaiah hyderabad": {"state": "Telungana","region": "Hyderabad"},"rajaguru ayyanar": {"state": "TamilNadu","region": "Chennai"},"rajaguru lingam": {"state": "TamilNadu","region": "Madurai"},"raju kumar": {"state": "Andra Pradesh","region": "East Godavari"},"raju rj": {"state": "Kerala","region": "Ernakulam"},"ramasamy p": {"state": "TamilNadu","region": "Tiruchirappalli"},"ramu g": {"state": "TamilNadu","region": "Chennai"},"ranjithlal vakkayil shanmugan": {"state": "Kerala","region": "Kozhikode"},"ravi kumar": {"state": "TamilNadu","region": "Madurai"},"ravi shankar": {"state": "Karnataka","region": "Bengaluru"},"ravindra reddy": {"state": "Karnataka","region": "Ballari"},"rosaiah k": {"state": "Andra Pradesh","region": "Guntur"},"rudragouda patil b": {"state": "Karnataka","region": "Vijayapura"},"rushikesh bhosale": {"state": "Maharashtra","region": "Pune"},"sakrappara guleppa": {"state": "Karnataka","region": "Bengaluru"},"sandeep mangalore": {"state": "Karnataka","region": "Mangalore"},"sandeep s": {"state": "TamilNadu","region": "Coimbatore"},"santhosh kumar": {"state": "Karnataka","region": "Mangalore"},"santhosh sj": {"state": "Karnataka","region": "Mysuru"},"santhosha dk": {"state": "Karnataka","region": "Bengaluru"},"santosh kumar ms": {"state": "Kerala","region": "Thiruvananthapuram"},"santosh sunil kadam": {"state": "Maharashtra","region": "Mumbai"},"saravana manikandan": {"state": "TamilNadu","region": "Chennai"},"saravanakumar kalidass": {"state": "TamilNadu","region": "Chennai"},"satheesh kasangottu": {"state": "Telungana","region": "Karimnagar"},"seepana malleswararao": {"state": "Andra Pradesh","region": "Visakhapatnam"},"shaik masood": {"state": "Telungana","region": "Hyderabad"},"shajahan syed": {"state": "Telungana","region": "Khammam"},"shanmuga k priyan": {"state": "TamilNadu","region": "Chennai"},"sharavanabasava n": {"state": "Karnataka","region": "Raichur"},"sharon abraham": {"state": "Kerala","region": "Kottayam"},"shiju palakkad": {"state": "Kerala","region": "Palakkad"},"shyam guntur": {"state": "Andra Pradesh","region": "East Godavari"},"sijo justin": {"state": "Kerala","region": "Thrissur"},"sivakumar mysuru": {"state": "Karnataka","region": "Mysuru"},"sridhayanithi s": {"state": "TamilNadu","region": "Chennai"},"srinath oddi": {"state": "Andra Pradesh","region": "Karimnagar"},"srinivasamurthy garnepudi": {"state": "Telungana","region": "Hyderabad"},"stalin a": {"state": "TamilNadu","region": "Salem"},"steny vishal v": {"state": "Karnataka","region": "Bengaluru"},"suba ramachandran": {"state": "TamilNadu","region": "Chennai"},"subash pandian": {"state": "TamilNadu","region": "Madurai"},"sugasan g": {"state": "TamilNadu","region": "Coimbatore"},"sukesh kumar kumar": {"state": "Karnataka","region": "Dakshina Kannada"},"suma gummadi k": {"state": "Karnataka","region": "Bengaluru"},"surendar k": {"state": "TamilNadu","region": "Chennai"},"sweety santra": {"state": "Karnataka","region": "Bengaluru"},"tamilarasu g": {"state": "TamilNadu","region": "Coimbatore"},"taraka krishna g": {"state": "Telungana","region": "Hyderabad"},"thamatam mahendra": {"state": "Telungana","region": "Hyderabad"},"thiyagarajan d": {"state": "TamilNadu","region": "Chennai"},"thurai murugan": {"state": "TamilNadu","region": "Tirunelveli"},"udaykumar cp": {"state": "Andra Pradesh","region": "Mahboobnagar"},"vanguru sathishkumar": {"state": "Telungana","region": "Nalgonda"},"vasanth kumar bm": {"state": "Karnataka","region": "Bengaluru"},"veeraraju ongole": {"state": "Andra Pradesh","region": "Nellore"},"venkadesh krishnagiri": {"state": "TamilNadu","region": "Krishnagiri"},"venkat tejaswara reddy": {"state": "Karnataka","region": "Bengaluru"},"vijaya bhaskar": {"state": "Andra Pradesh","region": "Vijayawada"},"vijayan kozhikode": {"state": "Kerala","region": "Kozhikode"},"viju lal r": {"state": "Kerala","region": "Kollam"},"vimal c": {"state": "TamilNadu","region": "Vellore"},"vimal vinod": {"state": "Kerala","region": "Kannur"},"vineethchandra vijayawada": {"state": "Andra Pradesh","region": "Guntur"},"vinit ingle": {"state": "Maharashtra","region": "Akola"},"vishnu j": {"state": "Karnataka","region": "Bengaluru"},"vishwanath wodayar": {"state": "Karnataka","region": "Davangere"},"shibin cr": {"state": "Kerala","region": ""},"kiran morsing rathod": {"state": "Maharashtra","region": ""},"rajasekhar damodhara": {"state": "Telungana","region": "Hyderabad"},"budda suresh suresh": {"state": "Andra Pradesh","region": "Kadappa"},"prithvi raj": {"state": "Karnataka","region": "Bengaluru"},"rohit bhimrao ingle": {"state": "Maharashtra","region": "SHOLAPUR"},"srinivasarao hyderabad": {"state": "Telungana","region": "Hyderabad"},"eresha k": {"state": "Karnataka","region": "Ballari"},"ramesh kommanaboina": {"state": "Maharashtra","region": "Madurai"},"shashank tiммарра naik": {"state": "Karnataka","region": "Mangaloru"},"manmadha rao": {"state": "Andra Pradesh","region": "Gutur"},"rejith r a": {"state": "Kerala","region": "Kozhikode"},"kiran kumar bs": {"state": "Karnataka","region": "Bengaluru"},"ajith kr": {"state": "Kerala","region": "Kottayam"},"muhammed falah kowwapurath": {"state": "Kerala","region": "Kannur"},"hyderabad maddiletti": {"state": "Telungana","region": "Hyderabad"},"dudekula babafakruddin": {"state": "Andra Pradesh","region": "Anantapur"},"kaviya sivan": {"state": "Kerala","region": "Palakkad"},"pranay pendli": {"state": "Telungana","region": "Karimnagar"},"isaac martin gopali": {"state": "Karnataka","region": "Hubli"},"chandu reddy": {"state": "Andra Pradesh","region": "Chittoor"},"vamshi pv": {"state": "Karnataka","region": "Bengaluru"},"amal cb": {"state": "Kerala","region": "Kozhikode"},"benjamin joseph": {"state": "TamilNadu","region": "Chennai"},"manthan dhondiba gayakwad": {"state": "Karnataka","region": "Vijayapura"},"praveen kumar": {"state": "TamilNadu","region": "Madurai"},"salugrace s": {"state": "TamilNadu","region": "Tirunelveli"},"deepak a": {"state": "TamilNadu","region": "Vellore"},"hemnath i": {"state": "TamilNadu","region": "Chennai"},"vasa datta bhargava": {"state": "Telungana","region": "Hyderabad"},"siva r": {"state": "TamilNadu","region": "Chennai"},"nagaraj g d gowda": {"state": "Karnataka","region": "Bengaluru"},"ajay kumar": {"state": "Karnataka","region": "Davangere"}};
const SUBPRODUCT_TYPE_MAP = {
  'cattle and livestock':'TP','fire':'TP','garage bill verification':'TP',
  'medical bill verification':'TP','motor personal accident':'TP',
  'motor tp connected case':'TP','motor tp full investigation':'TP',
  'motor tp investigation':'TP','motor tp part investigation':'TP',
  'own damage':'TP','salary verification':'TP','summons handing over':'TP',
  'theft':'TP','warranty verification':'TP','workman compensation':'TP'
};
function typeOfSub(sub){
  const k = normName(sub);
  if(!k) return "Health";
  if (Object.prototype.hasOwnProperty.call(SUBPRODUCT_TYPE_MAP, k)) return SUBPRODUCT_TYPE_MAP[k];
  /* A NAME NOT ON THE MAP used to fall to Health in silence — so a TP sub-product SKD spells
     a new way ("Motor TP", "TP Investigation") would land its cases in the HEALTH tables with
     nobody told, and on 19-Aug the TP release table read 1 against an office sheet of 20+.
     The fallback now reads the string's own words before surrendering: anything carrying
     "motor" or the word "tp" is Motor TP. Not a guess — the name says so itself; only a name
     that says neither still defaults to Health. */
  if (/motor/.test(k) || /(^|[^a-z])tp([^a-z]|$)/.test(" " + k + " ")) return "TP";
  return "Health";
}
/* ══════════ FOUR BUCKETS, ONE CLASSIFIER — v33.7, 24-Sep-2026 ═══════════════════════════
   Sujit: "Every screen that carries the product switch 'Motor / TP | Health' gets two more
   pills: OD and MBV. Under OD only Own Damage cases show; under MBV only Medical Bill
   Verification cases show … A case belongs to exactly one. Where 'All' exists it stays All."

   Until now Own Damage and Medical Bill Verification sat INSIDE Motor / TP (SUBPRODUCT_TYPE_MAP
   says 'TP' for both), so every TP count on Analytics, the Out of TAT meeting, IN TAT, the
   Documents page, Business and the Today extracts carried them. productOf() is the ONE
   reading now — the server stamps it on every case as `product`, and the pages load the very
   same function from /api/product-rules.js, so no page does its own string matching.
     OD  = sub-product "Own Damage", any spelling of case.
     MBV = "MEDICAL BILL VERIFICATION" (isMbvSub — GARAGE BILL VERIFICATION is NOT MBV, the
           rule the Bill Verification chase has kept since v21.5).
     TP / Health = exactly what typeOfSub said before, minus those two.
   typeOfSub() itself is unchanged and still answers the two-way question for the readers
   that never had a switch (the Document Register, the mails, Reporting, Productivity). */
const PRODUCTS = [
  { key: "TP", label: "Motor / TP", short: "TP", icon: "fa-car-burst" },
  { key: "Health", label: "Health", short: "Health", icon: "fa-heart-pulse" },
  { key: "OD", label: "OD", short: "OD", long: "Own Damage", icon: "fa-car-side" },
  { key: "MBV", label: "MBV", short: "MBV", long: "Medical Bill Verification", icon: "fa-file-invoice" }
];
function productOf(sub) {
  const k = normName(sub);
  if (!k) return "Health";
  if (/own\s*damage/.test(k)) return "OD";
  if (isMbvSub(sub)) return "MBV";
  return typeOfSub(sub);
}
/* what a page or a connector may write for a product: "od", "OD", "own damage", "mbv",
   "medical bill verification", "tp", "motor", "motor tp", "health" → the bucket key, or "" for All */
/* the two-way parent of a bucket (OD and MBV live under the Motor TP grant), and the pills
   a Motor TP / Health grant opens on a screen */
function productParent(k) { return (k === "OD" || k === "MBV" || k === "TP") ? "TP" : "Health"; }
function productPills(grants) {
  const g = Array.isArray(grants) ? grants : [];
  return PRODUCTS.map(p => p.key).filter(k => g.includes(productParent(k)));
}
function productKey(v) {
  const s = String(v == null ? "" : v).trim().toLowerCase();
  if (!s || s === "all" || s === "both") return "";
  if (s === "od" || /own\s*damage/.test(s)) return "OD";
  if (s === "mbv" || /medical\s*bill/.test(s)) return "MBV";
  if (s === "tp" || /motor/.test(s)) return "TP";
  if (s === "health") return "Health";
  return "";
}
function foStateOf(officerName, foMap){ const k1 = normName(officerName), k2 = normName(firstFO(officerName)); const d = FO_DIRECTORY[k1] || FO_DIRECTORY[k2]; if (d && d.state) return canonState(d.state); const fi = foMap ? (foMap[k1] || foMap[k2]) : null; return (fi && fi.state) ? canonState(fi.state) : ""; }
function tatDH(t){ const s = String(t==null?"":t); const dm = s.match(/(\d+)\s*D/i), hm = s.match(/(\d+)\s*H/i); const dd = dm ? dm[1] : (/^\s*\d+\s*$/.test(s) ? s.trim() : ""); return [dd, hm ? hm[1] : ""]; }
function foRegionOf(officerName, foMap){ const k1 = normName(officerName), k2 = normName(firstFO(officerName)); const d = FO_DIRECTORY[k1] || FO_DIRECTORY[k2]; if (d && d.region) return d.region; const fi = foMap ? (foMap[k1] || foMap[k2]) : null; return (fi && fi.region) ? fi.region : ""; }
/* ---------- TP OUT-OF-TAT page (website version of the FO Completed Sheet) ----------
   Out of TAT = Motor-TP case whose SKD TAT is beyond 30 days. The worker also keeps a
   small KV memory ("ootat:done") of WHEN each out-of-TAT claim was first seen completed,
   so the page can show "completed in the last 24 hours" — the same thing the spreadsheet
   does by comparing Sheet1 against each day's Today paste, but automatic. */
const OOTAT_LIMIT_DAYS = 30;      // last-resort TP limit, only for a sub-product not named in OOTAT_TAT_STD below
/* ---- THE TAT OF EACH SUB-PRODUCT, IN DAYS ----------------------------------------
   This is the table the whole Out of TAT decision now runs on: a case is OUT OF TAT the
   moment its SKD TAT passes the number written against ITS OWN sub-product. Motor TP Full
   Investigation gets 25 days, Motor TP Part Investigation 12, Theft 5, and so on — no more
   one flat 30-day rule for everything on the Motor side.
   MOTOR / TP numbers: given by Sujit, 28 Jul 2026 — all 15 TP sub-products are covered.
   HEALTH numbers: carried over from the TaaSen Code.gs "TAT_STD" already in use on the
   Analytics page, so both pages judge a case the same way. Any of these can be changed by
   editing the number here; anything NOT listed falls back to TP 30 / Cashless 1 / Health 4. */
const OOTAT_TAT_STD = {
  /* ---- MOTOR / TP ---- */
  'cattle and livestock': 4, 'fire': 6, 'garage bill verification': 3,
  'medical bill verification': 3, 'motor personal accident': 6,
  'motor tp connected case': 12, 'motor tp full investigation': 25,
  'motor tp investigation': 25, 'motor tp part investigation': 12,
  'own damage': 6, 'salary verification': 3, 'summons handing over': 3,
  'theft': 5, 'warranty verification': 3, 'workman compensation': 20,
  /* ---- HEALTH ---- */
  'cashless': 1, 'cashless full case': 3, 'cashless-genuinity': 1, 'cashless-ped': 1,
  'corporate verification': 3, 'critical illness': 8, 'document pick up': 3,
  'document verification': 5, 'full investication': 12, 'full investigation': 12,
  'gpa - death and hospitalization': 8, 'gpa - death and ptd': 8, 'hospital daily cash': 5,
  'ipa-death and ptd': 8, 'loss of job': 5,
  'opd claim': 5, 'payout': 5, 'post facto': 3,
  'pre claim verification': 3, 'profile verification': 3,
  're investigation': 3, 'runner boy': 3,
  /* ── THE DAY-5 SIX (Sujit, 28-Aug-2026, on the Out of TAT meeting page) ──────────────
     "IPA-TTD and Hospitalization · OFFLINE · Personal Accident · Pre & Post claim ·
      Reimbursement · Reimbursement-Half case — all need to be in Manager Follow-up before
      the fifth; the fifth day starts, it needs to come to Out of TAT."
     The rule below reads `days <= limit` as still-inside-TAT, so a limit of 4 puts days
     1-4 on Manager Follow-up and moves the case to Out of TAT the moment day 5 begins.
     Written as its own block, with his words, so the next person to read this table knows
     these six numbers are a business instruction and not a typo. Every other sub-product
     keeps the number it had. */
  'ipa-ttd and hospitalization': 4,
  'offline': 4,
  'personal accident': 4,
  'pre & post claim': 4,
  'reimbursement': 4,
  'reimbursement-half case': 4,
  'smc _ ci': 8, 'smc_ci': 8, 'sme verification': 3, 'spot intimation': 3, 'travel insurance': 3
};
const OOTAT_DONE_KEEP_MS = 30 * 24 * 3600 * 1000;   // remember completion timestamps for 30 days (the page's widest window)
function tatDaysNum(t) { const dh = tatDH(t); const n = parseInt(dh[0], 10); return isFinite(n) ? n : 0; }
/* PARTIALLY COMPLETED — the one word for "this man has finished, the CASE has not".
   Three field officers on one claim and two of them have done their part: those two are NOT
   completed, because the claim itself is still open and still waiting on the third. They read
   "Partially Completed", they sit in their own table, and they never fall into any completed
   bucket. Only when EVERY man on the claim has finished does "FO Completed" stand.
   The test strips out every non-letter first, so "Partially Completed", "Partially-Completed",
   "Partial Complete" and "partiallycompleted" all read the same. */
const PART_COMPLETED = "Partially Completed";
function isPartCompletedW(s) {
  const x = String(s == null ? "" : s).toLowerCase().replace(/[^a-z]/g, "");
  return x.indexOf("partial") >= 0 && x.indexOf("complet") >= 0;
}
function isCompletedStatusW(s) {
  const x = String(s == null ? "" : s).toLowerCase();
  if (x.indexOf("partial") >= 0) return false;   // "Partially Completed" — HE is done, the CASE is not
  if (/\bnot\s*complete|incomplete|un-?complete/.test(x)) return false;   // v20.3: "Not Completed" is the opposite word
  return x.indexOf("complete") >= 0;
}
/* The MEETING is only about work that is still sitting with the field officer, so the page
   carries exactly four statuses — Pending · Assigned · FO Accepted · FO Rejected. Anything
   the officer has already finished ("FO Completed"), anything he has finished while the claim
   waits on somebody else ("Partially Completed" — that man has his own table), and anything
   that has moved on past him (review, released, closed) belongs elsewhere, not here.
   A blank status counts as Pending, which is how the rest of the portal reads it too. */
function isMeetingStatusW(s) {
  const x = String(s == null ? "" : s).toLowerCase().trim();
  if (!x) return true;
  if (x.indexOf("complete") >= 0) return false; // "FO Completed" and "Partially Completed" — he has done his work, there is nothing to ask HIM
  return x.indexOf("pending") >= 0 || x.indexOf("assign") >= 0 || x.indexOf("accept") >= 0 || x.indexOf("reject") >= 0;
}
/* How many days this ONE case is allowed, by its own sub-product. The named table wins; if a
   sub-product is not in it yet, the old rule still applies so nothing ever goes unjudged. */
/* ── EVERY PRODUCT THE PORTAL KNOWS, as a list ── v18.1
   The New Case drop-down is built from THIS, not from a list typed out in the page, so the
   choices can never drift from the two maps that actually judge a case: the one that decides
   Motor TP from Health, and the one that sets its TAT. A product added to those maps appears
   in the drop-down the same day, with the right type and the right clock. */
function allProducts() {
  const keys = new Set(Object.keys(SUBPRODUCT_TYPE_MAP).concat(Object.keys(OOTAT_TAT_STD)));
  const title = s => s.replace(/\b\w/g, c => c.toUpperCase());
  return Array.from(keys).sort().map(k => {
    const type = SUBPRODUCT_TYPE_MAP[k] === "TP" ? "TP" : "Health";
    return { key: k, name: title(k), type, tat: ootatLimitFor(k, type) };
  });
}

/* ═══════════════════════════════════════════════════════════════════════════════════════
   THE CONNECTED CASE, READ OFF THE TRIGGER                       v22.3 · 09-Sep-2026
   Sujit: "In a trigger we will be mentioning like this. This connected case will be
   released, whichever claim number we have mentioned — that is not released … this claim
   number has been released before 10 or 20 days, still the main case not released, need
   to be mentioned."
   Every SKD trigger on a connected claim carries the OTHER claim's number in a sentence:
   "This case is Connected with 3379515046", "Connected With 321171,321161,321176",
   "Batch case of MOT17892544". Nobody can hold 300 of those in his head, so the meeting
   card never showed the one fact that decides the call: has the other side gone out?
   These three functions read the sentence, find EVERY claim number in it (not just the
   first — "Connected With 321171,321161,321176" is three cases), and each one is answered
   from the portal's own books:
     · still on the open feed  → open, with its days, status, officer and manager
     · gone from the open feed and in the CM archive → released, with the date and how
       long ago
     · neither → said in words as unknown, never guessed. A number the portal has never
       seen is usually the client's own reference, and calling that "released" would send
       a man to close a case that was never ours.
   Two refusals carried over from the Connected Cases screen, unchanged:
   a phone number is not a claim number ("Ph : 9177323068" dies before the read), and the
   trigger's repeat of the case's OWN number is never mistaken for the other side.       */
function trigKey(s) { return String(s == null ? "" : s).replace(/[^A-Za-z0-9]/g, "").toUpperCase(); }
function trigOwnVariants(claimNo) {
  const out = new Set(); const full = trigKey(claimNo); if (full) out.add(full);
  const m = String(claimNo == null ? "" : claimNo).match(/\(([^)]+)\)/);
  if (m) { const b = trigKey(m[1]); if (b) out.add(b); const wo = trigKey(String(claimNo).replace(/\([^)]*\)/g, "")); if (wo) out.add(wo); }
  return Array.from(out);
}
function trigClaimsOf(trigger, ownClaimNo) {
  const raw = String(trigger == null ? "" : trigger);
  if (!raw.trim()) return [];
  /* phone numbers die first — they are marked (Ph / C.No / Contact / Mob) and a claim
     number is never written behind such a marker */
  const s = raw.replace(/(ph(?:one)?|c\s*\.?\s*no|contact(?:\s*no)?|mob(?:ile)?)\s*\.?\s*[:\-]?\s*\+?[0-9][0-9 ()-]{7,}/gi, " ");
  const own = trigOwnVariants(ownClaimNo);
  const re = /[A-Za-z0-9][A-Za-z0-9()\/-]{5,}/g;
  const seen = new Set(), out = [];
  let mt;
  while ((mt = re.exec(s))) {
    const tk = mt[0].replace(/[.,;]+$/, "");
    if (((tk.match(/\d/g)) || []).length < 4) continue;               // CONNECTED, PETTITIONER, INVESTIGATION…
    const k = trigKey(tk); if (!k || seen.has(k)) continue;
    let isOwn = false;
    for (const o of own) { if (o === k || (o.length >= 6 && k.indexOf(o) !== -1) || (k.length >= 6 && o.indexOf(k) !== -1)) { isOwn = true; break; } }
    if (isOwn) continue;
    /* a bare ten-digit number starting 6-9 is shaped like a mobile: it is taken only when
       the sentence points straight at it ("connected with 9999015144") */
    const before = s.slice(Math.max(0, mt.index - 16), mt.index);
    const pointed = /\b(with|of|no|claim|case)\s*[:\-]?\s*$/i.test(before) || /,\s*$/.test(before);
    if (/^[6-9]\d{9}$/.test(k) && !pointed) continue;
    seen.add(k); out.push({ no: tk, key: k });
    if (out.length >= 6) break;                                       // a sentence naming more than six is prose, not a list
  }
  return out;
}
/* Answers every trigger number on every row, in ONE pass over the feed and ONE database
   read. `all` is the WHOLE open feed, never the caller\'s scoped slice — the other side of
   a connected pair usually sits under a different manager, and a main case that is alive
   and well must never be reported as released because the reader could not see it. */
async function trigResolve(env, rows, all, now) {
  const wanted = new Map();                       // key -> [row, ...]
  for (const r of rows) {
    const list = trigClaimsOf(r.trigger, r.claim);
    if (!list.length) continue;
    r.linked = list.map(x => ({ no: x.no, key: x.key, state: "unknown" }));
    for (const L of r.linked) { if (!wanted.has(L.key)) wanted.set(L.key, []); wanted.get(L.key).push(L); }
  }
  if (!wanted.size) return;
  /* 1 · the open feed answers first, and its answer is final: a case on it is not released */
  const openBy = new Map();
  for (const c of (all || [])) { const k = trigKey(c.claimNo); if (k && !openBy.has(k)) openBy.set(k, c); }
  const misses = [];
  for (const [k, links] of wanted) {
    const c = openBy.get(k);
    if (!c) { misses.push(k); continue; }
    const dh = tatDH(c.tat);
    for (const L of links) {
      L.state = "open"; L.status = c.status || ""; L.days = Number(dh[0] || 0) || 0;
      L.fo = c.officerName || ""; L.manager = c.manager || ""; L.sub = c.subProduct || "";
      L.foDone = c.foCompletedDate || "";
    }
  }
  if (!misses.length || !env || !env.DB) return;
  /* 2 · gone from the open feed — the CM archive is asked for its closing date, in one
        query. A number the archive has never seen keeps state "unknown", said in words. */
  /* ══ v27.7, 16-Sep-2026 — THE SAME CEILING THAT COST A MORNING ON THE REGISTER ═════════
     This asked for up to 400 claim keys in one IN (...). D1 REFUSES A QUERY CARRYING MORE
     THAN 100 BOUND PARAMETERS, so on any busy screen the whole read threw, the catch below
     swallowed it, and every linked claim quietly read "unknown" instead of "released on
     <date>". Nobody would ever see a fault — only a number that never resolves. In slices
     of 90 now, and one bad slice no longer costs the others. */
  const rowsOut = [];
  for (let i = 0; i < misses.length && i < 3600; i += 90) {
    const cap = misses.slice(i, i + 90);
    const marks = cap.map(() => "?").join(",");
    try {
      const res = await env.DB.prepare(
        "SELECT ckey, claim, mgr_ymd, data FROM cm_keep WHERE ckey IN (" + marks + ")"
      ).bind(...cap).all();
      for (const row of (res && res.results) || []) rowsOut.push(row);
    } catch (e) { /* this slice is a bonus, never a blocker — the rest still answer */ }
  }
  try {
    for (const row of rowsOut) {
      const links = wanted.get(String(row.ckey || "")); if (!links) continue;
      let d = null; try { d = JSON.parse(row.data || "{}"); } catch (e) { d = null; }
      const ymd = String(row.mgr_ymd || "");
      let ago = null;
      if (/^\d{4}-\d{2}-\d{2}$/.test(ymd)) {
        const t = Date.parse(ymd + "T00:00:00+05:30");
        if (!isNaN(t)) ago = Math.max(0, Math.floor(((now || Date.now()) - t) / 86400000));
      }
      for (const L of links) {
        L.state = "released"; L.on = ymd; L.ago = ago;
        L.manager = (d && d.manager) || ""; L.fo = (d && d.officerName) || "";
        L.sub = (d && d.subProduct) || ""; L.foDone = (d && d.foCompletedDate) || "";
      }
    }
  } catch (e) { /* the archive is a bonus here, never a blocker: the numbers still show as unknown */ }
}

function ootatLimitFor(sub, type) {
  const k = normName(sub);
  if (k && Object.prototype.hasOwnProperty.call(OOTAT_TAT_STD, k)) return OOTAT_TAT_STD[k];
  if (type === "TP") return OOTAT_LIMIT_DAYS;
  return k.indexOf("cashless") >= 0 ? 1 : 4;
}
/* TWO OR THREE FIELD OFFICERS ON ONE CASE — AND WHAT EACH OF THEM HAS ACTUALLY DONE.
   Checked against the live feed on 29 Jul 2026: of 1679 open cases, 420 have more than one
   officer on them (342 have two, 70 have three, 8 have four). The feed sends ONE row per
   claim; the men arrive together in fieldOfficers, and the single "status" on that row is the
   CASE's status, not any one man's. Each man's own state is in StackHolders, which names the
   parts he was given and says where each part stands:
     "Manoj Kumar P": "Driver verification-Fo Accepted, Insured verification-Fo Accepted, ..."
     "Ravi Kumar":    "Pettetioner Verification-FO Completed"
     "PRAVEEN KUMAR": "Accident Spot verification-FO Completed"
   That is claim 3410137326: two men have finished their part and the third has not started
   his, while the case itself still reads "FO Accepted". Working it out per man — every part
   done = FO Completed, so he drops off the meeting; anything still open = the earliest stage
   among the parts he has left, whatever else he has already finished, because he still owes
   work and still has to be asked. The names of the parts he still owes are kept too, so he is
   asked about those and not about the whole case. Then the Partially Completed rule below
   turns the finished men on a still-open claim into their own separate list.
   A man with no entry in StackHolders falls back to the case status, so nobody is lost. */
const FO_STAGE = { "pending": 0, "assigned": 1, "fo accepted": 2, "accepted": 2, "fo rejected": 3, "rejected": 3 };
function foPartsOf(txt) {
  return String(txt == null ? "" : txt).split(",").map(seg => {
    const t = seg.trim(); if (!t) return null;
    const i = t.lastIndexOf("-");                       // part name first, his status after it
    return i > 0 ? { part: t.slice(0, i).trim(), status: t.slice(i + 1).trim() } : { part: t, status: "" };
  }).filter(Boolean);
}
/* THE PARTIALLY COMPLETED RULE, applied once the whole case is on the table. Three men on a
   claim, two have finished, one has not: those two are NOT completed men, because the claim
   itself is still open — they are PARTIALLY COMPLETED and they belong in the Partially
   Completed table, while the third keeps his own word (Assigned / FO Accepted / FO Rejected).
   Only when every man on the case is finished does "FO Completed" stand, and the case is
   truly done from field. */
function partCompleteRows(rows) {
  const anyOpen = rows.some(r => !isCompletedStatusW(r.status) && !isPartCompletedW(r.status));
  if (!anyOpen) return rows;                       // everybody is finished — leave FO Completed alone
  rows.forEach(r => { if (isCompletedStatusW(r.status)) { r.status = PART_COMPLETED; r.part = true; } });
  return rows;
}
function ootatFoRows(c) {
  const caseSt = c.status || "";
  const stake = explodeStake(c).filter(r => r.fo);
  const src = stake.length ? stake : [{ fo: String(c.officerName || "").trim(), parts: "" }];
  const out = [];
  src.forEach(r => {
    /* A name that still arrives with the men joined together — "Anil P, Ravi K" — is two men,
       and neither of them can be held to the other's part, so they are split apart here and
       both fall back to the case status rather than one invented officer of that name. */
    const names = String(r.fo).split(/[,/]+/).map(x => x.trim()).filter(Boolean);
    if (names.length > 1) { names.forEach(n => out.push({ name: n, status: caseSt, pending: [] })); return; }
    const who = names.length ? names[0] : String(r.fo || "").trim();
    const parts = foPartsOf(r.parts);
    if (!parts.length) { out.push({ name: who, status: caseSt, pending: [] }); return; }
    const open = parts.filter(p => !isCompletedStatusW(p.status));
    let st;
    if (!open.length) st = "FO Completed";                    // every part he was given is finished
    else {
      /* He still owes something. However much of his own work he has already done, he is still
         a MEETING man and he reports the part he is furthest behind on — the parts left with
         him are listed beside his name, so he is asked about those, not about the whole case. */
      let best = open[0];
      open.forEach(p => {
        const a = FO_STAGE[String(p.status).toLowerCase()], b = FO_STAGE[String(best.status).toLowerCase()];
        if (a != null && (b == null || a < b)) best = p;      // report the part he is furthest behind on
      });
      st = best.status || caseSt;
    }
    out.push({ name: who, status: st, pending: open.map(p => p.part).filter(Boolean) });
  });
  return partCompleteRows(out);
}
// Pure: dedup + keep only out-of-TAT cases. Each case is judged against ITS OWN sub-product's
// TAT from OOTAT_TAT_STD above (Theft 5d, Motor TP Part Investigation 12d, Cashless 1d, ...);
// only a sub-product missing from that table falls back to TP 30d / Cashless 1d / Health 4d.
// Returns {out (ONE per claim), outAll (one per OFFICER on the claim, with HIS own status),
//          doneMap (copy, updated), changed, newly (records first seen completed NOW)}.
/* A case's age when SKD sends NO TAT. tatDaysNum answers 0 for a blank, and 0 is inside every
   limit there is — so a case whose TAT field never arrived sat on IN TAT for ever, however old
   it grew. The created date is on every row, so the age is counted from that instead.
   dd/MM/yyyy, read by hand: new Date("05/08/2026") is 8 May in a US runtime. */
function ootatAgeDays(c, now) {
  const n = tatDaysNum(c.tat);
  if (n > 0 || /\d/.test(String(c.tat || ''))) return n;          // SKD sent a number — trust it, even 0
  const m = String(c.createdOn || '').match(/(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4})/);
  if (!m) return 0;
  const t = Date.UTC(+m[3], +m[2] - 1, +m[1]);
  if (!isFinite(t)) return 0;
  return Math.max(0, Math.floor(((now || Date.now()) - t) / 86400000));
}

function ootatSplit(cases, doneMapIn, now) {
  const doneMap = {}; for (const k in (doneMapIn || {})) doneMap[k] = doneMapIn[k];
  let changed = false;
  const byClaim = {};
  const live = {};                                             // every claim in this pull
  for (const c of cases) {
    const days = ootatAgeDays(c, now);
    const key = String(c.claimNo || "").trim(); if (!key) continue;
    live[key] = 1;
    const ex = byClaim[key];
    if (!ex) byClaim[key] = { c, days, type: productOf(c.subProduct), completed: isCompletedStatusW(c.status), rows: [] };   /* v33.7 — TP · Health · OD · MBV */
    else { if (days > ex.days) { ex.days = days; ex.c = c; } if (!isCompletedStatusW(c.status)) ex.completed = false; }
    /* Keep EVERY officer. The line above still settles on one record per claim, because the
       out-of-TAT memory counts claims and not people; this keeps each man beside his own
       status so the meeting can call all three of them instead of only the one that survived
       the dedup. The same officer arriving twice on one claim is still counted once. */
    const rec = byClaim[key];
    ootatFoRows(c).forEach(fo => {
      const fk = normName(fo.name);
      const seen = rec.rows.find(x => x.foKey === fk);
      if (!seen) rec.rows.push({ c, foKey: fk, fo: fo.name, status: fo.status, part: !!fo.part, pending: fo.pending || [], days });
      else if (days > seen.days) { seen.days = days; seen.c = c; seen.status = fo.status; seen.part = !!fo.part; seen.pending = fo.pending || []; }
    });
  }
  const out = [], newly = [], outAll = [], inAll = [];
  for (const key in byClaim) {
    const rec = byClaim[key];
    if (rec.days <= ootatLimitFor(rec.c.subProduct, rec.type)) {
      /* ── STILL INSIDE ITS OWN TAT — v13.8, 24-Aug-2026 ──────────────────────────────
         Sujit, 24-Aug: "Whichever going out of TAT need to be in Out of TAT; the rest,
         which is IN TAT, need to be in Manager Follow-up — same feature, same everything."
         Until today a case inside its TAT was simply skipped here, which is why the meeting
         page could only ever be a list of failures — by the time a case appeared, it was
         already late. The same per-officer rows are now built for the in-TAT side too,
         judged by each sub-product's OWN limit (Motor TP Full 25, Part 12, Health 4,
         Cashless 1 day), so "inside TAT" always means inside THIS case's TAT and never one
         number applied to everything. */
      const inPart = rec.rows.filter(x => isPartCompletedW(x.status)).map(x => x.fo).filter(Boolean);
      const inOpen = rec.rows.filter(x => !isCompletedStatusW(x.status) && !isPartCompletedW(x.status)).map(x => x.fo).filter(Boolean);
      const inNames = rec.rows.map(x => x.fo).filter(Boolean);
      rec.partFo = inPart; rec.openFo = inOpen;
      rec.rows.forEach(rw => inAll.push({
        c: rw.c, days: rec.days, type: rec.type, fo: rw.fo, foStatus: rw.status,
        foPending: rw.pending || [],
        completed: isCompletedStatusW(rw.status),
        partCompleted: isPartCompletedW(rw.status),
        caseDone: !inOpen.length && !inPart.length,
        partFo: inPart.slice(), openFo: inOpen.slice(),
        sharedWith: inNames.filter(n => normName(n) !== rw.foKey)
      }));
      continue;
    }
    out.push(rec);
    /* who else is on this claim — so each man's card can say who he is sharing it with */
    const names = rec.rows.map(x => x.fo).filter(Boolean);
    /* THE THREE LISTS THAT MAKE A CASE READABLE AT A GLANCE:
         partFo  — men who have finished while the case is still open  (Partially Completed)
         doneFo — men who have finished on a case where EVERYBODY is finished (FO Completed)
         openFo — men who still owe something; while this list has anybody in it the case
                  cannot count as completed, whatever the case-level status says. */
    const partFo = rec.rows.filter(x => isPartCompletedW(x.status)).map(x => x.fo).filter(Boolean);
    const doneFo = rec.rows.filter(x => isCompletedStatusW(x.status)).map(x => x.fo).filter(Boolean);
    const openFo = rec.rows.filter(x => !isCompletedStatusW(x.status) && !isPartCompletedW(x.status)).map(x => x.fo).filter(Boolean);
    rec.partFo = partFo; rec.doneFo = doneFo; rec.openFo = openFo;
    if (openFo.length) rec.completed = false;      // somebody is still working — this is NOT completed from field
    rec.rows.forEach(rw => outAll.push({
      c: rw.c, days: rec.days, type: rec.type, fo: rw.fo, foStatus: rw.status,
      foPending: rw.pending || [],                 // the parts still sitting with HIM
      completed: isCompletedStatusW(rw.status),
      partCompleted: isPartCompletedW(rw.status),    // HE is finished but the case is not
      caseDone: !openFo.length && !partFo.length,   // every man on this claim is finished
      partFo: partFo.slice(), openFo: openFo.slice(),
      sharedWith: names.filter(n => normName(n) !== rw.foKey)
    }));
    if (rec.completed && !doneMap[key]) { doneMap[key] = now; newly.push(rec); changed = true; }
    /* REOPENED. A case that was completed and has since gone back to Assigned / FO Accepted
       (reallocated, a part reopened) used to keep its completion stamp, so Completed From
       Field went on listing it as done — with a "completed 3 days ago" it no longer earned.
       The stamp goes when the completion does. v20.3 */
    if (!rec.completed && doneMap[key]) { delete doneMap[key]; changed = true; }
  }
  /* FORGETTING. The memory used to drop any stamp older than 30 days — and a case still
     sitting completed in the feed on day 31 was then stamped AGAIN as newly completed,
     logged to the archive a second time and shown as "completed today". A stamp is now
     kept for as long as its claim is still in the feed, and dropped only once the case has
     left (closed, CM reviewed) AND the stamp is past thirty days. v20.3 */
  for (const k in doneMap) { if (!live[k] && now - doneMap[k] > OOTAT_DONE_KEEP_MS) { delete doneMap[k]; changed = true; } }
  return { out, outAll, inAll, doneMap, changed, newly };
}

// The exact "FO Completed" sheet column order — used by BOTH the CSV download and the Apps-Script feed.
/* Status is now THE MAN'S OWN status, not the case's — on a claim with three officers where
   two have finished, those two read "Partially Completed" and the third reads his own Assigned /
   FO Accepted. The old case-level word is kept beside it as "Case Status" so nothing is lost,
   and "Still Pending With" names the men the claim is actually waiting on. */
/* HOSPITAL NAME IS COLUMN G — Sujit, 13-Aug-2026, holding SKD's own export ("SKD - Corinsoft",
   Hospital Name in G) against this sheet, which did not carry the hospital at all:
   "In G column for Excel, every excel format, I need a hospital name."
   The live feed already sends it (normalize() hunts hospitalName under six spellings); the
   sheet was simply never given the column. It is INSERTED at G, nothing is dropped — every
   column that used to live right of F moved one letter right, which is why the index maps
   below (SHEET_HINT_AT, pickSheetRows' FO Name column, the hint row's Status slot) all had
   to move with it. If you add another column, move them again or the sheet writes the right
   words in the wrong boxes and no test that reads by NAME will notice. wsheet reads by index
   for exactly this reason. */
/* v32.8 — Verdict and Verdict reason are APPENDED, at 23 and 24. Every index constant in this
   file (SHEET_HINT_AT, CLAIM_AT = 2, STAKE_AT = 18) counts from the left, so adding at the end
   moves nothing. They are filled after the rows are built, and BLANKED for an insurer login
   beside the five people columns — our reading of his claim is not his to download. */
const SHEET_COLUMNS = ["Client","Sub Product","Claim Number","Patient/Insured","Trigger","Assigning Manager","Hospital Name","Allotment Manager","Manager","FO Name","Status","CreatedOn","SKD TAT","SKD TAT-H","Alloted Date","Alloted TAT","CAT TAT","CAT Completed","StackHolders","ST","Type","Case Status","Still Pending With","Verdict","Verdict reason","OHS"];
const VERDICT_AT = 23, VERDICT_WHY_AT = 24;
/* v33.8 — the field officer's OHS (team head), the LAST column on purpose: every index above
   (SHEET_HINT_AT, CLAIM_AT, STAKE_AT, r[9]) and his Google Sheet scripts count from the left,
   so the column sits at Z and moves nothing. Cut off with the verdict for an insurer login. */
const OHS_AT = 25;
/* SKD's own Excel style: ONE ROW PER FIELD OFFICER — his name in FO Name, HIS verification parts as
   clean text (no {}= wrapper) in StackHolders, and that officer's own state in ST. */
function parseStakeW(s) {
  // the live feed sends StackHolders as a real JSON map {"FO name":"his parts"} — handle that first
  if (s && typeof s === "object" && !Array.isArray(s)) return Object.keys(s).map(k => ({ fo: String(k).trim(), part: String(s[k] == null ? "" : s[k]).trim() }));
  let t = String(s == null ? "" : s).trim();
  if (!t || t === "{}") return [];
  if (t.charAt(0) === "{") t = t.slice(1);
  if (t.charAt(t.length - 1) === "}") t = t.slice(0, -1);
  const out = [];
  t.split(",").forEach(seg => {
    const i = seg.indexOf("=");
    if (i > -1) out.push({ fo: seg.slice(0, i).trim(), part: seg.slice(i + 1).trim() });
    else if (out.length && seg.trim()) out[out.length - 1].part += ", " + seg.trim();
    else if (seg.trim()) out.push({ fo: "", part: seg.trim() });
  });
  return out;
}
function explodeStake(c) {
  const all = parseStakeW(c.stackHolders);
  const stake = all.filter(s => s.fo);
  if (!stake.length) {
    const clean = all.map(s => s.part).join(", ");
    return [{ fo: c.officerName || "", parts: clean }];
  }
  const rows = stake.map(s => ({ fo: s.fo, parts: s.part }));
  // officers on the case that the map missed still get their own row
  String(c.officerName || "").split(/[,/]+/).map(x => x.trim()).filter(Boolean).forEach(nm => {
    if (!rows.some(r => normName(r.fo) === normName(nm))) rows.push({ fo: nm, parts: "" });
  });
  return rows;
}
async function buildSheetRows(env, want, me, status, client) {
  const d = await getCases(env);
  let cases = d.cases;
  const foMap = await getFoStateMap(env);
  if (me && (isScopedRole(me.role))) cases = scopeCases(cases, me, me.role === "coordinator" ? foMap : null);
  /* the Dashboard's client dropdown, carried through to the whole-sheet download so the
     button hands back the screen he is looking at. Matched the forgiving way, because the
     name travels as text and SKD spells one insurer several ways. */
  const wantClient = String(client || "").trim();
  if (wantClient) cases = cases.filter(c => sameClientW(wantClient, c.client));
  want = String(want || "all").toLowerCase();
  /* v33.7 — four buckets: tp | health | od | mbv (All stays All). Own Damage and Medical
     Bill Verification are no longer inside "tp". */
  { const pk = productKey(want); if (pk) cases = cases.filter(c => productOf(c.subProduct) === pk); }
  /* Status filter: the SAME question the dashboard tile asks, so the number you pressed and
     the number of rows in the sheet are the same number.

     "complete" and "partial" are answered by the shared helpers, not by a substring, because
     "Partially Completed" contains the word "complete". A bare indexOf here would hand you a
     sheet of 248 rows after you pressed a tile reading 217 — the screen and the download
     disagreeing about the same click, which is worse than either being wrong alone.
     Everything else is the plain keyword match it has always been. */
  status = String(status || "").toLowerCase().trim();
  if (status === "complete")      cases = cases.filter(c => isCompletedStatusW(c.status));
  else if (status === "partial")  cases = cases.filter(c => isPartCompletedW(c.status));
  else if (status)                cases = cases.filter(c => (c.status || "").toLowerCase().indexOf(status) !== -1);
  const rows = [];
  cases.forEach(c => {
    const dh = tatDH(c.tat);
    /* Each man's OWN status, worked out from his own parts in StackHolders and then put
       through the Partially Completed rule, so a finished man on an unfinished case reads
       "Partially Completed" and never "FO Completed". */
    const mine = {}; const stillWith = [];
    ootatFoRows(c).forEach(f => {
      mine[normName(f.name)] = f.status;
      if (!isCompletedStatusW(f.status) && !isPartCompletedW(f.status) && f.name) stillWith.push(f.name);
    });
    const waiting = stillWith.join(", ");
    explodeStake(c).forEach(e => {   // SKD-Excel style: one row per field officer with HIS parts + HIS state
      /* A case with no StackHolders at all still arrives with the men joined into one name —
         "Anil P, Ravi K". That is two men, and the sheet wants a line each, so they are split. */
      const who = String(e.fo || "").split(/[,/]+/).map(x => x.trim()).filter(Boolean);
      (who.length ? who : [String(e.fo || "")]).forEach(nm => {
        const own = mine[normName(nm)];
        rows.push([c.client, c.subProduct, c.claimNo, c.insured, c.trigger, c.assigningManager, c.hospitalName || "", c.allotmentManager, c.manager, nm, (own == null ? (c.status || "") : own), c.createdOn, dh[0], dh[1], c.allotmentDate, c.allotedTat, c.catTat, c.catCompleted, e.parts, foStateOf(nm || c.officerName, foMap), typeOfSub(c.subProduct), c.status || "", waiting, "", ""]);
      });
    });
  });
  /* ══════════ THE CLIENT'S OWN DOWNLOAD ══════════════════════════════════════════════
     scopeCases has already narrowed this to his insurer and blanked our names on the CASE —
     but this sheet does not read its people from the case. FO Name comes out of
     StackHolders through ootatFoRows/explodeStake, and StackHolders, Still Pending With,
     Assigning/Allotment/Manager are all our staff by name. Left alone, a client login would
     download the very names the screen refuses to show him, which is the worst of both: a
     rule that looks enforced and is not.

     So the sheet is folded back to ONE ROW PER CASE for him (a per-officer sheet with the
     officer blanked is just duplicate lines nobody can explain) and the five people columns
     are emptied. His TAT, his status, his hospital and his dates all stand — that is what he
     asked us for. ST (the state) stays too: it is where the work is, not who did it. */
  if (isClientRole(me)) {
    /* claim is column C and StackHolders column S; neither is in SHEET_HINT_AT, and they are
       NOT added to it — that map is walked by sheetRowFromHint to let a hint overwrite a
       cell, and a hint able to rewrite the claim number is a bug waiting to happen. */
    const CLAIM_AT = 2, STAKE_AT = 18;
    const seen = new Set(), folded = [];
    for (const r of rows) {
      const k = claimKey(r[CLAIM_AT]);
      if (seen.has(k)) continue;
      seen.add(k);
      const o = r.slice();
      o[SHEET_HINT_AT.assigningManager] = ""; o[SHEET_HINT_AT.allotmentManager] = "";
      o[SHEET_HINT_AT.manager] = ""; o[SHEET_HINT_AT.fo] = "";
      o[STAKE_AT] = ""; o[SHEET_HINT_AT.waiting] = "";
      /* v32.8 — THE VERDICT IS CUT OFF ENTIRELY, not blanked. Two empty columns headed
         "Verdict" would tell the insurer we keep a fraud reading on his claims while refusing
         to show it, which is the worst of both: it invites the question and answers nothing.
         His sheet ends at Still Pending With, exactly as it did before this version. */
      o.length = VERDICT_AT;
      folded.push(o);
    }
    return { columns: SHEET_COLUMNS.slice(0, VERDICT_AT), rows: folded, want };
  }
  /* THE VERDICT, WRITTEN IN LAST — one query for the whole sheet, not one per row. A database
     that will not answer leaves the two cells empty rather than losing the download. */
  try {
    const vm = await verdictMap(env, Array.from(new Set(rows.map(r => String(r[2] || "")).filter(Boolean))));
    for (const r of rows) {
      const g = vm[String(r[2] || "")];
      if (g) { r[VERDICT_AT] = verdictLabel(g.v) || g.v; r[VERDICT_WHY_AT] = g.reason || ""; }
    }
  } catch (e) { /* the sheet is the point */ }
  /* v33.8 — the OHS beside every field officer line, off the same Teams store the OHS TEAM
     table draws; two teams → both heads; no team → blank */
  try {
    const ix = await ohsIndexFor(env, me);
    if (ix.size) for (const r of rows) { const h = ix.heads(r[9]); r[OHS_AT] = h.length ? h.join(" / ") : ""; }
  } catch (e) { /* the sheet is the point */ }
  return { columns: SHEET_COLUMNS, rows, want };
}

/* ================= REAL EXCEL (.xlsx) WRITER — no library, hand-built =================
   Every "Excel" button in the portal comes through here, so every download looks the same:
   the 22 FO-Completed columns, a navy heading that stays put while you scroll, filter
   arrows on row 1, and columns already wide enough that nothing reads "#########".

   Why not CSV any more: a .csv makes Excel show the yellow "Possible Data Loss" bar, and
   it quietly turns a long claim number like 220210000123 into 2.2021E+11. A real .xlsx
   writes that claim number as TEXT, so what SKD typed is exactly what the sheet shows.

   An .xlsx file is really just a ZIP holding a handful of XML files, so the ZIP is built
   here by hand — no npm package, nothing extra to install on Cloudflare.                */

const XLSX_CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c; }
  return t;
})();
function xlsxCrc32(bytes) {
  let c = 0 ^ (-1);
  for (let i = 0; i < bytes.length; i++) c = (c >>> 8) ^ XLSX_CRC_TABLE[(c ^ bytes[i]) & 0xFF];
  return (c ^ (-1)) >>> 0;
}
// XML will not carry raw control characters, and one stray character makes Excel call the
// whole workbook corrupt — so they are dropped before anything else is escaped.
function xmlEsc(v) {
  return String(v == null ? "" : v)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
function xlsxColName(n) { let s = ""; while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = (n - m - 1) / 26; } return s; }
const XLSX_ENC = new TextEncoder();
async function xlsxDeflate(bytes) {
  // Cloudflare and modern browsers both have CompressionStream; if it is ever missing the
  // ZIP is written uncompressed instead, which Excel opens just the same (only bigger).
  try {
    if (typeof CompressionStream === "undefined") return null;
    const cs = new CompressionStream("deflate-raw");
    const out = new Response(new Blob([bytes]).stream().pipeThrough(cs));
    return new Uint8Array(await out.arrayBuffer());
  } catch (e) { return null; }
}
async function zipBytes(files) {
  const parts = [], central = [];
  let offset = 0, n = 0;
  for (const f of files) {
    const nameB = XLSX_ENC.encode(f.name);
    const raw = f.data;
    const crc = xlsxCrc32(raw);
    let body = await xlsxDeflate(raw), method = 8;
    if (!body || body.length >= raw.length) { body = raw; method = 0; }
    const lh = new Uint8Array(30 + nameB.length);
    const lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0, true);
    lv.setUint16(8, method, true); lv.setUint16(10, 0, true); lv.setUint16(12, 0x2821, true); // fixed 1/1/2000 stamp
    lv.setUint32(14, crc, true); lv.setUint32(18, body.length, true); lv.setUint32(22, raw.length, true);
    lv.setUint16(26, nameB.length, true); lv.setUint16(28, 0, true);
    lh.set(nameB, 30);
    parts.push(lh, body);
    const ch = new Uint8Array(46 + nameB.length);
    const cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0, true);
    cv.setUint16(10, method, true); cv.setUint16(12, 0, true); cv.setUint16(14, 0x2821, true);
    cv.setUint32(16, crc, true); cv.setUint32(20, body.length, true); cv.setUint32(24, raw.length, true);
    cv.setUint16(28, nameB.length, true); cv.setUint16(30, 0, true); cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true); cv.setUint16(36, 0, true); cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    ch.set(nameB, 46);
    central.push(ch);
    offset += lh.length + body.length; n++;
  }
  let cdSize = 0; for (const c of central) cdSize += c.length;
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(4, 0, true); ev.setUint16(6, 0, true);
  ev.setUint16(8, n, true); ev.setUint16(10, n, true);
  ev.setUint32(12, cdSize, true); ev.setUint32(16, offset, true); ev.setUint16(20, 0, true);
  let total = offset + cdSize + 22;
  const all = new Uint8Array(total);
  let p = 0;
  for (const b of parts) { all.set(b, p); p += b.length; }
  for (const c of central) { all.set(c, p); p += c.length; }
  all.set(eocd, p);
  return all;
}
// The only columns worth keeping as real numbers, so the day counts sort and total properly.
const XLSX_NUM_COLS = { "SKD TAT": 1, "SKD TAT-H": 1, "Alloted TAT": 1, "CAT TAT": 1 };
function xlsxSheetXml(columns, rows) {
  const nc = columns.length, nr = rows.length + 1;
  const ref = "A1:" + xlsxColName(nc) + nr;
  const numeric = columns.map(h => !!XLSX_NUM_COLS[h]);
  // Column widths from the widest thing actually in the column, so no cell shows #########.
  const widths = columns.map(h => String(h).length);
  for (const r of rows) for (let i = 0; i < nc; i++) { const L = String(r[i] == null ? "" : r[i]).length; if (L > widths[i]) widths[i] = L; }
  let cols = "<cols>";
  for (let i = 0; i < nc; i++) cols += '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + Math.min(60, Math.max(9, widths[i] + 3)) + '" customWidth="1"/>';
  cols += "</cols>";
  let sd = '<row r="1" ht="24" customHeight="1" s="1" customFormat="1">';
  for (let i = 0; i < nc; i++) sd += '<c r="' + xlsxColName(i + 1) + '1" s="1" t="inlineStr"><is><t xml:space="preserve">' + xmlEsc(columns[i]) + "</t></is></c>";
  sd += "</row>";
  for (let ri = 0; ri < rows.length; ri++) {
    const r = rows[ri], rn = ri + 2;
    sd += '<row r="' + rn + '">';
    for (let i = 0; i < nc; i++) {
      const raw = r[i] == null ? "" : r[i];
      const s = String(raw);
      if (s === "") continue;               // empty cells are simply left out — smaller file, same look
      const cell = xlsxColName(i + 1) + rn;
      if (numeric[i] && /^-?\d+(\.\d+)?$/.test(s.trim()) && s.trim().length < 15) sd += '<c r="' + cell + '"><v>' + s.trim() + "</v></c>";
      else sd += '<c r="' + cell + '" s="2" t="inlineStr"><is><t xml:space="preserve">' + xmlEsc(s) + "</t></is></c>";
    }
    sd += "</row>";
  }
  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
    '<dimension ref="' + ref + '"/>' +
    '<sheetViews><sheetView tabSelected="1" workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>' +
    '<sheetFormatPr defaultRowHeight="15"/>' + cols +
    "<sheetData>" + sd + "</sheetData>" +
    '<autoFilter ref="' + ref + '"/>' +
    '<pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>' +
    "</worksheet>";
}
const XLSX_STYLES = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
  '<numFmts count="1"><numFmt numFmtId="164" formatCode="@"/></numFmts>' +
  '<fonts count="2">' +
  '<font><sz val="11"/><color theme="1"/><name val="Calibri"/></font>' +
  '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>' +
  "</fonts>" +
  '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>' +
  '<fill><patternFill patternType="solid"><fgColor rgb="FF001F3F"/><bgColor indexed="64"/></patternFill></fill></fills>' +
  '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
  '<cellXfs count="3">' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
  '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>' +
  '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="center"/></xf>' +
  "</cellXfs>" +
  '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
  "</styleSheet>";
async function xlsxBytes(columns, rows, sheetName) {
  const nm = String(sheetName || "Cases").replace(/[\\\/\?\*\[\]:]/g, " ").slice(0, 31) || "Cases";
  const f = (name, str) => ({ name, data: XLSX_ENC.encode(str) });
  return await zipBytes([
    f("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'),
    f("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
    f("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="' + xmlEsc(nm) + '" sheetId="1" r:id="rId1"/></sheets></workbook>'),
    f("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'),
    f("xl/styles.xml", XLSX_STYLES),
    f("xl/worksheets/sheet1.xml", xlsxSheetXml(columns, rows))
  ]);
}
const XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
// One place that turns rows into the downloaded file, so every button behaves identically.
async function xlsxResponse(columns, rows, fileBase) {
  const body = await xlsxBytes(columns, rows, "Cases");
  // A button names its own file, so the name is scrubbed here — no slashes, no run of dots,
  // nothing that could read as a path in the browser's Save dialog.
  const safe = String(fileBase || "taasen-cases").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/\.{2,}/g, ".").replace(/^[-.]+|[-.]+$/g, "").slice(0, 90) || "taasen-cases";
  return new Response(body, { headers: { "Content-Type": XLSX_MIME, "Content-Disposition": 'attachment; filename="' + safe + '.xlsx"', "Cache-Control": "no-store" } });
}
/* A front-end button hands over the claim numbers it is showing; this turns them into the
   same 22 columns, keeping the order the screen was in and never inventing a claim the
   signed-in person is not allowed to see. Anything the live feed no longer carries still
   comes down as its own line, marked, so a list never quietly loses rows.               */
/* ── A ROW THAT SAID NOTHING BUT "Not in the live list" ──────────────────────────────────
   11-Aug-2026, from his own download: page after page of lines carrying a claim number and
   twenty-one empty boxes. The cause is honest enough — the sheet is rebuilt from the LIVE
   open feed, and a case that has since closed is no longer on it — but a blank line is
   useless in a meeting, and it made the workbook look broken.

   The screen asking for the download already KNOWS those cases: it is looking at them. So it
   may now send what it knows (`hints`, keyed by claim), and a case missing from the live feed
   is filled from that instead of coming back empty. Its Status still says so out loud, because
   a case that has left the open feed is a fact worth seeing — it is just no longer a blank. */
/* shifted one right of Assigning Manager on 13-Aug-2026 when Hospital Name took column G */
const SHEET_HINT_AT = { client: 0, sub: 1, insured: 3, assigningManager: 5, hospital: 6, allotmentManager: 7, manager: 8, fo: 9, createdOn: 11, tatD: 12, tatH: 13, state: 19, type: 20, caseStatus: 21, waiting: 22 };
function sheetRowFromHint(claim, h) {
  const row = SHEET_COLUMNS.map(() => "");
  row[2] = claim;
  if (h && typeof h === "object") {
    for (const k in SHEET_HINT_AT) {
      const v = h[k];
      if (v !== undefined && v !== null && String(v).trim() !== "") row[SHEET_HINT_AT[k]] = String(v);
    }
  }
  const st = h && h.status ? String(h.status).trim() : "";
  row[10] = st ? (st + " — no longer on the live open list") : "Not on the live open list now";
  return row;
}
function pickSheetRows(all, claims, fos, hints) {
  const list = (claims || []).map(x => String(x == null ? "" : x)).filter(s => s.trim() !== "");
  if (!list.length) return all;
  /* The screen may also say WHICH FIELD OFFICERS the list stands for — one man's own row, one
     OHS team, one state's men. Then only THOSE men's lines come down, so a team download is
     that team's work and not every other officer who happened to touch the same claim.
     Safety valve: if a claim carries no line for any of them (a name spelt differently in the
     feed, an officer since removed), all of that claim's lines come anyway — a case the man
     selected on screen is never silently dropped out of his workbook.                      */
  const want = new Set();
  (fos || []).forEach(n => String(n == null ? "" : n).split(/[,/]+/).forEach(t => { t = normName(t); if (t) want.add(t); }));
  const byKey = new Map();
  for (const r of all) { const k = claimKey(r[2]); if (!k) continue; if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(r); }
  const out = [], seen = new Set();
  for (const c of list) {
    const k = claimKey(c);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    const hit = byKey.get(k);
    if (hit) {
      let take = hit;
      if (want.size) { const mine = hit.filter(r => want.has(normName(r[9]))); if (mine.length) take = mine; }   // r[9] = FO Name since Hospital took G
      for (const r of take) out.push(r);
    }
    else out.push(sheetRowFromHint(c, hints && hints[claimKey(c)]));
  }
  return out;
}

/* ---- ONE LINE PER FIELD OFFICER ---------------------------------------------------------
   THIS IS THE FORMAT. Every case sheet this portal writes puts ONE ROW PER FIELD OFFICER,
   with the claim number repeated on each of his rows and HIS OWN status beside his name —
   the same shape SKD's own export uses.

   Sujit, 12-Aug-2026, holding the two files side by side:

       "I don't want like this — see, in one row it's showing Assigned and Partially
        Completed. I need in one row Completed and one row Assigned. Use the same claim
        number... change this format for every Excel wherever the option is there."

   THE HISTORY, so nobody repeats it. On 1 Aug 2026 the opposite was done: the rows were
   folded to one line per claim, because he had pressed a tile reading 322 and opened a
   workbook longer than 322 and read the extra lines as cases he had not asked for. The fold
   kept the promise of the number but paid for it by cramming three men into one cell —

       FO Name  SUBASH PANDIAN, SRIDHAYANITHI S, DINESH S
       Status   SUBASH PANDIAN — Fo Accepted; SRIDHAYANITHI S — Partially Completed; ...

   — which cannot be filtered, cannot be sorted by status, and cannot be pivoted. A cell you
   have to read with your eyes is not data. So the fold is gone and the promise is kept the
   honest way instead: the download pill names BOTH numbers, "217 cases · 260 lines", and the
   sheet says which is which. A bigger line count is the format working, not a leak.

   If you are here to make the sheet shorter, do not fold these rows. Give him a pivot or a
   second summary tab and leave the row per man alone.                                       */

function normalize(c) {
  const officers = Array.isArray(c.fieldOfficers) ? c.fieldOfficers.filter(Boolean) : [];
  return {
    claimNo: c.claimNumber || "", client: c.client || "", subProduct: c.subProduct || "",
    insured: pick(c, ["patientName", "insuredName", "insured", "patientname", "insured_name", "insuredPatientName", "patientFullName", "customerName", "claimantName", "memberName", "proposerName", "patient"]), officerName: officers.length ? officers.join(", ") : "",
    // the old SKD portal's "Contact number" field — auto-fills the calling pages.
    // Top-level first (the cheap, exact read), then the guarded nested dig — see digContactW.
    contactNo: pick(c, CONTACT_KEYS) || digContactW(c),
    manager: c.manager || "", assigningManager: c.assigningManager || "", allotmentManager: c.allotmentManager || "",
    reportManager: pick(c, ["reportManager", "reportingManager"]),
    hospitalName: pick(c, ["hospitalName", "hospital", "hospName", "hospitalname", "treatingHospital", "hospitalFullName"]),
    policeStation: pick(c, ["psName", "policeStation", "policeStationName", "police_station", "firPoliceStation", "firPsName", "stationName", "ps"]),
    hospitalState: c.hospitalState || "", insurerState: c.insurerState || "",
    /* ══════ WHERE THE CASE IS — v20.0 ═══════════════════════════════════════════════════
       Sujit, 31-Aug-2026: "I need this pin code to come to my portal, the pin code of
       insured and Hospital."

       Two pin codes and the two addresses they might be hiding inside, carried through from
       whatever SKD sends. Every one of these key names is a GUESS until /api/raw-open is
       read against the live feed — which is exactly why they cost nothing to be wrong about:
       pick() returns "" for a name that is not there, so a wrong guess is an empty string
       and a right one is a working feature the day Praveen turns the field on.

       The pin codes are what the allocation screen measures kilometres from. Where no pin
       field arrives, the ADDRESS is kept too, because "…, Anna Nagar, Madurai - 625020"
       carries the answer in its own text and pinInText digs it out. And where neither
       arrives, hospitalCity/insuredCity still put the case in a district. Four rungs, so
       the screen degrades honestly instead of going blank. */
    hospitalPin: pick(c, ["hospitalPincode", "hospitalPinCode", "hospitalPin", "hospital_pincode",
      "hospPincode", "hospitalZip", "hospitalPostalCode", "treatingHospitalPincode"]),
    insuredPin: pick(c, ["insuredPincode", "insuredPinCode", "insuredPin", "insured_pincode",
      "patientPincode", "patientPinCode", "claimantPincode", "customerPincode", "pincode",
      "pinCode", "pin_code", "postalCode", "zipCode", "addressPincode"]),
    hospitalAddress: pick(c, ["hospitalAddress", "hospital_address", "hospitalAddr",
      "hospitalFullAddress", "treatingHospitalAddress", "hospitalLocation"]),
    insuredAddress: pick(c, ["insuredAddress", "insured_address", "patientAddress",
      "claimantAddress", "customerAddress", "address", "communicationAddress", "residenceAddress"]),
    hospitalCity: pick(c, ["hospitalCity", "hospital_city", "hospCity", "hospitalDistrict", "hospitalTown"]),
    insuredCity: pick(c, ["insuredCity", "patientCity", "claimantCity", "customerCity", "city",
      "district", "insuredDistrict", "town"]),
    tat: c.skdTat || "", status: c.status || "", createdOn: c.createdOn || "", trigger: c.trigger || "",
    // ---- review-stage passthrough: fills the SR & TAT / Manager Completed columns IF the live feed carries them.
    //      Field names are best-guesses; confirm the real ones via /api/raw-open, then trim this list. ----
    cmReviewed: pick(c, ["cmReviewed", "cmReview", "cmReviewedDate", "cmReviewDate", "cmReviewStatus", "cmReviewedOn"]),
    qcReviewed: pick(c, ["qcReviewed", "qcReview", "qcReviewedDate", "qcReviewDate", "qcReviewStatus", "qcReviewedOn"]),
    caseReleased: pick(c, ["caseReleased", "released", "caseReleasedDate", "releaseDate", "releasedOn"]),
    reviewStage: pick(c, ["reviewStage", "caseStage", "stage", "currentStage", "statusStage"]),
    managerCompletedDate: pick(c, ["managerCompletedDate", "managerCompleted", "mgrCompletedDate"]),
    /* PRAVEEN'S KEYS, 6-Aug-2026. His mail: "I have updated the completed case API in the
       portal with the following specific keys: allotedDate, acceptedDateFo, catCompletedDate,
       reportingManager, reportingDoneDate. These keys are being used uniformly across the
       implementation." Three of the five were already in these lists (allotedDate,
       acceptedDateFo, reportingManager); reportingDoneDate is added here, and
       catCompletedDate feeds foCompletedDate below — see the note there. */
    reportingDate: pick(c, ["reportingDate", "reportDate", "reportedDate", "reportingDoneDate", "reportingDone"]),
    allotmentDate: pick(c, ["allotmentDate", "allocationDate", "allotedDate", "allottedDate", "allocatedDate"]),
    allotedTat: pick(c, ["allotedTat", "allotmentTat", "allocationTat", "allottedTat", "clientAllotedTat", "allotTat"]),
    catTat: pick(c, ["catTat", "catTAT", "catTatDays", "clientTat", "catTatValue", "catAgeing"]),
    catCompleted: pick(c, ["catCompleted", "catCompletedDate", "catCompletedOn", "clientCompletedDate", "catClosedDate"]),
    stackHolders: pick(c, ["stackHolders", "stakeHolders", "stakeholders", "stakeHolder", "stackHolder", "verificationType", "verificationTypes", "stakeHolderType"]),
    acceptedDate: pick(c, ["acceptedDateFo", "acceptedDate", "foAcceptedDate"]),
    /* catCompletedDate — Praveen's name for the date the case's field work was completed
       (his catTat / catCompleted pair: the target date and the date it was actually met).
       It fills the FO-Completed milestone ONLY when no explicit foCompletedDate arrives, so
       an explicit key can never be overridden by the inferred one. If a real case ever
       shows this reading a different milestone than intended, drop the last name from this
       list and the column honestly returns to "not sent" rather than lying. */
    foCompletedDate: pick(c, ["foCompletedDate", "fieldOfficerCompletedDate", "catCompletedDate"]),
    finalConclusion: pick(c, ["finalConclusion", "conclusion", "caseConclusion"]),
    reason: pick(c, ["reason", "conclusionReason", "finalReason"]),
    rtaFlag: /motor tp|accident|\brta\b/i.test((c.subProduct || "") + " " + (c.trigger || "")),
    product: productOf(c.subProduct || "")          /* v33.7 — TP · Health · OD · MBV, decided once, here */
  };
}
/* the last good open-case list, kept in memory — served (marked, dated) while SKD is down */
let OPEN_LAST = null;   // { ts, d }
/* v34.3 — AND KEPT IN R2, because the memory above is one isolate's memory. Cloudflare runs this
   Worker as many short-lived isolates, so on the morning it mattered (25-Sep) the isolate that
   answered the dashboard had never seen a good book and fell to the demo case, while another
   isolate a minute earlier had one. Every good read is written to book/open-cases.json (at most
   once every two minutes per isolate, ~1 MB); a failed read looks there when memory is empty.
   The copy is served for up to two days, always marked stale with the time it was read. */
const OPEN_BOOK_KEY = "book/open-cases.json", OPEN_BOOK_PUT_MS = 2 * 60 * 1000, OPEN_BOOK_MEMORY_MS = 6 * 3600 * 1000, OPEN_BOOK_KEEP_MS = 48 * 3600 * 1000;
let OPEN_BOOK_PUT_AT = 0;
async function keepOpenBook(env, d, ts, force) {
  if (!env || !env.PHOTOS || !d || !d.cases || !d.cases.length) return false;
  if (!force && ts - OPEN_BOOK_PUT_AT < OPEN_BOOK_PUT_MS) return false;
  OPEN_BOOK_PUT_AT = ts;
  try { await env.PHOTOS.put(OPEN_BOOK_KEY, JSON.stringify({ ts, total: d.total, cases: d.cases }), { httpMetadata: { contentType: "application/json" }, customMetadata: { ts: String(ts) } }); return true; }
  catch (e) { return false; }
}
async function lastOpenBook(env) {
  if (OPEN_LAST && (Date.now() - OPEN_LAST.ts) < OPEN_BOOK_MEMORY_MS) return { ts: OPEN_LAST.ts, d: OPEN_LAST.d, from: "memory" };
  if (!env || !env.PHOTOS) return null;
  try {
    const o = await env.PHOTOS.get(OPEN_BOOK_KEY);
    if (!o) return null;
    const j = JSON.parse(await o.text());
    if (!j || !Array.isArray(j.cases) || !j.cases.length) return null;
    const ts = Number(j.ts) || 0;
    if (!ts || Date.now() - ts > OPEN_BOOK_KEEP_MS) return { ts, d: null, from: "r2", tooOld: true };
    const d = { total: j.total != null ? j.total : j.cases.length, cases: j.cases };
    OPEN_LAST = { ts, d };
    return { ts, d, from: "r2" };
  } catch (e) { return null; }
}
export const _openBook = { forget() { OPEN_LAST = null; OPEN_BOOK_PUT_AT = 0; OPEN_INFLIGHT = null; BOOK_HEAD_AT = 0; }, headNow() { BOOK_HEAD_AT = 0; }, key: OPEN_BOOK_KEY, pulls() { return OPEN_PULLS; }, last() { return OPEN_LAST; } };
/* ══════════ THE BOOK KEEPER — v34.7, 26-Sep-2026 ═══════════════════════════════════════════
   Sujit, 11:09 am, the amber strip across every member's screen: "This error is coming for
   everyone … I gave around 80 members access … I am ready to pay any amount … I want fully
   faster." Measured a minute later: SKD's API hands the whole open book (1,558 cases, ~2 MB) in
   10 to 30 seconds, swinging above and below our 25-second line all day. Their site is fast
   because it never asks for the whole book. And WE were asking for it once per member per page —
   hundreds of whole-book pulls an hour queuing on their server, so more of them crossed 25 s.

   So the book is pulled ONCE and served to everyone:
     · the keeper (bookTick, from the cron every 2 minutes) pulls the book with a 90-second window
       — nobody is waiting on it — and writes it to R2 with its time;
     · every door reads the copy: this isolate's memory while it is under 30 s old, then R2's
       stamp (a cheap head), adopting a newer copy when the keeper — or another isolate — wrote
       one; a copy under FIVE minutes old IS the book, and no member ever waits on SKD;
     · a copy older than five minutes (the keeper failing, SKD down) makes the request pull for
       itself, bounded 25 s as before, falling to the stale copy with the amber strip if that
       fails — exactly v34.3's ladder;
     · anything the portal itself does at SKD (assign, deactivate, a new case) re-pulls at once
       in the background (bookRefresh), so a case acted on through the portal shows on the next
       page; changes made on SKD's own screens show within two minutes;
     · ?fresh=1 (the strip's Try again) forces a live pull for that one request.
   His 24-Sep rule — no memo, a case acted on must show at once — is kept for everything the
   portal does; only changes made outside the portal wait up to two minutes. He said the word
   on 26-Sep. Not a secret, not a binding: the PHOTOS bucket the Worker already has.          */
const BOOK_FRESH_MS = 5 * 60 * 1000, BOOK_MEMORY_MS = 30 * 1000, BOOK_HEAD_EVERY_MS = 10 * 1000, BOOK_PULL_MS = 90 * 1000;
let BOOK_HEAD_AT = 0, OPEN_INFLIGHT = null, OPEN_PULLS = 0;   /* one pull at a time (v34.3), counted for the tests */
/* one pull from SKD, shared by everybody who asks while it runs; keeps memory and R2 */
async function pullBook(env, opts) {
  if (OPEN_INFLIGHT) return OPEN_INFLIGHT;
  const timeoutMs = (opts && opts.timeoutMs) || skdTmo(env, "SKD_TIMEOUT_MS", 25000), taker = (opts && opts.taker) || "request";
  OPEN_INFLIGHT = (async () => {
    const t0 = Date.now();
    OPEN_PULLS++;
    try {
      const r = await skdGet(env, "/cases/open-cases", { timeoutMs });
      const raw = await readSkdJson(r, "open cases");
      const list = Array.isArray(raw.data) ? raw.data : (Array.isArray(raw) ? raw : []);
      const d = { total: raw.total != null ? raw.total : list.length, cases: list.map(normalize) };
      if (d.cases.length) { const ts = Date.now(); OPEN_LAST = { ts, d }; await keepOpenBook(env, d, ts, !!(opts && opts.force)); }
      try { await stSoft(env, "book:pull", JSON.stringify({ at: Date.now(), ok: true, ms: Date.now() - t0, total: d.cases.length, by: taker })); } catch (e) { }
      return d;
    } catch (e) {
      try { await stSoft(env, "book:pull", JSON.stringify({ at: Date.now(), ok: false, ms: Date.now() - t0, error: String((e && e.message) || e), by: taker })); } catch (x) { }
      throw e;
    }
  })();
  try { return await OPEN_INFLIGHT; } finally { OPEN_INFLIGHT = null; }
}
/* the keeper's own firing: a generous window, R2 written every time */
export async function bookTick(env, now) {
  try { const d = await pullBook(env, { timeoutMs: BOOK_PULL_MS, taker: "keeper", force: true }); return { ok: true, total: d.cases.length }; }
  catch (e) { return { ok: false, why: String((e && e.message) || e) }; }
}
/* after something the portal itself did at SKD: pull again now, in the background */
export function bookRefresh(env, ctx, why) {
  const p = pullBook(env, { taker: "after " + (why || "action"), force: true }).catch(() => null);
  try { if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p); } catch (e) { }
  return p;
}
/* the copy R2 holds, adopted when it is newer than what this isolate remembers */
async function adoptBookFromR2(env, now) {
  if (!env || !env.PHOTOS) return false;
  if (now - BOOK_HEAD_AT < BOOK_HEAD_EVERY_MS) return false;
  BOOK_HEAD_AT = now;
  try {
    const h = await env.PHOTOS.head(OPEN_BOOK_KEY);
    const ts = Number(h && h.customMetadata && h.customMetadata.ts) || 0;
    if (!ts || (OPEN_LAST && ts <= OPEN_LAST.ts)) return false;
    const o = await env.PHOTOS.get(OPEN_BOOK_KEY);
    if (!o) return false;
    const j = JSON.parse(await o.text());
    if (!j || !Array.isArray(j.cases) || !j.cases.length) return false;
    OPEN_LAST = { ts: Number(j.ts) || ts, d: { total: j.total != null ? j.total : j.cases.length, cases: j.cases } };
    return true;
  } catch (e) { return false; }
}
/* THE BOOK, for every door in this file and the modules: the copy while it is fresh, a pull
   of its own only when there is no fresh copy (or opts.fresh asks for one) */
async function getCases(env, opts) {
  const now = Date.now();
  if (!(opts && opts.fresh)) {
    if (OPEN_LAST && now - OPEN_LAST.ts < BOOK_MEMORY_MS) return OPEN_LAST.d;
    await adoptBookFromR2(env, now);
    if (OPEN_LAST && now - OPEN_LAST.ts < BOOK_FRESH_MS) return OPEN_LAST.d;
  }
  return pullBook(env, { taker: (opts && opts.fresh) ? "fresh" : "request" });
}

/* ---------- COMPLETE (closed) cases — Praveen's "Get Cases by Status" API ----------
   The Complete-cases button used to filter the OPEN-case feed in the browser, which can
   never work: a case drops off /cases/open-cases the moment it is completed, so the one
   list we were searching is the one list that cannot contain a closed case.
   This calls the real status endpoints instead — one per review milestone — and unions
   the answers. Every call made is reported back in `diag` (URL, HTTP code, row count),
   so the screen can show exactly what it asked for and exactly what came back. */
/* DM REVIEWED IS NO LONGER ASKED FOR — Sujit's instruction of 5-Aug-2026.
   It answered HTTP 200 with {"isAttendance":true,"cases":[]} every single time: not a closed
   case in it, ever. Asking for it bought nothing and cost a whole round trip to a server that
   is already the slow part of this screen, so the screen now asks for the two lists that
   actually carry closed cases. The line is left here, commented, so it can be switched back on
   in one move the day that endpoint starts answering properly. */
const COMPLETE_BUCKETS = [
  { type: "cm-reviewed", flag: "cmReviewed", label: "CM Reviewed" },
  { type: "qc-reviewed", flag: "qcReviewed", label: "QC Reviewed" }
  // { type: "dm-reviewed", flag: "dmReviewed", label: "DM Reviewed" }
];

/* Status rows are shaped differently from open-case rows — createdDate not createdOn,
   managerName not manager, cmNumber for the contact — so alias them across BEFORE
   normalize() sees them, otherwise every one of those columns arrives blank. */
function aliasStatusRow(r) {
  const c = Object.assign({}, r);
  if (c.createdOn == null && c.createdDate != null) c.createdOn = c.createdDate;
  if (c.manager == null && c.managerName != null) c.manager = c.managerName;
  if (c.contactNumber == null && c.cmNumber != null) c.contactNumber = c.cmNumber;
  if (c.claimNumber == null && c.claimNo != null) c.claimNumber = c.claimNo;
  /* THE FIELD OFFICER AND THE TAT, whatever this API decided to call them.
     normalize() below reads the officer out of `fieldOfficers` and the TAT out of `skdTat`,
     because that is what the OPEN-case feed sends. The status feed is a different feed with
     different spellings, so on the Complete-cases screen both arrived empty — which is why
     every closed case showed its state as "(Unknown)" and every one of them landed in the
     "≤ 4h" column: an empty TAT reads as nought hours, and nought hours is inside four.
     A wrong nought is worse than a blank, so the names are gathered here and the reading
     below refuses to guess when there is still nothing to read. */
  if (c.fieldOfficers == null) {
    const fo = pick(c, ["fieldOfficers", "fieldOfficerName", "fieldOfficerNames", "fieldOfficer",
      "foName", "foNames", "officerName", "officerNames", "assignedFo", "assignedTo",
      "investigatorName", "investigator", "empName", "employeeName"]);
    if (fo) c.fieldOfficers = Array.isArray(fo) ? fo : String(fo).split(/\s*[,/|;]\s*/).filter(Boolean);
  }
  if (c.skdTat == null || c.skdTat === "") {
    const t = pick(c, ["skdTat", "skdTAT", "tat", "TAT", "tatDays", "tatHours", "caseTat",
      "ageing", "ageingDays", "age", "totalTat", "turnAroundTime", "turnaroundTime"]);
    if (t !== "" && t != null) c.skdTat = t;
  }
  /* THE THREE MEN ON THE JOURNEY. The Case Journey screen follows a case from the day it is
     made to the day the manager closes it — created → allotted → accepted by the field officer
     → completed by him → reported → completed by the manager — and it names the man at each
     handover. normalize() reads these three straight off the row (no alias list), so on the
     status feed they arrived blank whatever the feed happened to call them. Gathered here.
     Nothing is invented: what still does not arrive stays empty, and the screen says
     "not sent" out loud rather than leaving a blank that could be read as a good result. */
  if (!c.assigningManager) c.assigningManager = pick(c, ["assigningManager", "assignManager", "assignedManager", "assigningManagerName", "assignedBy", "caseAssignedBy"]);
  if (!c.allotmentManager) c.allotmentManager = pick(c, ["allotmentManager", "allocationManager", "allotManager", "allottingManager", "allotmentManagerName", "allocatedBy", "allottedBy"]);
  if (!c.reportManager) c.reportManager = pick(c, ["reportManager", "reportingManager", "reportedManager", "reportManagerName", "reportedBy"]);
  return c;
}
function statusListOf(raw) {
  if (Array.isArray(raw)) return raw;
  if (!raw || typeof raw !== "object") return [];
  for (const k of ["cases", "data", "content", "result", "records"]) if (Array.isArray(raw[k])) return raw[k];
  return [];
}
// One status call. Never throws — a dead endpoint must still be reportable on screen.
async function probeStatusList(env, type, qs, opts) {
  const path = "/cases/status/" + type + (qs ? "?" + qs : "");
  const d = { type, path, httpStatus: 0, rows: 0, bytes: 0, list: [] };
  try {
    const r = await skdGet(env, path, opts);
    d.httpStatus = r.status;
    const text = await r.text();
    d.bytes = text.length;
    /* 502 / 503 / 504 / 524 are not an answer at all — they mean their server was still working
       when the line was cut. Say that in words. "Response was not JSON" sent everybody hunting
       for a formatting fault that never existed; the real cure is a smaller date window. */
    if (r.status >= 500) { d.error = "their server did not finish in time (HTTP " + r.status + ") — ask for a smaller date window"; return d; }
    let raw = null;
    try { raw = JSON.parse(text); } catch (e) { d.error = "response was not JSON"; return d; }
    d.list = statusListOf(raw);
    d.rows = d.list.length;
    if (!d.rows && text.length < 300) d.emptyBody = text;   // e.g. {"isAttendance":true,"cases":[]}
  } catch (e) { d.error = String(e && e.message ? e.message : e); }
  return d;
}
/* ── THE PAGES NOBODY MENTIONED ──────────────────────────────────────────────────────────
   Proven live on 20-Aug-2026, on Sujit's own signed-in session, against
   /cases/status/cm-reviewed:
     · fromDate/toDate are IGNORED — one day asked, two days answered, byte-identical
       (tried as 2026-08-19 and as 26-08-19, both);
     · pageSize is IGNORED — pageSize=100 and pageSize=500 both answered the same 220 rows;
     · page WORKS — page=1 is the same 220 rows the plain call serves, but page=2 answered
       29 FURTHER closed cases and page=3 another 20: real cases the plain call never shows.
       That is where a slice of "why is the completed number very less" was living.
   So every closed-case pull now WALKS the pages and unions them by claim number. The walk
   stops at the first empty page, at the first page that adds nothing new (their pages carry
   no visible ordering contract, so a repeating page must end the walk rather than loop it),
   or at page 8 — a hard stop so a misbehaving server cannot eat the whole sweep. Page 1 is
   asked exactly as before, so the day their server changes again the portal is no worse
   than it was — and the per-page counts ride along in diag, so the screen can SAY what the
   paging recovered instead of it being a matter of faith. */
async function probeStatusListPaged(env, type, qs, opts) {
  const first = await probeStatusList(env, type, qs, opts);
  first.pages = [{ page: 1, rows: first.rows, added: first.rows, error: first.error || "" }];
  if (first.error || !first.rows) return first;
  const keyOfRow = r => claimKey(r && (r.claimNumber != null ? r.claimNumber : r.claimNo));
  const seen = new Set(first.list.map(keyOfRow).filter(Boolean));
  for (let pg = 2; pg <= 8; pg++) {
    const d = await probeStatusList(env, type, (qs ? qs + "&" : "") + "page=" + pg, opts);
    const added = [];
    for (const row of d.list) {
      const k = keyOfRow(row);
      if (!k || seen.has(k)) continue;
      seen.add(k); added.push(row);
    }
    first.pages.push({ page: pg, rows: d.rows, added: added.length, error: d.error || "" });
    if (added.length) {
      first.list = first.list.concat(added);
      first.rows = first.list.length;
      first.bytes += d.bytes || 0;
    }
    if (d.error || !d.rows || !added.length) break;
  }
  return first;
}
/* THE DATE WINDOW IS NOW COMPULSORY — Praveen's instruction of 5-Aug-2026.
   Asking /cases/status/... for everything is what made their server run past Cloudflare's
   limit and answer HTTP 524. So a window is ALWAYS sent, and if the screen sends none we
   open on the last seven days ourselves. */
const COMPLETE_DEFAULT_DAYS = 7;
function ymdIST(ms) { return new Date(ms + 19800000).toISOString().slice(0, 10); }   // India time, not UTC
function lastNDayWindow(n) {
  const now = Date.now();
  return { from: ymdIST(now - (n - 1) * 86400000), to: ymdIST(now) };
}
/* Did a status row really carry a field officer / a TAT? Asked through the same normalize()
   the screen is fed from, so the answer on the screen is the answer the screen is living with —
   not a separate opinion that could drift away from it. */
function sentFo(row) {
  if (!row || typeof row !== "object") return false;
  const n = normalize(aliasStatusRow(row));
  return !!String(n.officerName || "").trim();
}
function sentTat(row) {
  if (!row || typeof row !== "object") return false;
  const n = normalize(aliasStatusRow(row));
  return String(n.tat || "").trim() !== "";
}
/* ── A SHORT MEMORY, SO THE SAME QUESTION IS NOT ASKED TWICE ──────────────────────────────
   The slow part of the Complete-cases screen is not this portal, it is the wait on SKD's
   server: one window can be several megabytes and takes them a long time to put together —
   long enough that asking for everything at once used to time out at HTTP 524.

   Until now EVERY visit asked again from scratch. Going Open → Complete → Open → Complete, or
   pressing Refresh, meant sitting through that same wait each time for an answer that had not
   changed. So the answer for a window is now kept for five minutes and handed straight back.

   Five minutes, not longer, because these are closed cases being reviewed through the day and
   a stale list would be its own kind of wrong. The screen is told when it got a kept copy and
   how old it is, so nobody is ever looking at something older than they think. Pressing
   Refresh clears the memory first, so Refresh always means what it says. */
const COMPLETE_CACHE = new Map();          // "from|to" -> { ts, payload }
const COMPLETE_CACHE_MS = 5 * 60 * 1000;
function completeCacheGet(key) {
  const hit = COMPLETE_CACHE.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts > COMPLETE_CACHE_MS) { COMPLETE_CACHE.delete(key); return null; }
  return hit;
}
function completeCachePut(key, payload) {
  if (COMPLETE_CACHE.size > 12) COMPLETE_CACHE.clear();   // a handful of windows is plenty
  COMPLETE_CACHE.set(key, { ts: Date.now(), payload });
}

/* ONE PULL PER WINDOW AT A TIME. On the morning SKD slowed down, every open browser tab
   asked for its own copy of the same window, each reload added another, and a struggling
   server was made to do the same heavy work ten times over. Now the first request starts
   the pull and everyone else asking for the SAME window simply waits for that one answer. */
const COMPLETE_PENDING = new Map();
async function getCompleteCases(env, from, to, opts) {
  const asked = !!(from && to);
  const win = asked ? { from, to } : lastNDayWindow(COMPLETE_DEFAULT_DAYS);
  const cacheKey = win.from + "|" + win.to;
  const oldHit = COMPLETE_CACHE.get(cacheKey) || null;   // kept aside — the stale copy of last resort
  /* ── THE HISTORY, UNIONED IN — ON EVERY ANSWER, NOT ONLY THE FIRST ──────────────────
     Everything downstream — CM Reviewed, Claim Match, the Analytics complete dataset —
     comes through this one function, so the archive is added here and nowhere else. Live
     rows are kept as they are and only claims the live feed does NOT carry are added, so
     today's truth always wins over a copy taken at a moment in time.

     v20.3, 02-Sep — Sujit: "the completed CM review is not coming correctly." It was not:
     the union used to run only after a FRESH pull, while the five-minute memory held the
     pre-union copy. So the first open of CM Reviewed showed live + archive, and any open in
     the next five minutes served the memory — live rows only — and the list SHRANK. Two
     answers to one question, depending on the second hand. The union now runs on the way
     out whichever door the rows came through. */
  const withArchive = async (payload) => {
    try {
      const arch = await archiveInWindow(env, win.from, win.to);
      if (!arch.length) return payload;
      const m = mergeArchive(payload.cases || [], arch);
      return Object.assign({}, payload, {
        cases: m.cases, total: m.cases.length,
        archiveAdded: m.added, archiveWindow: win.from + " to " + win.to
      });
    } catch (e) { return payload; }   // a bad archive must never break the live answer
  };
  if (opts && opts.fresh) COMPLETE_CACHE.delete(cacheKey);
  else {
    const hit = completeCacheGet(cacheKey);
    if (hit) return withArchive(Object.assign({}, hit.payload, { fromMemory: true, memoryAgeSec: Math.round((Date.now() - hit.ts) / 1000) }));
  }
  if (COMPLETE_PENDING.has(cacheKey)) return COMPLETE_PENDING.get(cacheKey);
  const job = pullCompleteCases(env, win, cacheKey, asked, oldHit).then(withArchive);
  COMPLETE_PENDING.set(cacheKey, job);
  try { return await job; }
  finally { COMPLETE_PENDING.delete(cacheKey); }
}
async function pullCompleteCases(env, win, cacheKey, asked, oldHit) {
  const dateQs = "fromDate=" + win.from + "&toDate=" + win.to;
  const statusTmo = { timeoutMs: skdTmo(env, "SKD_STATUS_TIMEOUT_MS", 75000) };
  const probes = await Promise.all(COMPLETE_BUCKETS.map(b => probeStatusListPaged(env, b.type, dateQs, statusTmo)));
  const widened = false;
  /* The old blind "retry over 2020 → today" is GONE on purpose. It doubled the load on their
     server for nothing (it came back 404), and it broke the house rule that whatever window is
     picked on screen is the ONLY window we ask for. What you choose is what you get. */

  // union by claim number — a case that is both CM and QC reviewed is ONE row carrying both flags
  const byClaim = new Map();
  probes.forEach((p, i) => {
    const b = COMPLETE_BUCKETS[i];
    p.list.forEach(row => {
      const n = normalize(aliasStatusRow(row));
      const key = String(n.claimNo || "").trim().toUpperCase();
      const prev = key ? byClaim.get(key) : null;
      const tgt = prev || n;
      if (!prev) { tgt.statusBuckets = []; if (tgt.dmReviewed == null) tgt.dmReviewed = ""; }
      if (!tgt[b.flag]) tgt[b.flag] = "Yes";   // never overwrite a real date, if he adds them later
      if (tgt.statusBuckets.indexOf(b.label) < 0) tgt.statusBuckets.push(b.label);
      if (!prev) byClaim.set(key || ("row-" + byClaim.size), tgt);
    });
  });

  const cases = Array.from(byClaim.values());
  const diag = probes.map((p, i) => ({
    label: COMPLETE_BUCKETS[i].label, type: p.type, url: env.SKD_API_BASE + p.path,
    httpStatus: p.httpStatus, rows: p.rows, bytes: p.bytes || 0,
    /* the page walk, page by page — how many rows each answered and how many were NEW */
    pages: p.pages || [],
    error: p.error || "", emptyBody: p.emptyBody || "", retriedWideWindow: p.retriedWideWindow || "",
    /* THE COLUMN NAMES THIS FEED ACTUALLY SENT — names only, never the contents, so no
       patient's details are ever printed on the screen. Without this, a column that arrives
       blank leaves nobody any the wiser as to whether the feed omitted it or we simply looked
       for it under the wrong name. Now the answer is on the screen. */
    fields: (p.list && p.list.length && p.list[0] && typeof p.list[0] === "object")
      ? Object.keys(p.list[0]).slice(0, 60) : [],
    /* and, plainly: did the two that were missing arrive this time? Read through normalize(),
       so this says what the screen will really get rather than what we hoped for. */
    hasFo: sentFo(p.list && p.list[0]),
    hasTat: sentTat(p.list && p.list[0])
  }));
  const payload = { total: cases.length, cases, diag, widened, window: win, defaultedWindow: !asked, days: COMPLETE_DEFAULT_DAYS };
  /* Only a real answer is worth keeping. If their server timed out or sent nothing back, that
     must not be held for five minutes — the next press has to be free to try again. */
  const gotSomething = cases.length > 0 && probes.some(p => p.httpStatus === 200 && !p.error);
  if (gotSomething) completeCachePut(cacheKey, payload);
  /* and if this pull FAILED but a good copy of the same window exists from the last two
     hours, serve that copy — marked stale, with its age — rather than an empty list that
     reads as "no closed cases". FAILED means every call errored or answered 4xx/5xx or
     never connected. An honest 200-with-no-rows is a REAL answer — their server saying
     "nothing in this window" — and must never be papered over with an old copy. */
  if (!gotSomething && probes.every(p => p.error || p.httpStatus >= 400 || p.httpStatus === 0)
      && oldHit && (Date.now() - oldHit.ts) < 2 * 3600 * 1000 && (oldHit.payload.cases || []).length) {
    return Object.assign({}, oldHit.payload, {
      stale: true, memoryAgeSec: Math.round((Date.now() - oldHit.ts) / 1000), failedDiag: diag
    });
  }
  return payload;
}

/* ---------- role scoping (coordinator -> FO state, manager -> manager name) ---------- */
function normName(s) { return s == null ? "" : String(s).replace(/\s+/g, " ").trim().toLowerCase(); }
function firstFO(name) { return name ? String(name).split(/[,/]/)[0].trim() : ""; }

// Build a { normalized-officer-id : {state, region} } map from the Get-All-FO-Details API.
/* ---- ONE state for Andhra Pradesh + Telangana ----------------------------------
   Sujit runs AP and Telangana as a single territory, so every state name the portal
   shows or scopes by collapses into one: "Andhra Pradesh & Telangana". */
const AP_TS_LABEL = "Andhra Pradesh & Telangana";
function canonState(s) {
  const v = String(s == null ? "" : s).trim();
  if (!v) return v;
  const k = v.toLowerCase().replace(/[^a-z]/g, "");
  if (k === "andrapradesh" || k === "andhrapradesh" || k === "ap" || k === "andra" || k === "andhra" ||
      k === "telungana" || k === "telangana" || k === "telengana" || k === "ts" || k === "tg" ||
      k === "andhrapradeshtelangana" || k === "andrapradeshtelungana" || k === "apts" || k === "aptelangana") return AP_TS_LABEL;
  return v;
}
async function getFoStateMap(env) {
  const cfg = (env.SKD_FO_PATH || SKD_FO_PATH_DEFAULT || "").trim();
  if (!cfg) return {};
  const target = /^https?:\/\//i.test(cfg) ? cfg : (env.SKD_API_BASE + cfg);
  try {
    let token = await getToken(env);
    let r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } });
    if (r.status === 401) { token = await getToken(env, true); r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } }); }
    const raw = await r.json();
    const list = Array.isArray(raw) ? raw : ((raw && (raw.users || raw.data || raw.officers || raw.fos || raw.fieldOfficers || raw.result || raw.list)) || []);
    const map = {};
    if (Array.isArray(list)) for (const o of list) {
      if (!o || typeof o !== "object") continue;
      const fn = String(o.firstName || "").trim();
      const ln = String(o.lastName || "").trim();
      const un = String(o.userName || o.username || "").trim();
      const generic = String(o.name || o.foName || o.fieldOfficerName || o.fullName || o.officerName || o.empName || o.employeeName || "").trim();
      const state = canonState(String(o.state || o.foState || o.stateName || o.State || "").trim());
      const region = String(o.region || o.foRegion || o.district || o.zone || o.Region || "").trim();
      if (!state && !region) continue;
      const keys = [];
      if (fn || ln) keys.push(normName((fn + " " + ln).trim()));
      if (fn) keys.push(normName(fn));
      if (un) keys.push(normName(un));
      if (generic) keys.push(normName(generic));
      for (const k of keys) if (k && !map[k]) map[k] = { state, region };
    }
    return map;
  } catch (e) { return {}; }
}

// A case's field-officer info: try the whole officer string, then just the first officer name.
/* every man on a shared claim, in the order SKD wrote them — "A, B, C" → [A, B, C] */
function officersOnCase(officerName) {
  return String(officerName == null ? "" : officerName).split(/[,/]+/).map(x => x.trim()).filter(Boolean);
}
function foInfoOf(officerName, foMap) {
  if (!officerName || !foMap) return null;
  return foMap[normName(officerName)] || foMap[normName(firstFO(officerName))] || null;
}

/* ══════════ A FIELD OFFICER'S CONTACT NUMBER ══════════════════════════════════════════
   Sujit, 11-Aug-2026, on the Field Officer Directory: "I need in this contact number also."

   Two sources, in this order:
     1. the SKD Get-All-FO-Details API, under whichever of the usual spellings it uses
     2. the portal's own phone book (KV "fo:phones") — typed in, or pasted from a sheet,
        on the Field Officers page itself

   Source 1 may well be empty: that same API sends no Status and no Case Limit today, which
   is why those two columns read "—" for all 187 men. So the book exists to make the column
   useful on the day it ships instead of on the day Praveen adds a field.

   A number is shown only if it survives foPhoneClean. A ten-digit Indian mobile or nothing —
   an all-same-digit dummy is thrown away, because the whole Acefone week was lost to a
   number that LOOKED like a number (+913333333333) and could not exist. A blank tells the
   truth; a wrong number sends a manager to a dead line at 9pm.                            */
const FO_PHONE_KEYS = ["mobile", "mobileNo", "mobileNumber", "mobile_no", "mobileNum", "mobno", "mobNo",
  "phone", "phoneNo", "phoneNumber", "phone_no", "contact", "contactNo", "contactNumber", "contact_no",
  "contactNum", "primaryContact", "primaryMobile", "userMobile", "userPhone", "userContact",
  "empMobile", "employeeMobile", "officerMobile", "foMobile", "foPhone", "foContact",
  "cell", "cellNo", "cellPhone", "alternateMobile", "altMobile", "whatsappNo", "whatsappNumber", "msisdn",
  "Mobile", "MobileNo", "MobileNumber", "Phone", "PhoneNo", "PhoneNumber", "Contact", "ContactNo", "ContactNumber"];
function foPhoneClean(v) {
  let s = String(v == null ? "" : v).trim();
  if (!s) return "";
  s = s.split(/[,;|\/]/)[0].trim();                                 // "98xxxxxxxx / 99xxxxxxxx" -> the first one
  let d = s.replace(/[^\d]/g, "");
  if (d.length > 10 && d.slice(0, 2) === "91") d = d.slice(2);      // +91 98xxxxxxxx
  while (d.length > 10 && d.charAt(0) === "0") d = d.slice(1);      // 0 98xxxxxxxx
  if (d.length !== 10) return "";
  if (!/^[6-9]/.test(d)) return "";                                 // an Indian mobile begins 6, 7, 8 or 9
  if (/^(\d)\1{9}$/.test(d)) return "";                             // 3333333333 — a placeholder, not a man
  return d;
}
function foPhoneFromRow(o) { for (const k of FO_PHONE_KEYS) { if (o[k] === undefined) continue; const c = foPhoneClean(o[k]); if (c) return c; } return ""; }
async function foPhoneBook(env) { if (!env.USERS) return {}; try { return JSON.parse(await stGet(env, "fo:phones") || "{}") || {}; } catch (e) { return {}; } }
// Who may CHANGE a number. Everyone with the Field Officers page may READ one.
function foPhoneEditor(u) { return !!u && (u.role === "admin" || u.role === "boss" || u.role === "hr"); }

// Full FO roster [{name, state, region, phone}] for the OHS Team page: live from the Get-All-FO-
// Details API (Field_Officer rows only), state filled from the API or the baked FO_DIRECTORY; if
// the API is unreachable, the baked directory alone is the fallback so the page still works.
/* ══════════ WHO COUNTS AS A FIELD OFFICER ════════════════════════════════════════════
   Sujit, 12-Aug-2026: "Bring Operation Head also in the field officer bucket... Team_Head_FO,
   that also you have to come in the field officer bucket only."

   Every person in SKD's Manage User carries a role string. Until today this kept only the
   rows with "field" in them, which quietly dropped two kinds of men:

     Veeraraju ongole   Field_Officer, Team_Head_FO   -> kept (because of Field_Officer)
     a Team Head with only Team_Head_FO               -> DROPPED, though he works the field
     Buddepalli Mohan   Operation_Head                -> DROPPED, every one of them

   They were missing from the directory, from the check-in dropdown, and from the not-filled
   count — so a location they filed could never match anybody. All three roles now count.
   The label is carried alongside so the screen can say WHICH of the three a man is, rather
   than quietly calling an Operation Head a field officer.                                */
const FO_ROLE_RE = /(field|team[_ ]?head[_ ]?fo|operation[_ ]?head)/i;
function foRolesText(o) {
  const r = o.roles !== undefined ? o.roles : (o.role !== undefined ? o.role : o.userRole);
  if (r === undefined || r === null || r === "") return "";
  return Array.isArray(r) ? r.join(",") : String(r);
}
function foRoleWanted(o) {
  const s = foRolesText(o);
  if (!s) return true;                               // an FO-only feed sends no roles — keep everyone
  if (FO_ROLE_RE.test(s)) return true;
  return /(^|[,;\s])(fo|oh)([,;\s]|$)/i.test(s);     // some records carry only the short code
}
function foRoleLabel(o) {
  const s = foRolesText(o);
  if (/operation[_ ]?head/i.test(s)) return "Operation Head";
  if (/team[_ ]?head[_ ]?fo/i.test(s)) return "Team Head FO";
  if (/field/i.test(s)) return "Field Officer";
  return s ? s.replace(/[_,]+/g, " ").replace(/\s+/g, " ").trim() : "";
}

async function getFoRoster(env) {
  const cfg = (env.SKD_FO_PATH || SKD_FO_PATH_DEFAULT || "").trim();
  let list = [];
  if (cfg) {
    const target = /^https?:\/\//i.test(cfg) ? cfg : (env.SKD_API_BASE + cfg);
    try {
      let token = await getToken(env);
      let r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } });
      if (r.status === 401) { token = await getToken(env, true); r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } }); }
      const raw = await r.json();
      list = Array.isArray(raw) ? raw : ((raw && (raw.users || raw.data || raw.officers || raw.fos || raw.fieldOfficers || raw.result || raw.list)) || []);
    } catch (e) { list = []; }
  }
  const book = await foPhoneBook(env);
  const seen = {}, out = [];
  if (Array.isArray(list)) for (const o of list) {
    if (!o || typeof o !== "object") continue;
    if (!foRoleWanted(o)) continue;
    const fn = String(o.firstName || "").trim(), ln = String(o.lastName || "").trim();
    const name = (fn || ln) ? (fn + " " + ln).trim() : String(o.name || o.foName || o.fieldOfficerName || o.fullName || o.officerName || o.empName || o.employeeName || o.userName || o.username || "").trim();
    if (!name || seen[name.toLowerCase()]) continue;
    seen[name.toLowerCase()] = 1;
    let state = String(o.state || o.foState || o.stateName || o.State || "").trim();
    let region = String(o.region || o.foRegion || o.district || o.zone || o.Region || "").trim();
    if (!state) { const d = FO_DIRECTORY[normName(name)]; if (d) { state = d.state || ""; region = region || d.region || ""; } }
    // the live number first; the portal's own book only where SKD sends nothing
    let phone = foPhoneFromRow(o);
    if (!phone) { const b = book[normName(name)]; phone = foPhoneClean(b && b.num); }
    /* ══════ SKD'S OWN ATTENDANCE — v12.2 ══════════════════════════════════════════════
       Sujit, 20-Aug-2026: "Access we have been received from Praveen that FO attendance
       punched with the date and time today. Check that."

       Checked, live, the same morning: the Get FO Users API this very function reads
       (SKD_FO_PATH → /users/fo) now carries two new fields on every one of its 190 rows —
         attendanceDateTime   "20/08/2026 06:31 AM"  (empty string until the man punches)
         isAttendance         true / false
       They were arriving on every roster refresh and being dropped right here, because this
       shaping line predates them. Now they are carried through, and the Field Tracker's
       dashboard turns them into the SKD-app attendance count, the per-officer punch time,
       and two new columns on the Attendance Excel.

       The RAW string is carried, not a parsed date. "20/08/2026 06:31 AM" is dd/MM/yyyy and
       new Date() on that string would happily read it as the 20th month or as US order
       depending on the runtime — the one bug class worse than no data is silently-wrong
       data. Whoever consumes this compares the date PART against today-in-IST as text.
       isAttendance is carried as a plain fact too, but the day judgement is made from the
       DATE, never from the flag — if SKD ever leaves the flag standing overnight, a stale
       "true" must not mark a man present who punched yesterday. */
    const att = String(o.attendanceDateTime == null ? "" : o.attendanceDateTime).trim();
    /* ══════ THE LOGIN NAME AND THE ON/OFF FLAG — v25.8 ═══════════════════════════════════
       Two more fields that were arriving on every row and being dropped right here, for the
       same reason the attendance pair was: this shaping line predates them.

       `userName` is not a nicety — it is the KEY. Praveen's two user-management doors
       (update-case-limit, change-user-status) are addressed by username and by nothing else,
       so without it the portal can read a man's row and still have no way to name him to
       SKD. `status` is the live Active / In-active word, which is what tells an approval
       which way change-user-status is about to flip him.

       Both are carried raw. No canonicalising of the status word: SKD writes "Active" and
       "In-active" today, and a reader that has already decided what those two strings are
       will quietly mis-read the third one SKD invents next year. Whoever consumes it tests
       for "inactive" and treats everything else as on. */
    out.push({ name, state, region, phone, role: foRoleLabel(o), att, isAtt: o.isAttendance === true,
               user: String(o.userName || o.username || "").trim(),
               status: String(o.status || "").trim() });
  }
  /* Did this list come from SKD just now, or is it the baked directory standing in?
     The Field Tracker has to be able to say which, because "nobody is missing a location"
     computed against a stale list is the flattering kind of wrong. Hung on the array
     itself so nothing that already calls this function sees any change — an array property
     does not survive JSON, so every existing caller gets byte-identical output. */
  const live = out.length > 0;
  if (!out.length) {
    for (const k in FO_DIRECTORY) {
      const d = FO_DIRECTORY[k];
      const cap = k.replace(/\b[a-z]/g, c => c.toUpperCase());
      const b = book[k];
      out.push({ name: cap, state: canonState((d && d.state) || ""), region: (d && d.region) || "", phone: foPhoneClean(b && b.num), role: "Field Officer" });
    }
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  try { Object.defineProperty(out, "live", { value: live, enumerable: false }); } catch (e) {}
  return out;
}

// Restrict a case list to what `user` may see. admin/boss -> everything.
/* WHOSE CASES ARE NARROWED, AND BY WHAT — asked in ONE place.
   Every route used to spell this list out for itself, and there were nine of them. That is
   how the Out of TAT Manager came to see the whole company on every page for weeks: the
   role was given a scope in scopeCases, but the nine guards that decide whether to CALL
   scopeCases had never heard of it. One helper now, so the next role cannot be forgotten. */
/* the Medical Bill Verification sub-product, spelt the several ways SKD spells it. A twin of
   isMbvProduct in mbvchase-index.js on purpose — importing across would close a module cycle. */
function isMbvSub(sub) {
  const s = String(sub == null ? "" : sub);
  if (/garage|vehicle|motor/i.test(s)) return false;
  return /medical\s*bill/i.test(s) || /\bmbv\b/i.test(s) || /bill\s*verification/i.test(s);
}
function isScopedRole(role) {
  return role === "coordinator" || role === "manager" || role === "ohs"
      || role === "product-head" || role === "ootat-manager"
      || role === "client-manager"
      /* v23.2 — the assigning desk is "scoped" only in the sense that scopeCases has a rule
         for it (its one product). Every other narrowing in there is keyed by role and simply
         does not apply to it. v23.3 — and the two bill-verification desks, narrowed to their
         own product the same way. */
      || role === "assign-team"
      || role === "mbv_operator" || role === "mbv_checker";
}

/* ══════════ THE CLIENT MANAGER — A LOGIN FOR THE INSURER ══════════════════════════════
   Sujit, 14-Aug-2026: "I need access for giving client — call it Client Manager. I want to
   select Health or TP, and which client, example ICICI Lombard, Chola like this. If it is TP
   only, they have to get that cases. They have to get Analytics, that option also."

   This is the first role in the portal held by somebody who does NOT work here, so it is
   built the other way round from every other role: instead of starting wide and narrowing,
   it starts at NOTHING and only what Admin ticked is added.

     · no client ticked  -> no cases at all (not "all cases")
     · no product ticked -> both, because a client login with a client and no product is
       plainly meant to see that client's whole book; an EMPTY CLIENT is the dangerous
       blank, an empty product is not.

   Client names are matched the forgiving way ON PURPOSE, but never loosely enough to reach a
   second insurer: SKD writes "Cholamandalam General insurance company Ltd" on one case and
   "Cholamandalam MS General Insurance" on another, and an exact match would hand the client
   an empty screen and a phone call. The test is: same first strong word, and one string's
   squashed form starts the other's. "ICICI Lombard GIC" therefore matches "ICICI Lombard
   General Insurance" and can never match "IFFCO Tokio".                                    */
function clientKeyW(s) {
  return String(s == null ? "" : s).toLowerCase().replace(/[^a-z0-9]+/g, " ")
    .replace(/\b(general|gen|insurance|ins|company|co|ltd|limited|gic|pvt|private|india|assurance|mS)\b/gi, " ")
    .replace(/\s+/g, " ").trim();
}
function sameClientW(a, b) {
  const ka = clientKeyW(a), kb = clientKeyW(b);
  if (!ka || !kb) return false;
  if (ka === kb) return true;
  const sa = ka.replace(/ /g, ""), sb = kb.replace(/ /g, "");
  if (sa === sb) return true;
  /* the first meaningful word must be the same insurer, then one may be the other's start —
     this is what stops "Bajaj Allianz" ever reaching "Bajaj Finserv" while still letting
     "Chola" reach "Cholamandalam" */
  const wa = ka.split(" ")[0], wb = kb.split(" ")[0];
  if (!wa || !wb) return false;
  const first = (wa.length <= wb.length) ? wa : wb, other = (wa.length <= wb.length) ? wb : wa;
  if (first.length < 4 || other.indexOf(first) !== 0) return false;
  return sa.indexOf(sb) === 0 || sb.indexOf(sa) === 0;
}
/* the products this login may see; empty list = both (see the note above) */
function clientProductsOf(u) {
  const got = Array.isArray(u && u.clientProducts) ? u.clientProducts.filter(x => MEET_PRODUCTS.includes(x)) : [];
  return got.length ? got : MEET_PRODUCTS.slice();
}
function clientCasesOf(cases, user) {
  const mine = Array.isArray(user.clients) ? user.clients.filter(Boolean) : [];
  if (!mine.length) return [];                      // nothing ticked = nothing seen. Never "everything".
  const prods = clientProductsOf(user);
  return cases.filter(c => prods.includes(typeOfSub(c.subProduct)) && mine.some(m => sameClientW(m, c.client)));
}
/* WHAT THE INSURER MUST NOT BE HANDED. His answer of 14-Aug-2026, asked directly: the client
   sees their cases WITHOUT our internal names. The field officer who is standing at the
   hospital and the manager running the file are ours; a client who can read those names can
   ring the man directly, and that is not a thing to leak by forgetting a column. Stripped
   here, at the one door every page's data comes through, rather than hidden on each screen —
   a screen can be re-added, a strip at the source cannot be forgotten. */
const CLIENT_HIDE_KEYS = ["officerName", "manager", "assigningManager", "allotmentManager", "reportManager",
  /* StackHolders is the sentence SKD builds out of our men and their parts — "Karthick Nani -
     Hospital Verification". It is a NAME field wearing a work-allocation coat, and blanking
     the five obvious ones while leaving this behind would have handed the client the very
     name the table refuses to print. Found by printing what the client login actually
     receives rather than by reading the code. */
  "stackHolders"];
/* the same people again, in the shapes the dashboard uses: per-officer status, the partially
   done and the still-open lists. Emptied rather than blanked — a list of nameless entries is
   a puzzle on screen, and the client has no use for a per-officer split of our own team. */
const CLIENT_EMPTY_KEYS = ["foStat", "partFo", "openFo"];
function stripInternalNames(cases) {
  return cases.map(c => {
    const o = Object.assign({}, c);
    for (const k of CLIENT_HIDE_KEYS) if (k in o) o[k] = "";
    for (const k of CLIENT_EMPTY_KEYS) if (k in o) o[k] = [];
    return o;
  });
}
function isClientRole(u) { return !!u && u.role === "client-manager"; }
/* Two spellings of one field officer? Exact after normalising, or every token of the shorter
   name found in the longer one — a token of four letters or more may sit inside a longer token
   ("sathishkumar" inside "sathish kumar vanguru"), a short one ("bm", "cp", "g") must be a whole
   token. The shorter name must carry at least two tokens, so "Ravi" alone can never claim
   every Ravi on the feed. */
function editDistance(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = new Array(n + 1), cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    const t = prev; prev = cur; cur = t;
  }
  return prev[n];
}
/* one token of a name against the other name: the same token, the token inside a longer one
   (four letters or more), or one letter out on a token of five or more / two letters out on a
   token of eight or more — "karthik" ~ "karthick", "nanni" ~ "nani", "veerraju" ~ "veeraraju" */
function tokenHit(t, longTokens, longJoined) {
  if (longTokens.includes(t)) return true;
  if (t.length >= 4 && longJoined.indexOf(t) >= 0) return true;
  if (t.length >= 5) { const allow = t.length >= 8 ? 2 : 1; if (longTokens.some(u => Math.abs(u.length - t.length) <= allow && editDistance(t, u) <= allow)) return true; }
  return false;
}
function sameManLoose(a, b) {
  const na = normName(a), nb = normName(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  const ta = String(a).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(" ").filter(Boolean);
  const tb = String(b).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(" ").filter(Boolean);
  const [short, long] = ta.length <= tb.length ? [ta, tb] : [tb, ta];
  const longJoined = long.join("");
  /* a one-word name ("Tharun", "veerraju") is accepted only when that one word is long enough
     to be somebody in particular (six letters or more) and matches a whole token of the other */
  if (short.length < 2) return short.length === 1 && short[0].length >= 6 && tokenHit(short[0], long, "");
  return short.every(t => tokenHit(t, long, longJoined));
}
/* is this officer name one of the team head's own men? */
function isTeamMan(user, officerName) {
  const men = Array.isArray(user && user.teamNames) ? user.teamNames : [];
  const n = String(officerName || "").trim();
  if (!n || !men.length) return false;
  return men.some(m => sameManLoose(m, n));
}
/* ══════════ FIELD OFFICER → HIS OHS — v33.8, 24-Sep-2026 ════════════════════════════════
   Sujit, on the Analytics hover card: "The field officers are there. Their OHS is not. Field
   officers belong to OHS teams, and I need the OHS name beside them."

   THE ONE SOURCE. The Teams store (Portal → OHS Team, KV "team:<id>": name · head · members)
   is what the OHS TEAM table on Analytics draws, and it is ALSO what fences the OHS login —
   currentUser() reads teamNames off the very same record. So the reverse index is built off
   that store and nothing else: never off states, never off a name's shape. An officer on no
   team answers "—"; an officer on two teams answers both heads; a head is his own OHS.
   Matched with sameManLoose, the spelling-tolerant match the fence itself uses.

   FENCED LIKE /api/teams-list: an OHS login is handed his own team only, a coordinator his
   states' teams, an insurer or the call centre nothing — the names of other teams' heads are
   ours, not theirs. Built once per request, memoised per officer name. */
async function ohsIndexFor(env, me) {
  const teams = [];
  if (env && env.USERS && me && me.role !== "client-manager" && me.role !== "call-centre") {
    try {
      const l = await env.USERS.list({ prefix: "team:" });
      for (const k of l.keys) {
        const v = await env.USERS.get(k.name);
        if (!v) continue;
        try { const t = JSON.parse(v); teams.push({ id: t.id, name: String(t.name || ""), head: String(t.head || ""), members: Array.isArray(t.members) ? t.members : [], state: t.state || "" }); } catch (e) {}
      }
    } catch (e) {}
  }
  let tl = teams;
  if (me && me.role === "ohs") tl = teams.filter(t => t.id === me.team);
  else if (me && me.role === "coordinator") {
    const myStates = (Array.isArray(me.states) && me.states.length ? me.states : (me.state ? [me.state] : [])).map(x => String(x).toLowerCase());
    if (myStates.length) tl = teams.filter(t => !t.state || myStates.includes(String(t.state).toLowerCase()));
  }
  const memo = {};
  const heads = (name) => {
    const n = String(name || "").trim(); if (!n) return [];
    const k = normName(n);
    if (memo[k]) return memo[k];
    const out = [];
    for (const t of tl) {
      if (!t.head) continue;
      if ([t.head].concat(t.members).some(m => m && sameManLoose(m, n))) { if (out.indexOf(t.head) < 0) out.push(t.head); }
    }
    memo[k] = out;
    return out;
  };
  /* every man on the case — the officerName field and the per-man foStat lines both */
  const stamp = (c) => {
    const men = officersOnCase(c && c.officerName);
    for (const f of ((c && c.foStat) || [])) { if (f && f.n && men.indexOf(f.n) < 0) men.push(f.n); }
    const m = {};
    for (const nm of men) { const h = heads(nm); if (h.length) m[nm] = h; }
    return m;
  };
  return { teams: tl, heads, stamp, size: tl.length };
}
function scopeCases(cases, user, foMap) {
  if (!user || user.role === "admin" || user.role === "boss") return cases;
  /* v23.2 — THE ASSIGNING DESK. It is not fenced to "his own cases" like a manager: its job
     is the whole unassigned pool, so the only narrowing it has is the product he was given.
     One ticked product means that product only; none or both means everything, which is how
     every assign-team record written before today reads. Put here rather than at each feed
     because there are ten of them and the eleventh is the one that gets forgotten. */
  if (user.role === "assign-team") {
    const ap = assignProductsOf(user);
    return ap.length ? cases.filter(c => ap.includes(typeOfSub(c.subProduct))) : cases;
  }
  /* v23.3 — THE BILL VERIFICATION DESK SEES BILL VERIFICATION CASES. Sujit, 09-Sep 3:20 pm:
     "for verification too, need to reflect them only below verification cases — only the
     product need to be filter and give only the Bill Verification details." The desk works
     one product; a Dashboard showing it 1,600 motor and health cases is 1,600 cases it can
     do nothing about. Garage Bill Verification is excluded, the same way the chase mail
     excludes it — that is a different desk's work. */
  if (user.role === "mbv_operator" || user.role === "mbv_checker") {
    return cases.filter(c => isMbvSub(c.subProduct));
  }
  if (user.role === "coordinator") {
    const states = (Array.isArray(user.states) ? user.states : (user.state ? [user.state] : [])).map(x => normName(canonState(x))).filter(Boolean);
    if (!states.length) return [];
    /* v20.4 — Sujit, 2-Sep-2026 9:24 pm, a state coordinator's phone beside his own screen: the
       coordinator's Analytics showed 116 open Health cases for his state, the admin's showed 126.
       The ten missing were shared claims — "A, B, C" — where the coordinator's own man rides
       second or third: this fence looked up the FIRST officer only, found a man of some other
       state, and dropped the case from his state entirely. The same fault the OHS branch below
       had until v20.3. A case is a state's if ANY officer on it belongs to that state — the
       arithmetic SKD and the Analytics drills already use. Every state coordinator was short
       the same way; this fixes all of them at once. */
    return cases.filter(c => officersOnCase(c.officerName).some(nm => { const st = foStateOf(nm, foMap); return st && states.includes(normName(st)); }));
  }
  /* ══ v20.8 — THE MANAGER'S OWN NAME, HOWEVER SKD SPELLS IT ═══════════════════════════════
     4-Sep 10:16 pm, from a Product Head (Jeltisen bino) with his SKD screen beside the portal:
     "cases in my name its not showing in taasen portal — Cl no 126015427100". SKD's Manage
     Case carries the manager as "jeltisen"; the portal knew him as "Jeltisen bino", and this
     fence compared the two letter for letter. So his own cases — the ones SKD files under his
     login name — were invisible to him, while his mapped managers' cases showed fine.
     A manager or product head is now matched to a case by ANY of: the manager name(s) set in
     Admin, his own display name, and the name part of his mail ID — and each of those the
     way the OHS fence matches men (sameManLoose): a whole name, or a name that is one whole
     token of the other ("jeltisen" ~ "Jeltisen bino"), never a bare initial. */
  const mgrCands = u => {
    const out = [];
    (Array.isArray(u.managers) ? u.managers : []).forEach(m => { if (normName(m)) out.push(String(m)); });
    if (u.manager && normName(u.manager)) out.push(String(u.manager));
    if (u.name && normName(u.name)) out.push(String(u.name));
    const local = String(u.email || "").split("@")[0].replace(/[._\-+0-9]+/g, " ").trim();
    if (local && normName(local) && local.replace(/\s+/g, "").length >= 6) out.push(local);
    return out;
  };
  const mgrHit = (cands, caseMgr) => {
    const cm = String(caseMgr || "").trim(); if (!cm) return false;
    const n = normName(cm);
    return cands.some(x => normName(x) === n || sameManLoose(x, cm));
  };
  if (user.role === "manager") {
    const cands = mgrCands({ manager: user.manager, name: user.name, email: user.email });
    if (!cands.length) return [];
    return cases.filter(c => mgrHit(cands, c.manager));
  }
  if (user.role === "product-head") {   // sees his own cases + every manager under him
    const cands = mgrCands(user);
    if (!cands.length) return [];
    return cases.filter(c => mgrHit(cands, c.manager));
  }
  /* ── THE OUT OF TAT MANAGER, EVERYWHERE EXCEPT THE MEETING ───────────────────────────
     His instruction of 11-Aug-2026: "this is showing all cases — I don't want like that.
     Only for Out of TAT need to show all the cases. For Analytics, Dashboard … I will map
     them like manager, and once I click that manager, only their cases."

     The meeting page is handled on its own in /api/ootat, where this role deliberately gets
     every case of the product it runs — that is its whole job and it does not change. This
     branch is every OTHER page, and here the role is now exactly as wide as the managers he
     was mapped to in Admin, and no wider.

     No manager mapped yet = no case data outside the meeting. That is the safe direction for
     an access rule: showing too little is a question somebody asks, showing too much is a
     leak nobody notices. The Admin screen says so beside the picker. */
  if (user.role === "ootat-manager") {
    const cands = mgrCands(user);
    if (!cands.length) return [];
    return cases.filter(c => mgrHit(cands, c.manager));
  }
  if (user.role === "ohs") {   // team head: only the cases of his team's officers (head + members)
    if (!(Array.isArray(user.teamNames) ? user.teamNames : []).length) return [];
    /* v20.3 — EVERY man on a shared claim, not only the first. "A, B, C" with the team's
       man at B used to be invisible to his own head: the whole string matched nobody and
       firstFO() gave A. A case is his team's if ANY officer on it is. */
    /* v20.5 — the SAME MAN, however he is spelt. Sujit, 3-Sep 5:10 pm: "I don't want any field
       officer missing in OHS." The team store says "NAGARAJ GOWDA", the feed says "NAGARAJ G D
       GOWDA"; "ISAAC GOPALI" against "ISAAC MARTIN GOPALI"; "vasanth bm" against "vasanth Kumar
       bm". An exact match dropped every one of those men's cases from his own head's page. */
    return cases.filter(c => String(c.officerName || "").split(/[,/]+/).map(x => x.trim()).filter(Boolean).some(n => isTeamMan(user, n)));
  }
  /* THE CLIENT'S OWN LOGIN. Narrowed to his insurer(s) and his product, then our people's
     names taken off — both in one place, because a scope that is right and a strip that was
     forgotten still ends in the client reading our field officer's name. */
  if (user.role === "client-manager") return stripInternalNames(clientCasesOf(cases, user));
  return cases;
}

/* ---------- base64 + Anthropic ---------- */
function base64FromArrayBuffer(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(bin);
}
async function anthropic(env, body) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify(body)
  });
  const t = await r.text();
  if (!r.ok) throw new Error("Claude HTTP " + r.status + " — " + t.slice(0, 400));
  const d = JSON.parse(t);
  return (d.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
}

/* ══════ GEMINI, CHATGPT and GROK — v26.3, 12-Sep-2026 10:00 pm ═════════════════════════════
   Sujit, on the AI ENGINE card: "add in this Gemini API also — I will be turning on for that."
   "I need option for ChatGPT also. Create for that also." "Grok, this API also. I'll give you
   for this." The same call the Claude path makes, addressed to Google, OpenAI or xAI instead.
   All three take the Claude-shaped body every caller already builds — system, messages,
   content blocks of text / document / image — so no caller has to know which engine is on.
   The blocks are translated:
     Gemini   text → { text }  ·  document/image (base64) → { inlineData: { mimeType, data } }
     ChatGPT  text → { type: input_text }  ·  document → { type: input_file, file_data: data URL }
              image → { type: input_image, image_url: data URL }
     Grok     as ChatGPT (xAI's door is the same shape), except a PDF cannot go inline: it is
              UPLOADED to xAI's Files door first, named by file_id, and DELETED the moment the
              answer is back — a claim file is not left sitting on somebody else's server.
   The answer comes back as plain text, the way anthropic() returns it. Doors as documented
   today: Google POST v1beta/models/{model}:generateContent with x-goog-api-key; OpenAI POST
   /v1/responses with a bearer key; xAI POST https://api.x.ai/v1/responses with a bearer key.
   Every call is written to ai_engine_usage with its tokens and price, so the card can say
   what the month cost. Nothing is retried here: a refusal is thrown with the company's own
   words. */
function geminiParts(content) {
  if (typeof content === "string") return [{ text: content }];
  const parts = [];
  for (const b of (Array.isArray(content) ? content : [])) {
    if (!b) continue;
    if (b.type === "text") parts.push({ text: String(b.text || "") });
    else if ((b.type === "document" || b.type === "image") && b.source && b.source.type === "base64")
      parts.push({ inlineData: { mimeType: String(b.source.media_type || (b.type === "document" ? "application/pdf" : "image/jpeg")), data: String(b.source.data || "") } });
  }
  return parts.length ? parts : [{ text: "" }];
}
/* OpenAI-shaped parts; `fileOf` is how a document block becomes a part — inline for OpenAI,
   an uploaded file_id for xAI — so the two callers share everything else */
async function responsesParts(content, fileOf) {
  if (typeof content === "string") return [{ type: "input_text", text: content }];
  const parts = []; let n = 0;
  for (const b of (Array.isArray(content) ? content : [])) {
    if (!b) continue;
    if (b.type === "text") parts.push({ type: "input_text", text: String(b.text || "") });
    else if (b.type === "document" && b.source && b.source.type === "base64") parts.push(await fileOf(b, ++n));
    else if (b.type === "image" && b.source && b.source.type === "base64")
      parts.push({ type: "input_image", image_url: "data:" + String(b.source.media_type || "image/jpeg") + ";base64," + String(b.source.data || "") });
  }
  return parts.length ? parts : [{ type: "input_text", text: "" }];
}
/* what a Responses-door answer says, read the same way for OpenAI and xAI */
function readResponses(d) {
  const u = d.usage || {};
  let text = "";
  for (const it of (Array.isArray(d.output) ? d.output : [])) {
    if (!it || it.type !== "message") continue;
    for (const c of (Array.isArray(it.content) ? it.content : [])) if (c && c.type === "output_text") text += (text ? "\n" : "") + String(c.text || "");
  }
  if (!text && typeof d.output_text === "string") text = d.output_text;
  const why = d.status && d.status !== "completed" ? d.status + (d.incomplete_details && d.incomplete_details.reason ? " (" + d.incomplete_details.reason + ")" : "") : "";
  return { text: text.trim() ? text : "", inTok: Number(u.input_tokens) || 0, outTok: Number(u.output_tokens) || 0, why };
}
/* the one shape of every keyed call: key → build the request → send → read → write it down */
async function keyedCall(env, engine, what, door, opts) {
  const g = await keySetup(env, engine);
  const name = ENGINE_NAME[engine] || engine;
  if (!g.key) throw new Error(name + ": no API key — paste it on Settings → AI ENGINE, or set the Worker variable " + keyEnvName(engine));
  const model = g.model;
  const t0 = Date.now();
  let req;
  try { req = await door.build(model, g.key); }
  catch (e) {
    if (door.after) { try { await door.after(g.key); } catch (e2) { } }     // a half-uploaded set is cleaned up too
    await noteEngineUse(env, { engine, model, what, ok: false, ms: Date.now() - t0 });
    throw e;
  }
  /* the second pass of the one retry below — same request, temperature taken back out */
  if (opts && opts.noTemp) { delete req.temperature; if (req.generationConfig) delete req.generationConfig.temperature; }
  const hadTemp = req.temperature !== undefined || !!(req.generationConfig && req.generationConfig.temperature !== undefined);
  let r, t;
  try {
    r = await fetch(door.url(model), { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, door.headers(g.key)), body: JSON.stringify(req) });
    t = await r.text();
  } finally { if (door.after) { try { await door.after(g.key); } catch (e) { } } }
  if (!r.ok) {
    let msg = t.slice(0, 400);
    try { const e = JSON.parse(t); if (e && e.error && (e.error.message || typeof e.error === "string")) msg = String(e.error.message || e.error).slice(0, 400); } catch (e) { }
    await noteEngineUse(env, { engine, model, what, ok: false, ms: Date.now() - t0 });
    /* v26.7 — SOME MODELS WILL NOT BE TOLD A TEMPERATURE. The reasoning models refuse the
       parameter outright ("Unsupported parameter: temperature"), and the questionnaire asks
       for 0 on every engine so that switching engines does not reword the paper. Rather than
       the portal guessing which model names allow it — the guess that put a model off a price
       page into the dropdown and cost him a morning — it asks once, and if THAT is the
       complaint, asks again without it. Steadiness is worth a retry; it is not worth a
       refusal he then has to read. */
    if (!(opts && opts.noTemp) && hadTemp && /temperature/i.test(msg)) return keyedCall(env, engine, what, door, { noTemp: true });
    /* v26.6 — the one refusal that has its answer on the same screen */
    const notFound = /model not found|does not exist|unknown model|invalid model|no such model/i.test(msg);
    throw new Error(name + " HTTP " + r.status + " — " + msg + (notFound ? " · Press REFRESH MODELS on Settings → AI ENGINE and pick one from the list this key can actually use." : ""));
  }
  let d = null; try { d = JSON.parse(t); } catch (e) { throw new Error(name + " sent an unreadable answer"); }
  const out = door.read(d);
  /* v31.5 — THE ZERO-COST BUG. This line used to fall back to a zero-rate price row, so a
     model with no entry in the map was billed at NOTHING: 131 Grok calls and 2.11M input
     tokens read "$0.00" on the card. An unknown price is now written as NULL — unpriced, and
     said so on the screen — never as free. priceFor also applies the long-context tier where
     a threshold is configured. */
  const price = priceFor(g.price, model, out.inTok);
  const cost = price.known ? (out.inTok * price.in + out.outTok * price.out) / 1e6 : null;
  await noteEngineUse(env, { engine, model, what, inTok: out.inTok, outTok: out.outTok, cost: cost, ok: !!out.text, ms: Date.now() - t0 });
  if (!out.text) throw new Error(name + " sent no answer" + (out.why ? " — " + out.why : ""));
  return out.text;
}
/* v26.6 — ASK THE COMPANY WHAT THIS KEY MAY CALL. Sujit, 13-Sep 10:06 am, on the Questionnaire:
   "Grok HTTP 400 — Model not found: grok-4.1-fast". That name came off a price page. This asks
   Google, OpenAI and xAI themselves, through their own list door, with his own key — the only
   list that can never be out of date or wrong. Returns the ids; the caller keeps them. */
export async function listEngineModels(env, engine) {
  const door = listDoorOf(engine);
  const name = ENGINE_NAME[engine] || engine;
  if (!door) throw new Error(name + " has no model list to ask for.");
  const g = await keySetup(env, engine);
  if (!g.key) throw new Error(name + ": no API key — paste it on Settings → AI ENGINE, or set the Worker variable " + keyEnvName(engine));
  const r = await fetch(door.url, { headers: Object.assign({ Accept: "application/json" }, door.head(g.key)) });
  const t = await r.text();
  if (!r.ok) {
    let msg = t.slice(0, 300);
    try { const e = JSON.parse(t); if (e && e.error) msg = String(e.error.message || e.error).slice(0, 300); } catch (e) { }
    throw new Error(name + " HTTP " + r.status + " on the model list — " + msg);
  }
  let d = null; try { d = JSON.parse(t); } catch (e) { throw new Error(name + " sent an unreadable model list"); }
  const ids = cleanModelList(door.read(d));
  if (!ids.length) throw new Error(name + " answered with no model this key can use for text.");
  return ids;
}

async function gemini(env, body, what) {
  return keyedCall(env, "gemini", what, {
    url: (model) => "https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(model) + ":generateContent",
    headers: (key) => ({ "x-goog-api-key": key }),
    build: async () => {
      const req = {
        contents: (body.messages || []).map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: geminiParts(m.content) })),
        generationConfig: { maxOutputTokens: Math.min(Math.max(parseInt(body.max_tokens, 10) || 1024, 1), 16000), temperature: aiTemp(body) }
      };
      if (body.system) req.systemInstruction = { parts: [{ text: String(body.system) }] };
      return req;
    },
    read: (d) => {
      const c = d.candidates && d.candidates[0];
      const u = d.usageMetadata || {};
      const text = c ? ((c.content && c.content.parts) || []).map(p => (p && p.text) || "").join("\n") : "";
      const why = !c ? (d.promptFeedback && d.promptFeedback.blockReason ? "blocked: " + d.promptFeedback.blockReason : "no candidate") : (c.finishReason && c.finishReason !== "STOP" ? c.finishReason : "");
      return { text: text.trim() ? text : "", inTok: Number(u.promptTokenCount) || 0, outTok: Number(u.candidatesTokenCount) || 0, why };
    }
  });
}
/* THE SAME STEADINESS ON EVERY ENGINE. A caller that names a temperature gets exactly that one
   from Google, OpenAI, xAI and Anthropic alike — the questionnaire asks for 0, so the same case
   asked twice does not come back reworded. Google's door has always sent 0.2 and still does
   when nobody names one; OpenAI's and xAI's are left alone unless a caller asks, because a
   parameter nobody needed is a parameter that can be refused (see keyedCall's one retry). */
function aiTemp(body) {
  const t = Number(body && body.temperature);
  return (isFinite(t) && t >= 0 && t <= 2) ? t : 0.2;
}
function aiTempAsked(body) {
  const t = Number(body && body.temperature);
  return (body && body.temperature !== undefined && isFinite(t) && t >= 0 && t <= 2) ? t : null;
}
async function responsesBody(body, fileOf) {
  const input = [];
  for (const m of (body.messages || [])) input.push({ role: m.role === "assistant" ? "assistant" : "user", content: await responsesParts(m.content, fileOf) });
  const req = { input, max_output_tokens: Math.min(Math.max(parseInt(body.max_tokens, 10) || 1024, 16), 16000) };
  const t = aiTempAsked(body);
  if (t !== null) req.temperature = t;
  if (body.system) req.instructions = String(body.system);
  return req;
}
async function openai(env, body, what) {
  return keyedCall(env, "openai", what, {
    url: () => "https://api.openai.com/v1/responses",
    headers: (key) => ({ "Authorization": "Bearer " + key }),
    build: async (model) => Object.assign({ model }, await responsesBody(body, async (b, n) =>
      ({ type: "input_file", filename: "document-" + n + ".pdf", file_data: "data:" + String(b.source.media_type || "application/pdf") + ";base64," + String(b.source.data || "") }))),
    read: readResponses
  });
}
function bytesOfBase64(b64) {
  const bin = atob(String(b64 || ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function grok(env, body, what) {
  const uploaded = [];
  return keyedCall(env, "grok", what, {
    url: () => "https://api.x.ai/v1/responses",
    headers: (key) => ({ "Authorization": "Bearer " + key }),
    build: async (model, key) => Object.assign({ model }, await responsesBody(body, async (b, n) => {
      /* the PDF goes up to xAI's Files door and is named by id; deleted in `after` */
      const fd = new FormData();
      fd.append("purpose", "assistants");
      fd.append("file", new Blob([bytesOfBase64(b.source.data)], { type: String(b.source.media_type || "application/pdf") }), "document-" + n + ".pdf");
      const r = await fetch("https://api.x.ai/v1/files", { method: "POST", headers: { "Authorization": "Bearer " + key }, body: fd });
      const t = await r.text();
      if (!r.ok) { let msg = t.slice(0, 300); try { const e = JSON.parse(t); if (e && e.error) msg = String(e.error.message || e.error).slice(0, 300); } catch (e) { } throw new Error("Grok HTTP " + r.status + " on the file upload — " + msg); }
      let d = {}; try { d = JSON.parse(t); } catch (e) { }
      if (!d.id) throw new Error("Grok's file upload answered without a file id");
      uploaded.push(d.id);
      return { type: "input_file", file_id: String(d.id) };
    })),
    read: readResponses,
    after: async (key) => {
      /* the claim papers do not stay on xAI's server — every uploaded file is deleted, best effort */
      for (const id of uploaded) { try { await fetch("https://api.x.ai/v1/files/" + encodeURIComponent(id), { method: "DELETE", headers: { "Authorization": "Bearer " + key } }); } catch (e) { } }
      uploaded.length = 0;
    }
  });
}
/* ══════ DEEPSEEK — v26.7, 14-Sep-2026. "Add deepseek, also, AI." ═══════════════════════════
   DeepSeek's door is OpenAI's older /chat/completions shape, not the Responses shape OpenAI
   and xAI now use, so it gets its own small builder rather than a flag bolted onto theirs.

   AND IT TAKES NO PDF. Their vision guide and their Files API list JPEG, PNG, GIF and WebP —
   that is all. The discharge summary is the whole grounding of a questionnaire, so dropping
   it silently would have made DeepSeek quietly write a different, weaker paper from the same
   button, which is precisely what he said he did not want. Instead the PDF is read into TEXT
   in this Cloudflare account first — the same reader Connector mode uses, OCR included when
   the page is a photograph of the paper — and the words go up with a line saying which
   document they came off and how they were read. Images still go inline as data URLs.  */
async function deepseekParts(env, content) {
  if (typeof content === "string") return [{ type: "text", text: content }];
  const parts = [], docs = [], names = [];
  for (const b of (Array.isArray(content) ? content : [])) {
    if (!b) continue;
    if (b.type === "text") parts.push({ type: "text", text: String(b.text || "") });
    else if (b.type === "image" && b.source && b.source.type === "base64")
      parts.push({ type: "image_url", image_url: { url: "data:" + String(b.source.media_type || "image/jpeg") + ";base64," + String(b.source.data || "") } });
    else if (b.type === "document" && b.source && b.source.type === "base64") { docs.push(b); names.push("document " + docs.length + ".pdf"); }
  }
  if (docs.length) {
    const read = await docsToText(env, docs, names);
    const lines = read.map((d, i) => "DOCUMENT " + (i + 1) + " — " + d.name
      + (d.note ? " (" + d.note + ")" : (d.pages ? " (" + d.pages + " pages, read from the PDF's own text)" : ""))
      + ":\n" + (d.text || "(nothing could be read out of it)"));
    /* first, so the papers are in front of the model before the instruction that uses them */
    parts.unshift({ type: "text", text: "THE PAPERS, READ INTO TEXT BY THE PORTAL (DeepSeek takes no PDF):\n\n" + lines.join("\n\n") });
  }
  return parts.length ? parts : [{ type: "text", text: "" }];
}
async function deepseek(env, body, what) {
  return keyedCall(env, "deepseek", what, {
    url: () => "https://api.deepseek.com/chat/completions",
    headers: (key) => ({ "Authorization": "Bearer " + key }),
    build: async (model) => {
      const messages = [];
      if (body.system) messages.push({ role: "system", content: String(body.system) });
      for (const m of (body.messages || [])) messages.push({ role: m.role === "assistant" ? "assistant" : "user", content: await deepseekParts(env, m.content) });
      const req = { model, messages, max_tokens: Math.min(Math.max(parseInt(body.max_tokens, 10) || 1024, 16), 16000) };
      const t = aiTempAsked(body);
      if (t !== null) req.temperature = t;
      return req;
    },
    read: (d) => {
      const c = d && d.choices && d.choices[0];
      const u = (d && d.usage) || {};
      const text = (c && c.message && (typeof c.message.content === "string" ? c.message.content
        : (Array.isArray(c.message.content) ? c.message.content.map(x => (x && x.text) || "").join("\n") : ""))) || "";
      const why = !c ? "no answer" : (c.finish_reason && c.finish_reason !== "stop" ? c.finish_reason : "");
      return { text: text.trim() ? text : "", inTok: Number(u.prompt_tokens) || 0, outTok: Number(u.completion_tokens) || 0, why };
    }
  });
}
/* THE ONE DOOR EVERY DIRECT CALL GOES THROUGH. The engine on the Settings card decides
   whether it is Claude or Gemini; the callers do not know and do not care. */
/* ONE PLACE THAT KNOWS WHICH COMPANY IS WHICH — v26.7. It was four `if`s here and another
   three inside the Settings card's Test button; adding DeepSeek would have made it eight
   places to remember. Now the doors are a table keyed by the same words KEY_ENGINES uses, so
   a sixth engine is a record there and a line here, and nothing else in the portal has to
   learn its name. */
/* EXPORTED since v27.1: Mail asks this table whether the engine it resolved can be
   called at all, rather than keeping a second copy of the same four names. */
export const ENGINE_DOOR = { gemini, openai, grok, deepseek };
export async function callEngine(env, engine, body, what) {
  const door = ENGINE_DOOR[engine];
  if (!door) throw new Error((ENGINE_NAME[engine] || engine) + " is not an engine this portal can call.");
  return door(env, body, what);
}
async function askModel(env, body, what) {
  const engine = await aiEngine(env);
  if (ENGINE_DOOR[engine]) return callEngine(env, engine, body, what);
  /* Claude API: the model is the one chosen on the Settings card — Haiku 4.5 by default
     (10:12 pm: "Claude use only this Haiku 4.5") — never the one a caller hard-coded */
  return anthropic(env, Object.assign({}, body, { model: await claudeModel(env) }));
}
function extractJsonObject(text) {
  let t = String(text).replace(/```json|```/g, "").trim();
  const start = t.indexOf("{");
  if (start < 0) throw new Error("No JSON in model reply");
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < t.length; i++) {
    const ch = t[i];
    if (esc) { esc = false; continue; }
    if (ch === "\\") { esc = true; continue; }
    if (ch === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (ch === "{") depth++;
    if (ch === "}") { depth--; if (depth === 0) return JSON.parse(t.slice(start, i + 1)); }
  }
  throw new Error("Unbalanced JSON in model reply");
}
/* ══ v31.10 · A CUT-OFF ANSWER IS SALVAGED, NOT SHREDDED ═══════════════════════════════════
   Sujit, 19-Sep, on 98504371: "we have requested 15 questions, but only six is coming."

   The engine's reply had been cut off by the answer allowance partway through question five.
   With no closing "]" the strict parse below failed, and the old last-resort line splitter
   took over — which kept every line EXACTLY as the JSON had written it. That is why his
   screen showed questions wrapped in quotes and ending in  ",  and why question 4 was the
   half-sentence "...the symptoms you experienced that led to" with nothing after it.

   This walks the array literal instead: every COMPLETE string is recovered and parsed on its
   own (so every escape is handled properly), and only the half-written tail is dropped. It
   also reports `cut`, which is how generateQuestionnaire now knows to ask again with a bigger
   allowance rather than handing him four questions out of fifteen. */
function jsonArraySalvage(text) {
  const t = String(text).replace(/```json|```/g, "").trim();
  const a = t.indexOf("[");
  if (a < 0) return null;
  const out = [];
  let i = a + 1, closedArray = false, cutString = false;
  while (i < t.length) {
    const ch = t[i];
    if (ch === "]") { closedArray = true; break; }
    if (ch !== '"') { i++; continue; }                     // whitespace, commas, stray prose
    let j = i + 1, closed = false;
    for (; j < t.length; j++) {
      if (t[j] === "\\") { j++; continue; }                 // the escaped character is not a delimiter
      if (t[j] === '"') { closed = true; break; }
    }
    if (!closed) { cutString = true; break; }               // the reply stopped mid-question
    let v = null;
    try { v = JSON.parse(t.slice(i, j + 1)); } catch (e) { v = null; }
    if (typeof v === "string" && v.trim()) out.push(v.trim());
    i = j + 1;
  }
  return { list: out, cut: cutString || !closedArray };
}
/* true when the engine's answer stopped before the array closed — the signal that the number
   he typed was not refused, it simply ran out of room. */
function jsonArrayWasCut(text) { const s = jsonArraySalvage(text); return !!(s && s.cut); }
function extractJsonArray(text) {
  let t = String(text).replace(/```json|```/g, "").trim();
  const a = t.indexOf("["), b = t.lastIndexOf("]");
  if (a >= 0 && b > a) { try { const arr = JSON.parse(t.slice(a, b + 1)); if (Array.isArray(arr)) return arr.map(x => String(x).trim()).filter(Boolean); } catch (e) {} }
  const sal = jsonArraySalvage(t);                          // v31.10 — a truncated array still yields its whole questions
  if (sal && sal.list.length) return sal.list;
  /* last resort: an engine that answered in prose or markdown. The unwrapping is v31.10 — a
     line left over from broken JSON must never reach the page still wearing its quotes. */
  return t.split("\n")
    .map(l => l.replace(/^\s*[-*\d]+[.)]?\s*/, "").trim())
    .map(l => l.replace(/,\s*$/, "").replace(/^"([\s\S]*)"$/, "$1").trim())
    .filter(l => l.length > 8);
}

/* ---------- Fetch a claim's documents (PDFs) as base64 blocks ---------- */
async function fetchClaimDocs(env, claim, opts) {
  opts = opts || {};
  const rf = await skdGetCase(env, claim);
  const full = await rf.json();
  const allFolders = Array.isArray(full.questionSet) ? full.questionSet : [];
  /* ══ THE PETITIONER'S OWN PAPERS STAY OUT — v20.3 ══════════════════════════════════════
     Sujit, 02-Sep, on the Reporting page: "I don't want to check the documents of the
     petitioner — the claim documents. The rest of the documents need to be checked and the
     report put." The claimant's bundle (the petition copy, the claim form, whatever his
     advocate filed) is his side's story; the report is OURS, written from what the field
     found — police, hospital, spot, RC/DL, witnesses. So with skipClaimDocs the "Claim
     Documents" folder is left out, by name, and the report says which folders it did and
     did not read, so nobody has to wonder. */
  const skipRe = /claim\s*doc|claimant|petition/i;
  const folders = opts.skipClaimDocs ? allFolders.filter(f => !skipRe.test(f.folderName || "")) : allFolders;
  const skippedFolders = opts.skipClaimDocs ? allFolders.filter(f => skipRe.test(f.folderName || "")).map(f => f.folderName || "") : [];
  const remarks = folders.map(f => (f.folderName || "") + ": " + (f.remark || "-")).join("\n");

  // priority score by filename keywords
  const KW = ["postmartem","postmortem","pm report","police","fir","charge","death certificate","death cert","hospital","icp","mlc","wound","disability","panchnama","mahazar","spot","questionnaire","intimation","policy","claim form","rc ","kyc","dl ","neft","gpa","medical","nominee","passbook"];
  let files = [];
  folders.forEach(f => (f.files || []).forEach(fl => {
    const name = (fl.fileName || "");
    if (!/\.pdf$/i.test(name)) return;              // PDFs only (skip videos/images)
    let score = 0;
    const low = name.toLowerCase();
    KW.forEach((k, idx) => { if (low.indexOf(k) !== -1) score += (KW.length - idx); });
    files.push({ name: name, folder: f.folderName || "", url: fl.downloadUrl, id: fl.id, score: score });
  }));
  files.sort((a, b) => b.score - a.score);

  const blocks = [];
  const used = [];
  let totalBytes = 0;
  const MAX_DOCS = 12, MAX_TOTAL = 22 * 1024 * 1024, MAX_ONE = 9 * 1024 * 1024;
  for (const fl of files) {
    if (blocks.length >= MAX_DOCS || totalBytes >= MAX_TOTAL) break;
    try {
      const buf = await fetchCaseDocBuf(env, fl);
      if (!buf) continue;
      if (buf.byteLength > MAX_ONE || totalBytes + buf.byteLength > MAX_TOTAL) continue;
      totalBytes += buf.byteLength;
      blocks.push({ type: "document", source: { type: "base64", media_type: "application/pdf", data: base64FromArrayBuffer(buf) } });
      used.push(fl.name);
    } catch (e) { /* skip */ }
  }
  return { blocks, used, remarks, skippedFolders, folders: folders.map(f => f.folderName || "") };
}

/* ══════════ MPA locked format ══════════ */
const MPA_FIELD_KEYS = ["claimNumber","injuredDeceasedName","typeOfClaim","dateOfLoss","informantName","ilIntimationMode","ilIntimationDate","informantRelationship","policyNumber","insuredName","policyStartDate","policyEndDate","sumInsured","product","nomineeName","nomineeRelation","policyCoverage","iclmIntimationDate","iclmManager","investigatorName","tat","trigger","conclusionRecommendation","evidenceForRejection","claimantName","claimantAge","claimantOccupation","claimantRelation","narrationDetails","hospitalizationYN","hospIfNoReason","pmDetails","firDetails","otherInsurance","otherVehicleInvolvementYN","ovIfYesDetails","insuredDrivingYN","vehicleAsPerClaimant","drivingOwnVehicleYN","vicinityName","vicinityKnownSince","vicinityNarration","hospitalization2","mlcDone","hospitalName","hospitalAddress","hospitalCity","doa","dod","icpNotes","dateOfDeath","form4CauseOfDeath","treatingDoctorName","disabilityCertAvailable","disabilityDoctorName","disabilityDoctorQualification","disabilityDoctorRegNo","disabilityAuthority","natureOfDisability","disabilityReviewPercentage","bodyPartAffected","psName","psCity","psDistrict","psState","firDateTime","policeIOName","firSections","mvActSections","complainantName","complainantAddress","complainantContact","complainantRelationship","policeGist","chargeSheetDetails","tpVehicleInvolvement","tpVehicleIfYesDetails","pmDone","pmCenter","pmCity","pmDate","pmState","pmDoctor","pmCauseOfDeath","alcoholIntoxication","visceraPreserved","dcVerified","dcDate","dcIssuingOffice","geoCaptured","geoIfNoReason","latitude","longitude","vicinityAttribute","roadType","natureRoad","typeOfAccident","ivCoRelation","tpCoRelation","photographCollected","photoIfNoReason","eyeWitness","eyeWitnessName","eyeWitnessContact","eyeWitnessNarration","ilRcCopy","ilRcIfNoReason","ilRegNo","ilClassOfVehicle","ilMakeModel","ilColour","ilOwnerName","ilOwnerContact","ilOwnerType","ilUnladenWeight","ilLadenWeight","ilSeating","ilEngineNo","ilChassisNo","ilUsage","ilGeoReach","ovInvolvement","ovRcCopy","ovClass","ovOwnerName","ovMakeModel","ovColor","ovUnladenWeight","ovLadenWeight","ovSeating","ovEngineNo","ovChassisNo","ovInsurance","ovTpLiability","dlVerified","dlNo","dlName","dlRtoName","dlType","dlCategory","dlDob","driverContact","driverRelationWithInsured","odClaimRegistered","odClaimNumber","odCurrentStatus","odGor","odDriverName","odDlNumber","odMpaDriverMatching","tpClaimRegistered","tpClaimNumber","tpCourtStatus","tpIfClosed","tpPotentialLiability","tpIfPaidAmount","socialMediaReport","industryCheckReport","iclmConclusion","iclmOpinion","gor","evidenceRejectionCase","closureDate","annexure"];

const MPA_SYSTEM_PROMPT = `You are the senior claims investigation report writer of SKD health allied services (TaaSen), preparing the ICLM-format Motor Personal Accident (MPA / CPA owner-driver) Investigation Report for ICICI Lombard. You read the attached claim documents and the PORTAL FIELDS, and you return the report VALUES only. The report grid, labels and layout are fixed in the portal — you never output them.

OUTPUT CONTRACT — ABSOLUTE
1. Return ONE JSON object and nothing else. No markdown, no code fences, no commentary before or after.
2. Keys — exactly these, all of them, no extras, none missing:
${MPA_FIELD_KEYS.join(', ')}
3. Every value is a plain string. Unknown / not applicable = "NA". Use "" (empty) ONLY for a reason-cell whose paired answer is Yes (geoIfNoReason, ilRcIfNoReason) or when the PORTAL FIELDS give "".
4. Multi-line cells (dcIssuingOffice, iclmConclusion) use \\n for the line/paragraph breaks. iclmConclusion is exactly 3 paragraphs separated by \\n.

HOUSE REGISTER — the client rejects anything that reads machine-made
- Plain Indian insurance-investigation English. Short factual sentences. Write like a field manager typing the final report, not like an assistant.
- NEVER use inside any value: bullet points, numbering, asterisks, markdown, em dashes, or the words "furthermore", "moreover", "comprehensive", "meticulous", "delve", "leverage", "showcase", "additionally". No hedging ("it appears", "possibly", "likely"). No meta lines ("based on the documents provided").
- House abbreviations as-is: RTA, IV, RC, DL, PM, MLC, FIR, GOR, CPA, TP, OD, NCB.
- Names, addresses, vehicle numbers, policy numbers: copy the exact spelling and spacing printed in the source document. When two documents differ, follow: RC/DL/policy for identity fields, MLC/hospital record for hospital names, FIR/police record for police fields.
- Yes/No cells: write exactly "Yes" or "No" (police-section TP involvement rows use "NO" in caps, and odClaimRegistered / tpClaimRegistered use "NO", matching house usage).

DATE STYLE — per field, exactly
- dateOfLoss -> DD-MMM-YYYY with month in CAPITALS (example: 10-JAN-2026).
- ilIntimationDate -> DD-Mmm-YYYY (example: 11-Mar-2026).
- policyStartDate, policyEndDate, iclmIntimationDate, doa, dod, dateOfDeath, pmDate, dcDate, dlDob, closureDate -> DD-MM-YYYY.
- firDateTime -> DD/MM/YYYY at HH.MMhrs (24-hour, dot between hours and minutes, example: 10/01/2026 at 18.00hrs).
- Dates inside prose values (narrationDetails, pmDetails, firDetails, policeGist, icpNotes, iclmConclusion) -> DD.MM.YYYY.
- Clock times in prose follow: "at around 4pm", "At about 4:15 PM", "at 12:35 PM", "at 6.00pm".

VERDICT ENGINE — the four cells must always agree
- iclmOpinion is "Payable" or "Rejection". Decide only from documented facts.
- Payable -> conclusionRecommendation "Payable"; evidenceForRejection "NA "; gor "NA"; evidenceRejectionCase "NA"; conclusion paragraph 3 ends: "Hence, we close the case as Payable."
- Rejection -> conclusionRecommendation "Rejection under policy exclusion " (fraud cases: "Rejection under fraud "); evidenceForRejection "NA " unless specific evidence; gor = one short ground line; evidenceRejectionCase = the proving documents; conclusion paragraph 3 ends: "Hence, the claim stands rejected."
- Never write a payable sentence in a rejection report or vice versa.

iclmConclusion — EXACTLY three paragraphs separated by \\n:
P1 opens "This is RTA case of {type in house wording}. " then the accident story in past tense with the ownership/usage finding.
P2 coverage facts: whether the insured's own policy vehicle was involved; RC and DL validity; "The policy includes a Compulsory Personal Accident (CPA) cover for the owner-driver."
P3 admissibility beginning "As per the policy terms and conditions, …" then the fixed final sentence from the VERDICT ENGINE.

Death claim: disabilityCertAvailable "No", the other disability keys "NA", fill PM + DC blocks. PTD/Disability claim: fill the disability block from the certificate; PM/DC/death rows "NA".

PORTAL FIELDS are authoritative: whatever the portal supplies (claim number, intimation dates, ICLM manager, TAT, trigger, geo coordinates, closure date, investigator name, FO remarks) is copied into the matching keys verbatim, not re-derived. Read every attached document and fill the remaining ${MPA_FIELD_KEYS.length} keys. Any field not evidenced by a document or portal field is "NA".`;

function validateMPA(fields) {
  const f = Object.assign({}, fields);
  MPA_FIELD_KEYS.forEach(k => { if (!(k in f)) f[k] = "NA"; });
  return f;
}

async function generateMPA(env, claim, opts) {
  opts = opts || {};
  const list = await getCases(env);
  let cd = findCaseByClaim(list.cases, claim);
  /* a COMPLETED case may already have left the open feed — the Reporting page is exactly
     for those, so the closed book is asked too before giving up on the case's own details */
  if (!cd) { try { const cc = await getCompleteCases(env, "", "", {}); cd = findCaseByClaim(cc.cases || [], claim); } catch (e) {} }
  cd = cd || { claimNo: String(claim).replace(/\//g, "-") };   // accept the client's 1234/…/TP writing style
  const doc = await fetchClaimDocs(env, cd.claimNo, { skipClaimDocs: !!opts.skipClaimDocs });
  if (!doc.blocks.length) throw new Error("No PDF documents found for this claim" + (doc.skippedFolders.length ? " outside the claim-documents folder (" + doc.skippedFolders.join(", ") + " was left out on purpose)." : "."));
  const portal = {
    claimNumber: cd.claimNo, client: cd.client, subProduct: cd.subProduct, insured: cd.insured,
    fieldOfficer: cd.officerName, manager: cd.manager, tat: cd.tat, status: cd.status,
    createdOn: cd.createdOn, trigger: cd.trigger, investigatorName: "SKD health allied services"
  };
  const taskText = "PORTAL FIELDS (authoritative — copy verbatim into matching keys):\n" + JSON.stringify(portal, null, 1) +
          "\n\nFIELD OFFICER REMARKS BY FOLDER:\n" + doc.remarks +
          "\n\nRead every attached document of this Motor PA claim and return the report VALUES as the single JSON object per your instructions.";
  /* ── v24.0 · CONNECTOR MODE — the papers become text here, the thinking goes on the queue ── */
  if (opts.queue) {
    const docs = await docsToText(env, doc.blocks, doc.used);
    const jobId = await queueJob(env, {
      kind: opts.queue.kind || "mpa", ref: cd.claimNo, title: (opts.queue.kind === "report_mpa" ? "Reports — " : "Reporting — ") + cd.claimNo + (cd.insured ? " · " + cd.insured : ""),
      by: opts.queue.by || {}, instructions: MPA_SYSTEM_PROMPT, task: taskText, docs,
      meta: { used: doc.used, skipped: doc.skippedFolders, folders: doc.folders, claim: cd.claimNo }
    });
    return { queued: true, jobId, used: doc.used, skippedFolders: doc.skippedFolders, folders: doc.folders, docs: docs.map(d => ({ name: d.name, pages: d.pages, scanned: d.scanned, chars: d.chars, note: d.note })) };
  }
  const userBlocks = doc.blocks.concat([{ type: "text", text: taskText }]);
  const raw = await askModel(env, {
    model: "claude-sonnet-4-6",
    max_tokens: 8000,
    system: MPA_SYSTEM_PROMPT,
    messages: [{ role: "user", content: userBlocks }]
  }, "Reporting — " + cd.claimNo);
  return { fields: validateMPA(extractJsonObject(raw)), used: doc.used, skippedFolders: doc.skippedFolders, folders: doc.folders };
}

/* ---------- simple AI report (fallback for non-MPA) ---------- */
async function aiReportSimple(env, d) {
  const facts = "Claim: " + d.claimNo + "\nClient: " + d.client + "\nSub-Product: " + d.subProduct + "\nInsured: " + d.insured + "\nStatus: " + d.status + "\nOfficer: " + d.officerName + "\nTAT: " + d.tat + "\nTrigger: " + d.trigger;
  const raw = await askModel(env, {
    model: "claude-sonnet-4-6", max_tokens: 1200,
    system: "You are a senior insurance field investigation report writer. Write a formal report using only the facts provided, in sections: EXECUTIVE SUMMARY, BACKGROUND, SCOPE, OBSERVATIONS, CONCLUSION AND RECOMMENDATION.",
    messages: [{ role: "user", content: [{ type: "text", text: "Prepare the report:\n\n" + facts }] }]
  });
  return raw;
}

/* ══════════ Questionnaire — reads Discharge Summary + Final Bill (Claim Documents folder only) ══════════ */

/* ── THE SET TABLE — THE ONE PLACE A QUESTIONNAIRE SET IS ADDED ─────────────────────────────
   Sujit, 14-Sep-2026: "I will be giving multiple questions to ask — total seven questions
   will be there for that. Seven question detail, what will be there, I will tell you."
   Three sets are live below; the remaining four are his to name and are NOT invented here.

   ADDING ONE IS ONE RECORD IN THIS TABLE AND NOTHING ELSE. The AI prompt, the cards on the
   Questionnaire page, the Word paper, the PDF paper and the check suite all read this table —
   the page fetches it from /api/questionnaire/sets and only falls back to its own built-in
   copy of these three when that door cannot be reached. A record:

     key         the url word, lower case, no spaces               'insured'
     card        the short name printed on the card                'Insured'
     label       who the paper addresses — used in the AI prompt   'Insured'
     icon        the Font Awesome name for the card                'fa-user-injured'
     blurb       the grey line under the card's name
     max         the DEFAULT number of questions — he types over it on the card itself
     focus       the house brief: what this reader is to be probed on
     paper.title        the centred bold line on every printed page
     paper.instruction  the line under it
     paper.sign         the foot's first label
     paper.name         the foot's second label
     paper.perPage      how many questions are dealt onto one sheet
     paper.ansLines     blank writing lines left under each question
   ─────────────────────────────────────────────────────────────────────────────────────────── */
const Q_MAX_QUESTIONS = 60;   // the ceiling on the number he may type into a card
const Q_SUBJECTS = {
  insured: {
    key: "insured", card: "Insured", label: "Insured", icon: "fa-user-injured", max: 25,
    blurb: "Incident, history, PED, treatment, payments",
    focus: "Address the INSURED / claimant. Probe the presenting complaints and the exact incident (date, time, place, how it happened, who was present); the full past medical history with durations to expose any pre-existing disease not disclosed; prior treatments and hospitalisations; current ailments (BP, diabetes, heart, asthma) with since-when; why the cashless facility was or was not used; payment proofs and mode; other insurance; and any discrepancy between the account and the documents.",
    paper: { title: "Query to insured", instruction: "Kindly fill in the necessary details needed so as to help us process your claim at the earliest.", sign: "Signature", name: "Customer Name", perPage: 5, ansLines: 3 }
  },
  doctor: {
    key: "doctor", card: "Doctor", label: "Treating Doctor", icon: "fa-user-doctor", max: 6,
    blurb: "Diagnosis, duration, PED, admission necessity",
    focus: "Address the TREATING / FAMILY DOCTOR. Probe only the clinically decisive points: since when the patient is known to the doctor; the exact diagnosis and its duration; whether the condition is pre-existing; the medical necessity and justification for admission and length of stay; and any clarification the documents raise. Keep to the sharpest questions only.",
    paper: { title: "Query to treating doctor", instruction: "Doctor kindly fill in the necessary details needed so as to help us process the claim of your Patient at the earliest.", sign: "Doctor's Signature & Seal", name: "Doctor Name", perPage: 3, ansLines: 4 }
  },
  bill: {
    key: "bill", card: "Bill", label: "Hospital Billing / Records Department", icon: "fa-file-invoice-dollar", max: 10,
    blurb: "Final bill, breakup, ICP, pharmacy, receipts",
    focus: "Address the HOSPITAL BILLING / MEDICAL RECORDS department. Probe the final bill and its detailed breakup; tariff/package rates and any discounts; ICP (in-patient case papers); pharmacy bills versus medicines actually administered; lab register entries; admission and discharge records; final-bill paid receipts and payment mode; the TD letter; and any billing discrepancy or inflation.",
    paper: { title: "Query to billing department", instruction: "Kindly fill in the necessary details needed so as to help us process the claim of your patient at the earliest.", sign: "Authorised Signatory & Hospital Seal", name: "Name", perPage: 5, ansLines: 3 }
  }
  /* ── SETS 4 – 7 GO HERE, one record each, in the shape above. Nothing else changes. ── */
};
function qSet(key) { return Q_SUBJECTS[String(key || "").toLowerCase()] || Q_SUBJECTS.insured; }
function qSetExists(key) { return !!Q_SUBJECTS[String(key || "").toLowerCase()]; }
/* THE NUMBER HE TYPED WINS. Sujit, 14-Sep: "it has been marked max 25 — keep their editing
   option; whatever we typing there, that much question need to be coming." The card's figure
   is now a box he types into, so the set's own max is only the number it OPENS with. */
function qCount(s, asked) {
  const n = parseInt(asked, 10);
  if (isFinite(n) && n > 0) return Math.min(n, Q_MAX_QUESTIONS);
  return s.max;
}
/* the answer allowance has to grow with the count, or a 40-question ask is silently cut off
   mid-JSON and comes back as 25 — which reads exactly like the AI ignoring the number

   ══ v31.10 — RAISED, because 95 a question was never enough ═══════════════════════════════
   Sujit, 19-Sep, asked 98504371 for 15 and got 6. The old figure gave that ask 2,325 tokens.
   One of his real questions — "What were your specific reasons for choosing <hospital> in
   Coimbatore, Tamil Nadu, for your treatment, considering your residence in Haryana?" — is
   about 40 tokens on its own, and a REASONING model (Grok 4.x, the GPT-5 line) spends part of
   the same allowance thinking before it writes a single word of the answer. So the reply ran
   out of room in the middle of question five and the array never closed.
   150 a question with a floor of 3,000 leaves room for both the length and the thinking. */
function qTokens(want) { return Math.min(Math.max(1600 + want * 150, 3000), 16000); }
function qSystemPrompt(s, want, ground) {
  return "You are a senior health-insurance claim investigator at SKD Health Allied Services (TaaSen), drafting a field-investigation QUESTIONNAIRE in the firm's house style.\n"
    + "You are given AT MOST ONE attachment — the case's Discharge Summary (DS) — plus portal fields and the field officers' folder remarks. Write probing, case-specific questions for the " + s.label + ", grounded in what the discharge summary actually says — real admission/discharge dates, diagnosis, treatment, length of stay, and any discrepancy between the discharge summary and the portal fields or remarks. If the DS is stated as NOT ATTACHED, never assume or invent its contents. " + s.focus + "\n"
    + "HARD RULE: return EXACTLY " + want + " question" + (want === 1 ? "" : "s") + " — not one more, not one fewer. The number is the investigator's instruction, not a ceiling: if the case seems to need fewer, go wider (earlier episodes, other policies, the payment trail, the documents still to be produced) until you have " + want + ".\n"
    /* v26.8 — the chosen trigger's ground, and the rule that it is never said out loud */
    + (ground ? ("\n" + ground + "\n\n" + INDIRECT_RULE + "\n") : "")
    + "Courteous, formal Indian claims-investigation English. Where a written detail is expected, phrase it so the respondent can fill in dates, durations, names and amounts.\n"
    + "Output ONLY a JSON array of strings (the questions). No prose, no numbering prefixes, no markdown.";
}
/* Files in the Claim Documents folder are named "<claim number> DS.pdf" (Discharge Summary)
   and "<claim number> FB.pdf" (Final Bill) — short forms, sometimes with dots/hyphens/digits
   (D.S, DS1, FB 2) or the full words. We attach ONLY those two documents (max 2 PDFs), which
   keeps the AI cost to the minimum. Anything not found is reported back as "not mentioned". */
function qNorm(n) { return String(n || "").replace(/\.pdf$/i, "").replace(/[^a-z0-9]/gi, "").toLowerCase(); }
/* ── v30.3 · EVERY WAY THE DISCHARGE SUMMARY IS NAMED ─────────────────────────────────────────
   Sujit, 18-Sep: "The DS or discharge summary — first will be claim number, afterwards will be
   DS or discharge summary or discharge … it may be like this anything, you have to scan this."
   So: the short form DS (D.S, D S, D-S) wherever it sits, the word DISCHARGE in any form, and a
   bare SUMMARY — which is how a hospital's own file often arrives ("220101623168 Summary.pdf").
   A summary that names itself a BILL, a FINAL bill, a payment, an investigation or a report is
   NOT the discharge summary and must never be attached in its place: that is the one mistake
   that would have the questions asked off the wrong paper. */
function qIsDS(name) {
  const base = String(name || "").replace(/\.pdf$/i, "");
  if (/(?:^|[^a-z])d[\s._-]?s(?![a-z])/i.test(base)) return true;      // DS · D.S · D-S · D S
  if (/discharge/i.test(base)) return true;                             // Discharge / Discharge Summary
  if (/summar/i.test(base) && !/bill|final|payment|receipt|invoice|investigat|report|police|claim\s*form/i.test(base)) return true;
  return false;
}
function qIsFB(name) { const base = String(name || "").replace(/\.pdf$/i, ""); return /(?:^|[^a-z])f[\s._-]?b(?![a-z])/i.test(base) || /final[\s._-]*bill|finalbill/i.test(base); }
/* ══ v31.7 — THE PAPERS HE TICKED, AND NOTHING ELSE ═══════════════════════════════════════
   Sujit, 19-Sep: "FROM NOW, DON'T READ DS OR DISCHARGE SUMMARY ANYTHING AUTOMATICALLY."

   This used to pick ONE file out of Claim Documents by guessing at its name — DS, D.S,
   "<claim> DS", "Discharge", "Summary" — and download nothing else. On 220205311413 that
   folder holds a customer feedback form and a file called 220205311413COM.pdf; neither name
   matches, so nothing was attached at all and the questions were written blind.

   A name is not a document. Nothing is chosen here now: `picks` comes from the ticks he made
   on the Questionnaire page, and only those papers — only those PAGES — are downloaded. */
async function fetchQDocs(env, claim, picks) {
  const rf = await skdGetCase(env, claim);
  const full = await rf.json();
  const folders = Array.isArray(full.questionSet) ? full.questionSet : [];
  const remarks = folders.map(f => (f.folderName || "") + ": " + (f.remark || "-")).join("\n");
  const groups = listCaseDocs(full);
  let totalFiles = 0; groups.forEach(g => { totalFiles += g.files.length; });
  if (!picks || !picks.length) return { blocks: [], used: [], notes: [], remarks, totalFiles, groups };
  const got = await blocksForPicks({
    full, picks,
    fetchBuf: (fl) => fetchCaseDocBuf(env, fl),
    pdfText: qPdfText, pdfPageImages: qPdfPageImages, wordRead: qWordRead,
    b64: (b) => base64FromArrayBuffer(b instanceof Uint8Array ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b)
  });
  return { blocks: got.blocks, used: got.used, notes: got.notes, remarks, totalFiles, groups };
}

/* ── ONE SHAPE OF ANSWER, WHICHEVER COMPANY ANSWERS ─────────────────────────────────────────
   Sujit, 14-Sep-2026: "I need all AI API — whenever I switch, that need to give same answer
   or need to prepare same questionnaire. I don't want any changes with that."

   Five engines can be on that card (Connector · Claude key · Gemini · ChatGPT · Grok), and
   five companies will never write the same twenty-five English sentences. What CAN be made
   the same — and is, here — is everything around the sentences, because that is what makes
   one engine's questionnaire feel like a different product from another's:
     · the same system prompt and the same case text, built once, above, for all of them
     · the same discharge summary attached (worker.js translates the PDF block per engine)
     · the same COUNT, asked as EXACTLY n, and topped up below when an engine gives fewer
     · temperature 0 everywhere, so the same ask twice does not wander
     · the same tidy-up: numbering stripped, blanks and repeats dropped, cut to n
     · the same paper: the Word and the PDF are typeset by the portal, never by the engine
   So switching engines changes the wording; it never changes the count, the grounding, the
   format or the form. That is the promise the portal can actually keep. */
function qTidy(list, want) {
  const out = [], seen = {};
  for (const raw of (list || [])) {
    const q = String(raw == null ? "" : raw)
      .replace(/^\s*(?:[-*•]|\d{1,3}[.)])\s*/, "")      // an engine that numbered inside the string
      .replace(/\s+/g, " ").trim();
    if (q.length < 8) continue;
    const k = q.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (seen[k]) continue;
    seen[k] = 1; out.push(q);
    if (out.length >= want) break;
  }
  return out;
}
/* THE CASE, READ ONCE — v26.8. He presses Generate once and three papers come back
   (insured, doctor, billing), so the discharge summary must not be fetched and decoded three
   times over: once here, and the three asks share it. */
async function qPrepare(env, claim, picks) {
  const list = await getCases(env);
  const cd = findCaseByClaim(list.cases, claim) || { claimNo: String(claim).replace(/\//g, "-") };   // accept the client's 1234/…/TP writing style
  const doc = await fetchQDocs(env, cd.claimNo, picks);
  return { cd, doc, portal: { insurer: cd.client, insured: cd.insured, claim: cd.claimNo, hospital: cd.hospitalName, subProduct: cd.subProduct, scope: cd.trigger } };
}
/* v31.7 — what the page prints under the questions: the papers and PAGES actually read, and
   every paper that could not be. "ds"/"dsSeen" are gone with the guessing that made them. */
function qDocsOut(doc) { return { used: doc.used || [], notes: doc.notes || [], totalFiles: doc.totalFiles }; }

async function generateQuestionnaire(env, claim, subject, ailment, opts) {
  opts = opts || {};
  const s = qSet(subject);
  /* v32.3 — triggerAny, NOT triggerOf. A trigger Sujit added himself is not in the static
     table, so triggerOf answers null — and a null trigger here does not raise an error, it
     quietly drops his prompt and writes the paper with no ground at all. That is the worst
     shape a fault can take on this page: it looks like it worked. Same at the two sites
     below. subOf is left alone; it already returns a typed sub unchanged when the trigger
     has no list of its own, which is exactly a new trigger's case. */
  const trig = opts.trigger ? await triggerAny(env, opts.trigger, triggerOf) : null;
  const sub = trig ? subOf(trig, opts.sub) : "";
  let want = qCount(s, opts.count);
  let perTrigger = 0, groundCount = 0;     // v31.1 — set when he has added more than one trigger
  const prep = opts.prep || await qPrepare(env, claim, opts.picks);
  const cd = prep.cd, doc = prep.doc, portal = prep.portal;
  const docLine = docLineFor(doc.used, doc.notes);
  /* ── v30.3 · HIS PROMPT IS THE GROUND ─────────────────────────────────────────────────────
     Sujit, 18-Sep: "Whichever prompt it will be there means that only regarding that question
     will we be asking." So for the INSURED and the DOCTOR paper the ground is his own sheet
     cell for this exact Trigger + Sub Trigger — column C and column D — or the prompt he typed
     and kept under Others. Only when there is no prompt at all for the pair (his "Fall from
     height" row, where column C is empty) does the trigger's old brief stand in, so the page
     still works rather than writing nothing. The BILL paper is unchanged: his Sheet2 is the
     same seven points for every trigger, and those seven are already the bill brief. */
  /* ══ v31.1 · UP TO THREE TRIGGERS, AND THEIR PROMPTS ARE THE WHOLE GROUND ══════════════
     Sujit, 18-Sep 3:18 pm: "If I added two triggers means, in that, what prompt is there,
     THAT PROMPT ONLY the question needs to be prepared ... I don't want any extra things."

     So every pair he picked is read, its prompt for THIS side of the paper is taken, and the
     ground is those prompts and nothing else. Our own standing brief for a trigger stands in
     only when NOT ONE of his pairs has a prompt for this side — otherwise a pair with an
     empty column C would quietly drag our old wording in behind his. The bill paper is
     untouched: his Sheet2's seven points are the same for every trigger. */
  let ground = trig ? groundFor(trig, sub, s.key) : "";
  if (trig && (s.key === "insured" || s.key === "doctor")) {
    const pairs = [{ trig, sub }];
    for (const x of (Array.isArray(opts.more) ? opts.more : [])) {
      const t2 = await triggerAny(env, x && x.trigger, triggerOf);   /* v32.3 — his own triggers count here too */
      if (!t2) continue;
      const s2 = subOf(t2, (x && x.sub) || "");
      if (pairs.some(p => p.trig.key === t2.key && String(p.sub || "") === String(s2 || ""))) continue;
      if (pairs.length < 3) pairs.push({ trig: t2, sub: s2 });
    }
    const built = [];
    for (let i = 0; i < pairs.length; i++) {
      const pr = (i === 0 && opts.prompt !== undefined) ? opts.prompt : await promptFor(env, pairs[i].trig.key, pairs[i].sub);
      const side = promptSideFor(s.key, pr);
      if (side) built.push({ label: pairs[i].trig.label, sub: pairs[i].sub, text: side, note: (pairs[i].trig[s.key] || {}).note });
    }
    if (built.length) ground = groundFromPrompts(built);
    /* ══ v31.1 · THE NUMBER IS PER TRIGGER ═══════════════════════════════════════════════
       Sujit, 18-Sep: "If I give three prompts means three trigger sub trigger, THREE AND
       THREE also need to be asked the questions." So the number in his box is what EACH
       trigger gets, not a total to be shared out — ten questions on three triggers is thirty,
       ten for each ground in turn. Capped at the page's own ceiling so a slip on the box
       cannot ask for a paper nobody would read. */
    if (built.length > 1) {
      perTrigger = want;
      want = Math.min(want * built.length, Q_MAX_QUESTIONS);
      groundCount = built.length;
    }
  }
  const caseText = "CASE / PORTAL FIELDS:\n" + JSON.stringify(portal, null, 1) +
    (ailment ? ("\n\nAilment / focus hint: " + ailment) : "") +
    "\n\n" + docLine +
    "\n\nCLAIM DOCUMENTS — FIELD OFFICER REMARKS:\n" + doc.remarks +
    "\n\nWrite the " + s.label + " questionnaire now — EXACTLY " + want + " question" + (want === 1 ? "" : "s") + " — as a JSON array of question strings. Ground the questions in the attached document(s). If a document is marked NOT ATTACHED, do not assume or invent its contents — work only from what is available."
    + (trig ? " Cover the confidential ground given in your instructions, and remember that not one word of that ground may appear in a question." : "")
    /* v31.1 — and when there is more than one ground, the number is per ground, in order */
    + (groundCount > 1 ? (" There are " + groundCount + " grounds in your instructions: write EXACTLY " + perTrigger
        + " question" + (perTrigger === 1 ? "" : "s") + " for EACH of them, in the order they are given, for " + want
        + " in all. Do not write about anything outside those " + groundCount + " grounds.") : "");
  const userBlocks = doc.blocks.concat([{ type: "text", text: caseText }]);
  const sys = qSystemPrompt(s, want, ground);
  /* ── v24.0 · CONNECTOR MODE — the discharge summary becomes text, the questions are asked of Claude on his plan ── */
  if (opts.queue) {
    const docs = opts.docsText || await docsToText(env, doc.blocks, doc.used);
    const jobId = await queueJob(env, {
      kind: "questionnaire", ref: cd.claimNo + "|" + s.key,
      title: "Questionnaire — " + cd.claimNo + " · " + s.label + (cd.insured ? " · " + cd.insured : "") + (trig ? " · " + trig.label : ""),
      by: opts.queue.by || {}, instructions: sys + "\nHARD RULE: exactly " + want + " questions.", task: caseText, docs,
      meta: { claim: cd.claimNo, subject: s.key, max: want, count: want, label: s.label, trigger: trig ? trig.key : "", sub: sub, ds: doc.ds, dsSeen: doc.dsSeen, totalFiles: doc.totalFiles }
    });
    return { queued: true, jobId, used: doc.used, docs: qDocsOut(doc), max: want, count: want, trigger: trig ? trig.key : "", sub };
  }
  const ask = (msgs, tok) => askModel(env, { model: Q_MODEL, max_tokens: tok, temperature: 0, system: sys, messages: msgs }, "Questionnaire — " + cd.claimNo);
  const first = [{ role: "user", content: userBlocks }];
  let raw = await ask(first, qTokens(want));
  /* ══ v31.10 · RAN OUT OF ROOM IS NOT THE SAME AS REFUSED ══════════════════════════════════
     An array that never closed means the engine was still writing when the allowance ended —
     it did not decline the number, it was cut off. Asking the same thing again with room to
     finish is the honest answer to that, and it is tried ONCE. A refusal, by contrast, comes
     back closed and short, and falls through to the top-up below exactly as before. */
  if (jsonArrayWasCut(raw)) {
    try { raw = await ask(first, Math.min(qTokens(want) * 2, 16000)); } catch (e) { /* the cut reply still stands */ }
  }
  let qs = qTidy(extractJsonArray(raw), want);
  /* THE TOP-UP. He typed a number; short of an engine refusing outright, that number is what
     comes back. Each pass asks for the shortfall only, and the questions already written go
     with it so a later batch cannot repeat them.

     v31.10 — two passes, not one, and it stops the moment a pass adds nothing. On 98504371
     the single pass was the difference between 6 and 15: the first ask was cut off at four,
     one top-up brought two more, and the page gave up there. A pass that earns nothing means
     the engine has said all it will, and waiting through a third is just his morning. */
  for (let pass = 0; pass < 2 && qs.length < want; pass++) {
    const short = want - qs.length;
    const before = qs.length;
    try {
      /* ONE user turn, never an assistant turn: OpenAI's and xAI's door want an assistant
         message written in output parts, Google's wants a model role, Anthropic's wants
         neither — one user turn is the only shape all four read the same way. */
      const again = userBlocks.concat([{
        type: "text",
        text: "ALREADY WRITTEN — " + qs.length + " of the " + want + " questions asked for:\n"
          + qs.map((q, i) => (i + 1) + ". " + q).join("\n")
          + "\n\nWrite the remaining " + short + " now — fresh questions on ground not yet covered above, never a rewording of one already written. Output ONLY a JSON array of the " + short + " new question strings."
      }]);
      const more = await ask([{ role: "user", content: again }], qTokens(short));
      qs = qTidy(qs.concat(extractJsonArray(more)), want);
    } catch (e) { /* the batches already written still stand — a failed top-up must not lose them */ }
    if (qs.length <= before) break;                 // that pass earned nothing; another will not
  }
  return { questions: qs, count: want, asked: want, short: Math.max(want - qs.length, 0), used: doc.used, docs: qDocsOut(doc), trigger: trig ? trig.key : "", sub };
}

/* ══ ALL THREE IN ONE PRESS — v26.8 ═════════════════════════════════════════════════════════
   Sujit, 14-Sep-2026 9:47 pm: "I will tell to generate the questionnaire means need to
   generate at a time at three. Also for insured, doctor and the billing at a time need to be
   reflected. Once created, we will check the QC and we will select that to send to claim
   documents."

   So one press, one reading of the discharge summary, three papers on the screen together,
   and the sending is a separate decision he makes after he has read them. The three asks run
   in sequence rather than together on purpose: the engines are rate-limited per key, and a
   burst of three is how a key earns a 429 in the middle of his morning. */
const Q_ALL_SETS = ["insured", "doctor", "bill"];
/* "trigA|subA,trigB|subB" → [{trigger, sub}], at most two extra pairs. Kept small and dumb
   on purpose: generateQuestionnaire checks every trigger name against the real list, so
   nothing that is not a trigger can reach the ground from here. */
function qMorePairs(raw) {
  const out = [];
  String(raw == null ? "" : raw).split(",").forEach(seg => {
    const t = String(seg || "").trim();
    if (!t || out.length >= 2) return;
    const i = t.indexOf("|");
    const trigger = (i > -1 ? t.slice(0, i) : t).trim().slice(0, 60);
    const sub = (i > -1 ? t.slice(i + 1) : "").trim().slice(0, 160);
    if (trigger) out.push({ trigger, sub });
  });
  return out;
}
async function generateQuestionnaireAll(env, claim, opts) {
  opts = opts || {};
  const prep = await qPrepare(env, claim, opts.picks);
  /* v30.3 — his prompt for this pair is read ONCE for the three papers, not once each */
  const trigNow = opts.trigger ? await triggerAny(env, opts.trigger, triggerOf) : null;   /* v32.3 — see generateQuestionnaire */
  const promptNow = trigNow ? await promptFor(env, trigNow.key, subOf(trigNow, opts.sub)) : null;
  const wants = opts.counts || {};
  const docsText = opts.queue ? await docsToText(env, prep.doc.blocks, prep.doc.used) : null;
  const out = { sets: {}, jobs: {}, docs: qDocsOut(prep.doc), claim: prep.cd.claimNo, queued: false };
  for (const key of (opts.only && opts.only.length ? opts.only : Q_ALL_SETS)) {
    if (!qSetExists(key)) continue;
    try {
      const r = await generateQuestionnaire(env, claim, key, opts.ailment, {
        prep, docsText, count: wants[key], trigger: opts.trigger, sub: opts.sub, queue: opts.queue,
        more: opts.more,           // v31.1 — the second and third trigger, if he added them
        prompt: promptNow          // v30.3 — the same prompt for all three papers, read once
      });
      if (r.queued) { out.queued = true; out.jobs[key] = { jobId: r.jobId, count: r.count }; }
      else out.sets[key] = { questions: r.questions, count: r.count };
    } catch (e) {
      /* one paper failing must not lose the other two — he can press Generate again for that
         one alone, with the other two already written and edited on his screen */
      out.sets[key] = { questions: [], count: qCount(qSet(key), wants[key]), error: String((e && e.message) || e).slice(0, 300) };
    }
  }
  return out;
}

/* ══════════════════════ AUTH — Google sign-in + approval ══════════════════════ */
const GOOGLE_CLIENT_ID = "1073218863392-hs11aeofa1uvb2f6274c7g42ks3kjgcl.apps.googleusercontent.com";
/* IDLE AUTO-LOGOUT — the session lasts this long and SLIDES forward on activity (see
   /api/auth/me), so an active person is never signed out; this many minutes with NO activity
   ends it. Sujit, 14-Aug-2026: "seven minutes it will be logout — extend till 20 minutes."
   THIS IS THE ONE THAT MATTERS. The four browser copies of the idle watcher only decide when
   the SCREEN gives up; the cookie is what the server honours, and leaving it at 7 while the
   pages waited 20 would have signed people out at seven minutes anyway — with the screen
   still looking alive, which is worse than the original complaint. Both were changed. */
const SESSION_TTL = 20 * 60;
function adminEmails(env) { return String(env.ADMIN_EMAILS || "sujith.dn@skdhealth.com").toLowerCase().split(",").map(s => s.trim()).filter(Boolean); }

function b64urlBytes(bytes) { let bin = ""; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]); return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64urlStr(str) { return b64urlBytes(new TextEncoder().encode(str)); }
function b64urlToStr(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return new TextDecoder().decode(b); }
async function hmac(secret, data) { const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)); return b64urlBytes(new Uint8Array(sig)); }
async function makeSession(env, payload) { const body = b64urlStr(JSON.stringify(payload)); const sig = await hmac(env.SESSION_SECRET, body); return body + "." + sig; }
const SESSION_COOKIE = "__Host-skd_session"; // __Host- = browser refuses this cookie over insecure HTTP or from another host
async function readSession(env, request) {
  if (!env.SESSION_SECRET) return null;
  const jar = request.headers.get("Cookie") || "";
  let m = jar.match(/(?:^|;\s*)__Host-skd_session=([^;]+)/);
  if (!m) m = jar.match(/(?:^|;\s*)skd_session=([^;]+)/); // old cookie name still accepted so nobody is kicked mid-session
  if (!m) return null;
  const token = decodeURIComponent(m[1]); const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const body = token.slice(0, dot), sig = token.slice(dot + 1);
  const expect = await hmac(env.SESSION_SECRET, body);
  if (!timingSafeEqual(sig, expect)) return null;
  let p; try { p = JSON.parse(b64urlToStr(body)); } catch (e) { return null; }
  if (!p.exp || p.exp < Math.floor(Date.now() / 1000)) return null;
  if (p.ua) { const h = await uaHash(request); if (h && !timingSafeEqual(p.ua, h)) return null; } // stolen-cookie shield: cookie only works in the browser it was issued to
  return p;
}
function sessionCookie(token, maxAge) { return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }

/* ══════════════════ EMAIL OTP SIGN-IN (beside Continue with Google) ══════════════════
   His ask: "they will paste their mail ID and get the OTP for mail ID — send, verify, and
   they can login: Continue with Google OR the OTP with mail ID."
   POST /api/auth/otp/start {email}  → a 6-digit code is MAILED; only its salted SHA-256
                                       hash is kept in KV, for 10 minutes.
   POST /api/auth/otp/verify {email, code} → the SAME signed session cookie as Google.
   Codes are single-use, 6 wrong tries kill them, resends wait 45 seconds, and one mail ID
   gets at most 6 codes an hour. Only APPROVED portal members can ask for a code at all.
   The mail itself goes out through whichever of these is configured in Cloudflare:
     · OTP_MAIL_URL (+ OTP_MAIL_KEY) — the TaaSen Apps Script mailer web app (free), or
     · BREVO_API_KEY (+ OTP_MAIL_FROM) — Brevo's email API.                              */
/* ── v34.9 · passwords (see /api/auth/password) ─────────────────────────────────────────── */
const PW_ITER = 100000;   /* the most PBKDF2 rounds a Worker allows */
let pwReady = false;
async function pwEnsure(env) {
  if (pwReady || !env.DB) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS portal_passwords (email TEXT PRIMARY KEY, hash TEXT, salt TEXT, iter INTEGER, must_change INTEGER DEFAULT 0, set_by TEXT, set_at INTEGER, fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0, last_login INTEGER)").run();
  pwReady = true;
}
async function pwHash(pw, saltHex, iter) {
  const salt = new Uint8Array(String(saltHex || "").match(/../g).map(x => parseInt(x, 16)));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(pw)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter || PW_ITER }, key, 256);
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function pwWeak(pw) {
  pw = String(pw || "");
  if (pw.length < 8) return "A password needs at least 8 characters.";
  if (pw.length > 128) return "That password is too long.";
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return "Use letters and numbers together.";
  return "";
}
function pwGenerate() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz", D = "23456789";
  const r = new Uint32Array(10); crypto.getRandomValues(r);
  let s = "";
  for (let i = 0; i < 6; i++) s += A[r[i] % A.length];
  for (let i = 6; i < 10; i++) s += D[r[i] % D.length];
  return s;
}
async function pwStore(env, email, pw, by, mustChange) {
  await pwEnsure(env);
  const sb = new Uint8Array(16); crypto.getRandomValues(sb);
  const salt = [...sb].map(x => x.toString(16).padStart(2, "0")).join("");
  const hash = await pwHash(pw, salt, PW_ITER);
  await env.DB.prepare("INSERT INTO portal_passwords (email, hash, salt, iter, must_change, set_by, set_at, fails, locked_until) VALUES (?1,?2,?3,?4,?5,?6,?7,0,0) ON CONFLICT(email) DO UPDATE SET hash = ?2, salt = ?3, iter = ?4, must_change = ?5, set_by = ?6, set_at = ?7, fails = 0, locked_until = 0")
    .bind(String(email).toLowerCase(), hash, salt, PW_ITER, mustChange ? 1 : 0, String(by || ""), Date.now()).run();
}
async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(s)));
  return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function otpMailBody(code) {
  return "Your TaaSen Claims Portal sign-in code is:\n\n    " + code + "\n\nIt works for 10 minutes and only once. If you did not ask for this code, simply ignore this mail — nobody can enter without it.\n\nTaaSen Claims Assistance Services · SKD inside";
}
async function sendOtpMail(env, email, code) {
  const subject = "TaaSen Portal — your sign-in OTP is " + code;
  /* v34.9 — Sujit, 29-Sep: two OTP mails came, one from sujith.dn@skdhealth.com (the Apps Script relay)
     and one from no-reply@taasenclaims.com. "Any one mail need to go … keep the no-reply mail … stop
     sending from my mail." no-reply goes FIRST now; the relay is only the spare if it refuses. */
  if (env.RESEND_API_KEY) {
    const r0 = await otpResend(env, { from: "TaaSen Claims Portal <no-reply@" + otpMailDomain(env) + ">", to: [email], subject, text: otpMailBody(code) });
    if (r0 && r0.ok) return { ok: true, via: "no-reply" };
  }
  if (env.OTP_MAIL_URL) {
    const r = await fetch(env.OTP_MAIL_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: env.OTP_MAIL_KEY || "", to: email, code, subject, text: otpMailBody(code) })
    });
    let j = null; try { j = await r.json(); } catch (e) { }
    if (r.ok && (!j || j.ok !== false)) return { ok: true };
    return { ok: false, why: "mailer answered " + r.status + (j && j.error ? " — " + j.error : "") };
  }
  if (env.BREVO_API_KEY) {
    const from = (env.OTP_MAIL_FROM || "no-reply@skdhealth.com").trim();
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST", headers: { "Content-Type": "application/json", "api-key": env.BREVO_API_KEY },
      body: JSON.stringify({ sender: { email: from, name: "TaaSen Claims Portal" }, to: [{ email }], subject, textContent: otpMailBody(code) })
    });
    if (r.ok || r.status === 201) return { ok: true };
    return { ok: false, why: "Brevo answered " + r.status };
  }
  if (env.RESEND_API_KEY) return { ok: false, why: "the no-reply mailer refused the OTP mail" };
  return { ok: false, why: "not configured — set OTP_MAIL_URL (Apps Script mailer) or BREVO_API_KEY in Cloudflare" };
}

async function verifyGoogleToken(idToken) {
  if (!idToken || typeof idToken !== "string" || idToken.length > 4096) return null;
  const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken));
  if (!r.ok) return null;
  const p = await r.json();
  if (p.aud !== GOOGLE_CLIENT_ID) return null;
  if (p.iss !== "accounts.google.com" && p.iss !== "https://accounts.google.com") return null; // must really be Google
  if (!(p.email_verified === true || p.email_verified === "true")) return null;
  if (p.exp && Number(p.exp) * 1000 < Date.now()) return null;                                 // expired token
  if (!p.email) return null;
  return { email: String(p.email).toLowerCase(), name: p.name || p.email };
}

/* ── THE D1 STATE SHELF — v17.8, born at 8:52 pm in front of ten people ─────────────────
   Dr Senthil Kumar pressed Save to history in the meeting and the screen said:
   "Could not save — KV put() limit exceeded for the day." Cloudflare's free KV allows
   1,000 writes A DAY, and today spent them: the GST timer's heartbeat alone writes once
   a MINUTE (1,440/day — the whole allowance on its own), and every meeting note and
   attendance mark paid from what was left, until a live meeting hit the wall.
   The house rule from the GST day already said it: KV is for settings somebody edits now
   and again; anything written often belongs in D1 — which allows 100,000 writes a day.
   So this shelf: the same JSON blobs, the same keys, a different cupboard. stGet reads
   D1 first and falls back to the old KV value once, so nothing already written is lost —
   the first save re-homes it. The hot keys (meeting notes, attendance, the GST heartbeat)
   now live here; true settings stay in KV where they belong. */
let stateShelfReady = false;
async function stEnsure(env) {
  if (stateShelfReady || !env.DB) return;
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS portal_state (k TEXT PRIMARY KEY, v TEXT)").run(); stateShelfReady = true; } catch (e) {}
}
async function stGet(env, k) {
  if (env.DB) {
    try {
      await stEnsure(env);
      const row = await env.DB.prepare("SELECT v FROM portal_state WHERE k = ?1").bind(k).first();
      if (row && row.v != null) return row.v;
    } catch (e) {}
  }
  if (env.USERS) { try { return await env.USERS.get(k); } catch (e) {} }   // the old cupboard, read-only
  return null;
}
/* The same read, but a database fault is REPORTED rather than swallowed. stGet answers null
   both for "nothing stored" and for "D1 did not answer", and for most keys that is fine. For
   the out-of-TAT completion memory it is not: a null there is read as "nobody has ever
   completed anything", every completed case is stamped afresh as completed NOW, and the
   whole memory is written back over the real one. v20.3 — see /api/ootat. */
async function stGetStrict(env, k) {
  if (!env.DB) throw new Error('no database binding');
  await stEnsure(env);
  const row = await env.DB.prepare("SELECT v FROM portal_state WHERE k = ?1").bind(k).first();
  return (row && row.v != null) ? row.v : null;
}
async function stPut(env, k, v) {
  await stEnsure(env);
  await env.DB.prepare("INSERT INTO portal_state (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2").bind(k, v).run();
}
async function stDel(env, k) {
  if (!env.DB) return;
  try { await stEnsure(env); await env.DB.prepare("DELETE FROM portal_state WHERE k = ?1").bind(k).run(); } catch (e) {}
}
async function stList(env, prefix) {
  if (!env.DB) return [];
  try {
    await stEnsure(env);
    const r = await env.DB.prepare("SELECT k, v FROM portal_state WHERE k LIKE ?1").bind(prefix + "%").all();
    return (r && r.results) || [];
  } catch (e) { return []; }
}
/* stSoft — a write that must never be able to break the thing it rides on. Signing in,
   sending an OTP, marking attendance: the ACT matters, the bookkeeping around it does not.
   31-Aug-2026, 8:58 pm: the sign-in page itself printed "KV put() limit exceeded for the
   day" and nobody could get in — because a login was allowed to fail on a counter. */
async function stSoft(env, k, v) { try { await stPut(env, k, v); } catch (e) {} }

/* ── THE MEMBER LIST, AND THE NIGHT IT LOCKED EVERYBODY OUT ────────────────────────────
   31-Aug-2026, 8:58 pm: the sign-in page answered "KV put() limit exceeded for the day".
   An APPROVED member — an admin, no less — was refused entry because the portal wanted to
   re-save a record that had not changed, and could not. Two rules come out of that night:
     · a record identical to the one already stored is not written at all (an admin signing
       in ten times used to cost ten writes of the same three lines);
     · when KV refuses anyway, the record goes to the D1 SHADOW and the sign-in carries on.
       The shadow is only ever written when KV said no, so it is always the newer copy — it
       is read first, and deleted the moment a real KV write succeeds again. */
async function kvGetUser(env, email) {
  if (env.DB) {
    try { const sh = await stGet(env, "ushadow:" + email); if (sh) return JSON.parse(sh); } catch (e) {}
  }
  if (!env.USERS) return null;
  try { const v = await env.USERS.get("u:" + email); return v ? JSON.parse(v) : null; } catch (e) { return null; }
}
async function kvPutUser(env, u) {
  const json = JSON.stringify(u);
  if (env.USERS) {
    try {
      const cur = await env.USERS.get("u:" + u.email);
      if (cur === json) return;                       // nothing changed — nothing to spend
      await env.USERS.put("u:" + u.email, json);
      await stDel(env, "ushadow:" + u.email);         // KV is authoritative again
      return;
    } catch (e) { /* falls through to the shadow */ }
  }
  await stSoft(env, "ushadow:" + u.email, json);
}
async function kvListUsers(env) {
  const byEmail = new Map();
  if (env.USERS) {
    try {
      const l = await env.USERS.list({ prefix: "u:" });
      for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { const uu = JSON.parse(v); byEmail.set(uu.email, uu); } catch (e) {} } }
    } catch (e) {}
  }
  for (const row of await stList(env, "ushadow:")) {   // the shadow wins: it is the newer copy
    try { const uu = JSON.parse(row.v); byEmail.set(uu.email, uu); } catch (e) {}
  }
  return Array.from(byEmail.values());
}

// ---- section-level access control (which portal pages a member may open) ----
/* ══════════ EVERY PAGE IS ITS OWN TICK — v28.0, 16-Sep-2026 ═════════════════════════
   Sujit, 7:42 am, MAHALAKSHMI ARUL's access drawer open:

     "In this, why all the options are not coming? For example the Document Register, the RTI
      one — every option needs to be there. Whichever I need, I will be selecting."

   He is right, and the reason is a habit that ran five times. Each of these five pages was
   added AFTER the access lists were written, and each was quietly hung off an older page's
   tick so that nobody would have to re-tick a box on the morning it shipped:

       Daily Brief         rode on  Dashboard
       Document Register   rode on  Upload Docs
       Not Activated FO    rode on  Field Officers
       FO Completed        rode on  Quality Audit
       CM Reviewed         rode on  Analytics

   Kind on the day, wrong ever after: the Document Register shows every claim number, insured
   and manager in the open book, and the only way to withhold it was to take away Upload Docs
   as well. He could not grant what he wanted or refuse what he did not.

   All five are real sections now. The old riding rule survives ONLY as a fallback for a list
   written before today: such a list is SILENT about these keys, not refusing them, so until
   it is saved again it still answers with the page each one used to ride on — nobody loses a
   page this morning. The moment Admin saves a person, the list carries ACL_EXPLICIT and every
   one of the five means exactly what the tick says, including un-ticked. Admin pre-ticks them
   from the old parent when it opens a silent list, so pressing Save never quietly takes a
   page away from somebody.                                                                  */
const ACCESS_ALIAS = { brief: "dashboard", docreg: "upload", foinactive: "officers", focompleted: "ootat", cmreviewed: "analytics" };
const ACL_EXPLICIT = "acl-v28";          // written by Admin on every save from v28.0 onward
const ACCESS_SECTIONS = ["dashboard", "brief", "business", "cases", "upload", "docreg", "newcase", "officers", "foinactive", "mbv", "reports", "analytics", "questionnaire", "ootat", "focompleted", "released", "cmreviewed", "ootatmeet", "mgrfollow", "feedback", "appointment", "ohsteam", "docs", "claimmatch", "field", "videocall", "fochange", "accounts", "joining", "foreq", "meet", "settings", "mail",
  /* v32.0 — the two invoicing keys. They MUST be here as well as in EXPLICIT_SECTIONS:
     ACCESS_SECTIONS is what accessOf() hands an admin and a boss, so a key missing from it
     makes canAccess() answer NO even to the admin. That is what bounced Sujit off
     /invoice.html into /portal on the very first deploy of v32.0, while /api/invoice/ping
     answered him perfectly — because invoiceRole() short-circuits on role first and the page
     gate did not. EXPLICIT_SECTIONS below still stops the pages arriving by silence for
     anybody else. ANY NEW PAGE KEY GOES IN BOTH LISTS. */
  "invoicing", "invoicing_admin"];
/* v21.0 — BILL VERIFICATION is never granted by silence. Every other page reads a missing
   access list as "all" (legacy-safe: the list was written before the page existed). Sujit,
   05-Sep-2026, prompt 1 of the MBV build: "OHS, coordinator and manager roles get no access
   unless explicitly granted." So this page needs the tick — or the post — by name. */
/* v23.2 — "joining" joins the list. Sujit, 09-Sep 2:40 pm: "in HR role you have to add one
   more thing called New Joining — add for the HR access." Until now New Joining was a ROLE
   rule buried in the page's own code (admin, boss, HR, and nobody else could ever be given
   it, nor could HR be taken off it). It is a page like any other now: admin and boss always
   have it, HR has it by default, and anybody else needs the tick BY NAME — applicants'
   phone numbers, photographs, resumes and bank details are not something to arrive by
   silence, so it sits beside Bill Verification on the explicit list. */
/* v32.0 — INVOICING joins them, for the same kind of reason. What we charge each insurer,
   the rate card and every bill ever raised are not something a page hands out because an
   access list written before the page existed happened to be silent. Both keys are explicit:
   "invoicing" raises and reads, "invoicing_admin" also edits the masters, unflags a GSTIN,
   cancels a raised invoice, runs the GST export and sees the bill number ledger. A
   client-manager and a call-centre login are refused OUTRIGHT inside the module whatever is
   ticked here — see INVOICE_NEVER_ROLES in invoice-index.js. */
const EXPLICIT_SECTIONS = ["mbv", "joining", "invoicing", "invoicing_admin"];
/* v22.2 — WHAT A POST GETS BY DEFAULT. Sujit, 08-Sep-2026 3:36 pm: "default, this only access
   need to be given to manager … if I want, I will be adding for someone." A member of one of
   these posts who is approved WITHOUT a page list gets exactly this set — not every page — and
   the admin ticks more for a particular person on top. Mirrors POST_DEFAULT_PAGES in admin.html.
   Every other post keeps the old rule (no list = everything except the explicit-only pages). */
/* ── EVERY POST'S PAGES, FROM HIS OWN CHECKLIST ── v23.3 · 09-Sep-2026 ─────────────────
   Sujit, 09-Sep 3:20 pm: "Whatever I have given now, that only need to give access. I don't
   want extra access … if I am selecting only two access, need to be reflecting for them, but
   they're getting all access after any update. I don't want anything like that."
   He is right, and there were THREE separate ways it happened:
     1 · a post with no saved page list meant EVERY page (that is what "defaultAccessFor"
         used to return), so anybody approved without a list, and every post added later,
         opened with the lot;
     2 · canAccess() handed Field Tracker to a manager, coordinator and product head by
         name, whatever the tick said — a grant his checklist could not take away;
     3 · the same override was mirrored in the sidebar, so even where the server refused,
         the menu item was drawn.
   All three are gone. This table IS the answer now: every post has an explicit list, taken
   from the checklist he filled in and saved on 9 Sep, and a post that somehow reaches here
   without one gets the Dashboard alone — never everything. */
const ROLE_DEFAULT_ACCESS = {
  "manager":                    ["dashboard", "business", "cases", "analytics", "questionnaire", "ootat", "mgrfollow", "ootatmeet", "field"],
  "product-head":               ["dashboard", "analytics", "questionnaire", "newcase", "claimmatch", "ootat", "mgrfollow", "ootatmeet", "field"],
  "coordinator":                ["dashboard", "analytics", "claimmatch", "mgrfollow", "ootatmeet", "ohsteam", "field"],
  "ohs":                        ["dashboard", "analytics", "mgrfollow", "ootatmeet"],
  "call-centre":                ["feedback", "appointment"],
  "hr":                         ["dashboard", "analytics", "claimmatch", "accounts", "officers", "joining", "mgrfollow", "ootatmeet", "field"],
  "ootat-manager":              ["dashboard", "analytics", "claimmatch", "appointment", "mgrfollow", "ootatmeet", "field"],
  "rti-manager":                ["dashboard", "analytics", "claimmatch", "upload", "field"],
  "document-manager":           ["dashboard", "analytics", "claimmatch", "docs", "questionnaire"],
  "hardcopy-dispatch-manager":  ["dashboard", "analytics", "docs"],
  "hardcopy-receiving-manager": ["dashboard", "analytics", "docs"],
  "mbv_operator":               ["dashboard", "analytics", "mbv", "field"],
  "mbv_checker":                ["dashboard", "analytics", "mbv"],
  "client-manager":             ["dashboard", "analytics", "claimmatch"],
  "accounts-team":              ["dashboard", "analytics", "accounts"],
  "assign-team":                ["dashboard", "analytics", "newcase", "field"],
  /* v25.0 — the field officer's post: Mail only (+ the case Mail button where a case list is shown to him) */
  "field-officer":              ["mail"]
};
/* v25.0 — Sujit, 10-Sep: "default access for Mail for everyone who has this portal." Every post
   on the checklist carries it — the sixteen he ticked on 9-Sep included — so a person given the
   portal has the Mail page the same minute. accessOf() adds it by silence as well (mailOff takes
   it away by name); listing it here is what makes the Admin checklist SHOW the tick. */
for (const k of Object.keys(ROLE_DEFAULT_ACCESS)) if (!ROLE_DEFAULT_ACCESS[k].includes("mail")) ROLE_DEFAULT_ACCESS[k].push("mail");
/* v25.8 — and FO Requests the same way, for every post that may ask. Sujit, 12-Sep: "except
   field officer and OHS, rest all need to give access for this." Listed here so the Admin
   checklist SHOWS the tick; accessOf() adds it by silence as well (foreqOff takes it away). */
const FOREQ_NEVER = ["field-officer", "client-manager"];   // a man asking for his own limit; an insurer's login. An OHS asks for HIS TEAM (3:40 pm) — fenced in foreq-index.js
for (const k of Object.keys(ROLE_DEFAULT_ACCESS)) if (!FOREQ_NEVER.includes(k) && !ROLE_DEFAULT_ACCESS[k].includes("foreq")) ROLE_DEFAULT_ACCESS[k].push("foreq");
/* v28.0 — a post's default list was written when these five rode on another page, so each
   post keeps whatever it would have had: derived once, here, rather than five edits per post
   that somebody would get wrong. */
(function seedAliasDefaults() {
  try {
    for (const r in ROLE_DEFAULT_ACCESS) {
      const L = ROLE_DEFAULT_ACCESS[r];
      if (!Array.isArray(L)) continue;
      for (const k in ACCESS_ALIAS) if (L.includes(ACCESS_ALIAS[k]) && !L.includes(k)) L.push(k);
    }
  } catch (e) { }
})();
function defaultAccessFor(role) {
  /* v23.3 — NEVER "everything" again. A post we have no table row for is a post nobody has
     decided about yet, and the safe answer to that is the Dashboard, not the whole portal. */
  return ROLE_DEFAULT_ACCESS[role] ? ROLE_DEFAULT_ACCESS[role].slice() : ["dashboard"];
}
/* the two posts that ARE the bill-verification desk: they always have the page, and nothing
   else unless ticked. Operator: create, upload, grid, draft. Checker: + Approve and Send. */
const MBV_ROLES = ["mbv_operator", "mbv_checker"];
function mbvRoleOf(u) {
  if (!u) return "";
  if (u.role === "admin" || u.role === "boss") return "admin";
  if (u.role === "mbv_checker") return "checker";
  if (u.role === "mbv_operator") return "operator";
  if (!canAccess(u, "mbv")) return "";
  return u.mbvRole === "checker" ? "checker" : "operator";
}
// admin + boss always see everything; anyone else is limited to their stored `access` list
// (a missing list means "all", so nobody is locked out by an older record).
/* The insurer's own login gets these two pages and nothing else, whatever is ticked. His
   words: "they have to get that cases, they have to get Analytics." Dashboard is the case
   list and Analytics is the ageing — both already read the scoped feed, so both narrow to
   his client by themselves. Fixed here rather than left to a tick, because a stray tick on
   an OUTSIDE login is a different order of mistake from a stray tick on one of ours. */
/* Sujit, 17-Aug-2026, on the Client Manager row: "Claim Match I need to give this also access."
   Safe to add because the fence is in the DATA, not in the page list: /api/open-cases and
   /api/complete-cases both run scopeCases, and for a client-manager that narrows to his own
   insurer AND strips our field officers' and managers' names in the same call. So a client
   pasting a list of claim numbers can only ever match his own book, and what comes back
   carries no name of ours. The page's own FO and Manager columns are hidden for him too —
   an empty column headed "Field Officer(s)" is not a leak, but it invites the question. */
const CLIENT_SECTIONS = ["dashboard", "analytics", "claimmatch"];
/* ADMIN AND NOBODY ELSE.
   Sujit, 18-Aug-2026: "The setting option need to come only for admin access."
   The Settings PAGE has always refused a non-admin — but the sidebar entry showed for anybody
   whose access list was silent, which is every member whose list was written before the page
   existed. A menu item that opens a locked door is worse than no menu item: it reads as
   something withheld rather than something that was never theirs, and it invites the question
   every week. This list is the fence, and it sits in accessOf so the server, the sidebar and
   the page cannot drift apart — one rule, never a second copy.
   It is deliberately NOT given to "boss" either: this page holds the Acefone token and the
   webhook key, and the page itself has only ever admitted role === "admin". */
const ADMIN_ONLY_SECTIONS = ["settings"];
/* THE OHS (TEAM HEAD) LOGIN — TWO PAGES, FULL STOP.
   Sujit, 20-Aug-2026, on a Meet with the first OHS login open on the shared screen, reading
   a sidebar of fifteen items: "OHS — don't want this many drop-down. Only the Dashboard and
   Analytics, that is enough."
   Same construction as the Client Manager fence above and for the same reason: fixed HERE,
   not left to ticks, so the sidebar, the routes and the Admin console can never drift
   apart. Both pages already narrow to his own team by themselves — the case feeds scope by
   his team's officer names, and (v12.6) the team list serves him his group alone — so the
   two pages he keeps are already HIS two pages. Note this also takes the Field Tracker off
   him: 'ohs' left FIELD_DEFAULT_ROLES the same day, because a default that outranks the
   fence would put a fifteenth item straight back on the sidebar. */
const OHS_SECTIONS = ["dashboard", "analytics"];
/* v18.0 — Sujit, 31-Aug, 9:28 pm: "I am giving this access, Out of TAT, for OHS — for
   particularly their team cases. Need to reflect for them."
   The 20-Aug fence (Dashboard + Analytics, whatever is ticked) was written when a team head
   had no business on a case-working page. That has changed for exactly two pages, and only
   these two may be added: the meeting and its inside-TAT twin. It is safe to grant BECAUSE
   the case scoping is already per-team — scopeCases() has narrowed an OHS login to his own
   team's officers since the role was born, and the meeting page, the remark box and the
   attendance register all pass through it. So the team head sees his own men's overdue
   cases and nobody else's, and the product-wide override below is refused to him by name. */
/* v20.4 — Sujit, 2-Sep-2026: "for OHS, only their cases need to be reflected in all,
   whatever I'm giving the access." So the grantable list grows to every case page whose feed
   already runs through scopeCases() for this role — Completed From Field (/api/ootat), FO
   Completed · Released · CM Reviewed (release-index + accounts-index), Cases (/api/open-cases),
   Business, Appointment, Feedback (fenced in this same version) and Documents (its list is the
   scoped open feed). Pages that carry company-wide data with no per-case fence — Upload, New
   Case, Field Officers, Reports, Questionnaire, Claim Match, Video Call, Officer Changed,
   Accounts, Settings — stay off the list, because a tick there would show him everything. */
/* v21.0 — 'mbv' is grantable to a team head by an explicit tick (the MBV register is the
   desk's own book, not SKD case data, so the per-team fence does not apply to it) */
const OHS_GRANTABLE = ["ootatmeet", "mgrfollow", "ootat", "released", "cases", "business", "appointment", "feedback", "docs", "mbv"];
/* v25.0 — MAIL IS THE ONE PAGE EVERYBODY HAS. Sujit, 10-Sep: everyone who has the portal has
   Mail. So it is the opposite of EXPLICIT_SECTIONS: granted by silence to every post (the OHS
   and Call-Centre fences included — a fence on case data is not a reason to keep a man from
   his own letters), and taken away only by name: the admin un-ticks it for one person and the
   record carries mailOff = true. A record that has never heard of the tick has it. The one
   post that never gets it is the insurer's own login (client-manager): the domain is ours. */
/* v25.8 — FO REQUESTS arrives the way Mail does: for every post BY SILENCE, except the two he
   named. Sujit, 12-Sep: "except field officer and OHS, rest all need to give access for this."
   Every one of the 17 managers carries a saved page list from 9-Sep that is silent about a key
   that did not exist then, and reading that silence as "no" would mean ticking 40 people by
   hand before a single request could be raised — the Mail rule of 10-Sep was made for exactly
   this. So: on by default for everyone who may ask, off by name for a field officer and an
   insurer's login (the server refuses them at the door as well), and foreqOff takes it away per
   person. An OHS has it — 3:40 pm: "for OHS, their field officer, their team, only they can do
   it" — and is fenced to his own team inside the module. */
function accessOf(u) {
  let list = accessOfPages(u);
  if (!u || u.role === "client-manager") return list;
  if (u.mailOff === true) list = list.filter(x => x !== "mail");
  else if (!list.includes("mail")) list = list.concat(["mail"]);
  if (FOREQ_NEVER.includes(u.role) || u.foreqOff === true) list = list.filter(x => x !== "foreq");
  else if (!list.includes("foreq")) list = list.concat(["foreq"]);
  /* v31.0 — DAILY MEETINGS arrives the way Mail did, and for the same reason: every saved
     page list in the portal was written before this key existed, and reading that silence as
     "no" would mean ticking eighty people by hand before one stand-up could be called. On by
     silence for every post, off by name with meetOff. The insurer's login never has it — it
     is above, where client-manager returns early. */
  if (u.meetOff === true) list = list.filter(x => x !== "meet");
  else if (!list.includes("meet")) list = list.concat(["meet"]);
  return list;
}
function accessOfPages(u) {
  if (!u) return [];
  if (u.role === "client-manager") return CLIENT_SECTIONS.slice();
  if (u.role === "ohs") {
    /* v23.3 — a team head with no saved list gets HIS TABLE ROW, not the bare two. The old
       fallback quietly dropped the pages the checklist gives him (IN TAT, Out of TAT) the
       moment a record had no list of its own — the opposite fault to the one he reported,
       and just as wrong: a tick that goes missing is a man locked out of his own meeting. */
    const src = Array.isArray(u.access) ? u.access : defaultAccessFor("ohs");
    const extra = src.filter(x => OHS_GRANTABLE.includes(x));
    return OHS_SECTIONS.concat(extra.filter(x => !OHS_SECTIONS.includes(x)));
  }
  if (u.role === "admin") return ACCESS_SECTIONS.slice();
  if (u.role === "boss") return ACCESS_SECTIONS.filter(x => !ADMIN_ONLY_SECTIONS.includes(x));
  /* v23.2 — HR always carries New Joining. Every HR record written before today is silent
     about the key (the page was a role rule then), and reading that silence as "no" would
     lock HR out of his own page the morning this ships. */
  if (u.role === "hr") {
    const lst = (Array.isArray(u.access) ? u.access.filter(x => ACCESS_SECTIONS.includes(x) && !ADMIN_ONLY_SECTIONS.includes(x)) : defaultAccessFor("hr"));
    return lst.includes("joining") ? lst : ["joining"].concat(lst);
  }
  /* the bill-verification posts always carry their page, plus whatever else is ticked */
  if (MBV_ROLES.includes(u.role)) {
    /* v23.3 — and the same for the two desks: no saved list means the table row, which is
       where his Dashboard and Analytics ticks live. Before this they opened on the Bill
       Verification page alone and nothing else. */
    const src = Array.isArray(u.access) ? u.access : defaultAccessFor(u.role);
    const extra = src.filter(x => ACCESS_SECTIONS.includes(x) && !ADMIN_ONLY_SECTIONS.includes(x));
    return extra.includes("mbv") ? extra : ["mbv"].concat(extra);
  }
  const list = (Array.isArray(u.access) ? u.access.filter(x => ACCESS_SECTIONS.includes(x)) : defaultAccessFor(u.role))
    .filter(x => !ADMIN_ONLY_SECTIONS.includes(x));
  // the Out of TAT Manager's whole job is the meeting — that page stays on whatever else is ticked
  if (u.role === "ootat-manager" && !list.includes("ootatmeet")) return list.concat(["ootatmeet"]);
  return list;
}
/* THE FIELD TRACKER TICK, AND WHY IT HAS A DEFAULT.
   The page was added on 12-Aug-2026, by which time every existing member already had an
   access list written for him. Such a list cannot say "Field Tracker: no" — it can only be
   silent, because the page did not exist when it was saved. Reading that silence as "no"
   would have locked out every manager and coordinator on the portal on the morning it
   shipped, which is the opposite of what was asked for:

     "If manager will be opening, need to come manager access. If admin or boss will be
      opening, need to reflect admin access itself, and the coordinator need to get access."

   So these four roles have it by default and the tick is there to GIVE it to anybody else —
   an ootat-manager, an rti-manager, a document manager. HR and Call-Centre do not get it by
   default and must be ticked, which is deliberate: the map shows where 187 men are standing,
   with their photographs, and that is not something to hand out by accident.
   v12.7, 20-Aug-2026: "ohs" came OFF this list the day the OHS login was fenced to
   Dashboard + Analytics ("only the dashboard and analytics, that is enough") — a default
   that outranks accessOf would have kept the Field Tracker on his sidebar regardless. */
const FIELD_DEFAULT_ROLES = ["manager", "coordinator", "product-head"];
/* a list saved by Admin from v28.0 on says so, and is then read word for word */
function aclExplicit(u) { return !!(u && Array.isArray(u.access) && u.access.indexOf(ACL_EXPLICIT) >= 0); }
function canAccess(u, section) {
  /* v23.3 — the Field Tracker override is GONE. It granted the page to a manager, coordinator
     and product head by role, over the top of the access list, so un-ticking it in Admin did
     nothing at all: "they're getting all access after any update. I don't want anything like
     that." Those three posts carry it on his checklist, so nothing changes for them — the
     difference is that it is now a tick he can take away. One rule, no exceptions. */
  const list = accessOf(u);
  if (list.includes(section)) return true;
  /* v28.0 — the five late pages: a list written before they had ticks is silent, not a
     refusal, so it is still answered by the page each one used to ride on. An explicit list
     gets no such help: there, un-ticked means no. */
  const parent = ACCESS_ALIAS[section];
  if (parent && !aclExplicit(u)) return list.includes(parent);
  return false;
}
// Sections that expose the case data itself. Call-Centre members have none of these,
// so the open-cases feed and the Excel/sheet downloads stay closed to them.
function canSeeCaseData(u) { return ["dashboard", "cases", "upload", "reports", "analytics", "questionnaire", "ootat", "ootatmeet", "mgrfollow", "ohsteam", "docs", "claimmatch", "fochange"].some(s => canAccess(u, s)); }

/* ---- OUT OF TAT MEETING: per-member PRODUCT access ----------------------------------
   One manager runs the out-of-TAT review meeting on top of his own manager job. For the
   product(s) ticked for him in Admin he sees EVERY case of that product — all states, all
   managers — because he is the one asking the officers. He is still an ordinary Manager
   everywhere else on the portal (Dashboard, Cases, Reports, Analytics ...): there he keeps
   seeing only his own cases, exactly as before. An empty list = no extra reach at all, so
   nothing changes for the other managers.                                              */
const MEET_PRODUCTS = ["TP", "Health"];
/* v23.2 — THE ASSIGNING DESK'S PRODUCT. Sujit, 09-Sep 2:40 pm: "for Assigning Team … you
   have to add Motor TP or Health, that option also select." The same two tickboxes, meaning
   the opposite thing: the assigning desk is not fenced to its own work — it already sees the
   whole pool — so a ticked product NARROWS it to that product rather than widening it. Both
   un-ticked leaves both products, which is how every assign-team record written before today
   reads, so nobody's view changes until somebody ticks a box on purpose. */
function assignProductsOf(u) {
  if (!u || u.role !== "assign-team") return [];
  const p = Array.isArray(u.meetProducts) ? u.meetProducts.filter(x => MEET_PRODUCTS.includes(x)) : [];
  return p.length === 1 ? p : [];        // one ticked = narrowed; none or both = everything
}
function meetProductsOf(u) {
  if (!u) return [];
  if (u.role === "admin" || u.role === "boss") return MEET_PRODUCTS.slice();
  if (u.role === "assign-team") return [];   // its product tick narrows the case feed, it does not run a meeting
  if (!canAccess(u, "ootatmeet") && !canAccess(u, "mgrfollow")) return [];   // the product tick only means something with a meeting page ticked
  /* v18.0 — THE TEAM HEAD IS NEVER WIDENED. A ticked product means "you run the meeting for
     all of it, every manager, every state" — the opposite of what an OHS login is for. His
     whole grant is "particularly their team cases", so the override is refused here by name
     rather than depending on nobody ever ticking a box in Admin. */
  if (u.role === "ohs") return [];
  /* v20.4 — THE STATE COORDINATOR IS NEVER WIDENED EITHER. Sujit, 2-Sep-2026: "for state
     coordinator I need only their cases to reflect in Out of TAT, IN TAT … I selected only
     Andhra-Telangana and Karnataka, but he is getting all access. I don't want that." The
     product tick on a coordinator meant "run the meeting for the whole product, every state"
     — the opposite of a grant that names his states. Refused here by role, exactly like the
     team head, so no tick in Admin can ever open the other states to him. */
  if (u.role === "coordinator") return [];
  const got = Array.isArray(u.meetProducts) ? u.meetProducts.map(x => String(x)).filter(x => MEET_PRODUCTS.includes(x)) : [];
  /* OUT OF TAT MANAGER — this is the role whose whole job is the meeting: every manager, every
     state. Admin can narrow him to Motor TP only or Health only by ticking one; with nothing
     ticked he runs both, so the role is never handed out empty. */
  if (u.role === "ootat-manager") return got.length ? got : MEET_PRODUCTS.slice();
  return got;
}
/* May this person type a meeting remark on this claim?
   Yes if the claim belongs to a product he was given, otherwise only inside his own slice. */
async function meetScopeCheck(env, me, claim) {
  if (!me || me.role === "admin" || me.role === "boss") return { allowed: true, notFound: false };
  const prods = meetProductsOf(me);
  if (prods.length) {
    const d = await getCases(env);
    const found = findCaseByClaim(d.cases, claim);
    if (!found) return { allowed: false, notFound: true };
    if (prods.includes(typeOfSub(found.subProduct))) return { allowed: true, notFound: false, claimNo: found.claimNo };
  }
  return claimScopeCheck(env, me, claim);
}

/* ══ THE ACEFONE RESULT-WEBHOOK KEY — owned by the portal, not by Cloudflare ══════════════
   Sujit, 17-Aug-2026, after forty minutes lost inside the Cloudflare dashboard trying to add
   one variable: "You only go and build it immediately and make this live."

   He was right to be annoyed. The old design put this key in a Worker environment variable,
   which meant: invent a random value with no help, tick a Secret box that is easy to miss,
   press a Deploy button that is easy to miss, and know that a variable saved without that
   press is silently not live. Four ways to get it wrong, and three of them fail with the
   SAME message, which is how the same half-hour got repeated.

   So the key now lives in KV, where the portal can create it, rotate it and read it back
   without anybody opening Cloudflare at all. Three things this must not break:

     1. THE ENV VAR STILL WINS NOTHING BUT STILL WORKS. Anyone who already set
        FEEDBACK_WEBHOOK_KEY keeps working — KV is checked first, the variable is the
        fallback. Nobody's live webhook stops the day they take this update.
     2. THE KEY IS MADE BY crypto.randomUUID() ON THE EDGE. Not by a person under pressure,
        and not by an assistant in a chat log — the value exists first inside Cloudflare and
        is never guessable from anything anybody has read.
     3. IT IS STILL COMPARED THE SLOW-SAFE WAY. Moving where the key is stored must not
        change how it is checked, so timingSafeEqual stays exactly where it was.           */
/* ══ THE ACEFONE API TOKEN — the portal can hold it too ═══════════════════════════════════
   Sujit, 17-Aug-2026, 9:15pm, after a day in which this token was deleted by accident and
   four separate attempts to put one back died on the same Cloudflare steps: the Secret box
   that is easy to miss, the Deploy button that is easy to miss, and the fact that missing
   either fails with a message identical to never having tried.

   So the token gets the same treatment the webhook key got in v9.8 — it can live in KV and be
   pasted once, from the portal, by an admin. But the PRECEDENCE IS THE OTHER WAY ROUND, and
   deliberately so:

     · the webhook key is MADE by the portal, so the portal's copy must win or pressing
       Generate would appear to do nothing;
     · this token is issued by Acefone and pasted in by a person. Cloudflare's secret store is
       the better home for it — encrypted at rest, invisible in the dashboard — so if a value
       is set there it WINS, and the portal's copy is only the fallback for when it is not.

   That way moving it into Cloudflare properly, later, is an upgrade that needs no cleanup: the
   moment the variable exists, it takes over.

   The trade-off is stated plainly on the Settings card rather than buried: a token in KV is
   readable by anything that can read this namespace, where a Worker secret is not. It is
   offered because a token nobody can install is worth nothing, and calling has been dead all
   day. It is never handed back to a browser once saved — only a mask of it. */
const ACE_KV_KEY = "acefone:token";
async function acefoneTokenOf(env) {
  if (env.ACEFONE_API_TOKEN) return { token: String(env.ACEFONE_API_TOKEN), source: "cloudflare", setBy: "", setTs: 0 };
  if (env.USERS) {
    try {
      const raw = await env.USERS.get(ACE_KV_KEY);
      if (raw) { const j = JSON.parse(raw); if (j && j.token) return { token: String(j.token), source: "portal", setBy: j.setBy || "", setTs: j.setTs || 0 }; }
    } catch (e) { /* unreadable -> no token, never a silent wrong one */ }
  }
  return { token: "", source: "none", setBy: "", setTs: 0 };
}

const HOOK_KV_KEY = "fbhook:key";
async function webhookKeyOf(env) {
  if (env.USERS) {
    try {
      const raw = await env.USERS.get(HOOK_KV_KEY);
      if (raw) {
        const j = JSON.parse(raw);
        if (j && j.key) return { key: String(j.key), source: "portal", setBy: j.setBy || "", setTs: j.setTs || 0 };
      }
    } catch (e) { /* unreadable -> fall through to the variable, never to "no key" silently */ }
  }
  if (env.FEEDBACK_WEBHOOK_KEY) return { key: String(env.FEEDBACK_WEBHOOK_KEY), source: "cloudflare", setBy: "", setTs: 0 };
  return { key: "", source: "none", setBy: "", setTs: 0 };
}
/* A key nobody has to invent. randomUUID is a real CSPRNG inside the Worker runtime, so the
   value is born on Cloudflare's edge and has never existed in a chat, a note or a screenshot. */
function newWebhookKey() {
  const a = crypto.randomUUID().replace(/-/g, "");
  const b = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  return "hk" + a + b;                                   // 42 chars, letters+digits only, URL-safe
}
/* The whole line he pastes into Acefone. Built from the request's own origin so it is right
   on the workers.dev address and on any custom domain later, with no hard-coded host to rot.
   The $words are Acefone's placeholders and must reach it unencoded — so they are appended
   as literal text, never through URLSearchParams, which would turn "$call_status" into
   "%24call_status" and quietly deliver a webhook that names no claim and updates nothing. */
function webhookUrlFor(origin, key) {
  return origin + "/api/feedback/webhook?key=" + encodeURIComponent(key)
    + "&claim=$custom_identifier&call_status=$call_status&duration=$duration"
    + "&recording=$recording_url&agent_number=$agent_number";
}
/* Never print a key in full on a screen that gets screenshotted. */
function maskKey(k) {
  const s = String(k || "");
  if (s.length <= 10) return s ? "••••••••" : "";
  return s.slice(0, 4) + "…" + s.slice(-4) + "  (" + s.length + " characters)";
}

/* ---------- Acefone caller-ID numbers + agent list (for the calling pages) ----------
   Baked from the Acefone console (Click to Call → Select Number / Select Agent).
   Change anytime WITHOUT re-uploading the site: add Worker variables
   ACEFONE_CALLER_IDS / ACEFONE_AGENTS (comma-separated; agents as Name:number). */
const ACEFONE_CALLER_IDS_DEFAULT = "918062034808,918062034809,918062034810,918062034811,918062034812,918062034813,918062034814,918062034815,918062034816,918062034817";
/* ── WHY +913333333333 IS GONE FROM THIS LIST (7-Aug-2026) ───────────────────────────────
   Acefone's own call listing settled a fortnight of "the call says success but my phone
   never rings". Read down its "rings first" column:
        Extension-0602256780003  →  answered · 98 seconds   ✓
        +913333333333            →  missed   ·  0 seconds   ✗
   3333333333 is not a telephone. It was a placeholder that got into this default list, and
   because "Megala" appeared TWICE in the dropdown — once as the working extension, once as
   that dummy — picking the wrong Megala rang a number that cannot exist. Acefone accepted
   the order ("queued"), dialled nothing that could answer, and the portal reported success.
   The dummy is deleted, and obviously-fake numbers are refused at the point of dialling
   below, so no list can ever put one back by accident. */
const ACEFONE_AGENTS_DEFAULT = "Megala:0602256780003,B GANESAN:0602256780004,B GANESAN:+919900197283,Suryanarayanan:+918056267447";
function acefoneCallerIds(env) { return String(env.ACEFONE_CALLER_IDS || ACEFONE_CALLER_IDS_DEFAULT).split(",").map(s => s.trim()).filter(Boolean).slice(0, 60); }
/* A number made of one repeated digit (3333333333, 0000000000 …) is never a real phone.
   It is always a placeholder somebody typed, and on the agent leg it fails silently. */
function aceFakeNumber(v) {
  const d = String(v == null ? "" : v).replace(/[^\d]/g, "").replace(/^91/, "");
  return d.length >= 6 && /^(\d)\1+$/.test(d);
}
function acefoneAgents(env) {
  return String(env.ACEFONE_AGENTS || ACEFONE_AGENTS_DEFAULT).split(",").map(s => s.trim()).filter(Boolean).slice(0, 120).map(p => {
    const i = p.indexOf(":");
    const a = i > 0 ? { name: p.slice(0, i).trim(), num: p.slice(i + 1).trim() } : { name: p, num: p };
    /* an extension is the kind that answers on this account — say so in the dropdown, so
       two entries for the same person are never a coin toss again */
    a.kind = /^0\d{10,}$/.test(String(a.num).replace(/[^\d]/g, "")) ? "extension" : "phone";
    return a;
  }).filter(a => !aceFakeNumber(a.num));
}

/* ── WHICH ACEFONE ACCOUNT PLACED THIS CALL ──────────────────────────────────────────────
   Sujit, 17-Aug-2026, holding the Acefone console (Users: B GANESAN, Malar Mannan, Megala,
   Srinivasa Murthy, Stella, Suryanarayanan) against the Appointment page:
   "I want to get this detail also which account they are booking their accounts. Their name
   need to be reflected."

   Until now every call attempt stored two things — the PORTAL login that pressed Call
   (`by`), and the digits handed to Acefone (`agent`). Neither of those is the answer to his
   question. One login can ring any of six accounts; 0602256780003 means nothing to anyone
   reading a row. So the name is resolved HERE, on the server, from this account's own agent
   list — never taken from anything the browser sends, because a browser that can name the
   account can also name the wrong one, and a call log that can be written to is not a
   record. An unknown number is reported as unknown, never guessed at: an unmatched call
   said to belong to somebody is worse than one that admits it has no name. */
function acefoneWho(env, num) {
  const want = aceDigits(num);
  if (!want) return { name: "", num: "", kind: "", known: false };
  const list = acefoneAgents(env);
  for (let i = 0; i < list.length; i++) {
    if (aceDigits(list[i].num) === want) return { name: list[i].name, num: want, kind: list[i].kind, known: true };
  }
  /* not on the list — the shape still tells us what KIND of leg this was */
  return { name: "", num: want, kind: /^0\d{10,}$/.test(want) ? "extension" : "phone", known: false };
}
/* One line fit to print on a row, in a mail, or in a dialog. Never invents a name. */
function acefoneWhoLabel(w) {
  if (!w || !w.num) return "";
  if (!w.known) return w.num + " (not on this account's agent list)";
  return w.name + " · " + (w.kind === "extension" ? "extension " : "") + w.num;
}

/* ---------- Acefone number cleaning + the one place a call is actually placed ----------
   Both calling pages (Feedback + Appointment) go through acefoneDial() so a fix
   made once is a fix made everywhere.

   Why the numbers are re-written before they are sent
   ---------------------------------------------------
   Acefone's own examples send DIGITS ONLY — no "+", no spaces, no brackets. A "+"
   was being passed straight through from the "Who is calling?" list (+919900197283),
   and the customer's mobile was being sent as a bare 10 digits. Leg 1 (your phone)
   still rings, because Acefone already knows that agent; leg 2 (the customer) is
   handed to the phone network, which refuses a number it cannot route. That is
   exactly the "my phone rang, I answered, then silence" fault.

   So: strip everything that is not a digit, and add the 91 country code when — and
   only when — the number is a plain 10-digit Indian mobile. Acefone AGENT IDs such
   as 0602256780003 are 13 digits and must reach Acefone untouched, which is why the
   91 is never bolted onto anything that is not exactly 10 digits.                    */
function aceDigits(s) { return String(s == null ? "" : s).replace(/[^\d]/g, ""); }
function aceNumber(s) {
  const d = aceDigits(s);
  if (!d) return "";
  if (d.length === 10) return "91" + d;                                          // 9900197283   -> 919900197283
  if (d.length === 11 && d.charAt(0) === "0") return "91" + d.slice(1);          // 09900197283  -> 919900197283
  if (d.length === 12 && d.slice(0, 2) === "91") return d;                       // already right
  if (d.length === 13 && d.slice(0, 3) === "091") return d.slice(1);             // 0919900197283-> 919900197283
  return d;                                                                      // agent IDs (0602256780003) pass through whole
}
/* Which "Call from" number will really be used, and whether the one asked for is allowed.
   Returns { cid, note } — note is plain English, safe to show on screen.               */
function acefoneCid(env, wanted) {
  const allowed = acefoneCallerIds(env).map(aceDigits);
  const want = aceDigits(wanted);
  if (want && allowed.indexOf(want) >= 0) return { cid: want, note: "the number you picked in “Call from”" };
  if (want) return { cid: env.ACEFONE_CALLER_ID ? aceDigits(env.ACEFONE_CALLER_ID) : "", note: "the number you picked (" + want + ") is NOT one of this account's numbers — it was dropped" };
  if (env.ACEFONE_CALLER_ID) return { cid: aceDigits(env.ACEFONE_CALLER_ID), note: "the fixed ACEFONE_CALLER_ID setting" };
  return { cid: "", note: "none sent — Acefone uses this account's own default number" };
}
/* ── THE AGENT EXTENSION ID — Servetel ticket 1001178, answered 27-Aug-2026 ──────────────
   Garvit Gauri, Servetel Support, in writing: "the agent_number parameter in the API
   request currently being passed contains the agent's extension number. However, this
   parameter should contain the Agent Extension ID and not the agent's extension number
   or mobile number."
   So an EXTENSION leg (0602256780003, 0602256780004 …) must be translated to its Agent
   Extension ID before the order is placed. A MOBILE leg was already right — their own
   sample shows "agent_number": "919900197283 (10 digit mobile number with prefix)",
   which is exactly what aceNumber() has always produced — and the rest of their sample
   (async "1", call_timeout 45, custom_identifier, caller_id as one of our DIDs) is what
   acefoneDial() has sent all along. The extension translation is the one missing piece.

   Where the ID comes from, in order:
   1. ACEFONE_AGENT_IDS Worker variable — "0602256780003:ID1,0602256780004:ID2" — for
      the day support hands the IDs in writing. A person's explicit setting always wins.
   2. The account's own agent list, asked live with the same Authorization header the
      calls use: GET {ACEFONE_AGENTS_URL || https://api.acefone.in/v1/agents}. Every
      number-looking field on each row (follow_me_number, intercom, extension, number …)
      is indexed against that row's own id. Cached ten minutes per isolate, so the
      lookup costs one extra HTTP call every ten minutes, not one per call.
   3. Found nowhere → the extension number is sent exactly as before (a call that may
      still ring beats a refusal invented here), and when Acefone then refuses, the
      reply names the missing ID in plain words instead of leaving a mystery.          */
const ACE_AGENT_IDS_CACHE = { at: 0, map: null };
function aceManualAgentIds(env) {
  const out = {};
  String(env.ACEFONE_AGENT_IDS || "").split(",").map(s => s.trim()).filter(Boolean).forEach(p => {
    const i = p.indexOf(":");
    if (i > 0) { const num = aceDigits(p.slice(0, i)); const id = p.slice(i + 1).trim(); if (num && id) out[num] = id; }
  });
  return out;
}
async function aceAgentIdMap(env) {
  const manual = aceManualAgentIds(env);
  const now = Date.now();
  let live = (ACE_AGENT_IDS_CACHE.map && (now - ACE_AGENT_IDS_CACHE.at) < 600000) ? ACE_AGENT_IDS_CACHE.map : null;
  if (!live) {
    live = {};
    try {
      const tok = (await acefoneTokenOf(env)).token;
      if (tok) {
        const r = await fetch(env.ACEFONE_AGENTS_URL || "https://api.acefone.in/v1/agents", {
          headers: { "Accept": "application/json", "Authorization": String(tok) }
        });
        if (r.ok) {
          const j = await r.json().catch(() => null);
          const rows = Array.isArray(j) ? j : ((j && (j.data || j.agents || j.result || j.results)) || []);
          for (const row of (Array.isArray(rows) ? rows : [])) {
            if (!row || typeof row !== "object") continue;
            const id = row.id != null ? String(row.id).trim()
              : (row.agent_id != null ? String(row.agent_id).trim()
                : (row.eid != null ? String(row.eid).trim() : ""));
            if (!id) continue;
            for (const k of ["follow_me_number", "followme_number", "intercom", "extension", "extension_number", "number", "agent_number", "phone"]) {
              const d = aceDigits(row[k]);
              if (d && d.length >= 6) live[d] = id;
            }
          }
          ACE_AGENT_IDS_CACHE.at = now; ACE_AGENT_IDS_CACHE.map = live;
        }
      }
    } catch (e) { /* list unreachable — the manual map and the honest fallback note still stand */ }
  }
  return Object.assign({}, live, manual);   // a person's explicit setting outranks the probe
}

/* WHO WAS DIALLED FROM WHICH PHONE, AND WHEN — kept in memory so a failure moments after
   another call can be named for what it usually is: the rings-first phone still busy.
   His screenshots of 7-Aug told exactly this story — a real call queued at 10:31, a test
   seconds later answered "Originate failed", and the bare words sent him hunting for a
   config fault when the likeliest truth was that his own phone was still ringing. */
const AGENT_LAST_DIAL = new Map();   // agent number -> ms timestamp of the last originate we sent
function agentBusySecs(agent) {
  const t = AGENT_LAST_DIAL.get(agent);
  if (!t) return null;
  const s = Math.round((Date.now() - t) / 1000);
  return (s >= 0 && s <= 90) ? s : null;
}
/* Place one click-to-call. opts: {agent, dest, callerId, tag, sync, probe}
   Returns { ok, agent, dest, sent, msg, http, self } — `sent` never contains the token.
   probe: test-line mode — a generic refusal is retried once WITHOUT the "Call from"
   number, so the answer becomes a diagnosis instead of a dead end. Never set on the
   ordinary Call buttons: a probe places a second real call, and only a test may do that. */
async function acefoneDial(env, opts) {
  const o = opts || {};
  const agent = aceNumber(o.agent), dest = aceNumber(o.dest);
  const out = { ok: false, agent: agent, dest: dest, sent: null, msg: "", http: 0, self: false };
  if (!agent) { out.msg = "No agent number."; return out; }
  if (!dest) { out.msg = "No number to call."; return out; }
  /* refuse a placeholder before it costs anybody a morning — see the note on the agent list */
  if (aceFakeNumber(agent)) { out.msg = "“" + agent + "” is not a real phone number — it is a placeholder made of one repeated digit, so nothing can ring. Pick a proper extension or your own mobile under “Who is calling?”."; return out; }
  if (aceFakeNumber(dest)) { out.msg = "“" + dest + "” is not a real phone number — it is a placeholder made of one repeated digit."; return out; }
  /* Ringing your own phone and then dialling that same phone can never connect —
     the second leg finds the line busy and you hear nothing. Say so plainly.
     EXCEPT on a deliberate self test (18-Aug: "I will select my number and once I'll dial
     it — need to call me for testing"). There the FIRST leg is the whole point: his phone
     ringing is the pass, and the busy second leg is expected and told to him in advance.
     Only the test endpoint sets this flag; every real call keeps the refusal. */
  if (agent === dest && !o.selfTest) { out.self = true; out.msg = "same number on both legs"; return out; }
  /* EXTENSION LEG → AGENT EXTENSION ID (Servetel ticket 1001178, 27-Aug-2026).
     Servetel in writing: agent_number "should contain the Agent Extension ID and not the
     agent's extension number or mobile number". A 10-digit mobile already goes out as
     91XXXXXXXXXX (their own sample's shape); only the 0-prefixed extensions translate.
     out.agent stays the extension number — that is the name every row, webhook match and
     busy-guard knows it by. Only the wire body carries the ID.                        */
  let agentSend = agent, agentIdMissing = false;
  if (/^0\d{10,}$/.test(agent)) {
    const ids = await aceAgentIdMap(env);
    if (ids[agent]) { agentSend = String(ids[agent]); out.agentId = agentSend; }
    else agentIdMissing = true;
  }
  const pick = acefoneCid(env, o.callerId);
  const build = useCid => {
    const b = { agent_number: agentSend, destination_number: dest, async: o.sync ? "0" : "1" };
    const t = Number(env.ACEFONE_CALL_TIMEOUT || 45);
    if (t > 0 && t <= 300) b.call_timeout = t;                       // stop a dead leg ringing for ever
    if (o.tag) b.custom_identifier = String(o.tag).slice(0, 60);     // comes back on the webhook
    if (useCid && pick.cid) b.caller_id = pick.cid;
    return b;
  };
  const shoot = async b => {
    const init = { method: "POST", headers: { "Content-Type": "application/json", "Authorization": String((await acefoneTokenOf(env)).token) }, body: JSON.stringify(b) };
    /* A synchronous call waits for the whole conversation, so it needs a hard stop of
       its own — otherwise a dead second leg would hang the page for ever. */
    if (o.sync) { try { init.signal = AbortSignal.timeout(75000); } catch (e) { /* older runtime: no signal */ } }
    const r = await fetch(env.ACEFONE_C2C_URL || "https://api.acefone.in/v1/click_to_call", init);
    const txt = await r.text(); let j = {}; try { j = JSON.parse(txt); } catch (e) { j = {}; }
    const good = r.ok && (j.Success === true || j.success === true || j.Success === "true" || j.success === "true");
    return { good: good, http: r.status, body: b,
      msg: String(j.Message || j.message || j.Error || j.error || txt || (good ? "Call placed" : "HTTP " + r.status)).replace(/\s+/g, " ").trim().slice(0, 220) };
  };
  const busyBefore = agentBusySecs(agent);       // read BEFORE we stamp this attempt
  AGENT_LAST_DIAL.set(agent, Date.now());
  if (AGENT_LAST_DIAL.size > 200) AGENT_LAST_DIAL.clear();
  let res = await shoot(build(true));
  /* A "Call from" number that this API key is not allowed to use is the other classic
     cause of a silent second leg. If that is what came back, try once more without it
     so the call still goes out on the account's own number. */
  if (!res.good && res.body.caller_id && /caller|did|number|not allow|permission|invalid|denied/i.test(res.msg)) {
    const again = await shoot(build(false));
    if (again.good) { again.msg = (again.msg || "Call placed") + " — note: “Call from: " + res.body.caller_id + "” was refused by Acefone, so your account's default number was used. Tick that number under My Numbers in the Acefone console, or choose “Call from: default number”."; res = again; }
  }
  /* TEST-LINE ONLY: "Originate failed" is Acefone's all-purpose refusal — it names nothing.
     So the test retries once without the "Call from" number. If THAT goes through, the
     Call-from number is proven to be the fault, in one sentence. If both fail, the two
     causes left are named in plain words — the busiest one first when we have evidence
     that this same rings-first phone was dialled moments ago. */
  if (o.probe && !res.good && res.body.caller_id) {
    const bare = await shoot(build(false));
    if (bare.good) {
      bare.msg = (bare.msg || "Call placed") + " — PROVEN: Acefone refuses the “Call from: " + res.body.caller_id + "” number but accepts the call without it. Tick " + res.body.caller_id + " under My Numbers in the Acefone console (for this API key), or pick “default number” in Call from.";
      res = bare;
    } else {
      res.msg = res.msg + " (tried again without the Call-from number — refused too, so that number is not the fault). In plain words, most likely: "
        + (busyBefore != null ? ("your rings-first phone " + agent + " was dialled " + busyBefore + " second" + (busyBefore === 1 ? "" : "s") + " ago and is still busy or ringing — wait for it to go fully idle, then test again. Otherwise: ") : "the rings-first phone is busy or unreachable, or ")
        + "the Acefone account is out of balance or call channels. Both are checked in the Acefone console, not in the portal.";
    }
  } else if (!res.good && busyBefore != null) {
    res.msg = res.msg + " — note: this same rings-first phone (" + agent + ") was dialled " + busyBefore + " second" + (busyBefore === 1 ? "" : "s") + " ago; if it was still busy or ringing, Acefone refuses the new call. Wait for it to go fully idle and try again.";
  }
  /* Say what was actually sent on the agent leg — evidence, not a mystery, both ways. */
  if (agentSend !== agent) {
    res.msg = (res.msg || "") + " — agent leg sent as Agent Extension ID " + agentSend + " for extension " + agent + " (Servetel's required format).";
  } else if (agentIdMissing && !res.good) {
    res.msg = (res.msg || "") + " — note: Servetel requires the AGENT EXTENSION ID for extension " + agent + " in agent_number, and it could not be found (the agent-list lookup returned nothing and no ACEFONE_AGENT_IDS variable is set). Ask Servetel support for the Extension ID of " + agent + " and set the Worker variable ACEFONE_AGENT_IDS = \"" + agent + ":<that ID>\", or pick your own mobile under “Who is calling?” — mobiles need no ID.";
  }
  out.ok = res.good; out.msg = res.msg; out.http = res.http; out.sent = res.body;
  return out;
}

/* ══════════ THE MEETING ATTENDANCE REGISTER — kept, day by day, in D1 — v20.6 ══════════
   Sujit, 03-Sep 5:50 pm, the daily "not attended" Excel open: "I want this monthly, not daily.
   Who attended, who did not, who marked it — 'Sujit not came, marked by Mohan' — with the date.
   I will pick the dates. Save this in our storage."
   Two tables. meeting_roster: who was ON the meeting each day (one line per officer per product,
   with his state, managers, team head and case count) — written every hour for today, so a man
   who was on the list and never marked reads "not marked" a month later instead of vanishing.
   meeting_att: every mark, the moment it is pressed — attended / not attended, by whom, when —
   permanent, beside the 200-day KV page the meeting page itself reads. */
let meetRegReady = false;
async function meetRegEnsure(env) {
  if (meetRegReady || !env.DB) return !!env.DB;
  try {
    await env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS meeting_roster (day TEXT, fokey TEXT, type TEXT, fo TEXT, state TEXT, managers TEXT, ohs TEXT, cases INTEGER, ts INTEGER, PRIMARY KEY (day, fokey, type))"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS meeting_att (day TEXT, fokey TEXT, fo TEXT, a TEXT, by TEXT, name TEXT, ts INTEGER, PRIMARY KEY (day, fokey))"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_meeting_roster_day ON meeting_roster(day)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_meeting_att_day ON meeting_att(day)")
    ]);
    meetRegReady = true;
  } catch (e) {}
  return meetRegReady;
}
const meetFoKey = s => String(s == null ? "" : s).replace(/[.,_]+/g, " ").replace(/\s+/g, " ").trim().toUpperCase();
/* today's roster — every officer with a line on the Out of TAT meeting, both products */
async function meetRosterSnapshot(env) {
  if (!(await meetRegEnsure(env))) return { ok: false, why: "no D1" };
  const d = await getCases(env);
  const now = Date.now(), day = new Date(now + 19800000).toISOString().slice(0, 10);
  const foMap = await getFoStateMap(env).catch(() => null);
  const teams = [];
  if (env.USERS) { try { const l = await env.USERS.list({ prefix: "team:" }); for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { const t = JSON.parse(v); teams.push({ name: String(t.name || ""), head: String(t.head || ""), members: Array.isArray(t.members) ? t.members : [] }); } catch (e) {} } } } catch (e) {} }
  const headOf = fo => { for (const t of teams) { if ([t.head].concat(t.members).some(m => m && sameManLoose(m, fo))) return t.head; } return ""; };
  const split = ootatSplit(d.cases, {}, now);
  const agg = {};
  for (const rec of split.outAll) {
    if (!isMeetingStatusW(rec.foStatus) && !isPartCompletedW(rec.foStatus)) continue;
    const fo = String(rec.fo || rec.c.officerName || "").trim(); const k = meetFoKey(fo); if (!k) continue;
    const key = k + "|" + rec.type;
    if (!agg[key]) agg[key] = { fokey: k, type: rec.type, fo, state: foStateOf(fo, foMap) || "", managers: new Set(), ohs: headOf(fo), cases: 0 };
    agg[key].cases++; if (rec.c.manager) agg[key].managers.add(String(rec.c.manager).trim());
  }
  const rows = Object.values(agg);
  for (let i = 0; i < rows.length; i += 40) {
    await env.DB.batch(rows.slice(i, i + 40).map(r => env.DB.prepare(
      "INSERT INTO meeting_roster (day, fokey, type, fo, state, managers, ohs, cases, ts) VALUES (?,?,?,?,?,?,?,?,?) " +
      "ON CONFLICT(day, fokey, type) DO UPDATE SET fo=excluded.fo, state=excluded.state, managers=excluded.managers, ohs=excluded.ohs, cases=excluded.cases, ts=excluded.ts"
    ).bind(day, r.fokey, r.type, r.fo, r.state, [...r.managers].join(" · "), r.ohs, r.cases, now)));
  }
  return { ok: true, day, officers: rows.length };
}
/* one mark, kept for good */
async function meetAttRecord(env, day, foKey, foRaw, attended, me, now) {
  if (!(await meetRegEnsure(env))) return;
  try {
    if (attended) await env.DB.prepare("INSERT INTO meeting_att (day, fokey, fo, a, by, name, ts) VALUES (?,?,?,?,?,?,?) ON CONFLICT(day, fokey) DO UPDATE SET fo=excluded.fo, a=excluded.a, by=excluded.by, name=excluded.name, ts=excluded.ts")
      .bind(day, foKey, foRaw, attended, me.email, me.name || me.email, now).run();
    else await env.DB.prepare("DELETE FROM meeting_att WHERE day = ?1 AND fokey = ?2").bind(day, foKey).run();
  } catch (e) {}
}

async function currentUser(env, request) {
  const s = await readSession(env, request);
  if (!s) return null;
  if (adminEmails(env).includes(s.email)) return { email: s.email, name: s.name || s.email, role: "admin", state: "", status: "approved" };
  const u = await kvGetUser(env, s.email);
  if (!(u && u.status === "approved")) return null;
  // OHS (team head) access: attach the team's officer names once, so every scope check can use them
  if (u.role === "ohs" && u.team && env.USERS) {
    try {
      const tv = await env.USERS.get("team:" + u.team);
      if (tv) { const t = JSON.parse(tv); u.teamNames = [t.head].concat(Array.isArray(t.members) ? t.members : []).filter(Boolean); u.teamName = t.name || u.teamName || ""; }
    } catch (e) { /* team missing -> teamNames stays empty -> sees nothing */ }
  }
  return u;
}

export default {
  async fetch(request, env, ctx) {
    let resp;
    try { resp = await handlePortal(request, env); }
    catch (e) {
      try { console.error("portal error:", (e && e.stack) || e); } catch (x) {} // detail goes to Cloudflare logs, never to the visitor
      resp = Response.json({ ok: false, error: "Server error — please try again." }, { status: 500 });
    }
    try { return withSecurityHeaders(request, resp); } catch (e) { return resp; }
  }
};

async function handlePortal(request, env) {
    const url = new URL(request.url);
    const clientIP = request.headers.get("CF-Connecting-IP") || "";

    // FIREWALL: banned IPs get nothing
    if (isBanned(clientIP)) return new Response("Forbidden", { status: 403 });
    // FIREWALL: probing for hack paths (/wp-admin, .php, /.env, /.git …) = instant 1-hour IP ban
    if (isAttackPath(url.pathname)) {
      banIP(clientIP);
      await secLog(env, "probe-banned", clientIP, url.pathname);
      return new Response("Not found", { status: 404 });
    }
    // SECURITY: only the methods the portal actually uses
    if (request.method !== "GET" && request.method !== "POST" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405, headers: { "Allow": "GET, POST, HEAD" } });
    }
    // FIREWALL: CSRF shield — a POST coming from another website is refused
    if (request.method === "POST") {
      const orig = request.headers.get("Origin");
      if (orig && orig !== url.origin) {
        await secLog(env, "csrf-blocked", clientIP, orig + " -> " + url.pathname);
        return Response.json({ ok: false, error: "Cross-site request refused." }, { status: 403 });
      }
    }
    // SECURITY: never serve backend/config files
    if (isBlockedPath(url.pathname)) return new Response("Not found", { status: 404 });

    /* ---------- DIAG (public shows only the build tag; config booleans are admin-only) ---------- */
    if (url.pathname === "/api/diag") {
      const base = { ok: true, build: "shield-3q", ts: Date.now() };
      const meD = await currentUser(env, request);
      if (meD && meD.role === "admin") {
        base.sessionSecret = !!env.SESSION_SECRET;
        base.usersKv = !!env.USERS;
        base.googleClientId = !!GOOGLE_CLIENT_ID;
        base.skd = { base: !!env.SKD_API_BASE, user: !!env.SKD_USERNAME, pass: !!env.SKD_PASSWORD, device: !!env.SKD_DEVICE_ID };
      }
      return Response.json(base);
    }

    /* ---------- TOKEN-AUTH DATA FEED for Google Sheets (Apps Script). No browser login needed. ----------
       Auth: header  X-SKD-Token: <token>   (or ?token=<token>)  ==  Worker variable SHEET_TOKEN.
       Read-only. Returns the exact 20-column sheet data as JSON. ?type=all|tp|health. */
    if (url.pathname === "/api/sheet-feed") {
      if (!env.SHEET_TOKEN) return Response.json({ ok: false, error: "Sheet feed not enabled — set the Worker variable SHEET_TOKEN." }, { status: 501 });
      const tok = request.headers.get("X-SKD-Token") || url.searchParams.get("token") || "";
      if (!tok || !timingSafeEqual(tok, env.SHEET_TOKEN)) {
        await secLog(env, "sheet-feed-denied", clientIP, "bad or missing token", true);
        return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      }
      if (!allowRate("sheetfeed:" + clientIP, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many requests — wait a while." }, { status: 429 });
      try {
        const want = (url.searchParams.get("type") || "all").toLowerCase();
        const status = (url.searchParams.get("status") || "").toLowerCase();
        const { columns, rows } = await buildSheetRows(env, want, null, status); // token = the owner: full unscoped data
        return new Response(JSON.stringify({ ok: true, type: want, status, columns, total: rows.length, rows }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---------- SH DAILY UPDATE FEED — the Google Sheet's one-click live pull ----------
       Same SHEET_TOKEN auth as /api/sheet-feed. Returns EXACTLY the columns of the
       "SH Daily Update" sheet (A–L), LIVE at the moment of the click:
         · HEALTH cases only
         · case status only Pending / Assigned / FO Accepted / FO Rejected
           (a blank status counts as Pending)
         · FO Completed is OUT, and a case where ANY officer has already finished
           his part (Partially Completed) is OUT too — his words: "I don't want
           FO Completed and one more Completed."                                   */
    if (url.pathname === "/api/sheet-feed/daily-health") {
      if (!env.SHEET_TOKEN) return Response.json({ ok: false, error: "Sheet feed not enabled — set the Worker variable SHEET_TOKEN." }, { status: 501 });
      const tok = request.headers.get("X-SKD-Token") || url.searchParams.get("token") || "";
      if (!tok || !timingSafeEqual(tok, env.SHEET_TOKEN)) {
        await secLog(env, "sheet-feed-denied", clientIP, "bad or missing token (daily-health)", true);
        return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      }
      if (!allowRate("sheetfeed:" + clientIP, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many requests — wait a while." }, { status: 429 });
      try {
        const d = await getCases(env);
        const foMap = await getFoStateMap(env).catch(() => null);
        const WANTED = /pending|assigned|accepted|reject/;
        const rows = [];
        for (const c of d.cases) {
          if (typeOfSub(c.subProduct) !== "Health") continue;
          const st = String(c.status || "").trim();
          const low = st.toLowerCase();
          if (low.indexOf("complet") >= 0) continue;                 // FO Completed / Partially Completed
          if (st && !WANTED.test(low)) continue;                     // CM Reviewed, QC Reviewed, Released, Closed…
          const fr = ootatFoRows(c);
          if (fr.some(f => isPartCompletedW(f.status) || isCompletedStatusW(f.status))) continue;  // a finished man on an open case = Partially Completed
          rows.push([
            c.client || "", c.subProduct || "", c.claimNo || "", c.insured || "",
            c.hospitalName || "", c.manager || "", c.officerName || "",
            st || "Pending", c.createdOn || "", tatDaysNum(c.tat),
            c.allotmentDate || "", foStateOf(c.officerName, foMap) || ""
          ]);
        }
        rows.sort((a, b) => b[9] - a[9]);   // oldest TAT on top — chase-first order
        return new Response(JSON.stringify({
          ok: true, total: rows.length,
          columns: ["Client", "Sub Product", "Claim Number", "Insured Name", "Hospital Name", "Manager", "FO Name", "Status", "CreatedOn", "SKD TAT-D", "Allotted Date", "State"],
          rows
        }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---------- ACEFONE CALL-RESULT WEBHOOK (public, key-guarded — Acefone's server calls this, not a browser).
       Acefone console → API Connect → Webhook → add URL:
       https://<your-site>/api/feedback/webhook?key=<FEEDBACK_WEBHOOK_KEY>&claim=$custom_identifier&call_status=$call_status&duration=$duration&recording=$recording_url
       Acefone fills in the $variables after every call, so the Feedback Calling page shows
       Answered / Missed + duration automatically. Optional — calling works without it. ---------- */
    if (url.pathname === "/api/feedback/webhook") {
      const hk = await webhookKeyOf(env);
      if (!hk.key) return Response.json({ ok: false, error: "Webhook not enabled — open Settings → Acefone call results in the portal and press Generate." }, { status: 501 });
      const wkey = url.searchParams.get("key") || "";
      if (!wkey || !timingSafeEqual(wkey, hk.key)) {
        await secLog(env, "fb-webhook-denied", clientIP, "bad or missing key", true);
        return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      }
      if (!allowRate("fbhook:" + clientIP, 600, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many requests" }, { status: 429 });
      try {
        // Acefone may send the variables in the query string (GET) or as a JSON/form body (POST) — accept all.
        const p = {};
        url.searchParams.forEach((v, k) => { p[String(k).toLowerCase()] = String(v); });
        if (request.method === "POST") {
          const ct = (request.headers.get("Content-Type") || "").toLowerCase();
          try {
            if (ct.includes("json")) { const bj = await request.json(); if (bj && typeof bj === "object") for (const k in bj) p[String(k).toLowerCase()] = String(bj[k]); }
            else { const fd = await request.formData(); fd.forEach((v, k) => { p[String(k).toLowerCase()] = String(v); }); }
          } catch (e) {}
        }
        const claim = String(p.claim || p.custom_identifier || p.customidentifier || p.custom_id || "").trim();
        if (!claim) return Response.json({ ok: true, note: "ping received — no claim/custom_identifier, nothing to update" });
        const rawStatus = String(p.call_status || p.status || "").toLowerCase();
        const result = !rawStatus ? "completed"
          : (/miss|no.?answer|unanswer|fail|busy|cancel|reject/.test(rawStatus) ? "missed"
          : (/answer|complete|success/.test(rawStatus) ? "answered" : rawStatus.slice(0, 30)));
        const dur = String(p.duration || p.call_duration || p.billing_duration || p.billsec || "").slice(0, 20);
        const rec = String(p.recording || p.recording_url || p.recording_link || "").slice(0, 400);
        // Why the call ended, in Acefone's own words — this is what tells you a second leg
        // was refused rather than simply not picked up.
        const why = String(p.hangup_cause || p.hangupcause || p.reason || p.disposition || p.call_flow || "").replace(/\s+/g, " ").trim().slice(0, 160);
        /* WHICH ACCOUNT, when the webhook knows and we did not. This body arrives from the
           open internet, so a NAME inside it is never believed — only the NUMBER is read,
           and the name is then looked up in this account's own agent list. An unrecognised
           number leaves the row nameless, which is the truthful outcome. */
        const hookNum = String(p.agent_number || p.agentnumber || p.agent || p.answered_agent || p.extension || "").trim();
        const hookWho = hookNum ? acefoneWho(env, hookNum) : null;
        const nameIt = row => {
          if (!row || !hookWho || !hookWho.known) return;
          if (row.agentName) return;                      // the placing stamp already named it — never overwritten
          row.agentName = hookWho.name; row.agentKind = hookWho.kind; row.agentKnown = true;
          if (!row.agent) row.agent = hookWho.num;
        };
        const stamp = entry => {
          const lc = entry.lastCall || {}; lc.result = result; lc.resultTs = Date.now(); if (dur) lc.duration = dur; if (rec) lc.recording = rec; if (why) lc.msg = why; nameIt(lc); entry.lastCall = lc;
          const lg = Array.isArray(entry.callLog) ? entry.callLog : [];   // also stamp the newest attempt in the call history (keeps the recording per try)
          if (lg.length) { const last = lg[lg.length - 1]; last.result = result; if (dur) last.duration = dur; if (rec) last.recording = rec; if (why) last.msg = why; nameIt(last); entry.callLog = lg; }
        };
        // The same webhook serves BOTH calling pages — update whichever queue holds this claim.
        let touched = 0;
        if (env.USERS) {
          let fbq = {}; try { fbq = JSON.parse(await stGet(env, "fbq:map") || "{}"); } catch (e) { fbq = {}; }
          if (fbq[claim]) { stamp(fbq[claim]); await stSoft(env, "fbq:map", JSON.stringify(fbq)); touched++; }
          let am = {}; try { am = JSON.parse(await stGet(env, "appt:map") || "{}"); } catch (e) { am = {}; }
          if (am[claim]) { stamp(am[claim]); await stSoft(env, "appt:map", JSON.stringify(am)); touched++; }
        }
        return Response.json({ ok: true, updated: touched });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---------- AUTH endpoints (public / self-guarded) ---------- */
    if (url.pathname === "/api/auth/google" && request.method === "POST") {
      try {
        if (!env.SESSION_SECRET) return Response.json({ ok: false, error: "Login not configured yet (SESSION_SECRET missing)." }, { status: 501 });
        const ip = request.headers.get("CF-Connecting-IP") || "?";
        if (!allowRate("login:" + ip, 20, 10 * 60 * 1000) || !(await kvLoginAllowed(env, ip))) {
          await secLog(env, "login-ratelimited", ip, "too many sign-in attempts");
          return Response.json({ ok: false, error: "Too many sign-in attempts — please wait a few minutes and try again." }, { status: 429 });
        }
        const body = await request.json();
        const g = await verifyGoogleToken(body.idToken || "");
        if (!g) { await secLog(env, "login-failed", ip, "Google token failed verification"); return Response.json({ ok: false, error: "Google sign-in could not be verified." }, { status: 401 }); }
        const isAdmin = adminEmails(env).includes(g.email);
        let role = "", state = "", status = "pending";
        if (isAdmin) {
          role = "admin"; status = "approved";
          await kvPutUser(env, { email: g.email, name: g.name, role: "admin", state: "", status: "approved", ts: Date.now() });
        } else {
          let u = await kvGetUser(env, g.email);
          if (u && u.status === "blocked") { await secLog(env, "blocked-user-signin", g.email, "revoked account tried to sign in", true); return Response.json({ ok: false, error: "Your access has been removed — contact your admin." }, { status: 403 }); }
          if (!u) { u = { email: g.email, name: g.name, role: "", state: "", status: "pending", ts: Date.now() }; await kvPutUser(env, u); }
          else if (g.name && u.name !== g.name) { u.name = g.name; await kvPutUser(env, u); }
          role = u.role; state = u.state; status = u.status;
        }
        if (status !== "approved") return Response.json({ ok: true, status: "pending", email: g.email });
        const token = await makeSession(env, { email: g.email, name: g.name, role, state, ua: await uaHash(request), exp: Math.floor(Date.now() / 1000) + SESSION_TTL });
        await secLog(env, "login-ok", g.email, "signed in (" + ip + ")", true);
        return new Response(JSON.stringify({ ok: true, status: "approved", role, state }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookie(token, SESSION_TTL) } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---- OTP step 1: paste the mail ID, the code goes out by mail ---- */
    if (url.pathname === "/api/auth/otp/start" && request.method === "POST") {
      try {
        if (!env.SESSION_SECRET) return Response.json({ ok: false, error: "Login not configured yet (SESSION_SECRET missing)." }, { status: 501 });
        const ip = request.headers.get("CF-Connecting-IP") || "?";
        if (!allowRate("otpstart:" + ip, 15, 10 * 60 * 1000) || !(await kvLoginAllowed(env, ip))) {
          await secLog(env, "login-ratelimited", ip, "too many OTP requests");
          return Response.json({ ok: false, error: "Too many OTP requests — please wait a few minutes and try again." }, { status: 429 });
        }
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const email = String(b && b.email || "").trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return Response.json({ ok: false, error: "That does not look like a mail ID — please check it." }, { status: 400 });
        /* same door as Google, same approvals:
             approved member  -> code goes out, verify signs him in
             BRAND-NEW mail   -> code still goes out; verifying it PROVES the mailbox is his,
                                 and then an access request is filed for the admin (status:
                                 pending) — exactly what a first Google sign-in does
             pending          -> no code; he is told the admin has not approved him yet
             blocked          -> refused outright                                          */
        let u = await kvGetUser(env, email);
        const isAdmin = adminEmails(env).includes(email);
        let newcomer = false;
        if (!isAdmin) {
          if (u && u.status === "blocked") { await secLog(env, "blocked-user-signin", email, "revoked account asked for OTP", true); return Response.json({ ok: false, error: "Your access has been removed — contact your admin." }, { status: 403 }); }
          if (u && u.status !== "approved") return Response.json({ ok: false, error: "Your access request is still awaiting approval — you will be able to sign in once an admin approves you." }, { status: 403 });
          if (!u) newcomer = true;
        }
        /* v34.9 — Sujit, 28-Sep: FORGOT PASSWORD → mail ID → OTP → in. Only a member already on the portal. */
        if (b && b.forgot && newcomer) return Response.json({ ok: false, error: "This mail ID is not on the portal — ask your admin to add you." }, { status: 404 });
        const now = Date.now();
        let rec = null; try { rec = JSON.parse(await stGet(env, "otp:" + email) || "null"); } catch (e) { rec = null; }
        /* resend manners: 45 seconds between mails, at most 6 codes an hour per mail ID */
        if (rec && rec.ts && now - rec.ts < 45 * 1000) return Response.json({ ok: false, error: "A code was just sent — please wait a moment, then try again (check spam too)." }, { status: 429 });
        let sends = (rec && Array.isArray(rec.sends)) ? rec.sends.filter(t => now - t < 60 * 60 * 1000) : [];
        if (sends.length >= 6) { await secLog(env, "otp-refused", email, "hourly send limit"); return Response.json({ ok: false, error: "Too many codes were sent to this mail ID in the last hour — please try later." }, { status: 429 }); }
        const n = new Uint32Array(1); crypto.getRandomValues(n);
        const code = String(100000 + (n[0] % 900000));
        const h = await sha256Hex(code + "|" + email + "|" + env.SESSION_SECRET);   // the code itself is never stored
        sends.push(now);
        await stPut(env, "otp:" + email, JSON.stringify({ h, exp: now + 10 * 60 * 1000, tries: 0, ts: now, sends }));
        const sent = await sendOtpMail(env, email, code);
        if (!sent.ok) { await secLog(env, "otp-mail-failed", email, sent.why || "?"); return Response.json({ ok: false, error: "The OTP mail could not be sent (" + (sent.why || "mailer error") + ")." }, { status: 502 }); }
        await secLog(env, "otp-sent", email, (newcomer ? "NEW-MEMBER verification code mailed (" : "sign-in code mailed (") + ip + ")", true);
        return Response.json({ ok: true, sent: true, newcomer });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---- OTP step 2: verify the code -> the same session cookie as a Google sign-in ---- */
    if (url.pathname === "/api/auth/otp/verify" && request.method === "POST") {
      try {
        if (!env.SESSION_SECRET) return Response.json({ ok: false, error: "Login not configured yet (SESSION_SECRET missing)." }, { status: 501 });
        const ip = request.headers.get("CF-Connecting-IP") || "?";
        if (!allowRate("otpverify:" + ip, 30, 10 * 60 * 1000) || !(await kvLoginAllowed(env, ip))) {
          await secLog(env, "login-ratelimited", ip, "too many OTP verify attempts");
          return Response.json({ ok: false, error: "Too many attempts — please wait a few minutes and try again." }, { status: 429 });
        }
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const email = String(b && b.email || "").trim().toLowerCase();
        const code = String(b && b.code || "").replace(/\D/g, "");
        if (!email || code.length !== 6) return Response.json({ ok: false, error: "Enter the 6-digit code from the mail." }, { status: 400 });
        let rec = null; try { rec = JSON.parse(await stGet(env, "otp:" + email) || "null"); } catch (e) { rec = null; }
        if (!rec || !rec.h) return Response.json({ ok: false, error: "No code was requested for this mail ID, or it already expired — send a new one." }, { status: 400 });
        const now = Date.now();
        if (rec.exp && now > rec.exp) { await stDel(env, "otp:" + email); try { await env.USERS.delete("otp:" + email); } catch (e) {} return Response.json({ ok: false, error: "That code has expired (codes work for 10 minutes) — send a new one." }, { status: 400 }); }
        if ((rec.tries || 0) >= 6) { await stDel(env, "otp:" + email); try { await env.USERS.delete("otp:" + email); } catch (e) {} await secLog(env, "otp-refused", email, "too many wrong codes", true); return Response.json({ ok: false, error: "Too many wrong tries — that code is cancelled. Send a fresh one." }, { status: 429 }); }
        const h = await sha256Hex(code + "|" + email + "|" + env.SESSION_SECRET);
        if (!timingSafeEqual(h, rec.h)) {
          rec.tries = (rec.tries || 0) + 1;
          await stSoft(env, "otp:" + email, JSON.stringify(rec));
          await secLog(env, "otp-wrong", email, "wrong code (" + rec.tries + "/6, " + ip + ")");
          return Response.json({ ok: false, error: "That code is not correct — check the mail and try again (" + (6 - rec.tries) + " tr" + (6 - rec.tries === 1 ? "y" : "ies") + " left)." }, { status: 401 });
        }
        await stDel(env, "otp:" + email); try { await env.USERS.delete("otp:" + email); } catch (e) {}   // single use — the code dies the moment it works
        /* the same door as Google: admins are always in, everyone else by approval */
        const isAdmin = adminEmails(env).includes(email);
        let role = "", state = "", name = email;
        if (isAdmin) {
          const ex = await kvGetUser(env, email);
          name = (ex && ex.name) || email; role = "admin";
          await kvPutUser(env, { email, name, role: "admin", state: "", status: "approved", ts: Date.now() });
        } else {
          const u = await kvGetUser(env, email);
          if (u && u.status === "blocked") return Response.json({ ok: false, error: "Your access has been removed — contact your admin." }, { status: 403 });
          if (!u && b && b.forgot) return Response.json({ ok: false, error: "This mail ID is not on the portal — ask your admin to add you." }, { status: 404 });
          if (!u) {
            /* THE NEWCOMER DOOR: the right code proves this mailbox is really his. His access
               request is filed for the admin — same as a first Google sign-in — and NO session
               is given until the admin approves him. */
            const nm = String(b && b.name || "").replace(/[<>]/g, "").trim().slice(0, 60);
            await kvPutUser(env, { email, name: nm || email, role: "", state: "", status: "pending", ts: Date.now() });
            await secLog(env, "access-requested", email, "new member request via email OTP (" + ip + ")", true);
            return Response.json({ ok: true, status: "pending", email });
          }
          if (u.status !== "approved") return Response.json({ ok: true, status: "pending", email });
          role = u.role; state = u.state; name = u.name || email;
        }
        /* v34.9 — FORGOT PASSWORD: the right code proves the mailbox; the right door is checked as at
           the password; then he sets a new password straight away (no old password asked). */
        const forgot = !!(b && b.forgot);
        if (forgot) {
          const door = String(b && b.door || "taasen") === "external" ? "external" : "taasen", isClient = role === "client-manager";
          if (door === "external" && !isClient) return Response.json({ ok: false, error: "This is a TaaSen staff login — go back and choose TaaSen User." }, { status: 403 });
          if (door === "taasen" && isClient) return Response.json({ ok: false, error: "This is an insurer / external login — go back and choose External User." }, { status: 403 });
          try { await pwEnsure(env); await env.DB.prepare("UPDATE portal_passwords SET must_change = 1, fails = 0, locked_until = 0 WHERE email = ?1").bind(email).run(); } catch (e) { }
          await secLog(env, "password-forgot", email, "OTP verified for a password reset (" + ip + ")", true);
        }
        const token = await makeSession(env, { email, name, role, state, ua: await uaHash(request), exp: Math.floor(Date.now() / 1000) + SESSION_TTL });
        await secLog(env, "login-ok", email, "signed in with email OTP (" + ip + ")", true);
        return new Response(JSON.stringify({ ok: true, status: "approved", role, state, mustChange: forgot }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookie(token, SESSION_TTL) } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══ PASSWORD SIGN-IN — v34.9, 27-Sep-2026 ════════════════════════════════════════════
       Sujit: "Don't want login from OTP now. Password will be keeping ... they can login." And
       the sign-in opens on two doors, the ICICI Fast Track way: TaaSen User (every employee) and
       External User (an insurer's own client-manager login). The OTP doors above stay in the
       code — nothing is taken away — but the sign-in page no longer offers them.
       Passwords live in D1 portal_passwords as PBKDF2-SHA256 (100,000 rounds, 16-byte salt),
       never in KV beside the member record, so saving a member's access in the drawer can never
       wipe his password. An admin / boss sets or resets one (/api/auth/password/set); it is
       marked must_change and the member picks his own at his first sign-in. Eight wrong tries
       lock that mail ID for 15 minutes. */
    if (url.pathname === "/api/auth/password" && request.method === "POST") {
      try {
        if (!env.SESSION_SECRET) return Response.json({ ok: false, error: "Login not configured yet (SESSION_SECRET missing)." }, { status: 501 });
        const ip = request.headers.get("CF-Connecting-IP") || "?";
        if (!allowRate("pwlogin:" + ip, 30, 10 * 60 * 1000) || !(await kvLoginAllowed(env, ip))) {
          await secLog(env, "login-ratelimited", ip, "too many password attempts");
          return Response.json({ ok: false, error: "Too many sign-in attempts — please wait a few minutes and try again." }, { status: 429 });
        }
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const email = String(b && b.email || "").trim().toLowerCase();
        const pw = String(b && b.password || "");
        const door = String(b && b.door || "taasen") === "external" ? "external" : "taasen";
        if (!email || !pw) return Response.json({ ok: false, error: "Type your mail ID and your password." }, { status: 400 });
        await pwEnsure(env);
        const rec = await env.DB.prepare("SELECT * FROM portal_passwords WHERE email = ?1").bind(email).first();
        const now = Date.now();
        if (rec && rec.locked_until && now < rec.locked_until) return Response.json({ ok: false, error: "Too many wrong passwords for this mail ID — try again in 15 minutes, or ask your admin to reset it." }, { status: 429 });
        const good = rec ? timingSafeEqual(await pwHash(pw, rec.salt, rec.iter || PW_ITER), rec.hash) : false;
        if (!good) {
          if (rec) {
            const f = (Number(rec.fails) || 0) + 1;
            await env.DB.prepare("UPDATE portal_passwords SET fails = ?2, locked_until = ?3 WHERE email = ?1").bind(email, f >= 8 ? 0 : f, f >= 8 ? now + 15 * 60 * 1000 : 0).run();
          }
          await secLog(env, "login-failed", email, "wrong password (" + ip + ")");
          return Response.json({ ok: false, error: rec ? "That password is not right." : "No password is set for this mail ID yet — ask your admin to set one." }, { status: 401 });
        }
        const isAdmin = adminEmails(env).includes(email);
        let role = "", state = "", name = email;
        if (isAdmin) { const ex = await kvGetUser(env, email); name = (ex && ex.name) || email; role = "admin"; }
        else {
          const u = await kvGetUser(env, email);
          if (!u || u.status === "blocked") return Response.json({ ok: false, error: "Your access has been removed — contact your admin." }, { status: 403 });
          if (u.status !== "approved") return Response.json({ ok: true, status: "pending", email });
          role = u.role; state = u.state; name = u.name || email;
        }
        const isClient = role === "client-manager";
        if (door === "external" && !isClient) return Response.json({ ok: false, error: "This is a TaaSen staff login — go back and choose TaaSen User." }, { status: 403 });
        if (door === "taasen" && isClient) return Response.json({ ok: false, error: "This is an insurer / external login — go back and choose External User." }, { status: 403 });
        await env.DB.prepare("UPDATE portal_passwords SET fails = 0, locked_until = 0, last_login = ?2 WHERE email = ?1").bind(email, now).run();
        const token = await makeSession(env, { email, name, role, state, ua: await uaHash(request), exp: Math.floor(now / 1000) + SESSION_TTL });
        await secLog(env, "login-ok", email, "signed in with password, " + door + " door (" + ip + ")", true);
        return new Response(JSON.stringify({ ok: true, status: "approved", role, state, mustChange: !!rec.must_change }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookie(token, SESSION_TTL) } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    /* his own password: signed in, old + new (the old is not asked when the admin's must_change is on) */
    if (url.pathname === "/api/auth/password/change" && request.method === "POST") {
      try {
        const me = await currentUser(env, request);
        if (!me) return Response.json({ ok: false, error: "Not signed in." }, { status: 401 });
        let b; try { b = await request.json(); } catch (e) { b = {}; }
        const email = String(me.email || "").toLowerCase();
        const nw = String(b && b.password || "");
        const bad = pwWeak(nw);
        if (bad) return Response.json({ ok: false, error: bad }, { status: 400 });
        await pwEnsure(env);
        const rec = await env.DB.prepare("SELECT * FROM portal_passwords WHERE email = ?1").bind(email).first();
        if (rec && !rec.must_change && !timingSafeEqual(await pwHash(String(b && b.old || ""), rec.salt, rec.iter || PW_ITER), rec.hash))
          return Response.json({ ok: false, error: "Your present password is not right." }, { status: 401 });
        await pwStore(env, email, nw, email, false);
        await secLog(env, "password-changed", email, "changed own password", true);
        return Response.json({ ok: true });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    /* v34.9 — Sujit: "Set passwords for all at once." Every approved member (only=missing: those with
       none yet) gets a first password, must-change, and the list comes back ONCE as an Excel. */
    if (url.pathname === "/api/auth/password/bulk" && request.method === "POST") {
      try {
        const me = await currentUser(env, request);
        if (!me) return Response.json({ ok: false, error: "Not signed in." }, { status: 401 });
        if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "Only admin and boss set passwords." }, { status: 403 });
        let b; try { b = await request.json(); } catch (e) { b = {}; }
        const onlyMissing = String(b && b.only || "missing") !== "all";
        await pwEnsure(env);
        const have = new Set((((await env.DB.prepare("SELECT email FROM portal_passwords").all()) || {}).results || []).map(r => r.email));
        const users = (await kvListUsers(env)).filter(u => u && u.email && u.status === "approved");
        const rows = [];
        for (const u of users) {
          const em = String(u.email).toLowerCase();
          if (onlyMissing && have.has(em)) continue;
          const pw = pwGenerate();
          await pwStore(env, em, pw, me.email || "", true);
          rows.push([u.name || em, em, u.role === "client-manager" ? "External User" : "TaaSen User", u.role || "", pw]);
        }
        await secLog(env, "password-bulk", me.email || "?", rows.length + " first passwords set", true);
        if (!rows.length) return Response.json({ ok: true, count: 0, message: "Everybody already has a password." });
        rows.sort((a, c) => String(a[0]).localeCompare(String(c[0])));
        return await xlsxResponse(["Name", "Mail ID", "Sign-in door", "Post", "First password (change at first sign-in)"], rows, "taasen-first-passwords-" + new Date(Date.now() + 19800000).toISOString().slice(0, 10));
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    /* the admin's key: set / reset a member's password (shown once), and which members have one */
    if ((url.pathname === "/api/auth/password/set" && request.method === "POST") || (url.pathname === "/api/auth/password/status" && request.method === "GET")) {
      try {
        const me = await currentUser(env, request);
        if (!me) return Response.json({ ok: false, error: "Not signed in." }, { status: 401 });
        if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "Only admin and boss set passwords." }, { status: 403 });
        await pwEnsure(env);
        if (request.method === "GET") {
          const rows = ((await env.DB.prepare("SELECT email, must_change, set_at, last_login FROM portal_passwords").all()) || {}).results || [];
          return Response.json({ ok: true, rows });
        }
        let b; try { b = await request.json(); } catch (e) { b = {}; }
        const email = String(b && b.email || "").trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return Response.json({ ok: false, error: "Which mail ID?" }, { status: 400 });
        const u = await kvGetUser(env, email);
        if (!u && !adminEmails(env).includes(email)) return Response.json({ ok: false, error: "There is no member with that mail ID. Approve him first." }, { status: 404 });
        let pw = String(b && b.password || "");
        if (!pw) pw = pwGenerate();
        const bad = pwWeak(pw);
        if (bad) return Response.json({ ok: false, error: bad }, { status: 400 });
        await pwStore(env, email, pw, me.email || "", true);
        await secLog(env, "password-set", me.email || "?", "set password for " + email, true);
        return Response.json({ ok: true, email, password: pw, mustChange: true });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    if (url.pathname === "/api/auth/me") {
      const s = await readSession(env, request);
      const u = await currentUser(env, request);
      if (!u || !s) return Response.json({ ok: false });
      // SLIDING IDLE SESSION: every check (page load + the client's activity ping) refreshes the 20-min window,
      // so an active user is never logged out, but 20 minutes with no activity ends the session (cookie + client).
      const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
      const token = await makeSession(env, { email: s.email, name: s.name, role: s.role, state: s.state || "", ua: s.ua || await uaHash(request), exp });
      const payload = { ok: true, exp, user: { email: u.email, name: u.name, role: u.role, state: u.state || "", states: u.states || (u.state ? [u.state] : []), manager: u.manager || "", access: accessOf(u), meetProducts: meetProductsOf(u),
        /* the client login carries its own scope so the screen can say whose portal this is
           — "ICICI Lombard · Motor TP" on the header beats a blank page nobody can explain */
        clients: isClientRole(u) ? (u.clients || []) : [], clientProducts: isClientRole(u) ? clientProductsOf(u) : [] } };
      return new Response(JSON.stringify(payload), { headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookie(token, SESSION_TTL) } });
    }
    if (url.pathname === "/api/auth/logout") {
      return new Response(JSON.stringify({ ok: true }), { headers: [
        ["Content-Type", "application/json"],
        ["Set-Cookie", SESSION_COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"],
        ["Set-Cookie", "skd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"]
      ] });
    }
    if (url.pathname.startsWith("/api/admin/")) {
      const me = await currentUser(env, request);
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      if (url.pathname === "/api/admin/users") {
        /* v34.6 — THE REPAIR, once per record. admin.html hid the Mail tick for an OHS and for
           Call Centre and un-ticked it, and a mailAware save then wrote mailOff = true — so every
           team head and every call-centre login approved or edited since v25.0 lost Mail without
           anybody choosing it. For those two posts the tick was never on the screen, so a
           mailOff on them can only be this fault: it is cleared here, on the console's own
           read, and written to the security log by name. Any other post keeps its flag — there
           the tick was visible and an admin may have meant it. */
        let users = await kvListUsers(env);
        const fixed = [];
        for (const u of users) {
          if (u && u.mailOff === true && (u.role === "ohs" || u.role === "call-centre")) {
            u.mailOff = false;
            try { await kvPutUser(env, u); fixed.push(u.email); } catch (e) { }
          }
        }
        if (fixed.length) { await secLog(env, "mail-restored", me.email, "Mail switched back on for " + fixed.length + " member(s) whose tick the console had hidden (v34.6): " + fixed.join(", "), true); users = await kvListUsers(env); }
        return Response.json({ ok: true, users, admins: adminEmails(env), mailRestored: fixed });
      }
      /* v20.5 — POST TEMPLATES for the members console. Sujit, 3-Sep: "more than 300 members,
         I want to give access for them … very easily, smartly." A template is a post with its
         pages, states and meeting products decided once; the console gives it to one person or
         to fifty in one press. Stored on the D1 shelf like every other setting; admin only. */
      if (url.pathname === "/api/admin/templates" && request.method === "GET") {
        let t = []; try { t = JSON.parse((await stGet(env, "admin:templates")) || "[]"); } catch (e) { t = []; }
        return Response.json({ ok: true, templates: Array.isArray(t) ? t : [] });
      }
      if (url.pathname === "/api/admin/templates" && request.method === "POST") {
        let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
        let t = []; try { t = JSON.parse((await stGet(env, "admin:templates")) || "[]"); } catch (e) { t = []; }
        if (!Array.isArray(t)) t = [];
        if (b.action === "delete") { t = t.filter(x => x && x.id !== String(b.id || "")); }
        else {
          const ROLE_OK_T = ["manager", "coordinator", "product-head", "boss", "ohs", "call-centre", "hr", "ootat-manager", "rti-manager", "document-manager", "hardcopy-dispatch-manager", "hardcopy-receiving-manager", "client-manager", "mbv_operator", "mbv_checker",
            /* v23.1 — Sujit, 09-Sep 1:35 pm: "add in this one more access called Accounts Team
               and Assigning Team." Two desks that already exist in the office but had to borrow
               somebody else's post to sign in. Neither is a SCOPED role (they are not judged by
               their own cases), so each one sees exactly the pages ticked for it and nothing else. */
            "accounts-team", "assign-team", "field-officer"];
          const name = String(b.name || "").trim().slice(0, 60);
          if (!name) return Response.json({ ok: false, error: "Give the template a name." }, { status: 400 });
          if (!ROLE_OK_T.includes(b.role)) return Response.json({ ok: false, error: "Pick a post for the template." }, { status: 400 });
          const tpl = { id: String(b.id || ("t" + Date.now())).replace(/[^a-z0-9]/gi, "").slice(0, 30) || ("t" + Date.now()), name, role: b.role,
            access: (Array.isArray(b.access) ? b.access : []).map(x => String(x)).filter(x => ACCESS_SECTIONS.includes(x)).slice(0, 40),
            states: (Array.isArray(b.states) ? b.states : []).map(x => String(x).trim().slice(0, 60)).filter(Boolean).slice(0, 40),
            meetProducts: (Array.isArray(b.meetProducts) ? b.meetProducts : []).map(x => String(x)).filter(x => MEET_PRODUCTS.includes(x)),
            by: me.email, ts: Date.now() };
          t = t.filter(x => x && x.id !== tpl.id).concat([tpl]).slice(-60);
        }
        await stPut(env, "admin:templates", JSON.stringify(t));
        await secLog(env, "admin-action", me.email, (b.action === "delete" ? "deleted" : "saved") + " post template " + String(b.name || b.id || ""), true);
        return Response.json({ ok: true, templates: t });
      }
      /* ══ THE MANAGER LIST ══════════════════════════════════════════ v33.2, 22-Sep-2026 ══
         Sujit, 22-Sep 12:57 pm, approving Dr. Preethi Kanagaraj as a Manager and typing her
         name into the manager box beside it, where nothing came back:
             "Why new managers are not reflecting … now 5 to 6 managers not reflecting."

         THIS LIST WAS BUILT ONLY FROM THE MANAGER NAMES WRITTEN ON TODAY'S OPEN CASES. So a
         manager approved on the portal this morning, who has not been given a case yet, was
         not on it — and could not be picked as anybody's manager, nor ticked under a Product
         Head or an Out of TAT Manager. Which is a circle with no way in: she cannot be scoped
         to cases until she is on the list, and she is not on the list until she has cases.
         A manager whose cases had all closed fell off it the same way.

         SO THE LIST IS BOTH NOW: the names SKD writes on live cases, AND every approved
         member of this portal whose post is Manager. The two are kept apart in the answer —
         `onCases` is what the feed actually says — because the scope match is made against
         SKD's own spelling, and a name the feed has never written will match no cases at all.
         That is worth SEEING on the screen rather than discovering a week later, so the
         console marks those "no cases yet" instead of quietly offering them as equals. */
      if (url.pathname === "/api/admin/meta") {
        let states = [], onCases = [], onPortal = [];
        try {
          const foMap = await getFoStateMap(env);
          states = [...new Set(Object.values(foMap).map(v => v.state).filter(Boolean))].sort();
        } catch (e) {}
        try {
          const d = await getCases(env);
          onCases = [...new Set(d.cases.map(c => String(c.manager || "").trim()).filter(Boolean))].sort();
        } catch (e) { onCases = []; }
        try {
          const seen = new Set(onCases.map(m => m.toLowerCase()));
          for (const u of await kvListUsers(env)) {
            if (!u || u.role !== "manager" || u.status !== "approved") continue;
            const nm = String(u.name || "").trim();
            if (!nm || seen.has(nm.toLowerCase())) continue;
            seen.add(nm.toLowerCase());
            onPortal.push(nm);
          }
          onPortal.sort();
        } catch (e) { onPortal = []; }
        /* the flat list stays the flat list — four places on the console read it as one */
        const managers = onCases.concat(onPortal).sort();
        return Response.json({ ok: true, states, managers, onCases, managersNew: onPortal });
      }
      if (url.pathname === "/api/admin/security-log") {
        if (!env.USERS) return Response.json({ ok: true, events: [], note: "KV not configured" });
        const events = [];
        if (env.DB) {
          try {
            const r = await env.DB.prepare("SELECT ts, type, who, detail FROM portal_seclog ORDER BY ts DESC LIMIT 100").all();
            for (const row of (r && r.results) || []) events.push({ t: new Date(Number(row.ts)).toISOString(), type: row.type, who: row.who, detail: row.detail });
          } catch (e) {}
        }
        /* the old KV lines still show until their 7-day TTL runs out */
        if (env.USERS) {
          try {
            const l = await env.USERS.list({ prefix: "sec:", limit: 100 });
            for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { events.push(JSON.parse(v)); } catch (e) {} } }
          } catch (e) {}
        }
        events.sort((a, b) => String(b.t || "").localeCompare(String(a.t || "")));
        return Response.json({ ok: true, events: events.slice(0, 100) });
      }
      if (url.pathname === "/api/admin/scopecheck") {
        const foMap = await getFoStateMap(env);
        const d = await getCases(env);
        const withFo = d.cases.filter(c => c.officerName);
        const matched = [], unmatched = [];
        for (const c of withFo) {
          const fi = foInfoOf(c.officerName, foMap);
          if (fi && fi.state) { if (matched.length < 12) matched.push({ claim: c.claimNo, officer: c.officerName, state: canonState(fi.state), region: fi.region }); }
          else if (unmatched.length < 12) unmatched.push({ claim: c.claimNo, officer: c.officerName });
        }
        return Response.json({ ok: true, foKeys: Object.keys(foMap).length, foStates: [...new Set(Object.values(foMap).map(v => v.state).filter(Boolean))].sort(), casesTotal: d.cases.length, casesWithFo: withFo.length, casesWithoutFo: d.cases.length - withFo.length, matchedSample: matched, unmatchedSample: unmatched });
      }
      if (url.pathname === "/api/admin/user" && request.method === "POST") {
        const b = await request.json();
        const em = String(b.email || "").toLowerCase().trim();
        if (!em || em.length > 120 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return Response.json({ ok: false, error: "valid email required" }, { status: 400 });
        if (b.action === "reject" || b.action === "delete") { if (env.USERS) await env.USERS.delete("u:" + em); await secLog(env, "admin-action", me.email, "removed/rejected " + em, true); return Response.json({ ok: true }); }
        if (b.action === "block") { const bu = await kvGetUser(env, em) || { email: em, name: em, ts: Date.now() }; bu.status = "blocked"; await kvPutUser(env, bu); await secLog(env, "admin-action", me.email, "blocked " + em, true); return Response.json({ ok: true }); }
        if (b.action === "unblock") { const uu = await kvGetUser(env, em); if (uu) { uu.status = "approved"; await kvPutUser(env, uu); } await secLog(env, "admin-action", me.email, "un-blocked " + em, true); return Response.json({ ok: true }); }
        let u = await kvGetUser(env, em) || { email: em, name: em, ts: Date.now() };
        u.status = "approved";
        const ROLE_OK = ["manager", "coordinator", "product-head", "boss", "ohs", "call-centre", "hr", "ootat-manager", "rti-manager", "document-manager", "hardcopy-dispatch-manager", "hardcopy-receiving-manager", "client-manager", "mbv_operator", "mbv_checker",
            /* v23.1 — Sujit, 09-Sep 1:35 pm: "add in this one more access called Accounts Team
               and Assigning Team." Two desks that already exist in the office but had to borrow
               somebody else's post to sign in. Neither is a SCOPED role (they are not judged by
               their own cases), so each one sees exactly the pages ticked for it and nothing else. */
            "accounts-team", "assign-team", "field-officer"]; // "admin" can never be assigned through the API
        u.role = ROLE_OK.includes(b.role) ? b.role : (ROLE_OK.includes(u.role) ? u.role : "manager");
        if (u.role === "coordinator") u.states = Array.isArray(b.states) ? b.states.map(s => String(s).trim().slice(0, 60)).filter(Boolean).slice(0, 40) : (b.state ? [String(b.state).trim().slice(0, 60)] : (u.states || []));
        else u.states = [];
        u.state = u.states[0] || "";
        u.manager = (u.role === "manager") ? String(b.manager || u.manager || "").slice(0, 80) : "";
        // Product Head: the managers under him (5-20). He sees his own + all their cases.
        /* The Out of TAT Manager now carries a manager list too — it is what he sees on every
           page EXCEPT the meeting (the meeting stays every-state, every-manager for his
           product). Unlike the Product Head it is allowed to be empty: he may be given the
           meeting alone, and then he simply has no case data on the other pages. */
        const wantsMgrList = (u.role === "product-head" || u.role === "ootat-manager");
        u.managers = wantsMgrList ? (Array.isArray(b.managers) ? b.managers.map(m => String(m).trim().slice(0, 80)).filter(Boolean).slice(0, 60) : (u.managers || [])) : [];
        if (u.role === "product-head" && !u.managers.length) return Response.json({ ok: false, error: "Pick at least one manager for this Product Head." }, { status: 400 });
        u.team = (u.role === "ohs") ? String(b.team || u.team || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80) : "";
        u.teamName = (u.role === "ohs") ? String(b.teamName || u.teamName || "").slice(0, 60) : "";
        if (u.role === "ohs" && !u.team) return Response.json({ ok: false, error: "Pick the team for this OHS (Team Head) member." }, { status: 400 });
        // section access: boss always full; others get the ticked list (default full if none sent)
        if (u.role === "call-centre") u.access = ["feedback", "appointment"];   // Call Centre: ONLY these two pages, always (server-enforced)
        /* OHS (Team Head): Dashboard + Analytics always, plus Out of TAT / Manager Follow-up
           if they are ticked (v18.0). Every other tick is still dropped, and the stored
           record says exactly what the login gets — accessOf() computes the same answer, so
           the two can never disagree. */
        else if (u.role === "ohs") {
          const t = (Array.isArray(b.access) ? b.access.map(x => String(x)) : []).filter(x => OHS_GRANTABLE.includes(x));
          u.access = ["dashboard", "analytics"].concat(t);
        }
        // HR: tick whatever pages you want, exactly like a Manager. A brand-new HR member starts with Field Officers.
        else if (u.role === "hr") u.access = (Array.isArray(b.access) && b.access.length) ? b.access.map(x => String(x)).filter(x => ACCESS_SECTIONS.includes(x)) : ["officers"];
        /* OUT OF TAT MANAGER: the meeting is his job, so he starts with that page and can never
           be left without it. Any other page can still be ticked for him on top. */
        else if (u.role === "ootat-manager") {
          const lst = (Array.isArray(b.access) && b.access.length) ? b.access.map(x => String(x)).filter(x => ACCESS_SECTIONS.includes(x)) : ["ootatmeet"];
          u.access = lst.includes("ootatmeet") ? lst : lst.concat(["ootatmeet"]);
        }
        else if (u.role === "boss") u.access = ACCESS_SECTIONS.slice();
        /* v21.0 — the bill-verification posts: the page is theirs whatever is ticked */
        else if (MBV_ROLES.includes(u.role)) {
          const lst = (Array.isArray(b.access) ? b.access.map(x => String(x)) : []).filter(x => ACCESS_SECTIONS.includes(x));
          u.access = lst.includes("mbv") ? lst : ["mbv"].concat(lst);
        }
        else if (Array.isArray(b.access)) u.access = b.access.map(x => String(x)).filter(x => ACCESS_SECTIONS.includes(x));
        else if (!Array.isArray(u.access)) u.access = defaultAccessFor(u.role);   // v22.2 — a manager starts with his post's eight pages
        /* v21.0 — the MBV role INSIDE the module for a post that was given the page by tick:
           operator unless the admin marked him a checker. The two dedicated posts carry
           their role in the post itself; every other post carries it here. */
        if (MBV_ROLES.includes(u.role)) u.mbvRole = u.role === "mbv_checker" ? "checker" : "operator";
        else if (Array.isArray(u.access) && u.access.includes("mbv")) u.mbvRole = (b.mbvRole === "checker" || (b.mbvRole === undefined && u.mbvRole === "checker")) ? "checker" : "operator";
        else u.mbvRole = "";
        /* v25.0 — the Mail tick works the other way round from every other page: it is ON unless
           the admin takes it off. A request from an admin.html that KNOWS the tick (mailAware)
           says so with the tick's absence; an older client, or a route that never sends a page
           list, leaves the flag exactly as it was. */
        if (b.mailAware === true && Array.isArray(b.access)) u.mailOff = !b.access.includes("mail");
        else if (b.mailOff !== undefined) u.mailOff = b.mailOff === true;
        /* Out of TAT meeting products (Motor TP / Health): for a ticked product this member sees
           EVERY case of it, all states and all managers. Cleared the moment the page tick is removed. */
        if (Array.isArray(b.meetProducts)) u.meetProducts = b.meetProducts.map(x => String(x)).filter(x => MEET_PRODUCTS.includes(x));
        else if (!Array.isArray(u.meetProducts)) u.meetProducts = [];
        if (!Array.isArray(u.access) || !u.access.includes("ootatmeet")) u.meetProducts = [];
        // an Out of TAT Manager with nothing ticked runs BOTH meetings — the role is never empty
        if (u.role === "ootat-manager" && !u.meetProducts.length) u.meetProducts = MEET_PRODUCTS.slice();
        /* ---- CLIENT MANAGER: which insurer(s), and which product ----------------------
           Saved for this role only, and WIPED for every other role — a person moved off the
           client role must not keep a client list that would come back to life if he were
           ever moved onto it again. Refusing to save an empty client list is deliberate: an
           outside login whose scope is blank is the one mistake here that cannot be seen by
           looking at the screen, because a blank scope shows an empty portal that looks
           merely quiet. */
        if (u.role === "client-manager") {
          u.clients = Array.isArray(b.clients) ? b.clients.map(x => String(x).trim().slice(0, 120)).filter(Boolean).slice(0, 40) : (u.clients || []);
          u.clientProducts = Array.isArray(b.clientProducts) ? b.clientProducts.map(x => String(x)).filter(x => MEET_PRODUCTS.includes(x)) : (u.clientProducts || []);
          if (!u.clients.length) return Response.json({ ok: false, error: "Pick at least one client for this Client Manager — a client login with no client would see nothing at all." }, { status: 400 });
          u.access = CLIENT_SECTIONS.slice();
          u.states = []; u.state = ""; u.manager = ""; u.managers = []; u.team = ""; u.teamName = ""; u.meetProducts = [];
        } else { u.clients = []; u.clientProducts = []; }
        await kvPutUser(env, u);
        await secLog(env, "admin-action", me.email, "approved/updated " + em + " role=" + u.role + (u.states.length ? " states=" + u.states.join("|").slice(0, 60) : "") + (u.manager ? " mgr=" + u.manager : ""), true);
        return Response.json({ ok: true, user: u });
      }
      /* ---- THE CLIENT LIST, LIVE ------------------------------------------------------
         The Admin screen must not ask him to TYPE "Cholamandalam General insurance company
         Ltd" — one letter out and the client login sees an empty portal, and nothing on
         screen would say why. So the picker offers the insurer names exactly as they appear
         on today's cases, each with its case count, and he chooses. Admin only. */
      if (url.pathname === "/api/admin/clients") {
        try {
          const d = await getCases(env);
          const byKey = new Map();
          for (const c of (d.cases || [])) {
            const nm = String(c.client || "").trim();
            if (!nm) continue;
            const k = clientKeyW(nm) || nm.toLowerCase();
            const got = byKey.get(k);
            /* several spellings of one insurer collapse to a single option, and the spelling
               offered is the one SKD uses MOST — matching is forgiving either way, but the
               list should read like his own paperwork */
            if (got) { got.cases++; got.spellings[nm] = (got.spellings[nm] || 0) + 1; }
            else byKey.set(k, { name: nm, cases: 1, spellings: { [nm]: 1 } });
          }
          const clients = Array.from(byKey.values()).map(o => {
            let best = o.name, n = 0;
            for (const s in o.spellings) if (o.spellings[s] > n) { n = o.spellings[s]; best = s; }
            return { name: best, cases: o.cases, alsoSpelt: Object.keys(o.spellings).filter(s => s !== best).slice(0, 6) };
          }).sort((a, b) => (b.cases - a.cases) || a.name.localeCompare(b.name));
          return Response.json({ ok: true, clients, total: clients.length, live: true });
        } catch (e) {
          return Response.json({ ok: true, clients: [], total: 0, live: false, error: String(e && e.message ? e.message : e) });
        }
      }
      /* ---- TEAMS: name + team head + member FOs (grouping for the coming OH access phase) ---- */
      if (url.pathname === "/api/admin/teams") {
        if (!env.USERS) return Response.json({ ok: true, teams: [] });
        const l = await env.USERS.list({ prefix: "team:" });
        const teams = [];
        for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { teams.push(JSON.parse(v)); } catch (e) {} } }
        teams.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
        return Response.json({ ok: true, teams });
      }
      if (url.pathname === "/api/admin/team" && request.method === "POST") {
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const action = String(b && b.action || "save").toLowerCase();
        if (action === "delete") {
          const id = String(b && b.id || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80);
          if (!id) return Response.json({ ok: false, error: "Missing team id." }, { status: 400 });
          if (env.USERS) await env.USERS.delete("team:" + id);
          await secLog(env, "admin-action", me.email, "team deleted: " + id, true);
          return Response.json({ ok: true });
        }
        const name = String(b && b.name || "").trim().slice(0, 60);
        const head = String(b && b.head || "").trim().slice(0, 80);
        let members = Array.isArray(b && b.members) ? b.members.map(x => String(x).trim().slice(0, 80)).filter(Boolean) : [];
        members = members.filter((x, i) => members.indexOf(x) === i).slice(0, 25);
        if (name.length < 2) return Response.json({ ok: false, error: "Team name is too short." }, { status: 400 });
        if (!head) return Response.json({ ok: false, error: "Select the team head." }, { status: 400 });
        if (!members.length) return Response.json({ ok: false, error: "Select at least one member field officer." }, { status: 400 });
        let id = String(b && b.id || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80);
        if (!id) id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) + "-" + Date.now().toString(36);
        const team = { id, name, head, members, updatedBy: me.email, updatedTs: Date.now() };
        if (env.USERS) await env.USERS.put("team:" + id, JSON.stringify(team));
        await secLog(env, "admin-action", me.email, "team saved: " + name + " (head " + head + ", " + members.length + " members)", true);
        return Response.json({ ok: true, team });
      }
      return Response.json({ ok: false, error: "Unknown admin endpoint" }, { status: 404 });
    }

    /* ── THE THREE KEY-AUTHED DOORS OF THE DRIVE RUN SIT IN FRONT OF THE SIGN-IN GATE ──
       The Google script has no login and never will — the key IS its door, exactly like
       Acefone's result webhook above. Left behind the gate these would answer 401 to the
       script all night and the folder would quietly never empty. ── */
    /* ══════════ CLAIM DOCUMENTS OUT OF THE DRIVE FOLDER — v13.5, 22-Aug-2026 ══════════
       Sujit: "Around 800 cases only for TP — the related documents, RTI or 134, will be in
       this drive. Once I put the documents in this drive, need to upload in my TP cases
       automatically." And minutes later, the detail that decides how the names are read:
       "One one time it may be more than 3 to 4 documents — RTI, 134, RTO RTI, Hospital RTI
       after the claim number. Everything need to upload."

       The folder was read before this was built. Every file is one PDF named
       "<claim number> <what the document is>.pdf", and BOTH halves vary:

         MOT17383716 134.pdf              · ICICI-style claim, one word after it
         3379508255-01 RTI.pdf            · Chola-style with its own -01 suffix
         C2300030220260040 RTI.pdf        · HDFC-style letter+digits
         600000000192718 134.pdf          · a fifteen-digit number
         OC-26-1502-1801-00000748(309603) RTI.pdf   · a bracketed second reference
         OC-27-1602-1890-00000018 (318434) RTI.pdf  · the same, with a SPACE before the bracket
         MOT14548003 RTI (1).pdf          · Drive's own duplicate marker
         8-2025 134.pdf                   · and names that are no claim number at all

       So the claim number cannot be found by counting words — a claim can contain a space,
       and the label can be two words ("RTO RTI"). THE MATCH DECIDES THE SPLIT: the name is
       cut at every possible point, longest claim first, and the first cut whose left-hand
       side is a real live case wins. Whatever is left over is the document's own label,
       kept as the file name so the case file reads "MOT17361398 RTO RTI.pdf" at SKD.

       Three rules this must never break:
         · ONE claim can receive as many documents as arrive — RTI, 134, RTO RTI and
           Hospital RTI are four different papers, not one repeated. Nothing is refused as a
           duplicate for sharing a claim number; only the SAME Drive file is refused twice.
         · A name that matches nothing is NEVER guessed onto a nearby case. It comes back as
           "not matched" with the claim number the portal read, and the script parks it in
           its own folder for a human to look at.
         · Every file, matched or not, is written into the register with its verdict, so the
           screen can say what happened to all 1,600 rather than only the good ones. ══════════ */
    if (url.pathname === "/api/drive-docs/push" && request.method === "POST") {
      try {
        const supplied = String(request.headers.get("X-SKD-Key") || "").trim();
        let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
        let form;
        try { form = await request.formData(); } catch (e) { return Response.json({ ok: false, error: "Send the files as multipart/form-data." }, { status: 400 }); }
        const key = supplied || String(form.get("key") || "").trim();
        /* SECURITY: this door takes no login — the Apps Script has none — so the key IS the
           door. A wrong key is refused and logged, and the answer says nothing about which
           part was wrong. */
        if (!cfg.key || key !== cfg.key) { await secLog(env, "access-denied", "drive-script", "drive-docs push with a wrong or missing key", false); return Response.json({ ok: false, error: "Not authorised." }, { status: 403 }); }
        await ddocBeat(env);   /* v33.0 */
        if (!allowRate("ddocpush", 600, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many pushes this hour — the script will try again on its next run." }, { status: 429 });
        /* ── THE NIGHT WINDOW, GUARDED AT THIS END TOO ──────────────────────────────────
           Sujit, 22-Aug-2026: "This upload session need to run in night time — why? Because
           daytime we will be working, and Praveen already informed that the server is
           crashing." The Apps Script only wakes between 10 pm and 8 am, but a trigger can be
           edited by anyone with the script open, and a mistake there would put a thousand
           uploads through SKD in the middle of a working morning. So the portal refuses
           daytime pushes itself — the same rule, written down twice on purpose. */
        /* v30.4 — the window still holds for a script running on its own, but NOT for the
           send list: papers he ticked himself are work he has asked for, in the handful, and
           making him wait until ten at night for four files is the opposite of "manual". */
        const queuedNow = (await sendQueue(env, 400)).length > 0;
        if (!ddocNightNow(cfg) && !cfg.anytime && !queuedNow) {
          const h = new Date(Date.now() + 19800000).getUTCHours();
          return Response.json({ ok: false, daytime: true, error: "Daytime — uploads run only between " + ddocWinText(cfg) + " IST, to keep SKD's server clear while the office is working. It is " + h + ":00 IST now. (A list ticked on the Document Register goes up at any hour.)" }, { status: 409 });
        }

        /* THE FIELD NAMES ARE docs0, docs1, docs2 … ON PURPOSE. Apps Script builds multipart
           for you only when each payload value has its OWN field name — repeat "docs" three
           times and two of the three files are silently dropped. So the script numbers them,
           the numbers are read back here and sorted, and each file lines up with its own row
           in `meta`. A plain "docs" is still accepted, for anything sending one file. */
        const numbered = [];
        for (const [k, v] of form.entries()) {
          const m = /^docs(\d*)$/.exec(k);
          if (!m || !v || typeof v !== "object" || !v.name) continue;
          numbered.push({ i: m[1] === "" ? 0 : parseInt(m[1], 10), f: v });
        }
        numbered.sort((a, b) => a.i - b.i);
        const files = numbered.map(x => x.f);
        if (!files.length) return Response.json({ ok: false, error: "No files received (the field names must be docs0, docs1 …)." }, { status: 400 });
        if (files.length > 10) return Response.json({ ok: false, error: "Maximum 10 files in one push." }, { status: 400 });
        let metaAll = []; try { metaAll = JSON.parse(String(form.get("meta") || "[]")); } catch (e) { metaAll = []; }
        const meta = numbered.map(x => metaAll[x.i] || {});

        /* the live book, indexed by every way a claim number can be written */
        const d = await getCases(env);
        const index = ddocIndex(d.cases);
        let log = []; try { log = JSON.parse(await env.USERS.get(DDOC_LOG_KEY) || "[]"); } catch (e) { log = []; }
        const seen = {}; for (const row of log) { if (row.fid && row.r === "uploaded") seen[row.fid] = row; }

        const now = Date.now();
        const results = [], toSend = {};        // claimNo -> [{file, entry}]
        for (let i = 0; i < files.length; i++) {
          const f = files[i];
          const m = meta[i] || {};
          const fid = String(m.fid || "").slice(0, 80);
          const name = String(m.name || f.name || "").slice(0, 200);
          const entry = { fid, n: name, ts: now, r: "", c: "", l: "", p: "", m: "" };
          /* the same Drive file, already uploaded once — never sent twice */
          if (fid && seen[fid]) {
            entry.r = "duplicate"; entry.c = seen[fid].c || ""; entry.l = seen[fid].l || "";
            entry.m = "This same file was already uploaded on " + new Date(seen[fid].ts + 19800000).toISOString().slice(0, 16).replace("T", " ") + " IST.";
            results.push({ fid, result: "duplicate", claimNo: entry.c, label: entry.l, msg: entry.m }); log.push(entry); continue;
          }
          if (!/\.pdf$/i.test(name) && f.type !== "application/pdf") {
            entry.r = "error"; entry.m = "Not a PDF.";
            results.push({ fid, result: "error", msg: entry.m }); log.push(entry); continue;
          }
          const sz = (typeof f.size === "number") ? f.size : 0;
          if (sz > 15 * 1024 * 1024) {
            entry.r = "error"; entry.m = "Bigger than 15 MB — SKD refuses it.";
            results.push({ fid, result: "error", msg: entry.m }); log.push(entry); continue;
          }
          /* a real PDF, checked by its own first five bytes — not by its name */
          try {
            const head = new Uint8Array(await f.slice(0, 5).arrayBuffer());
            let tag = ""; for (let k = 0; k < head.length; k++) tag += String.fromCharCode(head[k]);
            if (tag !== "%PDF-") { entry.r = "error"; entry.m = "Not a genuine PDF (signature check failed)."; results.push({ fid, result: "error", msg: entry.m }); log.push(entry); continue; }
          } catch (e) { entry.r = "error"; entry.m = "The file could not be read."; results.push({ fid, result: "error", msg: entry.m }); log.push(entry); continue; }

          const cut = ddocSplit(name, index);
          if (!cut.hit) {
            entry.r = "nomatch"; entry.c = cut.readAs; entry.l = cut.label;
            entry.m = "No live case carries this claim number" + (cut.readAs ? (" — read as \"" + cut.readAs + "\"") : "") + ".";
            results.push({ fid, result: "nomatch", claimNo: "", label: cut.label, msg: entry.m }); log.push(entry); continue;
          }
          entry.c = cut.hit.claimNo; entry.l = cut.label; entry.p = typeOfSub(cut.hit.subProduct);
          (toSend[cut.hit.claimNo] = toSend[cut.hit.claimNo] || []).push({ f, name, entry, fid, label: cut.label });
        }

        /* ══ THE LIST IS THE PERMISSION ══════════════════════════════ v33.1, 22-Sep-2026 ══
           Sujit, 22-Sep: "I don't want to upload [automatically]. I WILL CLICK THIS AND SEND —
           that only need to be uploaded."

           v30.4 stopped the portal OFFERING the whole book. It never stopped it ACCEPTING one:
           any PDF whose name carried a live claim number went straight through to SKD, so an
           older script — or one whose sweep was switched back on — could still put the entire
           folder onto the cases and this door would help it. It asks now.

           If the register cannot be read, NOTHING GOES. "We could not check whether he asked"
           is not "he asked", and the whole point of this gate is that silence means no. */
        let asked = null, askErr = "";
        try { asked = await queuedFor(env, Object.keys(toSend)); }
        catch (e) { asked = null; askErr = String((e && e.message) || e); }
        for (const claimNo of Object.keys(toSend)) {
          const keep = [];
          for (const g of toSend[claimNo]) {
            const verdict = asked ? mayPush(asked, claimNo, g.label || g.name)
              : { ok: false, why: "The send list could not be read just now, so nothing was sent. Nothing is lost — it stays in the folder." };
            /* ONE TICK IS ONE PAPER. His folder holds two copies of some papers under
               different Drive ids; without this the snapshot would let both through in the
               same push and SKD would refuse the second. The permission is spent when it is
               used, so the second copy is turned away here and never leaves the folder. */
            if (verdict.ok) { keep.push(g); delete asked[claimNo][verdict.col]; continue; }
            g.entry.r = "notasked";
            g.entry.m = verdict.why;
            results.push({ fid: g.fid, result: "notasked", claimNo, label: g.label, msg: g.entry.m });
            log.push(g.entry);
          }
          if (keep.length) toSend[claimNo] = keep; else delete toSend[claimNo];
        }
        if (askErr) await secLog(env, "docreg-send", "drive-script", "push refused — the send list could not be read: " + askErr.slice(0, 120), true);

        /* one call to SKD per claim — his "3 to 4 documents in one time" arrive together,
           exactly as a person would attach them on the case screen */
        for (const claimNo in toSend) {
          const group = toSend[claimNo];
          const up = await skdUploadDocs(env, claimNo, group.map(g => ({ file: g.f, name: g.name })));
          for (const g of group) {
            /* v33.0 — THREE words, not two. "a file entry already exists" is SKD saying the
               paper is already on the case: a success. Writing it as an error put 3,129 red
               lines on the card and buried the few that were real. sendVerdict has always
               known the difference; the log line now uses the same judgement. */
            const vv = sendVerdict(up.ok, up.ok ? (up.msg || "") : (up.error || ""));
            g.entry.r = vv.status === "sent" ? "uploaded" : vv.status;
            g.entry.m = up.ok ? (up.msg || "Uploaded to the case at SKD.") : ("SKD refused it: " + (up.error || "no reason given"));
            results.push({ fid: g.fid, result: g.entry.r, claimNo, label: g.label, msg: g.entry.m });
            log.push(g.entry);
            /* v30.4 — the verdict goes back onto his own row on the register, and "a file
               entry already exists" is written there as ALREADY ON THE CASE, which is what it
               actually means, rather than as one more red error line. */
            try { const col = colOfName(g.label || g.name); if (col) await markSent(env, claimNo, col, up.ok, up.ok ? (up.msg || "") : (up.error || "")); } catch (e) {}
          }
        }

        if (log.length > DDOC_LOG_MAX) log = log.slice(log.length - DDOC_LOG_MAX);
        try { await env.USERS.put(DDOC_LOG_KEY, JSON.stringify(log)); } catch (e) { /* the upload already happened — a full register must not undo it */ }
        try { await env.USERS.put(DDOC_KV_KEY, JSON.stringify(Object.assign({}, cfg, { lastRun: now, lastCount: files.length }))); } catch (e) {}
        return Response.json({ ok: true, results });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }


    /* ══════════ WHICH CLAIMS TO GO LOOKING FOR — the direction he corrected ══════════
       Sujit, 22-Aug-2026: "In my drive, already completed case documents will also be there.
       You don't want to search from this thing. You have to check the claim number in OUR
       PORTAL — from there you have to check the drive, documents available, take that, pull
       that and upload it."

       That inversion is the whole design now, and he is right about why: the folder holds
       papers for cases that closed months ago, and sweeping the folder would push all of
       them at SKD. The LIVE BOOK is the driver. This door hands the script a slice of live
       claim numbers to go looking for, newest work first, and remembers which ones have
       already been looked for so a night does not re-search the same thousand names.

       A claim that had nothing in Drive is looked for again after three days — documents
       arrive days after a case does, and a case checked once at midnight must not be written
       off for ever. */
    if (url.pathname === "/api/drive-docs/wanted" && request.method === "GET") {
      try {
        const supplied = String(request.headers.get("X-SKD-Key") || "").trim();
        let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
        if (!cfg.key || supplied !== cfg.key) return Response.json({ ok: false, error: "Not authorised." }, { status: 403 });
        await ddocBeat(env);   /* v33.0 — ASKING is being alive, even when the answer is nothing */
        /* ══ v30.4 · THE SCRIPT NO LONGER CHOOSES — HE DOES ═══════════════════════════════
           Sujit, 18-Sep 6:40 am, after a night that offered SKD 363 papers it already had:
           "I told before, one feature is there — in night time the documents will be
            uploading that portal. I don't want that to work, because we are going to manual.
            I will select all or I will select whichever need to upload."

           So this door stops handing out the whole book. It hands out HIS SEND LIST: the
           papers he ticked on the Document Register and nothing else. An empty list is the
           off switch — the script wakes, is given nothing, and goes back to sleep without
           touching SKD. The night window no longer gates it either: a list he made himself
           at eleven in the morning is work he has asked for, and it is a handful of files,
           not the thousand-file sweep the window was written to keep out of office hours. */
        const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get("limit") || "60", 10) || 60));
        const q = await sendQueue(env, limit);
        const seen = {}, out = [];
        for (const row of q) { if (!seen[row.claim]) { seen[row.claim] = 1; out.push(row.claim); } }
        const files = q.map(row => ({ claim: row.claim, col: row.col, name: row.name || "", fid: row.fid || "" }));
        return Response.json({ ok: true, night: out.length > 0, queueOnly: true, window: ddocWinText(cfg), gapSeconds: cfg.gapSeconds || 90,
          claims: out, files, waiting: q.length,
          note: out.length
            ? "These are the papers Sujit ticked on the Document Register. Send only these — the charge sheet is never on this list."
            : "Nothing has been ticked on the Document Register, so there is nothing to send. Sleep and ask again later." });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    /* "I looked for this claim in the folder and there was nothing" — recorded so the same
       name is not searched again tonight. Not a failure, and not written into the register:
       a register of 1,600 "nothing found" lines would bury the twelve that need a person. */
    if (url.pathname === "/api/drive-docs/checked" && request.method === "POST") {
      try {
        const supplied = String(request.headers.get("X-SKD-Key") || "").trim();
        let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
        if (!cfg.key || supplied !== cfg.key) return Response.json({ ok: false, error: "Not authorised." }, { status: 403 });
        let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
        const claims = Array.isArray(b && b.claims) ? b.claims.slice(0, 400) : [];
        if (!claims.length) return Response.json({ ok: true, marked: 0 });
        let chk = {}; try { chk = JSON.parse(await stGet(env, DDOC_CHK_KEY) || "{}"); } catch (e) { chk = {}; }
        const now = Date.now();
        for (const c of claims) { const k = claimKey(c); if (k) chk[k] = now; }
        /* housekeeping: a claim not seen for a month has left the live book — forget it */
        const cutoff = now - 31 * 24 * 3600 * 1000;
        for (const k in chk) { if (chk[k] < cutoff) delete chk[k]; }
        await stSoft(env, DDOC_CHK_KEY, JSON.stringify(chk));
        return Response.json({ ok: true, marked: claims.length });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }


    /* ══════════ THE DRIVE FOLDER, LISTED — POST /api/docreg/drive (v27.2) ══════════════
       Sujit, 16-Sep 3:40 am, the "All separated PDF" folder open on one screen and the
       Document Register on the other:

         "In this Drive, all the RTI, 134 will be available — which, which is available.
          Please mark in this dashboard and let me know, connect this Drive and which which
          it is there or not. Make this also activate, need to function correctly."

       WHY THE REGISTER WAS SHOWING DASHES. The amber "In Drive" mark was read off
       drivedocs:log — the PUSH REGISTER, which only ever holds the handful of files a night's
       upload actually offered SKD. The folder holds hundreds of RTI and 134 papers that were
       never offered, so the column read as a dash while the paper sat in the folder. Reading
       the push log was never going to answer "which, which is available" — only the folder
       itself can.

       WHAT THIS DOOR IS. The folder's LISTING — names and Drive ids, no bytes, no upload, no
       call to SKD at all. So it is nothing like the push door: it does not wait for the night
       window (there is no SKD load to spare), it cannot put a paper on a case by accident,
       and a whole folder of 2,000 names costs five small posts.

       THE KEY IS THE DOOR, exactly as on the push route — the Apps Script has no login, so it
       sends the same X-SKD-Key it already holds. Nothing new for him to set up.

       STALE ROWS. Each run carries a runId; every row it writes is stamped with it. When the
       script says it has finished the folder, rows older than that runId are dropped — so a
       file DELETED from Drive stops showing as held, instead of staying Yes for ever.        */
    if (url.pathname === "/api/docreg/drive" && request.method === "POST") {
      try {
        let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
        const supplied = String(request.headers.get("X-SKD-Key") || "").trim();
        let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
        const key = supplied || String((b && b.key) || "").trim();
        if (!cfg.key || key !== cfg.key) { await secLog(env, "access-denied", "drive-script", "docreg drive listing with a wrong or missing key", false); return Response.json({ ok: false, error: "Not authorised." }, { status: 403 }); }
        await ddocListBeat(env);   /* v33.4 — the LISTING half is alive; that is not the sending half */
        if (!allowRate("docregdrive", 300, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many listing pages this hour." }, { status: 429 });
        await ensureDocRegSchema(env);

        const runId = Math.max(0, parseInt((b && b.runId) || 0, 10) || Date.now());
        const files = Array.isArray(b && b.files) ? b.files.slice(0, 1000) : [];

        /* the run is finished: anything not seen this run is no longer in the folder */
        if (b && b.done) {
          let gone = 0;
          try { const r = await env.DB.prepare("DELETE FROM doc_drive WHERE at < ?1").bind(runId).run(); gone = (r && r.meta && r.meta.changes) || 0; } catch (e) { gone = 0; }
          try { await env.DB.prepare("DELETE FROM doc_drive_miss WHERE at < ?1").bind(runId).run(); } catch (e) {}
          let held = 0; try { const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM doc_drive").first(); held = (c && c.n) || 0; } catch (e) {}
          try { await stPut(env, "docreg:drive:last", JSON.stringify({ at: Date.now(), runId, held, gone })); } catch (e) {}
          return Response.json({ ok: true, done: true, held, dropped: gone });
        }
        if (!files.length) return Response.json({ ok: false, error: "No file names in this page." }, { status: 400 });

        /* the live book, indexed every way a claim number can be written — the SAME index the
           upload script matches on, so the register and the uploader can never disagree about
           which case a file belongs to */
        const d = await getCases(env);
        const index = ddocIndex(d.cases);

        const put = [], miss = [], per = {};
        for (const col of DOC_COLS) per[col.key] = 0;
        let matched = 0, nocol = 0, nocase = 0;
        for (const f of files) {
          const name = String((f && (f.name || f.n)) || "").slice(0, 200);
          const fid = String((f && (f.id || f.fid)) || "").slice(0, 80);
          if (!name || !/\.pdf$/i.test(name)) continue;
          const cut = ddocSplit(name, index);
          if (!cut.hit) { nocase++; miss.push({ name, why: "no live case" + (cut.readAs ? " for \"" + cut.readAs + "\"" : "") }); continue; }
          /* ONLY the label decides the column, never the whole name. "500000000080764_134.pdf"
             carries 134 twice over — once as a document type and once inside a fifteen-digit
             claim number — and reading the whole string would file half the folder as 134. */
          const col = colOfName(cut.label);
          if (!col) { nocol++; miss.push({ name, why: cut.label ? ("\"" + cut.label + "\" is not one of the seven columns") : "no document name after the claim number" }); continue; }
          matched++; per[col]++;
          put.push(env.DB.prepare("INSERT OR REPLACE INTO doc_drive (claim, col, name, fid, at) VALUES (?1, ?2, ?3, ?4, ?5)")
            .bind(cut.hit.claimNo, col, name, fid, runId));
        }
        if (put.length) { try { await env.DB.batch(put); } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); } }
        /* the not-matched names are the ones a person must act on, so they are kept by name —
           capped, and only the newest run's, so the list never becomes a landfill */
        if (miss.length) {
          const mp = miss.slice(0, 200).map(m => env.DB.prepare("INSERT OR REPLACE INTO doc_drive_miss (name, read_as, at) VALUES (?1, ?2, ?3)").bind(m.name, m.why, runId));
          try { await env.DB.batch(mp); } catch (e) {}
        }
        return Response.json({ ok: true, runId, seen: files.length, matched, filed: put.length, per, notMatched: { noCase: nocase, noDocName: nocol } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }


    /* ---------- GATE: everything past here needs an approved session ---------- */
    let me = null;
    {
      const p = url.pathname;
      // brand images stay public: the sign-in page (logged-out) and Word letterheads load them
      const publicAsset = /^\/(logo|logo-icon|logo-transparent|fieldforce-logo|fieldforce-logo-dark|fieldforce-icon|favicon-32|favicon-48|favicon-180|mail-icon-192|mail-icon-512|mail-icon-maskable)\.png$/.test(p);
      /* v32.2 — THE THREE FILES THAT MAKE TaaSen MAIL INSTALLABLE ON A PHONE.
         run_worker_first puts this sign-in gate in front of EVERY file, and that breaks a PWA
         in two places a person would never think to look:
           · a browser fetches the MANIFEST with no cookie at all, so behind the gate it 302s
             to the sign-in page and the install offer silently never appears;
           · the SERVICE WORKER must be served as JavaScript from the root scope before anyone
             is signed in, or registration fails and there are no notifications, ever.
         Neither file carries anything private — the manifest is a name, a colour and three
         icon paths, and sw.js is code that fetches nothing without the viewer's own cookie.
         The mail-install page is public on purpose too: it is the link Sujit forwards on
         WhatsApp, and a staff member opens it BEFORE he has ever signed in. */
      const pwaPublic = (p === "/sw.js" || p === "/manifest.webmanifest" || p === "/mail-install.html");
      const publicPage = (p === "/" || p === "/index.html") || publicAsset || pwaPublic;
      if (!publicPage) {
        me = await currentUser(env, request);
        if (!me) {
          if (p.startsWith("/api/")) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
          return Response.redirect(url.origin + "/", 302);
        }
        if (p === "/admin.html" && me.role !== "admin") return Response.redirect(url.origin + "/portal.html", 302);
        if (p === "/api-check.html" && me.role !== "admin") return Response.redirect(url.origin + "/portal.html", 302);   // the live API diagnostic: admin only
        // section access: block the standalone pages a member isn't allowed to open
        if (p === "/analytics.html" && !canAccess(me, "analytics")) {
          await secLog(env, "access-denied", me.email, "analytics (not permitted)", false);
          return url.searchParams.get("embed") ? new Response("Not permitted", { status: 403 }) : Response.redirect(url.origin + "/portal.html", 302);
        }
        if (p === "/questionnaire.html" && !canAccess(me, "questionnaire")) {
          await secLog(env, "access-denied", me.email, "questionnaire (not permitted)", false);
          return url.searchParams.get("embed") ? new Response("Not permitted", { status: 403 }) : Response.redirect(url.origin + "/portal.html", 302);
        }
        /* v32.0 — INVOICING. The page is served two ways (as /invoice by its own module, and
           as the asset /invoice.html the sidebar frames), so the gate has to stand in front of
           both or the second one is an open back door. A client-manager and a call-centre
           login are refused here by name, exactly as the module refuses them: an insurer's own
           login never sees our rate card, and a tick in Admin cannot widen that. */
        /* mirrors invoiceRole() in invoice-index.js exactly — the two refused roles first,
           then admin and boss always, then the ticks. The module short-circuits on role and
           this gate must too, or the page and its own doors disagree about the same person. */
        if (p === "/invoice.html" && me.role !== "admin" && me.role !== "boss" &&
            (["client-manager", "call-centre"].indexOf(String(me.role || "")) !== -1 ||
             !(canAccess(me, "invoicing") || canAccess(me, "invoicing_admin")))) {
          await secLog(env, "access-denied", me.email, "invoicing (not permitted)", false);
          return url.searchParams.get("embed") ? new Response("Not permitted", { status: 403 }) : Response.redirect(url.origin + "/portal.html", 302);
        }
      }
    }

    // Secure Claude proxy (browser modules call this) — model + token caps enforced
    if (url.pathname === "/api/ai" && request.method === "POST") {
      if (!allowRate("ai:" + (me ? me.email : "?"), 60, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many AI requests this hour — please wait a while and try again." }, { status: 429 });
      let bodyIn;
      try { bodyIn = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      if (!bodyIn || !Array.isArray(bodyIn.messages) || !bodyIn.messages.length || bodyIn.messages.length > 12) return Response.json({ ok: false, error: "Bad messages" }, { status: 400 });
      /* v24.0 — Connector mode: the browser's prompt (the Questionnaire page typed by hand) goes on the AI queue for Claude on his plan */
      if ((await aiEngine(env)) === "connector") {
        const userText = bodyIn.messages.map(m => Array.isArray(m.content) ? m.content.filter(c => c && c.type === "text").map(c => c.text).join("\n") : String(m.content || "")).join("\n\n").slice(0, 60000);
        const kind = bodyIn.kind === "questionnaire" || /questionnaire/i.test(String(bodyIn.system || "")) ? "questionnaire" : "questionnaire";
        const jobId = await queueJob(env, { kind, ref: "manual|" + Date.now().toString(36), title: "Questionnaire — typed case" + (bodyIn.title ? " · " + String(bodyIn.title).slice(0, 80) : ""),
          by: { email: me ? me.email : "", name: me ? me.name : "" }, instructions: String(bodyIn.system || "").slice(0, 24000), task: userText, docs: [], meta: { manual: true } });
        return Response.json({ ok: true, queued: true, jobId, engine: "connector" });
      }
      const safe = {
        model: await claudeModel(env),                 // v26.3 — the card's choice, not the page's
        max_tokens: Math.min(Math.max(parseInt(bodyIn.max_tokens, 10) || 1000, 1), AI_MAX_TOKENS),
        messages: bodyIn.messages
      };
      if (typeof bodyIn.system === "string" && bodyIn.system.length <= 24000) safe.system = bodyIn.system;
      const bodyText = JSON.stringify(safe);
      if (bodyText.length > 300000) return Response.json({ ok: false, error: "Request too large" }, { status: 413 });
      /* v26.3 — Gemini / ChatGPT mode: the same prompt goes to Google or OpenAI, and the answer
         is handed back in the shape the page already reads (content[0].text), so the page needs no change.
         v26.7 — the list is KEYED, so DeepSeek (and the next one) needs no edit here. */
      const eng = await aiEngine(env);
      if (KEYED.includes(eng)) {
        try {
          const text = await askModel(env, safe, "Questionnaire — typed case");
          return Response.json({ ok: true, engine: eng, content: [{ type: "text", text }] });
        } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e).slice(0, 300), engine: eng }, { status: 502 }); }
      }
      if (!env.ANTHROPIC_API_KEY) return Response.json({ error: "ANTHROPIC_API_KEY not set" }, { status: 500 });
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: bodyText
      });
      return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json" } });
    }

    // MPA locked-format report (returns the field JSON)
    if (url.pathname.startsWith("/api/report-mpa/")) {
      const claim = decodeURIComponent(url.pathname.substring("/api/report-mpa/".length));
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      if (!allowRate("heavy:" + (me ? me.email : "?"), 40, 60 * 60 * 1000)) { await secLog(env, "rate-limited", me ? me.email : "?", "report-mpa"); return Response.json({ ok: false, error: "Too many report/questionnaire requests this hour — please wait a while." }, { status: 429 }); }
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me ? me.email : "?", "report-mpa " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      try {
        /* v24.0 — Connector mode: queued for Claude on his plan; the page polls /api/ai/result */
        const qm = (await aiEngine(env)) === "connector" ? { kind: "report_mpa", by: { email: me.email, name: me.name } } : null;
        const r = await generateMPA(env, claim, qm ? { queue: qm } : {});
        if (r.queued) return Response.json({ ok: true, queued: true, jobId: r.jobId, claim, used: r.used, docs: r.docs, engine: "connector" });
        return Response.json({ ok: true, claim, fields: r.fields, used: r.used });
      }
      catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    // AI Questionnaire — reads the case's Discharge Summary + Final Bill (Claim Documents folder)
    /* ══ THE SET TABLE, READ BY THE PAGE ══════════════════════════════════════════════════
       The cards on the Questionnaire page are drawn from this, not from a list written into
       the page — so his sets 4 to 7 arrive by editing Q_SUBJECTS in this file and nothing
       else. The page keeps its own copy of the three as a fallback for the moment this door
       cannot be reached, exactly as the FO directory does. */
    if (url.pathname === "/api/questionnaire/sets") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 });
      /* ── v30.3 · THE SUB TRIGGER LIST IS HIS SHEET, PLUS WHAT HE HAS ADDED ────────────────
         His prompt sheet is the standard, so the list under each trigger is the sheet's own
         rows in his order, and after them every sub trigger he has saved himself under Others.
         A trigger his sheet does not cover keeps the built-in list rather than going empty. */
      /* v32.3 — and the same one level up: his six, then every trigger he has added himself.
         A trigger he added has no subs of its own yet, so the loop below leaves it empty and
         its dropdown opens with only "Other — I will type it". That is the way in. */
      const trigs = await triggersFor(env, triggerList());
      for (const t of trigs) {
        try { const merged = await subsFor(env, t.key); if (merged.length) t.subs = merged; } catch (e) {}
      }
      return Response.json({ ok: true, max: Q_MAX_QUESTIONS, sets: Object.keys(Q_SUBJECTS).map(k => {
        const s = Q_SUBJECTS[k];
        return { key: k, card: s.card || s.label, label: s.label, icon: s.icon || "fa-clipboard-question", blurb: s.blurb || "", max: s.max, focus: s.focus || "", paper: paperOf(s) };
      }), triggers: trigs, indirect: INDIRECT_RULE, subMark: SUB_MARK });
    }

    /* ══ v30.3 · WHICH PROMPT THIS PAIR USES, AND KEEPING A NEW ONE ════════════════════════
       Sujit, 18-Sep: "Whichever prompt it will be there means that only regarding that question
       will we be asking … Others — for that, the prompt need to be saved with the sub trigger.
       You need to ask what will be this sub trigger name; the prompt will be saved and next
       time this also need to be [there]."

       GET  /api/questionnaire/prompt?trigger=&sub=   what will be used, and where it came from
       POST /api/questionnaire/sub                    keep a sub trigger and its prompt

       The GET answers for the page's own eyes — it shows him the prompt before he presses
       Generate, which is the whole of his doubt answered on screen every time. It also carries
       the READY-MADE ground for the typed-case path, so a case with no claim number asks on the
       same words as a case opened from the portal, and there is no second copy to drift.
       The POST is admin + boss: the saved list is everybody's, and the standard is his. */
    if (url.pathname === "/api/questionnaire/prompt" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 });
      /* v32.3 — triggerAny, not triggerOf: a trigger he added himself is not in the static
         table, so triggerOf alone would answer "Unknown trigger." for the one he just typed. */
      const trig = await triggerAny(env, (url.searchParams.get("trigger") || "").slice(0, 60), triggerOf);
      const sub = String(url.searchParams.get("sub") || "").replace(/\s+/g, " ").trim().slice(0, 160);
      if (!trig) return Response.json({ ok: false, error: "Unknown trigger." }, { status: 400 });
      const pr = sub ? await promptFor(env, trig.key, sub) : null;
      const ins = promptSideFor("insured", pr), doc = promptSideFor("doctor", pr);
      return Response.json({
        ok: true, trigger: trig.key, sub,
        from: pr ? pr.from : "", by: (pr && pr.by) || "", at: (pr && pr.at) || 0,
        ins, doc,
        onSheet: sheetSubs(trig.key).some(s2 => s2.toLowerCase() === sub.toLowerCase()),
        /* the same ground the Worker would build, for the typed-case path */
        ground: {
          insured: ins ? groundFromPrompt(trig.label, sub, "insured", ins, (trig.insured || {}).note) : groundFor(trig, sub, "insured"),
          doctor: doc ? groundFromPrompt(trig.label, sub, "doctor", doc, (trig.doctor || {}).note) : groundFor(trig, sub, "doctor"),
          bill: groundFor(trig, sub, "bill")
        }
      });
    }
    /* ══════════ THE PAPERS ON THIS CASE ══════════════════════════ v31.7, 19-Sep-2026 ═════
       Sujit: "I need what documents are available there to that particular case — in that I
       will select." Every PDF SKD holds, folder by folder. Nothing is downloaded here: this
       is the list he ticks from, and only a tick causes a download. */
    if (url.pathname === "/api/questionnaire/docs" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (isClientRole(me)) return Response.json({ ok: false, error: "The papers of a case are internal." }, { status: 403 });
      const claim = (url.searchParams.get("claim") || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me ? me.email : "?", "q-docs " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      try {
        const rf = await skdGetCase(env, sc.claimNo || claim);
        const full = await rf.json();
        const groups = listCaseDocs(full);
        let n = 0; groups.forEach(g => { n += g.files.length; });
        return Response.json({ ok: true, claim: sc.claimNo || claim, groups, total: n, maxPages: MAX_PICK_PAGES, maxPapers: MAX_PICK_PAPERS });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 502 }); }
    }

    /* ══════════ THE PAGES INSIDE ONE PAPER ══════════════════════════════════════════════
       "In that PDF total 50 pages was there; in that 50 pages any 3 to 25 pages I'll be
       selecting." To tick page 12 he has to know what is on page 12, so each page comes back
       with its first line. A scan has no text line and says so once, rather than showing
       fifty blank rows. ONE file is downloaded, the one he opened. */
    if (url.pathname === "/api/questionnaire/doc-pages" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (isClientRole(me)) return Response.json({ ok: false, error: "The papers of a case are internal." }, { status: 403 });
      const claim = (url.searchParams.get("claim") || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me ? me.email : "?", "q-doc-pages " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      if (!allowRate("qpages:" + me.email, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many papers opened this hour — please wait a while." }, { status: 429 });
      try {
        const rf = await skdGetCase(env, sc.claimNo || claim);
        const full = await rf.json();
        const fl = findDoc(full, url.searchParams.get("folder") || "", url.searchParams.get("name") || "");
        if (!fl) return Response.json({ ok: false, error: "That paper is not on this case." }, { status: 404 });
        const buf = await fetchCaseDocBuf(env, fl);
        if (!buf) return Response.json({ ok: false, error: "SKD would not hand that file over. It is on the case, but the download was refused." }, { status: 502 });
        const got = await peekPages(new Uint8Array(buf), qPdfText, qPdfPageImages, 400, fl.kind, qWordRead);
        return Response.json(Object.assign({ ok: !!got.ok, name: fl.name, folder: fl.folder, maxPages: MAX_PICK_PAGES }, got));
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 502 }); }
    }

    if (url.pathname === "/api/questionnaire/sub" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) { await secLog(env, "access-denied", me.email, "questionnaire sub trigger (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 }); }
      if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "A new sub trigger is kept for everyone, so only admin can add one. You can still generate with the prompt you have typed — it just will not be saved." }, { status: 403 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      /* v32.3 — triggerAny, so a sub trigger can be put under a trigger he added himself */
      const trig = await triggerAny(env, String((b && b.trigger) || "").slice(0, 60), triggerOf);
      if (!trig) return Response.json({ ok: false, error: "Pick the trigger first." }, { status: 400 });
      try {
        const saved = await saveSubPrompt(env, trig.key, (b && b.sub) || "", (b && b.ins) || "", (b && b.doc) || "", { email: me.email, name: me.name });
        await secLog(env, "questionnaire-sub", me.email, trig.label + " · " + saved.sub, true);
        return Response.json({ ok: true, trigger: trig.key, sub: saved.sub, ins: saved.ins, doc: saved.doc, subs: await subsFor(env, trig.key) });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 400 }); }
    }

    /* ══ v32.3 · KEEPING A TRIGGER HE TYPED ════════════════════════════════════════════════
       Sujit, 21-Sep: "Questionnaire trigger add — Other — I will type it. Need to add more
       multiple triggers question triggers after this need to save same, like sub trigger."

       POST /api/questionnaire/trigger   keep a trigger, by name, and nothing else

       The sub-trigger door above, one level up and with one field instead of three. Same
       guard, same reason: the trigger list is everybody's, so only he changes it. No prompt is
       taken here — the prompt belongs to the pair, and he makes the pair by adding a sub
       trigger under it through the door above, exactly as he always has. */
    if (url.pathname === "/api/questionnaire/trigger" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) { await secLog(env, "access-denied", me.email, "questionnaire trigger (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 }); }
      if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "A new trigger is kept for everyone, so only admin can add one. You can still generate with the prompt you have typed — it just will not be saved." }, { status: 403 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      try {
        const saved = await saveTrigger(env, (b && b.label) || "", { email: me.email, name: me.name });
        await secLog(env, "questionnaire-trigger", me.email, saved.label, true);
        return Response.json({ ok: true, trigger: saved, triggers: await triggersFor(env, triggerList()) });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 400 }); }
    }

    /* ══ TAKE A TRIGGER OFF THE LIST AGAIN ══════════════════ v32.7 · 21-Sep-2026 ════════
       Sujit, hours after the Other box shipped, looking at his own list: "permanent
       exclusions / Standard exclusion — remove this." Adding was one-way until now.
       Same fence as adding: admin or boss, because the list is everyone's. His SIX SHEET
       TRIGGERS CAN NEVER GO — deleteTrigger refuses those by name, whatever is posted. */
    if (url.pathname === "/api/questionnaire/trigger/remove" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) { await secLog(env, "access-denied", me.email, "questionnaire trigger remove (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 }); }
      if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "The trigger list is everyone's, so only admin can take one off." }, { status: 403 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      try {
        const gone = await deleteTrigger(env, (b && b.trigger) || "", { email: me.email, name: me.name }, triggerOf);
        await secLog(env, "questionnaire-trigger-removed", me.email, gone.label + " (" + gone.subsRemoved + " sub prompts)", true);
        return Response.json({ ok: true, removed: gone, triggers: await triggersFor(env, triggerList()) });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 400 }); }
    }
    /* how many sub prompts sit under a trigger — asked before the remove is offered, so the
       confirmation can name exactly what is about to go rather than saying "are you sure" */
    if (url.pathname === "/api/questionnaire/trigger/subcount" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 });
      const k = String(url.searchParams.get("trigger") || "").slice(0, 120);
      return Response.json({ ok: true, trigger: k, subs: await subCountFor(env, k) });
    }

    /* ══ ALL THREE AT ONCE — v26.8 ════════════════════════════════════════════════════════
       "Generate the questionnaire means need to generate at a time at three." One press, one
       reading of the discharge summary, the insured / doctor / billing papers together. */
    if (url.pathname.startsWith("/api/questionnaire/all/")) {
      const claim = decodeURIComponent(url.pathname.substring("/api/questionnaire/all/".length));
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) { await secLog(env, "access-denied", me.email, "questionnaire (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 }); }
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      /* three papers is three asks — a third of the hourly allowance each press */
      if (!allowRate("heavy:" + me.email, 40, 60 * 60 * 1000)) { await secLog(env, "rate-limited", me.email, "questionnaire all"); return Response.json({ ok: false, error: "Too many report/questionnaire requests this hour — please wait a while." }, { status: 429 }); }
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me.email, "questionnaire " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      const counts = {};
      for (const k of Q_ALL_SETS) { const v = url.searchParams.get(k); if (v) counts[k] = v; }
      const only = (url.searchParams.get("only") || "").split(",").map(s2 => s2.trim().toLowerCase()).filter(Boolean);
      try {
        const qm = (await aiEngine(env)) === "connector" ? { by: { email: me.email, name: me.name } } : null;
        const r = await generateQuestionnaireAll(env, claim, {
          counts, only, ailment: (url.searchParams.get("ailment") || "").slice(0, 200),
          trigger: (url.searchParams.get("trigger") || "").slice(0, 60), sub: (url.searchParams.get("sub") || "").slice(0, 160),
          /* v31.1 — "one more trigger also need to be mentioned ... minimum three". They ride
             the query string as trigger|sub, comma separated, and are read here rather than
             trusted: an unknown trigger is dropped, never guessed at. */
          more: qMorePairs(url.searchParams.get("more")),
          /* v31.7 — the papers and pages he ticked, as "folder|name|1-3,7" joined by ";;".
             Nothing is downloaded that is not named here. */
          picks: parsePicks(url.searchParams.get("picks")),
          queue: qm
        });
        return Response.json(Object.assign({ ok: true, claim, engine: await aiEngine(env) }, r));
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 500 }); }
    }

    /* ══ THE FINISHED QUESTIONNAIRE AS A FILE — download, or straight into Claim Documents ══
       Sujit, 14-Sep-2026: "we will be getting Microsoft Word form and PDF form, and one more
       thing need to be upload — the Claim Documents need to upload there."

       The bytes are built HERE, not in the browser, for one reason: SKD's upload door checks
       that a file really begins %PDF- before it will take it. A print-to-PDF cannot be
       handed to that door at all, and a second PDF made a second way would drift from the
       one he downloaded. One builder, one file: the download and the upload are the same
       bytes, and the question list that made them came off his own screen after his edits. */
    if (url.pathname === "/api/questionnaire/file" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "questionnaire")) { await secLog(env, "access-denied", me.email, "questionnaire file (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Questionnaire page." }, { status: 403 }); }
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const wantUp = !!(b && (b.upload === true || b.upload === 1 || b.upload === "1"));
      const cleanQs = (list) => (Array.isArray(list) ? list : [])
        .map(q => String(q == null ? "" : q).replace(/\s+/g, " ").trim()).filter(Boolean).slice(0, Q_MAX_QUESTIONS)
        .map(q => q.slice(0, 600));
      /* v26.8 — "we will select that to send to claim documents": the tick list arrives as
         `sets`, and every ticked paper goes into the case folder in ONE call to SKD, the way a
         person attaching three files on the case screen would. A single {subject, questions}
         is still accepted — that is what the Download PDF button sends. */
      const many = Array.isArray(b && b.sets) ? b.sets.map(x => ({ set: qSet(x && x.subject), qs: cleanQs(x && x.questions) })).filter(x => x.qs.length) : null;
      const set = qSet(b && b.subject);
      const qs = many ? [] : cleanQs(b && b.questions);
      if (!many && !qs.length) return Response.json({ ok: false, error: "There are no questions to put on the paper yet." }, { status: 400 });
      if (many && !many.length) return Response.json({ ok: false, error: "None of the papers you ticked has any questions on it yet." }, { status: 400 });
      if (many && !wantUp) return Response.json({ ok: false, error: "A download is one paper at a time — ask for each set on its own." }, { status: 400 });
      const mIn = (b && b.meta) || {};
      const claim = String((b && b.claim) || mIn.claim || "").trim();
      const meta = { insurer: String(mIn.insurer || "").slice(0, 160), insured: String(mIn.insured || "").slice(0, 160), claim: String(mIn.claim || claim).slice(0, 80), hospital: String(mIn.hospital || "").slice(0, 160) };
      let claimNo = claim;
      if (claim) {
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const sc = await claimScopeCheck(env, me, claim);
        if (!sc.allowed && !sc.notFound) { await secLog(env, "scope-blocked", me.email, "questionnaire file " + claim); return Response.json({ ok: false, error: "This case is outside your scope." }, { status: 403 }); }
        /* SKD writes 1234/…/TP as 1234-…-TP — send the case folder the spelling it owns */
        try { const dd = await getCases(env); const ff = findCaseByClaim(dd.cases, claim); if (ff) { claimNo = ff.claimNo; meta.claim = meta.claim || ff.claimNo; } } catch (e) { }
        if (/\//.test(claimNo)) claimNo = claimNo.replace(/\//g, "-");
      }
      const papers = many || [{ set, qs }];
      const built = [];
      for (const p of papers) {
        let bytes;
        try { bytes = questionnairePdf(meta, p.set, p.qs); }
        catch (e) { return Response.json({ ok: false, error: "The " + (p.set.card || p.set.label) + " PDF could not be typeset: " + String((e && e.message) || e).slice(0, 200) }, { status: 500 }); }
        built.push({ set: p.set, qs: p.qs, bytes, name: questionnaireFileName(p.set.key, meta.claim || claimNo, "pdf") });
      }

      if (!wantUp) {
        return new Response(built[0].bytes, { status: 200, headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": 'attachment; filename="' + built[0].name + '"',
          "Cache-Control": "no-store"
        } });
      }
      /* ── into the case's Claim Documents folder at SKD ── */
      if (!claimNo) return Response.json({ ok: false, error: "Open this page from a case (or type the claim number) before uploading — the portal must know which case folder to put it in." }, { status: 400 });
      if (!allowRate("upload:" + me.email, 30, 60 * 60 * 1000)) { await secLog(env, "rate-limited", me.email, "questionnaire upload"); return Response.json({ ok: false, error: "Too many uploads this hour — please wait a while." }, { status: 429 }); }
      const up = await skdUploadDocs(env, claimNo, built.map(x => ({ file: new Blob([x.bytes], { type: "application/pdf" }), name: x.name })));
      const names = built.map(x => x.name);
      await secLog(env, up.ok ? "questionnaire-uploaded" : "questionnaire-upload-failed", me.email, claimNo + " · " + names.join(", ") + (up.ok ? "" : " · " + String(up.error || "").slice(0, 120)), false);
      if (!up.ok) {
        /* 14-Sep-2026. A 403 here is never about THIS case: SKD refuses every document the
           portal offers, on every case — the Drive register had 1,674 of them. So the answer
           says where the fix is instead of leaving him staring at a status code. */
        const said = readAnswer(up.status || 0, up.body || "");
        return Response.json({ ok: false, names, error: "SKD refused it: " + (up.error || "no reason given"),
          said: said.plain,
          hint: (up.status === 403) ? "This is not about this case — SKD refuses every document the portal sends. Upload Docs → Upload door → Find the door." : ""
        }, { status: 502 });
      }
      return Response.json({ ok: true, name: names[0], names, claim: claimNo, papers: built.length,
        questions: built.reduce((n, x) => n + x.qs.length, 0),
        sets: built.map(x => ({ key: x.set.key, card: x.set.card || x.set.label, name: x.name, questions: x.qs.length })),
        msg: (names.length === 1 ? names[0] + " is" : names.length + " papers (" + built.map(x => x.set.card || x.set.label).join(", ") + ") are") + " now in the Claim Documents folder of " + claimNo + "." });
    }

    if (url.pathname.startsWith("/api/questionnaire/")) {
      const claim = decodeURIComponent(url.pathname.substring("/api/questionnaire/".length));
      const subject = (url.searchParams.get("subject") || "insured").toLowerCase();
      const ailment = (url.searchParams.get("ailment") || "").slice(0, 200);
      const count = url.searchParams.get("count");
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      if (!allowRate("heavy:" + (me ? me.email : "?"), 40, 60 * 60 * 1000)) { await secLog(env, "rate-limited", me ? me.email : "?", "questionnaire"); return Response.json({ ok: false, error: "Too many report/questionnaire requests this hour — please wait a while." }, { status: 429 }); }
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me ? me.email : "?", "questionnaire " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      try {
        /* v24.0 — Connector mode: queued for Claude on his plan; the page polls /api/ai/result */
        const qm = (await aiEngine(env)) === "connector" ? { by: { email: me.email, name: me.name } } : null;
        /* v31.1 — the single-paper door takes the extra triggers too, so a paper regenerated
           on its own covers the same ground as the three written together */
        const extra = { trigger: (url.searchParams.get("trigger") || "").slice(0, 60), sub: (url.searchParams.get("sub") || "").slice(0, 160), more: qMorePairs(url.searchParams.get("more")), picks: parsePicks(url.searchParams.get("picks")) };
        const r = await generateQuestionnaire(env, claim, subject, ailment, Object.assign({ count }, extra, qm ? { queue: qm } : {}));
        if (r.queued) return Response.json({ ok: true, queued: true, jobId: r.jobId, claim: claim, subject: subject, used: r.used, docs: r.docs, max: r.max, count: r.count, engine: "connector" });
        return Response.json({ ok: true, claim: claim, subject: subject, questions: r.questions, count: r.count, asked: r.asked, used: r.used, docs: r.docs, engine: await aiEngine(env) });
      }
      catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* FIELD-DOC FILE PROXY: streams one uploaded file from SKD using the portal's own token,
       so members never need a separate skdhealth.net login. Role-fenced + rate-limited. */
    /* ══════════ WHY SOME DOCUMENTS WOULD NOT OPEN — v27.6, 16-Sep-2026 ═══════════════════
       Sujit, 4:55 am: "Once it is Yes I will click that, the documents need to open. Few
       documents is not getting open. Check this and fix this now."

       Two causes, both real, both found in the code rather than guessed at:

       1 · THE ID. Every place that builds this link read the file id as /cases/download/(\d+)
           — DIGITS ONLY — and this door then demanded ^\d{1,12}$ on top. A file whose id
           carries a letter, a dot or a dash, or simply runs past twelve digits, produced an
           EMPTY href: the link was on the screen, it looked exactly like the others, and
           clicking it did nothing at all. Both ends now take [\w.-], which is every shape a
           path segment can safely hold.

       2 · THE TYPE. SKD's download route often answers application/octet-stream, or with no
           Content-Type at all. Sent on with "inline", a browser cannot know it is a PDF, so
           it opens a blank tab or silently downloads — which reads, correctly, as "it did
           not open". The name is the one thing we always have, so the type is taken from the
           extension whenever SKD's own answer is missing or generic. SKD's type is kept
           whenever it actually says something. */
    if (url.pathname === "/api/case-file") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      const claim = url.searchParams.get("claim") || "";
      const fid = url.searchParams.get("id") || "";
      const fname = (url.searchParams.get("name") || "document").replace(/[^\w.\- ()]/g, "_").slice(0, 120);
      if (!validClaim(claim) || !/^[\w.-]{1,40}$/.test(fid)) return fileProblem("That document link is not readable.", "The file id in the link (" + String(fid).slice(0, 40) + ") is not one this portal can ask SKD for.", claim);
      if (!allowRate("file:" + me.email, 300, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many file opens this hour — please wait a little." }, { status: 429 });
      let sc = await claimScopeCheck(env, me, claim);
      /* v34.5 — a Yes on the register opens its paper for everyone who can see the register:
         the fence is lifted for an OPEN MOTOR TP case only (the register's own book), and never
         for an insurer login. A Health case, or a closed one, is fenced exactly as before. */
      if (!sc.allowed && !sc.notFound && docRegWide(me)) {
        try { const d = await getCases(env); const f = findCaseByClaim(d.cases, claim); if (f && typeOfSub(f.subProduct) === "TP") sc = { allowed: true, notFound: false, claimNo: f.claimNo, viaDocReg: true }; } catch (e) { }
      }
      if (!sc.allowed) { await secLog(env, "scope-blocked", me.email, "case-file " + claim, false); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      try {
        const got = await fetchSkdFile(env, fid);   // tries Bearer / Basic / token-in-URL / open, remembers the winner
        if (!got.ok) return fileProblem("SKD would not give us this document.", "SKD answered: " + got.detail, claim, fname);
        const r = got.r;
        const h = new Headers();
        h.set("Content-Type", fileTypeFor(fname, r.headers.get("Content-Type")));
        h.set("Content-Disposition", 'inline; filename="' + fname + '"');
        h.set("Cache-Control", "private, max-age=300");
        return new Response(r.body, { status: 200, headers: h });
      } catch (e) { return fileProblem("This document could not be fetched.", String(e && e.message ? e.message : e), claim, fname); }
    }

    // Raw case details (documents + history) — role-fenced
    if (url.pathname.startsWith("/api/case-full/")) {
      const claim = decodeURIComponent(url.pathname.substring("/api/case-full/".length));
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      /* NOT FOR THE CLIENT'S LOGIN. This one does not read our own tidy case record — it
         hands back SKD's whole working file: folder names, field remarks, who wrote them.
         Stripping five fields cannot make that safe, because the names are inside free text
         a person typed. So the insurer is refused it outright and told plainly, rather than
         given a filtered version somebody might later trust. */
      if (isClientRole(me)) return Response.json({ ok: false, error: "The working file of a case is internal. Your login shows the case, its status and its ageing." }, { status: 403 });
      const sc = await claimScopeCheck(env, me, claim);
      if (!sc.allowed) { await secLog(env, "scope-blocked", me ? me.email : "?", "case-full " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
      let cfClaim = sc.claimNo || claim;   // canonical SKD claim number (5573/…/TP -> 5573-…-TP)
      if (!sc.claimNo && /[\/]/.test(claim)) { try { const dd = await getCases(env); const ff = findCaseByClaim(dd.cases, claim); cfClaim = ff ? ff.claimNo : claim.replace(/\//g, "-"); } catch (e) { cfClaim = claim.replace(/\//g, "-"); } }
      try { const r = await skdGetCase(env, cfClaim); return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json" } }); }
      catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }); }
    }

    if (url.pathname.startsWith("/api/upload-docs/") && request.method === "POST") {
      const claim = decodeURIComponent(url.pathname.substring("/api/upload-docs/".length));
      if (!canAccess(me, "upload")) { await secLog(env, "access-denied", me ? me.email : "?", "upload-docs (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to upload documents." }, { status: 403 }); }
      try {
        const form = await request.formData();
        const files = form.getAll("claimDocs").filter(f => f && typeof f === "object" && f.name);
        if (!files.length) return Response.json({ ok: false, error: "No files received (the field name must be claimDocs)." }, { status: 400 });
        if (files.length > 10) return Response.json({ ok: false, error: "Maximum 10 files are allowed." }, { status: 400 });
        for (const f of files) { if (!/\.pdf$/i.test(f.name) && f.type !== "application/pdf") return Response.json({ ok: false, error: "Only PDF files are accepted — rejected: " + f.name }, { status: 400 }); }
        // SECURITY: rate limit + size caps + real-PDF signature check + role fence
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        if (!allowRate("upload:" + (me ? me.email : "?"), 30, 60 * 60 * 1000)) { await secLog(env, "rate-limited", me ? me.email : "?", "upload-docs"); return Response.json({ ok: false, error: "Too many uploads this hour — please wait a while." }, { status: 429 }); }
        let totalUp = 0;
        for (const f of files) {
          const sz = (typeof f.size === "number") ? f.size : 0;
          totalUp += sz;
          if (sz > 15 * 1024 * 1024) return Response.json({ ok: false, error: "File too large (max 15 MB): " + f.name }, { status: 400 });
          const head = new Uint8Array(await f.slice(0, 5).arrayBuffer());
          let tag = ""; for (let i = 0; i < head.length; i++) tag += String.fromCharCode(head[i]);
          if (tag !== "%PDF-") { await secLog(env, "upload-blocked", me ? me.email : "?", "fake PDF refused: " + String(f.name).slice(0, 60), true); return Response.json({ ok: false, error: "Not a genuine PDF (file signature check failed): " + f.name }, { status: 400 }); }
        }
        if (totalUp > 60 * 1024 * 1024) return Response.json({ ok: false, error: "Batch too large (max 60 MB total)." }, { status: 400 });
        if (me && (isScopedRole(me.role))) {
          const sc = await claimScopeCheck(env, me, claim);
          if (!sc.allowed && !sc.notFound) { await secLog(env, "scope-blocked", me.email, "upload " + claim); return Response.json({ ok: false, error: "This case is outside your scope." }, { status: 403 }); }
        }
        const cfgPath = (env.SKD_UPLOAD_PATH || SKD_UPLOAD_PATH_DEFAULT || "").trim();
        if (!cfgPath) return Response.json({ ok: false, error: "Upload endpoint not configured yet. Set a Worker variable SKD_UPLOAD_PATH (or SKD_UPLOAD_PATH_DEFAULT in worker.js) — a full URL or a path, using {claim} or {claim-number} where the claim number goes." }, { status: 501 });
        let claimOut = claim;   // send SKD its own writing style: 5573/…/TP becomes 5573-…-TP
        if (/[\/]/.test(claim)) { try { const dd = await getCases(env); const ff = findCaseByClaim(dd.cases, claim); claimOut = ff ? ff.claimNo : claim.replace(/\//g, "-"); } catch (e) { claimOut = claim.replace(/\//g, "-"); } }
        /* ONE code path for every upload (v26.9). This route used to build its own multipart
           body; now it hands the files to skdUploadDocs like everything else, so the shape the
           door finder proved is the shape this button sends — a found door fixes the Send
           button, the Drive push and the questionnaire push in the same moment. */
        const up = await skdUploadDocs(env, claimOut, files.map(f => ({ file: f, name: f.name })));
        if (!up.ok) {
          const plain = readAnswer(up.status || 0, up.body || "");
          return Response.json({ ok: false, error: up.error || plain.plain, said: plain.plain,
            hint: (up.status === 403) ? "SKD refuses every document this login sends, on every case — 1,674 tries so far. Settings → Upload door → Find the door." : "" },
            { status: (up.status && up.status >= 400 && up.status < 600) ? up.status : 502 });
        }
        return Response.json({ ok: true, msg: up.msg, count: files.length });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══════════════ THE UPLOAD DOOR ══════════════════════════════════════════════════════
       14-Sep-2026. "Send 3 to Claim Documents" came back 403 Access Denied, and the register
       showed it was never one case: 1,674 attempts, 0 landed, the same refusal every time.
       Proved live the same hour that the address and the login are both fine — a GET at the
       upload address answers 405 (the route is there), the case reads 200. So the refusal is
       an authorisation rule on their POST handler, and his instruction was not to sit and
       wait for it to be lifted: "whatever he gave the access in that we can do... please try
       to send this documents."

       So the portal goes and knocks. It tries every shape the handler might be expecting —
       four field names, with and without the folder name and the claim number — and, if a
       second SKD login is set, tries all of them again as that login. It stops at the first
       one SKD accepts, writes that shape down, and every upload after it is built that way.
       One page is sent per try, titled so nobody has to wonder what it is.

       Admin only, and capped: this posts to their production server.
       ═══════════════════════════════════════════════════════════════════════════════════ */
    if (url.pathname === "/api/upload-door" && request.method === "GET") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      const t = skdUploadTarget(env, "{claim}");
      let last = []; try { last = JSON.parse(await stGet(env, DOOR_KEY + ":last") || "[]"); } catch (e) { last = []; }
      return Response.json({
        ok: true,
        found: await doorGet(env),
        altSet: hasAltIdentity(env),
        addressSet: !t.error,
        address: t.url || "",
        fields: FIELD_NAMES,
        tries: doorPlan("{claim}", hasAltIdentity(env)).map(doorLabel),
        last
      });
    }

    if (url.pathname === "/api/upload-door/find" && request.method === "POST") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      if (!allowRate("door:" + me.email, 6, 60 * 60 * 1000)) return Response.json({ ok: false, error: "That has been tried a few times this hour already — give SKD a rest and try again later." }, { status: 429 });
      let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
      const claim = String((b && b.claim) || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Give the claim number of a live case to test against." }, { status: 400 });
      const t = skdUploadTarget(env, claim);
      if (t.error) return Response.json({ ok: false, error: t.error }, { status: 501 });

      /* the shape the portal sends TODAY goes first, so if SKD has quietly been fixed the
         answer is the very first line and nothing else is sent at all */
      const plan = doorPlan(t.claimOut, hasAltIdentity(env));
      const bytes = probePdf(t.claimOut, istStamp(Date.now()));
      const rows = [];
      let won = null;
      for (const row of plan) {
        const file = new Blob([bytes], { type: "application/pdf" });
        let res;
        try { res = await skdUploadDocs(env, t.claimOut, [{ file, name: probeName() }], { door: row }); }
        catch (e) { res = { ok: false, status: 0, body: String(e && e.message ? e.message : e) }; }
        const said = readAnswer(res.status || 0, res.body || res.error || "");
        rows.push({ tried: doorLabel(row), field: row.field, who: row.who, status: res.status || 0, ok: !!res.ok, said: said.plain, body: String(res.body || res.error || "").slice(0, 200) });
        if (res.ok) { won = row; break; }
      }

      if (won) {
        await doorPut(env, won);
        await secLog(env, "admin-action", me.email, "upload door found: " + doorLabel(won), true);
      }
      await stSoft(env, DOOR_KEY + ":last", JSON.stringify({ ts: Date.now(), claim: t.claimOut, by: me.name || me.email, won: won || null, rows }));

      return Response.json({
        ok: true,
        found: won,
        tried: rows.length,
        rows,
        msg: won
          ? ("Found it — " + doorLabel(won) + ". A check page went onto case " + t.claimOut + " and can be ignored. Every upload from now on is sent this way; the documents held back in the Drive folder go up on the next night's run."
            + (won.who === "alt" ? "" : " Nothing about the sign-in had to change."))
          : (hasAltIdentity(env)
            ? "No way in. SKD refused every shape, with both sign-ins — so this is a permission on their side and only they can lift it. Nothing here is wrong: the address answers, the login is accepted, the case reads."
            : "No way in. SKD refused every shape the portal can send with its own sign-in. Nothing here is wrong — the address answers and the login is accepted; that login is simply not allowed to attach anything. The next thing to try is the login your people attach documents with on the corinsoft screen: set SKD_UPLOAD_USER and SKD_UPLOAD_PASS on the Worker and press this again.")
      });
    }

    /* ══════════════ THE DOCUMENT REGISTER ════════════════════════════════════════════════
       14-Sep-2026, straight after the upload door came back refused ten times out of ten:

         "Create one sheet which all documents has been uploaded... if RTI has been uploaded
          means in RTI column mentioned Yes, in 134 need to mention as Yes, and for hospital,
          DL extract, RC extract... whichever open cases available, only for Motor TP, that
          all need to be there in this sheet. Need to mark AUTOMATICALLY."

       Nobody types a Yes here. Every mark is read off the case's own file at SKD, and the
       file name that proves it travels with the mark so a Yes can be opened and checked.
       The third answer — "In Drive, not uploaded" — is the one a plain Yes/No sheet would
       get wrong: those papers ARE collected, and it is SKD's 403 keeping them off the case.
       ═══════════════════════════════════════════════════════════════════════════════════ */
    if (url.pathname === "/api/docreg" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      /* ══ THE REGISTER IS GATED ON ITS OWN TICK NOW — v29.0, 16-Sep-2026 ═════════════════
         MAHALAKSHMI ARUL, 9:44 am: Document Register on her sidebar, and pressing it answered
         "You do not have access to the document register."

         A HALF-FINISHED MIGRATION, and mine. v28.0 gave the Document Register its own tick, so
         she could be granted it WITHOUT Upload Docs — and she was. The sidebar read the new
         tick and drew the item; these four doors were still asking the old question, "may she
         upload?", and she may not. A menu item that opens onto a refusal is the exact fault
         the Settings note in admin.html warns about, and I wrote a fresh one into the portal
         this morning while fixing something else.

         They ask for "docreg" now. Nobody loses the page: canAccess() still answers a list
         written before the tick existed with Upload Docs, so every old login reads exactly as
         it did — and a new one can be given the register alone, which was the whole point. */
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      const liveNow = await docRegLive(env);
      let rows = await docRegRows(env, liveNow.claims, liveNow.pairs);
      /* v34.5 — the whole book for whoever holds the tick (docRegWide); an insurer login is
         still read from the live book it is allowed to see, never from the whole store */
      if (isScopedRole(me.role) && !docRegWide(me)) {
        try {
          const d = await getCases(env);
          const mine = {};
          for (const c of scopeCases(d.cases || [], me, await getFoStateMap(env))) if (c && c.claimNo) mine[c.claimNo] = 1;
          rows = rows.filter(r => mine[r.claim]);
        } catch (e) { rows = []; }
      }
      const stats = { cases: rows.length, read: 0, waiting: 0, complete: 0 };
      const per = {};
      for (const c of DOC_COLS) per[c.key] = { yes: 0, drive: 0 };
      for (const r of rows) {
        if (r.readAt) stats.read++;
        let w = 0;
        for (const c of DOC_COLS) {
          if (r.marks[c.key] === "yes") per[c.key].yes++;
          else if (r.marks[c.key] === "drive") { per[c.key].drive++; w++; }
        }
        if (w) stats.waiting++;
        if (r.got === DOC_COLS.length) stats.complete++;
      }
      let last = null; try { last = JSON.parse(await stGet(env, "docreg:last") || "null"); } catch (e) { last = null; }
      /* openNow is what Analytics calls TP OPEN CASES; cases is how many of them have been
         read so far. The two are different numbers and the screen says so, rather than
         letting a half-filled register look like a shrinking book. */
      /* v30.5 — the age of the case, on its own row: "add TAT, from lower to higher" */
      { const tat = liveNow.tat || {}; for (const r of rows) { const dd = tat[r.claim]; r.tatD = (dd == null ? null : dd); } }
      /* v30.4 — what he has already ticked and where it got to, so the screen can say
         "queued", "sent" or "already on the case" on the row itself rather than in a log */
      let send = { rows: {}, count: { queued: 0, sent: 0, already: 0, error: 0 }, total: 0 };
      try { send = await sendState(env); } catch (e) {}
      /* v33.0 — and whether the thing that collects that list is alive. The register is where
         he presses Send, so it is where the silence has to be said out loud. */
      let script = null;
      try { script = await ddocHealth(env, (await sendQueue(env, 400)).length); } catch (e) { script = null; }
      /* v33.6 — the collector's own truth: the portal moves the papers now, and the card
         says when it last ran, what it did, and whether the Drive web app answered */
      let collector = null;
      try { collector = await collectorState(env); } catch (e) { collector = null; }
      /* v34.4 — the three RTI/134 tiles, from the same rows the table draws */
      const chase = chaseStats(rows);
      chase.notPutRule = Object.keys(NOT_PUT).map(k => ({ col: k, who: NOT_PUT[k].map(x => x.who) }));
      return Response.json({ ok: true, cols: DOC_COLS.map(c => ({ key: c.key, label: c.label, hint: c.hint })), rows, stats, per, last,
        openNow: liveNow.claims ? liveNow.claims.length : null, liveBook: !!liveNow.live, bookAt: liveNow.at || 0,
        send, sendCols: SEND_COLS, sendDefault: SEND_DEFAULT, sendNever: SEND_NEVER, script, collector, chase });
    }

    /* ══════════ HIS SELECTION GOES ON THE WORK LIST — v30.4, 18-Sep-2026 ══════════════════
       Sujit, 6:40 am: "I need one option called selection ... one button ... I will select all,
       or I will select whichever need to upload, that need to go there in this dashboard
       itself." And, of the nightly run that had just refused 363 papers before breakfast:
       "I don't want that to work, because we are going to manual."

       WHAT THIS DOOR DOES, AND WHAT IT DOES NOT. It does not talk to SKD and it does not touch
       Google Drive — the portal holds neither the bytes nor a Drive login. It writes down what
       he has ticked. /api/drive-docs/wanted then hands the Apps Script exactly this list and
       nothing else, the script fetches those papers from the folder and pushes them, and the
       push door writes each verdict back onto the row. So the night job stops choosing: an
       empty list means it has nothing to do, which is the off switch he asked for.

       THE CHARGE SHEET IS REFUSED HERE TOO, not only left off the screen — twice in one
       morning he said it must never go up, and a rule he can lean on is one the door keeps
       even when a request is written by hand. Papers already on the case are not queued: that
       is what earned 3,089 "a file entry already exists" refusals, and it stops today. */
    if (url.pathname === "/api/docreg/send" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      if (!canAccess(me, "upload") && me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "Sending a paper onto a case needs the Upload Docs permission." }, { status: 403 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const want = Array.isArray(b && b.claims) ? b.claims.map(c => String(c || "").trim()).filter(Boolean).slice(0, 1000) : [];
      if (!want.length) return Response.json({ ok: false, error: "Tick the cases you want sent." }, { status: 400 });
      /* which document types this press is for — his ticks, never a column the rule forbids */
      let cols = Array.isArray(b && b.cols) ? b.cols.map(c => String(c || "").trim()).filter(sendable) : SEND_DEFAULT.slice();
      if (!cols.length) cols = SEND_DEFAULT.slice();
      const liveSend = await docRegLive(env);
      let rows = await docRegRows(env, liveSend.claims, liveSend.pairs);
      if (isScopedRole(me.role) && !docRegWide(me)) {   /* v34.5 — the whole book for the tick */
        try {
          const d = await getCases(env);
          const mine = {};
          for (const c of scopeCases(d.cases || [], me, await getFoStateMap(env))) if (c && c.claimNo) mine[c.claimNo] = 1;
          rows = rows.filter(r => mine[r.claim]);
        } catch (e) { rows = []; }
      }
      const byClaim = {}; for (const r of rows) byClaim[r.claim] = r;
      const drive = await driveIndexFor(env, want);
      /* v30.4b — what has ALREADY gone, paper by paper. "[If] RTI sent, after two days [I
         send the] 134 — only RTI need to be blocked, rest documents need to go." */
      const before = await sendState(env, want);
      const out = { queued: 0, cases: 0, already: 0, blocked: 0, sentBefore: 0, nothing: [], per: {}, notPut: 0, notPutWho: {} };
      for (const k of SEND_COLS) out.per[k] = 0;
      for (const claim of want) {
        const r = byClaim[claim];
        if (!r) continue;                                   // not his case, or not in the live book
        /* v34.4 — "we will not put 134 for Bajaj and the Chola": a paper the client does not take
           is left out of the press, counted, and named in the note */
        const colsFor = cols.filter(k => needed(k, r.client));
        for (const k of cols) if (!needed(k, r.client) && (r.marks || {})[k] === "drive") { out.notPut++; out.notPutWho[notPutFor(k, r.client)] = 1; }
        const plan = sendPlan(r.marks || {}, drive[claim] || {}, colsFor, before.rows, claim);
        out.already += plan.already.length;
        out.blocked += plan.blocked.length;
        out.sentBefore += plan.gone.length;
        if (!plan.send.length) { out.nothing.push(claim); continue; }
        const n = await queueSend(env, claim, plan.send, { email: me.email, name: me.name });
        if (n) { out.queued += n; out.cases++; for (const it of plan.send) out.per[it.col] = (out.per[it.col] || 0) + 1; }
      }
      await secLog(env, "docreg-send", me.email, out.queued + " paper(s) on " + out.cases + " case(s) put on the send list", true);
      /* ══ v33.6 · THE PRESS COLLECTS ═════════════════════════════════════════════════════
         Sujit, 24-Sep: "the papers are in our Drive, the register knows it, I pressed Send,
         and the send depends on a time trigger in Google's account that has gone quiet. I
         will not babysit Apps Script triggers. Fix the design, not the trigger."
         So the very press that queues the paper goes and gets it: the first batch is pulled
         from Drive through the all-in-one web app and uploaded through the door BEFORE this
         answer is written, so a two-paper Send comes back with "sent" on the row inside the
         minute. Anything larger continues on the half-hour cron, or on Collect now. The
         v33.0 heartbeat of the script's own timer is no longer what this answer is told by. */
      let run = null;
      if (out.queued) { try { run = await docSendNow(env, { max: 6, budgetMs: 25000, taker: me.email || "send" }); } catch (e) { run = null; } }
      const st = await sendState(env);
      const health = await ddocHealth(env, (await sendQueue(env, 400)).length);
      let collector = null; try { collector = await collectorState(env); } catch (e) { collector = null; }
      const words = pressWords(out.queued, run, collector && collector.counts);
      return Response.json({ ok: true, queued: out.queued, cases: out.cases, alreadyOnCase: out.already, chargeSheetsLeftOut: out.blocked,
        alreadySent: out.sentBefore, nothingToSend: out.nothing, per: out.per, send: st, script: health, collector, run, words,
        notPut: out.notPut, notPutWho: Object.keys(out.notPutWho),
        note: out.queued
          ? (out.queued + " paper" + (out.queued === 1 ? "" : "s") + " added. " + (words.text || "")
             + (out.sentBefore ? (" " + out.sentBefore + " paper" + (out.sentBefore === 1 ? " was" : "s were") + " sent before and were left alone.") : ""))
          : (out.sentBefore
             ? ("Nothing new to send — " + out.sentBefore + " paper" + (out.sentBefore === 1 ? " has" : "s have") + " already gone up from " + (out.sentBefore === 1 ? "that case" : "those cases") + ", and a paper is never sent twice.")
             : (out.notPut
                ? ("Nothing to send — the only paper waiting is a 134, and 134 is not put for " + Object.keys(out.notPutWho).join(" and ") + ".")
                : "Nothing to send — every paper on those cases is either already on the case, not in the Drive folder, or the charge sheet.")) });
    }
    /* v33.6 — collect the list now: another time-boxed batch, for a list bigger than one
       press carries. Same permission as the press itself. */
    if (url.pathname === "/api/docreg/send/run" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      if (!canAccess(me, "upload") && me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "Sending a paper onto a case needs the Upload Docs permission." }, { status: 403 });
      if (!allowRate("docsend:" + me.email, 30, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Collected many times this hour already — the half-hour run carries on by itself." }, { status: 429 });
      let run = null;
      try { run = await docSendNow(env, { max: batchFor(Date.now()), budgetMs: 25000, taker: me.email || "run", force: true }); } catch (e) { run = { ok: false, why: String((e && e.message) || e) }; }
      let collector = null; try { collector = await collectorState(env); } catch (e) { collector = null; }
      return Response.json({ ok: true, run, collector, send: await sendState(env) });
    }
    /* v33.6 — is the Drive web app there, and does it know the new action? (admin / boss) */
    if (url.pathname === "/api/docreg/send/ping" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (me.role !== "admin" && me.role !== "boss") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      if (!allowRate("docping:" + me.email, 20, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Asked many times this hour already." }, { status: 429 });
      const p = await pingWebApp(env);
      try {
        await ensureSendSchema(env);
        await env.DB.prepare("INSERT INTO doc_collect (id, script_ok, script_at, script_said) VALUES (1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET script_ok=excluded.script_ok, script_at=excluded.script_at, script_said=excluded.script_said")
          .bind(p.ok ? 1 : 0, Date.now(), String(p.said || "").slice(0, 300)).run();
      } catch (e) {}
      return Response.json({ ok: true, webApp: p, collector: await collectorState(env) });
    }
    /* what is on the list right now, and how the last press went */
    if (url.pathname === "/api/docreg/send" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      const st = await sendState(env);
      const q = await sendQueue(env, 400);
      let collector = null; try { collector = await collectorState(env); } catch (e) { collector = null; }
      return Response.json({ ok: true, send: st, waiting: q.length, cols: SEND_COLS, sendDefault: SEND_DEFAULT, never: SEND_NEVER,
        script: await ddocHealth(env, q.length),   /* v33.0 — the script's own timer, kept as the fallback's pulse */
        collector });                                /* v33.6 — the portal's own collector */
    }
    /* he changed his mind before the script got there */
    if (url.pathname === "/api/docreg/send/cancel" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
      const claims = Array.isArray(b && b.claims) ? b.claims.map(c => String(c || "").trim()).filter(Boolean).slice(0, 1000) : null;
      const gone = await unqueue(env, claims);
      return Response.json({ ok: true, removed: gone, send: await sendState(env) });
    }

    /* the same rows as the screen, as a real .xlsx — his own column order, his own words */
    if (url.pathname === "/api/docreg.xlsx" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      const liveDl = await docRegLive(env);
      let rows = await docRegRows(env, liveDl.claims, liveDl.pairs);
      if (isScopedRole(me.role) && !docRegWide(me)) {   /* v34.5 — the whole book for the tick */
        try {
          const d = await getCases(env);
          const mine = {};
          for (const c of scopeCases(d.cases || [], me, await getFoStateMap(env))) if (c && c.claimNo) mine[c.claimNo] = 1;
          rows = rows.filter(r => mine[r.claim]);
        } catch (e) { rows = []; }
      }
      /* ══ THE DOWNLOAD IS WHAT HE IS LOOKING AT — v27.6 ═════════════════════════════════
         Sujit: "Once I'll select the Excel, in that all this need to become... and the
         manager, their name also need to be reflected. I am asking only the open cases."
         The search box and the pill travel with the button, and the filtering is done by the
         SAME docRegPick() the screen uses, so the file and the screen cannot disagree. */
      rows = docRegPick(rows, url.searchParams.get("q") || "", url.searchParams.get("only") || "", DOC_COLS.length);
      /* v30.5 — the age travels with the download too, and the file is ordered by it the way
         the screen is, so the sheet he sends on reads in the same order he was looking at */
      { const tat = liveDl.tat || {}; for (const r of rows) r.tatD = (tat[r.claim] == null ? null : tat[r.claim]); }
      const ord = String(url.searchParams.get("tat") || "").toLowerCase();
      if (ord === "asc" || ord === "desc") {
        const dir = ord === "asc" ? 1 : -1;
        rows = rows.slice().sort((a, b) => {
          const x = (a.tatD == null ? (dir === 1 ? 1e9 : -1) : a.tatD), y = (b.tatD == null ? (dir === 1 ? 1e9 : -1) : b.tatD);
          return (x - y) * dir || String(a.claim).localeCompare(String(b.claim));
        });
      }
      /* v34.4 — "Pending" and "To upload" travel with the sheet, and a 134 the client does not
         take reads "Not put - Chola" in its own cell, never "-" */
      const cols = ["Claim numbers", "TAT days"].concat(DOC_COLS.map(c => c.label))
        .concat(["Received", "Still to come", "Pending (RTI / 134)", "To upload (RTI / 134)", "Connected with", "Manager", "Client", "Insured", "Field officer", "Status", "Read at", "What the case file shows"]);
      const label = k => (DOC_COLS.filter(c => c.key === k)[0] || { label: k }).label;
      const body = rows.map(r => {
        const t = r.chase || triage(r);
        const line = [r.claim, (r.tatD == null ? "" : r.tatD)];
        for (const c of DOC_COLS) line.push(t.skipWhy[c.key] ? ("Not put - " + t.skipWhy[c.key]) : cellWord(r.marks[c.key], (r.via || {})[c.key]));
        const proof = DOC_COLS.filter(c => r.proof[c.key]).map(c => c.label + ": " + r.proof[c.key]).join(" | ");
        line.push(r.got, DOC_COLS.length - r.got, t.pending.map(label).join(", "), t.upload.map(label).join(", "), (r.with || []).join(", "),
          r.manager || "", r.client || "", r.insured || "", r.officer || "", r.status || "",
          r.readAt ? new Date(r.readAt + 19800000).toISOString().slice(0, 16).replace("T", " ") + " IST" : "not read yet", proof);
        return line;
      });
      await secLog(env, "download", me.email, "document register (" + rows.length + " open Motor TP cases)", false);
      return xlsxResponse(cols, body, "TaaSen-document-register");
    }

    /* ONE case, read again this second — pressed from the register, and pressed by the portal
       itself the moment a document of its own actually lands on a case */
    if (url.pathname === "/api/docreg/refresh" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
      const claim = String((b && b.claim) || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Give a claim number." }, { status: 400 });
      if (!allowRate("docreg:" + me.email, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many refreshes this hour — the register fills itself anyway." }, { status: 429 });
      if (isScopedRole(me.role) && !docRegWide(me)) {   /* v34.5 — the whole book for the tick */
        const sc = await claimScopeCheck(env, me, claim);
        if (!sc.allowed) return Response.json({ ok: false, error: "That case is outside your scope." }, { status: 403 });
      }
      let live = null;
      try { const d = await getCases(env); live = findCaseByClaim(d.cases, claim) || null; } catch (e) { live = null; }
      const r = await docRegOne(env, skdGetCaseDoc, live, claim);
      return Response.json(r, { status: r.ok ? 200 : 500 });
    }

    /* fill a batch now, instead of waiting for the half-hour. Admin only: it is a run at
       SKD's server, and his standing word is that it buckles under the daytime load. */
    if (url.pathname === "/api/docreg/sweep" && request.method === "POST") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
      const limit = Math.max(1, Math.min(200, parseInt((b && b.limit) || 40, 10) || 40));
      const r = await docRegTick(env, { limit });
      return Response.json({ ok: !!r.ok, ...r });
    }

    /* ══════════ DAILY NEWS — v28.1, 16-Sep-2026 ═════════════════════════════════
       Sujit, 7:46 am: "Change this name — Daily News... if I select the date need to show
       that date's news."

       A DAY IS A RECORD, NOT A QUERY. The date in the query string reads the row that was
       written on that day and nothing else — no re-filtering of today's feed, no quietly
       serving today when yesterday is missing. A day we never gathered says so, which is the
       only answer that stays true a month later. */
    if (url.pathname === "/api/news" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "brief")) return Response.json({ ok: false, error: "You do not have access to Daily News." }, { status: 403 });
      const asked = String(url.searchParams.get("date") || "").trim();
      const ymd = /^\d{4}-\d{2}-\d{2}$/.test(asked) ? asked : ymdOf(Date.now());
      const day = await readDay(env, ymd);
      const days = await daysHeld(env, 70);
      /* v29.3 — the count now includes the television channels, which it never did: the page
         said "25 sources" while thirty-eight were being asked, so the fifteen that were
         failing were not even in the number they were failing out of. And `tv` travels with
         the answer so the page can say the channels refused rather than show a blank space. */
      return Response.json({ ok: true, ymd, today: ymdOf(Date.now()), days,
        stories: (day && day.stories) || [], at: (day && day.at) || 0,
        watching: NEWS_TOPICS.length + NEWS_FEEDS.length + NEWS_YT.length,
        channels: NEWS_YT.length, tv: (day && day.tv) || null,
        held: !!day });
    }
    /* gather now — pressed from the page, and the same call the daily run makes */
    if (url.pathname === "/api/news/refresh" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "brief")) return Response.json({ ok: false, error: "You do not have access to Daily News." }, { status: 403 });
      if (!allowRate("news:" + me.email, 12, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Daily News has been gathered several times this hour already — please give it a few minutes." }, { status: 429 });
      try {
        const r = await newsTick(env, { force: true, fetch: (...a) => fetch(...a) });
        return Response.json(Object.assign({ ok: !!r.ok }, r));
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 500 }); }
    }

    /* what the folder listing holds, for the screen and for him to read at a glance —
       a login, not the key */
    if (url.pathname === "/api/docreg/drive" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docreg")) return Response.json({ ok: false, error: "You do not have access to the document register." }, { status: 403 });
      await ensureDocRegSchema(env);
      const per = {}; for (const c of DOC_COLS) per[c.key] = 0;
      let claims = 0, rows = 0, miss = [];
      try {
        const r = await env.DB.prepare("SELECT col, COUNT(*) AS n FROM doc_drive GROUP BY col").all();
        for (const x of ((r && r.results) || [])) { if (per[x.col] != null) per[x.col] = x.n; rows += x.n; }
        const c = await env.DB.prepare("SELECT COUNT(DISTINCT claim) AS n FROM doc_drive").first();
        claims = (c && c.n) || 0;
        const m = await env.DB.prepare("SELECT name, read_as FROM doc_drive_miss ORDER BY at DESC LIMIT 200").all();
        miss = (m && m.results) || [];
      } catch (e) {}
      let last = null; try { last = JSON.parse(await stGet(env, "docreg:drive:last") || "null"); } catch (e) { last = null; }
      return Response.json({ ok: true, claims, files: rows, per, cols: DOC_COLS.map(c => ({ key: c.key, label: c.label })), notMatched: miss, last,
        feedUrl: url.origin + "/api/docreg/drive" });
    }

    /* what the register holds — the screen's door (a login, not the key) */
    if (url.pathname === "/api/drive-docs" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "upload")) return Response.json({ ok: false, error: "You do not have access to document uploads." }, { status: 403 });
      let cfg = {}, log = [];
      try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
      try { log = JSON.parse(await env.USERS.get(DDOC_LOG_KEY) || "[]"); } catch (e) { log = []; }
      /* v33.0 — counted through logVerdict, so the thousands of lines ALREADY written as
         "error" that are really "already on the case" are read correctly. Nothing stored is
         rewritten: the judgement is applied here, where it is shown. */
      const count = countLog(log);
      const day = new Date(Date.now() + 19800000).toISOString().slice(0, 10);
      const today = log.filter(r => new Date(r.ts + 19800000).toISOString().slice(0, 10) === day);
      const tCount = countLog(today);
      /* the not-matched list is the one a person must ACT on, so it comes whole (newest first)
         while the rest is summarised — a screen that lists 1,600 successes buries the 12 that
         need a human */
      const nomatch = log.filter(r => logVerdict(r) === "nomatch").slice(-400).reverse();
      const recent = log.slice(-120).reverse().map(r => Object.assign({}, r, { r: logVerdict(r) }));
      const uploadPathSet = !!((env.SKD_UPLOAD_PATH || SKD_UPLOAD_PATH_DEFAULT || "").trim());
      const health = scriptHealth({ lastAsk: await ddocLastAsk(env), lastRun: cfg.lastRun || 0,
        lastList: await ddocLastList(env), waiting: (await sendQueue(env, 400)).length, now: Date.now() });
      let collector = null; try { collector = await collectorState(env); } catch (e) { collector = null; }   /* v33.6 */
      return Response.json({ ok: true, on: !!cfg.key, masked: cfg.key ? maskKey(cfg.key) : "", setBy: cfg.setBy || "", setTs: cfg.setTs || 0,
        lastRun: cfg.lastRun || 0, lastCount: cfg.lastCount || 0, total: log.length, count, today: tCount, nomatch, recent, script: health, collector,
        uploadPathSet, pushUrl: url.origin + "/api/drive-docs/push",
        note: uploadPathSet ? "" : "The SKD upload address is not set on this Worker (SKD_UPLOAD_PATH), so nothing can reach the case files yet — every push would come back refused." });
    }
    if (url.pathname === "/api/drive-docs/key" && request.method === "POST") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      let cfg = {}; try { cfg = JSON.parse(await env.USERS.get(DDOC_KV_KEY) || "{}"); } catch (e) { cfg = {}; }
      let b = {}; try { b = await request.json(); } catch (e) { b = {}; }
      if (b && b.off) {
        await env.USERS.put(DDOC_KV_KEY, JSON.stringify(Object.assign({}, cfg, { key: "", setBy: me.name || me.email, setTs: Date.now() })));
        await secLog(env, "admin-action", me.email, "drive-docs key switched OFF", true);
        return Response.json({ ok: true, on: false });
      }
      /* ROTATION IS DESTRUCTIVE, and the answer says so: the key sitting in the Apps Script
         stops working the moment a new one is stored, and files pile up in the folder until
         it is repasted. */
      const key = "dd" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
      await env.USERS.put(DDOC_KV_KEY, JSON.stringify(Object.assign({}, cfg, { key, setBy: me.name || me.email, setTs: Date.now() })));
      await secLog(env, "admin-action", me.email, "drive-docs key " + (cfg.key ? "ROTATED" : "created"), true);
      return Response.json({ ok: true, on: true, key, rotated: !!cfg.key, masked: maskKey(key), pushUrl: url.origin + "/api/drive-docs/push" });
    }
    if (url.pathname === "/api/drive-docs/xlsx" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "upload")) return Response.json({ ok: false, error: "You do not have access to document uploads." }, { status: 403 });
      let log = []; try { log = JSON.parse(await env.USERS.get(DDOC_LOG_KEY) || "[]"); } catch (e) { log = []; }
      const want = String(url.searchParams.get("only") || "").trim();     // '' = everything, 'nomatch' = the list to fix
      const rows = log.filter(r => !want || r.r === want).reverse().map(r => [
        new Date(r.ts + 19800000).toISOString().slice(0, 16).replace("T", " "),
        r.n || "", r.c || "", r.l || "", r.p || "",
        r.r === "uploaded" ? "Uploaded to the case" : r.r === "nomatch" ? "NOT MATCHED — no live case" : r.r === "duplicate" ? "Already uploaded before" : "Error",
        r.m || ""]);
      if (!rows.length) rows.push(["", "(nothing in the register yet)", "", "", "", "", ""]);
      return await xlsxResponse(["When (IST)", "File name in Drive", "Claim number matched", "Document", "Product", "What happened", "Detail"], rows, "claim-docs-from-drive" + (want ? "-" + want : ""));
    }

    /* WHAT THE CARRIED HISTORY HOLDS. Its own door, so a screen showing a five-month figure
       can say where the older months came from instead of leaving it to be assumed. */
    if (url.pathname === "/api/cm-archive/stats") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canSeeCaseData(me)) return Response.json({ ok: false, error: "Your access does not include case data." }, { status: 403 });
      try {
        const st = await archiveStats(env);
        /* IS IT STILL GROWING? That is the only question worth asking of an archive, and the
           old answer — one total — could not tell a history moving forward from one that
           stopped in August and was never going to move again. The catcher runs hourly, so
           anything past three hours is a fault worth naming rather than a slow day. */
        const c = st.caught || {};
        const ageH = c.lastAt ? Math.round((Date.now() - c.lastAt) / 3600000 * 10) / 10 : null;
        const healthy = !!(c.available && c.lastOk && ageH !== null && ageH <= 3);
        return Response.json({ ok: true, ...st, healthy, caughtAgeHours: ageH,
          note: st.loaded
            ? "CM Reviewed history carried inside the site, because SKD's own API serves only the last two days."
            : "The carried archive file could not be read — the closed-case screens are showing the live feed plus whatever the portal has caught itself.",
          growth: !c.available
            ? "The portal cannot keep new closed cases: the D1 database binding \"DB\" is missing, so the history stops at the carried file."
            : (c.lastAt === 0
                ? "The hourly catcher has not run yet. It runs at the top of every hour; until then the history stops at the carried file."
                : (healthy
                    ? "Growing by itself — last caught " + ageH + " h ago, " + c.lastRead + " closed cases read and " + c.lastSaved + " kept."
                    : "NOT growing as it should — last run was " + (ageH === null ? "never" : ageH + " h ago") +
                      (c.lastWhy ? " and it said: " + c.lastWhy : "") + ". Anything closed since then is only in SKD's own two-day window.")) });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* CATCH NOW. The catcher runs at the top of every hour by itself; this is the button for
       the day you cannot wait for it — the day the portal is deployed, when yesterday is still
       inside SKD's two-day window and will not be tomorrow. Admin only, because it writes to
       the archive, and it answers with what it actually did rather than a cheerful "done". */
    if (url.pathname === "/api/cm-archive/catch" && request.method === "POST") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 });
      try {
        const r = await keepSweep(env, getCompleteCases);
        /* THE RECONCILIATION, ON THE SCREEN. 19-Aug: "Caught up: 195" sat beside a mail table
           totalling 163 and he asked which was wrong. Neither — the catch is the feed's whole
           two-day window with CM and QC together; the mail's table is one date, CM alone. Two
           unexplained numbers side by side read as a contradiction, so this dialog now does
           the subtraction itself: by stage, then by completed date, dd/mm. */
        const days = Object.keys(r.byDate || {}).sort().map(d => {
          const p = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d);
          return (p ? p[3] + "/" + p[2] : d) + ": " + r.byDate[d];
        }).join(" · ");
        return Response.json({ ok: r.ok, read: r.read, saved: r.saved, why: r.why || "",
          cm: r.cm || 0, qcOnly: r.qcOnly || 0, byDate: r.byDate || {},
          said: r.ok
            ? (r.saved + " closed cases kept, out of " + r.read + " the live feed served — " +
               (r.cm || 0) + " reached CM Reviewed, " + (r.qcOnly || 0) + " are QC Reviewed only" +
               (days ? ". By completed date — " + days : "") +
               ". The daily mail's table counts ONE date and CM Reviewed alone, so its total reads lower than this on purpose.")
            : ("Nothing was kept — " + (r.why || "the reason was not reported, which is itself a fault.")) });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    if (url.pathname === "/api/fo-list") {
      const cfg = (env.SKD_FO_PATH || SKD_FO_PATH_DEFAULT || "").trim();
      if (!cfg) return Response.json({ ok: false, error: "FO list endpoint not configured — set a Worker variable SKD_FO_PATH (full URL or path) to Praveen's Get All FO Details API." }, { status: 501 });
      const target = /^https?:\/\//i.test(cfg) ? cfg : (env.SKD_API_BASE + cfg);
      try {
        let token = await getToken(env);
        let r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } });
        if (r.status === 401) { token = await getToken(env, true); r = await fetch(target, { headers: { "Authorization": "Bearer " + token, "Accept": "application/json" } }); }
        return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json" } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══════════ FIELD OFFICER PHONE BOOK ══════════════════════════════════════════════
       The numbers the SKD Manage-User API does not send. Read by anyone who has the Field
       Officers page; changed only by Admin, Management or HR — a wrong mobile against the
       right man is a worse fault than a blank, so the pen is kept in few hands.          */
    if (url.pathname === "/api/fo-phones" && request.method === "GET") {
      if (!canAccess(me, "officers")) { await secLog(env, "access-denied", me.email, "FO phone book (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Field Officers." }, { status: 403 }); }
      const book = await foPhoneBook(env);
      return Response.json({ ok: true, phones: book, canEdit: foPhoneEditor(me), count: Object.keys(book).length });
    }
    if (url.pathname === "/api/fo-phones" && request.method === "POST") {
      if (!canAccess(me, "officers")) { await secLog(env, "access-denied", me.email, "FO phone book (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Field Officers." }, { status: 403 }); }
      if (!foPhoneEditor(me)) { await secLog(env, "access-denied", me.email, "FO phone book write (not permitted)", false); return Response.json({ ok: false, error: "Only Admin, Management or HR can change a field officer's contact number." }, { status: 403 }); }
      if (!allowRate("fophone:" + me.email, 200, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many contact-number saves this hour — please wait a little." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const entries = Array.isArray(b && b.entries) ? b.entries.slice(0, 600) : [];
      if (!entries.length) return Response.json({ ok: false, error: "Nothing to save." }, { status: 400 });
      const book = await foPhoneBook(env);
      const now = Date.now(), bad = [];
      let saved = 0, cleared = 0, same = 0;
      for (const it of entries) {
        const nm = String((it && it.name) || "").replace(/\s+/g, " ").trim().slice(0, 120);
        if (!nm) continue;
        const key = normName(nm);
        const rawNum = String((it && it.num) == null ? "" : it.num).trim();
        if (!rawNum) { if (book[key]) { delete book[key]; cleared++; } continue; }   // blank = rub it out
        const num = foPhoneClean(rawNum);
        if (!num) { bad.push({ name: nm, num: rawNum.slice(0, 30) }); continue; }    // never store a number we do not believe
        if (book[key] && book[key].num === num) { same++; continue; }
        book[key] = { num, name: nm, by: me.email, ts: now };
        saved++;
      }
      const keys = Object.keys(book);
      if (keys.length > 3000) return Response.json({ ok: false, error: "The phone book is full (3000 officers)." }, { status: 400 });
      if (saved || cleared) {
        await stSoft(env, "fo:phones", JSON.stringify(book));
        await secLog(env, "admin-action", me.email, "FO contact numbers: " + saved + " saved, " + cleared + " cleared", true);
      }
      return Response.json({ ok: true, phones: book, saved, cleared, same, bad, count: keys.length });
    }

    // DIAGNOSTIC: raw open-cases sample — shows the exact field names SKD sends,
    // so CM/QC (and stage dates / conclusion) can be mapped precisely. Safe to remove later.
    if (url.pathname === "/api/raw-open") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 }); // SECURITY: raw unscoped data is admin-only
      const n = Math.max(1, Math.min(5, parseInt(url.searchParams.get("n") || "2", 10) || 2));
      try {
        const r = await skdGet(env, "/cases/open-cases");
        const raw = await r.json();
        const list = Array.isArray(raw.data) ? raw.data : (Array.isArray(raw) ? raw : []);
        return Response.json({ ok: true, total: raw.total != null ? raw.total : list.length, sampleKeys: list[0] ? Object.keys(list[0]) : [], sample: list.slice(0, n) });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* DIAGNOSTIC: free-hand probe. Fires ONE read-only GET at any path on the SKD server and hands
       back the untouched reply, so a "try it like this" suggestion from Praveen can be tested in
       seconds instead of waiting on a redeploy. Admin only; GET only; cannot leave his server. */
    if (url.pathname === "/api/raw-probe") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 }); // SECURITY: raw unscoped data is admin-only
      let p = String(url.searchParams.get("p") || "").trim();
      if (!p) return Response.json({ ok: false, error: "Nothing to try — give a path such as /cases/status/pending" }, { status: 400 });
      if (p.length > 500) return Response.json({ ok: false, error: "That address is too long." }, { status: 400 });
      // SECURITY: keep the probe pinned to SKD's own base — no absolute URL, no protocol-relative host, no climbing out
      if (/^[a-z][a-z0-9+.-]*:/i.test(p) || p.slice(0, 2) === "//" || p.indexOf("..") >= 0 || /[\s<>"'\\]/.test(p)) {
        return Response.json({ ok: false, error: "Only a plain path on the SKD server is allowed, for example /cases/status/pending?page=1" }, { status: 400 });
      }
      if (p.charAt(0) !== "/") p = "/" + p;

      const out = { ok: true, path: p, url: env.SKD_API_BASE + p };
      try {
        const t0 = Date.now();
        const r = await skdGet(env, p);
        out.ms = Date.now() - t0;
        out.httpStatus = r.status;
        out.contentType = r.headers.get("content-type") || "";
        const text = await r.text();
        out.bytes = text.length;

        let raw = null, parsed = true;
        try { raw = JSON.parse(text); } catch (e) { parsed = false; }
        out.isJson = parsed;
        if (!parsed) { out.body = text.slice(0, 4000); return Response.json(out); }

        const isArr = Array.isArray(raw);
        const isObj = raw && typeof raw === "object" && !isArr;
        out.envelopeKeys = isArr ? ["(the body is a bare array)"] : (isObj ? Object.keys(raw) : ["(body is " + typeof raw + ")"]);

        let list = isArr ? raw : [];
        if (isObj) {
          for (const k of ["data", "cases", "content", "result", "records", "items"]) {
            if (Array.isArray(raw[k])) { list = raw[k]; out.rowsFoundUnder = k; break; }
          }
        }
        out.rowCount = list.length;
        out.total = isObj ? (raw.total != null ? raw.total : (raw.totalElements != null ? raw.totalElements : (raw.totalRecords != null ? raw.totalRecords : null))) : null;
        if (list[0] && typeof list[0] === "object") { out.rowKeys = Object.keys(list[0]); out.firstRow = list[0]; }
        out.body = text.slice(0, 4000);
      } catch (e) { out.ok = false; out.error = String(e && e.message ? e.message : e); }
      return Response.json(out);
    }

    /* DIAGNOSTIC: Praveen's new "Get Cases by Status" API (his mail of 30-Jul-2026).
       GET /cases/status/{type} — pending | assigned | deferred | fo-accepted | fo-rejected |
       fo-completed | cm-reviewed | qc-reviewed | dm-reviewed, with optional fromDate, toDate,
       page, pageSize (pageSize defaults to 10).

       His mail carried no example response, so this route finds out for itself and answers the
       three questions we cannot answer from the documentation:
         1. does the endpoint answer at all, and does it really hold CM/QC-reviewed cases?
         2. is pageSize above 10 honoured — we have thousands of rows to pull?
         3. does a case that has moved on to QC still appear under cm-reviewed (CUMULATIVE),
            or only under the stage it is sitting at right now (CURRENT-STAGE ONLY)?
            Settled by claim-number overlap between the two lists — no need to ask him.
       Admin only, read-only, safe to delete once the feed is wired in. */
    if (url.pathname === "/api/raw-status") {
      if (!me || me.role !== "admin") return Response.json({ ok: false, error: "Admin only" }, { status: 403 }); // SECURITY: raw unscoped data is admin-only
      const ALL = ["pending", "assigned", "deferred", "fo-accepted", "fo-rejected", "fo-completed", "cm-reviewed", "qc-reviewed", "dm-reviewed"];
      const asked = String(url.searchParams.get("types") || "cm-reviewed,qc-reviewed,fo-completed,dm-reviewed,pending")
        .split(",").map(s => s.trim()).filter(s => ALL.indexOf(s) >= 0);
      const types = asked.length ? asked : ["cm-reviewed", "qc-reviewed"];
      const size = Math.max(1, Math.min(1000, parseInt(url.searchParams.get("pageSize") || "200", 10) || 200));
      const today = new Date().toISOString().slice(0, 10);

      // the claim number under whatever name SKD happens to use for it
      const claimOf = (row) => {
        if (!row || typeof row !== "object") return null;
        for (const k of ["claimNumber", "claimNo", "claim_no", "claimno", "claimNum", "claim"]) {
          if (row[k] != null && String(row[k]).trim()) return String(row[k]).trim();
        }
        for (const k of Object.keys(row)) {
          if (/claim/i.test(k) && row[k] != null && typeof row[k] !== "object" && String(row[k]).trim()) return String(row[k]).trim();
        }
        return null;
      };

      // pull one status list. Never throws — a dead endpoint must still be reportable.
      const probe = async (type, qs) => {
        const path = "/cases/status/" + type + (qs ? "?" + qs : "");
        const out = { url: env.SKD_API_BASE + path };
        try {
          const r = await skdGet(env, path);
          out.httpStatus = r.status;
          out.contentType = r.headers.get("content-type") || "";
          const text = await r.text();
          out.bytes = text.length;
          let raw = null;
          try { raw = JSON.parse(text); } catch (e) { out.notJson = text.slice(0, 400); return out; }
          const isArr = Array.isArray(raw);
          out.envelopeKeys = isArr ? ["(the body is a bare array)"] : (raw && typeof raw === "object" ? Object.keys(raw) : ["(body is " + typeof raw + ")"]);
          const list = isArr ? raw
            : (Array.isArray(raw && raw.data) ? raw.data
              : (Array.isArray(raw && raw.cases) ? raw.cases
                : (Array.isArray(raw && raw.content) ? raw.content
                  : (Array.isArray(raw && raw.result) ? raw.result
                    : (Array.isArray(raw && raw.records) ? raw.records : [])))));
          out.rowCount = list.length;
          out.total = (!isArr && raw && raw.total != null) ? raw.total
            : ((!isArr && raw && raw.totalElements != null) ? raw.totalElements
              : ((!isArr && raw && raw.totalRecords != null) ? raw.totalRecords : null));
          out.claims = list.map(claimOf).filter(Boolean);
          if (list[0] && typeof list[0] === "object") { out.rowKeys = Object.keys(list[0]); out.sample = list[0]; }
          if (!list.length && !isArr && text.length < 900) out.emptyBody = text;   // e.g. {"message":"No records"}
        } catch (e) { out.error = String(e && e.message ? e.message : e); }
        return out;
      };

      try {
        // two shots per status: as-is, and with a wide date window, so we learn whether the
        // dates are doing the filtering or whether the list is simply empty
        const report = {};
        for (const t of types) {
          report[t] = {
            withoutDates: await probe(t, "page=1&pageSize=" + size),
            withWideDates: await probe(t, "fromDate=2020-01-01&toDate=" + today + "&page=1&pageSize=" + size)
          };
        }
        const best = (t) => {
          const r = report[t]; if (!r) return null;
          if (r.withoutDates && r.withoutDates.rowCount) return r.withoutDates;
          if (r.withWideDates && r.withWideDates.rowCount) return r.withWideDates;
          return r.withoutDates || r.withWideDates;
        };

        // ---- the verdicts, worked out here so the page has nothing left to guess ----
        const perStatus = types.map(t => {
          const p = best(t) || {};
          return {
            status: t,
            reachable: p.httpStatus >= 200 && p.httpStatus < 300,
            httpStatus: p.httpStatus || 0,
            rows: p.rowCount != null ? p.rowCount : 0,
            total: p.total,
            fields: p.rowKeys ? p.rowKeys.length : 0,
            datesMattered: !!(report[t] && report[t].withoutDates && report[t].withWideDates
              && report[t].withoutDates.rowCount !== report[t].withWideDates.rowCount),
            problem: p.error || p.notJson || (p.httpStatus >= 400 ? ("HTTP " + p.httpStatus) : null)
          };
        });

        const cm = best("cm-reviewed"), qc = best("qc-reviewed");
        let overlap;
        if (cm && qc && cm.claims && qc.claims && cm.claims.length && qc.claims.length) {
          const inCm = new Set(cm.claims);
          const both = qc.claims.filter(c => inCm.has(c));
          overlap = {
            cmRows: cm.claims.length, qcRows: qc.claims.length, inBoth: both.length, examples: both.slice(0, 3),
            cumulative: both.length > 0,
            verdict: both.length
              ? "CUMULATIVE — a case that has moved on to QC still shows under cm-reviewed, so the CM Reviewed count is complete as it stands."
              : "CURRENT-STAGE ONLY — no claim appears in both lists, so a case sitting at QC is missing from cm-reviewed. We must add the later stages ourselves to get the true CM Reviewed figure."
          };
        } else {
          overlap = { cumulative: null, verdict: "Cannot be settled yet — one of the two lists came back with no rows." };
        }

        /* the page-size question can only be answered if something actually came back —
           with every list empty there is nothing to measure, and saying "honoured" there
           would read as good news when in fact we learned nothing. */
        const probes = types.map(best).filter(Boolean);
        const anyRows = probes.some(p => (p.rowCount || 0) > 0);
        const capped = probes.filter(p => p.rowCount === 10 && (p.total == null || p.total > 10));
        const pageSize = {
          asked: size,
          capped: anyRows ? capped.length > 0 : null,
          verdict: !anyRows
            ? "Cannot be settled yet — not one list returned a single row, so there is nothing to measure the page size against."
            : (capped.length
              ? "CAPPED AT 10 — we asked for " + size + " rows and got exactly 10 back. Praveen must raise the pageSize limit before we can pull thousands of cases."
              : "Honoured — more than 10 rows came back (or the lists are genuinely that short).")
        };

        // which of the fields we need are actually on the rows
        const WANTED = ["claim", "cmReview", "qcReview", "dmReview", "release", "bill", "invoice", "stage", "status", "date", "client", "patient", "insured", "manager", "officer", "tat", "product"];
        const fieldScan = {};
        for (const t of types) {
          const p = best(t);
          if (p && p.rowKeys) {
            fieldScan[t] = { all: p.rowKeys, interesting: p.rowKeys.filter(k => WANTED.some(w => k.toLowerCase().indexOf(w.toLowerCase()) >= 0)) };
          }
        }

        const anyLive = perStatus.some(s => s.reachable);
        const cmRows = (perStatus.find(s => s.status === "cm-reviewed") || {}).rows || 0;
        const qcRows = (perStatus.find(s => s.status === "qc-reviewed") || {}).rows || 0;
        const headline = !anyLive
          ? "The new API is NOT answering yet — not one status came back."
          : (cmRows || qcRows)
            ? ("It works, and CM/QC reviewed cases ARE coming through — " + cmRows + " CM-reviewed and " + qcRows + " QC-reviewed on the first page.")
            : "The API answers, but it gave back NO CM-reviewed and NO QC-reviewed rows at all.";

        return Response.json({
          ok: true, checkedOn: new Date().toISOString(), base: env.SKD_API_BASE,
          headline, perStatus, overlap, pageSize, fieldScan, report
        });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    if (url.pathname === "/api/health") {
      let live = false, total = 0, err = "";
      try { const d = await getCases(env); live = true; total = d.total; } catch (e) { err = String(e && e.message ? e.message : e); }
      /* v34.7 — the copy's age and the keeper's last pull, for anyone diagnosing a slow morning */
      let lastPull = null; try { lastPull = JSON.parse(await stGet(env, "book:pull") || "null"); } catch (e) { lastPull = null; }
      const book = OPEN_LAST ? { at: new Date(OPEN_LAST.ts).toISOString(), ageSec: Math.max(0, Math.round((Date.now() - OPEN_LAST.ts) / 1000)), cases: OPEN_LAST.d.cases.length } : null;
      return Response.json({ ok: true, msg: "Worker live", live: live, total: total, error: err, hasAI: !!env.AI, hasClaude: !!env.ANTHROPIC_API_KEY, time: new Date().toISOString(), book, lastPull });
    }

    /* ══════════ ONE CLASSIFIER, SERVED TO THE PAGES — v33.7 ═══════════════════════════════
       The pages used to carry their own copy of SUBPRODUCT_TYPE_MAP (analytics.html) and their
       own word lists (the Documents page). This door hands them the Worker's own functions,
       printed from source, so the browser runs exactly what the server runs: productOf,
       productKey, PRODUCTS, typeOfSub and the map it reads. Nothing here is a case. */
    if (url.pathname === "/api/product-rules.js" && request.method === "GET") {
      if (!me) return new Response("/* sign in first */", { status: 401, headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-store" } });
      const js = "/* TaaSen product rules — generated from worker.js, v33.7. Do not edit. */\n" +
        "(function(){\n" +
        "var SUBPRODUCT_TYPE_MAP = " + JSON.stringify(SUBPRODUCT_TYPE_MAP) + ";\n" +
        "var PRODUCTS = " + JSON.stringify(PRODUCTS) + ";\n" +
        normName.toString() + "\n" + typeOfSub.toString() + "\n" + isMbvSub.toString() + "\n" +
        productOf.toString() + "\n" + productParent.toString() + "\n" + productPills.toString() + "\n" + productKey.toString() + "\n" +
        "window.TAASEN_PRODUCTS = PRODUCTS; window.productOf = productOf; window.productKey = productKey; window.productParent = productParent; window.productPills = productPills; window.typeOfSubShared = typeOfSub;\n" +
        "window.prodOf = function (c) { return (c && c.product) || productOf(c && c.subProduct); };\n" +
        "window.productLabel = function (k, long) { for (var i = 0; i < PRODUCTS.length; i++) if (PRODUCTS[i].key === k) return long ? (PRODUCTS[i].long || PRODUCTS[i].label) : PRODUCTS[i].label; return k || 'All'; };\n" +
        "})();\n";
      return new Response(js, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" } });
    }
    if (url.pathname === "/api/open-cases") {
      try {
        const me = await currentUser(env, request);
        if (me && !canSeeCaseData(me)) return Response.json({ ok: true, source: "RESTRICTED", total: 0, cases: [] });   // e.g. Call Centre: no case-list access
        /* WHEN SKD IS DOWN, THE LAST GOOD LIST IS BETTER THAN A SKELETON — but only if it is
           marked. If the live pull fails and a good list from the last six hours is in hand,
           that list is served with stale:true and the time it was fetched, and the screen says
           so. Role scoping below runs on it exactly as on a live list — a stale answer must
           never be a wider answer. */
        let d, staleInfo = null;
        /* v34.7 — the copy the keeper holds, or a pull of this request's own when ?fresh=1 */
        try { d = await getCases(env, { fresh: url.searchParams.get("fresh") === "1" }); }
        catch (liveErr) {
          /* v34.3 — memory first, then the copy kept in R2 (see lastOpenBook); the demo case only
             when there is no copy at all, or the copy is older than two days */
          const last = await lastOpenBook(env);
          if (last && last.d) {
            d = last.d;
            staleInfo = { staleAt: new Date(last.ts).toISOString(), staleAgeSec: Math.round((Date.now() - last.ts) / 1000), from: last.from, error: String(liveErr && liveErr.message ? liveErr.message : liveErr) };
          } else if (last && last.tooOld) {
            throw new Error(String(liveErr && liveErr.message ? liveErr.message : liveErr) + " The last good copy of the book is from " + new Date(last.ts).toISOString().slice(0, 10) + " — too old to show.");
          } else throw liveErr;
        }
        let cases = d.cases;
        /* v34.9 — OUR OWN CASES (made on New Case, allocated on Pinaka App) join the list, fenced by the
           same rule below. SKD's copy wins on the same claim. Lazy import: case-store imports this file. */
        try {
          const cs = await import("./case-store-index.js");
          const ours = await cs.ourCases(env);
          if (ours.length) { const have = new Set(cases.map(c => claimKey(c.claimNo))); cases = cases.concat(ours.filter(c => !have.has(claimKey(c.claimNo)))); }
        } catch (e) { /* the SKD list is the point; our own cases are an extra until they are all there is */ }
        if (me && (isScopedRole(me.role))) {
          const foMap = me.role === "coordinator" ? await getFoStateMap(env) : null;
          cases = scopeCases(cases, me, foMap);
        }
        /* v33.7 — ?product=tp|health|od|mbv narrows the answer to one bucket (the connector's
           way of asking "the OD cases"); applied AFTER the fence, never instead of it */
        { const pk = productKey(url.searchParams.get("product") || ""); if (pk) cases = cases.filter(c => productOf(c.subProduct) === pk); }
        /* EVERY OFFICER'S OWN STATUS, worked out here where the whole case is in hand, so the
           Analytics page never has to guess it from the case-level word. foStat is one entry
           per man ({n: name, s: his own status}); partFo are the men who have finished while
           the case is still open, openFo the men it is still waiting on. */
        cases = cases.map(c => {
          const fr = ootatFoRows(c);
          return Object.assign({}, c, {
            foStat: fr.map(f => ({ n: f.name, s: f.status })),
            partFo: fr.filter(f => isPartCompletedW(f.status)).map(f => f.name).filter(Boolean),
            openFo: fr.filter(f => !isCompletedStatusW(f.status) && !isPartCompletedW(f.status)).map(f => f.name).filter(Boolean)
          });
        });
        /* v33.8 — EVERY MAN'S OHS, on the case: foOhs = { "<officer>": ["<team head>", …] },
           from the Teams store, fenced as the team list is. Built once for this reply. */
        try { const ix = await ohsIndexFor(env, me); if (ix.size) cases = cases.map(c => Object.assign({}, c, { foOhs: ix.stamp(c) })); } catch (e) { /* the list is the point */ }
        /* THE VERDICT — v32.8. Attached here, after scoping, so the map is only ever built for
           the claims already on this reply; a manager cannot learn what a case outside his
           slice is marked. AND NEVER FOR AN INSURER LOGIN: a client-manager is the client's own
           login, and our private reading of their claim is not theirs to read. A database that
           cannot be reached leaves the verdicts off rather than failing the case list. */
        if (me && !isClientRole(me)) {
          try {
            const vm = await verdictMap(env, cases.map(c => c.claimNo));
            cases = cases.map(c => (vm[c.claimNo] ? Object.assign({}, c, { verdict: vm[c.claimNo] }) : c));
          } catch (e) { /* the list is the point; the marks are an extra */ }
        }
        /* v34.9 — OUR status from Pinaka (FO Accepted / FO Rejected / FO Completed), beside SKD's own —
           never written to SKD. Not for an insurer's login. */
        if (me && !isClientRole(me)) {
          try {
            const cs = await import("./case-store-index.js");
            const am = await cs.appStatusMap(env, cases.map(c => c.claimNo));
            if (Object.keys(am).length) cases = cases.map(c => (am[c.claimNo] ? Object.assign({}, c, { pinaka: am[c.claimNo] }) : c));
          } catch (e) { /* an extra, never a reason to fail the list */ }
        }
        /* v34.7 — the time of the copy every answer is drawn from, so the screen can say "as at" */
        const bookTs = OPEN_LAST ? OPEN_LAST.ts : Date.now();
        return Response.json(Object.assign({ ok: true, source: "LIVE", total: cases.length, cases, bookAt: new Date(bookTs).toISOString(), bookAgeSec: Math.max(0, Math.round((Date.now() - bookTs) / 1000)) },
          staleInfo ? { stale: true, staleAt: staleInfo.staleAt, staleAgeSec: staleInfo.staleAgeSec, staleFrom: staleInfo.from, staleError: staleInfo.error } : {}));
      }
      catch (e) { return Response.json({ ok: true, source: "DEMO", total: DEMO_CASES.length, cases: DEMO_CASES, error: String(e && e.message ? e.message : e) }); }
    }

    /* COMPLETE (closed) cases. The "Complete cases" button on Analytics calls THIS, and this
       makes a live call to Praveen's /cases/status/{cm-reviewed|qc-reviewed|dm-reviewed} on
       every click. `diag` carries the exact URLs hit and what each returned, so the screen
       can prove what it asked for instead of anyone having to take our word for it.
       Optional ?from=YYYY-MM-DD&to=YYYY-MM-DD. Role-scoped exactly like /api/open-cases. */
    if (url.pathname === "/api/complete-cases") {
      try {
        const cu = await currentUser(env, request);
        if (cu && !canSeeCaseData(cu)) return Response.json({ ok: true, source: "RESTRICTED", total: 0, cases: [], diag: [] });
        const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
        const from = String(url.searchParams.get("from") || "").slice(0, 10);
        const to = String(url.searchParams.get("to") || "").slice(0, 10);
        const fresh = url.searchParams.get("fresh") === "1";        // the Refresh button — always re-ask
        const d = await getCompleteCases(env, isDate(from) ? from : "", isDate(to) ? to : "", { fresh });
        let cases = d.cases;
        if (cu && (isScopedRole(cu.role))) {
          const foMap = cu.role === "coordinator" ? await getFoStateMap(env) : null;
          cases = scopeCases(cases, cu, foMap);
        }
        /* v33.8 — every man's OHS on the closed cases too (Case Journey, Reallocated, Complete
           cases on Analytics draw the same hover card) */
        try { const ix = await ohsIndexFor(env, cu); if (ix.size) cases = cases.map(c => Object.assign({}, c, { foOhs: ix.stamp(c) })); } catch (e) { /* the list is the point */ }
        /* ── THE ANSWER GOES BACK WITHOUT ITS EMPTY BOXES ────────────────────────────────
           A closed case comes back with 34 columns, and on this feed 25 of them are empty for
           every single case. Sent as they are, that is roughly 19 MB down the line, of which
           about 11 MB is nothing but empty boxes — and his browser has to read every one of
           them before a figure appears on screen.

           So an empty column is simply left out, and the full list of column names is sent once
           at the end; the screen puts the blanks back the moment it arrives. Nothing is lost,
           nothing downstream changes, and the answer is a little over half the size.

           It only happens when the screen ASKS for it (lean=1), so a page still sitting in
           somebody's browser from before this change keeps getting exactly what it expects. */
        let leanKeys = null;
        if (url.searchParams.get("lean") === "1" && cases.length) {
          leanKeys = Object.keys(cases[0]);
          cases = cases.map(c => { const o = {}; for (const k in c) if (c[k] !== "") o[k] = c[k]; return o; });
        }
        return Response.json({
          ok: true, source: "LIVE", total: cases.length, cases, leanKeys,
          diag: d.diag, widened: d.widened, apiRows: d.total, scopedOut: d.total - cases.length,
          window: d.window, defaultedWindow: d.defaultedWindow, days: d.days,
          fromMemory: !!d.fromMemory, memoryAgeSec: d.memoryAgeSec || 0,
          /* SKD down + a kept copy served in its place: say so, and carry the failed pull's
             diagnosis so the screen can name what went wrong upstream */
          stale: !!d.stale, failedDiag: d.failedDiag || null
        });
      }
      catch (e) { return Response.json({ ok: false, source: "ERROR", total: 0, cases: [], diag: [], error: String(e && e.message ? e.message : e) }); }
    }

    // "TODAY (TP)" sheet export — Motor-TP cases only, in the EXACT column order of the
    // FO-Completed Google Sheet: Client, Sub Product, Claim Number, Patient/Insured, Trigger,
    // Assigning Manager, Allotment Manager, Manager, FO Name, Status, CreatedOn, SKD TAT,
    // SKD TAT-H, Alloted Date, Alloted TAT, CAT TAT, CAT Completed, StackHolders, ST, Type.
    // Role-scoped like /api/export. ST (state) is resolved from the FO directory, Type = TP.
    if (url.pathname === "/api/export-sheet") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canSeeCaseData(me)) return Response.json({ ok: false, error: "Your access does not include case downloads." }, { status: 403 });
        const want = (url.searchParams.get("type") || "all").toLowerCase(); // all | tp | health
        const status = (url.searchParams.get("status") || "").toLowerCase(); // '' | pending | assign | accept | complete | reject
        const client = url.searchParams.get("client") || "";                  // the Dashboard's client dropdown
        const { columns, rows } = await buildSheetRows(env, want, me, status, client);
        const stamp = new Date().toISOString().slice(0, 10);
        const label = productKey(want) || "ALL";     /* v33.7 — TP · Health · OD · MBV · ALL */
        const stLabel = status ? ("-" + status) : "";
        const clLabel = client ? ("-" + String(client).replace(/[^A-Za-z0-9]+/g, "-").slice(0, 24)) : "";
        return await xlsxResponse(columns, rows, "skd-today-" + label + stLabel + clLabel + "-" + stamp);
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ---------- TP OUT OF TAT page: data + manager remarks (role-scoped, KV-backed) ---------- */
    if (url.pathname === "/api/ootat" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootat")) { await secLog(env, "access-denied", me.email, "ootat (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to TP Out of TAT." }, { status: 403 }); }
        const d = await getCases(env);
        let cases = d.cases;
        const foMap = await getFoStateMap(env).catch(() => null);
        if (isScopedRole(me.role)) cases = scopeCases(cases, me, me.role === "coordinator" ? foMap : null);
        const now = Date.now();
        /* ══ THE COMPLETION MEMORY IS READ STRICTLY — v20.3 ═══════════════════════════════
           It used to be read through stGet, which answers null for a D1 fault as readily as
           for an empty key. On a fault every completed case looked brand new, was stamped
           "completed just now", logged to the archive a second time, and the corrupted map
           was WRITTEN BACK over the real one — so the Completed From Field page would show
           every old completion as fresh, for good. Now a fault leaves the memory alone: the
           page still renders (with the stamps it could read, if any), and nothing is saved. */
        let doneMap = {}, doneReadOk = true;
        try { doneMap = JSON.parse((await stGetStrict(env, "ootat:done")) || "{}") || {}; }
        catch (e) { doneMap = {}; doneReadOk = false; }
        const split = ootatSplit(cases, doneMap, now);
        if (split.changed && doneReadOk) { await stSoft(env, "ootat:done", JSON.stringify(split.doneMap)); }
        // PERMANENT ARCHIVE: every completion is appended once to ootat:log (admin-only download; capped at 5000 newest)
        if (split.newly.length && env.USERS && doneReadOk) {
          try {
            let log = []; try { log = JSON.parse(await stGet(env, "ootat:log") || "[]"); } catch (e) { log = []; }
            for (const rec of split.newly) { const c = rec.c; log.push({ c: c.claimNo, cl: c.client || "", s: c.subProduct || "", ty: rec.type, i: c.insured || "", m: c.manager || "", f: c.officerName || "", st: foStateOf(c.officerName, foMap) || "", rg: foRegionOf(c.officerName, foMap) || "", d: rec.days, ts: now }); }
            if (log.length > 5000) log = log.slice(log.length - 5000);
            await stSoft(env, "ootat:log", JSON.stringify(log));
          } catch (e) {}
        }
        let remarks = {};
        if (true) { try { remarks = JSON.parse(await stGet(env, "ootat:remarks") || "{}"); } catch (e) { remarks = {}; } }
        const rowOf = rec => { const c = rec.c, dh = tatDH(c.tat); return {
          claim: c.claimNo, client: c.client, sub: c.subProduct, type: rec.type, insured: c.insured || "",
          /* v17.8 — Sujit, 31-Aug, in the meeting itself: "for health, after the insured name
             need a hospital name — I can see that it is available." It is — the live feed
             sends hospitalName on the case — and the meeting row now carries it instead of
             leaving it behind on the mapping-room floor. */
          hospital: c.hospitalName || "",
          manager: c.manager || "", fo: c.officerName || "", state: foStateOf(c.officerName, foMap) || "",
          region: foRegionOf(c.officerName, foMap) || "",
          tatD: rec.days, tatH: dh[1] || "", status: c.status || "", createdOn: c.createdOn || "",
          /* WHO ACTUALLY FINISHED, name by name. A case where two men out of three are done is
             NOT a completed case, so it never reaches the completed list at all — but when it
             does show, only the men who really finished are named, never the whole line-up. */
          foStat: (rec.rows || []).map(r => ({ n: r.fo, s: r.status })),
          partFo: (rec.partFo || []).slice(), doneFo: (rec.doneFo || []).slice(), openFo: (rec.openFo || []).slice(),
          part: !!(rec.partFo && rec.partFo.length),
          doneTs: split.doneMap[String(c.claimNo || "").trim()] || 0 }; };
        const out = split.out.map(rowOf).sort((a, b) => b.tatD - a.tatD);
        const visible = {}; out.forEach(r => { if (remarks[r.claim]) visible[r.claim] = remarks[r.claim]; });
        /* v33.7 — ?product=tp|health|od|mbv narrows the rows to one bucket (the page keeps its own pills) */
        { const pk = productKey(url.searchParams.get("product") || ""); if (pk) return Response.json({ ok: true, ts: now, limit: OOTAT_LIMIT_DAYS, out: out.filter(r => r.type === pk), remarks: visible, product: pk }); }
        return Response.json({ ok: true, ts: now, limit: OOTAT_LIMIT_DAYS, out, remarks: visible });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    if (url.pathname === "/api/ootat/log" && request.method === "GET") {
      // SECURITY: the saved completion archive is ADMIN-ONLY, as requested.
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (me.role !== "admin") { await secLog(env, "access-denied", me.email, "ootat completion archive (admin only)", false); return Response.json({ ok: false, error: "Admin only" }, { status: 403 }); }
      let log = [], remarks = {};
      if (env.USERS) {
        try { log = JSON.parse(await stGet(env, "ootat:log") || "[]"); } catch (e) { log = []; }
        try { remarks = JSON.parse(await stGet(env, "ootat:remarks") || "{}"); } catch (e) { remarks = {}; }
      }
      return Response.json({ ok: true, log, remarks });
    }
    if (url.pathname === "/api/ootat/remark" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootat")) { await secLog(env, "access-denied", me.email, "ootat remark (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to TP Out of TAT." }, { status: 403 }); }
        if (!allowRate("remark:" + me.email, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many remark saves this hour — please wait a little." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const claim = String(b && b.claim || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const text = String(b && b.text != null ? b.text : "").trim().slice(0, 500);
        // Reallocated / Not Reallocated decision comes WITH the remark. Not Reallocated -> Feedback Calling queue.
        const realloc = String(b && b.realloc || "").trim().toLowerCase();
        if (realloc && realloc !== "reallocated" && realloc !== "not-reallocated") return Response.json({ ok: false, error: "Invalid reallocation value." }, { status: 400 });
        if (text && !realloc) return Response.json({ ok: false, error: "Please select Reallocated or Not Reallocated along with the remark." }, { status: 400 });
        const chk = await claimScopeCheck(env, me, claim);   // SECURITY: managers/coordinators only touch their own slice
        if (!chk.allowed) { await secLog(env, "scope-block", me.email, "ootat remark on out-of-scope claim " + claim, false); return Response.json({ ok: false, error: "This claim is not in your scope." }, { status: 403 }); }
        let remarks = {};
        if (true) { try { remarks = JSON.parse(await stGet(env, "ootat:remarks") || "{}"); } catch (e) { remarks = {}; } }
        const now = Date.now();
        for (const k in remarks) { if (remarks[k] && remarks[k].ts && (now - remarks[k].ts > 90 * 24 * 3600 * 1000)) delete remarks[k]; }  // keep 90 days
        let saved = null;
        if (text) { saved = { t: text, ra: realloc, by: me.email, name: me.name || me.email, ts: now }; remarks[claim] = saved; }
        else delete remarks[claim];   // empty text clears the remark
        await stSoft(env, "ootat:remarks", JSON.stringify(remarks));
        // ---- Feedback Calling queue sync ----
        if (env.USERS) {
          try {
            let fbq = {}; try { fbq = JSON.parse(await stGet(env, "fbq:map") || "{}"); } catch (e) { fbq = {}; }
            for (const k in fbq) { if (fbq[k] && fbq[k].addedTs && (now - fbq[k].addedTs > 180 * 24 * 3600 * 1000)) delete fbq[k]; } // keep 180 days
            const cs = s => String(s == null ? "" : s).slice(0, 120);
            /* HEALTH cases only — TP never enters the feedback queue. A PARTIALLY COMPLETED case
               (b.part) never enters it either: the case is not finished, so there is nobody to
               feedback-call yet — the remark itself still saves exactly like any other. */
            if (text && realloc === "not-reallocated" && !b.part && typeOfSub(b.sub) === "Health") {
              const ex = fbq[claim] || {};
              fbq[claim] = {
                claim, client: cs(b.client) || ex.client || "", sub: cs(b.sub) || ex.sub || "", insured: cs(b.insured) || ex.insured || "",
                manager: cs(b.manager) || ex.manager || "", fo: cs(b.fo) || ex.fo || "", state: cs(b.state) || ex.state || "",
                tatD: parseInt(b.tatD, 10) || ex.tatD || 0, remark: text,
                addedTs: ex.addedTs || now, addedBy: ex.addedBy || me.email,
                status: ex.status || "pending", fb: ex.fb || "", fbBy: ex.fbBy || "", fbTs: ex.fbTs || 0
              };
            } else { delete fbq[claim]; }   // reallocated (or remark cleared) -> leaves the feedback queue
            await stSoft(env, "fbq:map", JSON.stringify(fbq));
          } catch (e) { /* queue sync must never break remark saving */ }
        }
        await secLog(env, "admin-action", me.email, (text ? ("remark saved on " + claim + (realloc ? " [" + realloc + "]" : "")) : ("remark cleared on " + claim)), true);
        return Response.json({ ok: true, claim, remark: saved });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══ THE VERDICT — FRAUD OR GENUINE ═══════════════════════════════════ v32.8, 21-Sep-2026
       Sujit: "Fraud/genuinely add". Three doors. The guard stack is the ootat remark's, with
       one addition that matters more than the rest: AN INSURER LOGIN IS REFUSED OUTRIGHT, on
       reading as well as writing. See rule 2 at the head of verdict-index.js. */
    if (url.pathname === "/api/case/verdict" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (isClientRole(me)) { await secLog(env, "access-denied", me.email, "case verdict (insurer login)", true); return Response.json({ ok: false, error: "The investigation verdict is internal." }, { status: 403 }); }
        if (!canSeeCaseData(me)) { await secLog(env, "access-denied", me.email, "case verdict (no case access)", false); return Response.json({ ok: false, error: "You do not have access to case data." }, { status: 403 }); }
        if (!canMarkVerdict(me.role)) return Response.json({ ok: false, error: "Marking a case Genuine or Fraud is for admin, management and managers. A field officer is the man being checked, so he never marks his own case." }, { status: 403 });
        if (!allowRate("verdict:" + me.email, 200, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many verdicts this hour — please wait a little." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const claim = String((b && b.claim) || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const chk = await claimScopeCheck(env, me, claim);   // SECURITY: a manager marks only his own slice
        if (!chk.allowed) { await secLog(env, "scope-block", me.email, "verdict on out-of-scope claim " + claim, false); return Response.json({ ok: false, error: "This claim is not in your scope." }, { status: 403 }); }
        const saved = await setVerdict(env, {
          claim, verdict: b && b.verdict, reason: b && b.reason, trig: b && b.trig,
          client: b && b.client, sub: b && b.sub, insured: b && b.insured,
          state: b && b.state, officer: b && b.fo, manager: b && b.manager
        }, { email: me.email, name: me.name });
        await secLog(env, "case-verdict", me.email,
          claim + " marked " + saved.label + (saved.changed ? " (was " + saved.prevLabel + ")" : ""), true);
        return Response.json({ ok: true, claim, verdict: saved });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 400 }); }
    }
    if (url.pathname === "/api/case/verdict/clear" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (isClientRole(me)) return Response.json({ ok: false, error: "The investigation verdict is internal." }, { status: 403 });
        if (!canClearVerdict(me.role)) return Response.json({ ok: false, error: "Taking a verdict off a case is for admin and management. Anyone who may mark one can correct it by marking it again, which leaves the trail." }, { status: 403 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const claim = String((b && b.claim) || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const out = await clearVerdict(env, claim, b && b.reason, { email: me.email, name: me.name });
        await secLog(env, "case-verdict-cleared", me.email, claim + " was " + out.clearedLabel, true);
        return Response.json({ ok: true, claim, cleared: out });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 400 }); }
    }
    /* The trail on one case — who marked it what, when, and with what reason, newest first. */
    if (url.pathname === "/api/case/verdict/history" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (isClientRole(me)) return Response.json({ ok: false, error: "The investigation verdict is internal." }, { status: 403 });
        if (!canSeeCaseData(me)) return Response.json({ ok: false, error: "You do not have access to case data." }, { status: 403 });
        const claim = String(url.searchParams.get("claim") || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const chk = await claimScopeCheck(env, me, claim);
        if (!chk.allowed) return Response.json({ ok: false, error: "This claim is not in your scope." }, { status: 403 });
        return Response.json({ ok: true, claim, now: await verdictFor(env, claim), log: await verdictHistory(env, claim, 30),
          canMark: canMarkVerdict(me.role), canClear: canClearVerdict(me.role) });
      } catch (e) { return Response.json({ ok: false, error: String((e && e.message) || e) }, { status: 500 }); }
    }

    /* ══════════ OUT OF TAT — MEETING (the manager's out-of-TAT review meeting) ══════════
       Same out-of-TAT rule as the Completed From Field page — Motor TP beyond 30 days,
       Health beyond 4 days, Cashless beyond 24 hours — but this page lists ONLY the cases
       that are still open, because those are the ones the meeting is about. Motor TP and
       Health are kept apart by the page's own switch.

       In the meeting the manager asks each field officer about his pending case. The officer
       says when he will close it, or what the problem is. Both go in: a REMARK and the DATE
       he promised. Every entry is APPENDED to a permanent per-claim history in KV
       ("ootatmeet:notes") together with the typist's NAME and LOGIN ID, so at the next meeting
       the page shows exactly what was said last time, by whom, and whether he kept his word. */
    if (url.pathname === "/api/ootat/meeting" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        /* ── TWO PAGES, ONE ROAD — v13.8 ────────────────────────────────────────────────
           scope=followup asks for the cases still INSIDE their TAT (Manager Follow-up);
           anything else is the out-of-TAT meeting, exactly as before. Each page has its own
           access tick, because they are different jobs for different people: chasing work
           that is still healthy is a manager's daily round, and the out-of-TAT meeting is
           the escalation. Everything else below — the officer split, the parts, the notes,
           the attendance — is shared on purpose, so the two pages can never drift apart. */
        const followup = String(url.searchParams.get("scope") || "") === "followup";
        const need = followup ? "mgrfollow" : "ootatmeet";
        if (!canAccess(me, need)) { await secLog(env, "access-denied", me.email, (followup ? "manager follow-up" : "out-of-TAT meeting") + " (not permitted)", false); return Response.json({ ok: false, error: followup ? "You do not have access to IN TAT." : "You do not have access to the Out of TAT meeting." }, { status: 403 }); }
        const d = await getCases(env);
        let cases = d.cases;
        const foMap = await getFoStateMap(env).catch(() => null);
        /* PRODUCT ACCESS: if Motor TP and/or Health is ticked for him in Admin, he runs the meeting
           for that product and must see ALL of it — every state, every manager — ON TOP OF his own
           cases, which he never loses. With nothing ticked he stays inside his own cases, exactly
           as before, so nothing changes for the other managers. */
        const prods = meetProductsOf(me);
        const wide = prods.length > 0;
        /* The OUT OF TAT MANAGER has no cases of his own to be narrowed to — he runs the meeting
           for the whole company. He gets every case of the product(s) he was given, under every
           manager, in every state, and nothing else. */
        if (me.role === "ootat-manager") {
          cases = cases.filter(c => prods.includes(typeOfSub(c.subProduct)));
        } else if (isScopedRole(me.role)) {
          const own = scopeCases(cases, me, me.role === "coordinator" ? foMap : null);
          if (wide) { const seen = new Set(own); cases = own.concat(cases.filter(c => !seen.has(c) && prods.includes(typeOfSub(c.subProduct)))); }
          else cases = own;
        }
        const now = Date.now();
        /* v20.5 — Sujit, 03-Sep 5:22 pm, an "OHS Name" written in red beside a field officer's
           managers: "I need the head of the team's name — example Rahul Veera Raju." Every
           officer row now carries his team head's name, looked up from the Teams store with
           the same spelling-tolerant match the OHS fence uses. */
        const teamsAll = [];
        if (env.USERS) { try { const l = await env.USERS.list({ prefix: "team:" }); for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { const t = JSON.parse(v); teamsAll.push({ name: String(t.name || ""), head: String(t.head || ""), members: Array.isArray(t.members) ? t.members : [] }); } catch (e) {} } } } catch (e) {} }
        const teamHeadCache = {};
        const teamOf = (fo) => {
          const k = normName(fo); if (!k) return null;
          if (teamHeadCache[k] !== undefined) return teamHeadCache[k];
          let hit = null;
          for (const t of teamsAll) { if ([t.head].concat(t.members).some(m => m && sameManLoose(m, fo))) { hit = t; break; } }
          teamHeadCache[k] = hit; return hit;
        };
        // read-only split: the meeting page never writes the ootat:done memory
        const split = ootatSplit(cases, {}, now);
        let notes = {};
        if (true) { try { notes = JSON.parse(await stGet(env, "ootatmeet:notes") || "{}"); } catch (e) { notes = {}; } }
        /* ONE LINE PER FIELD OFFICER, judged on HIS OWN status — still open and still with him:
           Pending / Assigned / FO Accepted / FO Rejected / Partially Completed. On a claim
           shared by three men, the one who has already finished his part drops off and the two
           who have not are both called; before this, the dedup kept a single officer per claim
           and the other two were never asked about their work at all. */
        const mapRow = rec => {
          const c = rec.c, dh = tatDH(c.tat);
          const who = rec.fo || c.officerName || "";
          return {
            claim: c.claimNo, client: c.client || "", sub: c.subProduct || "", type: rec.type, insured: c.insured || "",
            /* v18.0 — THE HOSPITAL, on the row the meeting actually reads. The first attempt
               put it on /api/ootat's builder, which feeds a different page; this is the one
               behind the screenshot with the word written across it in red. Sent for every
               case, always a string — the page decides that a Health case with "" says
               "hospital not in the feed" rather than showing an empty space. */
            hospital: c.hospitalName || "",
            manager: c.manager || "", fo: who, state: foStateOf(who, foMap) || "",
            region: foRegionOf(who, foMap) || "",
            tatD: rec.days, tatH: dh[1] || "", limitD: ootatLimitFor(c.subProduct, rec.type),
            status: rec.foStatus || "", createdOn: c.createdOn || "",
            /* v22.3 — the two fields the connected-case check and the FO clock are read from.
               The trigger is SKD's own sentence, sent word for word and never trimmed here:
               the page shows it as written, and trigResolve() reads the claim numbers out of it. */
            trigger: c.trigger || "", foDone: c.foCompletedDate || "",
            pending: rec.foPending || [],              // the parts of the case still with HIM
            sharedWith: rec.sharedWith || [],          // the other officers on this same claim
            ohs: (function () { const t = teamOf(who); return t ? t.head : ""; })(),   // v20.5 — his team head's name
            team: (function () { const t = teamOf(who); return t ? t.name : ""; })(),
            partFo: rec.partFo || [],                    // men on this claim who have already finished
            waitingFor: rec.openFo || [],              // men the claim is still waiting on
            /* v13.2, 21-Aug-2026 — each waiting man's STATE, in the same order as waitingFor.
               Sujit, with Karnataka selected and the Partially Completed table open: "which
               state have selecting, that State's pending case is only need to be reflected."
               A state's meeting is about the cases PENDING in that state — so the page must
               be able to judge every row by where the claim is still waiting, not only by
               where the man who already finished happens to sit. An officer the directory
               does not know sends "" and the page says so instead of guessing. */
            waitingSt: (rec.openFo || []).map(n => foStateOf(n, foMap) || "")
          };
        };
        /* v13.8 — the same rows, from whichever side of the TAT line this page is about */
        /* v20.5 — Sujit, 3-Sep 5:10 pm: "I don't want any extra field officer reflected — only
           their cases." A shared claim keeps the case on the team head's page (scopeCases), but
           the meeting draws one line per MAN, and the partner from another team was getting his
           own line. The line survives only when the man on it is one of the head's own. */
        const source = (followup ? split.inAll : split.outAll).filter(rec => me.role !== "ohs" || isTeamMan(me, rec.fo));
        const out = source.filter(rec => isMeetingStatusW(rec.foStatus)).map(mapRow).sort((a, b) => b.tatD - a.tatD);
        /* THE PARTIALLY COMPLETED TABLE. These men have finished their own part, so there is nothing
           to ask THEM in the meeting — but the claim is still open, held by somebody else, and
           that is exactly what has to be seen separately. They are not completed and they are
           not pending; they are their own list. */
        const part = source.filter(rec => isPartCompletedW(rec.foStatus)).map(mapRow).sort((a, b) => b.tatD - a.tatD);
        /* v22.3 — every trigger read, every number it names answered from the open feed
           (d.cases — the WHOLE feed, not this reader's slice) and then from the CM archive */
        try { await trigResolve(env, out.concat(part), d.cases, now); } catch (e) {}
        const visible = {}; out.concat(part).forEach(r => { if (notes[r.claim]) visible[r.claim] = notes[r.claim]; });
        /* Which product buttons the page offers. A product he was GIVEN always gets its button.
           A product he was not given still appears if some of his OWN cases sit in it, so he never
           loses sight of his own work. Anyone without product access keeps both buttons as before. */
        /* v33.7 — FOUR PILLS, THE SAME FENCE. The ticks in Admin are still Motor TP and Health
           (MEET_PRODUCTS, typeOfSub) and every fence above still reads them exactly as before, so
           nobody gains or loses a case. What changes is the pill row: a Motor TP grant now offers
           Motor / TP · OD · MBV, because those are the buckets its cases fall into; a Health grant
           offers Health. Anyone unfenced sees all four. */
        const products = productPills(wide ? MEET_PRODUCTS.filter(t => prods.includes(t) || out.some(r => productParent(r.type) === t) || part.some(r => productParent(r.type) === t)) : MEET_PRODUCTS.slice());
        /* v13.2 — TODAY'S ATTENDANCE rides along, so the "Meeting attended" buttons open
           already knowing who was marked, by whom, and when. The register is kept per IST
           day in "ootatmeet:att"; only today's page is sent, because that is the meeting
           being run. Yesterday's register is reached through the daily Excel, not here. */
        let attStore = {};
        if (true) { try { attStore = JSON.parse(await stGet(env, "ootatmeet:att") || "{}"); } catch (e) { attStore = {}; } }
        const attDay = new Date(now + 19800000).toISOString().slice(0, 10);   // IST, same clock as every daily thing here
        /* v33.7 — ?product=… hands back one bucket's rows (the page filters by r.type itself;
           the connector asks here). The pill list is unchanged by it. */
        { const pk = productKey(url.searchParams.get("product") || "");
          if (pk) return Response.json({ ok: true, ts: now, scope: followup ? "followup" : "ootat", out: out.filter(r => r.type === pk), part: part.filter(r => r.type === pk), notes: visible, products, wideProducts: prods, att: attStore[attDay] || {}, attDay, product: pk }); }
        return Response.json({ ok: true, ts: now, scope: followup ? "followup" : "ootat", out, part, notes: visible, products, wideProducts: prods, att: attStore[attDay] || {}, attDay });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    if (url.pathname === "/api/ootat/meeting" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootatmeet") && !canAccess(me, "mgrfollow")) { await secLog(env, "access-denied", me.email, "out-of-TAT meeting note (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Out of TAT meeting." }, { status: 403 }); }
        if (!allowRate("meetnote:" + me.email, 400, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many meeting notes saved this hour — please wait a little." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const claim = String(b && b.claim || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        const text = String(b && b.text != null ? b.text : "").trim().slice(0, 500);
        const promised = String(b && b.promised || "").trim();      // YYYY-MM-DD — the date the field officer committed to
        if (promised && !/^\d{4}-\d{2}-\d{2}$/.test(promised)) return Response.json({ ok: false, error: "Invalid completion date." }, { status: 400 });
        if (!text && !promised) return Response.json({ ok: false, error: "Type a remark, or pick the date he promised." }, { status: 400 });
        // SECURITY: his own slice, PLUS every case of a product he was given (he is the one running that meeting)
        const chk = await meetScopeCheck(env, me, claim);
        if (!chk.allowed) { await secLog(env, "scope-block", me.email, "out-of-TAT meeting note on out-of-scope claim " + claim, false); return Response.json({ ok: false, error: "This claim is not in your scope." }, { status: 403 }); }
        let notes = {};
        if (true) { try { notes = JSON.parse(await stGet(env, "ootatmeet:notes") || "{}"); } catch (e) { notes = {}; } }
        const now = Date.now();
        // housekeeping: forget a claim once its newest meeting note is a year old
        for (const k in notes) { const hh = notes[k] && notes[k].h; const last = (hh && hh.length) ? hh[hh.length - 1].ts : 0; if (!last || now - last > 365 * 24 * 3600 * 1000) delete notes[k]; }
        const cs = s => String(s == null ? "" : s).slice(0, 120);
        const ex = notes[claim] || {};
        const hist = Array.isArray(ex.h) ? ex.h.slice() : [];
        // WHO TYPED IT is stored on every line: display name + the login ID it was typed from
        hist.push({ t: text, p: promised, by: me.email, name: me.name || me.email, ts: now });
        if (hist.length > 40) hist.splice(0, hist.length - 40);      // keep the 40 most recent meetings per claim
        notes[claim] = {
          cl: cs(b.client) || ex.cl || "", s: cs(b.sub) || ex.s || "", i: cs(b.insured) || ex.i || "",
          m: cs(b.manager) || ex.m || "", f: cs(b.fo) || ex.f || "", st: cs(b.state) || ex.st || "",
          ty: cs(b.type) || ex.ty || "", h: hist
        };
        await stPut(env, "ootatmeet:notes", JSON.stringify(notes));
        await secLog(env, "admin-action", me.email, "out-of-TAT meeting note on " + claim + (promised ? " [promised " + promised + "]" : ""), true);
        return Response.json({ ok: true, claim, note: notes[claim] });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    // Undo — removes only the LAST line of a claim's history, and only if the same person typed it.
    if (url.pathname === "/api/ootat/meeting/undo" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootatmeet") && !canAccess(me, "mgrfollow")) return Response.json({ ok: false, error: "You do not have access to the Out of TAT meeting." }, { status: 403 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const claim = String(b && b.claim || "").trim();
        if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
        let notes = {};
        if (true) { try { notes = JSON.parse(await stGet(env, "ootatmeet:notes") || "{}"); } catch (e) { notes = {}; } }
        const rec = notes[claim];
        if (!rec || !Array.isArray(rec.h) || !rec.h.length) return Response.json({ ok: false, error: "Nothing to undo on this claim." }, { status: 404 });
        const last = rec.h[rec.h.length - 1];
        if (me.role !== "admin" && String(last.by || "").toLowerCase() !== String(me.email || "").toLowerCase()) return Response.json({ ok: false, error: "Only " + (last.name || last.by) + " can remove that line." }, { status: 403 });
        rec.h.pop();
        if (!rec.h.length) delete notes[claim]; else notes[claim] = rec;
        await stPut(env, "ootatmeet:notes", JSON.stringify(notes));
        await secLog(env, "admin-action", me.email, "out-of-TAT meeting note removed on " + claim, true);
        return Response.json({ ok: true, claim, note: notes[claim] || null });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══════════ MEETING ATTENDANCE — "meeting attended, okay; if not…" ══════════════════
       v13.2, 21-Aug-2026. Sujit: "next to field officer name I need one button called
       MEETING ATTENDED — if meeting attended okay, if not — and a separate Excel for the
       meeting on a daily basis: whoever was available to the meeting, and whatever I have
       been updated the remark."

       So attendance is a REGISTER, kept per day the way a register is: one page per IST
       date in KV "ootatmeet:att", one line per field officer, and every mark remembers who
       pressed it and when. A mark is always for TODAY — the register is filled in the
       meeting, not backdated — and pressing the same answer again clears it, so a slip of
       the finger is undone by the same finger. The officer's name is squeezed to one key
       exactly the way the meeting page squeezes it (capitals, single spaces, no dots), so
       "Basavaraj M" and "BASAVARAJ  M." are one man here too. */
    if (url.pathname === "/api/ootat/meeting/attend" && request.method === "POST") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootatmeet") && !canAccess(me, "mgrfollow")) { await secLog(env, "access-denied", me.email, "meeting attendance (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Out of TAT meeting." }, { status: 403 }); }
        if (!allowRate("meetatt:" + me.email, 400, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many attendance marks this hour — please wait a little." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const foRaw = String(b && b.fo || "").replace(/\s+/g, " ").trim().slice(0, 120);
        if (!foRaw) return Response.json({ ok: false, error: "No field officer named." }, { status: 400 });
        const attended = String(b && b.attended || "").trim().toLowerCase();   // 'yes' | 'no' | '' = clear the mark
        if (attended && attended !== "yes" && attended !== "no") return Response.json({ ok: false, error: "Attendance can only be yes, no, or cleared." }, { status: 400 });
        const foKey = foRaw.replace(/[.,_]+/g, " ").replace(/\s+/g, " ").trim().toUpperCase();   // MUST match the page's mtFoKey
        let attStore = {};
        if (true) { try { attStore = JSON.parse(await stGet(env, "ootatmeet:att") || "{}"); } catch (e) { attStore = {}; } }
        const now = Date.now();
        const day = new Date(now + 19800000).toISOString().slice(0, 10);       // the register page is TODAY (IST), never a chosen date
        /* housekeeping: a register older than 200 days has been downloaded long ago if it was
           ever wanted — pages beyond that are dropped so this key can never grow without end */
        const keepFrom = new Date(now + 19800000 - 200 * 86400000).toISOString().slice(0, 10);
        for (const d in attStore) { if (d < keepFrom) delete attStore[d]; }
        const page = attStore[day] || {};
        if (attended) page[foKey] = { fo: foRaw, a: attended, by: me.email, name: me.name || me.email, ts: now };
        else delete page[foKey];
        if (Object.keys(page).length) attStore[day] = page; else delete attStore[day];
        await stPut(env, "ootatmeet:att", JSON.stringify(attStore));
        await meetAttRecord(env, day, foKey, foRaw, attended, me, now);   // v20.6 — the permanent register
        await secLog(env, "admin-action", me.email, "meeting attendance: " + foRaw + (attended ? (" marked " + (attended === "yes" ? "ATTENDED" : "NOT ATTENDED")) : " mark cleared") + " for " + day, true);
        return Response.json({ ok: true, day, att: attStore[day] || {} });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ── THE DAILY MEETING EXCEL — the register and the words, one day per file ──────────
       GET /api/ootat/meeting/day-xlsx?day=YYYY-MM-DD (no day = today, IST). One line per
       field officer; an officer whose meeting produced remarks gets one line PER REMARK
       with his attendance repeated beside each, so the sheet reads like the meeting went:
       who was in the room, who was not, what each man said, what date he promised, and who
       typed every word. An officer marked present who said nothing still gets his line —
       attendance is a fact even when the discussion moved on.

       A scoped login (manager / coordinator / client) gets HIS meeting's day, not the
       company's: his officers, his claims — judged the same way the meeting page itself is
       scoped, product grants included. Admin, boss and the Out-of-TAT manager get everything. */
    /* ── THE MONTHLY REGISTER — v20.6 ──────────────────────────────────────────────────
       GET /api/ootat/meeting/register-xlsx?from=YYYY-MM-DD&to=YYYY-MM-DD[&type=TP|Health]
       One line per officer per meeting day: attended / NOT attended / not marked, who marked
       it and when, his state, team head, managers and case count that day. A summary per
       officer follows the lines. Admin and boss only — it is the register somebody answers for. */
    if (url.pathname === "/api/ootat/meeting/register-xlsx" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (me.role !== "admin" && me.role !== "boss") { await secLog(env, "access-denied", me.email, "meeting register (admin/boss only)", false); return Response.json({ ok: false, error: "The attendance register is for admin and management." }, { status: 403 }); }
        if (!(await meetRegEnsure(env))) return Response.json({ ok: false, error: "The D1 database is not available, so the register cannot be read." }, { status: 501 });
        const isoOk = v => /^\d{4}-\d{2}-\d{2}$/.test(v);
        const today = new Date(Date.now() + 19800000).toISOString().slice(0, 10);
        let from = String(url.searchParams.get("from") || "").slice(0, 10), to = String(url.searchParams.get("to") || "").slice(0, 10);
        if (!isoOk(to)) to = today;
        if (!isoOk(from)) from = to.slice(0, 8) + "01";
        if (from > to) { const t = from; from = to; to = t; }
        const wantType = String(url.searchParams.get("type") || "").trim();
        const stamp = ts => { if (!ts) return ""; const d = new Date(Number(ts) + 19800000).toISOString(); return d.slice(0, 10) + " " + d.slice(11, 16); };
        const SEP = "";
        const ro = wantType
          ? await env.DB.prepare("SELECT * FROM meeting_roster WHERE day >= ?1 AND day <= ?2 AND type = ?3").bind(from, to, wantType).all()
          : await env.DB.prepare("SELECT * FROM meeting_roster WHERE day >= ?1 AND day <= ?2").bind(from, to).all();
        const at = await env.DB.prepare("SELECT * FROM meeting_att WHERE day >= ?1 AND day <= ?2").bind(from, to).all();
        const marks = {};
        ((at && at.results) || []).forEach(r => { marks[r.day + SEP + r.fokey] = r; });
        /* marks made before this register existed live only in the 200-day KV page — read them too */
        try {
          const attStore = JSON.parse(await stGet(env, "ootatmeet:att") || "{}");
          for (const dday in attStore) { if (dday < from || dday > to) continue; const page = attStore[dday] || {}; for (const k in page) { const kk = dday + SEP + k; if (!marks[kk]) { const m = page[k]; marks[kk] = { day: dday, fokey: k, fo: m.fo || k, a: m.a, by: m.by, name: m.name, ts: m.ts }; } } }
        } catch (e) {}
        const lines = {};
        ((ro && ro.results) || []).forEach(r => {
          const kk = r.day + SEP + r.fokey;
          if (!lines[kk]) lines[kk] = { day: r.day, fokey: r.fokey, fo: r.fo, state: r.state || "", ohs: r.ohs || "", managers: new Set(), types: new Set(), cases: 0 };
          const L = lines[kk]; L.cases += Number(r.cases || 0); if (r.type) L.types.add(r.type); String(r.managers || "").split(" · ").filter(Boolean).forEach(m => L.managers.add(m));
        });
        for (const kk in marks) { if (!lines[kk]) { const m = marks[kk]; lines[kk] = { day: m.day, fokey: m.fokey, fo: m.fo, state: "", ohs: "", managers: new Set(), types: new Set(), cases: 0, noRoster: true }; } }
        const list = Object.values(lines).map(L => Object.assign(L, { mark: marks[L.day + SEP + L.fokey] || null }));
        const attWord = L => L.mark ? (L.mark.a === "yes" ? "ATTENDED" : "NOT ATTENDED") : "NOT MARKED";
        const attRank = L => L.mark ? (L.mark.a === "yes" ? 2 : 0) : 1;
        list.sort((a, b) => a.day.localeCompare(b.day) || attRank(a) - attRank(b) || String(a.fo).localeCompare(String(b.fo)));
        const COLS = ["Meeting date", "Field officer", "State", "OHS team head", "Manager(s)", "Product", "Open cases that day", "Attendance", "Marked by", "Marked at (IST)", "Note"];
        const rows = list.map(L => [L.day, L.fo, L.state, L.ohs, [...L.managers].join(" · "), [...L.types].join(" + "), L.cases || "", attWord(L),
          L.mark ? (L.mark.name || L.mark.by || "") : "", L.mark ? stamp(L.mark.ts) : "",
          L.mark ? (L.mark.a === "no" ? (L.fo + " did not come — marked by " + (L.mark.name || L.mark.by || "")) : "") : (L.noRoster ? "" : "on the meeting list, nobody marked him")]);
        const sum = {};
        list.forEach(L => { const k = L.fokey; if (!sum[k]) sum[k] = { fo: L.fo, state: L.state, ohs: L.ohs, days: 0, yes: 0, no: 0, none: 0, noBy: {} }; const S = sum[k]; S.days++; if (!S.state && L.state) S.state = L.state; if (!S.ohs && L.ohs) S.ohs = L.ohs;
          if (!L.mark) S.none++; else if (L.mark.a === "yes") S.yes++; else { S.no++; const by = L.mark.name || L.mark.by || ""; S.noBy[by] = (S.noBy[by] || 0) + 1; } });
        const sumRows = Object.values(sum).sort((a, b) => (b.no - a.no) || (b.none - a.none) || String(a.fo).localeCompare(String(b.fo)));
        rows.push(["", "", "", "", "", "", "", "", "", "", ""]);
        rows.push(["SUMMARY " + from + " to " + to, "Field officer", "State", "OHS team head", "Meeting days", "Attended", "NOT attended", "Not marked", "Attendance %", "Not-attended marks by", ""]);
        sumRows.forEach(S => rows.push(["", S.fo, S.state, S.ohs, S.days, S.yes, S.no, S.none, S.days ? Math.round(S.yes * 100 / S.days) + "%" : "", Object.keys(S.noBy).map(n => n + " (" + S.noBy[n] + ")").join(" · "), ""]));
        if (!list.length) rows.unshift([from + " to " + to, "(no meeting day recorded in this window yet — the roster is written every hour from the day this version went live; marks made earlier are read from the meeting page's own memory)", "", "", "", "", "", "", "", "", ""]);
        await secLog(env, "admin-action", me.email, "meeting attendance register downloaded " + from + " to " + to + (wantType ? " " + wantType : ""), true);
        return await xlsxResponse(COLS, rows, "meeting-attendance-register-" + from + "-to-" + to + (wantType ? "-" + wantType.toLowerCase() : ""));
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    if (url.pathname === "/api/ootat/meeting/day-xlsx" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "ootatmeet") && !canAccess(me, "mgrfollow")) { await secLog(env, "access-denied", me.email, "meeting day Excel (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Out of TAT meeting." }, { status: 403 }); }
        const qd = String(url.searchParams.get("day") || "").slice(0, 10);
        const day = /^\d{4}-\d{2}-\d{2}$/.test(qd) ? qd : new Date(Date.now() + 19800000).toISOString().slice(0, 10);
        const keyOf = s => String(s == null ? "" : s).replace(/[.,_]+/g, " ").replace(/\s+/g, " ").trim().toUpperCase();
        const inDay = ts => ts && new Date(ts + 19800000).toISOString().slice(0, 10) === day;   // the same IST clock as the register
        const stamp = ts => { if (!ts) return ""; const d = new Date(ts + 19800000).toISOString(); return d.slice(0, 10) + " " + d.slice(11, 16); };
        let attStore = {}, notes = {};
        if (env.USERS) {
          try { attStore = JSON.parse(await stGet(env, "ootatmeet:att") || "{}"); } catch (e) { attStore = {}; }
          try { notes = JSON.parse(await stGet(env, "ootatmeet:notes") || "{}"); } catch (e) { notes = {}; }
        }
        const dayAtt = attStore[day] || {};
        /* the words typed THAT day, claim by claim, straight out of the permanent history */
        let lines = [];
        for (const claim in notes) {
          const rec = notes[claim]; if (!rec || !Array.isArray(rec.h)) continue;
          for (const x of rec.h) {
            if (!inDay(x.ts)) continue;
            lines.push({ claim, fo: rec.f || "", client: rec.cl || "", sub: rec.s || "", insured: rec.i || "",
              manager: rec.m || "", state: rec.st || "", text: x.t || "", promised: x.p || "", by: x.name || x.by || "", ts: x.ts });
          }
        }
        /* SCOPE — the same slice the meeting page itself would show this login. His own cases,
           plus every case of a product he was given; his officers are the men on those cases. */
        if (me.role !== "admin" && me.role !== "boss") {
          const prods = meetProductsOf(me);
          if (me.role === "ootat-manager" || isScopedRole(me.role)) {
            const d = await getCases(env);
            const foMap = me.role === "coordinator" ? await getFoStateMap(env).catch(() => null) : null;
            let mine;
            if (me.role === "ootat-manager") mine = d.cases.filter(c => prods.includes(typeOfSub(c.subProduct)));
            else {
              const own = scopeCases(d.cases, me, foMap);
              if (prods.length) { const seen = new Set(own); mine = own.concat(d.cases.filter(c => !seen.has(c) && prods.includes(typeOfSub(c.subProduct)))); }
              else mine = own;
            }
            const okClaims = new Set(), okFos = new Set();
            for (const c of mine) {
              okClaims.add(String(c.claimNo || "").trim());
              String(c.officerName || "").split(/[,/]+/).forEach(n => { const k = keyOf(n); if (k) okFos.add(k); });
            }
            lines = lines.filter(L => okClaims.has(String(L.claim).trim()) || okFos.has(keyOf(L.fo)));
            for (const k in dayAtt) { if (!okFos.has(k)) delete dayAtt[k]; }
          }
        }
        /* one section per officer: attendance first, then his remarks in the order they were typed */
        const officers = {};
        for (const k in dayAtt) officers[k] = { name: dayAtt[k].fo || k, att: dayAtt[k], lines: [] };
        for (const L of lines) {
          const k = keyOf(L.fo) || "(NO FIELD OFFICER)";
          if (!officers[k]) officers[k] = { name: L.fo || "(No field officer)", att: null, lines: [] };
          officers[k].lines.push(L);
        }
        const COLS = ["Meeting date", "Field officer", "State", "Meeting attended", "Marked by", "Marked at (IST)",
          "Claim number", "Client", "Sub product", "Insured", "Manager", "What the field officer said", "Date he promised", "Typed by", "Typed at (IST)"];
        const rows = [];
        Object.keys(officers).sort((a, b) => a.localeCompare(b)).forEach(k => {
          const o = officers[k];
          const attWord = o.att ? (o.att.a === "yes" ? "YES — attended" : "NO — not attended") : "(not marked)";
          const attBy = o.att ? (o.att.name || o.att.by || "") : "";
          const attAt = o.att ? stamp(o.att.ts) : "";
          const st = o.lines.length ? (o.lines[0].state || "") : "";
          if (!o.lines.length) rows.push([day, o.name, st, attWord, attBy, attAt, "", "", "", "", "", "", "", "", ""]);
          else o.lines.sort((a, b) => (a.ts || 0) - (b.ts || 0)).forEach(L =>
            rows.push([day, o.name, L.state || st, attWord, attBy, attAt, L.claim, L.client, L.sub, L.insured, L.manager, L.text, L.promised, L.by, stamp(L.ts)]));
        });
        /* an empty day says so in words — a sheet of bare headers reads as a broken download */
        if (!rows.length) rows.push([day, "(nothing was marked and nothing was typed on this day)", "", "", "", "", "", "", "", "", "", "", "", "", ""]);
        await secLog(env, "admin-action", me.email, "meeting day Excel downloaded for " + day, true);
        return await xlsxResponse(COLS, rows, "meeting-" + day);
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* ══════════ WEBHOOK SETUP — the Cloudflare trip, deleted ══════════════════════════
       Admin-only. Four doors, and the split between them is the point:

         GET    /api/webhook-setup            — is it on, where does the key live, when was
                                                it set. Returns the key MASKED and never in
                                                full, because this is the call the page makes
                                                on every load and a screenshot of a page load
                                                should not be able to leak it.
         POST   /api/webhook-setup/generate   — make a new one. Returns the full URL ONCE,
                                                so it can go straight to the clipboard.
         POST   /api/webhook-setup/reveal     — hand back the full URL again later. A
                                                separate, deliberate, logged press — losing
                                                the URL should not force a rotation, but
                                                reading it back should leave a trace.
         POST   /api/webhook-setup/off        — turn it off and forget the key.

       Rotation is destructive to a working integration: the moment a new key is stored, the
       URL sitting in the Acefone console is wrong and results stop arriving until it is
       repasted. That is not a thing to discover later, so the answer says so in words and
       the page repeats it before asking. ══════════ */
    /* ══════════ ACEFONE TOKEN — paste it once, from the portal ═══════════════════════
       Admin only. Three doors, and NO door hands the token back:
         GET  /api/acefone-setup        — is it set, where it lives, masked, who set it
         POST /api/acefone-setup/save   — { token } paste it in
         POST /api/acefone-setup/clear  — forget the portal's copy
       There is deliberately no "reveal". The webhook ADDRESS has to be read back because it
       gets pasted into Acefone; this token only ever travels the other way, so once it is in
       there is no honest reason for a browser to see it again — and every reason not to. */
    if (url.pathname.startsWith("/api/acefone-setup")) {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (me.role !== "admin") { await secLog(env, "access-denied", me.email, "acefone token setup (admin only)", false); return Response.json({ ok: false, error: "Only an admin can change the Acefone token." }, { status: 403 }); }
      const cur = await acefoneTokenOf(env);

      if (url.pathname === "/api/acefone-setup" && request.method === "GET") {
        return Response.json({ ok: true, on: !!cur.token, source: cur.source, masked: maskKey(cur.token),
          setBy: cur.setBy, setTs: cur.setTs,
          /* the portal cannot replace a Cloudflare variable, and must not pretend it can */
          canEdit: cur.source !== "cloudflare", storage: !!env.USERS });
      }
      if (url.pathname === "/api/acefone-setup/save" && request.method === "POST") {
        if (!env.USERS) return Response.json({ ok: false, error: "Storage is not available, so the token cannot be saved here." }, { status: 501 });
        if (cur.source === "cloudflare") return Response.json({ ok: false, error: "A Worker variable ACEFONE_API_TOKEN is already set, and that one wins. Change it in Cloudflare, or delete it there first." }, { status: 409 });
        if (!allowRate("acetok:" + me.email, 12, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many token changes this hour." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { b = {}; }
        /* Acefone tokens are long opaque strings. Trim, and refuse the two things a tired
           person actually pastes by mistake: nothing at all, and the placeholder text. */
        const tok = String((b && b.token) || "").trim();
        if (tok.length < 20) return Response.json({ ok: false, error: "That does not look like an Acefone token — they are long. Copy the whole value from API Connect → API Tokens." }, { status: 400 });
        if (/^[<{].*[>}]$/.test(tok) || /your.?token|paste.?here|api.?token/i.test(tok)) return Response.json({ ok: false, error: "That is placeholder text, not a token. Paste the real value from Acefone." }, { status: 400 });
        await env.USERS.put(ACE_KV_KEY, JSON.stringify({ token: tok, setBy: me.name || me.email, setTs: Date.now() }));
        await secLog(env, "admin-action", me.email, "acefone API token " + (cur.token ? "replaced" : "saved") + " in the portal", true);
        return Response.json({ ok: true, on: true, source: "portal", masked: maskKey(tok), replaced: !!cur.token });
      }
      if (url.pathname === "/api/acefone-setup/clear" && request.method === "POST") {
        if (!env.USERS) return Response.json({ ok: false, error: "Storage is not available." }, { status: 501 });
        await env.USERS.delete(ACE_KV_KEY);
        await secLog(env, "admin-action", me.email, "acefone API token removed from the portal", true);
        const after = await acefoneTokenOf(env);
        return Response.json({ ok: true, on: !!after.token, source: after.source });
      }
      return Response.json({ ok: false, error: "Unknown acefone-setup action." }, { status: 404 });
    }

    /* ══════════ THE PHONE INSIDE THE PORTAL — WebRTC, SIP over WSS ═══════════════════════
       Sujit, 19-Aug-2026, on the live site: "Calling need to work in this my portal itself.
       Need to ring here itself. I don't want to go one more time to that call centre website
       — need to integrate in this website itself."
       The only way a web page can carry real telephone audio is a WebRTC registration
       against the phone company's own gateway. The portal cannot invent that gateway —
       Acefone has to answer it. So this stores exactly what Acefone support hands over
       (their WSS server address, the SIP domain, and a SIP username + password for each
       extension), and the calling pages then register the browser AS that extension: press
       Call, the rings-first leg lands inside the page, answers itself, and the voice runs
       on the computer's mic and speaker. Until Acefone provides those details, nothing here
       is set and every screen behaves exactly as before — the feature waits, it never fakes.
         GET  /api/webphone-setup          admin — what is saved, passwords masked
         POST /api/webphone-setup/save     admin — { wss, realm, agents:[{num,user,pass,name}] }
         POST /api/webphone-setup/clear    admin — forget it all
         GET  /api/webphone/creds?agent=N  calling-page members — that one extension's login.
       The creds door hands the browser the SIP password, because the browser is the thing
       that must sign in — a SIP line cannot be registered without it. Anyone who can read it
       already holds calling-page access and can place calls as themselves on these very
       pages; the Settings card says this in words rather than leaving it to be found. */
    const WEBPHONE_KV_KEY = "webphone:cfg";
    if (url.pathname === "/api/webphone/creds" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!(canAccess(me, "feedback") || canAccess(me, "appointment"))) return Response.json({ ok: false, error: "You do not have access to the calling pages." }, { status: 403 });
      if (!allowRate("wpcred:" + me.email, 600, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many phone-credential reads this hour." }, { status: 429 });
      const num = String(url.searchParams.get("agent") || "").replace(/[^\d]/g, "");
      if (!num) return Response.json({ ok: true, on: false });
      let cfg = null; if (env.USERS) { try { cfg = JSON.parse(await env.USERS.get(WEBPHONE_KV_KEY) || "null"); } catch (e) { cfg = null; } }
      const a = cfg && cfg.wss && cfg.realm && cfg.agents ? cfg.agents[num] : null;
      if (!a || !a.user || !a.pass) return Response.json({ ok: true, on: false });
      return Response.json({ ok: true, on: true, wss: cfg.wss, realm: cfg.realm, user: a.user, pass: a.pass, name: a.name || "" });
    }
    if (url.pathname.startsWith("/api/webphone-setup")) {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (me.role !== "admin") { await secLog(env, "access-denied", me.email, "webphone setup (admin only)", false); return Response.json({ ok: false, error: "Only an admin can change the portal phone." }, { status: 403 }); }
      if (!env.USERS) return Response.json({ ok: false, error: "Storage is not available, so the portal phone cannot be configured." }, { status: 501 });
      let cfg = null; try { cfg = JSON.parse(await env.USERS.get(WEBPHONE_KV_KEY) || "null"); } catch (e) { cfg = null; }

      if (url.pathname === "/api/webphone-setup" && request.method === "GET") {
        const agents = [];
        if (cfg && cfg.agents) for (const k in cfg.agents) { const a = cfg.agents[k]; agents.push({ num: k, user: a.user || "", name: a.name || "", passSet: !!a.pass }); }
        return Response.json({ ok: true, on: !!(cfg && cfg.wss && cfg.realm && agents.length),
          wss: (cfg && cfg.wss) || "", realm: (cfg && cfg.realm) || "", agents,
          setBy: (cfg && cfg.setBy) || "", setTs: (cfg && cfg.setTs) || 0 });
      }
      if (url.pathname === "/api/webphone-setup/save" && request.method === "POST") {
        if (!allowRate("wpsave:" + me.email, 30, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many changes this hour." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        const wss = String((b && b.wss) || "").trim();
        const realm = String((b && b.realm) || "").trim();
        if (!/^wss:\/\/.+/.test(wss)) return Response.json({ ok: false, error: "The server address must start with wss:// — that is the WebSocket address Acefone support gives for WebRTC SIP." }, { status: 400 });
        if (!realm || /\s/.test(realm)) return Response.json({ ok: false, error: "The SIP domain looks wrong — it is a bare domain like voice.example.com, with no spaces." }, { status: 400 });
        const inA = Array.isArray(b && b.agents) ? b.agents.slice(0, 30) : [];
        const agents = {};
        for (const r of inA) {
          const num = String((r && r.num) || "").replace(/[^\d]/g, "");
          const user = String((r && r.user) || "").trim().slice(0, 80);
          if (!num || num.length < 3 || !user) continue;
          /* an empty password on an existing row means "keep the one already saved" — a
             person editing a username must not be forced to re-find every password */
          let pass = String((r && r.pass) || "").slice(0, 120);
          if (!pass && cfg && cfg.agents && cfg.agents[num] && cfg.agents[num].pass && cfg.agents[num].user === user) pass = cfg.agents[num].pass;
          if (!pass) continue;
          agents[num] = { user, pass, name: String((r && r.name) || "").trim().slice(0, 60) };
        }
        if (!Object.keys(agents).length) return Response.json({ ok: false, error: "No usable extension rows — each needs the extension number, the SIP username and the SIP password from Acefone." }, { status: 400 });
        await env.USERS.put(WEBPHONE_KV_KEY, JSON.stringify({ wss, realm, agents, setBy: me.name || me.email, setTs: Date.now() }));
        await secLog(env, "admin-action", me.email, "portal webphone saved — " + Object.keys(agents).length + " extension(s)", true);
        return Response.json({ ok: true, saved: Object.keys(agents).length });
      }
      if (url.pathname === "/api/webphone-setup/clear" && request.method === "POST") {
        await env.USERS.delete(WEBPHONE_KV_KEY);
        await secLog(env, "admin-action", me.email, "portal webphone configuration removed", true);
        return Response.json({ ok: true });
      }
      return Response.json({ ok: false, error: "Unknown webphone-setup action." }, { status: 404 });
    }

    if (url.pathname.startsWith("/api/webhook-setup")) {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (me.role !== "admin") { await secLog(env, "access-denied", me.email, "webhook setup (admin only)", false); return Response.json({ ok: false, error: "Only an admin can change the call-results webhook." }, { status: 403 }); }
      if (!env.USERS) return Response.json({ ok: false, error: "Storage is not available, so the key cannot be saved here." }, { status: 501 });
      const cur = await webhookKeyOf(env);

      if (url.pathname === "/api/webhook-setup" && request.method === "GET") {
        return Response.json({
          ok: true, on: !!cur.key, source: cur.source,
          masked: maskKey(cur.key), setBy: cur.setBy, setTs: cur.setTs,
          /* the env-var case can be READ but not rotated from here — the portal does not own
             that value and must not pretend it can replace it */
          canRotate: cur.source !== "cloudflare",
          origin: url.origin
        });
      }
      if (url.pathname === "/api/webhook-setup/generate" && request.method === "POST") {
        if (!allowRate("hookgen:" + me.email, 12, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many key changes this hour." }, { status: 429 });
        const key = newWebhookKey();
        await env.USERS.put(HOOK_KV_KEY, JSON.stringify({ key, setBy: me.name || me.email, setTs: Date.now() }));
        await secLog(env, "admin-action", me.email, "acefone webhook key " + (cur.key ? "ROTATED" : "created"), true);
        return Response.json({ ok: true, rotated: !!cur.key, url: webhookUrlFor(url.origin, key), masked: maskKey(key) });
      }
      if (url.pathname === "/api/webhook-setup/reveal" && request.method === "POST") {
        if (!allowRate("hookrev:" + me.email, 30, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many reveals this hour." }, { status: 429 });
        if (!cur.key) return Response.json({ ok: false, error: "No key yet — press Generate first." }, { status: 404 });
        await secLog(env, "admin-action", me.email, "acefone webhook URL read back", true);
        return Response.json({ ok: true, url: webhookUrlFor(url.origin, cur.key), source: cur.source });
      }
      if (url.pathname === "/api/webhook-setup/off" && request.method === "POST") {
        await env.USERS.delete(HOOK_KV_KEY);
        await secLog(env, "admin-action", me.email, "acefone webhook key removed", true);
        /* honest about what turning it off does NOT do: a Cloudflare variable is not ours to delete */
        const after = await webhookKeyOf(env);
        return Response.json({ ok: true, on: !!after.key, source: after.source,
          note: after.key ? "The portal's key is gone, but the Worker variable FEEDBACK_WEBHOOK_KEY is still set and is now in use. Remove it in Cloudflare to switch the webhook off completely." : "" });
      }
      return Response.json({ ok: false, error: "Unknown webhook-setup action." }, { status: 404 });
    }

    /* ══════════ FEEDBACK CALLING — cases marked "Not Reallocated" land here.
       The feedback team calls and records how the field visit went.
       Every call is placed BY THIS PORTAL on the account's own Acefone key
       (ACEFONE_API_TOKEN). No case, name or phone number is sent to any outside
       calling service — that path has been removed. ══════════ */
    if (url.pathname === "/api/feedback" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "feedback")) { await secLog(env, "access-denied", me.email, "feedback (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Feedback Calling." }, { status: 403 }); }
      let fbq = {}; if (true) { try { fbq = JSON.parse(await stGet(env, "fbq:map") || "{}"); } catch (e) { fbq = {}; } }
      let list = Object.keys(fbq).map(k => fbq[k]).filter(x => typeOfSub(x.sub) === "Health").sort((a, b) => (b.addedTs || 0) - (a.addedTs || 0));   // HEALTH only
      /* v20.4 — THE QUEUE IS FENCED LIKE EVERY OTHER PAGE. Sujit, 2-Sep-2026: a scoped login
         (state coordinator, team head, manager) must see only his own cases "in all whatever
         I'm giving the access". Each queue entry carries the manager and the field officer it
         was filed with, so the same scopeCases() fence runs over the queue as over the feed —
         a coordinator keeps his states' cases, a team head his men's, a manager his own.
         Admin, boss and the call-centre role keep the whole queue, which is their job. */
      if (isScopedRole(me.role)) {
        const foMapFb = me.role === "coordinator" ? await getFoStateMap(env).catch(() => null) : null;
        const pseudo = list.map(x => ({ claimNo: x.claim, manager: x.manager || "", officerName: x.fo || "", subProduct: x.sub || "", client: x.client || "" }));
        const keep = new Set(scopeCases(pseudo, me, foMapFb).map(c => c.claimNo));
        list = list.filter(x => keep.has(x.claim));
      }
      // AUTO-FILL the insured's phone from the live SKD feed ("Contact number" in the old portal).
      // Only fills EMPTY boxes — a number typed by the team is never overwritten, and stays editable.
      try {
        const dfeed = await getCases(env);
        const cmap = {};
        dfeed.cases.forEach(c => { const k = claimKey(c.claimNo); const p = String(c.contactNo || "").replace(/[^\d]/g, ""); if (k && p.length >= 10) cmap[k] = p.slice(0, 13); });
        list.forEach(x => { if (!x.phone) { const p = cmap[claimKey(x.claim)]; if (p) x.phone = p; } });
      } catch (e) { /* SKD unreachable — the queue still works, numbers just stay blank */ }
      /* whose case is whose — each row says its holder, and whether that holder is YOU,
         worked out here because the browser is never trusted to know its own name */
      const myNameFb = me.name || me.email;
      list.forEach(x => { if (x) { x.owner = x.owner || ""; x.ownedByMe = !!x.owner && x.owner === myNameFb; } });
      const aceTok = !!(await acefoneTokenOf(env)).token;
      return Response.json({ ok: true, list, apiConfigured: aceTok, acefone: aceTok, callerIds: acefoneCallerIds(env), agents: acefoneAgents(env) });
    }
    /* Acefone click-to-call: rings the feedback agent's phone first, then connects the insured.
       Needs Worker variables: ACEFONE_API_TOKEN (secret) + optional ACEFONE_CALLER_ID / ACEFONE_C2C_URL. */
    if (url.pathname === "/api/feedback/call" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "feedback")) return Response.json({ ok: false, error: "You do not have access to Feedback Calling." }, { status: 403 });
      if (!(await acefoneTokenOf(env)).token) return Response.json({ ok: false, error: "Acefone is not connected yet — open Settings → Acefone calling in the portal and paste the token from Acefone console → API Connect → API Tokens." }, { status: 501 });
      if (!allowRate("fbcall:" + me.email, 60, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many calls this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const digits = s => String(s == null ? "" : s).replace(/[^\d]/g, "");
      let phone = digits(b.phone); const agent = String(b.agent || "").trim().slice(0, 30);
      if (!agent) return Response.json({ ok: false, error: "Enter your agent number (the phone that rings first)." }, { status: 400 });
      if (!phone) {   // empty box → pull the Contact number straight from the SKD case page (same field the old portal shows)
        try { const rfc = await skdGetCase(env, claim); const rawc = await rfc.json(); phone = digits(contactFromCaseJson(rawc)).slice(0, 13); } catch (e) { }
      }
      if (phone.length < 10 || phone.length > 13) return Response.json({ ok: false, error: "No usable phone number — SKD has no contact number on this case either. Type the insured's 10-digit mobile, then press Call." }, { status: 400 });
      let fbq = {}; if (true) { try { fbq = JSON.parse(await stGet(env, "fbq:map") || "{}"); } catch (e) { fbq = {}; } }
      if (!fbq[claim]) return Response.json({ ok: false, error: "This claim is not in the feedback queue." }, { status: 404 });
      try {
        const dial = await acefoneDial(env, { agent: agent, dest: phone, callerId: b.callerId, tag: claim });
        if (dial.self) return Response.json({ ok: false, error: "You are trying to ring your own phone twice. “Who is calling?” is set to " + dial.agent + ", and that is also the number being called. Your phone rings, you answer, and then Acefone dials the very same phone — it is busy, so you hear nothing. Put the customer's number in the box next to Call, or pick a different phone under “Who is calling?”." }, { status: 400 });
        const okCall = dial.ok;
        /* WHOSE ACCOUNT — resolved from the account's own agent list, stamped on the attempt
           and on the history line, so a row can always say which of the six placed it. */
        const who = acefoneWho(env, dial.agent);
        const stamp = { ts: Date.now(), by: me.name || me.email, agent: dial.agent,
          agentName: who.name, agentKind: who.kind, agentKnown: who.known,
          to: dial.dest, status: okCall ? "initiated" : "failed", msg: dial.msg.slice(0, 220) };
        fbq[claim].phone = phone;
        fbq[claim].lastCall = stamp;
        fbq[claim].callCount = (fbq[claim].callCount || 0) + 1;   // record how many times we called
        const clg = Array.isArray(fbq[claim].callLog) ? fbq[claim].callLog : [];
        clg.push(Object.assign({}, stamp));
        fbq[claim].callLog = clg.slice(-20);
        await stSoft(env, "fbq:map", JSON.stringify(fbq));
        await secLog(env, "admin-action", me.email, "feedback call " + (okCall ? "started" : "FAILED") + " on " + claim + " from " + (acefoneWhoLabel(who) || "?"), true);
        if (!okCall) return Response.json({ ok: false, error: "Acefone did not accept the call — " + dial.msg }, { status: 502 });
        return Response.json({ ok: true, entry: fbq[claim], calling: { agent: dial.agent, agentName: who.name, agentKind: who.kind, agentKnown: who.known, who: acefoneWhoLabel(who), to: dial.dest, from: (dial.sent && dial.sent.caller_id) || "", msg: dial.msg } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 502 }); }
    }
    /* "Test my calling" — the same dial, with NO claim and NO queue behind it.
       The feedback queue is often empty, so without this there is no way at all to
       find out why a call did not connect. Two modes:
         check  — sends nothing to Acefone, just shows what WOULD be sent
         live   — places one real call and waits for Acefone's true answer (async 0) */
    if (url.pathname === "/api/acefone/test" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!(canAccess(me, "feedback") || canAccess(me, "appointment"))) return Response.json({ ok: false, error: "You do not have access to the calling pages." }, { status: 403 });
      let b; try { b = await request.json(); } catch (e) { b = {}; }
      const live = !!(b && b.live);
      const agentN = aceNumber(b && b.agent), destN = aceNumber(b && b.phone);
      const pick = acefoneCid(env, b && b.callerId);
      const whoT = acefoneWho(env, agentN);
      const report = {
        agent: agentN || "(empty)",
        /* the account this test would go out on, named — a bare 0602256780003 tells nobody
           whose phone is about to ring, and that is the whole complaint */
        agentName: whoT.name, agentKind: whoT.kind, agentKnown: whoT.known,
        who: acefoneWhoLabel(whoT),
        to: destN || "(empty)",
        from: pick.cid || "(account default)",
        fromNote: pick.note,
        tokenSet: !!(await acefoneTokenOf(env)).token,
        /* asks the SAME resolver the webhook itself asks. Reading env.FEEDBACK_WEBHOOK_KEY
           directly here would have this report say "webhook off" the moment the key moved
           into the portal — a second opinion about the same fact, which is how a screen ends
           up confidently wrong. */
        webhookSet: !!(await webhookKeyOf(env)).key,
        sameNumber: !!(agentN && destN && agentN === destN),
        timeout: Number(env.ACEFONE_CALL_TIMEOUT || 45)
      };
      if (!(await acefoneTokenOf(env)).token) return Response.json({ ok: false, report, error: "Acefone is not connected — paste the token on Settings → Acefone calling." }, { status: 501 });
      if (!live) return Response.json({ ok: true, live: false, report });

      /* ── THE SELF TEST — "need to call me for testing" ─────────────────────────────────
         Sujit, 18-Aug-2026, after an afternoon of test calls that needed a second phone he
         did not have: "Need to ask for whom you have to call. I will select my number and
         once I'll dial it. Need to call me for testing."
         So the test is now ONE phone: he names the phone that should ring, Acefone rings
         it, and the ringing IS the pass. Mechanics: the named number is used as BOTH legs
         with the dial layer's selfTest flag. His phone rings (leg one — the test), he
         answers, Acefone dials the same busy line (leg two) and he hears a busy tone —
         which the screen tells him to EXPECT, so an expected noise cannot be read as a
         fault. Three rules:
           · an EXTENSION is refused here in words — an extension is a handset somewhere
             else, and a self test that rings somebody else's desk tests nothing of his;
           · the dial is fire-and-forget, never sync — a waited-out self test would report
             the busy second leg as a FAILURE when the ringing first leg was the whole
             point, and a test that fails on success teaches people to ignore it;
           · every real call path keeps the same-number refusal untouched. */
      if (b && b.selfTest) {
        const ring = aceNumber(b.phone);
        if (!ring || ring.replace(/\D/g, "").length < 10) return Response.json({ ok: false, report, error: "Type the phone that should ring — usually your own mobile, 10 digits." }, { status: 400 });
        if (/^0\d{10,}$/.test(ring)) return Response.json({ ok: false, report, error: "“" + ring + "” is an Acefone extension, not a phone. A self test must ring a phone YOU are holding — type your own mobile." }, { status: 400 });
        if (!allowRate("acetest:" + me.email, 12, 60 * 60 * 1000)) return Response.json({ ok: false, report, error: "Too many test calls this hour — 12 is the limit." }, { status: 429 });
        try {
          const dial = await acefoneDial(env, { agent: ring, dest: ring, callerId: b && b.callerId, tag: "portal-selftest", selfTest: true });
          await secLog(env, "admin-action", me.email, "acefone SELF test " + (dial.ok ? "OK" : "FAILED") + " -> " + ring, true);
          report.selfTest = true; report.ring = ring; report.sent = dial.sent; report.msg = dial.msg; report.http = dial.http;
          return Response.json({ ok: !!dial.ok, live: true, report, error: dial.ok ? "" : ("Acefone says: " + dial.msg) });
        } catch (e) { return Response.json({ ok: false, report, error: "Could not reach Acefone — " + String(e && e.message ? e.message : e) }, { status: 502 }); }
      }

      if (!agentN) return Response.json({ ok: false, report, error: "Pick who is calling first — that phone rings before anything else happens." }, { status: 400 });
      if (!destN || destN.length < 10) return Response.json({ ok: false, report, error: "Type the number to test-call (10 digits)." }, { status: 400 });
      if (report.sameNumber) return Response.json({ ok: false, report, error: "Both legs are the same phone (" + agentN + "). Acefone would ring you, you would answer, and then it would dial that same phone — busy, so silence. Use a SECOND phone as the number to call." }, { status: 400 });
      if (!allowRate("acetest:" + me.email, 12, 60 * 60 * 1000)) return Response.json({ ok: false, report, error: "Too many test calls this hour — 12 is the limit." }, { status: 429 });
      try {
        let dial;
        /* Ask for the true outcome first (async 0). If this account will not do a
           synchronous call, fall back to the ordinary fire-and-forget one so the test
           still puts a real call through instead of just failing. */
        try { dial = await acefoneDial(env, { agent: agentN, dest: destN, callerId: b && b.callerId, tag: "portal-test", sync: true, probe: true }); }
        catch (e1) { dial = null; }
        if (!dial || (!dial.ok && /timeout|abort|network|fetch/i.test(dial.msg || ""))) {
          const quick = await acefoneDial(env, { agent: agentN, dest: destN, callerId: b && b.callerId, tag: "portal-test" });
          quick.msg = (quick.msg || "") + " (Acefone accepted the call but would not wait for the result — watch the two phones.)";
          dial = quick;
        }
        await secLog(env, "admin-action", me.email, "acefone test call " + (dial.ok ? "OK" : "FAILED") + " -> " + destN, true);
        report.sent = dial.sent; report.msg = dial.msg; report.http = dial.http;
        return Response.json({ ok: !!dial.ok, live: true, report, error: dial.ok ? "" : ("Acefone says: " + dial.msg) });
      } catch (e) { return Response.json({ ok: false, report, error: "Could not reach Acefone — " + String(e && e.message ? e.message : e) }, { status: 502 }); }
    }
    /* THE CALLING LISTING — Acefone's own record of recent calls, fetched on demand.
       7-Aug-2026: a call came back "Originate successfully queued" and his phone never
       rang. "Queued" only means Acefone ACCEPTED the order — whether the phone was then
       actually rung is written nowhere in the portal, because the result webhook is off.
       This asks Acefone's records API directly: every call it really made in the window,
       with its own status, reason, seconds and recording. Two truths it can tell that
       nothing else can: a queued call MISSING from this list never became a call at all
       (died inside Acefone — account-side), and a call marked missed with 0 seconds was
       rung but never answered. The API token never leaves the worker. */
    if (url.pathname === "/api/acefone/records") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!(canAccess(me, "feedback") || canAccess(me, "appointment"))) return Response.json({ ok: false, error: "You do not have access to the calling pages." }, { status: 403 });
      if (!(await acefoneTokenOf(env)).token) return Response.json({ ok: false, error: "Acefone is not connected — paste the token on Settings → Acefone calling." }, { status: 501 });
      if (!allowRate("acerec:" + me.email, 30, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many listing reads this hour." }, { status: 429 });
      const hoursQ = Number(url.searchParams.get("hours"));
      const hours = (isFinite(hoursQ) && hoursQ >= 1 && hoursQ <= 168) ? hoursQ : 24;
      const fmtIST = ms => { const d = new Date(ms + 19800000).toISOString(); return d.slice(0, 10) + " " + d.slice(11, 19); };
      const now = Date.now();
      const winFrom = fmtIST(now - hours * 3600000), winTo = fmtIST(now);
      const base = env.ACEFONE_RECORDS_URL || "https://api.acefone.in/v1/call/records";
      try {
        const r = await fetchT(base + "?from_date=" + encodeURIComponent(winFrom) + "&to_date=" + encodeURIComponent(winTo) + "&page=1&limit=100",
          { headers: { "Authorization": String((await acefoneTokenOf(env)).token), "Accept": "application/json" } }, 20000);
        const text = await r.text();
        let j = null; try { j = JSON.parse(text); } catch (e) { j = null; }
        if (!r.ok || !j) {
          return Response.json({ ok: false, http: r.status, window: { from: winFrom, to: winTo },
            error: "Acefone's records API answered " + r.status + " — " + String(text || "").replace(/\s+/g, " ").trim().slice(0, 200) });
        }
        const list = Array.isArray(j.data) ? j.data : (Array.isArray(j.results) ? j.results : (Array.isArray(j.records) ? j.records : (Array.isArray(j) ? j : [])));
        const P = (o, keys) => { for (const k of keys) { const v = o && o[k]; if (v !== undefined && v !== null && String(v).trim() !== "") return String(v); } return ""; };
        const rows = list.map(c => ({
          when: P(c, ["date", "time", "call_time", "start_stamp", "created_at", "timestamp"]),
          agent: P(c, ["agent_number", "agent", "answered_agent", "agent_name", "accountid"]),
          /* WHOSE ACCOUNT. Acefone sometimes sends a name of its own; when it does not, the
             number is looked up in this account's agent list. Either way the row can say who
             booked the call instead of showing thirteen digits nobody can read. */
          agentName: (() => {
            const w = acefoneWho(env, P(c, ["agent_number", "agent", "answered_agent", "accountid"]));
            return w.known ? w.name : P(c, ["agent_name", "agentname", "user_name", "username"]);
          })(),
          customer: P(c, ["client_number", "customer_number", "destination_number", "client", "callerid"]),
          from: P(c, ["did_number", "did", "caller_id", "clid", "source"]),
          status: P(c, ["status", "call_status", "disposition", "leg_status"]),
          reason: P(c, ["hangup_cause", "reason", "hangup_reason", "failure_reason", "description"]),
          seconds: P(c, ["call_duration", "duration", "answered_seconds", "billsec", "conversation_duration"]),
          recording: P(c, ["recording_url", "recording", "call_recording"]),
          /* the claim number we stamped on the call when we placed it — this is what lets a
             recording find its way back to its own case without anybody matching by hand */
          tag: P(c, ["custom_identifier", "customIdentifier", "custom_id", "tag"]),
          id: P(c, ["call_id", "uuid", "id", "callid"])
        }));
        /* the column names Acefone actually sent — names only, so an unexpected shape can
           be read off the screen instead of guessed at */
        const fields = (list.length && list[0] && typeof list[0] === "object") ? Object.keys(list[0]).slice(0, 60) : [];
        /* "WHICH ACCOUNT ARE THEY BOOKING ON" — the same rows, counted per account. Answered
           is counted separately from placed, because six calls that nobody picked up is not
           the same day's work as six that connected, and one number would hide that. */
        const tally = {};
        rows.forEach(r2 => {
          const key = (r2.agentName || "") + "|" + (r2.agent || "");
          const t = tally[key] || (tally[key] = { name: r2.agentName || "", num: r2.agent || "", calls: 0, answered: 0, seconds: 0 });
          t.calls++;
          const s = Number(String(r2.seconds || "0").replace(/[^\d.]/g, "")) || 0;
          const missed = /miss|fail|cancel|noanswer|no_answer|busy/i.test((r2.status || "") + " " + (r2.reason || ""));
          if (!missed && s > 0) { t.answered++; t.seconds += s; }
        });
        const byAccount = Object.keys(tally).map(k => tally[k]).sort((a, b) => b.calls - a.calls);
        return Response.json({ ok: true, hours, window: { from: winFrom, to: winTo }, total: (j.count != null ? j.count : rows.length), rows, byAccount, fields });
      } catch (e) {
        return Response.json({ ok: false, window: { from: winFrom, to: winTo }, error: String(e && e.message ? e.message : e) }, { status: 502 });
      }
    }
    /* ── EVERY CALL OF ONE CLAIM, WITH ITS VOICE, INSIDE THIS PORTAL ─────────────────────
       His instruction of 7-Aug-2026: "I don't want to go to the main third party portal.
       I want to see in my website itself for each claim number … only the record to be
       there." So: give one claim, get back Acefone's own calls FOR THAT CLAIM, each with a
       recording that plays here.

       Matched two ways, strongest first:
         1. the claim number we stamped on the call as custom_identifier when we placed it
         2. failing that, the customer's number as recorded in this claim's own call log
       Nothing is matched on time alone — a guessed recording on the wrong case would be
       far worse than none, so a call we cannot tie to this claim is simply not shown. */
    if (url.pathname === "/api/acefone/claim-calls") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      /* 20-Aug-2026, the five call-centre logins: their whole JOB is the calls this box
         shows, but the Call Centre role holds no case-data section, so canSeeCaseData()
         alone was refusing the very people the recordings belong to. The calling pages
         count as reason enough. */
      if (!(canSeeCaseData(me) || canAccess(me, "feedback") || canAccess(me, "appointment"))) return Response.json({ ok: false, error: "You do not have access to case data." }, { status: 403 });
      if (!(await acefoneTokenOf(env)).token) return Response.json({ ok: false, error: "Acefone is not connected — paste the token on Settings → Acefone calling." }, { status: 501 });
      const claim = String(url.searchParams.get("claim") || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      if (!allowRate("aceclaim:" + me.email, 120, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many recording reads this hour." }, { status: 429 });
      const daysQ = Number(url.searchParams.get("days"));
      const days = (isFinite(daysQ) && daysQ >= 1 && daysQ <= 30) ? daysQ : 7;
      const fmtIST = ms => { const d = new Date(ms + 19800000).toISOString(); return d.slice(0, 10) + " " + d.slice(11, 19); };
      const now = Date.now();
      const winFrom = fmtIST(now - days * 86400000), winTo = fmtIST(now);
      /* the numbers this claim was actually dialled on, from our own call log */
      const wantNums = new Set();
      try {
        for (const key of ["appt:map", "fbq:map"]) {
          const raw = env.USERS ? await env.USERS.get(key) : null;
          if (!raw) continue;
          const m = JSON.parse(raw), ent = m && m[claim];
          if (!ent) continue;
          const add = v => { const d = String(v == null ? "" : v).replace(/[^\d]/g, "").replace(/^91/, ""); if (d.length >= 10) wantNums.add(d.slice(-10)); };
          add(ent.phone);
          (Array.isArray(ent.callLog) ? ent.callLog : []).forEach(l => add(l && l.to));
          if (ent.lastCall) add(ent.lastCall.to);
        }
      } catch (e) { /* no log yet — the tag match below still works */ }
      const base = env.ACEFONE_RECORDS_URL || "https://api.acefone.in/v1/call/records";
      try {
        const r = await fetchT(base + "?from_date=" + encodeURIComponent(winFrom) + "&to_date=" + encodeURIComponent(winTo) + "&page=1&limit=200",
          { headers: { "Authorization": String((await acefoneTokenOf(env)).token), "Accept": "application/json" } }, 20000);
        const text = await r.text();
        let j = null; try { j = JSON.parse(text); } catch (e) { j = null; }
        if (!r.ok || !j) return Response.json({ ok: false, http: r.status, window: { from: winFrom, to: winTo },
          error: "Acefone's records API answered " + r.status + " — " + String(text || "").replace(/\s+/g, " ").trim().slice(0, 200) });
        const list = Array.isArray(j.data) ? j.data : (Array.isArray(j.results) ? j.results : (Array.isArray(j.records) ? j.records : (Array.isArray(j) ? j : [])));
        const P = (o, keys) => { for (const k of keys) { const v = o && o[k]; if (v !== undefined && v !== null && String(v).trim() !== "") return String(v); } return ""; };
        const claimKey = String(claim).replace(/[^a-z0-9]/gi, "").toLowerCase();
        const out = [];
        for (const c of list) {
          const tag = P(c, ["custom_identifier", "customIdentifier", "custom_id", "tag"]);
          const cust = P(c, ["client_number", "customer_number", "destination_number", "client", "callerid"]);
          const cust10 = cust.replace(/[^\d]/g, "").replace(/^91/, "").slice(-10);
          const byTag = tag && tag.replace(/[^a-z0-9]/gi, "").toLowerCase() === claimKey;
          const byNum = !!(cust10 && wantNums.has(cust10));
          if (!byTag && !byNum) continue;
          const rec = P(c, ["recording_url", "recording", "call_recording"]);
          const agNum = P(c, ["agent_number", "agent", "answered_agent", "accountid"]);
          const agWho = acefoneWho(env, agNum);
          out.push({
            when: P(c, ["date", "time", "call_time", "start_stamp", "created_at", "timestamp"]),
            agent: P(c, ["agent_number", "agent", "answered_agent", "agent_name", "accountid"]),
            /* whose account made this one — see the note on /api/acefone/records */
            agentName: agWho.known ? agWho.name : P(c, ["agent_name", "agentname", "user_name", "username"]),
            customer: cust,
            status: P(c, ["status", "call_status", "disposition", "leg_status"]),
            reason: P(c, ["hangup_cause", "reason", "hangup_reason", "failure_reason", "description"]),
            seconds: P(c, ["call_duration", "duration", "answered_seconds", "billsec", "conversation_duration"]),
            /* the voice is served THROUGH this portal, never as a link into Acefone's site —
               that is the whole point of his request */
            play: rec ? ("/api/acefone/recording?u=" + encodeURIComponent(rec)) : "",
            how: byTag ? "claim number stamped on the call" : "the number this claim was dialled on",
            id: P(c, ["call_id", "uuid", "id", "callid"])
          });
        }
        return Response.json({ ok: true, claim, days, window: { from: winFrom, to: winTo }, scanned: list.length, rows: out });
      } catch (e) {
        return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 502 });
      }
    }
    /* The voice itself, streamed through the portal so he never opens Acefone's site.
       SSRF is the risk in any "fetch this URL" endpoint, so the host is allow-listed to
       Acefone's own domains and nothing else — a link pointing anywhere else is refused. */
    if (url.pathname === "/api/acefone/recording") {
      if (!me) return new Response("Not signed in", { status: 401 });
      /* same rule as claim-calls above: a Call Centre login may play the recordings of the
         calls its own pages place */
      if (!(canSeeCaseData(me) || canAccess(me, "feedback") || canAccess(me, "appointment"))) return new Response("Forbidden", { status: 403 });
      if (!allowRate("acerecplay:" + me.email, 300, 60 * 60 * 1000)) return new Response("Too many recording plays this hour.", { status: 429 });
      const raw = String(url.searchParams.get("u") || "");
      let u = null; try { u = new URL(raw); } catch (e) { return new Response("Bad recording link", { status: 400 }); }
      const extra = String(env.ACEFONE_REC_HOSTS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
      const host = u.hostname.toLowerCase();
      const okHost = u.protocol === "https:" &&
        (host === "acefone.in" || host.endsWith(".acefone.in") || host === "acefone.com" || host.endsWith(".acefone.com")
          || host.endsWith(".myacefone.com") || extra.indexOf(host) >= 0);
      if (!okHost) return new Response("That recording link is not an Acefone address, so it was not opened.", { status: 400 });
      try {
        const rr = await fetchT(u.toString(), { headers: { "Authorization": String((await acefoneTokenOf(env)).token || ""), "Accept": "*/*" } }, 30000);
        if (!rr.ok) return new Response("Acefone would not give the recording (HTTP " + rr.status + ").", { status: 502 });
        const h = new Headers();
        h.set("Content-Type", rr.headers.get("Content-Type") || "audio/mpeg");
        const len = rr.headers.get("Content-Length"); if (len) h.set("Content-Length", len);
        h.set("Cache-Control", "private, max-age=300");
        h.set("Content-Disposition", "inline");
        return new Response(rr.body, { status: 200, headers: h });
      } catch (e) { return new Response("Could not fetch the recording — " + String(e && e.message ? e.message : e), { status: 502 }); }
    }
    /* ── TAKE / RELEASE — five callers, one queue, no double-calling ─────────────────────
       Sujit, 20-Aug-2026: "We have total five call centre guys — I want to give access in
       same website. They have to take appointment before field, and the feedback call after."
       Five people working one shared list top-down WILL ring the same insured twice inside
       ten minutes — so a case can now be TAKEN. Taking writes the caller's name on the row
       for everybody to see; a case already with somebody else is refused with that name
       (409), never silently stolen — first come is first served, and the screen says whose
       it is. Only the holder (or an admin) releases it. Touches ONLY the owner field: a
       Take must never be able to wipe a feedback note or flip a status. */
    if (url.pathname === "/api/queue/take" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const page = (b && b.page === "appointment") ? "appointment" : "feedback";
      if (!canAccess(me, page)) return Response.json({ ok: false, error: "You do not have access to this page." }, { status: 403 });
      if (!allowRate("qtake:" + me.email, 400, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many take/release actions this hour." }, { status: 429 });
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      if (!env.USERS) return Response.json({ ok: false, error: "Storage is not available." }, { status: 501 });
      const kvKey = page === "appointment" ? "appt:map" : "fbq:map";
      let map = {}; try { map = JSON.parse(await stGet(env, kvKey) || "{}"); } catch (e) { map = {}; }
      if (page === "feedback" && !map[claim]) return Response.json({ ok: false, error: "This claim is not in the feedback queue." }, { status: 404 });
      const rec = map[claim] || { claim, status: "pending", addedTs: Date.now() };   // appointment rows may have no record yet
      const myName = me.name || me.email;
      const take = !!(b && b.take);
      if (take) {
        if (rec.owner && rec.owner !== myName) {
          return Response.json({ ok: false, taken: true, owner: rec.owner, error: "This case is already with " + rec.owner + " — pick another one, or ask them to release it." }, { status: 409 });
        }
        rec.owner = myName; rec.ownerTs = Date.now();
      } else {
        if (rec.owner && rec.owner !== myName && me.role !== "admin") {
          return Response.json({ ok: false, taken: true, owner: rec.owner, error: "Only " + rec.owner + " (or an admin) can release this case." }, { status: 409 });
        }
        rec.owner = ""; rec.ownerTs = 0;
      }
      map[claim] = rec;
      await stSoft(env, kvKey, JSON.stringify(map));
      const entry = Object.assign({}, rec, { ownedByMe: rec.owner === myName && !!rec.owner });
      return Response.json({ ok: true, entry });
    }

    if (url.pathname === "/api/feedback/update" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "feedback")) { await secLog(env, "access-denied", me.email, "feedback update (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Feedback Calling." }, { status: 403 }); }
      if (!allowRate("fb:" + me.email, 200, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many feedback saves this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const FB_STATUSES = ["pending", "called-good", "called-issue", "no-answer", "done"];
      const status = String(b && b.status || "pending").toLowerCase();
      if (!FB_STATUSES.includes(status)) return Response.json({ ok: false, error: "Invalid feedback status." }, { status: 400 });
      const note = String(b && b.note != null ? b.note : "").trim().slice(0, 600);
      let fbq = {}; if (true) { try { fbq = JSON.parse(await stGet(env, "fbq:map") || "{}"); } catch (e) { fbq = {}; } }
      if (!fbq[claim]) return Response.json({ ok: false, error: "This claim is not in the feedback queue." }, { status: 404 });
      fbq[claim].status = status; fbq[claim].fb = note; fbq[claim].fbBy = me.name || me.email; fbq[claim].fbTs = Date.now();
      if (b && b.phone != null) fbq[claim].phone = String(b.phone).replace(/[^\d]/g, "").slice(0, 13); // remember the insured's number for the next call
      await stSoft(env, "fbq:map", JSON.stringify(fbq));
      await secLog(env, "admin-action", me.email, "feedback " + status + " on " + claim, true);
      return Response.json({ ok: true, entry: fbq[claim] });
    }
    /* This route used to hand a whole case — insured's name, claim number and phone —
       to an OUTSIDE calling service set in FEEDBACK_API_URL. That has been switched off
       on purpose: all calling is done inside this portal on your own Acefone account.
       The route is kept only so an old page left open in somebody's browser gets a clear
       answer instead of a blank error. It now sends NOTHING anywhere. */
    if (url.pathname === "/api/feedback/push" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      return Response.json({ ok: false, error: "Cases are no longer sent to any outside calling service. Every call is placed from this portal on your own Acefone account — press the green Call button, or Test calling to check the line. Refresh the page to get the current screen." }, { status: 410 });
    }

    /* ══════════ APPOINTMENT CALLING — HEALTH cases in Assigned / FO Accepted status.
       The appointment team calls the insured and fixes the field-visit appointment.
       Statuses: pending → no-answer (page reminds after 1 hour to try again) → done.
       "Appointment Done" cases move to the Done tab and stay as records. ══════════ */
    if (url.pathname === "/api/appointments" && request.method === "GET") {
      try {
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canAccess(me, "appointment")) { await secLog(env, "access-denied", me.email, "appointment (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Appointment Calling." }, { status: 403 }); }
        const d = await getCases(env);
        let cases = d.cases;
        if (isScopedRole(me.role)) {
          const foMap = me.role === "coordinator" ? await getFoStateMap(env).catch(() => null) : null;
          cases = scopeCases(cases, me, foMap);
        }
        // HEALTH cases only (no TP), and only Assigned / FO Accepted status
        cases = cases.filter(c => typeOfSub(c.subProduct) === "Health")
          .filter(c => { const s = String(c.status || "").toLowerCase(); return s.indexOf("assign") !== -1 || s.indexOf("accept") !== -1; });
        let am = {}; if (true) { try { am = JSON.parse(await stGet(env, "appt:map") || "{}"); } catch (e) { am = {}; } }
        const dg = s => { const p = String(s == null ? "" : s).replace(/[^\d]/g, ""); return p.length >= 10 ? p.slice(0, 13) : ""; };
        const myNameAp = me.name || me.email;
        const list = cases.map(c => {
          const r = am[c.claimNo] || {};
          return { claim: c.claimNo, client: c.client || "", sub: c.subProduct || "", insured: c.insured || "", hospital: c.hospitalName || "",
            fo: c.officerName || "", manager: c.manager || "", caseStatus: c.status || "", createdOn: c.createdOn || "",
            status: r.status || "pending", phone: r.phone || dg(c.contactNo), note: r.note || "", when: r.when || "",   // phone auto-fills from SKD's Contact number, stays editable
            owner: r.owner || "", ownedByMe: !!r.owner && r.owner === myNameAp,   // who has TAKEN this case, and is it you
            lastTryTs: r.lastTryTs || 0, lastCall: r.lastCall || null, callCount: r.callCount || 0, callLog: r.callLog || [], by: r.by || "", ts: r.ts || 0 };
        }).filter(x => x.status !== "done");
        // Done records survive even after the case moves on in SKD — pure record keeping.
        const done = Object.keys(am).map(k => am[k]).filter(r => r && r.status === "done")
          .map(r => ({ claim: r.claim, client: r.client || "", sub: r.sub || "", insured: r.insured || "", hospital: r.hospital || "",
            fo: r.fo || "", manager: r.manager || "", caseStatus: r.caseStatus || "", status: "done", phone: r.phone || "",
            note: r.note || "", when: r.when || "", lastCall: r.lastCall || null, callCount: r.callCount || 0, callLog: r.callLog || [], by: r.by || "", ts: r.ts || 0, doneTs: r.doneTs || r.ts || 0 }));
        done.sort((a, b) => (b.doneTs || 0) - (a.doneTs || 0));
        const aceTok2 = !!(await acefoneTokenOf(env)).token;
        return Response.json({ ok: true, list, done, acefone: aceTok2, apiConfigured: aceTok2, callerIds: acefoneCallerIds(env), agents: acefoneAgents(env) });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }
    if (url.pathname === "/api/appointments/update" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "appointment")) { await secLog(env, "access-denied", me.email, "appointment update (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Appointment Calling." }, { status: 403 }); }
      if (!allowRate("appt:" + me.email, 300, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many appointment saves this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const A_ST = ["pending", "no-answer", "done"];
      const status = String(b && b.status || "pending").toLowerCase();
      if (!A_ST.includes(status)) return Response.json({ ok: false, error: "Invalid appointment status." }, { status: 400 });
      let am = {}; if (true) { try { am = JSON.parse(await stGet(env, "appt:map") || "{}"); } catch (e) { am = {}; } }
      const nowTs = Date.now();
      for (const k in am) { const r = am[k]; if (!r) { delete am[k]; continue; }
        if (r.status === "done" && r.doneTs && nowTs - r.doneTs > 365 * 24 * 3600 * 1000) delete am[k];          // done records: keep 1 year
        else if (r.status !== "done" && r.ts && nowTs - r.ts > 180 * 24 * 3600 * 1000) delete am[k]; }           // stale unfinished: 180 days
      const cs = s => String(s == null ? "" : s).slice(0, 120);
      const ex = am[claim] || {};
      const rec = { claim,
        client: cs(b.client) || ex.client || "", sub: cs(b.sub) || ex.sub || "", insured: cs(b.insured) || ex.insured || "",
        hospital: cs(b.hospital) || ex.hospital || "", fo: cs(b.fo) || ex.fo || "", manager: cs(b.manager) || ex.manager || "",
        caseStatus: cs(b.caseStatus) || ex.caseStatus || "",
        status,
        phone: b.phone != null ? String(b.phone).replace(/[^\d]/g, "").slice(0, 13) : (ex.phone || ""),
        note: String(b.note != null ? b.note : (ex.note || "")).trim().slice(0, 600),
        when: String(b.when != null ? b.when : (ex.when || "")).slice(0, 40),
        lastTryTs: ex.lastTryTs || 0, lastCall: ex.lastCall || null, addedTs: ex.addedTs || nowTs,
        /* carried, not rebuilt — this save used to DROP the call history and would have
           dropped the Take marker the same way: a record rewrite must copy what it does
           not own, or every Save quietly erases somebody's work */
        callCount: ex.callCount || 0, callLog: Array.isArray(ex.callLog) ? ex.callLog : [],
        owner: ex.owner || "", ownerTs: ex.ownerTs || 0,
        by: me.name || me.email, ts: nowTs, doneTs: ex.doneTs || 0 };
      if (status === "no-answer") rec.lastTryTs = nowTs;             // the 1-hour retry timer starts now
      if (status === "done") { if (!rec.doneTs) rec.doneTs = nowTs; } else rec.doneTs = 0;
      am[claim] = rec;
      await stSoft(env, "appt:map", JSON.stringify(am));
      await secLog(env, "admin-action", me.email, "appointment " + status + " on " + claim, true);
      return Response.json({ ok: true, entry: rec });
    }
    /* Acefone click-to-call from the Appointment page — same flow as the feedback call. */
    if (url.pathname === "/api/appointments/call" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "appointment")) return Response.json({ ok: false, error: "You do not have access to Appointment Calling." }, { status: 403 });
      if (!(await acefoneTokenOf(env)).token) return Response.json({ ok: false, error: "Acefone is not connected yet — open Settings → Acefone calling in the portal and paste the token from Acefone console → API Connect → API Tokens." }, { status: 501 });
      if (!allowRate("apcall:" + me.email, 60, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many calls this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const digits = s => String(s == null ? "" : s).replace(/[^\d]/g, "");
      let phone = digits(b.phone); const agent = String(b.agent || "").trim().slice(0, 30);
      if (!agent) return Response.json({ ok: false, error: "Enter your agent number (the phone that rings first)." }, { status: 400 });
      if (!phone) {   // empty box → pull the Contact number straight from the SKD case page (same field the old portal shows)
        try { const rfc = await skdGetCase(env, claim); const rawc = await rfc.json(); phone = digits(contactFromCaseJson(rawc)).slice(0, 13); } catch (e) { }
      }
      if (phone.length < 10 || phone.length > 13) return Response.json({ ok: false, error: "No usable phone number — SKD has no contact number on this case either. Type the insured's 10-digit mobile, then press Call." }, { status: 400 });
      let am = {}; if (true) { try { am = JSON.parse(await stGet(env, "appt:map") || "{}"); } catch (e) { am = {}; } }
      const ex = am[claim] || { claim, status: "pending", addedTs: Date.now() };
      ["client", "sub", "insured", "hospital", "fo", "manager", "caseStatus"].forEach(f => { if (b[f] != null && !ex[f]) ex[f] = String(b[f]).slice(0, 120); });
      try {
        const dial = await acefoneDial(env, { agent: agent, dest: phone, callerId: b.callerId, tag: claim });
        if (dial.self) return Response.json({ ok: false, error: "You are trying to ring your own phone twice. “Who is calling?” is set to " + dial.agent + ", and that is also the number being called. Your phone rings, you answer, and then Acefone dials the very same phone — it is busy, so you hear nothing. Put the customer's number in the box next to Call, or pick a different phone under “Who is calling?”." }, { status: 400 });
        const okCall = dial.ok;
        /* whose Acefone account placed it — same stamp as the feedback page, same helper */
        const who = acefoneWho(env, dial.agent);
        const stamp = { ts: Date.now(), by: me.name || me.email, agent: dial.agent,
          agentName: who.name, agentKind: who.kind, agentKnown: who.known,
          to: dial.dest, status: okCall ? "initiated" : "failed", msg: dial.msg.slice(0, 220) };
        ex.phone = phone;
        ex.lastCall = stamp;
        ex.callCount = (ex.callCount || 0) + 1;   // record how many times we called
        const alg = Array.isArray(ex.callLog) ? ex.callLog : [];
        alg.push(Object.assign({}, stamp));
        ex.callLog = alg.slice(-20);
        am[claim] = ex;
        await stSoft(env, "appt:map", JSON.stringify(am));
        await secLog(env, "admin-action", me.email, "appointment call " + (okCall ? "started" : "FAILED") + " on " + claim + " from " + (acefoneWhoLabel(who) || "?"), true);
        if (!okCall) return Response.json({ ok: false, error: "Acefone did not accept the call — " + dial.msg }, { status: 502 });
        return Response.json({ ok: true, entry: ex, calling: { agent: dial.agent, agentName: who.name, agentKind: who.kind, agentKnown: who.known, who: acefoneWhoLabel(who), to: dial.dest, from: (dial.sent && dial.sent.caller_id) || "", msg: dial.msg } });
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 502 }); }
    }

    /* ── THE NUMBERS FILL THEMSELVES ──────────────────────────────────────────────────────
       Sujit, 19-Aug-2026: "Once the number need to be updated there automatically — now
       it's updating once I click." The pull button worked, one press per case — which on a
       forty-case queue is forty presses nobody was ever going to make. The two calling
       pages now send their number-less claims here in small batches the moment they load.
       For each claim the insured's number is read from the SKD case file (the same dig the
       pull button used), WRITTEN BACK into that page's queue so every colleague sees it
       from now on, and returned to the page that asked.
       Bounded on purpose: 8 claims a call, 240 fills an hour per person — enough to fill a
       whole queue inside a minute, never enough to hammer SKD. A case whose file carries no
       number answers '' and the page remembers not to ask again that sitting — asking twice
       cannot invent a number. A number the team TYPED is never overwritten: the write below
       only lands where the stored phone is empty. */
    if (url.pathname === "/api/phones/fill" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const page = (b && b.page === "appointment") ? "appointment" : "feedback";
      if (!canAccess(me, page)) return Response.json({ ok: false, error: "You do not have access to this page." }, { status: 403 });
      if (!allowRate("phfill:" + me.email, 240, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Number-fill limit reached this hour — the boxes already filled stay filled." }, { status: 429 });
      const claims = (Array.isArray(b && b.claims) ? b.claims : []).map(c => String(c || "").trim()).filter(c => c && validClaim(c)).slice(0, 8);
      if (!claims.length) return Response.json({ ok: true, phones: {}, filled: 0 });
      const digits = s => String(s == null ? "" : s).replace(/[^\d]/g, "");
      const phones = {};
      for (const claim of claims) {
        let p = "";
        try { const rfc = await skdGetCase(env, claim); const rawc = await rfc.json(); p = digits(contactFromCaseJson(rawc)).slice(0, 13); } catch (e) { p = ""; }
        phones[claim] = (p.length >= 10) ? p : "";
      }
      /* persist what was found — once filled, filled for everybody, and the next load of the
         page costs nothing. One KV write for the whole batch, and only into EMPTY phones. */
      let filled = 0;
      try {
        if (env.USERS) {
          const kvKey = page === "appointment" ? "appt:map" : "fbq:map";
          let map = {}; try { map = JSON.parse(await stGet(env, kvKey) || "{}"); } catch (e) { map = {}; }
          let dirty = false;
          for (const claim of claims) {
            const p = phones[claim];
            if (!p) continue;
            if (page === "appointment") {
              /* an appointment row may have no stored record yet — a minimal one is made so
                 the number survives; GET merges it in front of the feed's own contact */
              const ex = map[claim] || { claim, status: "pending", addedTs: Date.now() };
              if (!ex.phone) { ex.phone = p; map[claim] = ex; dirty = true; filled++; }
            } else if (map[claim] && !map[claim].phone) {
              /* feedback: only queue members — this endpoint must not be able to grow the queue */
              map[claim].phone = p; dirty = true; filled++;
            }
          }
          if (dirty) await stSoft(env, kvKey, JSON.stringify(map));
        }
      } catch (e) { /* a failed save must not lose the answer — the page still gets the numbers */ }
      return Response.json({ ok: true, phones, filled });
    }

    /* ── THE ROW THAT UPDATES ITSELF ──────────────────────────────────────────────────────
       One claim's latest call, straight from the queue store — one KV read, cheap enough to
       ask every few seconds. The live calling panel polls this after a Call is placed, so
       Answered / Missed / the recording appear on their own the moment Acefone's webhook
       lands, instead of waiting for somebody to press Refresh. */
    if (url.pathname === "/api/call-status" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      const page = url.searchParams.get("page") === "appointment" ? "appointment" : "feedback";
      if (!canAccess(me, page)) return Response.json({ ok: false, error: "You do not have access to this page." }, { status: 403 });
      if (!allowRate("cstat:" + me.email, 1500, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many status checks this hour." }, { status: 429 });
      const claim = String(url.searchParams.get("claim") || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      let map = {}; if (env.USERS) { try { map = JSON.parse(await env.USERS.get(page === "appointment" ? "appt:map" : "fbq:map") || "{}"); } catch (e) { map = {}; } }
      const r = map[claim];
      if (!r) return Response.json({ ok: true, found: false });
      return Response.json({ ok: true, found: true, entry: {
        claim: r.claim, status: r.status || "", phone: r.phone || "",
        lastCall: r.lastCall || null, callCount: r.callCount || 0, callLog: r.callLog || [],
        by: r.by || "", ts: r.ts || 0, note: r.note || "", when: r.when || "",
        fb: r.fb || "", fbBy: r.fbBy || "", fbTs: r.fbTs || 0, lastTryTs: r.lastTryTs || 0 } });
    }

    /* Team list for the Analytics "Team Performance" table — grouping metadata only
       (name, head, members, state).

       ══ SCOPED BY ROLE — v12.6, 20-Aug-2026 ═══════════════════════════════════════════
       Sujit, on a Meet with the first OHS login open beside him: "I gave OHS access. It is
       showing all the groups for him. I want only that group need to be reflected for him
       — that group and that cases need to be reflected."

       His CASES were already narrowed (every other team's row sat at zero — the case fence
       held), but this route handed the whole company's team sheet to ANY signed-in login:
       every group's name, every head, every member. So a team head scrolled through
       twenty-six teams to find his one row, and the org chart went along for free. The
       same fence the OHS Team page has had all along now stands here too — one door,
       narrowed the same way everywhere, so the Analytics table, the team dropdowns and
       anything else this list feeds all narrow together:

         · ohs            -> HIS team alone (the same t.id === me.team rule as /api/teams)
         · coordinator    -> the teams of his own state(s), stateless teams included,
                             exactly as the OHS Team page already narrows him
         · client-manager -> NOTHING. An insurer login has no business reading our team
                             structure at all — heads and members are our people's names,
                             and this is the role held by somebody who does not work here
         · call-centre    -> nothing either; their two pages never draw this table
         · everyone else (admin, boss, manager, product-head, ...) -> unchanged          */
    if (url.pathname === "/api/teams-list" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      let teams = [];
      if (env.USERS && me.role !== "client-manager" && me.role !== "call-centre") {
        const l = await env.USERS.list({ prefix: "team:" });
        for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { const t = JSON.parse(v); teams.push({ id: t.id, name: t.name, head: t.head, members: Array.isArray(t.members) ? t.members : [], state: t.state || "" }); } catch (e) {} } }
        if (me.role === "ohs") teams = teams.filter(t => t.id === me.team);
        else if (me.role === "coordinator") {
          const myStates = (Array.isArray(me.states) && me.states.length ? me.states : (me.state ? [me.state] : [])).map(s => String(s).toLowerCase());
          if (myStates.length) teams = teams.filter(t => !t.state || myStates.includes(String(t.state).toLowerCase()));
        }
      }
      teams.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
      return Response.json({ ok: true, teams });
    }

    /* ══════════ WHICH OHS IS THIS FIELD OFFICER UNDER ══════════ v31.4, 18-Sep-2026 ═══════
       Sujit, 18-Sep 8:14 pm, the Field Docs of 98506648 open: "I need in this page their OHS
       name also beside their name — example now Vijaya Bhaskar, it is in which OHS that I
       want." And again at 8:21 with four men on one Motor TP case: "Still I didn't receive
       the OHS name to the field officer. I need a name."

       NAMES IN, HEADS OUT — and nothing else. The Teams store holds the whole org chart, and
       /api/teams-list narrows it by role precisely so that a login cannot read the lot. This
       door does not hand back the chart at all: it is asked about the men who are already on
       the case in front of you, and answers with each one's team head and team name. A man on
       nobody's team comes back with an empty head rather than a guess, because a wrong OHS
       name is worse than none — the same rule as the officer on a part.

       Matched with sameManLoose, the spelling-tolerant match the OHS fence itself uses, so
       "Vijaya Bhaskar" on SKD's case file finds "Vijaya  Bhaskar" on our team sheet. */
    if (url.pathname === "/api/fo/ohs" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      /* the insurer's login and the call centre read no team structure anywhere else, and
         must not read it here either */
      if (me.role === "client-manager" || me.role === "call-centre") return Response.json({ ok: true, ohs: {} });
      const want = String(url.searchParams.get("names") || "").split("|").map(s => s.trim()).filter(Boolean).slice(0, 40);
      if (!want.length) return Response.json({ ok: true, ohs: {} });
      const tl = [];
      if (env.USERS) {
        try {
          const l = await env.USERS.list({ prefix: "team:" });
          for (const k of l.keys) {
            const v = await env.USERS.get(k.name);
            if (!v) continue;
            try { const t = JSON.parse(v); tl.push({ name: String(t.name || ""), head: String(t.head || ""), members: Array.isArray(t.members) ? t.members : [] }); } catch (e) {}
          }
        } catch (e) {}
      }
      const ohs = {};
      for (const nm of want) {
        let hit = null;
        for (const t of tl) { if ([t.head].concat(t.members).some(m => m && sameManLoose(m, nm))) { hit = t; break; } }
        ohs[nm] = hit
          ? { head: hit.head || "", team: hit.name || "", self: !!(hit.head && sameManLoose(hit.head, nm)) }
          : { head: "", team: "", self: false };
      }
      return Response.json({ ok: true, ohs });
    }

    /* ══════════ THE BUSINESS PAGE — the whole book, counted ══════ v12.8, 20-Aug-2026 ═══
       Sujit: "I want one option below the Dashboard called Business. I need in this,
       client-wise: how many case received, how many case has been closed — CM Reviewed —
       out of that, with the managers, state-wise, all things. How many cases have been
       allocated for field. New cases came in, monthly wise. Full business view — how much
       business we got, how much business we will give, how much business we have been
       closed."

       BUSINESS IS COUNTED IN CASES, and that is said on the page rather than implied: the
       SKD feed carries no rupee value on a case, so "how much business" can only honestly
       mean how many cases — got (received), closed (CM + QC Reviewed), and still to give
       (the open balance, split into with-the-field / with-the-managers / rejected /
       pending). The day per-case rates exist somewhere, multiplying is one line.

       WHAT IS COUNTED, exactly:
         received  every case the portal holds, once per claim — the live open feed
                   UNIONED with the closed history (carried archive since 1 April 2026 +
                   everything the hourly catcher has kept). A claim on both sides counts
                   ONCE, as closed.
         closed    the closed union: CM Reviewed + QC Reviewed (the same union every other
                   closed screen reads — never a separate arithmetic to disagree with).
         open      received minus closed, split by the same status rules as the daily
                   mail's buckets: field = Assigned/Accepted (out with the field),
                   managers = FO/Partially Completed (waiting on us), rejected, pending.
       Client spellings are merged the same forgiving-but-fenced way the Client Manager
       login matches insurers (clientKeyW) — "ICICI Lombard GIC" and "ICICI Lombard
       General Insurance" are one client, IFFCO can never fold into ICICI. Managers merge
       on case-and-spacing only (the MONIKA B / Monika B lesson). A case with no client
       named, no manager named, no parsable date or no known state is COUNTED APART under
       its own label — never dropped, never guessed.

       Scoping: the endpoint follows the same fences as every case feed — a scoped role
       that has been ticked for this page sees its own slice's business, an admin sees the
       company. Access is its own tick ("business"), off for every existing member until
       ticked — a page of company-wide totals is not something to inherit by silence.    */
    if (url.pathname === "/api/business" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "business")) { await secLog(env, "access-denied", me.email, "business (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to the Business page." }, { status: 403 }); }
      const wantProd = productKey(url.searchParams.get("product") || "");         // "TP" | "Health" | "OD" | "MBV" | "" (v33.7)
      const istISO = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata" }).format(new Date());
      const BIZ_FROM = "2026-04-01";                                              // the carried history starts here
      /* ── FROM / TO — v12.9, his ask the day after the page shipped: "I want the selection,
         from – to, till date." Pick any two dates and every figure on the page recounts for
         the cases RECEIVED in that window. The arithmetic stays the cohort he asked for in
         the first breath ("how many received, how many closed OUT OF THAT"): closed means
         closed-by-now out of the window's intake, so the columns always reconcile —
         received = closed + open, in every row, whatever the window. A case with no
         readable created date cannot be placed in a dated window, so when a window is set
         those cases are EXCLUDED AND COUNTED (noDateOut), never silently — and with no
         window set they stay in, under "(no date from SKD)", exactly as before. */
      const isDateQ = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
      const fromQ = String(url.searchParams.get("from") || "").slice(0, 10);
      const toQ = String(url.searchParams.get("to") || "").slice(0, 10);
      const narrowed = isDateQ(fromQ) || isDateQ(toQ);
      const winFrom = isDateQ(fromQ) ? fromQ : BIZ_FROM;
      const winTo = isDateQ(toQ) ? toQ : istISO;
      const monthOf = v => {
        const s = String(v == null ? "" : v).trim(); if (!s) return "";
        let m = s.match(/^(\d{4})-(\d{2})-\d{2}/); if (m) return m[1] + "-" + m[2];
        m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);                    // dd/MM/yyyy — Indian order, always
        if (m) return m[3] + "-" + String(m[2]).padStart(2, "0");
        return "";
      };
      const dayOf = v => {
        const s = String(v == null ? "" : v).trim(); if (!s) return "";
        let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/); if (m) return m[1] + "-" + m[2] + "-" + m[3];
        m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
        if (m) return m[3] + "-" + String(m[2]).padStart(2, "0") + "-" + String(m[1]).padStart(2, "0");
        return "";
      };
      let open = [], closed = [];
      const diag = { openError: "", closedError: "" };
      try { open = (await getCases(env)).cases || []; } catch (e) { diag.openError = String((e && e.message) || e); }
      try { closed = (await getCompleteCases(env, BIZ_FROM, istISO, {})).cases || []; } catch (e) { diag.closedError = String((e && e.message) || e); }
      const foMap = await getFoStateMap(env);
      if (isScopedRole(me.role)) { open = scopeCases(open, me, foMap); closed = scopeCases(closed, me, foMap); }

      const seen = new Map();                                                     // claimKey -> {c, closed}
      for (const c of closed) { const k = claimKey(c.claimNo); if (k && !seen.has(k)) seen.set(k, { c, closed: true }); }
      for (const c of open) { const k = claimKey(c.claimNo); if (k && !seen.has(k)) seen.set(k, { c, closed: false }); }

      const keyOfClient = s => clientKeyW(s) || "(no client named)";
      const keyOfMgr = s => { const v = String(s == null ? "" : s).replace(/\s+/g, " ").trim().toLowerCase(); return v || "(no manager named)"; };
      const mk = (map, key, display) => { let r = map.get(key); if (!r) { r = { name: display, received: 0, closed: 0, open: 0, field: 0, mgr: 0, rejected: 0, pending: 0 }; map.set(key, r); } return r; };
      const clients = new Map(), managers = new Map(), states = new Map(), months = new Map();
      const cMonths = new Map(), cMgrs = new Map(), cStates = new Map();
      /* v20.5 — Sujit, 03-Sep 8:20 am, the Business page: "once I select a client I need the
         products — how many cases in each — and the state also." Three more cuts, counted by
         the same bump: client → sub-product, client → state → sub-product, state → sub-product. */
      const cProds = new Map(), cStateProds = new Map(), sProds = new Map();
      const bump = (rec, isClosed, openBucket) => {
        rec.received++;
        if (isClosed) rec.closed++;
        else { rec.open++; rec[openBucket]++; }
      };
      const totals = { received: 0, closed: 0, open: 0, field: 0, mgr: 0, rejected: 0, pending: 0 };
      let noDate = 0, noDateOut = 0;
      for (const { c, closed: isClosed } of seen.values()) {
        if (wantProd && productOf(c.subProduct) !== wantProd) continue;       /* v33.7 — the one classifier */
        /* the from–to window, applied to the case's CREATED day (the cohort) */
        if (narrowed) {
          const day = dayOf(c.createdOn);
          if (!day) { noDateOut++; continue; }            // cannot be placed in a dated window — counted, never silent
          if (day < winFrom || day > winTo) continue;
        }
        const clientRaw = String(c.client || "").trim();
        const mgrRaw = String(c.manager || "").trim();
        const st = foStateOf(c.officerName, foMap) || "(no state known)";
        const ck = keyOfClient(clientRaw), mgk = keyOfMgr(mgrRaw);
        const ym = monthOf(c.createdOn) || "(no date from SKD)";
        if (ym === "(no date from SKD)") noDate++;
        /* the open balance, split by the same rules as the daily mail's buckets */
        let bucket = "pending";
        if (!isClosed) {
          const s = String(c.status || "").toLowerCase();
          if (s.indexOf("reject") !== -1) bucket = "rejected";
          else if (isPartCompletedW(c.status) || isCompletedStatusW(c.status)) bucket = "mgr";
          else if (s.indexOf("assign") !== -1 || s.indexOf("accept") !== -1) bucket = "field";
        }
        bump(totals, isClosed, bucket);
        bump(mk(clients, ck, clientRaw || "(no client named)"), isClosed, bucket);
        bump(mk(managers, mgk, mgrRaw || "(no manager named)"), isClosed, bucket);
        bump(mk(states, st, st), isClosed, bucket);
        bump(mk(months, ym, ym), isClosed, bucket);
        bump(mk(cMonths, ck + "\u0001" + ym, ym), isClosed, bucket);
        bump(mk(cMgrs, ck + "\u0001" + mgk, mgrRaw || "(no manager named)"), isClosed, bucket);
        bump(mk(cStates, ck + "\u0001" + st, st), isClosed, bucket);
        const spName = String(c.subProduct || "").trim() || "(no sub-product)";
        bump(mk(cProds, ck + "\u0001" + spName, spName), isClosed, bucket);
        bump(mk(cStateProds, ck + "\u0001" + st + "\u0001" + spName, spName), isClosed, bucket);
        bump(mk(sProds, st + "\u0001" + spName, spName), isClosed, bucket);
      }
      const flat = (map, withKey) => [...map.entries()].map(([k, r]) => withKey ? { client: clients.get(k.split("\u0001")[0]) ? clients.get(k.split("\u0001")[0]).name : k.split("\u0001")[0], ...r } : r);
      const byReceived = (a, b) => b.received - a.received;
      return Response.json({
        ok: true,
        window: { from: winFrom, to: winTo, narrowed, historyFrom: BIZ_FROM, today: istISO },
        product: wantProd || "All",
        totals,
        clients: flat(clients).sort(byReceived),
        managers: flat(managers).sort(byReceived),
        states: flat(states).sort(byReceived),
        months: flat(months).sort((a, b) => String(a.name).localeCompare(String(b.name))),
        clientMonths: flat(cMonths, true),
        clientManagers: flat(cMgrs, true),
        clientStates: flat(cStates, true),
        clientProducts: flat(cProds, true),
        clientStateProducts: [...cStateProds.entries()].map(([k, r]) => { const p = k.split("\u0001"); return { client: clients.get(p[0]) ? clients.get(p[0]).name : p[0], state: p[1], ...r }; }),
        stateProducts: [...sProds.entries()].map(([k, r]) => { const p = k.split("\u0001"); return { state: p[0], ...r }; }),
        noDate,
        noDateOut,
        diag,
        basis: "Counted in CASES — the SKD feed carries no rupee value on a case. Received = every case the portal holds" + (narrowed ? " whose created date falls in the selected window" : " since 1 April 2026") + ", once per claim (live open feed + closed history). Closed = CM Reviewed + QC Reviewed out of those, the same closed union every other screen reads. Open = received minus closed, split by the daily mail's own bucket rules."
      });
    }

    /* ══════════ DOCUMENTS register — back-office records which documents were RECEIVED and which are
       NOT AVAILABLE for each FO-completed case, each stamped with the date. Stored in the portal. ══════════ */
    if (url.pathname === "/api/docs" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docs")) { await secLog(env, "access-denied", me.email, "docs (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Documents." }, { status: 403 }); }
      let map = {}; if (true) { try { map = JSON.parse(await stGet(env, "docs:map") || "{}"); } catch (e) { map = {}; } }
      return Response.json({ ok: true, entries: map });
    }
    if (url.pathname === "/api/docs/update" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "docs")) { await secLog(env, "access-denied", me.email, "docs update (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to Documents." }, { status: 403 }); }
      if (!allowRate("docs:" + me.email, 400, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many document saves this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const claim = String(b && b.claim || "").trim();
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Invalid claim number." }, { status: 400 });
      const cs = s => String(s == null ? "" : s).slice(0, 300);
      const cleanArr = a => (Array.isArray(a) ? a : []).slice(0, 25).map(x => ({ doc: String(x && x.doc || "").slice(0, 40), date: (typeof (x && x.date) === "number" && x.date > 0) ? x.date : 0 })).filter(x => x.doc);
      let map = {}; if (true) { try { map = JSON.parse(await stGet(env, "docs:map") || "{}"); } catch (e) { map = {}; } }
      const now = Date.now();
      for (const k in map) { if (map[k] && map[k].ts && (now - map[k].ts > 365 * 24 * 3600 * 1000)) delete map[k]; }   // keep a year
      const prev = map[claim] || {};
      map[claim] = {
        received: cleanArr(b.received), notAvail: cleanArr(b.notAvail), remarks: cs(b.remarks),
        courier: cs(b.courier).slice(0, 60),                                   // courier / DTDC tracking number
        hcReceived: !!(b && b.hcReceived),                                     // hardcopy received at office?
        hcDate: (typeof (b && b.hcDate) === "number" && b.hcDate > 0) ? b.hcDate : (b && b.hcReceived ? now : 0),
        dispatch: (b && typeof b.dispatch === "object" && b.dispatch) ? { courier: cs(b.dispatch.courier).slice(0, 60), sentTo: cs(b.dispatch.sentTo).slice(0, 120), sent: !!b.dispatch.sent, date: (typeof b.dispatch.date === "number" && b.dispatch.date > 0) ? b.dispatch.date : (b.dispatch.sent ? now : 0), remarks: cs(b.dispatch.remarks) } : (prev.dispatch || null),
        fo: cs(b.fo).slice(0, 140), by: me.email, name: me.name || me.email, ts: now
      };
      await stSoft(env, "docs:map", JSON.stringify(map));
      await secLog(env, "admin-action", me.email, "docs updated on " + claim, true);
      return Response.json({ ok: true, entry: map[claim] });
    }

    /* ══════════ OHS TEAM page — team head + 5-6 member FOs, filtered by the coordinator's state.
       Same team store as the Admin console (team:*). A coordinator only sees / creates teams
       for their own state(s); admin sees everything. ══════════ */
    if (url.pathname === "/api/teams" && request.method === "GET") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "ohsteam")) { await secLog(env, "access-denied", me.email, "ohsteam (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to OHS Team." }, { status: 403 }); }
      const fos = await getFoRoster(env);
      const statesAll = fos.map(f => f.state).filter(Boolean);
      const states = statesAll.filter((s, i) => statesAll.indexOf(s) === i).sort();
      const myStates = (me.role === "coordinator")
        ? (Array.isArray(me.states) && me.states.length ? me.states : (me.state ? [me.state] : []))
        : [];
      let teams = [];
      if (env.USERS) {
        const l = await env.USERS.list({ prefix: "team:" });
        for (const k of l.keys) { const v = await env.USERS.get(k.name); if (v) { try { teams.push(JSON.parse(v)); } catch (e) {} } }
      }
      if (myStates.length) { const low = myStates.map(s => String(s).toLowerCase()); teams = teams.filter(t => !t.state || low.includes(String(t.state).toLowerCase())); }
      if (me.role === "ohs") teams = teams.filter(t => t.id === me.team);   // a team head sees only HIS team
      teams.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
      teams = teams.map(t => ({ ...t, canEdit: me.role === "admin" || (t.createdBy || "") === me.email, canRename: me.role === "admin" || (t.createdBy || "") === me.email || (me.role === "ohs" && me.team === t.id) }));
      return Response.json({ ok: true, teams, fos, states, myStates, role: me.role, myTeam: me.role === "ohs" ? (me.team || "") : "" });
    }
    if (url.pathname === "/api/teams" && request.method === "POST") {
      if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
      if (!canAccess(me, "ohsteam")) { await secLog(env, "access-denied", me.email, "ohsteam save (not permitted)", false); return Response.json({ ok: false, error: "You do not have access to OHS Team." }, { status: 403 }); }
      if (!allowRate("team:" + me.email, 60, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many team saves this hour." }, { status: 429 });
      let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
      const action = String(b && b.action || "save").toLowerCase();
      const myStates = (me.role === "coordinator")
        ? (Array.isArray(me.states) && me.states.length ? me.states : (me.state ? [me.state] : [])).map(s => String(s).toLowerCase())
        : [];
      async function getTeam(id) { if (!env.USERS || !id) return null; const v = await env.USERS.get("team:" + id); if (!v) return null; try { return JSON.parse(v); } catch (e) { return null; } }
      // RENAME: the team name can be changed anytime — by the admin, the creator, or the team's own OHS head
      if (action === "rename") {
        const id = String(b && b.id || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80);
        const newName = String(b && b.name || "").trim().slice(0, 60);
        if (newName.length < 2) return Response.json({ ok: false, error: "Team name is too short." }, { status: 400 });
        const ex = await getTeam(id);
        if (!ex) return Response.json({ ok: false, error: "Team not found." }, { status: 404 });
        const mayRename = me.role === "admin" || (ex.createdBy || "") === me.email || (me.role === "ohs" && me.team === id);
        if (!mayRename) return Response.json({ ok: false, error: "You cannot rename this team." }, { status: 403 });
        ex.name = newName; ex.updatedBy = me.email; ex.updatedTs = Date.now();
        await env.USERS.put("team:" + id, JSON.stringify(ex));
        // keep the OHS members' stored teamName label in sync
        try {
          const ul = await env.USERS.list({ prefix: "u:" });
          for (const k of ul.keys) { const v = await env.USERS.get(k.name); if (!v) continue; let uu; try { uu = JSON.parse(v); } catch (e) { continue; } if (uu && uu.role === "ohs" && uu.team === id) { uu.teamName = newName; await env.USERS.put(k.name, JSON.stringify(uu)); } }
        } catch (e) {}
        await secLog(env, "admin-action", me.email, "OHS team renamed to: " + newName, true);
        return Response.json({ ok: true, team: ex });
      }
      if (me.role === "ohs") return Response.json({ ok: false, error: "A team head can rename the team, but members are changed by the admin / coordinator." }, { status: 403 });
      if (action === "delete") {
        const id = String(b && b.id || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80);
        const ex = await getTeam(id);
        if (!ex) return Response.json({ ok: false, error: "Team not found." }, { status: 404 });
        if (me.role !== "admin" && (ex.createdBy || "") !== me.email) return Response.json({ ok: false, error: "Only the admin or the team's creator can delete it." }, { status: 403 });
        await env.USERS.delete("team:" + id);
        await secLog(env, "admin-action", me.email, "OHS team deleted: " + (ex.name || id), true);
        return Response.json({ ok: true });
      }
      const name = String(b && b.name || "").trim().slice(0, 60);
      const head = String(b && b.head || "").trim().slice(0, 80);
      const state = String(b && b.state || "").trim().slice(0, 40);
      let members = Array.isArray(b && b.members) ? b.members.map(x => String(x).trim().slice(0, 80)).filter(Boolean) : [];
      members = members.filter((x, i) => members.indexOf(x) === i).filter(x => x.toLowerCase() !== head.toLowerCase());
      if (name.length < 2) return Response.json({ ok: false, error: "Team name is too short." }, { status: 400 });
      if (!head) return Response.json({ ok: false, error: "Select the team head." }, { status: 400 });
      if (!members.length) return Response.json({ ok: false, error: "Select the member field officers (5–6)." }, { status: 400 });
      if (members.length > 6) return Response.json({ ok: false, error: "Maximum 6 member field officers per team." }, { status: 400 });
      // "Andhra Pradesh & Telangana" is a combined OHS-page option; a coordinator holding both states may use it.
      const stateLow = state.toLowerCase();
      const isCombo = stateLow === "andhra pradesh & telangana";
      const coordHasAPTS = myStates.some(s => /^(andra|andhra) pradesh$/.test(s)) && myStates.some(s => /^tel(u|a)ngana$/.test(s));
      const stateOk = !myStates.length || !state || myStates.includes(stateLow) || (isCombo && coordHasAPTS);
      if (!stateOk) { await secLog(env, "scope-blocked", me.email, "ohs team outside coordinator state: " + state, false); return Response.json({ ok: false, error: "You can only create teams for your own state." }, { status: 403 }); }
      let id = String(b && b.id || "").replace(/[^a-z0-9-]/gi, "").slice(0, 80);
      let createdBy = me.email;
      if (id) {
        const ex = await getTeam(id);
        if (!ex) return Response.json({ ok: false, error: "Team not found." }, { status: 404 });
        if (me.role !== "admin" && (ex.createdBy || "") !== me.email) return Response.json({ ok: false, error: "Only the admin or the team's creator can edit it." }, { status: 403 });
        createdBy = ex.createdBy || me.email;
      } else {
        id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) + "-" + Date.now().toString(36);
      }
      const team = { id, name, head, members, state, createdBy, updatedBy: me.email, updatedTs: Date.now() };
      if (env.USERS) await env.USERS.put("team:" + id, JSON.stringify(team));
      await secLog(env, "admin-action", me.email, "OHS team saved: " + name + " [" + (state || "no state") + "] head " + head + ", " + members.length + " members", true);
      return Response.json({ ok: true, team: { ...team, canEdit: true } });
    }

    /* The main "Download Excel". It used to send ten columns as a .csv; it now sends the same
       22-column .xlsx as every other Excel button in the portal, still scoped to the signed-in
       person (coordinator -> their states, manager -> their own cases, admin/boss -> everything). */
    if (url.pathname === "/api/export") {
      try {
        const me = await currentUser(env, request);
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!canSeeCaseData(me)) return Response.json({ ok: false, error: "Your access does not include case downloads." }, { status: 403 });
        const st = (url.searchParams.get("status") || "").toLowerCase(); // respect the dashboard status filter
        const want = (url.searchParams.get("type") || "all").toLowerCase();
        const { columns, rows } = await buildSheetRows(env, want, me, st, url.searchParams.get("client") || "");
        const stamp = new Date().toISOString().slice(0, 10);
        return await xlsxResponse(columns, rows, "skd-cases-" + stamp);
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* EVERY Excel button on every screen ends up here. The page sends the claim numbers it is
       showing plus a name for the file; the answer is always the same 22-column workbook, in the
       order the screen was in. Nothing the person cannot already see can come out of it, because
       the rows are built from their own scoped list before the claim numbers are matched. */
    if (url.pathname === "/api/export-xlsx" && request.method !== "POST") return Response.json({ ok: false, error: "Use the Excel button on the page — this address only answers a POST." }, { status: 405 });
    if (url.pathname === "/api/export-xlsx" && request.method === "POST") {
      try {
        const me = await currentUser(env, request);
        if (!me) return Response.json({ ok: false, error: "Not signed in" }, { status: 401 });
        if (!allowRate("xlsx:" + me.email, 240, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many downloads this hour — please wait a little." }, { status: 429 });
        let b; try { b = await request.json(); } catch (e) { return Response.json({ ok: false, error: "Bad request body" }, { status: 400 }); }
        /* The case-data fence guards the branch that GOES AND FETCHES CASES. The typesetter
           branch below fetches nothing — it only sets what the page already had on screen —
           so it must not be fenced by case access, or HR, whose whole world is the Field
           Officers page, could not download the officer list they are the keeper of. */
        const bringsOwnSheet = !!(b && b.sheet && Array.isArray(b.sheet.columns) && b.sheet.columns.length && Array.isArray(b.sheet.rows));
        if (!bringsOwnSheet && !canSeeCaseData(me)) return Response.json({ ok: false, error: "Your access does not include case downloads." }, { status: 403 });
        /* ── A SCREEN THAT BRINGS ITS OWN COLUMNS ────────────────────────────────────────
           Every other Excel button on the site wants the same twenty-two columns, so it sends
           claim numbers and the sheet is rebuilt here from the live feed. The Case Journey
           screen is the one exception: it wants HIS nineteen columns, in HIS order and under
           HIS names — Client · Sub Product · Claim Number · … · Final Conclusion ·
           StackHolders — plus the waiting time between each pair of stages, which is worked
           out on the screen and exists nowhere else.

           So when a page sends `sheet`, this makes a real Excel file out of exactly what it
           was handed and asks SKD for nothing at all. It is a typesetter, not a source: the
           rows came from the feed this same person is already allowed to read, through the
           same role scope, so nothing here can show anybody a case they could not already
           see. The role fence and the hourly limit above still apply, and the size is capped. */
        const sheet = b && b.sheet;
        if (bringsOwnSheet) {
          const cols = sheet.columns.slice(0, 80).map(x => String(x == null ? "" : x).slice(0, 120));
          const rws = sheet.rows.slice(0, 20000).map(r => {
            const a = Array.isArray(r) ? r : [];
            const out = []; for (let i = 0; i < cols.length; i++) out.push(a[i] == null ? "" : String(a[i]).slice(0, 800));
            return out;
          });
          const nm = String(b && b.name || "taasen-case-journey").slice(0, 70);
          const rs = await xlsxResponse(cols, rws, nm + "-" + new Date().toISOString().slice(0, 10));
          /* This is the typesetter path: the screen handed us finished rows and we only set
             them in Excel. Whatever shape they are in is the screen's shape, so cases and
             lines are the same number here and the row-per-officer rule does not apply —
             these rows are officers, or match results, or whatever that screen was listing. */
          rs.headers.set("X-Cases", String(rws.length));
          rs.headers.set("X-Rows", String(rws.length));
          rs.headers.set("Access-Control-Expose-Headers", "X-Cases, X-Rows");
          return rs;
        }
        const claims = Array.isArray(b && b.claims) ? b.claims.slice(0, 20000) : [];
        // the field officers the on-screen list stands for — see pickSheetRows
        const fos = Array.isArray(b && b.fos) ? b.fos.slice(0, 4000) : [];
        const want = String(b && b.type || "all").toLowerCase();
        const status = String(b && b.status || "").toLowerCase();
        /* what the SCREEN knows about each claim, so a case that has left the live feed is
           still a full line instead of a blank one. Keyed the same way claims are matched. */
        const hints = {};
        if (b && b.hints && typeof b.hints === "object") {
          let n = 0;
          for (const k in b.hints) { if (n++ > 20000) break; const kk = claimKey(k); if (kk) hints[kk] = b.hints[k]; }
        }
        const { columns, rows } = await buildSheetRows(env, want, me, status);
        const picked = pickSheetRows(rows, claims, fos, hints);   // one line per field officer — see ONE LINE PER FIELD OFFICER above
        const stamp = new Date().toISOString().slice(0, 10);
        const base = String(b && b.name || "taasen-cases").slice(0, 70);
        const res = await xlsxResponse(columns, picked, base + "-" + stamp);
        /* The page reads these back for the little green pill, and since 12 Aug 2026 they are
           DIFFERENT numbers on purpose: X-Cases is how many claims are in the sheet, X-Rows how
           many field-officer lines those claims came to. "217 cases · 260 lines" is the honest
           way to keep the promise the button makes — he pressed 217 and 217 claims are what he
           got, written the way SKD writes them. Both are sent so the screen can say both; a
           pill that showed only the line count would look like the button had overshot. */
        const nCases = new Set(picked.map(r => claimKey(r[2])).filter(Boolean)).size;
        res.headers.set("X-Cases", String(nCases));
        res.headers.set("X-Rows", String(picked.length));
        res.headers.set("Access-Control-Expose-Headers", "X-Cases, X-Rows");
        return res;
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    if (url.pathname.startsWith("/api/case/")) {
      const claim = decodeURIComponent(url.pathname.split("/").pop());
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Case not found" }, { status: 404 });
      try {
        const me = await currentUser(env, request);
        const d = await getCases(env);
        let found = findCaseByClaim(d.cases, claim);   // 5573/…/TP finds 5573-…-TP too
        /* v34.9 — not in SKD's open book: one of OUR cases (New Case), else the copy our case store kept */
        let cs = null;
        try { cs = await import("./case-store-index.js"); } catch (e) { cs = null; }
        if (!found && cs) {
          try { found = findCaseByClaim(await cs.ourCases(env), claim) || await cs.keptCase(env, claim); } catch (e) { found = null; }
        }
        if (!found) return Response.json({ ok: false, error: "Case not found" }, { status: 404 });
        if (cs && me && !isClientRole(me)) {
          try { const am = await cs.appStatusMap(env, [found.claimNo]); if (am[found.claimNo]) found = Object.assign({}, found, { pinaka: am[found.claimNo] }); } catch (e) { }
        }
        if (me && (isScopedRole(me.role))) {
          const foMap = me.role === "coordinator" ? await getFoStateMap(env) : null;
          if (!scopeCases([found], me, foMap).length) return Response.json({ ok: false, error: "Case not found" }, { status: 404 });
        }
        /* the insurer's own login sees his case WITHOUT our people on it — scopeCases already
           strips the list this came from, and this single-case door has to strip too or the
           one name we refuse to print in a table arrives through a claim click instead */
        return Response.json({ ok: true, source: "LIVE", case: isClientRole(me) ? stripInternalNames([found])[0] : found });
      }
      catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    if (url.pathname.startsWith("/api/report/")) {
      const claim = decodeURIComponent(url.pathname.split("/").pop());
      if (!validClaim(claim)) return Response.json({ ok: false, error: "Case not found" }, { status: 404 });
      /* the AI case report is OUR write-up of the file, naming our officer and our manager;
         the client role has no Reports page, and this is the door behind that page */
      if (isClientRole(me)) return Response.json({ ok: false, error: "Case reports are internal." }, { status: 403 });
      try {
        const d = await getCases(env);
        const found = findCaseByClaim(d.cases, claim);
        if (!found) return Response.json({ ok: false, error: "Case not found" }, { status: 404 });
        if (me && (isScopedRole(me.role))) { // SECURITY: role fence
          const foMap = me.role === "coordinator" ? await getFoStateMap(env) : null;
          if (!scopeCases([found], me, foMap).length) { await secLog(env, "scope-blocked", me.email, "report " + claim); return Response.json({ ok: false, error: "Case not found" }, { status: 404 }); }
        }
        if (!allowRate("heavy:" + (me ? me.email : "?"), 40, 60 * 60 * 1000)) return Response.json({ ok: false, error: "Too many report requests this hour — please wait a while." }, { status: 429 });
        if ((found.status || "").toLowerCase().indexOf("complete") === -1) return Response.json({ ok: false, error: "Report only for FO Completed." }, { status: 400 });
        try { const narrative = await aiReportSimple(env, found); return Response.json({ ok: true, claimNo: claim, narrative: narrative, data: found }); }
        catch (err) { return Response.json({ ok: false, error: "AI unavailable: " + (err && err.message ? err.message : err), data: found }); }
      } catch (e) { return Response.json({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 }); }
    }

    /* 31-Aug-2026 — THE FILES THAT ARE NOT PAGES. The repo root is the asset folder, so the
       deploy carries everything up: this worker's own source, every module file, the carried
       archive, the docs. wrangler.toml now says run_worker_first = true, which puts the
       sign-in gate above in front of every file for the first time; this is the second lock,
       for the files no browser should be handed even AFTER sign-in — source is not a page,
       cm-archive.tsv is an ingredient (cm-archive-index.js reads it through the binding,
       which does not pass through this door), and the docs are ours. Anything the regex
       catches answers the same 404 a wrong claim number gets: not a hint that it exists. */
    /* v26.8 — THREE FILES WERE FALLING THROUGH THIS, and one of them mattered.
       The list above catches source by SHAPE (…-index.js, run-….mjs, ….gs), so a new module
       whose name does not fit one of those shapes is served to anybody signed in. Two of mine
       did not fit — and questionnaire-triggers.js is his whole confidential trigger sheet:
       every doubt the desk checks for, which is the one thing the indirect rule exists to keep
       off the page. A field officer typing the file name would have read it.
         questionnaire-triggers.js  the investigation ground — must never leave the Worker
         questionnaire-doc.js       the PDF typesetter — source, not a page
         WHAT-TO-DO.txt             the change log, missed since the day this gate was written
       questionnaire-data.js stays public on purpose: questionnaire.html loads it as a script.
       ANY NEW MODULE MUST BE ADDED HERE unless its name already matches a shape above.
       18-Sep-2026 — the v30.0 Questionnaire Trigger Lock was rolled back: nothing imports its
       modules any more and the Worker never reaches them. The FILES are still in the repo, so
       the two shapes that cover them stay in this list — qlock-[a-z0-9-]+.js (qlock-vocab-seed.js,
       qlock-fixture.js: his wordings and his fixture) and TaaSen_Questionnaire_….xlsx/.docx. A dead
       file is still his file; it must not become a public URL because the code around it went away. */
    /* v32.0 — invoice-seed.js and invoice-doc.js do NOT match the …-index.js shape, and the
       seed carries our three GSTINs, our PANs and the whole client list. invoice-[a-z0-9-]+\.js
       covers both and every invoice module that comes after them. run-inv01.mjs holds it. */
    /* v34.1 — bridge/ is the payout bridge, a Node service that runs OUTSIDE this Worker (on a
       machine that can hold a bank certificate and a whitelisted IP). Its files live in the repo
       beside everything else, so the whole folder is walled here: not one of them is a page. */
    if (/^\/(entry\.js|bridge\/.*|worker\.js|wrangler\.toml|README\.md|_CLAUDE_MAP\.md|WHAT-TO-DO\.txt|cm-archive\.tsv|[a-z0-9-]*-index\.js|invoice-[a-z0-9-]+\.js|questionnaire-(?!data\.js)[a-z0-9-]+\.js|qlock-[a-z0-9-]+\.js|TaaSen_Questionnaire_[A-Za-z_]+\.(?:xlsx|docx)|field-ui-[a-z]+\.js|(?:run|check)-[a-z0-9-]+\.mjs|[^/]+\.gs|\.assetsignore|hook-order-check\.js|all-pages-react\.js|pdf-lite\.js|petition-rules\.js|pdf-text\.js|mbv-docs\.js|mail-ai\.js|mail-(?:client|pages)\.js)$/i.test(url.pathname)) {
      return new Response("Not found", { status: 404 });
    }
    return env.ASSETS.fetch(request);
}

/* ══════════ SHARED WITH THE FIELD OFFICER LOCATION TRACKER (/field) ══════════════════
   Sujit, 12-Aug-2026: "If manager will be opening, need to come manager access. If admin
   or boss will be opening, need to reflect admin access itself, and the coordinator need
   to get access for this."

   So the tracker stopped having two passcodes of its own and started using THIS login.
   Rather than copy the cookie-reading and the FO roster into field/index.js — where the
   copy would quietly drift the day either one changes here — the tracker imports the real
   ones. Nothing above this line was rewritten to make that possible: these five were
   already exactly what the tracker needed, they were simply not reachable from outside.

   The only other change in this file is the word "field" inside ACCESS_SECTIONS, which is
   what lets you tick the page on or off per person in the Admin console like every other
   page. Remove these two things and the tracker falls back to being a separate app.      */
export { stGet, stPut, stSoft, stDel, stList, allProducts, currentUser, canAccess, getFoRoster, canonState, normName,
         /* v34.9 — the ONE password hasher, shared with Pinaka (app-index.js) */
         pwHash, pwWeak, pwGenerate, PW_ITER,
         /* v20.5 — Officer Changed reads SKD's own case history (who reassigned) and places each change in its FO state */
         skdGetCase, foStateOf, sameManLoose, isTeamMan, meetRosterSnapshot, ootatLimitFor,
         /* added 12-Aug-2026 for the Release stage — the same scoping helper every other
            page uses, so a manager's released list is narrowed by the SAME rule as his
            case list. Section 7 of the handover: one helper, never a second copy. */
         scopeCases, isScopedRole, getFoStateMap, getCompleteCases, getCases, claimKey, validClaim,
         /* v23.2 — the access checks, so run-access232.mjs can hold them to his own words */
         accessOf, assignProductsOf,
         /* v20.9 — the Lok Adalat chase needs the coordinator list and the admin addresses */
         kvListUsers, adminEmails,
         /* v25.0 — TaaSen Mail writes its sends / exports / deactivations to the same security log, and
            builds a box's export with the same zip writer the Excel exports use */
         secLog,
         /* v15.9 — Accounts wanted typeOfSub too. It is NOT re-listed here: it is already
            exported further down (see the 17-Aug note for the position mail), and a name may
            appear in this list ONCE. Adding it a second time is not a duplicate that the
            bundler tidies away — esbuild stops with "Multiple exports with the same name" and
            NOTHING deploys, which is exactly what killed the first v15.9 build at 12:38 on
            29-Aug-2026. One name, one line, however many pages come to need it. */
         /* v13.5 — the Drive folder's name reading, exported so the REAL file names out of his
            folder can be run through it in a test instead of trusted by eye */
         ddocVariants, ddocIndex, ddocSplit,
         /* the one test for "the field officer has finished" — Partially Completed is NOT it.
            isPartCompletedW is its opposite number, exported 12-Aug-2026 so the FO Completed
            page can COUNT the partials separately instead of quietly folding them in. That
            folding is exactly what made the dashboard tile read 248 when the true FO Completed
            figure was lower — see the note on count() in app.js. */
         isCompletedStatusW, isPartCompletedW,
         /* added 13-Aug-2026 for the Not Activated FO page — that page prints case rows, so
            it must ask the SAME "may this login see case data at all" question every other
            case list asks, not invent a second copy that drifts. */
         canSeeCaseData,
         /* added 13-Aug-2026 for the Daily Brief. anthropic() is the ONE door to Claude this
            worker has — the brief must walk through it, not grow a second copy with its own
            headers and its own bugs. allowRate ties the brief to the SAME hourly AI budget as
            /api/ai ("ai:" + email), so a person cannot spend two budgets by using two pages.
            tatDaysNum reads "116D 5H" the way every other screen reads it. */
         anthropic, gemini, openai, grok, deepseek, askModel, allowRate, AI_ALLOWED_MODELS, tatDaysNum,
         /* added 19-Aug-2026 for the mail's Cashless hour-by-hour table — "for cashless I
            need hourly basis". tatDH is the ONE parser of "0D 6H"; the mail must ask it,
            not grow a second regex that drifts. */
         tatDH,
         /* added 19-Aug-2026 for the Check-a-date diagnostic — it probes the status buckets
            DIRECTLY (including dm-reviewed, which the portal does not read) so "the TP bucket
            is not open" becomes a measured row count instead of a suspicion. Read-only. */
         probeStatusList, probeStatusListPaged,
         /* v16.0 — GST FILED (gst-index.js) hands back a zip holding one Excel and the bill
            PDFs. Both builders are exported rather than copied: xlsxBytes is what every Excel
            button on this site already comes out of, so his GST sheet is typeset by the same
            code as his case sheets, and zipBytes is the ZIP writer xlsxBytes itself uses — an
            .xlsx IS a zip. A second copy of either in another file would drift the day one of
            them is fixed. Checked against the export list before adding: neither name was
            here (see the 29-Aug note above about what a duplicate export costs). */
         xlsxBytes, zipBytes,
         /* added 17-Aug-2026 for the twice-daily position mail (daily-index.js), and since
            29-Aug-2026 the Accounts page bills off this SAME line. typeOfSub is the ONE place
            that decides Motor TP from Health — the mail and the invoice must ask it, not carry
            a second opinion, or his 849/793 split would drift from every screen in the portal.
            firstFO reads the first officer off a shared case the same way the rest does. */
         typeOfSub, firstFO,
         /* added 17-Aug-2026 so the suite can hold the account-naming rule directly: a name
            is only ever produced by looking a NUMBER up in this account's own agent list.
            Exported for the test, not for another page — every page gets its name from the
            call stamp, never by calling this a second time with its own idea of the list. */
         acefoneWho, acefoneWhoLabel,
         /* added 17-Aug-2026 with the webhook key move. Exported so the suite can hold the
            precedence rule directly — KV first, the Cloudflare variable as the fallback that
            never stops working — and prove the built URL keeps Acefone's $words unencoded. */
         webhookKeyOf, webhookUrlFor, maskKey,
         /* added 17-Aug-2026 with the Acefone token move. Exported so the suite can hold the
            precedence rule directly — and this one is the REVERSE of the webhook key's: a
            Cloudflare variable always wins, because it is the safer home for a credential
            somebody else issued. */
         acefoneTokenOf,
         /* v14.1 — the VIDEO CALL page (call-index.js). The guest link is an HMAC-signed
            token, signed with THIS worker's SESSION_SECRET through THIS worker's hmac(). A
            second copy of the signing code inside the call module is exactly how the desk and
            the guest page end up disagreeing about whether a link is valid, so the three
            primitives are exported rather than re-typed.
            Sujit, 24-Aug-2026: "For video calling this website, I want this website itself
            below the field tracking. I need a separate option." */
         hmac, b64urlStr, b64urlToStr,
         /* v20.0 — the ALLOCATION page (assign-index.js) has to WRITE to SKD, not only read
            it: Praveen's POST /assign/{claim}/assign-fo. Every other call to that server in
            this file goes out with a token from getToken(), and the write must carry the
            SAME one — a second login inside the assign module would mean two tokens, two
            expiries, and a 401 that only ever appears on the one path nobody tests.
            Checked against this list before adding: getToken was not on it (see the 29-Aug
            note above about what a duplicate export costs). */
         getToken,
         /* v20.3 — the TAT engine's two new pieces, exported so the suite can hold them:
            the strict state read (a D1 fault must not be read as an empty memory) and the
            age-from-created-date fallback for a case SKD sends no TAT for. */
         stGetStrict, ootatAgeDays, ootatSplit,
         /* v20.3 — the REPORTING page (reporting-index.js) writes the ICLM investigation
            report from the field's documents through the same generateMPA every report has
            always come from — one prompt, one field list, never a second copy. */
         generateMPA, MPA_FIELD_KEYS, findCaseByClaim, isClientRole,
         /* v24.0 — the AI queue writes a connector-built report through the same check */
         validateMPA,
         /* v21.0 — MEDICAL BILL VERIFICATION (mbv-index.js). mbvRoleOf is the ONE reading of
            operator / checker / admin, so the sidebar, the page and the module cannot disagree;
            fetchSkdFile is the proven multi-auth road to a field officer's photograph in SKD's
            document store, which the visit-proof step reads through rather than growing a
            second copy of the retries. Both checked against this list first (29-Aug rule). */
         mbvRoleOf, fetchSkdFile,
         /* v21.1 — CLAUDE IN THE PORTAL (assist-index.js) mints a short session for the member so
            every tool call goes back through the front door AS that member — the same cookie the
            browser carries, signed by the same secret — instead of growing a second permission
            system. Checked against this list first (29-Aug rule). */
         makeSession,
         /* v33.7 — the ONE product classifier (TP · Health · OD · MBV) and its pills, for count-index and the suites */
         productOf, productKey, productParent, productPills, PRODUCTS,
         /* v33.8 — field officer → OHS, off the Teams store, for the suites */
         ohsIndexFor,
         /* v26.7 — the questionnaire set table and the four small rules that make one engine's
            questionnaire the same shape as another's: the number he typed (qCount), the answer
            allowance that grows with it (qTokens), the tidy-up every engine's list goes through
            (qTidy) and the one temperature they all obey (aiTemp). Exported so run-qbuild264
            can hold each of them to his own sentences. */
         Q_SUBJECTS, Q_MAX_QUESTIONS, qSet, qCount, qTokens, qTidy, qSystemPrompt, aiTemp, generateQuestionnaire,
         /* v31.10 — the reader that turned a cut-off answer into six damaged questions on
            98504371, and the two pieces that now salvage it. Exported so run-qcount3110 can
            hold them to the exact text that came back off his screen. */
         extractJsonArray, jsonArraySalvage, jsonArrayWasCut,
         /* v26.8 — the three papers in one press, and the set list they run over */
         generateQuestionnaireAll, Q_ALL_SETS };
