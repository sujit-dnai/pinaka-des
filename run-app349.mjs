/* ══ v34.9 — PASSWORD SIGN-IN (portal + Pinaka), THE TWO DOORS, LIVE TRACKING, TRAVEL EXPENSES ══
   node run-app349.mjs   (harness copied from run-app348.mjs)
   was: node run-app348.mjs        (plain node 22 — node:sqlite stands in for D1)

   Sujit, 27-Sep: "if I select any field officer from my portal, need to alarm at app ... all
   access need to be kept from portal itself."

   §1 the clock and the fence (pure)          §6 the 2-minute tick: SKD-given cases, moved, re-ring
   §2 the portal gives access (a code)        §7 reject rings the portal bell
   §3 the phone signs in with it              §8 the portal signs a phone out
   §4 his cases, only his, cross-origin       §9 the pages and the wiring
   §5 ALLOCATE RINGS HIS PHONE (Firebase)                                                     */

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import entry from './entry.js';
import { makeSession, bookTick, claimKey } from './worker.js';
import { kmOfPoints, expenseStep, seesOfficer, liveState, istDay, appTick } from './app-index.js';
import { tidyEnglish, isFiller, langForState, sniffAudio } from './voice-index.js';

let PASS = 0, FAIL = 0;
const ok = (n, c, d) => { if (c) { PASS++; console.log('  ✓ ' + n); } else { FAIL++; console.log('  ✗ FAIL: ' + n + (d !== undefined ? '\n      ' + String(d).slice(0, 700) : '')); } };

function makeD1() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE IF NOT EXISTS portal_state (k TEXT PRIMARY KEY, v TEXT)');
  const stmt = (sql) => { let args = []; const api = { bind(...a) { args = a.map(x => x === undefined ? null : x); return api; },
    async run() { const s = db.prepare(sql); const r = s.run(...args); return { success: true, meta: { changes: Number(r.changes || 0), last_row_id: Number(r.lastInsertRowid || 0) } }; },
    async all() { const s = db.prepare(sql); try { return { results: s.all(...args) }; } catch (e) { if (/does not return data/.test(String(e))) { s.run(...args); return { results: [] }; } throw e; } },
    async first() { const s = db.prepare(sql); try { return s.get(...args) || null; } catch (e) { if (/does not return data/.test(String(e))) { s.run(...args); return null; } throw e; } } }; return api; };
  return { prepare: stmt, async batch(list) { const out = []; for (const s of list) out.push(await s.run()); return out; }, _db: db };
}
function makeR2() {
  const store = new Map();
  return { _store: store,
    async put(k, v, o) { store.set(k, { v: String(v), o: o || {} }); return {}; },
    async get(k) { const x = store.get(k); return x ? { key: k, httpMetadata: x.o.httpMetadata, customMetadata: x.o.customMetadata, async text() { return x.v; } } : null; },
    async head(k) { const x = store.get(k); return x ? { key: k, size: x.v.length, customMetadata: x.o.customMetadata } : null; },
    async delete(k) { store.delete(k); }, async list() { return { objects: [...store.keys()].map(key => ({ key })) }; } };
}
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const KV = new Map();
const ASSET_LOG = [];
const env = { DB: makeD1(), USERS: { async get(k) { return KV.has(k) ? KV.get(k) : null; }, async put(k, v) { KV.set(k, v); }, async delete(k) { KV.delete(k); }, async list(o) { const keys = []; for (const k of KV.keys()) if (!o || !o.prefix || k.startsWith(o.prefix)) keys.push({ name: k }); return { keys }; } },
  SESSION_SECRET: 'test-secret', PHOTOS: makeR2(), AI: null, ADMIN_EMAILS: 'sujith.dn@skdhealth.com',
  ASSETS: { async fetch(req) { ASSET_LOG.push(new URL(req.url || req).pathname); return new Response('asset ' + new URL(req.url || req).pathname, { status: 200, headers: { 'content-type': 'text/plain' } }); } },
  SKD_API_BASE: 'https://skdhealth.net/o/corinsoft', SKD_USERNAME: 'u', SKD_PASSWORD: 'p', SKD_DEVICE_ID: 'd', SKD_TIMEOUT_MS: '1500', SKD_FO_PATH: '/users/fo',
  FCM_PROJECT_ID: 'pinaka-test', FCM_CLIENT_EMAIL: 'pinaka@pinaka-test.iam.gserviceaccount.com', FCM_PRIVATE_KEY: privateKey.replace(/\n/g, '\\n') };
const waited = [];
const ctx = { waitUntil(p) { waited.push(p); Promise.resolve(p).catch(() => { }); } };
const flush = async () => { while (waited.length) await waited.shift(); };
const ADMIN = 'sujith.dn@skdhealth.com', COORD = 'coord@skdhealth.com';
KV.set('u:' + ADMIN, JSON.stringify({ email: ADMIN, name: 'Sujit D N', role: 'admin', status: 'approved' }));
KV.set('u:' + COORD, JSON.stringify({ email: COORD, name: 'Coord', role: 'coordinator', status: 'approved', access: ['dashboard'] }));
const cookieFor = async (email) => '__Host-skd_session=' + encodeURIComponent(await makeSession(env, { email, name: 'x', exp: Math.floor(Date.now() / 1000) + 3600 }));
const call = async (path, body, o) => {
  o = o || {};
  const h = { 'content-type': 'application/json', Accept: 'application/json' };
  if (o.as) h.Cookie = await cookieFor(o.as);
  if (o.token) h.authorization = 'Bearer ' + o.token;
  /* v34.9 — the current app says who it is (the version gate stops an old installed app) */
  if (!o.oldApp) { h['x-app-version'] = o.appVersion || '2.1.1'; h['x-app-platform'] = o.platform || 'web'; }
  if (o.origin) h.origin = o.origin;
  /* v34.9 — one phone per officer: when a test signs the SAME officer in again, the harness hands back
     that officer's live phone token (the portal answered 409 onePhone). A real second phone: { fresh: true }. */
  const res = await entry.fetch(new Request('https://taasenclaims.com' + path, { method: o.method || (body ? 'POST' : 'GET'), headers: h, body: body ? JSON.stringify(body) : undefined }), env, ctx);
  if ((path === '/api/app/login' || path === '/api/app/activate') && body) {
    const j = await res.clone().json().catch(() => null);
    if (j && j.ok && j.device) { const d = env.DB._db.prepare('SELECT ukey FROM app_devices WHERE id = ?').get(j.device); if (d) LOGINS.set(d.ukey, j); }
    else if (j && j.onePhone && !o.fresh) {
      const id = String(body.id || '').toLowerCase(), ph = id.replace(/\D/g, '').slice(-10);
      const r = env.DB._db.prepare('SELECT ukey, name FROM app_officers WHERE lower(emp_id) = ? OR lower(user) = ? OR (length(?) = 10 AND phone = ?) OR ukey = ?').get(id, id, ph, ph, id);
      const c = r && LOGINS.get(r.ukey), live = c && env.DB._db.prepare('SELECT revoked_at FROM app_devices WHERE id = ?').get(c.device);
      if (c && live && !live.revoked_at) return new Response(JSON.stringify(c), { status: 200, headers: { 'content-type': 'application/json' } });
      if (r) { env.DB._db.prepare('UPDATE app_devices SET revoked_at = ? WHERE ukey = ? AND revoked_at IS NULL').run(Date.now(), r.ukey); return call(path, body, o); }
    }
  }
  return res;
};
const LOGINS = new Map();
const J = async (...a) => { const r = await call(...a); const j = await r.json().catch(() => ({})); return Object.assign(j, { _status: r.status, _h: r.headers }); };

let BOOK = [
  { claimNumber: 'A100', client: 'HDFC ERGO', subProduct: 'MOTOR TP FULL INVESTIGATION', patientName: 'Arun', status: 'FO Accepted', skdTat: '9D', fieldOfficers: ['MILTON VEMU'], manager: 'hemalatha a', contactNo: '9000000001' },
  { claimNumber: 'B200', client: 'HDFC ERGO', subProduct: 'HEALTH FULL INVESTIGATION', patientName: 'Bala', status: 'Assigned', skdTat: '5D', fieldOfficers: ['Kiran Nimmala'], manager: 'hemalatha a' },
  { claimNumber: 'S300', client: 'Care', subProduct: 'HEALTH FULL INVESTIGATION', patientName: 'Selvi', status: 'Assigned', skdTat: '5D', fieldOfficers: ['Kiran Nimmala', 'Milton Vemu'], manager: 'x',
    stackHolders: { 'Kiran Nimmala': 'Hospital Verification - Assigned', 'Milton Vemu': 'Insured verification - Assigned' } }
];
const ROSTER = [
  { firstName: 'MILTON', lastName: 'VEMU', userName: 'milton.v', mobileNumber: '9876543210', state: 'Tamil Nadu', status: 'Active' },
  { firstName: 'Kiran', lastName: 'Nimmala', userName: 'kiran.n', mobileNumber: '9123456780', state: 'Andhra Pradesh', status: 'Active' }
];
const FCM = [], ASSIGN = [];
globalThis.fetch = async (url, init) => {
  const u = String(url), host = new URL(u).host;
  if (/skdhealth\.net/.test(host)) {
    if (/\/auth\/login/.test(u)) return new Response(JSON.stringify({ jwtToken: 'tok' }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (/\/cases\/open-cases/.test(u)) return new Response(JSON.stringify({ total: BOOK.length, data: BOOK }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (/\/users\/fo/.test(u)) return new Response(JSON.stringify(ROSTER), { status: 200, headers: { 'content-type': 'application/json' } });
    if (/\/assign\//.test(u)) { ASSIGN.push(u); return new Response(JSON.stringify({ message: 'assigned' }), { status: 200, headers: { 'content-type': 'application/json' } }); }
    if (/\/cases\/claim\//.test(u)) return new Response(JSON.stringify({ caseDetails: [{}], caseHistory: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
  }
  if (host === 'oauth2.googleapis.com') return new Response(JSON.stringify({ access_token: 'ya29.test', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } });
  if (host === 'fcm.googleapis.com') {
    const b = JSON.parse(init.body);
    FCM.push({ url: u, auth: init.headers.authorization, body: b });
    if (b.message.token === 'dead-token-xxxxxxxxxxxxxxxxxxxxx') return new Response('{"error":{"status":"NOT_FOUND","message":"UNREGISTERED"}}', { status: 404 });
    return new Response('{"name":"projects/pinaka-test/messages/1"}', { status: 200 });
  }
  return new Response('{"ok":false}', { status: 502 });
};
const db = env.DB._db;
const IST = 330 * 60000;
const istAt = (h, m) => { const d = new Date(Date.now() + IST); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), h, m || 0) - IST; };


KV.set('u:client@icici.com', JSON.stringify({ email: 'client@icici.com', name: 'ICICI Desk', role: 'client-manager', status: 'approved', clients: ['ICICI'] }));
KV.set('u:ohs@skdhealth.com', JSON.stringify({ email: 'ohs@skdhealth.com', name: 'OHS One', role: 'ohs', status: 'approved', team: 't1' }));
KV.set('team:t1', JSON.stringify({ name: 'Team 1', head: 'OHS One', members: ['MILTON VEMU'] }));
KV.set('u:sc@skdhealth.com', JSON.stringify({ email: 'sc@skdhealth.com', name: 'SC TN', role: 'coordinator', status: 'approved', states: ['Tamil Nadu'] }));
const cookieOf = (r) => (r.headers.get('set-cookie') || '').split(';')[0];

console.log('\n══ 1 · PORTAL PASSWORD, TWO DOORS ══');
{
  const noAdmin = await J('/api/auth/password/set', { email: COORD }, { as: COORD });
  ok('only admin/boss set a password', noAdmin._status === 403);
  const set = await J('/api/auth/password/set', { email: COORD }, { as: ADMIN });
  ok('admin makes a password (shown once), must change', set.ok && /^[A-Za-z]{6}\d{4}$/.test(set.password) && set.mustChange === true, JSON.stringify(set));
  const row = env.DB._db.prepare('SELECT * FROM portal_passwords WHERE email = ?').get(COORD);
  ok('only a PBKDF2 hash + salt is kept, never the password', row && row.hash.length === 64 && row.salt.length === 32 && row.iter === 100000 && row.hash.indexOf(set.password) < 0);
  const bad = await J('/api/auth/password', { email: COORD, password: 'wrong123x', door: 'taasen' });
  ok('a wrong password → 401', bad._status === 401);
  const ext = await J('/api/auth/password', { email: COORD, password: set.password, door: 'external' });
  ok('a staff login at the External door is refused and sent back', ext._status === 403 && /TaaSen User/.test(ext.error));
  const r = await call('/api/auth/password', { email: COORD, password: set.password, door: 'taasen' });
  const j = await r.json();
  ok('the right password at the TaaSen door → signed in, with mustChange', j.ok && j.status === 'approved' && j.mustChange === true && /skd_session=/.test(r.headers.get('set-cookie') || ''), JSON.stringify(j));
  const weak = await J('/api/auth/password/change', { password: 'short' }, { as: COORD });
  ok('his own new password must be 8+ with letters and numbers', weak._status === 400);
  const ch = await J('/api/auth/password/change', { password: 'Kavitha2026' }, { as: COORD });
  ok('he sets his own (no old password asked while must_change)', ch.ok);
  const again = await J('/api/auth/password', { email: COORD, password: 'Kavitha2026', door: 'taasen' });
  ok('...and signs in with it, no longer asked to change', again.ok && again.mustChange === false);
  const ch2 = await J('/api/auth/password/change', { password: 'Another2026', old: 'nope' }, { as: COORD });
  ok('after that, changing asks for the present password', ch2._status === 401);
  await J('/api/auth/password/set', { email: 'client@icici.com', password: 'IciciDesk2026' }, { as: ADMIN });
  const c1 = await J('/api/auth/password', { email: 'client@icici.com', password: 'IciciDesk2026', door: 'taasen' });
  ok('an insurer login at the TaaSen door is refused', c1._status === 403 && /External User/.test(c1.error));
  const c2 = await J('/api/auth/password', { email: 'client@icici.com', password: 'IciciDesk2026', door: 'external' });
  ok('...and let in at the External door', c2.ok && c2.status === 'approved');
  for (let i = 0; i < 8; i++) await J('/api/auth/password', { email: COORD, password: 'bad' + i + 'xxxxx', door: 'taasen' });
  const locked = await J('/api/auth/password', { email: COORD, password: 'Kavitha2026', door: 'taasen' });
  ok('8 wrong passwords lock the mail ID for 15 minutes — even the right one waits', locked._status === 429);
  const html = fs.readFileSync('index.html', 'utf8');
  ok('the sign-in page opens on the two doors: TaaSen User and External User', /data-door="taasen"[\s\S]{0,200}TaaSen User/.test(html) && /data-door="external"[\s\S]{0,200}External User/.test(html));
  ok('...the OTP box is still in the page but no longer offered', /<div class="divider" style="display:none">/.test(html) && /id="otpSend"/.test(html));
  const adm = fs.readFileSync('admin.html', 'utf8');
  ok('Admin → Members drawer has Set password', /data-act="setpw"/.test(adm) && /\/api\/auth\/password\/set/.test(adm));
}

console.log('\n══ 2 · PINAKA PASSWORD ══');
let TOKEN = '';
{
  await bookTick(env, Date.now());
  const p = await J('/api/app/admin/password', { name: 'MILTON VEMU' }, { as: ADMIN });
  ok('Pinaka App → Set password for an officer (shown once, his SKD user name to type)', p.ok && p.loginId === 'milton.v' && p.password.length === 10, JSON.stringify(p));
  const bad = await J('/api/app/login', { id: 'milton.v', password: 'nope1234' });
  ok('wrong password → 401', bad._status === 401);
  const good = await J('/api/app/login', { id: '9876543210', password: p.password, platform: 'android' });
  ok('Employee ID OR mobile + password → a device token', good.ok && /^pk_/.test(good.token) && good.officer.name === 'MILTON VEMU');
  TOKEN = good.token;
  const list = await J('/api/app/admin/officers', null, { as: ADMIN });
  ok('the officer list shows "password set"', list.officers.find(o => o.name === 'MILTON VEMU').hasPassword === true);
  const cases = await J('/api/app/cases', null, { token: TOKEN });
  ok('his cases load; A100 has no alarm row (it was his before he signed in)', cases.ok && cases.cases.find(c => c.claim === 'A100').app === null);
  const acc = await J('/api/app/accept', { claim: 'A100' }, { token: TOKEN });
  ok('"Where is the accepted button?" — Accept by CLAIM works on a case that never rang', acc.ok, JSON.stringify(acc));
  const notHis = await J('/api/app/accept', { claim: 'B200' }, { token: TOKEN });
  ok('...but not on a case that is not his', notHis._status === 404);
  const cs2 = await J('/api/app/cases', null, { token: TOKEN });
  ok('...and A100 now shows accepted', !!cs2.cases.find(c => c.claim === 'A100').app.acceptedAt);
}

console.log('\n══ 3 · LIVE TRACKING ══');
{
  ok('km: two points 1.6 km apart', kmOfPoints([{ lat: 13.08, lng: 80.27, at: 0 }, { lat: 13.09, lng: 80.28, at: 600000 }]) === 1.6);
  ok('km: a jump faster than 150 km/h is left out', kmOfPoints([{ lat: 13.08, lng: 80.27, at: 0 }, { lat: 14.08, lng: 80.27, at: 60000 }]) === 0);
  ok('km: a bad fix (accuracy 500 m) is left out', kmOfPoints([{ lat: 13.08, lng: 80.27, at: 0 }, { lat: 13.09, lng: 80.28, acc: 500, at: 600000 }]) === 0);
  const t0 = Date.now();
  ok('live states: moving / stopped / no signal / GPS off / off duty',
    liveState({ on_duty: 1, last_at: t0, last_speed: 5 }, t0) === 'moving' && liveState({ on_duty: 1, last_at: t0, last_speed: 0 }, t0) === 'stopped' &&
    liveState({ on_duty: 1, last_at: t0 - 50 * 60000 }, t0) === 'silent' && liveState({ on_duty: 1, gps_off: 1 }, t0) === 'gps_off' && liveState({ on_duty: 0 }, t0) === 'off');
  const d = await J('/api/app/duty', { on: true }, { token: TOKEN });
  ok('Start duty', d.ok && d.onDuty);
  const now = Date.now();
  const loc = await J('/api/app/location', { points: [{ lat: 13.0827, lng: 80.2707, acc: 10, speed: 6, at: now - 120000 }, { lat: 13.0927, lng: 80.2807, acc: 10, speed: 6, at: now - 60000 }, { lat: 999, lng: 1, at: now }] }, { token: TOKEN });
  ok('points are saved (a bad one is dropped)', loc.ok && loc.saved === 2);
  const live = await J('/api/app/admin/live', null, { as: ADMIN });
  const m = live.officers.find(o => o.name === 'MILTON VEMU');
  ok('the Live Board shows him Moving at his last point', m && m.status === 'moving' && m.lat === 13.0927, JSON.stringify(m));
  await J('/api/app/location', { points: [], gps: 'off' }, { token: TOKEN });
  const live2 = await J('/api/app/admin/live', null, { as: ADMIN });
  ok('GPS switched off on duty → red GPS OFF on the board', live2.officers.find(o => o.name === 'MILTON VEMU').status === 'gps_off');
  const today = new Date(Date.now() + 330 * 60000).toISOString().slice(0, 10);
  const rt = await J('/api/app/admin/route?name=MILTON%20VEMU&date=' + today, null, { as: ADMIN });
  ok('a day\'s route with its km', rt.ok && rt.points.length === 2 && rt.km > 1);
  const ohsLive = await J('/api/app/admin/live', null, { as: 'ohs@skdhealth.com' });
  ok('an OHS sees the Live Board for HIS team (Milton is in it)', ohsLive.ok && ohsLive.officers.length === 1);
  const ohsOff = await J('/api/app/admin/officers', null, { as: 'ohs@skdhealth.com' });
  ok('...but not the officer access list (codes, passwords)', ohsOff._status === 403);
  const km = await J('/api/app/km?date=' + today, null, { token: TOKEN });
  ok('the phone asks its own GPS km for a day', km.ok && km.km > 1);
  const night = new Date(); const at22 = (() => { const x = new Date(Date.now() + 330 * 60000); return Date.UTC(x.getUTCFullYear(), x.getUTCMonth(), x.getUTCDate(), 22, 0) - 330 * 60000; })();
  await appTick(env, at22);
  ok('every duty ends by itself at night', env.DB._db.prepare("SELECT on_duty FROM app_duty").get().on_duty === 0);
}

console.log('\n══ 4 · EXPENSES: TODAY\'s purposes and limits; officer → OHS → State Coordinator → Admin → Paid ══');
{
  const today = new Date(Date.now() + 330 * 60000).toISOString().slice(0, 10);
  const bill = await entry.fetch(new Request('https://taasenclaims.com/api/app/expense/bill', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + TOKEN, 'content-type': 'image/jpeg', 'x-file-name': 'ticket.jpg' }, body: new Uint8Array([255, 216, 255, 1, 2, 3]) }), env, ctx);
  const bj = await bill.json();
  ok('a bill photo is stored in R2 under his own folder, with its name', bj.ok && /^pinaka\/bills\/milton-vemu\//.test(bj.key) && env.PHOTOS._store.has(bj.key) && bj.name === 'ticket.jpg');
  const xls = await entry.fetch(new Request('https://taasenclaims.com/api/app/expense/bill', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + TOKEN, 'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'x-file-name': 'bill.xlsx' }, body: new Uint8Array([80, 75, 3, 4]) }), env, ctx);
  ok('TODAY\'s document types are taken (Excel here)', (await xls.json()).ok);
  const apk = await entry.fetch(new Request('https://taasenclaims.com/api/app/expense/bill', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + TOKEN, 'content-type': 'application/zip', 'x-file-name': 'evil.apk' }, body: new Uint8Array([1]) }), env, ctx);
  ok('an .apk (or html / svg / exe / js) is blocked', apk.status === 415);
  const auto = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Auto Fare', amount: 81, bills: [bj.key] }, { token: TOKEN });
  ok('Auto Fare ₹81 → "Maximum amount for Auto Fare is ₹80"', auto._status === 400 && auto.error === 'Maximum amount for Auto Fare is ₹80');
  const bad = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Food Allowance', amount: '12.345', bills: [bj.key] }, { token: TOKEN });
  ok('three decimals → "Please enter a valid number"', bad._status === 400 && bad.error === 'Please enter a valid number');
  const nob = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Bus Ticket', amount: 120 }, { token: TOKEN });
  ok('no bill → "Please attach a document (Mandatory)"', nob._status === 400 && nob.error === 'Please attach a document (Mandatory)');
  const none = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'No Expenses' }, { token: TOKEN });
  ok('No Expenses → ₹0, no bill needed', none.ok && none.amount === 0);
  const none2 = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'No Expenses', amount: 5 }, { token: TOKEN });
  ok('...and any other amount → "Amount must be ₹0 for No Expenses"', none2._status === 400 && none2.error === 'Amount must be ₹0 for No Expenses');
  const fut = await J('/api/app/expenses', { claim: 'A100', date: '2099-01-01', purpose: 'Bus Ticket', amount: 50, bills: [bj.key] }, { token: TOKEN });
  ok('a future date is refused', fut._status === 400);
  const fuel = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Fuel', from: 'Office', to: 'Apollo', touchPoint: 'Hospital Verification' }, { token: TOKEN });
  const e1 = env.DB._db.prepare('SELECT * FROM app_expenses WHERE id = ?').get(fuel.id);
  ok('Fuel by km (on by default, ₹4/km): GPS km × 4, no bill', fuel.ok && e1.km_gps > 1 && e1.rate === 4 && e1.amount === Math.round(e1.km_gps * 4 * 100) / 100 && e1.touch_point === 'Hospital Verification', JSON.stringify(e1));
  const edited = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Fuel', km: 40 }, { token: TOKEN });
  ok('changing the GPS km needs a reason', edited._status === 400 && /reason/.test(edited.error));
  const bus2 = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Bus Ticket', amount: '120', bills: [bj.key, 'pinaka/bills/someone-else/x.jpg'] }, { token: TOKEN });
  const e2 = env.DB._db.prepare('SELECT * FROM app_expenses WHERE id = ?').get(bus2.id);
  ok('Bus Ticket with the bill → submitted ("Expense added successfully ✅"); a key from another officer\'s folder is dropped', bus2.ok && bus2.message === 'Expense added successfully ✅' && JSON.parse(e2.bills).length === 1 && e2.status === 'submitted');
  const dup = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Bus Ticket', amount: '120', bills: [bj.key] }, { token: TOKEN });
  ok('the same purpose, amount and date → "Looks like a duplicate — submit anyway?"', dup._status === 409 && dup.duplicate === true);
  const dup2 = await J('/api/app/expenses', { claim: 'A100', date: today, purpose: 'Bus Ticket', amount: '120', bills: [bj.key], force: true }, { token: TOKEN });
  ok('...submit anyway works, and is flagged for the checker', dup2.ok);
  const edit = await J('/api/app/expenses', { id: dup2.id, claim: 'A100', date: today, purpose: 'Bus Ticket', amount: '110', bills: [bj.key], force: true }, { token: TOKEN });
  ok('edit while Submitted', edit.ok && env.DB._db.prepare('SELECT amount FROM app_expenses WHERE id = ?').get(dup2.id).amount === 110);
  const del = await J('/api/app/expenses/delete', { id: dup2.id }, { token: TOKEN });
  ok('delete while Submitted', del.ok && !env.DB._db.prepare('SELECT id FROM app_expenses WHERE id = ?').get(dup2.id));
  const r1 = await J('/api/app/admin/settings', { bikeRate: 5 }, { as: 'ohs@skdhealth.com' });
  ok('only admin/boss change the rate', r1._status === 403);
  const set = await J('/api/app/admin/settings', { purposes: [{ name: 'Parking', max: 50 }, { name: 'Auto Fare', max: 100 }] }, { as: ADMIN });
  ok('Field Masters: a new purpose is added, a limit changed, and TODAY\'s nine all stay', set.ok && set.purposes.length === 10 && set.purposes.find(p => p.name === 'Parking').max === 50 && set.purposes.find(p => p.name === 'Auto Fare').max === 100 && set.purposes.find(p => p.name === 'No Expenses'));
  await J('/api/app/admin/settings', { purposes: [{ name: 'Auto Fare', max: 80 }] }, { as: ADMIN });
  const sc0 = await J('/api/app/admin/expense', { id: bus2.id, action: 'approve' }, { as: 'sc@skdhealth.com' });
  ok('the State Coordinator cannot approve before the OHS', sc0._status === 403);
  const ohsList = await J('/api/app/admin/expenses', null, { as: 'ohs@skdhealth.com' });
  ok('the OHS sees it waiting for him', ohsList.expenses.find(x => x.id === bus2.id).step === 'l1');
  const chg = await J('/api/app/admin/expense', { id: bus2.id, action: 'approve', amount: 100 }, { as: 'ohs@skdhealth.com' });
  ok('changing the amount needs a note', chg._status === 400);
  const l1 = await J('/api/app/admin/expense', { id: bus2.id, action: 'approve', amount: 100, note: 'bus fare is 100' }, { as: 'ohs@skdhealth.com' });
  ok('OHS approves ₹100 with a note → waits for the State Coordinator', l1.ok && l1.status === 'l1' && l1.amount === 100);
  const l2 = await J('/api/app/admin/expense', { id: bus2.id, action: 'approve' }, { as: 'sc@skdhealth.com' });
  ok('State Coordinator (Tamil Nadu) approves → waits for Admin', l2.ok && l2.status === 'l2');
  const l3 = await J('/api/app/admin/expense', { id: bus2.id, action: 'approve' }, { as: ADMIN });
  ok('Admin approves → Approved', l3.ok && l3.status === 'approved');
  const paid = await J('/api/app/admin/expense', { id: bus2.id, action: 'paid' }, { as: ADMIN });
  ok('Admin marks it Paid', paid.ok && paid.status === 'paid');
  const bulk = await J('/api/app/admin/expenses/bulk', { ids: [fuel.id, none.id] }, { as: ADMIN });
  ok('bulk approve (admin) takes the rows within the limit with no flag', bulk.ok && bulk.approved === 2, JSON.stringify(bulk));
  const rej2 = await J('/api/app/admin/expense', { id: fuel.id, action: 'reject', note: 'not on duty that day' }, { as: ADMIN });
  ok('reject with a reason', rej2.ok);
  const mine = await J('/api/app/expenses', null, { token: TOKEN });
  ok('the officer\'s list shows Paid and Rejected with the note, plus the purposes and the rate', mine.expenses.find(x => x.id === bus2.id).status === 'paid' && mine.expenses.find(x => x.id === fuel.id).rejected.note === 'not on duty that day' && mine.purposes.length >= 9 && mine.bikeRate === 4);
  const month = today.slice(0, 7);
  const x = await call('/api/app/admin/expenses.xlsx?month=' + month, null, { as: ADMIN });
  ok('the month Excel downloads', x.status === 200 && /spreadsheet/.test(x.headers.get('content-type')));
  const po = await J('/api/app/admin/expenses/payout', {}, { as: ADMIN });
  ok('Approved → Payouts: with nothing approved-and-unpaid it says so', po._status === 409 || po.ok);
  const bl = await call('/api/app/admin/bill?key=' + encodeURIComponent(bj.key), null, { as: ADMIN });
  ok('the portal opens the bill', bl.status === 200);
  ok('expenseStep: nothing for a coordinator on another state', expenseStep({ role: 'coordinator', states: ['Kerala'] }, { status: 'l1', officer: 'X', state: 'Tamil Nadu' }) === '');
}

console.log('\n══ 5 · PASSWORDS FOR ALL (Excel) ══');
{
  const r = await call('/api/auth/password/bulk', { only: 'missing' }, { as: ADMIN });
  ok('members without a password get one, as an Excel', r.status === 200 && /spreadsheet/.test(r.headers.get('content-type')));
  const again = await J('/api/auth/password/bulk', { only: 'missing' }, { as: ADMIN });
  ok('...a second run: everybody already has one', again.ok && again.count === 0);
  const no = await J('/api/auth/password/bulk', {}, { as: COORD });
  ok('not for a coordinator', no._status === 403 || no._status === 401);
  const o = await call('/api/app/admin/password/bulk', { only: 'missing' }, { as: ADMIN });
  ok('officers without a Pinaka password get one, as an Excel (Kiran here)', o.status === 200 && /spreadsheet/.test(o.headers.get('content-type')));
}

console.log('\n══ 6 · TRANSLATOR — /api/fo/v1/voice ══');
{
  ok('tidy English: F.I.R → FIR, Rs 2500 → ₹2,500, in-patient number → IP number', tidyEnglish('F.I.R 245/2026, Rs 2500 paid, in-patient number 45872') === 'FIR 245/2026, ₹2,500 paid, IP number 45872', tidyEnglish('F.I.R 245/2026, Rs 2500 paid, in-patient number 45872'));
  ok('Whisper\'s fillers are caught ("Thank you.", "[Music]")', isFiller('Thank you.') && isFiller('[Music]') && isFiller('  ') && !isFiller('The insured was admitted on 12-09-2026'));
  ok('language by state: TN Tamil, KA Kannada, KL Malayalam, AP/TS Telugu, MH Marathi', langForState('Tamil Nadu') === 'ta' && langForState('Karnataka') === 'kn' && langForState('Kerala') === 'ml' && langForState('Andhra Pradesh & Telangana') === 'te' && langForState('Maharashtra') === 'mr' && langForState('Goa') === 'auto');
  const SAMPLE = 'The insured was admitted on 12-09-2026 at Apollo Hospital, IP number 45872, discharged on 15-09-2026. Bills of Rs 2500 were verified.';
  const calls = [];
  let MODE = 'ok';
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (/api\.sarvam\.ai/.test(u)) {
      calls.push({ who: 'sarvam', key: init.headers['api-subscription-key'], mode: init.body.get('mode'), model: init.body.get('model'), lang: init.body.get('language_code') });
      if (MODE === 'sarvamDown') return new Response('{"error":{"message":"down"}}', { status: 503 });
      if (MODE === 'silent') return new Response(JSON.stringify({ transcript: 'Thank you.', language_code: 'ta-IN', language_probability: 0.9 }), { status: 200 });
      return new Response(JSON.stringify(init.body.get('mode') === 'translate' ? { transcript: SAMPLE, language_code: 'ta-IN', language_probability: 0.93 } : { transcript: 'காப்பீட்டாளர் 12-09-2026 அன்று…', language_code: 'ta-IN' }), { status: 200 });
    }
    if (/api\.openai\.com\/v1\/audio\/(translations|transcriptions)/.test(u)) {
      calls.push({ who: 'openai', path: u.split('/audio/')[1], model: init.body.get('model'), auth: init.headers.authorization });
      return new Response(JSON.stringify({ text: u.includes('translations') ? SAMPLE : 'மூலம்' }), { status: 200 });
    }
    return realFetch(url, init);
  };
  env.SARVAM_API_KEY = 'sk_sarvam_test'; env.TRANSLATOR_OPENAI_KEY = 'sk-openai-test';
  const clip = (seq, extra) => entry.fetch(new Request('https://taasenclaims.com/api/fo/v1/voice', { method: 'POST', headers: Object.assign({ authorization: 'Bearer ' + TOKEN, 'content-type': 'audio/webm', 'x-lang': 'ta', 'x-field': 'eRem', 'x-case': 'A100', 'x-clip': 'c1', 'x-seq': String(seq), 'x-seconds': '28' }, extra || {}), body: new Uint8Array(4000).fill(7) }), env, ctx);
  const no = await entry.fetch(new Request('https://taasenclaims.com/api/fo/v1/voice', { method: 'POST', headers: { 'content-type': 'audio/webm' }, body: new Uint8Array(10) }), env, ctx);
  ok('no device token → 401 (no key, no door)', no.status === 401);
  const dcfg = await J('/api/fo/v1/voice/settings', null, { as: ADMIN });
  ok('v34.9 (28-Sep): until admin re-orders, OpenAI is first and Gemini the backup', dcfg.ok && dcfg.cfg.engines[0] === 'openai' && dcfg.cfg.engines[1] === 'gemini', JSON.stringify(dcfg.cfg && dcfg.cfg.engines));
  await J('/api/fo/v1/voice/settings', { engines: ['sarvam', 'openai', 'workers'] }, { as: ADMIN });   /* the checks below walk Sarvam → OpenAI */
  const r1 = await clip(0); const j1 = await r1.json();
  ok('Sarvam first: English back, digits kept, ₹ tidy, "Heard in Tamil" words, engine named', j1.ok && j1.engine === 'sarvam' && /12-09-2026/.test(j1.english) && /₹2,500/.test(j1.english) && /IP number 45872/.test(j1.english) && /காப்பீட்டாளர்/.test(j1.original) && j1.langName === 'Tamil', JSON.stringify(j1));
  const sv = calls.filter(c => c.who === 'sarvam');
  ok('...called with saaras:v3, translate AND transcribe, ta-IN, key in api-subscription-key (from the Worker secret)', sv.some(c => c.mode === 'translate') && sv.some(c => c.mode === 'transcribe') && sv.every(c => c.model === 'saaras:v3' && c.lang === 'ta-IN' && c.key === 'sk_sarvam_test'));
  ok('...the audio is kept as proof in R2 beside his files', /^pinaka\/voice\/milton-vemu\/A100\/c1-0\.webm$/.test(j1.audioKey) && env.PHOTOS._store.has(j1.audioKey));
  const u = env.DB._db.prepare('SELECT * FROM voice_usage ORDER BY id DESC').get();
  ok('the usage log has who / seconds / engine / cost — and NO text', u.ukey === 'milton vemu' && u.seconds === 28 && u.engine === 'sarvam' && u.cost > 0 && !Object.values(u).some(v => String(v).includes('insured')));
  MODE = 'sarvamDown'; calls.length = 0;
  const r2 = await clip(1); const j2 = await r2.json();
  ok('Sarvam down → OpenAI whisper-1 (translations) answers instead', j2.ok && j2.engine === 'openai' && calls.some(c => c.who === 'openai' && c.path === 'translations' && c.model === 'whisper-1' && c.auth === 'Bearer sk-openai-test'), JSON.stringify(j2));
  MODE = 'silent';
  const r3 = await clip(2); const j3 = await r3.json();
  ok('silence → "Sorry, Didn\'t hear that. Speak Loudly"', r3.status === 422 && j3.silence && j3.error === "Sorry, Didn't hear that. Speak Loudly");
  MODE = 'ok';
  const lang = await J('/api/fo/v1/voice/lang', null, { token: TOKEN });
  ok('the phone asks its default language: Tamil for a Tamil Nadu officer', lang.ok && lang.lang === 'ta' && lang.maxSeconds === 120 && lang.silenceSeconds === 4);
  const ohs = await J('/api/fo/v1/voice/settings', null, { as: 'ohs@skdhealth.com' });
  ok('Translator settings: admin and boss only', ohs._status === 403);
  const set = await J('/api/fo/v1/voice/settings', { engines: ['openai', 'sarvam'], dailyLimit: 3, langByOfficer: { 'milton vemu': 'te' }, monthlyCapInr: 1 }, { as: ADMIN });
  ok('admin sets the engine order, a daily limit, his language', set.ok && set.cfg.engines.join() === 'openai,sarvam' && set.cfg.langByOfficer['milton vemu'] === 'te');
  const lang2 = await J('/api/fo/v1/voice/lang', null, { token: TOKEN });
  ok('...and his phone now defaults to Telugu', lang2.lang === 'te');
  const r4 = await clip(0, { 'x-clip': 'c2' }); const j4 = await r4.json();
  ok('the new order is used: OpenAI first', j4.ok && j4.engine === 'openai');
  const r5 = await clip(0, { 'x-clip': 'c3' }); await r5.json();
  const r6 = await clip(0, { 'x-clip': 'c4' }); const j6 = await r6.json();
  ok('the monthly cap stops the Translator and says so (₹1 cap here)', r6.status === 429 && (j6.cap || j6.limit));
  ok('...and the portal bell warned at 80%', !!env.DB._db.prepare("SELECT id FROM alerts WHERE kind = 'translator_cap'").get());
  const usage = await J('/api/fo/v1/voice/usage', null, { as: ADMIN });
  ok('this month\'s use by officer and engine, and which keys are set', usage.ok && usage.rows.length >= 2 && usage.keys.sarvam === true);
  const play = await call('/api/fo/v1/voice/audio?key=' + encodeURIComponent(j1.audioKey), null, { as: ADMIN });
  ok('▶ on the portal plays the proof', play.status === 200 && /audio/.test(play.headers.get('content-type')));
  const exp = await J('/api/app/expenses', { claim: 'A100', date: new Date(Date.now() + 330 * 60000).toISOString().slice(0, 10), purpose: 'No Expenses', force: true, remarks: 'Bus strike today', remarksAudio: [j1.audioKey, 'pinaka/voice/someone-else/x.webm'] }, { token: TOKEN });
  const er = env.DB._db.prepare('SELECT remarks_audio FROM app_expenses WHERE id = ?').get(exp.id);
  ok('an expense remark that came from voice keeps ITS clip (another officer\'s is dropped)', exp.ok && er.remarks_audio === j1.audioKey);
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app has NO API key in it', !/sk-[A-Za-z0-9]{10,}|sk_sarvam|api-subscription-key|OPENAI_API_KEY/.test(html));
  ok('the app records small (24 kbps, mono) and sends 28-second pieces as it records', /audioBitsPerSecond: 24000/.test(html) && /channelCount: 1/.test(html) && /segMs >= 28000/.test(html));
  ok('the messages are today\'s, plus the new noisy one', html.includes("Sorry, Didn't hear that. Speak Loudly") && html.includes('Too noisy — move to a quieter place and try again') && html.includes('Pinaka needs the microphone only while you hold Translator'));
  ok('Add to text is the default, Replace kept, Try again, Discard', /data-tr="add">' \+ S\('trAdd'\)/.test(html) && html.includes("trAdd:'Add to text'") && html.includes("trRep:'Replace text'"));
  /* v34.9 (28-Sep) — Gemini with the key saved on the portal; engine errors are recorded */
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (/generativelanguage\.googleapis\.com\/v1beta\/models\/[^:]+:generateContent/.test(u)) {
      const b = JSON.parse(init.body); calls.push({ who: 'gemini', key: init.headers['x-goog-api-key'], mime: b.contents[0].parts[0].inline_data.mime_type, hasAudio: b.contents[0].parts[0].inline_data.data.length > 0 });
      return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ english: SAMPLE, original: 'மூலம்', lang: 'ta' }) }] } }] }), { status: 200 });
    }
    return realFetch(url, init);
  };
  delete env.SARVAM_API_KEY; delete env.TRANSLATOR_OPENAI_KEY;
  env.GEMINI_API_KEY = 'AIza-test-gemini';
  await J('/api/fo/v1/voice/settings', { engines: ['sarvam', 'openai', 'gemini'], monthlyCapInr: 0, dailyLimit: 60 }, { as: ADMIN });
  calls.length = 0;
  const g1 = await clip(0, { 'x-clip': 'g1' }); const gj = await g1.json();
  ok('no Sarvam / OpenAI key → Gemini answers: English, digits, ₹ tidy, audio sent as webm with the key', gj.ok && gj.engine === 'gemini' && /₹2,500/.test(gj.english) && calls.some(c => c.who === 'gemini' && c.key === 'AIza-test-gemini' && c.mime === 'audio/webm' && c.hasAudio), JSON.stringify(gj).slice(0, 200));
  const ge = env.DB._db.prepare("SELECT err FROM voice_usage WHERE clip = 'g1'").get();
  ok('...and why the engines before it failed is recorded (no key)', ge && /sarvam: no SARVAM_API_KEY/.test(ge.err) && /openai: no OpenAI key/.test(ge.err));
  const us2 = await J('/api/fo/v1/voice/usage', null, { as: ADMIN });
  ok('the Translator card shows the Gemini key and the last engine errors', us2.keys.gemini === true && us2.recentErrors.length >= 1);
  const rc = await J('/api/fo/v1/voice/recent', null, { as: ADMIN });
  const rco = await J('/api/fo/v1/voice/recent', null, { as: 'ohs@skdhealth.com' });
  ok('admin sees the last clips with engine, result, the reason and the proof key; the file type is read from its bytes', rc.ok && rc.clips.length >= 1 && rc.clips.some(c => c.audio_key && c.engine) && rco._status === 403 && sniffAudio(new Uint8Array([0,0,0,0x20,0x66,0x74,0x79,0x70]).buffer, 'audio/webm') === 'audio/mp4' && sniffAudio(new Uint8Array([0x1a,0x45,0xdf,0xa3]).buffer, 'audio/mp4') === 'audio/webm');
  const h28 = fs.readFileSync('pinaka.html', 'utf8');
  delete env.GEMINI_API_KEY;
  globalThis.fetch = realFetch;
}

console.log('\n══ 7 · OUR PORTAL ONLY: case store, FO status, our own cases, Final Report, Field Work ══');
{
  const cs = await import('./case-store-index.js');
  const run = await cs.storeTick(env, Date.now(), { force: true });
  ok('the case store keeps every case of the book on our server', run.ok && run.book === 3 && db.prepare('SELECT COUNT(*) AS n FROM case_store WHERE hash IS NOT NULL').get().n === 3, JSON.stringify(run));
  ok('...and one full copy a day in R2', [...env.PHOTOS._store.keys()].some(k => /^book\/daily\/\d{4}-\d{2}-\d{2}\.json$/.test(k)));
  const again = await cs.storeTick(env, Date.now(), { force: true });
  ok('a quiet book writes nothing the second time', again.ok && again.written === 0);
  const again2 = await cs.storeTick(env, Date.now());
  ok('...and the 10-minute guard skips an early run', again2.skipped === true);
  ok('A100 (accepted in §2) shows FO Accepted on OUR portal — nothing sent to SKD', db.prepare("SELECT app_status FROM case_store WHERE ck = 'a100'").get().app_status === 'accepted' && !ASSIGN.some(u => /accept/i.test(u)));
  ok('...and the bell rang for the accept', !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_accept'").get());
  const oc = await J('/api/open-cases', null, { as: ADMIN });
  const a = oc.cases.find(c => c.claimNo === 'A100');
  ok('the case list carries OUR status beside SKD\'s', a && a.pinaka && a.pinaka.label === 'FO Accepted' && a.status === 'FO Accepted');
  const cl = await J('/api/open-cases', null, { as: 'client@icici.com' });
  ok('...never for an insurer\'s login', !(cl.cases || []).some(c => c.pinaka));

  /* a case SKD stops sending is kept */
  const saveBook = BOOK; BOOK = BOOK.filter(c => c.claimNumber !== 'B200');
  await bookTick(env, Date.now());
  await cs.storeTick(env, Date.now(), { force: true });
  ok('a case SKD drops is kept, marked gone', !!db.prepare("SELECT gone_at FROM case_store WHERE ck = 'b200'").get().gone_at);
  const kept = await J('/api/case/B200', null, { as: ADMIN });
  ok('...and still opens on our portal from our copy', kept.ok && kept.case && kept.case.kept === true && kept.case.claimNo === 'B200', JSON.stringify(kept).slice(0, 300));
  BOOK = saveBook; await bookTick(env, Date.now());

  /* OUR OWN CASE: made on New Case, allocated here, rings his phone */
  await J('/api/newcase/list', null, { as: ADMIN });
  db.prepare("INSERT INTO new_cases (id, claim, claim_key, client, sub_product, type, insured, hospital, allocated, created, by_email, by_name, stage, state) VALUES ('nc-9','TS-9001','ts9001','Chola MS','HEALTH FULL INVESTIGATION','Health','Ravi Kumar','Apollo','2026-09-27',?,'sujith.dn@skdhealth.com','Sujit D N','approved','Tamil Nadu')").run(Date.now());
  cs.forgetOurCases();
  const our = await J('/api/app/admin/our', null, { as: ADMIN });
  ok('Pinaka App → Our cases lists the approved New Case, waiting for allocation', our.ok && our.cases.some(c => c.claim === 'TS-9001' && c.status === 'Pending Allocation' && c.parts.includes('Doctor verification')), JSON.stringify(our).slice(0, 300));
  const skdOne = await J('/api/app/admin/our/allocate', { claim: 'B200', officers: [{ name: 'Kiran Nimmala' }] }, { as: ADMIN });
  ok('an SKD case cannot be allocated here', skdOne._status === 400);
  const ohsAl = await J('/api/app/admin/our/allocate', { claim: 'TS-9001', officers: [{ name: 'MILTON VEMU' }] }, { as: 'ohs@skdhealth.com' });
  ok('OHS cannot allocate', ohsAl._status === 403);
  await J('/api/app/push', { fcmToken: 'milton-phone-token-0123456789abcdef', platform: 'android' }, { token: TOKEN });
  const inHours = new Date(Date.now() + IST).getUTCHours() >= 8 && new Date(Date.now() + IST).getUTCHours() < 20;
  const fcm0 = FCM.length, asg0 = ASSIGN.length;
  const al = await J('/api/app/admin/our/allocate', { claim: 'TS-9001', officers: [{ name: 'MILTON VEMU', parts: ['Insured verification', 'Doctor verification'] }] }, { as: ADMIN });
  ok('admin allocates OUR case to Milton — his phone rings (8 AM–8 PM), SKD is never called', al.ok && al.rang.includes('MILTON VEMU') && (!inHours || FCM.length > fcm0) && ASSIGN.length === asg0, JSON.stringify(al));
  const mine = await J('/api/app/cases', null, { token: TOKEN });
  const ts = mine.cases.find(c => c.claim === 'TS-9001');
  ok('...the case is on his phone with his two parts', ts && ts.parts.map(p => p.name).join() === 'Insured verification,Doctor verification', JSON.stringify(ts));
  env.DB._db.prepare("UPDATE app_assign SET clock_at = ?1 WHERE claim = 'TS-9001'").run(Date.now() - 1000);
  const ring = await J('/api/app/alarm', null, { token: TOKEN });
  const ra = (ring.alarms || []).find(x => x.claim === 'TS-9001');
  ok('the ringing screen gets the case details with the alarm — insured, client, hospital', ra && ra.case && ra.case.insured === 'Ravi Kumar' && ra.case.client === 'Chola MS' && ra.case.hospital === 'Apollo', JSON.stringify(ring).slice(0, 600));
  await appTick(env, Date.now());
  ok('...and the 2-minute tick does not ring it a second time', db.prepare("SELECT COUNT(*) AS n FROM app_assign WHERE claim = 'TS-9001'").get().n === 1);
  const oc2 = await J('/api/open-cases', null, { as: ADMIN });
  const t9 = oc2.cases.find(c => c.claimNo === 'TS-9001');
  ok('our case is on the portal\'s case list, marked TaaSen, Assigned to him', t9 && t9.ourCase === true && t9.status === 'Assigned' && t9.officerName === 'MILTON VEMU');
  const one = await J('/api/case/TS-9001', null, { as: ADMIN });
  ok('...and opens in the case drawer', one.ok && one.case.ourCase === true);
  const acc = await J('/api/app/accept', { claim: 'TS-9001' }, { token: TOKEN });
  ok('he accepts it → FO Accepted on our portal', acc.ok && db.prepare("SELECT app_status FROM case_store WHERE ck = 'ts9001'").get().app_status === 'accepted');

  /* FINAL REPORT — to the design: gate on touch points, Field Masters questions, then Case Complete */
  const g0 = await J('/api/app/report?claim=TS-9001', null, { token: TOKEN });
  ok('the Final Report is locked until every touch point of his part is done or rejected', g0.ok && g0.gate.ok === false && /2 touch points pending: Insured verification, Doctor verification/.test(g0.gate.text), JSON.stringify(g0.gate));
  const tpl = await J('/api/app/tp?claim=TS-9001', null, { token: TOKEN });
  ok('his touch points come with their photo checklists', tpl.ok && tpl.tps.length === 2 && tpl.tps[0].checklist.includes('Insured with ID proof') && tpl.tps[1].checklist.includes("Doctor's statement"));
  const up = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + TOKEN, 'content-type': 'image/jpeg', 'x-kind': 'tp', 'x-case': 'TS-9001', 'x-label': 'House%20front' }, body: new Uint8Array(2000) }), env, ctx);
  const uj = await up.json();
  ok('a GPS-stamped photo is stored on our server under the case', uj.ok && /^pinaka\/tp\/milton-vemu\/ts9001\//.test(uj.key), JSON.stringify(uj));
  const bad = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + TOKEN, 'content-type': 'text/html', 'x-kind': 'tp' }, body: 'x' }), env, ctx);
  ok('...html is refused', bad.status === 415);
  const photos = tpl.tps[0].checklist.map(l => ({ key: uj.key, label: l, lat: 13.06, lng: 80.15, at: Date.now() }));
  const half = await J('/api/app/tp', { claim: 'TS-9001', tp: 'Insured verification', action: 'done', photos: photos.slice(0, 1) }, { token: TOKEN });
  ok('"done" needs every photo on the checklist, and names what is missing', half._status === 400 && /House front/.test(half.error));
  const tpd = await J('/api/app/tp', { claim: 'TS-9001', tp: 'Insured verification', action: 'done', photos: photos.concat([{ key: 'pinaka/tp/someone/x.jpg', label: 'x' }]), remarks: 'Met the insured at home.' }, { token: TOKEN });
  ok('...with all of them it is done (another officer\'s photo is dropped)', tpd.ok && tpd.tp.status === 'done' && tpd.tp.photos.length === 3);
  const noWhy = await J('/api/app/tp', { claim: 'TS-9001', tp: 'Doctor verification', action: 'reject' }, { token: TOKEN });
  ok('rejecting a touch point needs a reason', noWhy._status === 400);
  await J('/api/app/tp', { claim: 'TS-9001', tp: 'Doctor verification', action: 'reject', reason: 'Doctor on leave till next week' }, { token: TOKEN });
  const g = await J('/api/app/report?claim=TS-9001', null, { token: TOKEN });
  ok('now it opens: the Health questions from Field Masters, the three conclusions, the reasons', g.ok && g.gate.ok && g.product === 'Health' && g.questions.length === 6 && g.conclusions.join() === 'Non Discrepant,Discrepant,Inconclusive' && g.reasons.Discrepant.includes('Bill Inflation'));
  const ans = g.questions.map(q => ({ heading: q, selectedOption: 'Yes', value: 'Verified on site, matches.' }));
  const draft = await J('/api/app/report', { claim: 'TS-9001', draft: true, answers: ans.slice(0, 2) }, { token: TOKEN });
  ok('a draft saves', draft.ok && draft.report.status === 'draft');
  const short = await J('/api/app/report', { claim: 'TS-9001', answers: ans.map((a, i) => i === 3 ? Object.assign({}, a, { value: 'ok' }) : a) }, { token: TOKEN });
  ok('"All fields are mandatory" — an answer under 5 characters stops the save', short._status === 400 && short.error === 'All fields are mandatory. Please fill in all text fields.');
  const vp = await J('/api/app/report', { claim: 'TS-9001', voicePending: true, answers: ans }, { token: TOKEN });
  ok('the save waits while a voice clip is still converting', vp._status === 409 && /voice/i.test(vp.error));
  const saved = await J('/api/app/report', { claim: 'TS-9001', answers: ans, timeTakenSec: 420 }, { token: TOKEN });
  ok('the Final Report is saved (time taken kept)', saved.ok && saved.report.status === 'saved' && saved.report.timeTakenSec === 420);
  const locked2 = await J('/api/app/report', { claim: 'TS-9001', answers: ans }, { token: TOKEN });
  ok('...and cannot be edited after the save', locked2._status === 409);
  const c1 = await J('/api/app/report/complete', { claim: 'TS-9001', finalConclusion: 'Discrepant' }, { token: TOKEN });
  ok('Case Complete: "Final Opinion is required."', c1._status === 400 && c1.error === 'Final Opinion is required.');
  const c2 = await J('/api/app/report/complete', { claim: 'TS-9001', finalOpinion: 'Bills inflated by ₹12,000.', finalConclusion: 'Discrepant' }, { token: TOKEN });
  ok('"Please select a Reason." for Discrepant', c2._status === 400 && c2.error === 'Please select a Reason.');
  const c3 = await J('/api/app/report/complete', { claim: 'TS-9001', finalOpinion: 'No documents', finalConclusion: 'Inconclusive', reason: 'No Documents Available' }, { token: TOKEN });
  ok('"No Documents Available" needs the reason details', c3._status === 400 && /details/.test(c3.error));
  const sub = await J('/api/app/report/complete', { claim: 'TS-9001', finalOpinion: 'Bills inflated by ₹12,000.', finalConclusion: 'Discrepant', reason: 'Bill Inflation' }, { token: TOKEN });
  ok('the case is completed → FO Completed on OUR portal, the bell rings', sub.ok && sub.report.status === 'submitted' && sub.report.conclusion === 'Discrepant' && db.prepare("SELECT app_status FROM case_store WHERE ck = 'ts9001'").get().app_status === 'completed' && !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_report'").get());
  const edit = await J('/api/app/report', { claim: 'TS-9001', answers: ans }, { token: TOKEN });
  ok('...and the report is read-only on the phone', edit._status === 409);
  const fw = await J('/api/app/admin/case?claim=TS-9001', null, { as: ADMIN });
  ok('Field Work shows the report with its conclusion, the alarm, allocation and our status', fw.ok && fw.reports.length === 1 && fw.reports[0].canDecide === true && fw.reports[0].conclusion === 'Discrepant' && fw.reports[0].answers.length === 6 && fw.alarms.length === 1 && fw.ourCase && fw.canAllocate && fw.appStatus.label === 'FO Completed' && fw.ourLog.length === 1, JSON.stringify(fw).slice(0, 400));
  ok('...and the touch points with their GPS photos and the reject reason', fw.field && fw.field.tps.length === 2 && fw.field.tps.some(t => t.status === 'rejected' && /leave/.test(t.rejectReason)) && fw.field.tps.some(t => t.photos.length === 3));
  const pic = await call('/api/app/admin/attendance/photo?key=' + encodeURIComponent(uj.key), null, { as: ADMIN });
  ok('...its photo opens on the portal', pic.status === 200);
  const fwOhs = await J('/api/app/admin/case?claim=TS-9001', null, { as: 'ohs@skdhealth.com' });
  ok('OHS sees it (his team) but may not decide', fwOhs.ok && fwOhs.reports.length === 1 && fwOhs.reports[0].canDecide === false && !fwOhs.canAllocate);
  const ohsDec = await J('/api/app/admin/report', { id: fw.reports[0].id, action: 'accept' }, { as: 'ohs@skdhealth.com' });
  ok('...and is refused if he tries', ohsDec._status === 403);
  const back0 = await J('/api/app/admin/report', { id: fw.reports[0].id, action: 'return' }, { as: ADMIN });
  ok('sending back needs a note', back0._status === 400);
  const fcm1 = FCM.length;
  const back = await J('/api/app/admin/report', { id: fw.reports[0].id, action: 'return', note: 'Add the discharge summary.' }, { as: ADMIN });
  ok('admin sends it back → his phone is told, our status "Report sent back"', back.ok && (!inHours || FCM.length > fcm1) && db.prepare("SELECT app_status FROM case_store WHERE ck = 'ts9001'").get().app_status === 'returned');
  const re1 = await J('/api/app/report', { claim: 'TS-9001', answers: ans }, { token: TOKEN });
  ok('...the report opens again on his phone', re1.ok && re1.report.status === 'saved');
  const noReply = await J('/api/app/report/complete', { claim: 'TS-9001', finalOpinion: 'x', finalConclusion: 'Non Discrepant' }, { token: TOKEN });
  ok('completing again needs his answer to the note', noReply._status === 400 && /note/.test(noReply.error));
  const re2 = await J('/api/app/report/complete', { claim: 'TS-9001', finalOpinion: 'Discharge summary added.', finalConclusion: 'Non Discrepant', reply: 'Added.' }, { token: TOKEN });
  const lst = await J('/api/app/admin/reports', null, { as: ADMIN });
  ok('...he answers and completes again; it is back in Final reports, round 2', re2.ok && lst.reports.some(r => r.claim === 'TS-9001' && r.rounds === 2 && r.reply === 'Added.'));
  const accR = await J('/api/app/admin/report', { id: fw.reports[0].id, action: 'accept' }, { as: ADMIN });
  ok('admin accepts the report', accR.ok && db.prepare("SELECT status FROM app_reports WHERE ck = 'ts9001'").get().status === 'accepted');

  /* courier check + officer totals */
  const ex = db.prepare("SELECT id FROM app_expenses WHERE claim = 'A100' LIMIT 1").get();
  const rc = await J('/api/app/admin/expense/received', { id: ex.id, received: false }, { as: ADMIN });
  ok('the courier check marks a bill "not received"', rc.ok && rc.received === false && db.prepare('SELECT bill_received FROM app_expenses WHERE id = ?').get(ex.id).bill_received === 0);
  const tot = await J('/api/app/admin/expenses/officers?month=' + new Date(Date.now() + 330 * 60000).toISOString().slice(0, 7), null, { as: ADMIN });
  ok('officer totals for the month: claimed / approved / paid / pending', tot.ok && tot.officers.length >= 1 && 'pending' in tot.officers[0]);
  const st = await J('/api/app/admin/store', null, { as: ADMIN });
  ok('the case store reports what it holds', st.ok && st.cases >= 3 && st.gone >= 0);

  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app has the Final Report with the Translator on every box', /function vReport\(/.test(html) && /boxWithMic\('q' \+ i/.test(html) && /boxWithMic\('cOp'/.test(html) && /boxWithMic\('cReply'/.test(html));
  const ad = fs.readFileSync('pinaka-admin.html', 'utf8');
  ok('the Pinaka page has Final reports, Our cases and the one-case Field Work view', /data-tab="rep"/.test(ad) && /data-tab="our"/.test(ad) && /function loadCase\(/.test(ad) && /data-a="rcv"/.test(ad));
  const appjs = fs.readFileSync('app.js', 'utf8');
  ok('the case drawer has the Field Work tab', /'Field Work'\)/.test(appjs) && /\/pinaka\/admin\?claim=/.test(appjs));
}

console.log('\n══ 8 · THE OFFICER\'S DAY (design): Employee ID, punch, plan, case clocks, fines, appeal, masters ══');
{
  const IST8 = 330 * 60000, istNow = new Date(Date.now() + IST8), hmNow = istNow.getUTCHours() * 60 + istNow.getUTCMinutes();
  const dayStr = istNow.toISOString().slice(0, 10), yStr = new Date(Date.now() + IST8 - 86400000).toISOString().slice(0, 10);
  const fmt = t => { const d = new Date(t + IST8); const p = n => String(n).padStart(2, '0'); return p(d.getUTCDate()) + '/' + p(d.getUTCMonth() + 1) + '/' + d.getUTCFullYear() + ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()); };
  /* Employee ID */
  const e1 = await J('/api/app/admin/empid', { name: 'MILTON VEMU', empId: 'tsn-fo-0412' }, { as: ADMIN });
  ok('Pinaka App → Employee ID for an officer (stored upper-case)', e1.ok && e1.done[0].empId === 'TSN-FO-0412');
  const e2 = await J('/api/app/admin/empid/bulk', { rows: [{ name: 'Kiran Nimmala', empId: 'TSN-FO-0413' }, { name: 'Somebody New', empId: 'TSN-FO-0412' }, { name: 'Kiran', empId: 'bad id!' }] }, { as: ADMIN });
  ok('...all at once from the Excel rows; a clash and an odd ID are reported, not saved', e2.ok && e2.saved === 1 && e2.problems.length === 2 && /already MILTON VEMU/.test(e2.problems[0].why));
  const e3 = await J('/api/app/admin/empid', { name: 'MILTON VEMU', empId: 'X1' }, { as: 'ohs@skdhealth.com' });
  ok('OHS cannot set Employee IDs', e3._status === 403);
  const xl = await call('/api/app/admin/empid.xlsx', null, { as: ADMIN });
  ok('the Employee-ID Excel lists every officer to fill in', xl.status === 200 && /spreadsheet/.test(xl.headers.get('content-type')));
  const pw = await J('/api/app/admin/password', { name: 'MILTON VEMU', password: 'Milton2026x' }, { as: ADMIN });
  ok('the password message now says the Employee ID to type', pw.ok && pw.loginId === 'TSN-FO-0412');
  const li = await J('/api/app/login', { id: 'tsn-fo-0412', password: 'Milton2026x', platform: 'web' });
  ok('he signs in with his Employee ID + password (no OTP)', li.ok && /^pk_/.test(li.token));
  const T2 = li.token;
  /* the day */
  const day0 = await J('/api/app/day', null, { token: T2 });
  ok('the phone asks where the day stands: punch, plan, updates, fines', day0.ok && day0.officer.empId === 'TSN-FO-0412' && day0.punched === false && 'updatesDue' in day0 && typeof day0.finesMonth === 'number');
  /* yesterday unfinished blocks today's punch */
  db.prepare("INSERT INTO app_punch (ukey, day, officer, at, lat, lng, selfie_key, late) VALUES ('milton vemu', ?, 'MILTON VEMU', ?, 13, 80, 'x', 0)").run(yStr, Date.now() - 86400000);
  db.prepare("INSERT INTO app_commit (day, ukey, ck, claim, plan, at) VALUES (?, 'milton vemu', 'a100', 'A100', 'Visit', ?)").run(yStr, Date.now() - 86400000);
  const sel = await (await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T2, 'content-type': 'image/jpeg', 'x-kind': 'selfie' }, body: new Uint8Array(3000) }), env, ctx)).json();
  ok('the selfie is stored on our server', sel.ok && /^pinaka\/selfie\/milton-vemu\//.test(sel.key));
  const opensAt = 7 * 60;
  if (hmNow >= opensAt) {
    const blocked = await J('/api/app/punch', { selfieKey: sel.key, lat: 12.9, lng: 80.1 }, { token: T2 });
    ok("yesterday's missing update blocks today's punch", blocked._status === 409 && blocked.missed.includes('A100'));
    const noNight = await J('/api/app/today', { claim: 'A100', text: 'hi', day: yStr }, { token: T2 });
    ok('an update needs 5 characters or more', noNight._status === 400);
    const upY = await J('/api/app/today', { claim: 'A100', text: 'Visited the insured; RC pending.', day: yStr }, { token: T2 });
    ok('...he finishes yesterday\'s update', upY.ok);
    const noGps = await J('/api/app/punch', { selfieKey: sel.key }, { token: T2 });
    ok('the punch needs GPS', noGps._status === 400 && /GPS/.test(noGps.error));
    const late = hmNow > 8 * 60 + 30;
    if (late) {
      const noWhy = await J('/api/app/punch', { selfieKey: sel.key, lat: 12.92, lng: 80.12 }, { token: T2 });
      ok('after 8:30 the punch asks why late', noWhy._status === 400 && noWhy.late === true);
    }
    const pu = await J('/api/app/punch', { selfieKey: sel.key, lat: 12.92, lng: 80.12, acc: 8, place: 'Tambaram', reason: 'Bike puncture' }, { token: T2 });
    ok('punched in' + (late ? ' — marked Late, the bell told' : ''), pu.ok && pu.late === late && (!late || !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_late'").get()));
    const att = await J('/api/app/admin/attendance?day=' + dayStr, null, { as: ADMIN });
    ok('the portal sees the punch with the selfie, place and reason', att.ok && att.punches.some(x => x.officer === 'MILTON VEMU' && x.selfie === sel.key && x.place === 'Tambaram'));
    const sp = await call('/api/app/admin/attendance/photo?key=' + encodeURIComponent(sel.key), null, { as: ADMIN });
    ok('...and the selfie opens', sp.status === 200);
    const cm0 = await J('/api/app/commit', null, { token: T2 });
    ok('the morning plan lists every case he holds', cm0.ok && cm0.cases.length >= 1 && cm0.plans.join() === 'Visit,Call,Documents,Report');
    const cm1 = await J('/api/app/commit', { items: [] }, { token: T2 });
    ok('...every case needs a plan', cm1._status === 400 && cm1.missing.length === cm0.cases.length);
    const cm2 = await J('/api/app/commit', { items: cm0.cases.map(c => ({ claim: c.claim, plan: 'Visit', time: '11:00', note: 'insured' })) }, { token: T2 });
    ok('...saved', cm2.ok && cm2.saved === cm0.cases.length);
    const day1 = await J('/api/app/day', null, { token: T2 });
    ok('the day now reads punched + committed', day1.punched && day1.committed);
    const upd = await J('/api/app/today', { claim: 'A100', text: 'Visited the insured again today.' }, { token: T2 });
    ok(hmNow >= 18 * 60 ? "Today's work saves an update after 6 PM" : "Today's work stays closed before 6 PM", hmNow >= 18 * 60 ? upd.ok : upd._status === 409);
  }
  /* case events */
  const st = await J('/api/app/case/event', { claim: 'A100', kind: 'started', lat: 12.9, lng: 80.1 }, { token: T2 });
  ok('Start case is recorded on our server', st.ok && !!db.prepare("SELECT id FROM app_caseev WHERE ck = 'a100' AND kind = 'started'").get());
  const rn = await J('/api/app/case/event', { claim: 'A100', kind: 'reached' }, { token: T2 });
  ok('"I have reached" needs the GPS photo', rn._status === 400);
  const nh = await J('/api/app/case/event', { claim: 'B200', kind: 'started' }, { token: T2 });
  ok('...and only on his own case', nh._status === 404);
  const cs1 = await J('/api/app/cases', null, { token: T2 });
  const a1 = cs1.cases.find(c => c.claim === 'A100');
  ok('his cases carry the product, TAT left, events and touch-point progress', a1 && a1.product === 'TP' && typeof a1.tatLeftH === 'number' && a1.events.started && a1.tp && a1.tp.total >= 1);
  /* fines: not accepted in 20 minutes */
  db.prepare("UPDATE app_assign SET accept_by = ?, accepted_at = NULL, rejected_at = NULL, closed_at = NULL WHERE id = (SELECT id FROM app_assign WHERE claim = 'S300' OR claim = 'A100' ORDER BY id LIMIT 1)").run(Date.now() - 60000);
  const tk = await appTick(env, Date.now());
  ok('not accepted in 20 minutes → ₹50 on his Fine Amount (once)', tk.day && tk.day.acceptFines >= 1 && !!db.prepare("SELECT id FROM app_fines WHERE rule = 'accept_20' AND amount = 50").get());
  const tk2 = await appTick(env, Date.now());
  ok('...a second tick does not fine again', tk2.day.acceptFines === 0);
  /* GPS off on duty */
  await J('/api/app/duty', { on: true }, { token: T2 });
  await J('/api/app/location', { points: [{ lat: 12.9, lng: 80.1, acc: 10, at: Date.now() }], gps: 'on' }, { token: T2 });
  const gps0 = db.prepare("SELECT COUNT(*) AS n FROM app_fines WHERE rule = 'gps_off'").get().n;
  const g1 = await J('/api/app/location', { points: [], gps: 'off' }, { token: T2 });
  const g2 = await J('/api/app/location', { points: [], gps: 'off' }, { token: T2 });
  ok('GPS off on duty → ₹50 and the manager told — once per switch-off', g1.ok && g2.ok && db.prepare("SELECT COUNT(*) AS n FROM app_fines WHERE rule = 'gps_off'").get().n === gps0 + 1 && !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_gps'").get());
  /* Motor TP not started in 3 days */
  db.prepare("DELETE FROM app_caseev WHERE ck = 'a100' AND kind = 'started'").run();
  db.prepare("UPDATE app_assign SET accepted_at = ? WHERE claim = 'A100'").run(Date.now() - 3.2 * 86400000);
  await appTick(env, Date.now());
  ok('Motor TP not started in 3 days → ₹50', !!db.prepare("SELECT id FROM app_fines WHERE rule = 'motor_start' AND claim = 'A100'").get());
  /* Cashless: 20 hours from creation, alerts at 2 h and 1 h */
  BOOK.push({ claimNumber: 'C400', client: 'Star Health', subProduct: 'HEALTH CASHLESS INVESTIGATION', patientName: 'Revanth', status: 'FO Accepted', fieldOfficers: ['MILTON VEMU'], manager: 'hemalatha a', createdOn: fmt(Date.now() - 19.5 * 3600000), allotmentDate: fmt(Date.now() - 19.5 * 3600000) });
  await bookTick(env, Date.now());
  await J('/api/app/accept', { claim: 'C400' }, { token: T2 });
  const fc0 = FCM.length;
  const tc = await appTick(env, Date.now());
  ok('cashless: 30 minutes left → the 2 h and 1 h alerts go to his phone', tc.day.cashless >= 2 && !!db.prepare("SELECT 1 FROM app_timers WHERE ck = 'c400' AND kind = 'cashless_1h'").get());
  BOOK[BOOK.length - 1].createdOn = fmt(Date.now() - 21 * 3600000); BOOK[BOOK.length - 1].allotmentDate = BOOK[BOOK.length - 1].createdOn;
  await bookTick(env, Date.now(), { force: true });
  const { forgetOurCases } = await import('./case-store-index.js'); forgetOurCases();
  await appTick(env, Date.now() + 1000);
  ok('...past 20 hours: "Cashless late" to the manager/admin bell — no fine, no move', !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_cashless'").get() && !db.prepare("SELECT id FROM app_fines WHERE claim = 'C400'").get());
  const cs2 = await J('/api/app/cases', null, { token: T2 });
  const c4 = cs2.cases.find(c => c.claim === 'C400');
  ok('the phone gets the cashless due time for the countdown', c4 && c4.cashless === true && c4.cashlessDue > 0);
  /* the fine page, appeal, decision */
  const fm = await J('/api/app/fines', null, { token: T2 });
  ok('Fine Amount: the month total and the breakup', fm.ok && fm.total >= 150 && fm.breakup.some(b => b.rule === 'accept_20') && fm.breakup.some(b => b.rule === 'gps_off'));
  const fid = fm.fines.find(f => f.rule === 'gps_off').id;
  const ap0 = await J('/api/app/fines/appeal', { id: fid }, { token: T2 });
  ok('an appeal needs a why', ap0._status === 400);
  const ap = await J('/api/app/fines/appeal', { id: fid, why: 'Network or GPS signal lost', text: 'Phone restarted after the update.' }, { token: T2 });
  ok('...appealed; the bell tells admin', ap.ok && !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_appeal'").get());
  const ap2 = await J('/api/app/fines/appeal', { id: fid, why: 'x' }, { token: T2 });
  ok('...not twice', ap2._status === 409);
  const af = await J('/api/app/admin/fines', null, { as: ADMIN });
  ok('the portal Fines list: per officer, with the appeal', af.ok && af.officers.some(o => o.officer === 'MILTON VEMU' && o.appeal === 1) && af.canExcel);
  const ohsF = await J('/api/app/admin/fine', { id: fid, action: 'waive' }, { as: 'ohs@skdhealth.com' });
  ok('OHS cannot decide a fine', ohsF._status === 403);
  const wv = await J('/api/app/admin/fine', { id: fid, action: 'waive', note: 'Genuine network issue' }, { as: ADMIN });
  const fm2 = await J('/api/app/fines', null, { token: T2 });
  ok('admin waives it — it drops out of his total', wv.ok && fm2.total === fm.total - 50 && fm2.fines.find(f => f.id === fid).status === 'waived');
  const fx = await call('/api/app/admin/fines.xlsx', null, { as: ADMIN });
  const fxN = await call('/api/app/admin/fines.xlsx', null, { as: COORD });
  ok('the monthly fine Excel is admin only', fx.status === 200 && fxN.status !== 200);
  /* rules + Field Masters */
  const r1 = await J('/api/app/admin/rules', { fines: { day_update: 300 }, lateAfter: '08:45' }, { as: ADMIN });
  const r2 = await J('/api/app/admin/rules', { fines: { day_update: 1 } }, { as: 'ohs@skdhealth.com' });
  ok('admin changes a fine amount and the late time; others cannot', r1.ok && r1.rules.fines.day_update === 300 && r1.rules.lateAfter === '08:45' && r2._status === 403);
  const m1 = await J('/api/app/admin/masters', { master: { TP: { heading: 'Corporate Visit', questions: ['FIR matches the petition', 'Spot verified'] } }, reasons: { TP: { Discrepant: ['Driver not licensed'], Inconclusive: ['Witness not traceable'], needsDetails: [] } } }, { as: ADMIN });
  const gm = await J('/api/app/master?claim=A100', null, { token: T2 });
  ok('Field Masters: the Motor-TP questions and reason lists are set on the portal and reach the phone', m1.ok && gm.product === 'TP' && gm.master.questions.length === 2 && gm.reasons.Discrepant[0] === 'Driver not licensed');
  /* the app */
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app is the design: sign-in with Employee ID, punch, plan, Home A, cases, workspace, camera B, Today, Profile, Fines, Appeal', ['function vLogin', 'function vPunch', 'function vCommit', 'function vHome', 'function vCases', 'function vCase', 'function camOpen', 'function vToday', 'function vProfile', 'function vFines', 'function vAppeal', 'function vTrip', 'function vComplete'].every(x => html.includes(x)) && html.includes("S('empid')"));
  ok('the photo stamp is burned into the picture (lat/long, time, claim, officer)', /function camBurn/.test(html) && /GMT \+05:30/.test(html));
  const ad = fs.readFileSync('pinaka-admin.html', 'utf8');
  ok('the portal page has Attendance, Fines, Field Masters and Employee IDs', /data-tab="att"/.test(ad) && /data-tab="fines"/.test(ad) && /data-tab="masters"/.test(ad) && /empid/.test(ad));
}

console.log('\n══ 9 · "I will do it on Tuesday" — the promised day, reminded, and said back at the update ══');
{
  const li = await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' });
  const T3 = li.token;
  const IST9 = 330 * 60000, today = new Date(Date.now() + IST9).toISOString().slice(0, 10), plus = n => new Date(Date.now() + IST9 + n * 86400000).toISOString().slice(0, 10);
  const cm = await J('/api/app/commit', null, { token: T3 });
  ok('the plan offers "Another day" beside Visit / Call / Documents / Report', cm.ok && cm.laterPlan === 'Another day' && cm.maxDays === 14);
  const items = cm.cases.map(c => ({ claim: c.claim, plan: 'Visit', time: '11:00', note: 'visit' }));
  const a100 = items.find(x => x.claim === 'A100') || items[0];
  Object.assign(a100, { plan: 'Another day', laterDay: today, time: '11:00', note: 'Police station visit' });
  const b1 = await J('/api/app/commit', { items }, { token: T3 });
  ok('"Another day" must be a day after today', b1._status === 400 && /pick the day/.test(b1.error));
  Object.assign(a100, { laterDay: plus(2), time: '' });
  const b2 = await J('/api/app/commit', { items }, { token: T3 });
  ok('...with a time', b2._status === 400 && /time/.test(b2.error));
  Object.assign(a100, { time: '11:30', note: '' });
  const b3 = await J('/api/app/commit', { items }, { token: T3 });
  ok('...and what he will do', b3._status === 400 && /what you will do/.test(b3.error));
  Object.assign(a100, { note: 'Police station visit for the FIR copy' });
  const b4 = await J('/api/app/commit', { items }, { token: T3 });
  ok('the promise is saved', b4.ok && !!db.prepare("SELECT id FROM app_promise WHERE ck = ? AND status = 'open' AND due_day = ?").get(claimKey(a100.claim), plus(2)));
  const cs = await J('/api/app/cases', null, { token: T3 });
  const c1 = cs.cases.find(c => c.claim === a100.claim);
  ok('before the day, his case says "You promised this for <day>"', c1 && c1.promise && c1.promise.state === 'later' && /^You promised this for (Sun|Mon|Tue|Wed|Thu|Fri|Sat) /.test(c1.promise.words));
  /* the promised day arrives */
  db.prepare("UPDATE app_promise SET due_day = ?, due_time = '00:01' WHERE ck = ?").run(today, claimKey(a100.claim));
  const fc = FCM.length;
  const tk = await appTick(env, Date.now());
  const hmN = new Date(Date.now() + IST9).getUTCHours() * 60 + new Date(Date.now() + IST9).getUTCMinutes();
  ok('on the day: reminded in the morning and at the promised time', hmN < 8 * 60 || (!!db.prepare("SELECT 1 FROM app_timers WHERE kind LIKE 'promise_am_%'").get() && !!db.prepare("SELECT 1 FROM app_timers WHERE kind LIKE 'promise_at_%'").get()));
  const cs2 = await J('/api/app/cases', null, { token: T3 });
  const c2 = cs2.cases.find(c => c.claim === a100.claim);
  ok('...and the case says "You promised this for today … You have to complete this today."', c2 && c2.promise.state === 'today' && /You promised this for today .*You have to complete this today\./.test(c2.promise.words));
  const td = await J('/api/app/today', null, { token: T3 });
  ok("Today's work shows the promise on that case", td.ok && td.cases.some(x => x.claim === a100.claim && x.promise && x.promise.state === 'today'));
  if (hmN >= 18 * 60) {
    const up = await J('/api/app/today', { claim: a100.claim, text: 'FIR copy collected at the police station.' }, { token: T3 });
    ok('the update on the promised day keeps the promise', up.ok && up.promise && up.promise.status === 'kept');
  } else {
    db.prepare("UPDATE app_promise SET due_day = ? WHERE ck = ? AND status = 'open'").run(plus(-1), claimKey(a100.claim));
    await appTick(env, Date.now());
    ok('a promised day that passes with no update → "missed", the manager told', !!db.prepare("SELECT id FROM app_promise WHERE ck = ? AND status = 'missed'").get(claimKey(a100.claim)) && !!db.prepare("SELECT id FROM alerts WHERE kind = 'pinaka_promise'").get());
  }
  const fw = await J('/api/app/admin/case?claim=' + encodeURIComponent(a100.claim), null, { as: ADMIN });
  ok('Field Work lists the promised days', fw.ok && fw.field.promises.length >= 1 && /Police station/.test(fw.field.promises[0].note));
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app: "Another day" with the date + time, and the promise banner', /Which day and time will you do it\?/.test(html) && /function promiseBanner/.test(html));
}

console.log('\n══ 10 · TEAM CHAT with @mentions — the case chat box (phone + portal) ══');
{
  const MGR = 'hema@skdhealth.com';
  KV.set('u:' + MGR, JSON.stringify({ email: MGR, name: 'Hemalatha A', role: 'manager', status: 'approved' }));
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const g0 = await J('/api/app/chat?claim=A100', null, { token: T });
  ok('the case chat opens on his case: members = him + the case manager (matched by name)', g0.ok && g0.me === 'fo:milton vemu' && g0.members.some(m => m.id === 'st:' + MGR && m.role === 'Case Manager') && g0.members.some(m => m.id === g0.me) && g0.messages.length === 0, JSON.stringify(g0).slice(0, 400));
  const no = await J('/api/app/chat?claim=B200', null, { token: T });
  ok("another officer's case: refused", no._status === 404);
  const al0 = db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'pinaka_chat'").get().n;
  const p1 = await J('/api/app/chat', { claim: 'A100', text: 'Reached the police station. @Hemalatha A FIR copy needs a fee.', mentions: [{ id: 'st:' + MGR }, { id: 'st:nobody@x.com' }, { id: g0.me }], cid: 'c1' }, { token: T });
  ok('he writes and tags the manager: only a member is tagged (not a stranger, not himself)', p1.ok && p1.mentions.length === 1 && p1.mentions[0].id === 'st:' + MGR);
  const p1b = await J('/api/app/chat', { claim: 'A100', text: 'Reached the police station. @Hemalatha A FIR copy needs a fee.', mentions: [{ id: 'st:' + MGR }], cid: 'c1' }, { token: T });
  ok('the offline retry with the same cid is not doubled', p1b.ok && p1b.again && p1b.id === p1.id && db.prepare("SELECT COUNT(*) AS n FROM app_chat").get().n === 1);
  const al = db.prepare("SELECT * FROM alerts WHERE kind = 'pinaka_chat' ORDER BY created DESC").get();
  ok('the tagged manager gets the portal bell: "{name} mentioned you · {claim}"', db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'pinaka_chat'").get().n === al0 + 1 && al.to_mail === MGR && /mentioned you · A100/.test(al.title));
  const mm = await J('/api/app/admin/chat/mentions', null, { as: MGR });
  ok('...and it is in his Mentions (unread 1)', mm.ok && mm.unread === 1 && mm.mentions[0].claim === 'A100');
  const pg = await J('/api/app/admin/chat?claim=A100', null, { as: MGR });
  ok('the case manager reads the thread on the portal; his tag is marked "you"', pg.ok && pg.messages.length === 1 && pg.messages[0].you && !pg.messages[0].mine);
  ok('opening the chat marks his mention read', (await J('/api/app/admin/chat/mentions', null, { as: MGR })).unread === 0);
  const fc = FCM.length;
  const r1 = await J('/api/app/admin/chat', { claim: 'A100', text: '@MILTON VEMU pay the fee, I approve.', mentions: [{ id: 'fo:milton vemu' }], replyTo: p1.id, cid: 'x1' }, { as: MGR });
  ok('the manager replies and tags him: the reply keeps the quote', r1.ok && r1.mentions.length === 1);
  ok("...his phone is pushed (\"Hemalatha A mentioned you · A100\")", FCM.slice(fc).some(f => /mentioned you · A100/.test(JSON.stringify(f))), JSON.stringify(FCM.slice(fc)).slice(0, 300));
  const th = await J('/api/app/chat/threads', null, { token: T });
  const a = th.threads.find(x => x.claim === 'A100');
  ok('Chat tab: A100 shows 1 unread and 1 @mention; other cases listed too', th.ok && a && a.unread === 1 && a.mentions === 1 && th.mentions === 1 && th.threads.length >= 2 && a.last && /pay the fee/.test(a.last.text));
  const fr = await J('/api/app/chat/mentions?fresh=1', null, { token: T });
  const fr2 = await J('/api/app/chat/mentions?fresh=1', null, { token: T });
  ok('the phone\'s service worker learns the mention once ("fresh")', fr.mentions.length === 1 && fr2.mentions.length === 0);
  const g1 = await J('/api/app/chat?claim=A100', null, { token: T });
  const last = g1.messages[g1.messages.length - 1];
  ok('the thread on the phone: his own message is "mine", the reply quotes it, "@ you" on the tag', g1.messages[0].mine && last.replyTo && last.replyTo.id === p1.id && last.you);
  const th2 = await J('/api/app/chat/threads', null, { token: T });
  ok('...and reading it clears the unread and the @', th2.threads.find(x => x.claim === 'A100').unread === 0 && th2.mentions === 0);
  const inc = await J('/api/app/chat?claim=A100&after=' + last.id, null, { token: T });
  ok('the 6-second refresh asks only for newer messages', inc.ok && inc.messages.length === 0);
  const cd = await J('/api/app/admin/chat?claim=A100', null, { as: COORD });
  ok('a coordinator who does not see this officer cannot read the chat', cd._status === 403);
  const pp = await J('/api/app/admin/chat/people', null, { as: ADMIN });
  const ad = await J('/api/app/admin/chat/members', { claim: 'A100', id: 'st:' + COORD }, { as: ADMIN });
  const cd2 = await J('/api/app/admin/chat?claim=A100', null, { as: COORD });
  ok('admin adds a portal member to the case chat; then he can read it and be tagged', pp.ok && ad.ok && cd2.ok && (await J('/api/app/chat?claim=A100', null, { token: T })).members.some(m => m.id === 'st:' + COORD));
  const em = await J('/api/app/chat', { claim: 'A100', text: '   ' }, { token: T });
  ok('an empty message is refused', em._status === 400);
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app: chat icon in the Case Workspace header, Team Chat tile, Chat tab with Chats/Mentions, @ list, Voice on the box', /right: chIcon\(c\.claim\)/.test(html) && /'Team Chat', 'Your manager and team/.test(html) && /function vChatTab/.test(html) && /Tag a member of this case/.test(html) && /data-f="chatIn"/.test(html));
  ok('the portal: Team Chat on the case page', /id="chatSec"/.test(fs.readFileSync('pinaka-admin.html', 'utf8')));
}

console.log('\n══ 11 · THE DOCUMENT SCANNER — scan pages → one PDF → "What is this document?" ══');
{
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const g = await J('/api/app/tp?claim=A100', null, { token: T });
  const tp = g.tps && g.tps[0];
  ok('each touch point carries its document list', g.ok && tp && Array.isArray(tp.docNames) && tp.docNames.length > 0, JSON.stringify(g).slice(0, 300));
  const { docsFor, DEFAULT_DOCS, checklistFor, DEFAULT_CHECKLISTS } = await import('./fo-app-index.js');
  ok('insured (Motor TP): statement, Aadhaar, DL, policy, RC, permit', ['Insured statement', 'Insured Aadhaar', 'Insured driving licence', 'Policy copy', 'RC card', 'Permit'].every(d => docsFor(DEFAULT_DOCS, 'Insured / owner verification', 'TP').includes(d)));
  ok('driver: statement, Aadhaar, DL — and no RC / permit there', docsFor(DEFAULT_DOCS, 'Driver verification', 'TP').join('|') === 'Driver statement|Driver Aadhaar|Driver driving licence');
  ok('petitioner: statement, ID, vehicle details, hospital, post-mortem, death records', ['Petitioner statement', 'Petitioner ID proof', 'Petitioner vehicle details', 'Postmortem report'].every(d => docsFor(DEFAULT_DOCS, 'Pettetioner Verification', 'TP').includes(d)));
  ok('161 witness: statement and ID proof', docsFor(DEFAULT_DOCS, '161 Witness', 'TP')[0] === '161 Witness statement');
  ok("police: the RTI letter's papers, one each (FIR, charge sheet … MVI, inquest)", ['FIR', 'Charge sheet', 'Case diary', 'Rough sketch', 'Observation mahazar', 'MVI report', 'Accident register (AR)', 'Inquest panchanama'].every(d => docsFor(DEFAULT_DOCS, 'Police Documents - Charge sheet - closure report', 'TP').includes(d)));
  ok('hospital: MLC, ICP, verified bill copies', ['MLC', 'ICP (indoor case papers)', 'Verified bill copies'].every(d => docsFor(DEFAULT_DOCS, 'Hospital verification', 'TP').includes(d)));
  ok('spot visit: 8 spot photos and the 360° video', checklistFor(DEFAULT_CHECKLISTS, 'Accident Spot verification').length === 9 && /360/.test(checklistFor(DEFAULT_CHECKLISTS, 'Accident Spot verification')[8]));
  const up = await call('/api/app/upload', null, { token: T });
  /* SKD's real part names (All cases TP/Health → StackHolders) */
  ok("SKD's names: 'Pettetioner Verification' gets the petitioner lists; a '… Visit Proof' part asks for ONE visit photo", checklistFor(DEFAULT_CHECKLISTS, 'Pettetioner Verification')[0] === 'Petitioner with ID proof' && checklistFor(DEFAULT_CHECKLISTS, 'Hospital visit proof photo').join() === 'Visit proof photo' && checklistFor(DEFAULT_CHECKLISTS, 'Insured Verification Visit Proof').join() === 'Visit proof photo');
  ok("...'Past Documents from Insured - Claimant' gets the past records list, not the insured one", docsFor(DEFAULT_DOCS, 'Past Documents from Insured - Claimant', 'Health')[0] === 'Past treatment records');
  ok("...MBV, AR - MLC, Police FIR / Panchanama, Garage, Vicinity each get their own list", docsFor(DEFAULT_DOCS, 'MBV - certified & Verified Bills', 'TP')[0] === 'Verified bill copies' && docsFor(DEFAULT_DOCS, 'AR - MLC DETAILS', 'TP')[0] === 'MLC' && docsFor(DEFAULT_DOCS, 'Police Station - Panchanama and other documents', 'TP')[0] === 'FIR' && docsFor(DEFAULT_DOCS, 'Garage Verification', 'TP')[0] === 'Job card' && docsFor(DEFAULT_DOCS, 'Vicinity Verification', 'Health')[0] === 'Vicinity statement');
  const upr = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T, 'content-type': 'application/pdf', 'x-kind': 'file', 'x-case': 'A100', 'x-label': 'Insured%20statement' }, body: '%PDF-1.4 test' }), env, ctx);
  const u = await upr.json();
  ok('the scanned PDF uploads to our server', u.ok && /^pinaka\/file\//.test(u.key));
  const s1 = await J('/api/app/tp', { claim: 'A100', tp: tp.tp, action: 'docs', files: [{ key: u.key, name: 'Insured statement', type: 'application/pdf', pages: 3 }, { key: 'pinaka/file/someone-else/x.pdf', name: 'x' }] }, { token: T });
  ok('it is saved on the touch point with its name and pages (another officer\'s file refused)', s1.ok && s1.files.length === 1 && s1.files[0].pages === 3 && s1.files[0].name === 'Insured statement');
  db.prepare("UPDATE app_tp SET status = 'done' WHERE ck = ? AND tp = ?").run(claimKey('A100'), tp.tp);
  const s2 = await J('/api/app/tp', { claim: 'A100', tp: tp.tp, action: 'docs', files: [{ key: u.key, name: 'Insured Aadhaar', type: 'application/pdf', pages: 3 }] }, { token: T });
  const row = db.prepare('SELECT status, files FROM app_tp WHERE ck = ? AND tp = ?').get(claimKey('A100'), tp.tp);
  ok('renamed after the touch point is done — the name changes, the status stays done', s2.ok && row.status === 'done' && JSON.parse(row.files)[0].name === 'Insured Aadhaar');
  const fw = await J('/api/app/admin/case?claim=A100', null, { as: ADMIN });
  ok('Field Work on the portal lists the document with its name and pages', fw.ok && fw.field.tps.some(t => (t.files || []).some(f => f.name === 'Insured Aadhaar' && f.pages === 3)));
  const vid = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T, 'content-type': 'video/mp4', 'x-kind': 'tp', 'x-case': 'A100', 'x-label': '360%C2%B0%20spot%20video' }, body: 'mp4data' }), env, ctx);
  const vj = await vid.json();
  const vbad = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T, 'content-type': 'video/mp4', 'x-kind': 'selfie' }, body: 'x' }), env, ctx);
  ok('the 360° video uploads on a touch point (and only there)', vj.ok && /\.mp4$/.test(vj.key) && vbad.status === 415);
  const mine = await entry.fetch(new Request('https://taasenclaims.com/api/app/myfile?key=' + encodeURIComponent(u.key), { headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T } }), env, ctx);
  const theirs = await entry.fetch(new Request('https://taasenclaims.com/api/app/myfile?key=' + encodeURIComponent('pinaka/file/someone/x.pdf'), { headers: { 'x-app-version': '2.1.1', 'x-app-platform': 'web', authorization: 'Bearer ' + T } }), env, ctx);
  ok('he opens his own document again; not anybody else\'s', mine.status === 200 && theirs.status === 404);
  const ms = await J('/api/app/admin/masters', null, { as: ADMIN });
  const sv = await J('/api/app/admin/masters', { docs: [{ match: 'driver', product: '', docs: ['Driver statement', 'Driver badge'] }, { match: '', docs: ['Other document'] }] }, { as: ADMIN });
  const g2 = await J('/api/app/tp?claim=A100', null, { token: T });
  ok('Field Masters: the document lists are on the portal and editable', ms.ok && ms.docs.length > 5 && sv.ok && sv.docs[0].docs[1] === 'Driver badge' && g2.ok);
  await J('/api/app/admin/masters', { docs: DEFAULT_DOCS }, { as: ADMIN });
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app: the scanner with the box that turns green, Auto, crop corners, Clean / B&W, pages → PDF, "What is this document?"', /function scOpen/.test(html) && /scbox ok|' ok' : paper/.test(html) && /function scWarp/.test(html) && /function scFilter/.test(html) && /What is this document\?/.test(html) && /imagesToPdf\(pages\.map/.test(html));
  ok('the app: Documents card with Scan / open / rename / delete, on every touch point (closed too)', /function docsCard/.test(html) && /data-act="scanDoc"/.test(html) && /documents can still be added/.test(html));
  ok('saving the touch point keeps the documents (files ride along)', /files: x\.files \|\| \[\]/.test(html));
}

console.log('\n══ 12 · EVERYONE SEES THEIR OWN CASES\' FIELD WORK — report, photos, documents, remarks (read only) ══');
{
  const OT = 'ootat@skdhealth.com', OT2 = 'other.ph@skdhealth.com', CL = 'client@icici.com';
  KV.set('u:' + OT, JSON.stringify({ email: OT, name: 'Hemalatha A', role: 'ootat-manager', status: 'approved' }));
  KV.set('u:' + OT2, JSON.stringify({ email: OT2, name: 'Somebody Else', role: 'product-head', status: 'approved' }));
  KV.set('u:' + CL, JSON.stringify({ email: CL, name: 'Client', role: 'client-manager', status: 'approved', clients: ['HDFC ERGO'] }));
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const pg0 = await J('/api/app/admin/officers', null, { as: OT });
  ok('an Out-of-TAT manager is not on the Pinaka App page', pg0._status === 403);
  const ck = claimKey('A100');
  db.prepare("INSERT INTO app_reports (ck, claim, ukey, officer, state, status, sections, created, updated, rounds) VALUES (?, 'A100', 'milton vemu', 'MILTON VEMU', 'Tamil Nadu', 'draft', '[]', ?, ?, 0) ON CONFLICT(ck, ukey) DO UPDATE SET status = 'draft'").run(ck, Date.now(), Date.now());
  const fw = await J('/api/app/admin/case?claim=A100', null, { as: OT });
  ok('...but on HIS case (he manages it) he reads the whole Field Work, read only', fw.ok && fw.readOnly && fw.canAllocate === false && fw.field.tps.length >= 1, JSON.stringify(fw).slice(0, 300));
  ok('...the touch-point remarks, photos and scanned documents are there', fw.field.tps.some(t => (t.files || []).length >= 1));
  ok('...and a Final Report still being written shows as a draft (not decidable)', fw.reports.some(r => r.status === 'draft' && !r.canDecide));
  const tpRow = db.prepare("SELECT files FROM app_tp WHERE ck = ? AND files LIKE '%pinaka/file/%'").get(ck);
  const fkey = JSON.parse(tpRow.files)[0].key;
  const ph = await call('/api/app/admin/attendance/photo?key=' + encodeURIComponent(fkey), null, { as: OT });
  ok('...he opens the scanned PDF', ph.status === 200);
  const sel = db.prepare("SELECT selfie_key FROM app_punch LIMIT 1").get();
  const ph2 = await call('/api/app/admin/attendance/photo?key=' + encodeURIComponent((sel && sel.selfie_key) || 'pinaka/selfie/milton-vemu/day-x/1.jpg'), null, { as: OT });
  ok('...but not an attendance selfie (not a case paper)', ph2.status === 404);
  const pgA = await call('/pinaka/admin?claim=A100&embed=1', null, { as: OT });
  const pgB = await call('/pinaka/admin', null, { as: OT });
  ok('the case drawer\'s Field Work tab opens for him; the whole Pinaka page does not', pgA.status === 200 && pgB.status === 403);
  const ch = await J('/api/app/admin/chat?claim=A100', null, { as: OT });
  ok('...and the case\'s Team Chat is open to him', ch.ok);
  const no = await J('/api/app/admin/case?claim=S300', null, { as: OT });
  const no2 = await J('/api/app/admin/case?claim=A100', null, { as: OT2 });
  ok('a case that is not his: not found (another manager\'s case, another product head)', no._status === 404 && no2._status === 404);
  const cl = await J('/api/app/admin/case?claim=A100', null, { as: CL });
  const clp = await call('/pinaka/admin?claim=A100&embed=1', null, { as: CL });
  ok('an insurer (External User) login never sees our field work', cl._status === 404 && clp.status === 403);
  const ad = fs.readFileSync('pinaka-admin.html', 'utf8');
  ok('the portal: "Latest from the field", the report\'s Evidence (photos, video, documents, remarks), Draft label', /function latestHtml/.test(ad) && /function evidenceHtml/.test(ad) && /Draft — still being written/.test(ad));
}

console.log('\n══ 13 · SOS — the officer presses it; his OHS, his State Coordinator, admin and boss are rung ══');
{
  const OHS = 'ravi.ohs@skdhealth.com', SH = 'tn.sc@skdhealth.com', SH2 = 'ap.sc@skdhealth.com';
  KV.set('team:t9', JSON.stringify({ id: 't9', name: 'Chennai South', head: 'Ravi Kumar', members: ['Milton Vemu', 'Someone'] }));
  KV.set('u:' + OHS, JSON.stringify({ email: OHS, name: 'Ravi Kumar', role: 'ohs', team: 't9', status: 'approved' }));
  KV.set('u:' + SH, JSON.stringify({ email: SH, name: 'TN Coordinator', role: 'coordinator', states: ['Tamil Nadu'], status: 'approved' }));
  KV.set('u:' + SH2, JSON.stringify({ email: SH2, name: 'AP Coordinator', role: 'coordinator', states: ['Andhra Pradesh'], status: 'approved' }));
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const a0 = db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'pinaka_sos'").get().n;
  const s1 = await J('/api/app/sos', { reason: 'Accident', note: 'Bike slipped near Tambaram', lat: 12.92493, lng: 80.1271, acc: 9, battery: 41, claim: 'A100' }, { token: T });
  const told = (s1.sos && s1.sos.told || []).map(x => x.email).sort();
  ok('SOS: he presses it — his OHS and his State Coordinator are told (not the other state\'s)', s1.ok && s1.sos.status === 'open' && told.includes(OHS) && told.includes(SH) && !told.includes(SH2), JSON.stringify(s1).slice(0, 300));
  const rows = db.prepare("SELECT * FROM alerts WHERE kind = 'pinaka_sos' ORDER BY created").all().slice(a0);
  ok('...the portal bell RINGS for the OHS, the coordinator and admin/boss, with the place', rows.length === told.length + 1 && rows.every(r => r.ring === 1) && rows.some(r => r.to_mail === OHS) && rows.some(r => r.to_mail === SH) && rows.some(r => /admin/.test(r.aud)) && /12\.92493, 80\.12710/.test(rows[0].body));
  const s2 = await J('/api/app/sos', { reason: 'Accident', lat: 12.93, lng: 80.13 }, { token: T });
  ok('a second press within 2 minutes only moves the pin (nobody rung twice)', s2.ok && s2.again && s2.sos.lat === 12.93 && db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'pinaka_sos'").get().n === a0 + told.length + 1);
  const lo = await J('/api/app/admin/sos', null, { as: OHS });
  const la = await J('/api/app/admin/sos', null, { as: SH2 });
  ok('the Live board shows it to his OHS; not to another state\'s coordinator', lo.ok && lo.open === 1 && lo.sos[0].officer === 'MILTON VEMU' && la.ok && la.open === 0);
  const fc = FCM.length;
  const ak = await J('/api/app/admin/sos', { id: lo.sos[0].id, action: 'ack' }, { as: OHS });
  ok('"I\'m on it" — his phone is told who is coming', ak.ok && FCM.slice(fc).some(f => /Ravi Kumar is on it/.test(JSON.stringify(f))));
  const g = await J('/api/app/sos', null, { token: T });
  ok('...and the app shows it', g.ok && g.sos.status === 'ack' && g.sos.ackBy === 'Ravi Kumar');
  const sf = await J('/api/app/sos/safe', {}, { token: T });
  ok('"I am safe now" closes it and tells them', sf.ok && !(await J('/api/app/sos', null, { token: T })).sos && db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'pinaka_sos' AND title LIKE '%safe now%'").get().n >= 3);
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app: SOS button in every header, reasons, SEND SOS NOW, Call 112, offline queue', /class="sosb/.test(html) && /SEND SOS NOW/.test(html) && /tel:112/.test(html) && /sosQueue/.test(html));
  ok('the portal: SOS on top of the Live board with Map, I\'m on it, Resolved', /function sosHtml/.test(fs.readFileSync('pinaka-admin.html', 'utf8')));
}

console.log('\n══ 14 · FIELD TRACKER: LIVE ON THE SAME MAP — the photo moves, home keeps a house ══');
{
  const d0 = await J('/api/field/dashboard', null, { as: ADMIN });
  ok('the Field Tracker answers (schema ready)', d0.ok, JSON.stringify(d0).slice(0, 200));
  db.prepare("INSERT INTO checkins (id, ts, name, mobile, lat, lng, address, city, loc_type) VALUES ('h1', ?, 'MILTON VEMU', '9876543210', 12.9000, 80.1000, 'Home street, Tambaram', 'Chennai', 'Home')").run(Date.now() - 86400000);
  db.prepare("INSERT INTO app_duty (ukey, on_duty, since, last_at, last_lat, last_lng, last_speed, gps_off, battery) VALUES ('milton vemu', 1, ?, ?, 12.9350, 80.1380, 6.5, 0, 77) ON CONFLICT(ukey) DO UPDATE SET on_duty = 1, since = excluded.since, last_at = excluded.last_at, last_lat = 12.9350, last_lng = 80.1380, last_speed = 6.5, gps_off = 0, battery = 77").run(Date.now() - 3600000, Date.now() - 60000);
  const d1 = await J('/api/field/dashboard', null, { as: ADMIN });
  const mc = (d1.checkins || []).find(c => c.liveKey === 'milton vemu');
  const lv = (d1.live || []).find(l => l.key === 'milton vemu');
  ok('his check-in carries his key and his HOME is known', mc && d1.homes && d1.homes['milton vemu'] && d1.homes['milton vemu'].lat === 12.9, JSON.stringify(d1.homes));
  ok('...and his Pinaka position is on the same answer: moving, where he is now, battery', lv && lv.onDuty && lv.status === 'moving' && lv.lat === 12.935 && lv.battery === 77);
  const l2 = await J('/api/field/live', null, { as: ADMIN });
  ok('the 30-second refresh asks only for the live positions', l2.ok && l2.live.some(l => l.key === 'milton vemu'));
  const l3 = await J('/api/field/live', null, { as: COORD });
  ok('a coordinator whose states do not hold him does not see him live', !l3.ok || !(l3.live || []).some(l => l.key === 'milton vemu'));
  const ui = (await import('./field-ui-client.js')).CLIENT_JS;
  ok('the map: LIVE badge on the moving photo, a house at home, house badge on a Home pin, 30-second refresh', /LIVE/.test(ui) && /function homeIcon/.test(ui) && /_home: true, _kind: 'home'/.test(ui) && /_kind: 'live'/.test(ui) && /api\('\/api\/live'\)/.test(ui));
}

console.log('\n══ 15 · STATE COORDINATOR MAY RE-ALLOCATE / CHANGE — on his own states\' cases ══');
{
  const { canAssignFo, coordinatorMay } = await import('./assign-index.js');
  ok('a State Coordinator may now allocate (admin, boss, manager as before; OHS still not)', canAssignFo({ role: 'coordinator' }) && canAssignFo({ role: 'manager' }) && !canAssignFo({ role: 'ohs' }) && !canAssignFo({ role: 'client-manager' }));
  const noStates = await coordinatorMay(env, { role: 'coordinator', states: [] }, { claimNo: 'A100', officerName: 'MILTON VEMU' });
  ok('...but only on his own states\' cases (a coordinator with no state gets none)', noStates === false && (await coordinatorMay(env, { role: 'manager' }, null)) === true);
  const r = await J('/api/assign/fo', { claim: 'B200', confirm: 'B200', foUserName: 'kiran.n' }, { as: COORD });
  ok('...and the SKD assign door refuses him outside his states', r._status === 403 && /own states/.test(r.error || ''), JSON.stringify(r).slice(0, 200));
}

console.log('\n══ 16 · OLD APP → "PLEASE INSTALL THE NEW PINAKA" ══');
{
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const old = await J('/api/app/cases', null, { token: T, oldApp: true });
  ok('an app that sends no version (2.0.0 and before) is stopped: "cannot be opened … install the new Pinaka"', old._status === 426 && old.updateRequired && /install the new Pinaka/.test(old.error));
  const a200 = await J('/api/app/cases', null, { token: T, appVersion: '2.0.0', platform: 'android' });
  const a210 = await J('/api/app/cases', null, { token: T, appVersion: '2.1.1', platform: 'android' });
  const web = await J('/api/app/cases', null, { token: T, appVersion: '1.0.0', platform: 'web' });
  ok('Android 2.0.0 stopped; Android 2.1.0 opens; the web app is never stopped', a200._status === 426 && a210.ok && web.ok);
  const al = await J('/api/app/alarm', null, { token: T, oldApp: true });
  ok('the alarm door stays open for the service worker', al.ok);
  const s1 = await J('/api/app/admin/minapp', { version: '2.2.0' }, { as: ADMIN });
  const a210b = await J('/api/app/cases', null, { token: T, appVersion: '2.1.1', platform: 'android' });
  const cs = await J('/api/app/admin/minapp', { version: '2.3.0' }, { as: COORD });
  ok('admin raises the oldest app allowed after a release → 2.1.0 is now stopped; others cannot change it', s1.ok && s1.minVersion === '2.2.0' && a210b._status === 426 && a210b.minVersion === '2.2.0' && cs._status === 403);
  await J('/api/app/admin/minapp', { version: '2.1.1' }, { as: ADMIN });
  const a210c = await J('/api/app/cases', null, { token: T, appVersion: '2.1.0', platform: 'android' });
  const low = await J('/api/app/admin/minapp', { version: '2.0.0' }, { as: ADMIN });
  ok('28-Sep: 2.1.0 phones (the "{}" uploads) are now told to install 2.1.1, and the floor cannot be set below 2.1.1', a210c._status === 426 && a210c.minVersion === '2.1.1' && low.minVersion === '2.1.1');
  const html = fs.readFileSync('pinaka.html', 'utf8');
  ok('the app sends its version on every call and shows "Please install the new Pinaka"', /x-app-version/.test(html) && /function vUpdate/.test(html) && /Please install the new Pinaka/.test(html));
}

console.log('\n══ 17 · LEAVE: OHS → State Coordinator → manager/admin; 2 days+ → his cases to OUR Pending; MAIL on decisions ══');
{
  const MAILS = [];
  env.RESEND_API_KEY = 're_test_key';
  env.__fetch = async (u, init) => { MAILS.push(JSON.parse(init.body)); return new Response(JSON.stringify({ id: 'm' + MAILS.length }), { status: 200 }); };
  const MGR = 'hema@skdhealth.com';
  KV.set('u:' + MGR, JSON.stringify({ email: MGR, name: 'Hemalatha A', role: 'manager', status: 'approved' }));
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const day = n => new Date(Date.now() + 330 * 60000 + n * 86400000).toISOString().slice(0, 10);
  const pv = await J('/api/app/leave/preview', null, { token: T });
  ok('the app can show the cases he holds before he applies', pv.ok && pv.claims.some(c => c.claim === 'A100') && pv.moveDays === 2, JSON.stringify(pv).slice(0, 300));
  const noReason = await J('/api/app/leave', { from: day(3), to: day(4), type: 'Casual leave', reason: '' }, { token: T });
  ok('a reason is needed', noReason._status === 400);
  const back = await J('/api/app/leave', { from: day(4), to: day(3), type: 'Casual leave', reason: 'family function' }, { token: T });
  ok('the last day cannot be before the first', back._status === 400);
  const warn = await J('/api/app/leave', { from: day(3), to: day(4), type: 'Casual leave', reason: 'family function at home' }, { token: T });
  ok('2 days: "once approved your cases will be given to other field officers" — with his claim numbers', warn._status === 409 && warn.needConfirm && warn.claims.some(c => c.claim === 'A100') && /other field officers/.test(warn.error));
  const ap = await J('/api/app/leave', { from: day(3), to: day(4), type: 'Casual leave', reason: 'family function at home', understood: true }, { token: T });
  ok('he ticks "I understand" → applied, waiting for OHS', ap.ok && ap.days === 2 && ap.claims.length >= 1);
  const clash = await J('/api/app/leave', { from: day(4), to: day(4), type: 'Sick leave', reason: 'fever again today' }, { token: T });
  ok('no second leave on the same days', clash._status === 409);
  const one = await J('/api/app/leave', { from: day(10), to: day(10), type: 'Sick leave', reason: 'doctor visit' }, { token: T });
  ok('1 day: no warning, his cases stay', one.ok && one.days === 1 && one.claims.length === 0);
  const bell = db.prepare("SELECT * FROM alerts WHERE kind = 'pinaka_leave' ORDER BY id DESC LIMIT 1").get();
  ok('the portal bell hears of it', bell && /applied for leave/.test(bell.title));
  const sc0 = await J('/api/app/admin/leave', { id: ap.id, action: 'approve' }, { as: 'sc@skdhealth.com' });
  ok('the State Coordinator cannot approve before the OHS', sc0._status === 403);
  const mg0 = await J('/api/app/admin/leave', { id: ap.id, action: 'approve' }, { as: MGR });
  ok('nor the manager', mg0._status === 403);
  const ol = await J('/api/app/admin/leave', null, { as: 'ohs@skdhealth.com' });
  ok('the OHS sees it waiting for him (everyone on the ladder can see it)', ol.ok && ol.leaves.find(x => x.id === ap.id).step === 'l1' && ol.waitingForMe >= 1);
  const cl = await J('/api/app/admin/leave', null, { as: COORD });
  ok('a coordinator of other states does not see him', cl.ok && !cl.leaves.some(x => x.id === ap.id));
  const s1 = await J('/api/app/admin/leave', { id: ap.id, action: 'approve', note: 'ok' }, { as: 'ohs@skdhealth.com' });
  const s2 = await J('/api/app/admin/leave', { id: ap.id, action: 'approve' }, { as: 'sc@skdhealth.com' });
  ok('OHS → l1, State Coordinator (Tamil Nadu) → l2', s1.ok && s1.status === 'l1' && s2.ok && s2.status === 'l2');
  const cancelLate = await J('/api/app/leave', null, { token: T });
  ok('his app shows the ladder so far', cancelLate.ok && cancelLate.leaves.find(x => x.id === ap.id).l2.by === 'SC TN');
  const noMail = MAILS.length;
  const s3 = await J('/api/app/admin/leave', { id: ap.id, action: 'approve' }, { as: MGR });
  ok('the manager gives the final approval → approved, his cases moved', s3.ok && s3.status === 'approved' && s3.moved.indexOf('A100') >= 0, JSON.stringify(s3));
  const cs = db.prepare("SELECT app_status, app_note FROM case_store WHERE ck = ?").get(claimKey('A100'));
  ok('A100 is now "Pending — FO on leave" on OUR portal (nothing sent to SKD)', cs && cs.app_status === 'leave' && /re-allocate/.test(cs.app_note) && !ASSIGN.some(u => /leave/.test(u)));
  const mb = db.prepare("SELECT * FROM alerts WHERE kind = 'pinaka_leave' AND to_mail = ? ORDER BY id DESC LIMIT 1").get(MGR);
  ok('the case manager is told on the bell with the claim numbers', mb && /A100/.test(mb.body));
  const nl = db.prepare("SELECT * FROM app_notify WHERE kind = 'leave' ORDER BY id DESC LIMIT 1").get();
  ok('no Mail ID yet → no mail, and the log says so', MAILS.length === noMail && nl && nl.ok === 0 && /no Mail ID/.test(nl.error));
  const eo = await J('/api/app/admin/email', { name: 'Milton Vemu', email: 'milton@example.com' }, { as: 'ohs@skdhealth.com' });
  ok('only admin, boss, managers, HR set Mail IDs', eo._status === 403);
  const eb = await J('/api/app/admin/email/bulk', { rows: [{ name: 'MILTON VEMU', email: 'Milton@Example.com' }, { name: 'Kiran Nimmala', email: 'not a mail' }, { name: 'Nobody Here', email: 'n@x.com' }] }, { as: ADMIN });
  ok('admin pastes Mail IDs: good one saved (lower-case), bad address and unknown name reported', eb.ok && eb.saved === 1 && eb.done[0].email === 'milton@example.com' && eb.problems.length === 2);
  const offs = await J('/api/app/admin/officers', null, { as: ADMIN });
  ok('the officers list shows his Mail ID', offs.ok && offs.officers.find(o => o.key === 'milton vemu').email === 'milton@example.com');
  const rj0 = await J('/api/app/admin/leave', { id: one.id, action: 'reject' }, { as: 'ohs@skdhealth.com' });
  const rj = await J('/api/app/admin/leave', { id: one.id, action: 'reject', note: 'audit visit that day' }, { as: 'ohs@skdhealth.com' });
  const lastMail = MAILS[MAILS.length - 1];
  ok('a reject needs a reason, then he gets the mail', rj0._status === 400 && rj.ok && lastMail && lastMail.to[0] === 'milton@example.com' && /Leave rejected/.test(lastMail.subject) && /audit visit/.test(lastMail.html));
  const lv = await J('/api/app/leave', { from: day(20), to: day(20), type: 'Personal', reason: 'bank work' }, { token: T });
  const cn = await J('/api/app/leave/cancel', { id: lv.id }, { token: T });
  const cn2 = await J('/api/app/leave/cancel', { id: ap.id }, { token: T });
  ok('he may cancel his own until it is decided — not after', cn.ok && cn2._status === 409);
  /* expense mails: every step says who approved and who has not */
  db.prepare("INSERT INTO app_expenses (ukey, officer, state, claim, exp_date, mode, amount, status, created) VALUES ('milton vemu','MILTON VEMU','Tamil Nadu','A100',?, 'Bus Ticket', 60, 'submitted', ?)").run(day(0), Date.now());
  const xid = db.prepare('SELECT MAX(id) AS id FROM app_expenses').get().id;
  const m0 = MAILS.length;
  await J('/api/app/admin/expense', { id: xid, action: 'approve' }, { as: 'ohs@skdhealth.com' });
  const x1 = MAILS[MAILS.length - 1];
  await J('/api/app/admin/expense', { id: xid, action: 'approve' }, { as: 'sc@skdhealth.com' });
  await J('/api/app/admin/expense', { id: xid, action: 'approve' }, { as: ADMIN });
  await J('/api/app/admin/expense', { id: xid, action: 'paid' }, { as: ADMIN });
  const x4 = MAILS[MAILS.length - 1];
  ok('each expense step mails him (OHS, State Coordinator, Admin, Paid)', MAILS.length === m0 + 4 && /approved by OHS/.test(x1.subject) && /State Coordinator: waiting/.test(x1.text) && /PAID/.test(x4.subject) && /Paid: yes/.test(x4.text), JSON.stringify(x1 && x1.subject));
  db.prepare("INSERT INTO app_expenses (ukey, officer, state, exp_date, mode, amount, status, created) VALUES ('milton vemu','MILTON VEMU','Tamil Nadu',?, 'Food Allowance', 90, 'submitted', ?)").run(day(0), Date.now());
  const yid = db.prepare('SELECT MAX(id) AS id FROM app_expenses').get().id;
  await J('/api/app/admin/expense', { id: yid, action: 'reject', note: 'no bill' }, { as: 'ohs@skdhealth.com' });
  ok('a rejected expense mails him with the reason', /REJECTED/.test(MAILS[MAILS.length - 1].subject) && /no bill/.test(MAILS[MAILS.length - 1].html));
  const nlog = await J('/api/app/admin/notify', null, { as: ADMIN });
  ok('the mail log is on the portal', nlog.ok && nlog.mails.length >= 5 && nlog.mails.some(m => !m.ok));
  delete env.__fetch; delete env.RESEND_API_KEY;
  const html = fs.readFileSync('pinaka.html', 'utf8'), adm = fs.readFileSync('pinaka-admin.html', 'utf8');
  ok('the app has a Leave screen with the "I understand" tick; the portal has the Leave tab and Mail IDs', /function vLeave/.test(html) && /understood/.test(html) && /api\/app\/admin\/leave/.test(adm) && /api\/app\/admin\/email\/bulk/.test(adm));
}

console.log('\n══ 18 · ONE PHONE PER OFFICER — a second phone is told "ask your admin to sign out the old one" ══');
{
  const live = db.prepare('SELECT COUNT(*) AS n FROM app_devices WHERE ukey = ? AND revoked_at IS NULL').get('milton vemu').n;
  const bad = await J('/api/app/login', { id: 'TSN-FO-0412', password: 'wrong-pass-1' }, { fresh: true });
  ok('a wrong password still says only "not right" (nothing about his phone)', bad._status === 401 && !bad.onePhone);
  const second = await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'android' }, { fresh: true });
  ok('the right password on a second phone → refused: already signed in, ask admin to sign out, they will support you', second._status === 409 && second.onePhone && /already signed in/.test(second.error) && /admin/.test(second.error) && /support you/.test(second.error) && !second.token, second.error);
  ok('...no new phone was added', db.prepare('SELECT COUNT(*) AS n FROM app_devices WHERE ukey = ? AND revoked_at IS NULL').get('milton vemu').n === live);
  const bell = db.prepare("SELECT * FROM alerts WHERE kind = 'pinaka_login' ORDER BY id DESC LIMIT 1").get();
  ok('admin sees it on the bell', bell && /second phone/.test(bell.title) && /Sign out/.test(bell.body));
  const out = await J('/api/app/admin/revoke', { name: 'MILTON VEMU' }, { as: ADMIN });
  const again = await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'android' }, { fresh: true });
  ok('admin presses Sign out → the new phone signs in', out.ok && out.signedOut >= 1 && again.ok && /^pk_/.test(again.token));
  const third = await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' }, { fresh: true });
  ok('...and now the OLD one is the second phone', third._status === 409 && third.onePhone && /Android/.test(third.error));
  const cd = await J('/api/app/admin/code', { name: 'MILTON VEMU' }, { as: ADMIN });
  const act = await J('/api/app/activate', { id: 'milton.v', code: cd.code, platform: 'web' }, { fresh: true });
  ok('the access code door keeps the same rule, and the code is not used up', act._status === 409 && act.onePhone && !!db.prepare('SELECT code_hash FROM app_officers WHERE ukey = ?').get('milton vemu').code_hash);
}

console.log('\n══ 19 · STORE APP FILES AS TEXT — {b64, type} + x-bin: 1 becomes the real file ══');
{
  const T = (await J('/api/app/login', { id: 'TSN-FO-0412', password: 'Milton2026x', platform: 'web' })).token;
  const jpg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9]);
  const b64 = Buffer.from(jpg).toString('base64');
  const r = await entry.fetch(new Request('https://taasenclaims.com/api/app/upload', { method: 'POST', headers: { authorization: 'Bearer ' + T, 'content-type': 'application/json', 'x-bin': '1', 'x-kind': 'tp', 'x-case': 'A100', 'x-app-version': '2.1.1', 'x-app-platform': 'android' }, body: JSON.stringify({ b64, type: 'image/jpeg' }) }), env, ctx);
  const j = await r.json();
  ok('a photo sent as text arrives whole (same size, image/jpeg, stored)', r.status === 200 && j.ok && j.type === 'image/jpeg' && j.bytes === jpg.length && env.PHOTOS._store.has(j.key), JSON.stringify(j).slice(0, 200));
  const h = fs.readFileSync('pinaka.html', 'utf8');
  ok('the store app sends photos, bills and voice this way', /function postFile/.test(h) && (h.match(/postFile\(API \+/g) || []).length >= 4);
}

{ const h = fs.readFileSync('pinaka.html', 'utf8');
  ok('28-Sep: the photo camera (punch, visit, touch point) has no gallery button — live photos only', !/id="camgal"/.test(h) && /data-cam="snap"/.test(h)); }
console.log('\n══ 20 · THE DAILY UPDATE GOES TO THE MEETING PAGES (Out of TAT + IN TAT) WITH HIS NAME ══');
{
  const { stGet } = await import('./worker.js');
  const notes = JSON.parse((await stGet(env, 'ootatmeet:notes')) || '{}');
  const hs = Object.values(notes).flatMap(n => n.h || []).filter(x => x.src === 'fo');
  ok('each case update from the app is a line on that claim, by the officer, named', hs.length >= 1 && hs.every(x => /\(Field Officer\)$/.test(x.name) && /^fo:/.test(x.by) && x.t.length >= 5), JSON.stringify(hs.slice(0, 2)));
  const perDay = {}; hs.forEach(x => { const k = x.by + '|' + x.day + '|' + x.t.slice(0, 0); perDay[k] = (perDay[k] || 0) + 1; });
  const a100 = notes['A100'] || Object.values(notes)[0];
  const fDays = (a100.h || []).filter(x => x.src === 'fo').map(x => x.day);
  ok('...one line per officer per case per day (a second save that day replaces his own)', new Set(fDays).size === fDays.length);
  const a = fs.readFileSync('app.js', 'utf8');
  ok('the meeting page shows FIELD OFFICER UPDATE with his name; "last meeting" and the ranking stay the managers\' lines', /FIELD OFFICER UPDATE/.test(a) && /x\.src !== 'fo'/.test(a) && /Pinaka app'/.test(a));
}

console.log('\n══ 21 · SIGN-IN FROM INDIA ONLY ══');
{
  const mk = (cc) => { const r = new Request('https://taasenclaims.com/api/app/login', { method: 'POST', headers: { 'content-type': 'application/json', 'x-app-version': '2.1.1', 'x-app-platform': 'web' }, body: JSON.stringify({ id: 'TSN-FO-0412', password: 'wrong-pass-9' }) }); Object.defineProperty(r, 'cf', { value: { country: cc } }); return r; };
  const us = await entry.fetch(mk('US'), env, ctx); const usj = await us.json();
  const inn = await entry.fetch(mk('IN'), env, ctx);
  ok('a sign-in from outside India is refused before the password is even checked; from India it reaches the door', us.status === 403 && usj.geo === 'US' && inn.status === 401);
  env.SIGNIN_COUNTRIES = 'IN,AE';
  const ae = await entry.fetch(mk('AE'), env, ctx);
  ok('...admin can widen the list with one Worker variable (SIGNIN_COUNTRIES)', ae.status === 401);
  delete env.SIGNIN_COUNTRIES;
}

console.log('\n══ 22 · PIN CODES LAND IN THEIR OWN DISTRICT (679522 is Palakkad, Kerala — not Karnataka) ══');
{
  const { pinLookup } = await import('./pincode-index.js');
  const p = pinLookup('679522'), ok1 = pinLookup('600122'), b = pinLookup('560036');
  ok('679522 → Palakkad, Kerala, near the district HQ (was 13.22, 76.05 in Karnataka)', p.state === 'Kerala' && Math.abs(p.lat - 10.78) < 0.5 && Math.abs(p.lng - 76.65) < 0.5 && p.approx === true);
  ok('...codes that were right stay exactly as they were (600122, 560036)', !ok1.approx && ok1.lat === 13.0175 && !b.approx && b.lat === 13.008);
}

console.log('\n══ 23 · DOCUMENT MANAGER ALLOCATES (Allocate tab on Pending cases, Re-allocate, Change, our cases) ══');
{
  const DM = 'docmgr@skdhealth.com';
  KV.set('u:' + DM, JSON.stringify({ email: DM, name: 'Doc Manager', role: 'document-manager', status: 'approved', access: ['dashboard', 'analytics', 'claimmatch', 'docs'] }));
  const { canAssignFo } = await import('./assign-index.js');
  const { canAllocOur } = await import('./app-index.js');
  ok('the Document Manager may allocate / re-allocate / change (SKD cases) and allocate our own cases', canAssignFo({ role: 'document-manager' }) && canAllocOur({ role: 'document-manager' }) && !canAssignFo({ role: 'hr' }) && !canAllocOur({ role: 'ohs' }));
  const our = await J('/api/app/admin/our', null, { as: DM });
  ok('...he sees Our cases with the officer list', our.ok && Array.isArray(our.officers) && our.cases.some(c => c.claim === 'TS-9001'), JSON.stringify(our).slice(0, 200));
  const al = await J('/api/app/admin/our/allocate', { claim: 'TS-9001', officers: [{ name: 'MILTON VEMU', parts: ['Insured verification'] }] }, { as: DM });
  ok('...and allocates one — the phone rings', al.ok && al.rang.includes('MILTON VEMU'), JSON.stringify(al));
  const off = await J('/api/app/admin/officers', null, { as: DM });
  ok('...nothing else of the Pinaka page opens for him (Officers stays shut)', off._status === 403);
}

console.log('\n══ 24 · FORGOT PASSWORD → MAIL ID → OTP → NEW PASSWORD ══');
{
  const realFetch = globalThis.fetch; let CODE = '';
  env.OTP_MAIL_URL = 'https://otp.test/send';
  globalThis.fetch = async (u, init) => { if (String(u) === env.OTP_MAIL_URL) { CODE = JSON.parse(init.body).code; return new Response('{"ok":true}', { status: 200 }); } return realFetch(u, init); };
  const nobody = await J('/api/auth/otp/start', { email: 'stranger@nowhere.com', forgot: true, door: 'taasen' });
  ok('a mail ID not on the portal gets no OTP (and no access request is filed)', nobody._status === 404 && !KV.get('u:stranger@nowhere.com'));
  env.DB._db.prepare('UPDATE portal_passwords SET locked_until = ?2 WHERE email = ?1').run(COORD, Date.now() + 600000);
  const st = await J('/api/auth/otp/start', { email: COORD, forgot: true, door: 'taasen' });
  ok('a member types his mail ID → the 6-digit OTP goes to his mail', st.ok && /^\d{6}$/.test(CODE), JSON.stringify(st));
  const wrong = await J('/api/auth/otp/verify', { email: COORD, code: CODE === '111111' ? '222222' : '111111', forgot: true, door: 'taasen' });
  ok('a wrong OTP is refused', wrong._status === 401);
  const r = await call('/api/auth/otp/verify', { email: COORD, code: CODE, forgot: true, door: 'taasen' });
  const j = await r.json();
  ok('the right OTP signs him in and asks for a new password', j.ok && j.status === 'approved' && j.mustChange === true && /skd_session=/.test(r.headers.get('set-cookie') || ''), JSON.stringify(j));
  const row = env.DB._db.prepare('SELECT must_change, locked_until FROM portal_passwords WHERE email = ?').get(COORD);
  ok('...the lock is lifted and no old password is needed', row.must_change === 1 && !row.locked_until);
  const ch = await J('/api/auth/password/change', { password: 'NewPass2026' }, { as: COORD });
  const again = await J('/api/auth/password', { email: COORD, password: 'NewPass2026', door: 'taasen' });
  ok('...he saves a new password and signs in with it', ch.ok && again.ok && again.mustChange === false);
  /* 29-Sep: ONE mail, from no-reply — the Apps Script relay (his own mailbox) is not used when no-reply works */
  const MAILS = []; const oldF = env.__fetch; env.__fetch = async (u, init) => { MAILS.push(JSON.parse(init.body)); return new Response('{"id":"m1"}', { status: 200 }); };
  const sent0 = 0; let relayHits = 0;
  globalThis.fetch = async (u, init) => { if (String(u) === env.OTP_MAIL_URL) { relayHits++; return new Response('{"ok":true}', { status: 200 }); } return realFetch(u, init); };
  env.RESEND_API_KEY = 're_test_key';
  await new Promise(r => setTimeout(r, 10));
  try { env.DB._db.prepare("DELETE FROM portal_state WHERE k = ?").run('otp:' + COORD); } catch (e) {} KV.delete('otp:' + COORD);
  const one = await J('/api/auth/otp/start', { email: COORD, forgot: true, door: 'taasen' });
  const last = MAILS[MAILS.length - 1] || {};
  ok('the OTP goes as ONE mail, from no-reply@taasenclaims.com — never from his own mailbox', one.ok && MAILS.length === sent0 + 1 && /no-reply@taasenclaims\.com/.test(last.from) && relayHits === 0, JSON.stringify({ one, from: last.from, relayHits }));
  globalThis.fetch = realFetch; delete env.OTP_MAIL_URL; env.__fetch = oldF;
}

console.log('\n' + PASS + ' passed · ' + FAIL + ' failed');
process.exit(FAIL ? 1 : 0);
