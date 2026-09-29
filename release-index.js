/*******************************************************************************************
 *  RELEASED FROM COMPLETED  —  the stage between FO Completed and CM Reviewed
 *  ----------------------------------------------------------------------------------------
 *  Sujit, 12-Aug-2026: "Once in completed option submitted, from completed need to come to
 *  Released. They have been submitted means need to come to CM Reviewed within 24 hours."
 *
 *  WHY THIS STAGE LIVES IN THE PORTAL AND NOT IN SKD
 *  SKD has exactly nine statuses and Released is not one of them:
 *      pending · assigned · deferred · fo-accepted · fo-rejected
 *      fo-completed · cm-reviewed · qc-reviewed · dm-reviewed
 *  So the portal keeps it. A manager presses Release on Completed From Field when the report
 *  and every document are in; the portal writes down WHO released it and WHEN, and the clock
 *  starts from that moment.
 *
 *  WHAT THE 24 HOURS DOES, AND WHAT IT DELIBERATELY DOES NOT DO
 *  It chases. Every hour the portal asks SKD which cases have reached cm-reviewed, and any
 *  case released more than 24 hours ago that has NOT got there is counted and listed.
 *
 *  It does NOT write "CM Reviewed" anywhere. That status belongs to SKD and is set by the
 *  person who reviews the case. A portal that showed Reviewed while SKD still said
 *  fo-completed would be lying about the case, which is the one fault this project keeps
 *  coming back to. Chased, never faked.
 *
 *  Routes  (mounted by entry.js, same trick as /field)
 *    POST /api/release            {claim}  a manager releases a completed case
 *    POST /api/release/undo       {claim}  admin or management takes it back
 *    GET  /api/released                    the Released page: what is waiting, what is overdue
 *    GET  /api/fo-completed                the stage BEFORE Released — see the note on it below
 *
 *  KV keys       rel:<claimKey>   one per released case
 *                release:sweep    what the hourly sweep last found
 *  Variables     RELEASE_ALERT_TO  optional. A mail address. Nothing is ever sent unless you
 *                                  set it yourself — see the note on the sweep below.
 *******************************************************************************************/

/* v17.8 — the release records moved off KV. One write per released case, plus the hourly
   sweep marker, out of a free allowance of 1,000 writes a day for the WHOLE portal — and on
   31-Aug that allowance ran out mid-meeting and took the sign-in page with it. D1 allows
   100,000 a day. Reads fall back to the old KV record until each one is re-saved, so no
   release already made is lost. */
import {
  stGet, stPut, stSoft, stDel, stList,
  currentUser, canAccess, scopeCases, getFoStateMap,
  getCompleteCases, getCases, claimKey, validClaim, normName,
  isCompletedStatusW, isPartCompletedW
} from './worker.js';

export async function handleRelease(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, '');
  const method = request.method.toUpperCase();

  const me = await currentUser(env, request).catch(() => null);
  if (!me) return json({ ok: false, error: 'Please sign in to the portal first.' }, 401);

  try {
    if (p === '/api/released' && method === 'GET')       return await listReleased(env, me);
    if (p === '/api/fo-completed' && method === 'GET')   return await foCompleted(env, me);
    if (p === '/api/release' && method === 'POST')       return await doRelease(request, env, me);
    if (p === '/api/release/undo' && method === 'POST')  return await undoRelease(request, env, me);
    return json({ ok: false, error: 'Unknown endpoint: ' + p }, 404);
  } catch (e) {
    return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}

/* WHO MAY RELEASE. Whoever works the Completed From Field page — that is where the button is,
   and that is the man who knows the report and the documents are actually in. Admin and
   Management too, since they see everything. */
function canRelease(me) {
  return !!me && (me.role === 'admin' || me.role === 'boss' || canAccess(me, 'ootat'));
}
/* Taking a release BACK is admin work. A release starts a clock somebody will be measured
   against, so it is not something to undo quietly. */
function canUndo(me) {
  return !!me && (me.role === 'admin' || me.role === 'boss');
}

const HOUR = 60 * 60 * 1000;
const TARGET_HOURS = 24;

/* ── storing one release ─────────────────────────────────────────────────────────────── */
async function doRelease(request, env, me) {
  if (!canRelease(me)) return json({ ok: false, error: 'You do not have Completed From Field, so you cannot release a case.' }, 403);
  if (!env.USERS) return json({ ok: false, error: 'KV binding "USERS" is missing.' }, 500);

  const b = await request.json().catch(() => ({}));

  /* One claim, or a whole pasted column of them. He works by pasting lists — Claim Match, the
     phone book, the field force — so this takes either and answers with one line per claim
     saying exactly what happened to it. Nothing is guessed and nothing is silently skipped. */
  const wanted = Array.isArray(b.claims) ? b.claims : [b.claim];
  const claims = [];
  const bad = [];
  const seen = new Set();
  for (const raw of wanted.slice(0, 500)) {
    const c = String(raw == null ? '' : raw).replace(/[\t,;|]+/g, ' ').trim();
    if (!c) continue;
    if (!validClaim(c)) { bad.push({ claim: c.slice(0, 40), why: 'that is not a claim number' }); continue; }
    const k = claimKey(c);
    if (seen.has(k)) { bad.push({ claim: c, why: 'listed twice' }); continue; }
    seen.add(k); claims.push(c);
  }
  if (!claims.length) return json({ ok: false, error: 'No claim number to release.', bad }, 400);

  /* One pull of the open feed for the whole batch, not one per claim. */
  let open = [];
  try { const d = await getCases(env); open = d.cases || []; }
  catch (e) { /* SKD unreachable — the releases still stand, the columns just read blank */ }
  const byKey = new Map(open.map(c => [claimKey(c.claimNo), c]));

  const done = [], already = [];
  for (const claim of claims) {
    const k = claimKey(claim);
    const existing = await relGet(env, k);
    if (existing) {
      let old = {}; try { old = JSON.parse(existing); } catch (e) {}
      already.push({ claim, at: old.at || '', atText: fmtIST(old.at), by: old.byName || old.by || '' });
      continue;
    }
    /* Who the case belonged to AT THE MOMENT OF RELEASE. The open feed drops a case the day it
       closes, so reading the manager and the officer later would give nothing — the same fault
       that once turned the Excel into blank rows. */
    const hit = byKey.get(k);
    const rec = {
      claim, claimKey: k,
      at: new Date().toISOString(),
      by: me.email, byName: me.name || me.email,
      client: hit ? (hit.client || '') : '',
      insured: hit ? (hit.insured || '') : '',
      manager: hit ? (hit.manager || '') : '',
      officerName: hit ? (hit.officerName || '') : '',
      subProduct: hit ? (hit.subProduct || '') : '',
      state: hit ? (hit.state || '') : '',
      /* whether the open feed even knew this claim — shown on screen, never hidden */
      onFeed: !!hit
    };
    await stPut(env, 'rel:' + k, JSON.stringify(rec));
    done.push({ claim, onFeed: !!hit });
  }

  return json({ ok: true, released: done.length, releasedList: done, already, bad });
}

/* one release record: the shelf first, the old KV copy behind it */
async function relGet(env, k) {
  try { const v = await stGet(env, 'rel:' + k); if (v) return v; } catch (e) {}
  try { return env.USERS ? await env.USERS.get('rel:' + k) : null; } catch (e) { return null; }
}

async function undoRelease(request, env, me) {
  if (!canUndo(me)) return json({ ok: false, error: 'Only Admin and Management can take a release back.' }, 403);
  const b = await request.json().catch(() => ({}));
  const k = claimKey(String(b.claim || ''));
  if (!k) return json({ ok: false, error: 'That is not a claim number.' }, 400);
  const had = await relGet(env, k);
  if (!had) return json({ ok: false, error: 'That case was never released.' }, 404);
  await stDel(env, 'rel:' + k); try { if (env.USERS) await env.USERS.delete('rel:' + k); } catch (e) {}
  return json({ ok: true });
}

/* ── reading them all back ───────────────────────────────────────────────────────────── */
async function allReleases(env) {
  /* BOTH cupboards, keyed by claim so a record that has moved is never counted twice.
     KV is read first and D1 second, so the newer copy (D1) wins on a duplicate. */
  const byKey = new Map();
  if (env.USERS) {
    try {
      let cursor;
      do {
        const l = await env.USERS.list({ prefix: 'rel:', cursor });
        for (const key of l.keys) {
          const v = await env.USERS.get(key.name);
          if (v) { try { const r = JSON.parse(v); byKey.set(String(r.claimKey || r.claim || key.name), r); } catch (e) {} }
        }
        cursor = l.list_complete ? null : l.cursor;
      } while (cursor);
    } catch (e) { /* KV unreadable — the shelf below still answers */ }
  }
  for (const row of await stList(env, 'rel:')) {
    try { const r = JSON.parse(row.v); byKey.set(String(r.claimKey || r.claim || row.k), r); } catch (e) {}
  }
  return Array.from(byKey.values());
}

/* Which of them SKD now shows as CM Reviewed. Asked over a window that starts at the oldest
   release, so a case released three weeks ago is still checked — a fixed seven-day window
   would quietly stop watching the very cases that have been waiting longest. */
async function reviewedSet(env, releases, opts) {
  /* Nothing released means nothing to look up — that is not a failure, and reporting it as
     one put an amber "SKD did not answer" warning on a page where SKD was never asked. */
  if (!releases.length) return { set: new Set(), live: true, stale: false, error: '' };
  let oldest = Date.now();
  for (const r of releases) { const t = Date.parse(r.at); if (isFinite(t) && t < oldest) oldest = t; }
  const from = new Date(oldest - 2 * 24 * HOUR).toISOString().slice(0, 10);
  const to = new Date(Date.now() + 24 * HOUR).toISOString().slice(0, 10);
  /* The PAGE reads the cached answer — a screen that pulled the whole closed-case window on
     every open is what made SKD's server return 524 for half an hour. The hourly SWEEP asks
     for a fresh one, because it runs once and its whole job is to notice a change. */
  let d;
  try { d = await getCompleteCases(env, from, to, opts && opts.fresh ? { fresh: true } : undefined); }
  catch (e) { return { set: new Set(), live: false, stale: false, error: String(e && e.message ? e.message : e), from, to }; }

  /* HOW WE KNOW SKD REALLY ANSWERED — and why a try/catch was not enough.
     getCompleteCases NEVER throws. When their server times out it hands back an empty list
     with the reason recorded in diag, so catching an exception would have caught nothing and
     the screen would have read "nobody has been reviewed" — every released case lighting up
     as overdue, and managers sent chasing men who had done their job. That is the oldest
     fault in this project written a new way. So we read diag and judge for ourselves. */
  const stale = !!d.stale;
  /* And one more trap inside the trap: when getCompleteCases serves the last good copy it hands
     back that copy's ORIGINAL diag — two clean 200s from the hour it worked — with this pull's
     failure tucked away under failedDiag. Reading the wrong one made a dead server look alive.
     stale is therefore decisive: if we are being given a copy, nobody answered just now. */
  const diag = stale
    ? (Array.isArray(d.failedDiag) ? d.failedDiag : [])
    : (Array.isArray(d.diag) ? d.diag : []);
  const answered = !stale && diag.some(p => p.httpStatus === 200 && !p.error);

  if (!answered && !stale) {
    const why = (diag.find(p => p.error) || {}).error || 'SKD did not answer';
    return { set: new Set(), live: false, stale: false, error: why, from, to };
  }

  const set = new Set();
  for (const c of (d.cases || [])) if (c.cmReviewed) set.add(claimKey(c.claimNo));
  /* live = they answered just now. stale = we are showing the last good copy, and the screen
     says so. A case that was unreviewed two hours ago and released thirty hours ago is still
     overdue either way, but nobody should have to guess which they are looking at. */
  return { set, live: answered, stale, ageSec: d.memoryAgeSec || 0, error: '', from, to };
}

function shape(r, reviewed, now) {
  const t = Date.parse(r.at);
  const hours = isFinite(t) ? Math.floor((now - t) / HOUR) : 0;
  const isReviewed = reviewed.set.has(r.claimKey);
  return {
    claim: r.claim,
    client: r.client || '', insured: r.insured || '',
    manager: r.manager || '', officerName: r.officerName || '',
    subProduct: r.subProduct || '', state: r.state || '',
    at: r.at, atText: fmtIST(r.at),
    by: r.byName || r.by || '',
    hours,
    reviewed: isReviewed,
    /* Overdue only means something when we actually heard from SKD. */
    overdue: (reviewed.live || reviewed.stale) && !isReviewed && hours >= TARGET_HOURS,
    waiting: (reviewed.live || reviewed.stale) && !isReviewed && hours < TARGET_HOURS
  };
}

/* ══════════ READY TO RELEASE ═════════════════════════════════════════════════════════
   Sujit, 12-Aug-2026, on being shown a paste box: "show them on Released, so I stop pasting."

   Every case the live feed says the field officer has FINISHED, that nobody has released yet,
   narrowed to what this person may see. Partially Completed is deliberately NOT here — the man
   is done, the case is not, and releasing it would start a 24-hour clock on work still running.
   Pasting still works underneath for the odd case that has already left the open feed. */
async function readyToRelease(env, me, releasedKeys) {
  let cases = [];
  let live = true;
  try { const d = await getCases(env); cases = d.cases || []; }
  catch (e) { live = false; }

  const done = cases.filter(c => isCompletedStatusW(c.status) && !releasedKeys.has(claimKey(c.claimNo)));
  const foMap = me.role === 'coordinator' ? await getFoStateMap(env).catch(() => null) : null;
  const mine = scopeCases(done, me, foMap);

  /* one row per CASE, not per officer — a claim worked by two men is still one release */
  const byClaim = new Map();
  for (const c of mine) {
    const k = claimKey(c.claimNo);
    const prev = byClaim.get(k);
    if (prev) { if (c.officerName && prev.officerName.indexOf(c.officerName) < 0) prev.officerName += ', ' + c.officerName; continue; }
    byClaim.set(k, {
      claim: c.claimNo, client: c.client || '', insured: c.insured || '',
      manager: c.manager || '', officerName: c.officerName || '',
      subProduct: c.subProduct || '', status: c.status || '', tat: c.tat || ''
    });
  }
  return { list: Array.from(byClaim.values()).sort((a, b) => a.claim.localeCompare(b.claim)), live };
}

/* ══════════ FO COMPLETED — the stage BEFORE Released ═══════════════════════════════════
   Sujit, 12-Aug-2026, looking at his own sidebar: "I asked for FO completed option. I need
   before the CM reviewed option. Is there no before that?"

   He was right and the portal was wrong. There was no FO Completed page. "Completed From
   Field" LOOKS like one and is not: it lists only cases that are completed AND already out
   of TAT, split TP/Health, inside a date window — a case an officer finished this morning,
   in time, never appears on it. The real FO Completed list existed only as the green table
   buried inside Released, where nobody would think to look for a stage.

   So this is that stage, standing on its own: every case the live feed says the field officer
   has finished, released or not, narrowed to what this person may see.

   PARTIALLY COMPLETED IS COUNTED SEPARATELY AND NEVER MIXED IN. The man is done, the case is
   not. Folding the two together is precisely the bug that made the dashboard tile read 248
   while Released — which excludes partials correctly — read 258. Two screens, two answers,
   one pipeline. Here they are two numbers, both named.                                    */
async function foCompleted(env, me) {
  /* Same permission as Completed From Field. canRelease() below already keys off 'ootat',
     so tying the page to the same section keeps one rule instead of inventing a second —
     and means nobody has to re-tick a box in Admin for a page that did not exist yesterday. */
  /* v29.0 — FO Completed is its own tick now (see the note in worker.js at the register's
     door). canRelease() still keys off 'ootat' on purpose: SEEING the list and PRESSING
     Release are different powers, and only the second one belongs to Quality Audit. */
  if (!canAccess(me, 'focompleted')) {
    return json({ ok: false, error: 'You do not have FO Completed, so this list is not open to you.' }, 403);
  }

  /* LIVENESS IS READ, NEVER INFERRED FROM THE COUNT. getCases throws when SKD is unreachable;
     it does not quietly answer with an empty list. But an empty list is also a perfectly
     ordinary answer, so the two must not be confused — reading emptiness as death is the
     mistake that once lit every case up as overdue. Down = we say down, and fall back to the
     last good copy with its age on the screen. */
  let cases = [], live = true, stale = false, staleAt = '', skdError = '';
  try {
    const d = await getCases(env);
    cases = d.cases || [];
  } catch (ex) {
    live = false;
    skdError = String(ex && ex.message ? ex.message : ex);
    /* getCases keeps the last good open-case list in the worker's memory and /api/open-cases
       serves it, dated, when the live pull fails. This page cannot reach that variable from
       here, so rather than invent a second cache it says plainly that it has nothing. A blank
       screen that explains itself beats a full screen that cannot be trusted. */
    stale = true;
  }

  const rel = await allReleases(env);
  const relBy = new Map(rel.map(r => [r.claimKey, r]));
  const foMap = me.role === 'coordinator' ? await getFoStateMap(env).catch(() => null) : null;

  /* One row per CASE, not per officer. A claim two men worked is still one case and one
     release — the same fold readyToRelease() uses, so the two screens cannot drift apart. */
  function fold(list) {
    const byClaim = new Map();
    for (const c of scopeCases(list, me, foMap)) {
      const k = claimKey(c.claimNo);
      const prev = byClaim.get(k);
      if (prev) {
        if (c.officerName && prev.officerName.indexOf(c.officerName) < 0) {
          prev.officerName += ', ' + c.officerName;
        }
        continue;
      }
      const r = relBy.get(k);
      byClaim.set(k, {
        claim: c.claimNo, client: c.client || '', insured: c.insured || '',
        manager: c.manager || '', officerName: c.officerName || '',
        subProduct: c.subProduct || '', state: c.hospitalState || c.insurerState || '',
        status: c.status || '', tat: c.tat || '',
        completedOn: c.foCompletedDate || '',
        /* no "still waiting for" column here on purpose: that per-officer breakdown is
           computed in the /api/open-cases handler, not by getCases, so reading it here would
           give a column that is blank on every row. Completed From Field carries it properly. */
        released: !!r, releasedAt: r ? (r.at || '') : '', releasedBy: r ? (r.by || '') : ''
      });
    }
    return Array.from(byClaim.values()).sort((a, b) => String(a.claim).localeCompare(String(b.claim)));
  }

  const rows    = fold(cases.filter(c => isCompletedStatusW(c.status)));
  const partial = fold(cases.filter(c => isPartCompletedW(c.status)));

  return json({
    ok: true,
    rows, partial,
    total: rows.length,
    releasedCount: rows.filter(r => r.released).length,
    toRelease: rows.filter(r => !r.released).length,
    partialCount: partial.length,
    live, stale, staleAt, skdError,
    canRelease: canRelease(me),
    generated: new Date().toISOString()
  });
}

async function listReleased(env, me) {
  if (!canAccess(me, 'released')) {
    return json({ ok: false, error: 'You do not have the Released page. Ask Admin to tick it for you.' }, 403);
  }
  const now = Date.now();
  const raw = await allReleases(env);
  const reviewed = await reviewedSet(env, raw);

  /* Narrowed by the SAME helper the case list uses. A manager sees his own released cases, a
     coordinator his own state's. One helper, per section 7 — never a second copy of the rule. */
  const pseudo = raw.map(r => ({ claimNo: r.claim, manager: r.manager, officerName: r.officerName, state: r.state }));
  const foMap = me.role === 'coordinator' ? await getFoStateMap(env).catch(() => null) : null;
  const allowed = new Set(scopeCases(pseudo, me, foMap).map(c => claimKey(c.claimNo)));
  const mine = raw.filter(r => allowed.has(r.claimKey));

  const rows = mine.map(r => shape(r, reviewed, now)).sort((a, b) => b.hours - a.hours);

  /* what is sitting in FO Completed waiting for somebody to press Release */
  const ready = canRelease(me)
    ? await readyToRelease(env, me, new Set(raw.map(r => r.claimKey)))
    : { list: [], live: true };

  return json({
    ok: true,
    rows,
    ready: ready.list,
    readyLive: ready.live,
    total: rows.length,
    overdue: rows.filter(r => r.overdue).length,
    waiting: rows.filter(r => r.waiting).length,
    reviewedCount: rows.filter(r => r.reviewed).length,
    targetHours: TARGET_HOURS,
    /* false = SKD did not answer just now. With skdStale true we are showing the last good
       copy and the screen says how old it is; with both false nothing is marked overdue. */
    skdLive: reviewed.live,
    skdStale: !!reviewed.stale,
    skdAgeSec: reviewed.ageSec || 0,
    skdError: reviewed.error,
    canRelease: canRelease(me),
    canUndo: canUndo(me),
    generated: new Date().toISOString()
  });
}

/* ══════════ THE HOURLY SWEEP ═════════════════════════════════════════════════════════
   Cloudflare calls this on the cron in wrangler.toml. It exists so the 24 hours is noticed
   even when nobody has the page open — which is the whole point of "automatically".

   It writes down what it found and it does not act. There is no mail unless YOU set the
   variable RELEASE_ALERT_TO to your own address; with it unset this sweep is silent, because
   a system that starts mailing people on its own is not something to switch on by surprise. */
export async function releaseSweep(env) {
  if (!env.USERS) return { ok: false, error: 'no KV' };
  const now = Date.now();
  const raw = await allReleases(env);
  const reviewed = await reviewedSet(env, raw, { fresh: true });

  if (!reviewed.live && !reviewed.stale) {
    /* Keep the previous finding rather than overwriting it with a blank one. */
    await stSoft(env, 'release:sweep', JSON.stringify({
      at: new Date().toISOString(), skdLive: false,
      note: 'SKD did not answer this hour, so nothing was re-counted.'
    }));
    return { ok: true, skdLive: false };
  }

  const rows = raw.map(r => shape(r, reviewed, now));
  const overdue = rows.filter(r => r.overdue);
  const summary = {
    at: new Date().toISOString(),
    /* the truth about where this hour's answer came from, not a hopeful true */
    skdLive: reviewed.live,
    skdStale: !!reviewed.stale,
    note: reviewed.live ? ''
      : 'SKD did not answer this hour — worked from the last good copy, about ' +
        Math.max(1, Math.round((reviewed.ageSec || 0) / 60)) + ' minutes old.',
    total: rows.length, overdue: overdue.length,
    waiting: rows.filter(r => r.waiting).length,
    reviewed: rows.filter(r => r.reviewed).length,
    worst: overdue.slice().sort((a, b) => b.hours - a.hours).slice(0, 20)
      .map(r => ({ claim: r.claim, hours: r.hours, manager: r.manager, officerName: r.officerName }))
  };
  await stSoft(env, 'release:sweep', JSON.stringify(summary));

  /* Mail only on a fresh answer. Chasing a manager over a case that SKD may have reviewed
     while their server was unreachable is exactly the phone call nobody should have to make. */
  const to = String(env.RELEASE_ALERT_TO || '').trim();
  if (to && overdue.length && reviewed.live) await sendOverdueMail(env, to, summary);
  return { ok: true, ...summary };
}

/* Plain words, one line per case, because it is read on a phone. */
function overdueMailText(s) {
  const lines = s.worst.map(r =>
    '  ' + r.claim + '  —  ' + r.hours + ' hours' + (r.manager ? '  ·  ' + r.manager : ''));
  return 'Released and still not CM Reviewed after ' + TARGET_HOURS + ' hours.\n\n' +
    s.overdue + ' case' + (s.overdue === 1 ? '' : 's') + ' out of ' + s.total + ' released.\n\n' +
    lines.join('\n') +
    (s.overdue > s.worst.length ? '\n  … and ' + (s.overdue - s.worst.length) + ' more' : '') +
    '\n\nOpen the Released page in the portal for the full list and the Excel.\n\n' +
    'TaaSen Claims Portal';
}

async function sendOverdueMail(env, to, summary) {
  const subject = 'Released — ' + summary.overdue + ' case' + (summary.overdue === 1 ? '' : 's') + ' past ' + TARGET_HOURS + ' hours';
  const text = overdueMailText(summary);
  try {
    /* v34.9 — no-reply first (Sujit, 29-Sep: "stop sending from my mail") */
    if (env.RESEND_API_KEY) {
      const { resendSend, mailDomain } = await import('./mail-index.js');
      const r0 = await resendSend(env, { from: 'TaaSen Claims Portal <no-reply@' + mailDomain(env) + '>', to: [to], subject, text });
      if (r0 && r0.ok) return true;
    }
    if (env.OTP_MAIL_URL) {
      await fetch(env.OTP_MAIL_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: env.OTP_MAIL_KEY || '', to, subject, text })
      });
      return true;
    }
    if (env.BREVO_API_KEY) {
      await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          sender: { email: env.OTP_MAIL_FROM || 'no-reply@skdhealth.net', name: 'TaaSen Claims Portal' },
          to: [{ email: to }], subject, textContent: text
        })
      });
      return true;
    }
  } catch (e) { /* a failed alert must never break the sweep */ }
  return false;
}

function fmtIST(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '';
  try {
    return d.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: true
    });
  } catch (e) { return iso; }
}
