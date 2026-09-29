/*******************************************************************************************
 *  THE TWICE-DAILY POSITION MAIL  —  5:30 AM and 5:30 PM, India time
 *  ----------------------------------------------------------------------------------------
 *  Sujit, 17-Aug-2026, holding the mail he types to his team twice a day: "I want to send
 *  like this mail automatically at morning 5:30 and one more time at evening at 5:30. This
 *  need to be done automatically, make this accordingly. I need more colourful."
 *  And, an hour later: "This district to be added. This is the manager complete means
 *  manage — I need to put the reports for manager. This is FO Completed, 1 TP and one is
 *  Health. Don't take the GPS and SKD table, I don't want."
 *
 *  So the mail carries, in this order:
 *    1. four coloured cards — total open, Motor TP, Health, out with the field
 *    2. TP / Health / Total
 *    3. Health and TP open cases in four buckets, with a Total column
 *    4. CAT Pending closure — Health, by STATE and by DISTRICT under it
 *    5. FO Completed by ageing, MANAGER-wise — Motor TP  (30/45/55/75/100 + the 45+ totals)
 *    6. FO Completed by ageing, MANAGER-wise — Health    (3/5/7/9/10th day)
 *  There is deliberately NO SKD vs GPS table: he asked for it to be left out.
 *
 *  WHAT THE FOUR BUCKETS ARE. Asked and confirmed by him, 17-Aug-2026:
 *       CAT Pending      Assigned + FO Accepted             — out with the field
 *       Managers pending FO Completed + Partially Completed — the field is done, we are not
 *       Rejected         FO Rejected
 *       Pending          not yet allotted
 *  His own numbers prove they partition the book: Health 546+213+5+29 = 793, TP
 *  691+132+11+15 = 849. And his manager table totals 132 — the same 132 as TP "Managers
 *  pending", which is what tables 5 and 6 break down. Anything this portal cannot place
 *  lands in a fifth row that appears ONLY when it is not empty: a bucket that quietly
 *  swallowed an unknown status would make the columns add up while being wrong, and that is
 *  the one failure a report must not have.
 *
 *  NOTHING IS SENT UNLESS HE SWITCHES IT ON. Set the Worker variable DAILY_MAIL_TO to the
 *  addresses (comma separated) and the two mails start; leave it unset and this module still
 *  computes everything and still draws it on /api/daily/preview, and posts to nobody. Same
 *  rule as the release alert: a system that starts mailing people on its own is not
 *  something to switch on by surprise.
 *
 *  Routes (named in entry.js)
 *    GET  /api/daily/preview   the exact mail, in the browser        [admin / boss]
 *    GET  /api/daily/json      the figures behind it                 [admin / boss]
 *    POST /api/daily/test      send ONE copy, to yourself only       [admin]
 *
 *  Variables
 *    DAILY_MAIL_TO   comma-separated recipients. UNSET = never sends.
 *    DAILY_MAIL_CC   optional, same shape.
 *******************************************************************************************/

import {
  currentUser, getCases, getFoRoster, typeOfSub, normName, firstFO, canonState,
  tatDaysNum, tatDH, isCompletedStatusW, isPartCompletedW, getCompleteCases, probeStatusList, probeStatusListPaged
} from './worker.js';
/* cm-keep is a leaf module (it imports nothing of ours), so this closes no cycle */
import { keepCaughtSince } from './cm-keep-index.js';
import { resendSend as nrSend, mailDomain as nrDomain } from './mail-index.js';   /* v34.9 — no-reply sender */

/* ══════════ TIME — INDIA, ALWAYS ══════════════════════════════════════════════════════
   5:30 am IST is 00:00 UTC and 5:30 pm IST is 12:00 UTC, exactly, all year: India does not
   move its clocks. So the hourly cron already in wrangler.toml lands on both slots on the
   hour and no new trigger is needed — the sweep simply asks which hour it is in India. */
function istParts(d) {
  const f = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  });
  const p = {};
  for (const part of f.formatToParts(d)) if (part.type !== 'literal') p[part.type] = part.value;
  return p;
}
function istDayKey(d) { const p = istParts(d); return p.year + '-' + p.month + '-' + p.day; }
function istHour(d) { return parseInt(istParts(d).hour, 10); }
function istPretty(d) {
  try {
    return new Date(d).toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata', weekday: 'short', day: '2-digit', month: 'short',
      year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true
    });
  } catch (e) { return new Date(d).toISOString(); }
}
/* Which of the two mails is due, if either. The whole hour counts on purpose: Cloudflare
   fires a cron "about" on time and a run that slipped to 5:47 must still go out — the KV
   guard in dailySweep is what stops a late run becoming a second run. */
export function slotFor(d) {
  const h = istHour(d);
  /* The 5 o'clock hour in India is only 23:30-00:29 UTC, so an hour-exact test would miss the
     slot entirely if Cloudflare's cron slipped past half past. The hour AFTER each slot counts
     too — which also buys a free retry: if the 5:30 run found SKD down and sent nothing, the
     6:30 run tries again, and the once-per-slot guard in dailySweep stops a second copy ever
     going out once one has. */
  if (h === 5 || h === 6) return 'morning';
  if (h === 17 || h === 18) return 'evening';
  return '';
}

/* ══════════ THE FOUR BUCKETS ═════════════════════════════════════════════════════════ */
const BUCKETS = [
  { key: 'cat',      label: 'CAT Pending',      colour: '#0d8f8f', note: 'Assigned + FO Accepted — out with the field' },
  { key: 'mgr',      label: 'Managers pending', colour: '#B26A00', note: 'FO Completed + Partially Completed — waiting on us' },
  { key: 'rejected', label: 'Rejected',         colour: '#C62828', note: 'FO Rejected' },
  { key: 'pending',  label: 'Pending',          colour: '#1F3C6E', note: 'not yet allotted' }
];
function bucketOf(status) {
  const s = String(status == null ? '' : status).toLowerCase();
  if (s.indexOf('reject') !== -1) return 'rejected';
  /* Partially Completed contains the word "complete", so both helpers are asked BEFORE any
     substring test — the same trap that made the dashboard's FO Completed tile read 248. */
  if (isPartCompletedW(status) || isCompletedStatusW(status)) return 'mgr';
  if (s.indexOf('assign') !== -1 || s.indexOf('accept') !== -1) return 'cat';
  if (s.indexOf('pending') !== -1) return 'pending';
  return 'other';   // named, never absorbed
}

/* ══════════ THE AGEING SCALES ════════════════════════════════════════════════════════
   The same two scales the Analytics screen uses, so the mail and the screen can never give
   two answers about one manager. Motor TP is his 30/45/55/75/100 scale of 14-Aug with the
   running totals beside it; Health is the 3/5/7/9/10th-day scale. If either changes on the
   screen it must change here — they are written down twice because a Worker module cannot
   import from a static HTML page, and that duplication is pinned by the wdaily suite. */
const TP_BANDS = [
  { label: 'Up to 30', min: 0, max: 30 }, { label: '31 - 45', min: 31, max: 45 },
  { label: '46 - 55', min: 46, max: 55 }, { label: '56 - 75', min: 56, max: 75 },
  { label: '76 - 100', min: 76, max: 100 }, { label: '100+', min: 101, max: Infinity }
];
const TP_PLUS = [{ label: '45+', from: 2 }, { label: '55+', from: 3 }, { label: '75+', from: 4 }, { label: '100+', from: 5 }];
const HEALTH_BANDS = [
  { label: 'Up to 3', min: 0, max: 3 }, { label: '4 - 5', min: 4, max: 5 },
  { label: '6 - 7', min: 6, max: 7 }, { label: '8 - 9', min: 8, max: 9 },
  { label: '10th day & above', min: 10, max: Infinity }
];
function bandIndex(days, bands) {
  for (let i = 0; i < bands.length; i++) if (days >= bands[i].min && days <= bands[i].max) return i;
  return bands.length - 1;
}
function plusCount(arr, from) { let n = 0; for (let i = from; i < arr.length; i++) n += (arr[i] || 0); return n; }

/* ══════════ STATE AND DISTRICT ═══════════════════════════════════════════════════════
   His table reads AP · KA · KL · MH · TN · TG — Andhra and Telangana SEPARATE. Everywhere
   else in this portal those two are deliberately one row (canonState merges them, because
   one coordinator runs both), so this report must NOT go through canonState or Telangana's
   cases would vanish into Andhra's line. The roster's raw spelling is read instead, and the
   district ("region" on the SKD record — Thanjavur, Hyderabad, Bengaluru) comes with it,
   because on 17-Aug he asked for the district under each state. */
const STATE_CODES = [
  { code: 'AP', test: /^(andh?ra|andra)/i },
  { code: 'TG', test: /^(telan|telun|tg$)/i },
  { code: 'KA', test: /^karn/i },
  { code: 'TN', test: /^tamil/i },
  { code: 'KL', test: /^kerala/i },
  { code: 'MH', test: /^mahar/i }
];
function stateCode(raw) {
  const s = String(raw == null ? '' : raw).replace(/\s+/g, ' ').trim();
  if (!s) return '';
  for (const c of STATE_CODES) if (c.test.test(s)) return c.code;
  return s.slice(0, 12);   // an unexpected state is shown as itself, never dropped
}
/* officer name -> { state, district }, from the live roster (getFoRoster falls back to the
   baked directory when SKD is unreachable, so a blip does not empty the table) */
async function foPlaceMap(env) {
  const map = {};
  try {
    for (const o of await getFoRoster(env)) {
      const k = normName(o.name);
      if (k && !map[k]) map[k] = { state: o.state || '', district: o.region || '' };
    }
  } catch (e) { /* no roster = no state split; the table says so rather than guessing */ }
  return map;
}

/* ══════════ THE FIGURES ═══════════════════════════════════════════════════════════════ */
/* ══ WHO RELEASED WHAT TO CM REVIEWED, IN THIS SHIFT ═════════════════════════════════════
   Sujit, 18-Aug-2026: "Which all went for CM Reviewed, that cases with manager names — how
   you are giving the FO Completed, like that. Health is different, for TP different. How many
   case example they have been released — one is five days, one is eight days, like that give
   me the table. Also this I need in morning and at evening: which all cases they released
   from morning 9 o'clock to 5:30."

   Two windows, because the two mails answer different questions:
     · the 5:30 AM mail  — everything released since yesterday evening's mail (17:30 IST)
     · the 5:30 PM mail  — everything released during today's working day (from 09:00 IST)

   THE DATE HAS TO CARRY A TIME FOR ANY OF THAT TO BE TRUE. SKD's Manager Completed Date
   sometimes arrives as a bare DD/MM/YYYY, and a window of hours cannot be cut out of a value
   that only knows days. So the parse records whether a time was there, and when none of the
   cases carry one the mail SAYS the window is the whole day rather than quietly presenting a
   day's work as a shift's. A table that cannot say which hours it covers is not a shift
   report, it is a guess with a heading. */
function parseSkdDate(str) {
  const s = String(str == null ? '' : str).trim();
  if (!s) return null;
  /* the same read as the Journey screen, AM/PM and all. "04:00 PM" taken as four in the
     MORNING turns a six-hour handover into a negative one, which draws as "never happened". */
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::\d{2})?(?:\s*([AaPp])\.?[Mm]\.?)?)?/);
  if (m) {
    let hh = +(m[4] || 0); const mer = m[6] ? m[6].toLowerCase() : '';
    if (mer === 'p' && hh < 12) hh += 12;
    else if (mer === 'a' && hh === 12) hh = 0;
    /* SKD's clock is India's. Built as IST wall time, then shifted to epoch, because this
       worker runs in UTC and a naive Date would land five and a half hours out. */
    const ms = Date.UTC(+m[3], +m[2] - 1, +m[1], hh, +(m[5] || 0)) - 19800000;
    return { ms, hasTime: m[4] !== undefined };
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : { ms: d.getTime(), hasTime: /\d:\d/.test(s) };
}
/* the shift this mail covers, in epoch ms */
function releaseWindow(at, slot) {
  const p = istParts(at);
  const istMidnight = Date.UTC(+p.year, +p.month - 1, +p.day) - 19800000;
  if (slot === 'evening') {
    return { from: istMidnight + 9 * 3600000, to: at.getTime(),
      label: 'today 9:00 am to now', short: '9:00 am → now', wholeDay: false };
  }
  /* THE MORNING MAIL IS YESTERDAY'S WHOLE DATE — 12:00 am to 11:59 pm.
     Sujit, 18-Aug: "Morning 5:30 mail, yesterday's 24 hours. How many cases they have been
     released that date — from 00 hours till 23.59 minutes."
     It used to run yesterday 5:30 pm → now, which was a SHIFT. He wants a DATE. A date is the
     better unit here and not only because he asked: it is the one a manager can check against
     his own sheet, it does not move depending on what time the mail happened to go out, and
     it makes the untimed dates SKD sends land exactly where they belong instead of needing to
     be nudged into a window with fuzzy edges. The cost is that a case released this morning
     between midnight and 5:30 waits for tomorrow's mail — which is right, because it belongs
     to today's date and today is not over. */
  const from = istMidnight - 24 * 3600000;
  const p2 = istParts(new Date(from));
  const dateTxt = p2.day + '/' + p2.month + '/' + p2.year;
  return { from, to: istMidnight - 1,
    label: 'the whole of ' + dateTxt + ', 12:00 am to 11:59 pm',
    short: dateTxt + ' · full day', wholeDay: true, dateTxt };
}
/* HAS THIS CASE REACHED CM REVIEWED?
   Three ways of asking, because the row can arrive by three roads and each carries the fact
   differently: the live feed unions the buckets and leaves statusBuckets behind it; the carried
   archive sets cmReviewed on every line, since that is all it holds; and a plain status column
   is the fallback for a feed shape carrying neither.
   cmReviewed is tested for a real VALUE rather than for truthiness alone — worker.js writes
   "Yes" today but leaves room for a real date to be written there later, and "No" must never
   be read as yes simply because it is a non-empty string. */
function isCmReviewedCase(c) {
  if (!c) return false;
  if (Array.isArray(c.statusBuckets) && c.statusBuckets.indexOf('CM Reviewed') > -1) return true;
  const v = String(c.cmReviewed == null ? '' : c.cmReviewed).trim();
  if (v && !/^(no|n|0|false|-)$/i.test(v)) return true;
  const st = String(c.status == null ? '' : c.status).toLowerCase().replace(/[^a-z]/g, '');
  return st.indexOf('cmreview') > -1;
}

/* Manager-wise CM-Reviewed releases inside the window, TP and Health apart.
   Days are the case's own TAT, so a row reads "5 · 8 · 12" exactly as he asked. */
async function buildReleases(env, at, slot) {
  const win = releaseWindow(at, slot);
  const out = { ok: false, why: '', win, timed: 0, untimed: 0, undated: 0, qcInWin: 0, TP: {}, Health: {}, total: 0,
    /* CASHLESS, IN HOURS. 19-Aug: "for product, only for cashless, I need hourly basis
       completed." He is right that days are the wrong ruler there: his own mail showed a
       Health table of 0d chips and 0.1d averages — a cashless case closes in hours, so read
       in days every case looks identical and the fast ones are invisible. These cases stay
       in the Health table (its total must keep meaning ALL of Health) and are ALSO collected
       here with their TAT read as hours, D×24+H. */
    Cash: {}, cashTotal: 0 };
  let cases = [];
  try {
    /* two days is enough for any shift and keeps the call small; the window below is what
       actually decides, not this range */
    const fmt = ms => { const d = new Date(ms + 19800000).toISOString(); return d.slice(0, 10); };
    /* FRESH, deliberately. Everywhere else a five-minute copy of this window is a kindness to
       SKD's server. Here it is not: this mail goes out twice a day and is the thing people act
       on, and a copy taken four minutes ago would silently drop the releases made in those four
       minutes — which, at 5:30 pm, are exactly the ones the evening mail exists to report. Two
       extra pulls a day is the whole price. */
    const d = await getCompleteCases(env, fmt(win.from - 26 * 3600000), fmt(at.getTime()), { fresh: true });
    cases = (d && d.cases) || [];
  } catch (e) { out.why = 'the closed-case feed could not be read — ' + String((e && e.message) || e); return out; }
  const nameIndex = { TP: {}, Health: {} };   // normalised name -> the spelling actually printed
  for (const c of cases) {
    /* CM REVIEWED ONLY. Sujit, 18-Aug: "the case released the number is little wrong."
       He was right, and this is most of it. getCompleteCases unions TWO buckets — cm-reviewed
       and qc-reviewed — into one row per claim, and this loop never asked which. So a case
       that had only ever reached QC Reviewed was being counted in a table headed "Released to
       CM Reviewed", and the figure read high. The heading names the stage; the arithmetic has
       to mean the same stage, or the number is answering a question nobody asked. */
    const isCm = isCmReviewedCase(c);
    const when = parseSkdDate(c.managerCompletedDate);
    /* A CM-REVIEWED CASE WITH NO DATE AT ALL cannot be placed in any day — but it must not be
       dropped in silence either. It is counted here and NAMED under the table, because a table
       that quietly leaves cases out reads as a complete answer and is not one. */
    if (!when) { out.undated++; continue; }
    if (when.hasTime) out.timed++; else out.untimed++;
    /* A date with no time is credited to its day, never dropped — dropping it would make a
       manager who really did release look idle.
       On a WHOLE-DAY window no allowance is needed at all: an untimed date parses to its own
       midnight, which is inside its own day and outside every other, so it answers exactly.
       That is a quiet second reason the morning mail is now a date rather than a shift.
       The evening window is hours, so an untimed date there is still admitted by its day and
       the mail says so rather than presenting a whole-day figure as an hourly one. */
    const inWin = (when.hasTime || win.wholeDay)
      ? (when.ms >= win.from && when.ms <= win.to)
      : (when.ms >= win.from - 12 * 3600000 && when.ms <= win.to);
    if (!inWin) continue;
    /* QC Reviewed only, inside this very window — counted so the table can NAME how many it
       excluded, instead of a static footnote that gives no number to check */
    /* QC REVIEWED COUNTS TOO — Sujit, 19-Aug: "if any QC reviewed, also calculate in this
       completed list." On the 18th I fenced QC out of this table, reasoning that a table
       headed CM Reviewed must count CM Reviewed — but that was MY reading of the heading, not
       his business rule. His office counts a case CLOSED the moment it reaches EITHER review
       stage, and his sheet is the yardstick this table is checked against, so the table must
       speak his language. Both stages count now; the split is still counted and PRINTED,
       because a merged number whose parts cannot be checked is how the next "why is it
       different" starts. */
    if (!isCm) out.qcInWin++;
    const side = typeOfSub(c.subProduct) === 'TP' ? 'TP' : 'Health';
    const box = out[side];
    /* ONE MANAGER, ONE ROW. SKD's own sheet carries "MONIKA B" and "Monika B", "Reshma unni"
       and "RESHMA UNNI" — the same person, typed by different people on different days. Keyed
       on the raw string, one manager becomes two rows each holding half his work, and nothing
       on the page distinguishes that from two managers who each did half as much. So the rows
       are grouped with case and spacing ignored, and kept under the FIRST spelling seen.
       Nothing is guessed: only case and whitespace are ignored, so two genuinely different
       names can never be joined. */
    const raw = String(c.manager || '').replace(/\s+/g, ' ').trim();
    const norm = raw ? raw.toLowerCase() : '(no manager named)';
    const disp = nameIndex[side][norm] || (nameIndex[side][norm] = raw || '(no manager named)');
    const r = box[disp] || (box[disp] = { name: disp, cases: 0, days: [], noDays: 0 });
    r.cases++;
    /* tatDaysNum answers 0 for a TAT it cannot read, which on this table would print a green
       "0d" chip — a case with no TAT would read as released the same day, and pull the manager's
       average down towards zero with it. So an unreadable TAT is kept apart and shown as "?"
       rather than being quietly turned into the best possible number. */
    if (/\d/.test(String(c.tat == null ? '' : c.tat))) r.days.push(tatDaysNum(c.tat));
    else r.noDays++;
    out.total++;
    /* the cashless copy, in hours — same case, same manager, finer clock */
    if (side === 'Health' && /cashless/i.test(String(c.subProduct || ''))) {
      const cr = out.Cash[disp] || (out.Cash[disp] = { name: disp, cases: 0, hours: [], noHours: 0 });
      cr.cases++;
      if (/\d/.test(String(c.tat == null ? '' : c.tat))) {
        const dh = tatDH(c.tat);
        cr.hours.push((parseInt(dh[0], 10) || 0) * 24 + (parseInt(dh[1], 10) || 0));
      } else cr.noHours++;
      out.cashTotal++;
    }
  }
  out.ok = true;
  return out;
}

export async function buildDaily(env, slot, now) {
  /* THE CLOCK IS AN ARGUMENT. On 19-Aug the whole wdaily release section went red overnight
     with not one line changed — its fixtures said 17/08 and "yesterday" had quietly become
     18/08, because this function read the real clock and the suite could not pin it. A test
     that fails by calendar is a test people learn to re-run until it is green, which is the
     end of it meaning anything. The cron and every live caller pass nothing and get the real
     clock; the suite passes the moment its fixtures were written for, for ever. */
  const at = now || new Date();
  let cases = [], live = true, skdError = '';
  try { const d = await getCases(env); cases = d.cases || []; }
  catch (e) { live = false; skdError = String(e && e.message ? e.message : e); }

  const place = await foPlaceMap(env);
  const blank = () => ({ cat: 0, mgr: 0, rejected: 0, pending: 0, other: 0, total: 0 });

  const fig = {
    at: at.toISOString(), atText: istPretty(at), dayKey: istDayKey(at),
    live, skdError,
    total: 0,
    byType: { TP: blank(), Health: blank() },
    catByState: {},           // code -> { total, aged, districts: { name -> {total, aged} } }
    stateUnknown: 0,
    /* the two manager reports: FO-Completed-and-partial cases per manager, aged */
    mgrTP: {}, mgrHealth: {}
  };

  for (const c of cases) {
    const t = typeOfSub(c.subProduct) === 'TP' ? 'TP' : 'Health';
    const b = bucketOf(c.status);
    const box = fig.byType[t];
    box[b]++; box.total++; fig.total++;

    const nm = c.officerName || '';
    const p = place[normName(nm)] || place[normName(firstFO(nm))] || null;
    const days = tatDaysNum(c.tat);

    /* CAT PENDING CLOSURE — Health only. His own totals prove it: 546 is the Health
       CAT-Pending figure exactly, and it is the Health book that is chased on a 4-day clock. */
    if (t === 'Health' && b === 'cat') {
      const code = p ? stateCode(p.state) : '';
      if (!code) fig.stateUnknown++;
      else {
        if (!fig.catByState[code]) fig.catByState[code] = { total: 0, aged: 0, districts: {} };
        const st = fig.catByState[code];
        st.total++; if (days >= 4) st.aged++;
        const dn = String((p && p.district) || '').trim() || '(district not on the officer record)';
        if (!st.districts[dn]) st.districts[dn] = { total: 0, aged: 0 };
        st.districts[dn].total++; if (days >= 4) st.districts[dn].aged++;
      }
    }

    /* THE MANAGER REPORTS. His words: "this is the manager complete means manage — I need to
       put the reports for manager, this is FO Completed, 1 TP and one is Health." That is the
       Managers-pending bucket broken down by the manager it is waiting on. */
    if (b === 'mgr') {
      const bands = t === 'TP' ? TP_BANDS : HEALTH_BANDS;
      const store = t === 'TP' ? fig.mgrTP : fig.mgrHealth;
      const key = String(c.manager || '').trim() || '(no manager named)';
      if (!store[key]) store[key] = { name: key, total: 0, bands: new Array(bands.length).fill(0) };
      const row = store[key];
      row.total++; row.bands[bandIndex(days, bands)]++;
    }
  }
  /* biggest first — the manager with the most waiting is the first conversation of the day */
  const sortRows = o => Object.keys(o).map(k => o[k]).sort((a, b) => (b.total - a.total) || a.name.localeCompare(b.name));
  /* the date the subject line carries, in India's reading */
  { const p2 = istParts(at);
    const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    fig.dateText = p2.day + ' ' + MON[+p2.month - 1] + ' ' + p2.year; }

  /* WHO RELEASED WHAT THIS SHIFT. Asked for separately from everything above because it is
     the one table built from the CLOSED feed rather than the open one — and if that feed is
     unreachable the mail says so in place of the table rather than printing an empty one. */
  try {
    fig.rel = await buildReleases(env, at, slot === 'evening' ? 'evening' : 'morning');
    if (fig.rel.ok) {
      /* The warning belongs to the EVENING mail alone. Its window is hours, so a date with no
         clock time cannot be placed inside it exactly and the mail has to say so. The morning
         mail asks about a whole date, which an untimed date answers perfectly well — printing
         a caveat there would be warning about a problem that is not present. */
      fig.rel.note = fig.rel.win && fig.rel.win.wholeDay ? ''
        : (fig.rel.timed === 0 && fig.rel.untimed > 0
            ? 'SKD sent no clock time on these, so the window is the whole day rather than the hours named.'
            : (fig.rel.untimed ? fig.rel.untimed + ' of these carried a date but no time, so they are counted to their day.' : ''));
      /* Cases that ARE CM Reviewed but carry no completion date at all cannot be placed in any
         day. They are named rather than dropped: a table that quietly leaves cases out reads as
         a complete answer, and the man reading it has no way to know it is not one. */
      fig.rel.undatedNote = fig.rel.undated
        ? fig.rel.undated + ' closed ' + (fig.rel.undated === 1 ? 'case carries' : 'cases carry') +
          ' no completion date from SKD at all, so ' + (fig.rel.undated === 1 ? 'it' : 'they') +
          ' cannot be placed in any day and ' + (fig.rel.undated === 1 ? 'is' : 'are') + ' not in this table.'
        : '';
      fig.rel.late = await buildLateArrivals(env, at, slot === 'evening' ? 'evening' : 'morning');
    }
  } catch (e) { fig.rel = { ok: false, why: String((e && e.message) || e) }; }

  fig.mgrTPRows = sortRows(fig.mgrTP);
  fig.mgrHealthRows = sortRows(fig.mgrHealth);
  delete fig.mgrTP; delete fig.mgrHealth;
  return fig;
}

/* ══════════ THE MAIL ═════════════════════════════════════════════════════════════════
   "I need more colourful." Built as inline-styled tables and nothing else: Gmail strips a
   <style> block, Outlook ignores flexbox and background-images, and a mail that arrives as
   naked text is worse than the one he types by hand. Every colour is written on the element
   that uses it, and every gradient carries a flat colour behind it for Outlook.           */
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function n(x) { return Number(x || 0).toLocaleString('en-IN'); }
function pct(a, b) { return b ? Math.round((a / b) * 100) : 0; }

const FONT = "font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
/* the manager rows are banded by how much each is holding — the same five-step heat the
   Analytics tables use, so the man at the top of the mail is the man at the top of the screen */
const HEAT = ['#1F3C6E', '#38761D', '#E1B12C', '#E08A1E', '#C0392B'];
function heatFor(i, len) {
  if (len <= 1) return HEAT[0];
  return HEAT[Math.min(HEAT.length - 1, Math.floor((i / len) * HEAT.length))];
}

function card(label, value, colour, sub) {
  return '<td width="25%" style="padding:5px" valign="top">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-radius:12px;background:' + colour + ';">' +
    '<tr><td style="padding:14px 10px;text-align:center;' + FONT + '">' +
    '<div style="font-size:26px;font-weight:800;color:#ffffff;line-height:1.1">' + n(value) + '</div>' +
    '<div style="font-size:10.5px;font-weight:700;color:#ffffff;opacity:.92;letter-spacing:.6px;text-transform:uppercase;margin-top:5px">' + esc(label) + '</div>' +
    (sub ? '<div style="font-size:10px;color:#ffffff;opacity:.78;margin-top:3px">' + esc(sub) + '</div>' : '') +
    '</td></tr></table></td>';
}
function th(text, bg, align) {
  return '<th style="' + FONT + ';font-size:11px;font-weight:700;color:#ffffff;background:' + (bg || '#1F3C6E') +
    ';padding:8px 8px;text-align:' + (align || 'left') + ';border:1px solid rgba(255,255,255,.22);white-space:nowrap">' + esc(text) + '</th>';
}
function td(text, o) {
  o = o || {};
  return '<td style="' + FONT + ';font-size:12px;padding:7px 8px;border:1px solid #D7E2EF;' +
    'color:' + (o.colour || '#0B2540') + ';background:' + (o.bg || '#ffffff') + ';' +
    'font-weight:' + (o.bold ? '700' : '500') + ';text-align:' + (o.align || 'left') + ';white-space:nowrap">' + text + '</td>';
}
/* a percentage that colours itself — green under 25, amber to 40, red above */
function pctCell(p) {
  const bg = p >= 40 ? '#FDECEA' : p >= 25 ? '#FFF6E6' : '#EAF6EE';
  const fg = p >= 40 ? '#A3271B' : p >= 25 ? '#B26A00' : '#1E7A3D';
  return td(p + '%', { bg, colour: fg, bold: true, align: 'center' });
}
/* a count cell: a zero is a faint dot, so the eye lands on the numbers that exist */
function numCell(v, o) {
  o = o || {};
  if (!v) return td('<span style="color:#C4D2E3">·</span>', { align: 'center', bg: o.bg });
  return td(n(v), { align: 'center', bold: true, colour: o.colour || '#0074D9', bg: o.bg });
}
function sectionTitle(text, colour) {
  return '<tr><td style="padding:22px 0 8px;' + FONT + ';font-size:14px;font-weight:800;color:#0B2540">' +
    '<span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:' + colour + ';margin-right:8px"></span>' +
    esc(text) + '</td></tr>';
}

function bucketTable(title, box, colour) {
  let rows = '';
  for (const b of BUCKETS) {
    const v = box[b.key];
    const hot = b.key === 'rejected' && v;
    rows += '<tr>' + td(esc(b.label)) +
      td(n(v), { align: 'right', bold: true, colour: hot ? '#ffffff' : '#0B2540', bg: hot ? '#C62828' : '#ffffff' }) + '</tr>';
  }
  if (box.other) rows += '<tr>' + td('Other status') + td(n(box.other), { align: 'right', bold: true, bg: '#FFF6E6', colour: '#B26A00' }) + '</tr>';
  rows += '<tr>' + td('Total', { bold: true, bg: '#F3F7FC' }) + td(n(box.total), { align: 'right', bold: true, bg: '#F3F7FC' }) + '</tr>';
  return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">' +
    '<tr>' + th(title, colour) + th('', colour) + '</tr>' + rows + '</table>';
}

/* ---- the manager report, one product ---- */
function managerTable(rows, bands, plus, headColour) {
  const nb = bands.length;
  let h = '<tr>' + th('Manager', headColour) + th('Total', headColour, 'center');
  for (const b of bands) h += th(b.label, headColour, 'center');
  for (const p of plus) h += th(p.label, '#B26A00', 'center');
  h += '</tr>';

  let body = '';
  const grand = { total: 0, bands: new Array(nb).fill(0) };
  rows.forEach((r, i) => {
    grand.total += r.total;
    for (let k = 0; k < nb; k++) grand.bands[k] += r.bands[k];
    const colour = heatFor(i, rows.length);
    let line = '<td style="' + FONT + ';font-size:12px;padding:7px 9px;border:1px solid rgba(255,255,255,.25);' +
      'background:' + colour + ';color:#ffffff;font-weight:700;white-space:nowrap">' + esc(r.name) + '</td>' +
      td(n(r.total), { align: 'center', bold: true, bg: '#F3F7FC' });
    for (let k = 0; k < nb; k++) line += numCell(r.bands[k], { colour: k === nb - 1 ? '#C62828' : '#0074D9' });
    for (const p of plus) line += numCell(plusCount(r.bands, p.from), { colour: '#B26A00', bg: '#FFF8EC' });
    body += '<tr>' + line + '</tr>';
  });

  let foot = '<tr>' + td('<b>GRAND TOTAL</b>', { bg: '#E8EFF8' }) + td(n(grand.total), { align: 'center', bold: true, bg: '#E8EFF8' });
  for (let k = 0; k < nb; k++) foot += td(n(grand.bands[k]), { align: 'center', bold: true, bg: '#E8EFF8' });
  for (const p of plus) foot += td(n(plusCount(grand.bands, p.from)), { align: 'center', bold: true, bg: '#FFF3E0', colour: '#B26A00' });
  foot += '</tr>';

  return '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' +
    h + body + foot + '</table>';
}

/* THE RELEASE TABLE — one row per manager, the days of each case spelt out.
   "One is five days start, and one is eight days, like that give me the table." So the days
   are printed individually rather than averaged away: an average hides the 30-day case that
   is the reason anybody is reading this. Longest first, so the worst is the first thing seen. */
function releaseTable(box, colour, timedNote) {
  const names = Object.keys(box).sort((a, b) => box[b].cases - box[a].cases || a.localeCompare(b));
  if (!names.length) {
    return '<table width="100%" cellpadding="0" cellspacing="0" style="' + FONT + ';font-size:12.5px;color:#6E8095;' +
      'background:#F7FAFD;border:1px solid #E2EAF4;border-radius:10px"><tr><td style="padding:14px 16px">' +
      'Nothing released in this window.</td></tr></table>';
  }
  let rows = '', tCases = 0, tDays = 0, tN = 0, tNo = 0;
  for (const n of names) {
    const r = box[n];
    const days = r.days.slice().sort((a, b) => b - a);
    tCases += r.cases; tNo += (r.noDays || 0); days.forEach(d => { tDays += d; tN++; });
    const avg = days.length ? Math.round((days.reduce((a, b) => a + b, 0) / days.length) * 10) / 10 : 0;
    const avgTxt = days.length ? avg + 'd' : '—';
    rows += '<tr>' +
      '<td style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:700;color:#0B2540">' + esc(r.name || n) + '</td>' +
      '<td align="center" style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:800;color:' + colour + '">' + r.cases + '</td>' +
      '<td style="padding:8px 10px;border-top:1px solid #EDF2F8;color:#33475b;font-size:12px">' +
        days.map(d => '<span style="display:inline-block;background:' + (d >= 30 ? '#FCE9E7' : d >= 15 ? '#FFF3D6' : '#EAF4EC') +
          ';color:' + (d >= 30 ? '#A3271B' : d >= 15 ? '#9A6A00' : '#1E7A3D') +
          ';border-radius:6px;padding:2px 7px;margin:1px 3px 1px 0;font-weight:700">' + d + 'd</span>').join('') +
        (r.noDays ? '<span style="display:inline-block;background:#EEF1F5;color:#6E8095;border-radius:6px;' +
          'padding:2px 7px;margin:1px 3px 1px 0;font-weight:700">' + (r.noDays > 1 ? r.noDays + ' × ?' : '?') + '</span>' : '') +
      '</td>' +
      '<td align="center" style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:700;color:#33475b">' + avgTxt + '</td>' +
      '</tr>';
  }
  const gAvg = tN ? Math.round((tDays / tN) * 10) / 10 : 0;
  return '<table width="100%" cellpadding="0" cellspacing="0" style="' + FONT + ';font-size:12.5px;border-collapse:collapse;' +
    'border:1px solid #E2EAF4;border-radius:10px;overflow:hidden">' +
    '<tr style="background:' + colour + ';color:#fff">' +
      '<th align="left" style="padding:9px 10px;font-size:11px;letter-spacing:.4px">MANAGER</th>' +
      '<th style="padding:9px 10px;font-size:11px;letter-spacing:.4px">CASES</th>' +
      '<th align="left" style="padding:9px 10px;font-size:11px;letter-spacing:.4px">DAYS TAKEN, CASE BY CASE</th>' +
      '<th style="padding:9px 10px;font-size:11px;letter-spacing:.4px">AVG</th></tr>' +
    rows +
    '<tr style="background:#F1F6FB"><td style="padding:9px 10px;font-weight:800;color:#0B2540;border-top:2px solid ' + colour + '">TOTAL</td>' +
      '<td align="center" style="padding:9px 10px;font-weight:800;color:' + colour + ';border-top:2px solid ' + colour + '">' + tCases + '</td>' +
      '<td style="padding:9px 10px;color:#6E8095;font-size:11.5px;border-top:2px solid ' + colour + '">' +
        (tNo ? '<b>' + tNo + '</b> of these carry no readable TAT, so they are shown as ? and left out of the averages. ' : '') +
        esc(timedNote || '') + '</td>' +
      '<td align="center" style="padding:9px 10px;font-weight:800;color:#33475b;border-top:2px solid ' + colour + '">' + (tN ? gAvg + 'd' : '—') + '</td></tr>' +
    '</table>';
}

/* ── REACHED CM REVIEW LATE — the table that closes the hole ────────────────────────────────
   19-Aug-2026. His office sheet: managers closed 327 on the 18th. The mail: 163. The missing
   164 were not miscounted — they were INVISIBLE: a manager's release only enters SKD's closed
   feed when the CM REVIEW happens, and for some teams that lags a day or two. The proof was
   in one screen: the managers whose numbers matched the office sheet exactly (Jeltisen 20,
   Sugi 19, Reshma 18) had near-empty FO-Completed piles, and the managers missing entirely
   (Annemaria 38, Amruthanjali 12, Anushiya 13) had the biggest ones.
   Those stragglers arrive tomorrow carrying YESTERDAY'S date — a date whose mail has already
   gone. Without this table they would never be reported by any mail at all. So every mail now
   also reports what reached CM Review since the previous mail but belongs to an earlier date:
   counted once, under the mail that first saw it, labelled with its true date. Over the days,
   a date's running total converges on his office sheet — and if it does not, the remainder
   provably never reached the feed, which is SKD's side to answer for. */
async function buildLateArrivals(env, at, slot) {
  const out = { ok: false, why: '', total: 0, qc: 0, TP: {}, Health: {}, byDate: {}, sinceHours: 12 };
  const p = istParts(at);
  const istMidnight = Date.UTC(+p.year, +p.month - 1, +p.day) - 19800000;
  /* the mail's own date scope: morning reports yesterday, evening reports today — LATE means
     strictly before that, so nothing is ever counted twice */
  const pad = n => ('0' + n).slice(-2);
  const scopeMs = slot === 'evening' ? istMidnight : istMidnight - 86400000;
  const sp = istParts(new Date(scopeMs + 19800000 + 1));
  const beforeYmd = sp.year + '-' + pad(sp.month) + '-' + pad(sp.day);
  const rows = await keepCaughtSince(env, at.getTime() - 12 * 3600000, beforeYmd);
  if (rows === null) { out.why = 'the kept-case archive could not be read, so late arrivals cannot be counted this time'; return out; }
  const nameIndex = { TP: {}, Health: {} };
  for (const c of rows) {
    /* QC stragglers count too — 19-Aug, his rule: closed is closed at EITHER review stage.
       The split is kept so the merged number stays checkable. */
    if (!isCmReviewedCase(c)) out.qc++;
    const side = typeOfSub(c.subProduct) === 'TP' ? 'TP' : 'Health';
    const raw = String(c.manager || '').replace(/\s+/g, ' ').trim();
    const norm = raw ? raw.toLowerCase() : '(no manager named)';
    const disp = nameIndex[side][norm] || (nameIndex[side][norm] = raw || '(no manager named)');
    const r = out[side][disp] || (out[side][disp] = { name: disp, cases: 0, days: [], noDays: 0 });
    r.cases++;
    if (/\d/.test(String(c.tat == null ? '' : c.tat))) r.days.push(tatDaysNum(c.tat)); else r.noDays++;
    const dm = /^(\d{4})-(\d{2})-(\d{2})$/.exec(c._mgrDoneYmd || '');
    const label = dm ? (dm[3] + '/' + dm[2]) : 'no date';
    out.byDate[label] = (out.byDate[label] || 0) + 1;
    out.total++;
  }
  out.ok = true;
  return out;
}

/* THE CASHLESS TABLE READS IN HOURS.
   Same shape as releaseTable and deliberately not the same function: the chips, the colours
   and the averages all mean different things on an hour clock, and one function serving two
   rulers is how a "d" quietly ends up on an hour figure. Colours: green under 24 h (same
   day), amber 24–72 h, red over 72 h — and the legend under the table says exactly that, so
   the rule is on the page and he can order it changed by reading it. */
function releaseHoursTable(box, colour) {
  const names = Object.keys(box).sort((a, b) => box[b].cases - box[a].cases || a.localeCompare(b));
  if (!names.length) {
    return '<table width="100%" cellpadding="0" cellspacing="0" style="' + FONT + ';font-size:12.5px;color:#6E8095;' +
      'background:#F7FAFD;border:1px solid #E2EAF4;border-radius:10px"><tr><td style="padding:14px 16px">' +
      'No Cashless case was released in this window.</td></tr></table>';
  }
  let rows = '', tCases = 0, tH = 0, tN = 0, tNo = 0;
  for (const n of names) {
    const r = box[n];
    const hrs = r.hours.slice().sort((a, b) => b - a);
    tCases += r.cases; tNo += (r.noHours || 0); hrs.forEach(h => { tH += h; tN++; });
    const avg = hrs.length ? Math.round((hrs.reduce((a, b) => a + b, 0) / hrs.length) * 10) / 10 : 0;
    rows += '<tr>' +
      '<td style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:700;color:#0B2540">' + esc(r.name || n) + '</td>' +
      '<td align="center" style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:800;color:' + colour + '">' + r.cases + '</td>' +
      '<td style="padding:8px 10px;border-top:1px solid #EDF2F8;color:#33475b;font-size:12px">' +
        hrs.map(h => '<span style="display:inline-block;background:' + (h > 72 ? '#FCE9E7' : h >= 24 ? '#FFF3D6' : '#EAF4EC') +
          ';color:' + (h > 72 ? '#A3271B' : h >= 24 ? '#9A6A00' : '#1E7A3D') +
          ';border-radius:6px;padding:2px 7px;margin:1px 3px 1px 0;font-weight:700">' + h + 'h</span>').join('') +
        (r.noHours ? '<span style="display:inline-block;background:#EEF1F5;color:#6E8095;border-radius:6px;' +
          'padding:2px 7px;margin:1px 3px 1px 0;font-weight:700">' + (r.noHours > 1 ? r.noHours + ' × ?' : '?') + '</span>' : '') +
      '</td>' +
      '<td align="center" style="padding:8px 10px;border-top:1px solid #EDF2F8;font-weight:700;color:#33475b">' + (hrs.length ? avg + 'h' : '—') + '</td>' +
      '</tr>';
  }
  const gAvg = tN ? Math.round((tH / tN) * 10) / 10 : 0;
  return '<table width="100%" cellpadding="0" cellspacing="0" style="' + FONT + ';font-size:12.5px;border-collapse:collapse;' +
    'border:1px solid #E2EAF4;border-radius:10px;overflow:hidden">' +
    '<tr style="background:' + colour + ';color:#fff">' +
      '<th align="left" style="padding:9px 10px;font-size:11px;letter-spacing:.4px">MANAGER</th>' +
      '<th style="padding:9px 10px;font-size:11px;letter-spacing:.4px">CASES</th>' +
      '<th align="left" style="padding:9px 10px;font-size:11px;letter-spacing:.4px">HOURS TAKEN, CASE BY CASE</th>' +
      '<th style="padding:9px 10px;font-size:11px;letter-spacing:.4px">AVG</th></tr>' +
    rows +
    '<tr style="background:#F1F6FB"><td style="padding:9px 10px;font-weight:800;color:#0B2540;border-top:2px solid ' + colour + '">TOTAL</td>' +
      '<td align="center" style="padding:9px 10px;font-weight:800;color:' + colour + ';border-top:2px solid ' + colour + '">' + tCases + '</td>' +
      '<td style="padding:9px 10px;color:#6E8095;font-size:11.5px;border-top:2px solid ' + colour + '">' +
        (tNo ? '<b>' + tNo + '</b> of these carry no readable TAT, so they are shown as ? and left out of the averages.' : '') + '</td>' +
      '<td align="center" style="padding:9px 10px;font-weight:800;color:#33475b;border-top:2px solid ' + colour + '">' + (tN ? gAvg + 'h' : '—') + '</td></tr>' +
    '</table>';
}

export function dailyHtml(fig, slot) {
  const when = slot === 'evening' ? 'Evening position · 5:30 PM' : 'Morning position · 5:30 AM';
  const H = fig.byType.Health, T = fig.byType.TP;
  const tot = { cat: H.cat + T.cat, mgr: H.mgr + T.mgr, rejected: H.rejected + T.rejected,
                pending: H.pending + T.pending, other: H.other + T.other, total: H.total + T.total };

  /* ---- TP / Health ---- */
  const t2 = '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;min-width:250px">' +
    '<tr>' + td('<b>Motor TP</b>', { bg: '#EAF2FB' }) + td(n(T.total), { align: 'right', bold: true, bg: '#EAF2FB', colour: '#0074D9' }) + '</tr>' +
    '<tr>' + td('<b>Health</b>', { bg: '#EAF6EE' }) + td(n(H.total), { align: 'right', bold: true, bg: '#EAF6EE', colour: '#1E7A3D' }) + '</tr>' +
    '<tr>' + td('<b>Total</b>', { bg: '#001f3f', colour: '#ffffff' }) + td(n(fig.total), { align: 'right', bold: true, bg: '#001f3f', colour: '#ffffff' }) + '</tr></table>';

  /* ---- the three bucket tables, side by side ---- */
  const t3 = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>' +
    '<td width="37%" valign="top" style="padding-right:8px">' + bucketTable('Health Open cases', H, '#1E7A3D') + '</td>' +
    '<td width="37%" valign="top" style="padding-right:8px">' + bucketTable('TP Open cases', T, '#0074D9') + '</td>' +
    '<td width="26%" valign="top">' + bucketTable('Total', tot, '#1F3C6E') + '</td>' +
    '</tr></table>';

  /* ---- CAT pending closure: state, then the districts under it ---- */
  const codes = Object.keys(fig.catByState).sort();
  let t4 = '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' +
    '<tr>' + th('State / District', '#0d8f8f') + th('Total', '#0d8f8f', 'center') +
    th('4 days and above', '#0d8f8f', 'center') + th('% 4 days and above', '#0d8f8f', 'center') + '</tr>';
  let sT = 0, sA = 0;
  for (const code of codes) {
    const r = fig.catByState[code];
    sT += r.total; sA += r.aged;
    t4 += '<tr>' +
      '<td style="' + FONT + ';font-size:12.5px;padding:8px 9px;border:1px solid rgba(255,255,255,.25);background:#1F3C6E;color:#ffffff;font-weight:800">' + esc(code) + '</td>' +
      td(n(r.total), { align: 'center', bold: true, bg: '#EAF2FB' }) +
      td(n(r.aged), { align: 'center', bold: true, bg: '#EAF2FB', colour: r.aged ? '#A3271B' : '#0B2540' }) +
      pctCell(pct(r.aged, r.total)) + '</tr>';
    /* the districts he asked for on 17-Aug, indented under their own state and sorted by the
       count that needs chasing, not alphabetically — the report is a work list */
    const dn = Object.keys(r.districts).sort((a, b) => (r.districts[b].aged - r.districts[a].aged) || (r.districts[b].total - r.districts[a].total));
    for (const d of dn) {
      const x = r.districts[d];
      t4 += '<tr>' +
        td('<span style="color:#9DB0C6">└</span> &nbsp;' + esc(d), { colour: '#33475B', bg: '#FAFCFF' }) +
        td(n(x.total), { align: 'center', bg: '#FAFCFF' }) +
        td(n(x.aged), { align: 'center', bg: '#FAFCFF', colour: x.aged ? '#A3271B' : '#6E8095', bold: !!x.aged }) +
        pctCell(pct(x.aged, x.total)) + '</tr>';
    }
  }
  t4 += '<tr>' + td('<b>Total</b>', { bg: '#E8EFF8' }) + td(n(sT), { align: 'center', bold: true, bg: '#E8EFF8' }) +
    td(n(sA), { align: 'center', bold: true, bg: '#E8EFF8' }) + pctCell(pct(sA, sT)) + '</tr></table>';
  if (fig.stateUnknown) {
    t4 += '<div style="' + FONT + ';font-size:11px;color:#B26A00;padding:6px 2px 0">' +
      n(fig.stateUnknown) + ' CAT-pending Health case' + (fig.stateUnknown === 1 ? '' : 's') +
      ' could not be placed in a state — the officer on ' + (fig.stateUnknown === 1 ? 'it is' : 'them is') +
      ' not on the SKD officer list under that spelling. Counted here rather than folded into a state, ' +
      'so this table is short by exactly that many and says so.</div>';
  }

  const dead = !fig.live;
  return '<!doctype html><html><body style="margin:0;padding:0;background:#EEF3F9">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EEF3F9;padding:18px 0">' +
    '<tr><td align="center">' +
    '<table role="presentation" width="860" cellpadding="0" cellspacing="0" style="width:860px;max-width:97%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 6px 22px rgba(2,32,64,.12)">' +

    /* header */
    '<tr><td style="background:#001f3f;background:linear-gradient(135deg,#001f3f 0%,#0074D9 100%);padding:22px 24px">' +
    '<div style="' + FONT + ';font-size:20px;font-weight:800;color:#ffffff;letter-spacing:-.2px">TaaSen — Daily Case Position</div>' +
    '<div style="' + FONT + ';font-size:12.5px;color:#BFE0FF;margin-top:5px">' + esc(when) + ' &nbsp;·&nbsp; ' + esc(fig.atText) + ' IST</div>' +
    '</td></tr>' +

    (dead ? '<tr><td style="padding:14px 24px;background:#FDECEA;' + FONT + ';font-size:12.5px;color:#A3271B">' +
      '<b>SKD did not answer when this was built, so these figures are empty — not zero.</b><br>' +
      '<span style="color:#6E8095">' + esc(fig.skdError) + '</span></td></tr>' : '') +

    '<tr><td style="padding:18px 18px 6px">' +

    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>' +
    card('Total open', fig.total, '#1F3C6E') +
    card('Motor TP', T.total, '#0074D9') +
    card('Health', H.total, '#1E7A3D') +
    card('Out with the field', tot.cat, '#0d8f8f', 'CAT Pending') +
    '</tr></table>' +

    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">' +
    sectionTitle('By product', '#0074D9') + '<tr><td>' + t2 + '</td></tr>' +

    sectionTitle('Open cases — where they are sitting', '#1E7A3D') + '<tr><td>' + t3 + '</td></tr>' +
    '<tr><td style="' + FONT + ';font-size:11px;color:#6E8095;padding:8px 2px 0">' +
    BUCKETS.map(b => '<span style="color:' + b.colour + ';font-weight:700">' + esc(b.label) + '</span> = ' + esc(b.note)).join(' &nbsp;·&nbsp; ') +
    '</td></tr>' +

    sectionTitle('CAT Pending closure — Health, by state and district', '#0d8f8f') + '<tr><td>' + t4 + '</td></tr>' +

    sectionTitle('FO Completed by ageing — MANAGER-wise · Motor TP', '#0074D9') +
    '<tr><td>' + managerTable(fig.mgrTPRows || [], TP_BANDS, TP_PLUS, '#1F3C6E') + '</td></tr>' +
    '<tr><td style="' + FONT + ';font-size:11px;color:#6E8095;padding:6px 2px 0">' +
    'Days in the field. <b style="color:#B26A00">45+ · 55+ · 75+ · 100+</b> are running totals — every case that has crossed that line. ' +
    'They overlap each other and the bands on purpose, so do not add a row across.</td></tr>' +

    sectionTitle('FO Completed by ageing — MANAGER-wise · Health', '#1E7A3D') +
    '<tr><td>' + managerTable(fig.mgrHealthRows || [], HEALTH_BANDS, [], '#1E7A3D') + '</td></tr>' +

    /* ── RELEASED TO CM REVIEWED THIS SHIFT ──────────────────────────────────────────── */
    (fig.rel && fig.rel.ok
      ? (sectionTitle('Released by MANAGER (CM + QC Reviewed) · Motor TP  (' + esc(fig.rel.win.short) + ')', '#0074D9') +
         '<tr><td>' + releaseTable(fig.rel.TP, '#1F3C6E', fig.rel.note) + '</td></tr>' +
         sectionTitle('Released by MANAGER (CM + QC Reviewed) · Health  (' + esc(fig.rel.win.short) + ')', '#1E7A3D') +
         '<tr><td>' + releaseTable(fig.rel.Health, '#1E7A3D', fig.rel.note) + '</td></tr>' +
         /* CASHLESS AGAIN, ON AN HOUR CLOCK — his 19-Aug ask. These cases are already inside
            the Health table above (its total must keep meaning all of Health); this reads the
            same releases in hours, because a case that closes in hours all reads 0d on a day
            clock and the fast work disappears. */
         sectionTitle('Cashless — the same releases, HOUR by HOUR  (' + esc(fig.rel.win.short) + ')', '#0E7C86') +
         '<tr><td>' + releaseHoursTable(fig.rel.Cash, '#0E7C86') + '</td></tr>' +
         '<tr><td style="' + FONT + ';font-size:11px;color:#6E8095;padding:6px 2px 12px">' +
         'Only <b>Cashless</b> cases, counted a second time on a finer clock — they are inside the Health table above too, ' +
         'so do not add the two tables together. Hours are the case’s own TAT read as hours (days × 24 + hours) — ' +
         '<b style="color:#1E7A3D">under 24h</b> same day, <b style="color:#9A6A00">24–72h</b>, <b style="color:#A3271B">over 72h</b>.' +
         '</td></tr>' +
         '<tr><td style="' + FONT + ';font-size:11px;color:#6E8095;padding:6px 2px 0">' +
         'Cases a manager sent to <b>CM Reviewed</b> between ' + esc(fig.rel.win.label) + '. ' +
         'Each chip is one case and how many days it had been running when it was released — ' +
         '<b style="color:#1E7A3D">under 15</b>, <b style="color:#9A6A00">15–29</b>, <b style="color:#A3271B">30+</b>. ' +
         'Printed case by case on purpose: an average hides the long one, and the long one is the reason to look. ' +
         '<b>Closed means closed at either stage — CM Reviewed and QC Reviewed both count</b>, the same rule as the office sheet' +
         (fig.rel.qcInWin ? ' (<b>' + fig.rel.qcInWin + '</b> of these are QC Reviewed)' : '') + '. ' +
         '<b>This table holds what has reached review by mail time.</b> A case your manager released on this date whose ' +
         'review happens later arrives in a later mail under <b>REACHED REVIEW LATE</b> — every case is counted exactly once, just never lost.' +
         '</td></tr>' +
         (fig.rel.undatedNote
           ? '<tr><td style="' + FONT + ';font-size:11.5px;color:#8a4b00;background:#FDF6EA;border:1px solid #F0D2A0;' +
             'border-radius:9px;padding:9px 12px;margin-top:4px">' + esc(fig.rel.undatedNote) + '</td></tr>'
           : '') +
         /* THE LATE ARRIVALS — the missing half of his office sheet, reported the day the feed
            finally serves it. Rendered only when there is something to say: a permanently
            empty table is noise, but a FAILED look is named, because "no late arrivals" and
            "could not look" must never wear the same face. */
         (fig.rel.late && fig.rel.late.ok && fig.rel.late.total > 0
           ? sectionTitle('REACHED REVIEW LATE — released on earlier dates, counted now', '#7A4CB0') +
             '<tr><td style="' + FONT + ';font-size:12px;color:#33475b;padding:2px 2px 8px">These were released by their managers on ' +
             'the dates below, but their review only happened in the last ' + fig.rel.late.sinceHours + ' hours — so no earlier mail could ' +
             'see them. Released on: <b>' + esc(Object.keys(fig.rel.late.byDate).map(function (d) { return d + ': ' + fig.rel.late.byDate[d]; }).join(' · ')) + '</b>' +
             (fig.rel.late.qc ? ' · ' + fig.rel.late.qc + ' of them QC Reviewed' : '') + '</td></tr>' +
             (Object.keys(fig.rel.late.TP).length ? '<tr><td>' + releaseTable(fig.rel.late.TP, '#7A4CB0', '') + '</td></tr>' : '') +
             (Object.keys(fig.rel.late.Health).length ? '<tr><td>' + releaseTable(fig.rel.late.Health, '#8E6BBF', '') + '</td></tr>' : '')
           : (fig.rel.late && !fig.rel.late.ok
               ? '<tr><td style="' + FONT + ';font-size:11.5px;color:#8a4b00;background:#FDF6EA;border:1px solid #F0D2A0;' +
                 'border-radius:9px;padding:9px 12px;margin-top:4px">Late arrivals could not be counted this time — ' + esc(fig.rel.late.why) + '</td></tr>'
               : '')))
      : (fig.rel && fig.rel.why
          ? sectionTitle('Released to CM Reviewed', '#A3271B') +
            '<tr><td style="' + FONT + ';font-size:12.5px;color:#A3271B;background:#FCE9E7;border:1px solid #F3C6C2;border-radius:10px;padding:12px 14px">' +
            'This table could not be built: ' + esc(fig.rel.why) + ' — so it is missing, not empty.</td></tr>'
          : '')) +
    '</table>' +

    '</td></tr>' +

    /* footer */
    '<tr><td style="padding:18px 24px;background:#F3F7FC;border-top:1px solid #E2EAF4;' + FONT + ';font-size:11.5px;color:#6E8095">' +
    'Counted live from the SKD open-case feed at ' + esc(fig.atText) + ' IST by the TaaSen Claims Portal. ' +
    'Every figure here is the same arithmetic the portal shows on screen — open the Dashboard and Analytics and the totals will match.' +
    '</td></tr>' +

    '</table></td></tr></table></body></html>';
}

/* the same thing in plain words, for a mail client that refuses HTML */
export function dailyText(fig, slot) {
  const H = fig.byType.Health, T = fig.byType.TP;
  const L = [];
  L.push('TaaSen — Daily Case Position');
  L.push((slot === 'evening' ? 'Evening position · 5:30 PM' : 'Morning position · 5:30 AM') + ' · ' + fig.atText + ' IST');
  L.push('');
  if (!fig.live) L.push('SKD did not answer when this was built — these figures are empty, not zero.');
  L.push('Total open: ' + fig.total + '   (Motor TP ' + T.total + ' · Health ' + H.total + ')');
  L.push('');
  for (const pair of [['Health', H], ['TP', T]]) {
    L.push(pair[0] + ' open cases:');
    for (const b of BUCKETS) L.push('   ' + b.label + ': ' + pair[1][b.key]);
    if (pair[1].other) L.push('   Other status: ' + pair[1].other);
    L.push('   Total: ' + pair[1].total);
  }
  L.push('');
  L.push('CAT Pending closure (Health) — state / district: total / 4 days and above / %');
  for (const code of Object.keys(fig.catByState).sort()) {
    const r = fig.catByState[code];
    L.push('   ' + code + ': ' + r.total + ' / ' + r.aged + ' / ' + pct(r.aged, r.total) + '%');
    for (const d of Object.keys(r.districts).sort()) {
      const x = r.districts[d];
      L.push('      ' + d + ': ' + x.total + ' / ' + x.aged + ' / ' + pct(x.aged, x.total) + '%');
    }
  }
  L.push('');
  L.push('FO Completed by ageing — manager-wise (Motor TP):');
  for (const r of (fig.mgrTPRows || [])) L.push('   ' + r.name + ': ' + r.total + '  (45+ ' + plusCount(r.bands, 2) + ')');
  L.push('');
  L.push('FO Completed by ageing — manager-wise (Health):');
  for (const r of (fig.mgrHealthRows || [])) L.push('   ' + r.name + ': ' + r.total);
  L.push('');
  L.push('TaaSen Claims Portal');
  return L.join('\n');
}

/* ══════════ SENDING ══════════════════════════════════════════════════════════════════
   The same two doors the release alert uses — his own mail relay if OTP_MAIL_URL is set,
   otherwise Brevo. Neither configured = nothing sent, and the caller is TOLD so rather than
   being allowed to believe a mail went out.                                              */
function listVar(v) { return String(v == null ? '' : v).split(/[,;|\n]+/).map(x => x.trim()).filter(Boolean); }

/* ══ THE HANDSHAKE ═══════════════════════════════════════════════════════════════════════
   18-Aug-2026. His relay refused with {"ok":false,"error":"bad code"} — not "bad key", so the
   key passed and a separate field named `code` was the problem. Sending a non-empty `code`
   was the obvious fix and it was REFUSED TOO, which kills the "it only checks presence"
   theory: the script validates `code` against a particular value.

   I do not have his Apps Script and I have now guessed twice. Guessing a third time costs him
   another ten minutes for a one-in-four chance, so the portal stops guessing and TRIES.

   These are the shapes an OTP-style Apps Script mailer plausibly wants, ordered by how likely
   each is. The test button walks them until one is accepted, says which one worked, and
   remembers it — after that the 5:30 mail uses the winner and nothing is probed again.

   Safe by construction: a REFUSED attempt sends nothing, and the walk STOPS at the first
   acceptance, so the worst case is a single test mail — which is what the button is for. */
const SHAPE_KV_KEY = 'daily:mailshape';
/* v12.3: every shape (except the deliberately-bare OTP one) now also carries the sender's
   display name under the three spellings an Apps Script mailer plausibly reads — `name` is
   what MailApp/GmailApp's own option is called, so a script that simply spreads the payload
   into sendEmail picks it up with no change at all. */
const MAIL_SHAPES = [
  { id: 'code=key',
    why: 'the script reads the shared secret from a field called `code`',
    build: (env, f) => ({ key: env.OTP_MAIL_KEY || '', code: env.OTP_MAIL_KEY || '',
      to: f.to, cc: f.cc, subject: f.subject, html: f.html, htmlBody: f.html, body: f.html, text: f.text,
      name: f.fromName, fromName: f.fromName, senderName: f.fromName }) },
  { id: 'code=key, no key field',
    why: '`code` is the only secret it looks at, and an unexpected `key` upsets it',
    build: (env, f) => ({ code: env.OTP_MAIL_KEY || '',
      to: f.to, cc: f.cc, subject: f.subject, html: f.html, htmlBody: f.html, body: f.html, text: f.text,
      name: f.fromName, fromName: f.fromName, senderName: f.fromName }) },
  { id: 'exact OTP shape',
    why: 'exactly the five fields the working sign-in mail sends, and nothing else — so this one alone carries no sender name',
    build: (env, f) => ({ key: env.OTP_MAIL_KEY || '', code: env.OTP_MAIL_KEY || '',
      to: f.to, subject: f.subject, text: f.text }) },
  { id: 'code=DAILY_MAIL_CODE',
    why: 'a value set by hand in the Worker variable DAILY_MAIL_CODE',
    build: (env, f) => ({ key: env.OTP_MAIL_KEY || '', code: env.DAILY_MAIL_CODE || 'daily',
      to: f.to, cc: f.cc, subject: f.subject, html: f.html, htmlBody: f.html, body: f.html, text: f.text,
      name: f.fromName, fromName: f.fromName, senderName: f.fromName }) },
  { id: 'no code at all',
    why: 'the original shape — kept last so the walk still covers it',
    build: (env, f) => ({ key: env.OTP_MAIL_KEY || '',
      to: f.to, cc: f.cc, subject: f.subject, html: f.html, text: f.text,
      name: f.fromName, fromName: f.fromName, senderName: f.fromName }) }
];
function shapeById(id) { for (const s of MAIL_SHAPES) if (s.id === id) return s; return null; }

/* one attempt, one shape. Never throws; the relay's own words always come back. */
async function tryRelay(env, shape, f) {
  let r, body = '';
  try {
    r = await fetch(env.OTP_MAIL_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(shape.build(env, f))
    });
    body = await r.text();
  } catch (e) {
    return { ok: false, shape: shape.id, status: 0, said: '', error: 'could not reach the mail relay — ' + String((e && e.message) || e) };
  }
  let j = null; try { j = JSON.parse(body); } catch (e) { j = null; }
  /* v21.3 — A WEB PAGE IS NOT A SENT MAIL. Sujit, 06-Sep 11 am: "I have been sent [the MBV
     chase], but still I received [nothing]" — and no chase mail of any kind had left at 8 am.
     Google answers an Apps Script that fails outside its own try/catch, or an account that
     has used up its daily mail allowance, with an HTML error page and HTTP 200. Under the
     old rule ("a 200 counts unless the relay says ok:false") that page counted as a send: the
     card said Sent, the slot was stamped, and nothing had gone. A real answer from the relay
     is JSON or a short line, never a document — so a document is now a refusal, with the
     page's own words carried back so the card can print them. */
  const said = String(body || '').replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300);
  /* a whole HTML document that talks of an error, a quota, a missing function or a sign-in is
     Google's page, not the relay's answer; a relay that happens to answer a bare "ok" inside
     html tags is left alone */
  const looksHtml = /^\s*<(!doctype|html)\b/i.test(body)
    && (/(error|exception|sorry|quota|too many times|limit exceeded|not found|unable to|denied|sign in|google apps script|script function)/i.test(said) || /<title>[^<]*(error|sorry)/i.test(body));
  /* the same rule the working OTP mail uses: a 200 counts UNLESS the relay says ok:false — or answers a page */
  if (r.ok && (!j || j.ok !== false) && !looksHtml) return { ok: true, shape: shape.id, status: r.status, said };
  if (looksHtml) return { ok: false, shape: shape.id, status: r.status, said,
    error: 'the mail relay answered a web page instead of a result (an Apps Script error, or Google\'s daily mail limit on the sending account) — it said: ' + (said || '(blank page)') };
  return { ok: false, shape: shape.id, status: r.status, said,
    error: 'the mail relay answered ' + r.status + ((j && (j.error || j.message)) ? ' — ' + (j.error || j.message) : (said ? ' — ' + said : '')) };
}

/* ══════════ SENDING ══════════════════════════════════════════════════════════════════
   The scheduled mail never probes. It uses the shape the test button proved, or the first
   one if nothing has been proved yet — a cron firing at 5:30 is no place to be trying five
   things and possibly sending five mails.                                               */
/* v17.5 — EXPORTED, and taught one more thing: replyTo. The recruitment mails from
   join-index.js ride this exact, production-proven sender rather than growing their own —
   one mail door for the whole portal, the same rule as one Excel builder. replyTo matters
   there: the interview mail says "if you are not available, reply to this mail", and that
   reply must land with the person who scheduled it, not in a no-reply box. Brevo carries
   it natively; the Apps Script relay receives it as a field and may use or ignore it —
   the mail body always names the address as well, so nothing is lost either way. */
export async function postMail(env, to, cc, subject, html, text, replyTo) {
  const f = { to: to.join(','), cc: cc.join(','), subject, html, text, fromName: await mailFromName(env), replyTo: String(replyTo || '') };
  /* v34.9 — Sujit, 29-Sep: "stop sending from my mail" — every portal mail leaves from
     no-reply@taasenclaims.com. A reply still reaches a person: the caller's reply-to, else
     MAIL_REPLY_TO, else the first admin. The Apps Script relay (his own mailbox) is only the
     spare when the no-reply sender refuses. */
  if (env.RESEND_API_KEY) {
    const rt = f.replyTo || String(env.MAIL_REPLY_TO || '').trim() || String(env.ADMIN_EMAILS || '').split(/[,;\s]+/).filter(Boolean)[0] || '';
    const m = { from: (f.fromName || 'TaaSen Claims Portal').replace(/[<>"]/g, '') + ' <no-reply@' + nrDomain(env) + '>', to, subject, html, text };
    if (cc.length) m.cc = cc;
    if (rt) m.replyTo = rt;
    const r0 = await nrSend(env, m);
    if (r0 && r0.ok) return { ok: true, via: 'no-reply', status: 200 };
    if (!env.OTP_MAIL_URL && !env.BREVO_API_KEY) return { ok: false, via: 'no-reply', error: (r0 && r0.error) || 'the no-reply sender refused' };
  }
  if (env.OTP_MAIL_URL) {
    let chosen = MAIL_SHAPES[0];
    if (env.USERS) {
      try { const id = await env.USERS.get(SHAPE_KV_KEY); const s2 = id && shapeById(id); if (s2) chosen = s2; } catch (e) {}
    }
    const res = await tryRelay(env, chosen, f);
    return { ok: res.ok, via: 'relay', status: res.status, error: res.error || '', said: res.said || '', shape: res.shape };
  }
  if (env.BREVO_API_KEY) {
    const body = {
      sender: { email: env.OTP_MAIL_FROM || 'no-reply@skdhealth.net', name: f.fromName },
      to: to.map(email => ({ email })), subject, htmlContent: html, textContent: text
    };
    if (cc.length) body.cc = cc.map(email => ({ email }));
    if (f.replyTo) body.replyTo = { email: f.replyTo };
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    });
    return { ok: r.ok, via: 'brevo', status: r.status };
  }
  return { ok: false, via: 'none', error: 'No mail sender configured — set OTP_MAIL_URL (your own relay) or BREVO_API_KEY.' };
}

/* THE TEST BUTTON'S SEND. Walks the shapes, stops at the first acceptance, remembers it, and
   reports every attempt — so a screenshot of one press tells the whole story. */
async function probeMail(env, to, cc, subject, html, text) {
  const f = { to: to.join(','), cc: cc.join(','), subject, html, text, fromName: await mailFromName(env) };
  if (!env.OTP_MAIL_URL) return await postMail(env, to, cc, subject, html, text);
  const tried = [];
  for (const shape of MAIL_SHAPES) {
    const res = await tryRelay(env, shape, f);
    tried.push({ shape: shape.id, why: shape.why, ok: res.ok, said: res.said, error: res.error || '' });
    if (res.ok) {
      if (env.USERS) { try { await env.USERS.put(SHAPE_KV_KEY, shape.id); } catch (e) {} }
      return { ok: true, via: 'relay', status: res.status, said: res.said, shape: shape.id, tried };
    }
  }
  return { ok: false, via: 'relay', status: tried.length ? 0 : 0,
    error: 'every shape was refused — the script wants something none of these match',
    said: tried[0] ? tried[0].said : '', tried };
}

/* Sujit, 18-Aug-2026: "The subject need to be changed as a data update. Subject need to be
   more updated." So it leads with what it is and WHEN — a subject that carries the date reads
   as today's position in a mailbox, sorts sensibly, and does not look like yesterday's mail
   sitting unread. The releases are on it too, because that is the number he opens it for. */
export function subjectFor(fig, slot) {
  const rel = fig.rel && fig.rel.ok ? fig.rel.total : null;
  const late = fig.rel && fig.rel.ok && fig.rel.late && fig.rel.late.ok ? fig.rel.late.total : 0;
  return 'TaaSen Data Update · ' + (fig.dateText || '') + ' ' + (slot === 'evening' ? 'Evening' : 'Morning') +
    ' · ' + fig.total + ' open (TP ' + fig.byType.TP.total + ' · Health ' + fig.byType.Health.total + ')' +
    (rel !== null ? ' · ' + rel + ' released' + (late > 0 ? ' (+' + late + ' late)' : '') : '');
}

/* ══════════ THE SWEEP ════════════════════════════════════════════════════════════════
   Called every hour by entry.js. Sends only in the 5 am and 5 pm IST hours, only once per
   slot per day, and only when SKD actually answered — a mail of zeroes landing at 5:30 in
   the morning reads as a quiet night rather than as a dead feed, and somebody would act on
   it long before anybody thought to check.                                                */
/* ══ WHO THE MAIL GOES TO — settable from the portal ══════════════════════════════════════
   Sujit, 18-Aug-2026: "I didn't receive the mail. What happened?"

   Nothing had gone wrong. The guard below did exactly what it was built to do — refuse to
   send to anybody until somebody names the recipients — and DAILY_MAIL_TO had never been
   added in Cloudflare. So a feature that was finished in v9.3 had sat switched off for a day,
   and the only sign of it was silence.

   Two things follow from that, and both are in here:

     1. THE LIST MOVES INTO THE PORTAL, like the webhook key and the Acefone token before it.
        A recipient list is not a credential; it is ordinary configuration he will edit as
        people join and leave, and it has no business behind a Deploy button.
     2. THE PORTAL'S LIST WINS over the variable, because this is the one he will edit. Same
        reasoning as the webhook key, opposite to the Acefone token: whoever is expected to
        change a thing must be the one whose change takes effect, or the edit silently does
        nothing.

   The guard itself does not move an inch. An empty list still means nothing is ever sent. */
const DAILY_KV_KEY = 'daily:mailto';

/* ══════════ WHOSE NAME IS ON THE MAIL ═══════════════════════════════════════════════════
   Sujit, 20-Aug-2026, reading the morning mail in his inbox: "I don't want send receiving
   in this name — TaaSen Claims Portal. I need my name itself. SUJIT D N Business head."

   Right — this mail goes to management, and a position mail from a robot reads like a
   notification; the same mail from the Business Head reads like a report. The display name
   is ordinary configuration, so it lives where the recipient list lives: in the portal,
   editable on the same Settings card, with his name as the default so it is right from the
   first deploy without touching anything.

   HOW FAR THE PORTAL'S ARM REACHES, said plainly: the portal can only PASS the name to
   whatever actually sends the mail. Brevo honours sender.name directly. The Apps Script
   relay is HIS script — the name rides the payload under three spellings (name, fromName,
   senderName — same cost-nothing trick as html/htmlBody), and if the script ignores all
   three, the From line will not change until one line is added to the script; the portal
   cannot reach into Google and edit it. The sign-in OTP mails keep the portal's name on
   purpose — a login code from a person reads as odd as a report from a robot.            */
const FROM_KV_KEY = 'daily:mailfrom';
const FROM_DEFAULT = 'Sujit D N · Business Head';
function cleanFromName(v) {
  return String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, 60);
}
async function mailFromName(env) {
  if (env && env.USERS) {
    try {
      const raw = await env.USERS.get(FROM_KV_KEY);
      if (raw) { const j = JSON.parse(raw); const n = cleanFromName(j && j.name); if (n) return n; }
    } catch (e) { /* unreadable -> the default, never a blank */ }
  }
  return cleanFromName(env && env.DAILY_MAIL_FROM_NAME) || FROM_DEFAULT;
}

function cleanEmails(v) {
  const raw = Array.isArray(v) ? v : String(v == null ? '' : v).split(/[,;\s]+/);
  const out = [], seen = {};
  raw.map(x => String(x || '').trim().toLowerCase()).forEach(a => {
    /* deliberately plain: one @, a dot after it, no spaces. Anything cleverer starts
       rejecting the real addresses people actually have. */
    if (!a || a.indexOf('@') < 1) return;
    const dom = a.slice(a.indexOf('@') + 1);
    if (dom.indexOf('.') < 1 || /\s/.test(a)) return;
    if (seen[a]) return;
    seen[a] = 1; out.push(a);
  });
  return out.slice(0, 40);
}
export async function dailyRecipients(env) {
  if (env && env.USERS) {
    try {
      const raw = await env.USERS.get(DAILY_KV_KEY);
      if (raw) {
        const j = JSON.parse(raw);
        const to = cleanEmails(j && j.to), cc = cleanEmails(j && j.cc);
        /* an empty saved list is a REAL answer — it is how he turns the mail off from the
           portal — so it must not fall through to the variable and quietly switch it back on */
        if (j) return { to, cc, source: 'portal', setBy: j.setBy || '', setTs: j.setTs || 0 };
      }
    } catch (e) { /* unreadable -> fall back to the variable, never to a guess */ }
  }
  return { to: cleanEmails(env && env.DAILY_MAIL_TO), cc: cleanEmails(env && env.DAILY_MAIL_CC),
    source: (env && env.DAILY_MAIL_TO) ? 'cloudflare' : 'none', setBy: '', setTs: 0 };
}

/* ── THE ATTEMPT REGISTER — v14.5, 26-Aug-2026 ──────────────────────────────────────────
   Sujit, 6:03 this morning: "Why I didn't receive today 5:30 morning mail?"

   His inbox held every slot for three days, each landing within a minute of time — and
   today's morning slot simply absent, while a live probe at 6:06 found SKD answering, the
   recipients set and the sender ready. So the machinery was healthy and the mail still did
   not exist, and NOTHING ANYWHERE could say why: the sweep kept a record only of successes.
   Silence was the only symptom, and silence does not say whether Cloudflare skipped the
   hour, SKD was down at 5:30, or the relay refused.

   So the sweep now writes down EVERY run in a mail hour — sent or not, and WHY not — and
   the Settings card reads it back. Three different silences finally read differently:
     · a try-record saying "SKD did not answer"      → the feed was down at 5:30;
     · a try-record saying "relay refused: …"        → the mailer, with its own words;
     · NO try-record at all for the hour             → Cloudflare never ran the cron, which
       is the one failure the worker itself cannot log, so its absence IS the log.
   The hour-after retry (slotFor counts 5 AND 6 o'clock) stays exactly as it was.          */
async function noteTry(env, at, slot, outcome) {
  if (!env.USERS) return;
  try {
    await env.USERS.put('daily:try:' + istDayKey(at) + ':' + slot,
      JSON.stringify(Object.assign({ atIst: istPretty(at) }, outcome)),
      { expirationTtl: 3 * 24 * 3600 });
  } catch (e) { /* the register must never break the mail it describes */ }
}

export async function dailySweep(env, now) {
  const at = now || new Date();
  const slot = slotFor(at);
  if (!slot) return { ok: true, sent: false, why: 'not a mail hour' };

  const who = await dailyRecipients(env);
  const to = who.to;
  if (!to.length) {
    await noteTry(env, at, slot, { sent: false, why: 'no recipients set' });
    return { ok: true, sent: false, why: 'no recipients set — nothing is ever sent until somebody is named on Settings → Daily position mail' };
  }

  const key = 'daily:sent:' + istDayKey(at) + ':' + slot;
  if (env.USERS) {
    const already = await env.USERS.get(key).catch(() => null);
    if (already) return { ok: true, sent: false, why: 'already sent this slot today' };
  }

  const fig = await buildDaily(env, slot);
  if (!fig.live) {
    await noteTry(env, at, slot, { sent: false, why: 'SKD did not answer' + (fig.skdError ? ' — ' + String(fig.skdError).slice(0, 160) : '') });
    return { ok: true, sent: false, why: 'SKD did not answer — a mail of zeroes reads as a quiet night' };
  }

  const res = await postMail(env, to, who.cc,
    subjectFor(fig, slot), dailyHtml(fig, slot), dailyText(fig, slot));
  if (res.ok && env.USERS) {
    try { await env.USERS.put(key, JSON.stringify({ at: fig.at, atIst: istPretty(at), total: fig.total, via: res.via }), { expirationTtl: 3 * 24 * 3600 }); } catch (e) {}
  }
  await noteTry(env, at, slot, res.ok
    ? { sent: true, via: res.via, total: fig.total }
    : { sent: false, why: 'the mail sender refused — ' + String(res.error || ('via ' + res.via + ', status ' + (res.status || '?'))).slice(0, 200) });
  return { ok: true, sent: !!res.ok, slot, to: to.length, total: fig.total, via: res.via, error: res.error || '' };
}

/* ══════════ THE LATE-ATTENDANCE MAIL — 5:30 PM, TO THE STATE COORDINATORS ═════════════
   Sujit, 20-Aug-2026, the day SKD's attendance reached the portal: "Same like one more
   mail — I need for evening 5:30. The field officers who all punch the late, after 8:30
   morning, their names. I want to ask the state coordinators: why this field officers not
   punched on time, give me explanation. State coordinators mail I'll give you — if that
   state is available means you have to mention them."

   A second daily mail, beside the position mail, on the same 5:30 pm tick:
     · every officer whose SKD punch today is AFTER the cut-off (his 8:30 am, editable),
       grouped by state, with the punch time on each name;
     · every officer with NO punch at all today, in his own block per state — worse than
       late, and never folded into it;
     · each state block addressed to that state's coordinator, whose address he pastes on
       Settings → Late attendance mail. A state with offenders but no saved address is
       flagged in amber ON the mail rather than silently skipped.

   Sent to the coordinators (To) with the position-mail list in Cc so management sees what
   was asked. OFF until he switches it on — the same safety catch as the position mail:
   a mail demanding explanations must never blast anybody by accident. If SKD's list could
   not be read it does not send: a mail calling every man absent because the feed was down
   would be a false accusation 190 names long. And on a day everybody punched on time it
   still goes, one green line, because "no mail" and "nobody late" must never look alike. */
const LATE_KV_KEY = 'late:cfg';
const LATE_AFTER_DEFAULT = '08:30';
/* The coordinator addresses HE gave, 20-Aug-2026, word for word — baked as the defaults so
   the mail is correctly addressed from the first deploy, before Settings is ever opened:
     "THIS IS FOR TAMIL NADU. skd.rajaguru@gmail.com AND saravanamanikandanskd@gmail.com ·
      ANDHRA PRADESH AND TELANGANA mohan.rao@skdhealth.net · MAHARASHTRA
      mahendersingh.skd@gmail.com · KERALA ravi.ssr81@gmail.com AND sijojustin16@gmail.com ·
      KARNATAKA mohan.rao@skdhealth.net · Default sujith.dn@skdhealth.com,
      senthil@skdhealth.com, resourcemanager@skdhealth.net"
   Keys are canonState labels lowercased (AP and Telangana are ONE territory here, as
   everywhere in this portal). Saving on the Settings card overrides all of this in KV. */
const LATE_COORDS_DEFAULT = {
  'tamilnadu': ['skd.rajaguru@gmail.com', 'saravanamanikandanskd@gmail.com'],
  'andhra pradesh & telangana': ['mohan.rao@skdhealth.net'],
  'maharashtra': ['mahendersingh.skd@gmail.com'],
  'kerala': ['ravi.ssr81@gmail.com', 'sijojustin16@gmail.com'],
  'karnataka': ['mohan.rao@skdhealth.net']
};
const LATE_DEFAULT_TO = ['sujith.dn@skdhealth.com', 'senthil@skdhealth.com', 'resourcemanager@skdhealth.net'];
async function lateCfg(env) {
  let c = null;
  if (env && env.USERS) { try { const raw = await env.USERS.get(LATE_KV_KEY); if (raw) c = JSON.parse(raw); } catch (e) { c = null; } }
  if (!c) {
    /* nothing saved yet: HIS spoken configuration, on from the first deploy — he named the
       addresses and asked for the mail in the same breath, which is the switch-on */
    return { on: true, after: LATE_AFTER_DEFAULT, coords: LATE_COORDS_DEFAULT, defaults: LATE_DEFAULT_TO, setBy: '', setTs: 0 };
  }
  const coords = (c.coords && typeof c.coords === 'object') ? c.coords : {};
  return { on: !!c.on, after: lateAfterClean(c.after) || LATE_AFTER_DEFAULT,
    coords, defaults: cleanEmails(c.defaults), setBy: c.setBy || '', setTs: c.setTs || 0 };
}
function lateAfterClean(v) {
  const m = String(v == null ? '' : v).trim().match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
  return m ? (String(m[1]).padStart(2, '0') + ':' + m[2]) : '';
}
function lateMinutes(hhmm) { const p = String(hhmm).split(':'); return parseInt(p[0], 10) * 60 + parseInt(p[1], 10); }
/* "20/08/2026 06:31 AM" -> minutes of the day, or -1 when unreadable. Text arithmetic on
   purpose — new Date() on a dd/MM/yyyy string reads it US-style and lies silently. */
function punchMinOf(att) {
  const parts = String(att == null ? '' : att).trim().split(/\s+/);
  if (parts.length < 3) return -1;
  const hm = parts[1].split(':');
  let h = parseInt(hm[0], 10); const m = parseInt(hm[1], 10);
  if (isNaN(h) || isNaN(m) || h < 1 || h > 12 || m < 0 || m > 59) return -1;
  const ap = parts[2].toUpperCase();
  if (ap !== 'AM' && ap !== 'PM') return -1;
  if (ap === 'PM' && h !== 12) h += 12;
  if (ap === 'AM' && h === 12) h = 0;
  return h * 60 + m;
}
function istDMY(d) {
  return new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', day: '2-digit', month: '2-digit', year: 'numeric' }).format(d || new Date());
}
/* one state's key in the coords map — the canonical label, lowercased */
function lateStateKey(s) { return (canonState(String(s == null ? '' : s).trim()) || '(no state on the SKD record)').toLowerCase(); }
function lateStateLabel(s) { return canonState(String(s == null ? '' : s).trim()) || '(no state on the SKD record)'; }

/* Reads the roster and sorts today's attendance into late / no-punch / on-time, by state. */
async function lateFigures(env, cfg) {
  let roster = [];
  try { roster = await getFoRoster(env); } catch (e) { roster = []; }
  const live = roster.length > 0 && roster.live !== false && roster.some(o => o.att !== undefined);
  const today = istDMY(new Date());
  const cut = lateMinutes(cfg.after);
  const states = {};
  let lateN = 0, noneN = 0, onTimeN = 0, total = 0;
  for (const o of roster) {
    if (o.att === undefined) continue;                    // fallback rows carry no attendance
    total++;
    const k = lateStateKey(o.state);
    if (!states[k]) states[k] = { label: lateStateLabel(o.state), late: [], none: [], onTime: 0 };
    const a = String(o.att || '').trim();
    const day = a ? a.split(' ')[0] : '';
    const punchedToday = !!a && day === today;
    const min = punchedToday ? punchMinOf(a) : -1;
    if (!punchedToday) { states[k].none.push(o); noneN++; }
    else if (min > cut) { states[k].late.push({ ...o, punchText: a.slice(day.length).trim(), punchMin: min }); lateN++; }
    else { states[k].onTime++; onTimeN++; }
  }
  for (const k in states) states[k].late.sort((a, b) => b.punchMin - a.punchMin); // worst first
  return { live, today, cut: cfg.after, states, lateN, noneN, onTimeN, total };
}

function lateSubject(f) {
  return 'TaaSen Attendance · ' + f.today + ' · punched after ' + f.cut + ': ' + f.lateN +
    ' · no punch: ' + f.noneN + (f.lateN + f.noneN ? ' — explanation needed' : ' — all on time');
}
function lateHtml(f, cfg) {
  const box = 'font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:0 auto;border:1px solid #E3EAF3;border-radius:12px;overflow:hidden';
  const th = 'text-align:left;padding:7px 10px;font-size:11px;color:#5A708C;text-transform:uppercase;letter-spacing:.4px;border-bottom:2px solid #E3EAF3';
  const td = 'padding:7px 10px;font-size:13px;color:#0B2E52;border-bottom:1px solid #EFF4FA';
  let h = '<div style="' + box + '">';
  h += '<div style="background:linear-gradient(120deg,#001f3f,#0074D9);color:#fff;padding:18px 22px">'
    + '<div style="font-size:17px;font-weight:800">TaaSen — Field Attendance, punched late</div>'
    + '<div style="font-size:12px;opacity:.85;margin-top:4px">' + esc(f.today) + ' · SKD app punches read live · late means after ' + esc(f.cut) + ' IST</div></div>';
  h += '<div style="padding:16px 22px">';
  h += '<div style="font-size:13px;color:#0B2E52;line-height:1.7;margin-bottom:6px">'
    + '<b>' + f.lateN + '</b> punched after ' + esc(f.cut) + ' and <b>' + f.noneN + '</b> have no punch at all today, out of '
    + f.total + ' field officers. <b>State coordinators: please reply with the reason against each name.</b></div>';
  const keys = Object.keys(f.states).sort((a, b) => f.states[a].label.localeCompare(f.states[b].label));
  const clean = [];
  for (const k of keys) {
    const s = f.states[k];
    if (!s.late.length && !s.none.length) { clean.push(s.label + ' — all ' + s.onTime + ' on time'); continue; }
    const co = (cfg.coords[k] || []).join(', ');
    h += '<div style="margin-top:16px;border:1px solid #E3EAF3;border-radius:10px;overflow:hidden">';
    h += '<div style="background:#F4F8FC;padding:9px 12px;font-size:13.5px;font-weight:800;color:#0B2E52">' + esc(s.label)
      + ' — ' + s.late.length + ' late · ' + s.none.length + ' no punch · ' + s.onTime + ' on time'
      + (co ? '<div style="font-weight:600;font-size:11.5px;color:#0B4A8F;margin-top:2px">Coordinator: ' + esc(co) + ' — explanation awaited</div>'
            : '<div style="font-weight:600;font-size:11.5px;color:#8a4b00;margin-top:2px">No coordinator address saved for this state yet — add it on Settings → Late attendance mail</div>')
      + '</div>';
    if (s.late.length) {
      h += '<table style="width:100%;border-collapse:collapse"><tr><th style="' + th + '">#</th><th style="' + th + '">Field officer</th><th style="' + th + '">Region</th><th style="' + th + '">Punched at</th><th style="' + th + '">Mobile</th></tr>';
      s.late.forEach((o, i) => {
        h += '<tr><td style="' + td + ';color:#8496ab">' + (i + 1) + '</td><td style="' + td + ';font-weight:700">' + esc(o.name) + '</td>'
          + '<td style="' + td + '">' + esc(o.region || '—') + '</td>'
          + '<td style="' + td + ';font-weight:800;color:#B3261E">' + esc(o.punchText) + '</td>'
          + '<td style="' + td + '">' + esc(o.phone || '—') + '</td></tr>';
      });
      h += '</table>';
    }
    if (s.none.length) {
      h += '<div style="padding:8px 12px;background:#FDF3F2;font-size:12px;font-weight:800;color:#7F1D1D">No punch at all today — ' + s.none.length + '</div>'
        + '<table style="width:100%;border-collapse:collapse">';
      s.none.forEach((o, i) => {
        h += '<tr><td style="' + td + ';color:#8496ab;width:34px">' + (i + 1) + '</td><td style="' + td + ';font-weight:700">' + esc(o.name) + '</td>'
          + '<td style="' + td + '">' + esc(o.region || '—') + '</td>'
          + '<td style="' + td + ';font-weight:800;color:#7F1D1D">NO PUNCH</td>'
          + '<td style="' + td + '">' + esc(o.phone || '—') + '</td></tr>';
      });
      h += '</table>';
    }
    h += '</div>';
  }
  if (!f.lateN && !f.noneN) {
    h += '<div style="margin-top:14px;background:#F0FAF3;border:1px solid #BFE0C9;border-radius:10px;padding:12px 14px;font-size:13px;color:#0B5E2A;font-weight:700">Every field officer punched by ' + esc(f.cut) + ' today. Nothing to ask.</div>';
  }
  if (clean.length) {
    h += '<div style="margin-top:14px;font-size:12px;color:#1E7A3D"><b>On time, nothing to ask:</b> ' + esc(clean.join(' · ')) + '</div>';
  }
  h += '<div style="margin-top:16px;font-size:11px;color:#8496ab;line-height:1.6">Late is judged from the SKD app punch (attendanceDateTime) against ' + esc(f.cut) + ' IST, read live at send time. A man with no SKD attendance record at all is not listed — he is on the Field Tracker’s "not on SKD list" count, which is a data question, not an attendance one.</div>';
  h += '</div></div>';
  return h;
}
function lateText(f, cfg) {
  const L = ['TaaSen — Field Attendance, punched late', f.today + ' · late means after ' + f.cut + ' IST', ''];
  const keys = Object.keys(f.states).sort((a, b) => f.states[a].label.localeCompare(f.states[b].label));
  for (const k of keys) {
    const s = f.states[k];
    if (!s.late.length && !s.none.length) continue;
    L.push(s.label + ' — ' + s.late.length + ' late · ' + s.none.length + ' no punch · ' + s.onTime + ' on time');
    const co = (cfg.coords[k] || []).join(', ');
    if (co) L.push('  Coordinator: ' + co + ' — explanation awaited');
    s.late.forEach(o => L.push('  LATE   ' + o.punchText + '  ' + o.name + (o.region ? ' (' + o.region + ')' : '')));
    s.none.forEach(o => L.push('  NO PUNCH        ' + o.name + (o.region ? ' (' + o.region + ')' : '')));
    L.push('');
  }
  if (!f.lateN && !f.noneN) L.push('Every field officer punched by ' + f.cut + ' today. Nothing to ask.');
  return L.join('\n');
}

/* who the late mail goes to: every saved coordinator plus the default list he named —
   "Default sujith.dn@skdhealth.com, senthil@skdhealth.com, resourcemanager@skdhealth.net".
   One mail to everybody, so every coordinator sees his own state asked in front of the
   others; that is what makes the question land. */
function lateTo(cfg) {
  const to = [], seen = {};
  for (const a of cleanEmails(cfg.defaults)) { if (!seen[a]) { seen[a] = 1; to.push(a); } }
  for (const k in cfg.coords) for (const a of cleanEmails(cfg.coords[k])) { if (!seen[a]) { seen[a] = 1; to.push(a); } }
  return to;
}

export async function lateSweep(env, now) {
  const at = now || new Date();
  if (slotFor(at) !== 'evening') return { ok: true, sent: false, why: 'not the evening hour' };
  const cfg = await lateCfg(env);
  if (!cfg.on) return { ok: true, sent: false, why: 'switched off — turn it on at Settings → Late attendance mail' };

  const key = 'late:sent:' + istDayKey(at);
  if (env.USERS) {
    const already = await env.USERS.get(key).catch(() => null);
    if (already) return { ok: true, sent: false, why: 'already sent today' };
  }

  const f = await lateFigures(env, cfg);
  if (!f.live) return { ok: true, sent: false, why: 'SKD attendance could not be read — a mail calling every man absent would be a false accusation' };

  const to = lateTo(cfg);
  if (!to.length) return { ok: true, sent: false, why: 'nobody to send to — save coordinator or default addresses on Settings → Late attendance mail' };

  const res = await postMail(env, to, [], lateSubject(f), lateHtml(f, cfg), lateText(f, cfg));
  if (res.ok && env.USERS) {
    try { await env.USERS.put(key, JSON.stringify({ at: Date.now(), late: f.lateN, none: f.noneN }), { expirationTtl: 3 * 24 * 3600 }); } catch (e) {}
  }
  return { ok: true, sent: !!res.ok, late: f.lateN, none: f.noneN, to: to.length, via: res.via, error: res.error || '' };
}

/* ══════════ ROUTES ═══════════════════════════════════════════════════════════════════ */
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}
export async function handleDaily(request, env, ctx) {
  const url = new URL(request.url);
  const me = await currentUser(env, request);
  if (!me) return json({ ok: false, error: 'Please sign in to the portal first.' }, 401);
  /* the mail is the whole company's position — every manager, every state — so it is Admin
     and Management only, the same fence as the raw diagnostics */
  if (me.role !== 'admin' && me.role !== 'boss') {
    return json({ ok: false, error: 'The daily position mail is Admin and Management only.' }, 403);
  }

  /* CHECK A DATE — the instrument for "my office sheet says 327, the portal says 163".
     It answers with the SAME arithmetic the mail uses (buildReleases itself, handed the moment
     the mail for that date would have fired), but read TODAY — so it holds everything the
     hourly catcher has accumulated since, including the CM reviews that happened after the
     mail went. Run it a day or two after the date and the number has climbed toward his
     sheet; whatever gap remains provably never reached SKD's feed at all, which is Praveen's
     side to answer for. dd/mm/yyyy in, because that is how he writes dates. */
  if (url.pathname === '/api/daily/releases') {
    const q = String(url.searchParams.get('date') || '').trim();
    const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(q) ||
      (/^(\d{4})-(\d{2})-(\d{2})$/.test(q) ? [q, q.slice(8, 10), q.slice(5, 7), q.slice(0, 4)] : null);
    if (!m) return json({ ok: false, error: 'Give the date as dd/mm/yyyy — for example 18/08/2026.' }, 400);
    /* the moment that date's MORNING mail fired: the day after, 05:35 IST — buildReleases
       turns that into "the whole of <date>, 12:00 am to 11:59 pm", the mail's own window */
    const asAt = new Date(Date.UTC(+m[3], +m[2] - 1, +m[1] + 1, 0, 5, 0));
    const rel = await buildReleases(env, asAt, 'morning');
    const fold = box => Object.keys(box).map(k => ({ name: box[k].name || k, cases: box[k].cases, days: box[k].days, noDays: box[k].noDays || 0 }))
      .sort((a, b) => b.cases - a.cases || a.name.localeCompare(b.name));
    /* THE BUCKETS THEMSELVES, MEASURED. 19-Aug: "the TP bucket is not open — check Dikshith,
       Sangeetha, Swetha." A suspicion about a feed must become a row count. The three status
       buckets are probed DIRECTLY for this date's window — including dm-reviewed, which the
       portal has never read: if the missing TP closes are parked in THAT stage, its row count
       says so here, with evidence to take to Praveen instead of a feeling. */
    let buckets = null;
    try {
      const pad2 = n => ('0' + n).slice(-2);
      const dFrom = (+m[3]) + '-' + pad2(+m[2]) + '-' + pad2(+m[1]);
      const dTo = new Date(Date.UTC(+m[3], +m[2] - 1, +m[1] + 1)).toISOString().slice(0, 10);
      const qs2 = 'fromDate=' + dFrom + '&toDate=' + dTo;
      const tmo = { timeoutMs: 30000 };
      /* paged, since 20-Aug-2026: page 2 and page 3 of cm-reviewed carry real closed cases
         the plain call never shows — the probe must count what the feed can actually serve,
         not just its first page */
      const [cm, qc, dm] = await Promise.all([
        probeStatusListPaged(env, 'cm-reviewed', qs2, tmo),
        probeStatusListPaged(env, 'qc-reviewed', qs2, tmo),
        probeStatusListPaged(env, 'dm-reviewed', qs2, tmo)
      ]);
      const shape = d => ({ rows: d.rows, http: d.httpStatus, error: d.error || '', pages: d.pages || [] });
      buckets = { cmReviewed: shape(cm), qcReviewed: shape(qc), dmReviewed: shape(dm) };
      /* count the TP-typed rows each bucket actually served — "is the TP side of the feed
         alive" answered as a number, through the same typeOfSub every table uses */
      const tpOf = d => d.list.reduce((n2, row) => {
        const sub = row && (row.subProduct || row.sub_product || row.subproduct || row.product || '');
        return n2 + (typeOfSub(String(sub)) === 'TP' ? 1 : 0);
      }, 0);
      buckets.cmReviewed.tpRows = tpOf(cm); buckets.qcReviewed.tpRows = tpOf(qc); buckets.dmReviewed.tpRows = tpOf(dm);
    } catch (e) { buckets = { error: String((e && e.message) || e) }; }
    const dmRows = buckets && buckets.dmReviewed && buckets.dmReviewed.rows;
    return json({
      ok: rel.ok, why: rel.why || '', date: m[1] + '/' + m[2] + '/' + m[3], window: rel.win && rel.win.label,
      total: rel.total, qcIncluded: rel.qcInWin, undated: rel.undated, cashless: rel.cashTotal,
      TP: fold(rel.TP), Health: fold(rel.Health), buckets,
      dmNote: dmRows
        ? ('SKD\u2019s dm-reviewed bucket answered ' + dmRows + ' row' + (dmRows === 1 ? '' : 's') + ' for this window \u2014 a stage this portal does not read today. ' +
           'If the missing releases are parked there, that is the wiring to add \u2014 say the word.')
        : '',
      note: 'This is everything the portal holds for that date RIGHT NOW — the live feed plus every case the hourly ' +
        'catcher has kept since, including CM reviews that happened after that date’s mail went out. This number grows ' +
        'for a day or two as CM reviews catch up. If your office sheet still says more after that, the remainder never ' +
        'reached SKD’s closed-case feed at all — the portal cannot count a case it was never shown, and that gap is ' +
        'SKD’s side to answer for.'
    });
  }

  if (url.pathname === '/api/daily/preview') {
    const slot = url.searchParams.get('slot') === 'evening' ? 'evening' : 'morning';
    const fig = await buildDaily(env, slot);
    return new Response(dailyHtml(fig, slot), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }

  if (url.pathname === '/api/daily/json') {
    const fig = await buildDaily(env, slotFor(new Date()) || 'morning');
    return json({
      ok: true, fig, subject: subjectFor(fig, slotFor(new Date()) || 'morning'),
      mailTo: (await dailyRecipients(env)).to, mailCc: (await dailyRecipients(env)).cc,
      senderReady: !!(env.OTP_MAIL_URL || env.BREVO_API_KEY),
      slots: ['05:30 IST', '17:30 IST']
    });
  }

  /* A TEST COPY GOES TO THE PERSON WHO PRESSED IT AND TO NOBODY ELSE. Not to DAILY_MAIL_TO —
     a "test" that mails the whole management team is not a test, it is the live mail sent by
     accident, and there is no way to take that back. */
  if (url.pathname === '/api/daily/test' && request.method === 'POST') {
    if (me.role !== 'admin') return json({ ok: false, error: 'Admin only.' }, 403);
    const slot = slotFor(new Date()) || 'morning';
    const fig = await buildDaily(env, slot);
    const res = await probeMail(env, [me.email], [], '[TEST] ' + subjectFor(fig, slot), dailyHtml(fig, slot), dailyText(fig, slot));
    /* `said` comes back either way. A relay that accepts the job and silently drops it looks
       identical to one that sent — its own answer is the only thing that tells them apart, so
       it is shown even on success rather than only when something already went wrong. */
    return json({
      ok: !!res.ok, sentTo: me.email, via: res.via, status: res.status || 0,
      error: res.error || '', said: res.said || '',
      shape: res.shape || '', tried: res.tried || [],
      note: res.ok ? 'Sent to you only — the team list was not used.' : ''
    }, res.ok ? 200 : 502);
  }

  /* ── WHO IT GOES TO ────────────────────────────────────────────────────────────────
     Admin only, like everything else on this route. Saving an EMPTY list is allowed and is
     how the mail is switched off from the portal — so the answer always says plainly whether
     anybody is on it, rather than leaving "saved" to imply "on". */
  if (url.pathname === '/api/daily/recipients') {
    if (request.method === 'GET') {
      const who = await dailyRecipients(env);
      /* v14.5 — today's two slots, read from the sent + attempt registers, so "why didn't I
         receive it" is answered by the card instead of by an investigation. */
      const today = {};
      if (env.USERS) {
        const day = istDayKey(new Date());
        for (const sl of ['morning', 'evening']) {
          let sent = null, tried = null;
          try { const r = await env.USERS.get('daily:sent:' + day + ':' + sl); if (r) sent = JSON.parse(r); } catch (e) {}
          try { const r = await env.USERS.get('daily:try:' + day + ':' + sl); if (r) tried = JSON.parse(r); } catch (e) {}
          today[sl] = { sent, tried };
        }
      }
      return json({ ok: true, on: who.to.length > 0, to: who.to, cc: who.cc, source: who.source,
        setBy: who.setBy, setTs: who.setTs, storage: !!env.USERS,
        senderReady: !!(env.OTP_MAIL_URL || env.BREVO_API_KEY),
        /* v12.3 — whose name the mail goes out under (see mailFromName above) */
        fromName: await mailFromName(env), fromDefault: FROM_DEFAULT,
        today, nowIst: istPretty(new Date()),
        slots: ['05:30 IST', '17:30 IST'], me: me.email });
    }
    if (request.method === 'POST') {
      if (me.role !== 'admin') return json({ ok: false, error: 'Admin only.' }, 403);
      if (!env.USERS) return json({ ok: false, error: 'Storage is not available, so the list cannot be saved here.' }, 501);
      let b; try { b = await request.json(); } catch (e) { b = {}; }
      const to = cleanEmails(b && b.to), cc = cleanEmails(b && b.cc);
      /* what was thrown away is reported, not swallowed — a typo silently dropped is a person
         who quietly never gets the mail and nobody finds out for a month */
      const asked = (Array.isArray(b && b.to) ? b.to : String((b && b.to) || '').split(/[,;\s]+/)).map(x => String(x || '').trim()).filter(Boolean);
      const rejected = asked.filter(a => to.indexOf(a.toLowerCase()) === -1);
      await env.USERS.put(DAILY_KV_KEY, JSON.stringify({ to, cc, setBy: me.name || me.email, setTs: Date.now() }));
      /* the sender name rides the same Save. Only touched when the box was actually sent
         (an old browser still on v12.2 must not wipe it); emptied on purpose = back to the
         default, which the answer says rather than leaving a blank to mean something. */
      if (b && typeof b.fromName === 'string') {
        const n = cleanFromName(b.fromName);
        if (n) await env.USERS.put(FROM_KV_KEY, JSON.stringify({ name: n, setBy: me.name || me.email, setTs: Date.now() }));
        else { try { await env.USERS.delete(FROM_KV_KEY); } catch (e) {} }
      }
      return json({ ok: true, on: to.length > 0, to, cc, rejected,
        fromName: await mailFromName(env),
        note: to.length ? '' : 'Nobody is on the list, so the daily mail is now OFF.' });
    }
  }

  /* ── THE LATE-ATTENDANCE MAIL — config + test (see lateSweep above) ────────────────── */
  if (url.pathname === '/api/daily/late-config') {
    if (request.method === 'GET') {
      const cfg = await lateCfg(env);
      const f = await lateFigures(env, cfg);
      const states = Object.keys(f.states).sort((a, b) => f.states[a].label.localeCompare(f.states[b].label))
        .map(k => ({ key: k, label: f.states[k].label, emails: cleanEmails(cfg.coords[k]),
                     lateToday: f.states[k].late.length, noneToday: f.states[k].none.length, onTimeToday: f.states[k].onTime }));
      return json({ ok: true, on: cfg.on, after: cfg.after, defaults: cleanEmails(cfg.defaults),
        states, live: f.live, today: f.today, lateN: f.lateN, noneN: f.noneN, onTimeN: f.onTimeN,
        to: lateTo(cfg), setBy: cfg.setBy, setTs: cfg.setTs, storage: !!env.USERS });
    }
    if (request.method === 'POST') {
      if (me.role !== 'admin') return json({ ok: false, error: 'Admin only.' }, 403);
      if (!env.USERS) return json({ ok: false, error: 'Storage is not available, so this cannot be saved here.' }, 501);
      let b; try { b = await request.json(); } catch (e) { b = {}; }
      const after = lateAfterClean(b && b.after) || LATE_AFTER_DEFAULT;
      const coords = {};
      if (b && b.coords && typeof b.coords === 'object') {
        for (const k of Object.keys(b.coords).slice(0, 40)) {
          const emails = cleanEmails(b.coords[k]);
          if (emails.length) coords[String(k).toLowerCase().slice(0, 60)] = emails;
        }
      }
      const saved = { on: !!(b && b.on), after, coords, defaults: cleanEmails(b && b.defaults),
        setBy: me.name || me.email, setTs: Date.now() };
      await env.USERS.put(LATE_KV_KEY, JSON.stringify(saved));
      return json({ ok: true, on: saved.on, after: saved.after, defaults: saved.defaults,
        coordStates: Object.keys(coords).length, to: lateTo(saved) });
    }
  }
  /* one copy, to the presser alone — never to the coordinators from a test button */
  if (url.pathname === '/api/daily/late-test' && request.method === 'POST') {
    if (me.role !== 'admin') return json({ ok: false, error: 'Admin only.' }, 403);
    const cfg = await lateCfg(env);
    const f = await lateFigures(env, cfg);
    if (!f.live) return json({ ok: false, error: 'SKD attendance could not be read just now, so there is nothing true to send. Try again in a minute.' }, 502);
    const res = await probeMail(env, [me.email], [], '[TEST] ' + lateSubject(f), lateHtml(f, cfg), lateText(f, cfg));
    return json({ ok: !!res.ok, sentTo: me.email, late: f.lateN, none: f.noneN,
      error: res.error || '', said: res.said || '', shape: res.shape || '', tried: res.tried || [],
      note: res.ok ? 'Sent to you only — no coordinator was mailed.' : '' }, res.ok ? 200 : 502);
  }

  return json({ ok: false, error: 'Unknown daily route.' }, 404);
}
