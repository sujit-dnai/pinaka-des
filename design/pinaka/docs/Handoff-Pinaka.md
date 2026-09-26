# Pinaka · developer hand-off (Expenses, Translator, Tracking, Full app, Client role)

Read this together with `Handoff-CaseSync.md`, which covers the case sync, meetings ring, fines and Excels. Rules and decisions are in `briefs/QUEUE.md`; source briefs are in `briefs/BRIEFS.md`. Repo: `sujit-dnai/skd-portal` (Cloudflare Worker, D1, KV, R2). All data in the designs is **sample**.

## 0. Global rules
- **No logout anywhere** (FO or client). Sign in once with Employee ID + password, then a 4–6 digit PIN each day. Only admin revokes a device: `POST /api/app/device/revoke`.
- **Look:** navy `#001F3F` → `#0074D9` gradient. IBM Plex Sans / Mono; Material Symbols Rounded in the app, Font Awesome in the portal. Logo `assets/pinaka-eagle.png`.
- **Sizes:** every screen is drawn for Android 360×800 and iPhone 390×844, light and dark. Portal screens are 1440.
- **Language chip on every header:** EN, Tamil, Telugu, Kannada, Malayalam, Marathi, Hindi.
- **Colour tokens:** each phone DC defines light/dark CSS variables at its root (`--bg --card --ink --body --mut --line --sky --blue --link --ok/okt/okb --red/redt/redb --amb/ambt`). Reuse these names in Flutter / React Native themes.
- **Reading the designs:** each phone component takes the props `platform` (android/ios), `theme` (light/dark) and `scene`. Open a component file and use Tweaks → scene to step through its states.

## 1. File map
| Design (canvas) | Phone / portal components | Scenes |
|---|---|---|
| `Case Sync.dc.html` | `CaseSync`, `PortalSync` | see Handoff-CaseSync.md |
| `Expenses.dc.html` | `ExpenseApp`, `PortalExpense` | list, loading, empty, error, offline, create, purpose, autoErr, fuel, train, noexp, noDoc, attach, dup, expired, success, trip, tripTrain, missed, month · portal: queue, change, reject, admin |
| `Translator.dc.html` | `TranslatorApp`, `PortalTranslator` | fr, remark, expense, perm, denied, lang, record, converting, result, added, silence, noisy, offline, saved, blocked · portal: case, settings |
| `Tracking.dc.html` | `TrackApp`, `PortalTrack` | moving, stopped, oem, low20, low10, locOff, mock, offDuty · portal: live, fo, route, config |
| `Pinaka Full App.dc.html` | `FullApp`, `VerifyApp`, `ClientApp` (+ earlier files linked in its index) | FullApp: login, pin, punch, late, homeA/B/C, cardsA/B/C, today, todayMissed, profile · VerifyApp: tp, camA/B/C, stamp, hStart, h8, hReached, hMoved, mDay2, mDay3, mFine · ClientApp: home, list, detail, approve, urgent, report, profile |
| Earlier | `Final Report.dc.html`, `Shared Case.dc.html`, `Team Chat Mentions.dc.html` | own Components-*.md files |

Pick **one** of the three Home layouts (A next action / B day timeline / C map), one of the three case-card designs, and one of the three camera layouts before build. Sujit decides.

## 2. Expenses
**Kept verbatim from today:** titles "Add Expense Details" / "Create Expenses", "Create (+)", the summary strip, the 9 purposes, the caps (Auto ₹80, Food ₹100, MRD ₹2,000, Room ₹2,500, the others no limit, No Expenses = ₹0), every hint, banner and error string, the 4 attach sources, "Submitting..." → "Expense added successfully ✅" + "Expense ID", and Create Courier after.

**New:**
- **Fields:** `expense_date` (≥ allocation date, not in the future). For travel: `from`, `to`, `tp_id`, and `mode` (Bike / Bus / Train / Auto-Taxi). Mode maps to a purpose: Bike → Fuel, Bus → Bus Ticket, Train → Train Ticket, Auto-Taxi → Auto Fare.
- **Bike:** `km = GPS distance from the case "started" event to the "completed" event` (moving points only, see §4). `amount = km × rate_per_km`, where the rate comes from Field Masters and is **still to be given by Sujit** (the design shows ₹4.00 as a sample). No bill is needed. If the officer edits the km, a reason is required and the row is flagged "km edited".
- **Bills:** several per expense. Photos are made smaller (~300 KB) and PDFs are kept as they are. apk/html/svg/exe/js are blocked. 10 MB maximum per file.
- **Remarks:** optional, 200 characters, with the Translator.
- **Duplicate guard:** same claim + purpose + day + amount ±10% → "Looks like a duplicate — submit anyway?".
- **Offline:** queued as "Waiting to send".
- **Travel step inside the Final Report flow** (`trip`): shown before Complete Case. The GPS trail is already measured. The officer can press "Add travel expense" or "No travel" (which stores `travel_none=1`).
- **Missed expense** (`missed`): `GET /api/fo/v1/expenses/missing` returns completed claims with no travel row and no `travel_none`, allowed for 30 days after completion. Tapping one opens the trip step pre-filled.
- **Status:** Submitted → OHS → State Coordinator → Admin → Paid. Each level can approve, approve a changed amount (note required) or reject (note required). A reject returns to the officer. Edit and delete are allowed only while Submitted and before OHS acts.
- **Portal Approvals → Expenses:** one tab per level. Flags: at cap, duplicate suspected, fuel km ≫ GPS km, bill date outside the case dates. Bulk approve works only for rows within cap and with no flag. Monthly totals go to Accounts → Payouts, which writes "Paid" back.

**D1:** add `mode, from_place, to_place, tp_id, km_gps, km_used, km_reason, rate, level (1 OHS / 2 SC / 3 Admin), l1_by/at/note, l2_by/at/note, l3_by/at/note, approved_amount, paid_at, travel_none` to the expenses table. Add a new table `expense_bills (expense_id, r2_key, mime, bytes)`.

## 3. Translator mic
**Kept verbatim:** every message used today (see BRIEFS §6), and the silence filter.

**New:**
- **The button:** one shared `Translator` component (mic icon plus a small "Translator" label) beside every free-text box: the 8 existing boxes plus Expense Remarks, TP Files Remarks, Case Completion Reason details, Leave Reason, Advance Salary Reason, Courier Remarks, Courier "Reason for not attaching", and the send-back reply.
- **Language chip:** Tamil, Telugu, Kannada, Malayalam, Hindi, Marathi, English or Auto. The default is the profile language, otherwise the state's language. The last pick is remembered.
- **Recording:** a 2:00 limit, auto-stop after 4 s of silence, Pause, Cancel and a level bar. Audio is mono 16 kHz Opus/AAC at 24–32 kbps.
- **Result card:** the English (editable) and "Heard in {lang}". The buttons are **Add to text (default, appends)**, Replace text, Try again and Discard. Digits and insurance words (FIR, MACT, IP number, PED, MLC, OP/IP, cashless) are kept as spoken.
- **Errors:** add "Too noisy — move to a quieter place and try again". The permission explainer says "Pinaka needs the microphone only while you hold Translator"; if denied, show Open Settings.
- **Offline:** the clip is saved and a chip shows "Voice waiting to convert (0:25)". It converts when back online, and a notification brings the officer back to the box. **The Final Report cannot be submitted while a clip waits.**
- **API:** `POST /api/fo/v1/voice {fileId|audio, lang, field, caseId}` → `{english, original, lang, seconds, confidence, engine}`. Engine order: Sarvam Saaras → OpenAI Whisper → Workers AI, with an 8 s fallback. Limit 60 clips per officer per day, a monthly cap with an alert at 80%, and a `voice_usage` log.
- **Proof:** on by default. Audio is stored in R2 and the portal shows ▶ plus a "Voice" tag, the Tamil heard, the engine and the confidence.
- **Portal Settings → Translator:** engine order (drag to reorder), max seconds, clips per day, monthly cap, silence seconds, keep audio, and the language for each officer.

## 4. Tracking (design only, to be built later)
- **Phone:** tracking runs while moving; when still for `still_minutes` it counts a stop and sleeps. One ongoing notification shows "On duty · Moving" or "On duty · Stopped since {time}". It changes only on a state change, with no sound or vibration.
- **OEM guide:** shown once, from `Build.MANUFACTURER` (Xiaomi, Oppo, Vivo, Realme, Samsung). It has two steps with deep links where they exist.
- **Battery:** below 20%, send every 20 min. Below 10%, send only stops and case events, and the portal shows "Phone silent".
- **Bad states:** permission removed, "while using" only, or location off → a red banner on the phone and red on the portal. `isMock` or a jump faster than `speed_flag_kmh` → the point is flagged, not dropped.
- **Auto-stop:** tracking stops at `auto_stop_time`, or when the day closes.
- **Portal Live Board** has 6 states: Moving (blue), Stopped at {place} since {time} (green), No status 45 min (grey), Location off / permission removed (red), Phone silent (amber), Off duty.
- **FO 360:** the day timeline with punch, commitment, meeting, accepts, stops, GPS-off and 6 PM updates, plus phone health.
- **Route Tracking:** moving segments drawn as lines and stops as dots sized by duration. The day's km comes from moving points only; flagged jumps are dashed red.
- **Allocate:** the Nearest Officer ranking uses the current stop point as the officer's position.
- **Remote Config:** 12 keys with their defaults, listed in `4d` (still_minutes 5, geofence 150 m, filters 50/200 m, batch 20 / 10 min, status sync 30 min, battery 20/10%, auto-stop 21:00 IST, grey 45 min, speed flag 150 km/h). The phones read them on the next sync.

## 5. Full app flows (the rules the app must enforce)
1. **Login:** Employee ID + password and a role pick (Field Officer / Insurer client). The device token is stored in secure storage. A PIN is set at first login and asked daily; biometric is optional. "Forgot PIN" means the manager resets it.
2. **Punch:** a full-screen punch opens from 07:00 and stays until the officer checks in. It takes a selfie and the GPS stamp, and the selfie goes to the portal dashboard tile. After 08:30 the day is tagged **Late** and a reason is required (with Translator). There is no check-out selfie.
3. **Morning commitment:** straight after the punch. Every held case needs a plan and a time, and new cases are held back until it is saved (Case Sync `2e`).
4. **Home:** one of the 3 layouts. A shows the next action from the commitment, B shows the day timeline, C shows a map with the nearest cases first.
5. **Cases:** the TAT chip shows "2d 4h left", turns amber at 1 day left and red when out of TAT. While any case is out of TAT the red banner "Release these first. No new cases until then." shows and allocation is blocked.
6. **Touch points:** Verify opens the chosen camera layout. Every photo carries the GPS stamp: mini map, lat/long, date-time GMT +05:30, address, claim and officer. The stamp is burned into the image and the raw EXIF is kept. Reject needs a reason.
7. **Health (all products):** Accept → Start → "I have reached" + GPS photo within 24 h. At 8 h the warning "16 hours left or this case moves" shows. At 24 h the case moves by itself with no manager step (server cron).
8. **Motor TP:** start within 3 days, with warnings on day 2 and on the morning of day 3. If not started, ₹50 is fined. There is no auto-move.
9. **Today's work:** opens from 18:00. Every held case needs an update, and all must be saved by 19:30 to close the day. Otherwise ₹250 is fined, the manager is flagged, and the updates must be finished before the next punch (`todayMissed`).
10. **Profile:** Fine Amount (breakup + appeal), My Expenses, Attendance, Leave, Advance Salary, Language, Change PIN, Battery settings, and the line "Only the admin can sign this phone out". There is no logout.

## 6. Insurer client role
- **Scope:** only the cases of the client's own company (and the client's own SPOC teams). They can see the officer's first name and city, the TaaSen SPOC and touch-point progress. They never see an officer's phone number or live location.
- **Home:** counts (Allocated, In field, FO Completed, Released this month, Out of TAT, Lok Adalat flagged) and a banner for any approval waiting. **TAT is counted from the insurer's own allocation date.**
- **Approvals:** the police document charge flow. TaaSen raises `{claim, station, for, amount}`, the client approves or declines with an optional note, and TaaSen pays only after approval. The receipt is attached to the case.
- **Urgent release:** reason (National Lok Adalat, Court date, Customer escalation, Other) and a release-by date. It sends an alert to the SPOC and the officer, and a Lok Adalat chip appears on every list. These rows feed the Lok Adalat / TAT scan.
- **Released:** the conclusion and summary. The files are the Final report PDF, FIR and documents, GPS-stamped photos and voice statements. "Download all" gives a ZIP.
- **API:** `GET /api/client/v1/cases?status=`, `GET /api/client/v1/cases/{claim}`, `POST /api/client/v1/approvals/{id} {approve|decline, note}`, `POST /api/client/v1/cases/{claim}/urgent {reason, by}`, `GET /api/client/v1/cases/{claim}/files`.

## 7. Still to come from Sujit
- The per-km bike rate for travel expenses.
- The Motor-TP reason lists for Discrepant and Inconclusive.
- The rating formula ("rating goes down" per missed accept or Motor TP not started).
- The choice of Home layout, case-card design and camera layout (A / B / C each).
- A native speaker's check of the Tamil sample line in Translator.
