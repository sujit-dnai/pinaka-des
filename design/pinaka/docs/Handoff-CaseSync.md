# Hand-off · Case sync, meetings, fines (portal ↔ Pinaka app)

Design: `Case Sync.dc.html` (app: `CaseSync.dc.html`, portal: `PortalSync.dc.html`). Rules: `briefs/QUEUE.md` → "Decisions 26-09-2026". Repo: `sujit-dnai/skd-portal` (Cloudflare Worker `skd-portal`, D1, KV, `entry.js` routing). All data in the mockups is sample.

## 1. Where it lives
- New module `app-index.js`, mounted in `entry.js` as `/api/app/*`. It is a machine path (`isMachinePath`), so there is no host redirect.
- Auth: the phone keeps a long-lived device token issued at Employee ID + password login and unlocked daily by PIN. There is **no logout**. Only admin revokes a device (`POST /api/app/device/revoke`, portal Field Officers page).
- Cases still come from SKD / PINAKA core. The portal stays the only door that assigns cases: the Allocate tab → `POST /assign/{claim}/assign-fo` (v20.0) and auto-assign. After SKD accepts, the Worker writes an `app_events` row and sends the push.

## 2. D1 tables (new)
| table | key columns |
|---|---|
| `app_devices` | `id, fo_user, platform (android/ios), push_token, app_version, last_seen, revoked_at` |
| `app_assign` | `claim, fo_user, part (TP ids, for shared cases), assigned_by, assigned_at, clock_starts_at, accept_by, accepted_at, rejected_at, reject_reason, fined` |
| `app_events` | `id, claim, fo_user, kind, payload_json, at_phone, at_server` (append-only; the phone's own time is kept too) |
| `app_location` | `fo_user, lat, lng, acc, moving, at` (downsampled; the Live Board reads the latest row) |
| `app_gps_off` | `id, fo_user, off_at, on_at, fined` |
| `app_commit` | `date, fo_user, claim, plan (Visit/Call/Documents/Report), plan_time, note, actual, done` |
| `meetings` / `meeting_ring` | `meeting: id, name, host, time, repeat` · `ring: meeting_id, person, rung_at, answered_at, joined_at, declined_reason, missed` |
| `fines` | `id, fo_user, rule, ref (claim/meeting/gps id), at, amount, status (added/appeal/waived/kept), appeal_text, appeal_proof, decided_by, decided_at` |

## 3. API
| door | who | what |
|---|---|---|
| `GET /api/app/cases?since=` | FO | Cases held, deltas since the cursor. Fields: claim, insurer/client, product, sub-product, insured name, accident/admission date, address, lat/lng, TAT due (from the TAT sheet, 48 products), touch points (own part; another officer's part shown without address, read-only), manager, allocated_by, allocated_at, status, `accept_by` |
| `POST /api/app/cases/{claim}/accept` | FO | → SKD accept for the officer's part; portal status FO Accepted |
| `POST /api/app/cases/{claim}/reject` | FO | `{reason, details}` → manager alert, case back to Allocate |
| `POST /api/app/cases/{claim}/event` | FO | `{kind: started, reached, tp_saved, tp_rejected, final_report, completed}`; `reached` carries the GPS photo (stamp: map, lat/long, time, address) |
| `POST /api/app/location` | FO | batch of points; `moving` flag; sent only while on duty |
| `POST /api/app/gps` | FO | `{state: off/on, at}`; the phone also sends it on the next boot if it was off |
| `POST /api/app/commit` | FO | the morning plan for every held case; must be saved before new cases are sent |
| `POST /api/app/day-update` | FO | the evening update per held case; the day closes when every case is saved before 7:30 PM |
| `GET /api/app/fines?month=` · `POST /api/app/fines/{id}/appeal` | FO | breakup + appeal `{why, text, proof}` |
| `POST /api/meet/new` · `POST /api/meet/{id}/connect` | Boss, OHS, State Coordinator, manager (`canHostMeeting()`; refuse FO and client **by name**, as `foreq-index.js` does) | Ticked people + teams (OHS teams from the OHS Team page) → one ring per person |
| `POST /api/app/meet/{id}/answer` | anyone rung | `{join}` or `{decline, reason}` |
| `GET /api/fines/export?month=` | **admin only** | monthly fine Excel |
| `GET /api/reports/{daily-updates, commitment, tat-alerts}.xlsx` | admin, manager | the other three Excels (columns shown on `6e`) |

## 4. Push and ring
- FCM data message, high priority. On Android: a full-screen-intent notification on its own channel (alarm sound, vibration, bypasses DND where the OS allows) that repeats until the case is opened. On iOS: a time-sensitive / critical alert, with a VoIP push (CallKit) for meeting rings.
- Kinds: `case_new`, `case_moved`, `tat_amber` (1 day left), `tat_red`, `meet_ring`, `fine_added`, `gps_off_warn`.
- **Meeting ring:** full screen for 2 minutes or until answered. People signed in only on the portal are rung through the existing `/api/alerts` bell (`ring on`).

## 5. Timers and rules (server-side cron every minute; the phone only displays them)
- **Accept window:** `clock_starts_at = assigned_at` when that falls between 08:00 and 20:00 IST, otherwise the next 08:00. `accept_by = clock_starts_at + 20 min`. If there is no accept by then: fine ₹50, no verification bata, rating goes down, `app_assign.fined = 1`.
- **Out of TAT:** while an officer holds any case out of TAT, `/api/app/cases` sends no new cases and the portal Allocate tab shows the reason.
- **Health:** after Accept → Start → reached + GPS photo within 24 h. A warning goes at 8 h. At 24 h the case is auto-moved.
- **Motor TP:** start within 3 days, with warnings on day 2 and the morning of day 3. Not started: ₹50. No auto-move.
- **Day update:** from 6:00 PM, due by 7:30 PM. Missed: ₹250, the manager is flagged, and it must be finished before the next morning's punch.
- **Meeting:** joining more than 10 min after the start counts as missed → ₹100 (daily FO meeting and State Coordinator meeting alike). Declining with a reason still counts as a fine, which the officer can appeal.
- **GPS off on duty:** the app locks, the manager is alerted, the Live Board row turns red, and ₹50 is fined per time.
- **Fines:** every fine goes to `fines` with status `added`. An appeal sets `appeal`. The manager or admin sets it to `waived` or `kept`. The month's total is the sum of added + kept.

## 6. Re-assign / revoke
When SKD's `caseHistory` shows the part moved (replayed in order, as `foFolderMap` already does), the next `/cases` delta sends `{claim, moved_to, by, at}`. The phone removes the card and shows the notice (`2c`). The officer's uploads stay with the case.

## 7. Offline
- The phone keeps the last case list and queues every POST with `at_phone`. The server orders events by `at_phone` but judges timers by `at_server`, so an accept sent late after offline is still fined.
- The phone shows the banner "Offline · cases as of {time} · your actions send when online" (`2b`).

## 8. Open items
- The fuel rate and the Motor-TP reason lists are still to be given by Sujit (queue items 3 and 4).
- Rating formula: how much "rating goes down" per missed accept.
- Meeting room engine for more than three people (the portal's note: "the engine that carries 300 is the next build").
