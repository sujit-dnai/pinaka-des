# Pinaka work queue (order agreed 26-09-2026)

1. @Mention in Team Chat (app + portal) — DONE → `Team Chat Mentions.dc.html`
2. Multi-allocation — DONE → Shared Case.dc.html
3. Final Report + Case Complete Report — DONE → Final Report.dc.html — brief pasted 26-09-2026; Motor-TP reason lists "TO BE GIVEN BY SUJIT"
0. Case sync portal ↔ app + Daily Meetings ring + Fine Amount + Excels — DESIGN DONE → Case Sync.dc.html (CaseSync + PortalSync). Hand-off → Handoff-CaseSync.md.
4. Expenses (app + portal Approvals → Expenses) — DESIGN DONE → Expenses.dc.html (ExpenseApp + PortalExpense) — brief pasted 26-09-2026; fuel rate TO BE GIVEN BY SUJIT
   + 26-09 evening: travel expense step inside Final Report flow (before Complete Case); "Missed expense" list of claims without travel (30 days); travel mode Bike/Bus/Train/Auto-Taxi, Bike = GPS km Start→Complete × per-km rate (rate TO BE GIVEN; sample ₹4/km), no bill; FO expenses approved OHS → State Coordinator → Admin.
5. Translator mic (all free-text boxes + portal Settings/▶) — DESIGN DONE → Translator.dc.html (TranslatorApp + PortalTranslator)
6. Tracking rebuild — DESIGN DONE → Tracking.dc.html (TrackApp + PortalTrack) — DESIGN ONLY: notification states, OEM battery guide, Live Board / FO 360 / Route Tracking states, Remote Config keys note
7. Full Pinaka app (15 screen groups) — DESIGN DONE → Pinaka Full App.dc.html (FullApp, VerifyApp, ClientApp) + earlier files linked in its index

Every pass: Android 360x800 + iPhone 390x844, light + dark, portal 1440 where asked. Sample data marked "sample".
Reference: uploads/pasted-1790412307127-0.png = today's Case Workspace (header chat + call icons, Workspace Tools grid, green "Final Report for Case").

## Decisions 26-09-2026 (case sync round)
- Source: taasenclaims.com portal API (new /api/app/cases). Arrival: push + full-screen alarm (Ola/Uber style, rings till opened) + list.
- 20-min accept only 8 AM–8 PM; night assignments start 8:00, fine at 8:20. Re-assigned case: vanishes with notice.
- Fines → profile "Fine Amount" with breakup + appeal: not accepted 20 min ₹50; day update after 7:30 PM ₹250; daily FO meeting (OHS TL) missed ₹100; State Coordinator meeting missed ₹100; GPS off on duty ₹50 (+ app lock, manager alert, Live Board red); Motor TP not started 3 days ₹50. Late >10 min = missed.
- Meetings: only Boss/OHS/State Coordinator/managers start from portal Daily Meetings; Connect rings only ticked people, full-screen 2 min, Join / Can't join + reason.
- Morning commitment: at punch-in per held case (plan + time), blocks new cases until saved.
- Excels: monthly fine (admin only), daily updates, commitment vs actual, TAT alerts.

## Decisions for the full app (from Q&A rounds)
- Logo: eagle = Pinaka mark; app name "Pinaka". Icons: Material Symbols Rounded. Font: IBM Plex Sans / Mono (portal).
- Language toggle on every header: EN, Tamil, Telugu, Kannada, Malayalam, Marathi, Hindi (main labels + tabs; questions shown in the officer's language; voice → AI English, show native text + English below).
- Login: Employee ID + password once, then 4–6 digit PIN daily unlock. NO logout anywhere; only admin signs a phone out from the portal. Role picked at login (FO / Insurer client).
- Attendance: full-screen "Punch attendance" from 7:00 AM until check-in, selfie + GPS, selfie shows on portal dashboard (mock the portal tile). After 8:30 AM = Late tag + reason note. No check-out selfie: from 6:00 PM "Today's work" asks an update for every held case; all saved before 7:30 PM closes the day. Missed updates flagged to manager; must be finished next morning before the punch.
- New case: accept within 20:00 countdown; at 0 warning "₹50 deducted for this case, no verification bata, rating goes down".
- Out-of-TAT cases block new allocation: red banner "Release these first. No new cases until then."
- TAT from uploads/tat_excel-*.xlsx (48 products; 15 Motor TP, 33 Health). Card shows "2d 4h left"; amber at 1 day left, red when out.
- Health (all products): after Accept → Start → "I have reached" + GPS photo within 24 h; at 8 h "16 hours left or this case moves"; at 24 h auto-moved, no manager step.
- Motor TP: start within 3 days; warnings day 2 and day 3 morning; ₹50 fine if not started; no auto-move.
- GPS photo stamp: mini map + lat/long + date-time + address strip (GPS Map Camera style).
- Variations: 3 Home layouts, 3 Verify camera layouts, 3 Case card designs. Presentation: canvas + live phone. Hand-off: page + Markdown.
