# Shared case (multi-allocation) — component list (hand-off to Claude Code)

Design: `Shared Case.dc.html` (app: `SharedCase.dc.html` with viewer = sujit | franklin; portal: `PortalShared.dc.html`). Sample: MOT17819657, Chola MS; Sujit D N (Lead, Chennai: Hospital, Doctor); Franklin (Madurai: Insured, Petitioner, Police Station).

## Keep
- Own touch points per officer (his part); other officer's folders shared read-only: "This folder is shared. Upload is disabled for your login."
- Portal counts every officer on a shared case with his own status.
- Workspace Tools, attendance, tracking (personal).

## New (app)
- SharedChip: "Shared · 2 officers", "with {name}", one status for each part (Assigned → Accepted → Part completed / Rejected). Accept or reject only your own part.
- OfficerColour: Sujit #0074D9, Franklin #F97316 (by allocation order) on chips, bar, pins, stamp, timeline.
- TouchPointGroups: "My touch points" (Verify photo, Form, Files, Reject, address, Navigate) / "{name}'s touch points" (read-only, "Address with {name}", View, "Not done yet by {name}").
- SplitProgress: "Mine 2/2 · Case 4/5".
- ReadOnlyTouchPoint: Form pages, Photo with stamp (claim, TP, date-time, GPS, "by {name}"), Files view/download, time done.
- CaseMap: photo pins for all officers' completed visits; address pins only for my pending TPs; All / Mine / {name}; legend; pin sheet (photo, stamp, who).
- CompleteMyPartSheet → "Part completed"; others see "{name} completed his part · 26-09-2026 4:10 pm".
- FinalReportGate: Lead only; unlocks when every part is completed; others "Final report by {Lead}", read-only after submit; lead removed → paused.
- Expenses: own bills only + case total for all officers.
- Daily update: own; timeline shows all with names and colours.
- Chat: all officers in the case chat with @mention.

## New (portal)
- AllocateSplit: tick each TP against an officer; Lead; district / distance / load; Add officer; Save.
- FieldWorkParts: parts side by side (status, photos, forms, files) + combined map with officer colours.
- Change officer on one part with a required reason → timeline; other parts undisturbed.
- Lead removed → banner, pick a new lead.

## States
Not accepted yet · rejected (manager reassigns, banner) · one done / one pending · all done waiting for the Lead · lead removed · offline (mine queues, other's as last synced).

## Hand-off notes
- case_officer rows carry: part (list of touch-point ids), lead (yes/no) and the part status.
- Each touch point has an owner officer.
- The API sends another officer's touch points without address fields and marks them read-only. Route planner never adds the other officer's stops.
- Photos and files of all parts are readable by every officer on the case.
- Case status 4 (FO Completed) is set only when all parts are completed.
