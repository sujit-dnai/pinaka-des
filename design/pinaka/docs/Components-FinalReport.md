# Final Report + Case Complete Report — component list (hand-off to Claude Code)

Design: `Final Report.dc.html` (app: `FinalReport.dc.html`, props product = health | motor; portal: `PortalReport.dc.html`). Sample only.

## Keep (same words, same lists, same order)
- Entry: Workspace → "Final Report for Case"; disabled from status 4; from CM Reviewed (5) banner: "Final Report becomes read-only from CM Reviewed onward. FO can edit it only up to status 4 (FO Completed)."
- Report master: plain list under "Corporate Visit" / Category / Category → Stage / Category → Stage → Case Field.
- "Select Report Details": Category, Stage, Case Field (only existing levels; single category auto-picked; hints "Select the case details" / "Select the case field"; changing clears answers).
- Question: red "*", Yes/No (default Yes; green / red), "Enter details for {question}...", mic with today's messages.
- Messages: "Please select all case details." · "All fields are mandatory. Please fill in all text fields." · "No fields configured for this selection." · "No final report data available for this case." · master error + Retry.
- "Submit Final Report" → "Confirm Final Report Submission" dialog → Review / Confirm & Save → "Saving final report...".
- Case Complete Report: title, sub-title, Final Opinion, Final Conclusion (Non Discrepant · Discrepant · Inconclusive), Reason (exact Health lists), "Complete Case" → "Completing case..." → "Case Completed Successfully" → "Go to Expenses" / "Back to Workspace".

## New
| Component | Notes |
|---|---|
| FinalReportGate | Unlocks only when every TP of my part is done or rejected; locked text "2 touch points pending: Hospital, Insured"; shared case: Lead only |
| ProgressJump | "12 of 18 answered", jump chips to empty answers, "Saved as draft 10:42 am" |
| DraftStore | On-phone draft, survives app close / no signal; "Draft restored" |
| AnswerRules | ≥5 characters, live counter, trimmed |
| ReviewPage | Every Q with Yes/No + answer, pickers, time taken, evidence strip for each TP |
| ReasonDetails | Required when the reason is flagged "Needs details" (No Documents Available; Other Insurance claims availed — confirm the list) |
| CompletionSummary | Conclusion chip (green / red / amber), reason, details, opinion, TPs done/rejected, expenses count |
| CompletionQueue | Offline: real time kept, "Completing — will send when online"; failure Retry |
| ReportReadOnly | After completion and from status 5 |
| Portal FieldWorkReport | Report + completion block; Pull into client report; Send back to officer (note → status 2); Mark CM Reviewed |
| Portal FieldMasters | Report questions editor; conclusion reason lists per product with order + "Needs details" flag |

## Data
- Final report: {caseId, userId, category, stage, caseField, timeTakenSec, answers:[{heading, selectedOption, value}]}
- Completion (JSON body): {caseId, finalOpinion, finalConclusion, reason?, reasonDetails?, completedAt}
- Motor-TP reason lists: TO BE GIVEN BY SUJIT (Field Masters).
- Default Yes kept as today.
