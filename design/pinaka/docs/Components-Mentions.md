# Team Chat · @mention — component list (hand-off to Claude Code)

Design file: `Team Chat Mentions.dc.html` (app views: `MentionChat.dc.html`, portal: `PortalChat.dc.html`). Sample data only.

## Keep (unchanged)
- ChatHeader: "{n} available member(s)", MemberChips, TeamMembersSheet (name, role, Available/Unavailable)
- MessageBubble: mine right navy, others left with initial avatar; times "Just now", "5m ago", "14:32", "Sep 26, 14:32"
- Reply: long-press or Reply button; ReplyBar "Replying to {name}"; quote in bubble
- ReadTicks, unread badges, ScrollToBottomButton
- VoiceInputSheet (Tamil → English into the box)
- EmptyChat: "No messages yet. Start the team conversation!"

## New
| Component | What it does | States |
|---|---|---|
| MentionInput | Draft = segments (text + mention) + tail input. "@" opens MentionList. Enter picks first match. Backspace on empty tail removes previous chip whole. Multiple chips allowed. | idle, list open, offline |
| MentionList | This case's chat members only (not me): avatar/initial, name (typed part bold), role, availability. Filters as you type ("@Suj" → Sujit D N). | loading (skeleton), solo "No one else to tag yet", non-member "Not in this case's team" (disabled), no match |
| MentionChip | "@Name" chip in the box | — |
| MentionSpan | Bold blue @Name in sent bubble; tap → PersonCard | member, left the case (grey + pill, no tap) |
| YouHighlight | Soft yellow row band + "@ you" tag when I am tagged; flashes 3× when opened from push / Mentions | normal, flashing |
| PersonCard | Sheet: name, role, "In this case's team", phone, Call | — |
| MentionBadge | Yellow "@" beside unread count on case card chat icon and workspace chat icon | shown while unread mentions > 0 |
| MentionsScreen | Every mention of me across cases, newest first; who, claim, message, time; Unread / All; Mark all read; tap → chat at message | unread, all read, empty |
| Bell type "Mention" | Mention rows in Notifications with their own type label and filter chip | — |
| MentionPush | "{name} mentioned you · {claim}" + first line; delivered even if chat muted; tap → openAt(caseId, messageId) | — |
| Portal: MentionsCounter | Topbar "@ Mentions" + red count; dropdown with Unread / All, Mark all read, View all | — |
| Portal: chat panel | Same MentionList, chips, highlight and "@ you" in the case page Team Chat | — |

## Rules
- Reply never tags the sender automatically; the user can add @name.
- Voice input never creates a mention. Only picking from MentionList adds to mentions[].
- Non-members cannot be tagged.

## Hand-off notes
- Each message stores `mentions: [{userId, name}]` beside its text. Existing message fields unchanged.
- The server validates mentions against the case's chat members and sends the mention push only to tagged users who are members.
- Unread mentions are counted per user per case (separate from the unread message count).
- Existing read-receipt logic stays unchanged.
- Offline: queued message keeps mentions[]; push fires when the server receives it.
- Member who later leaves: keep the mention, render grey "left the case".
