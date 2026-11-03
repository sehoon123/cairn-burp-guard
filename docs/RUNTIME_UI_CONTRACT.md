# Runtime/UI contracts for second implementation wave

Read AGENTS.md and INTERFACES.md first. This document records the second implementation wave's technical contract. That initial local/synthetic wave began after202 tests and did not include publication or native traffic. Current public-development/isolated-Burp authorization is in AGENTS.md; current results are in [VERIFICATION.md](VERIFICATION.md) and [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md). Historical task restrictions do not supersede the user's subsequent explicit authorization. The JSON-oriented UI task section below is historical: current guided forms, Korean tab order and independent dialog saves are specified in [UX_REDESIGN.md](UX_REDESIGN.md) and [UI.md](UI.md). Shared `GuardUiAccess.java` remains the unchanged UI/controller boundary.

Current examples/shortcuts add only local UI navigation and draft filling: `UsageGuide` has no policy/traffic/storage access; table Enter/double-click uses the same guarded edit/read-only review paths; URL Enter fills only the target draft; rule selection previews before explicit filling; numeric recipes replace only three basic draft fields. None saves policy, resolves approvals or sends traffic implicitly. The original project/revision compare-and-set, hard gates and shared API remain unchanged. Current artifact-specific results must not inherit an older hash's native acceptance.

## Runtime task files (only RateGate.java, ApprovalQueue.java and corresponding tests/docs)

Package `dev.cairnguard.runtime`.

`public final class RateGate implements AutoCloseable`:
- `RateGate(GuardConfig.Limits limits)`
- `void update(GuardConfig.Limits limits)` validates bounds and wakes waiters; lower max concurrent applies to new sends (existing sends never revoked).
- `Permit acquire(String host, java.util.function.BooleanSupplier stillCurrent) throws Rejected, InterruptedException`.
- `Map<String,Object> snapshot()` fixed categorical/numeric keys: active, queued, stalled, admitted, rejected, closed, globalRps, perHostRps,maxConcurrent (may add numeric keys).
- `void close()` rejects/wakes waiting calls, never releases permits for still-running upstream calls.
- nested `public static final class Rejected extends Exception { String reason(); }`, reasons QUEUE_TIMEOUT, QUEUE_FULL, SHUTDOWN, POLICY_CHANGED, IN_FLIGHT_TIMEOUT, HOST_CAPACITY.
- nested `public final class Permit implements AutoCloseable { public void close(); }` idempotent, releases only when native response observed or dispatch conclusively NOT begun.
- Shared monotonic global AND per-host evenly spaced pacing, NO idle burst credit. Fair FIFO queue, bounded queue+host cardinality. Canonical key MUST `PolicyEngine.canonicalHost` (or equivalent call), same normalization for configured hostRps overrides. Timing uses nanoTime. A host entry can evict only when its rate-window debt expired and not active/queued; max4096 keys, fail closed on capacity.
- Request deadline: if ANY permit outstanding beyond limits.requestTimeoutMillis, STOP new admissions as IN_FLIGHT_TIMEOUT, count stalled; DO NOT recycle that permit automatically. A late actual response closes it and can clear quarantine. Snapshot may compute aging. Pending waiters wake at timeout or rate interval to see stalled permits even without external signal.
- Try immediate acquire even with maxQueued=0 if rate+concurrency permit available. Count queue bound only genuinely waiting calls. BooleanSupplier false -> POLICY_CHANGED; callbacks no arbitrary request data. Fair FIFO admitted request order acceptable head-of-line blocking documented.

`public final class ApprovalQueue implements AutoCloseable`:
- `ApprovalQueue()` capacity100 (optional package test constructor)
- `Result await(String evidenceId,String projectId,long timeoutMillis,BooleanSupplier stillCurrent) throws InterruptedException`.
- `record Result(boolean allowed,String reason)` reasons APPROVED,DENIED,APPROVAL_TIMEOUT,APPROVAL_CAPACITY,SHUTDOWN,POLICY_CHANGED.
- `record Pending(String id,String evidenceId,String projectId,String createdAt,String expiresAt)` public immutable snapshot; NO raw request/header/body/URL fields; UI resolves masked evidenceId.
- `boolean decide(String approvalId,boolean allow)` one-shot; expired/stale decision must not allow.
- `List<Pending> snapshot()` sorted oldest first, bounded; `void cancelAll(String reason)` on policy/project/pause updates; `void close()` denies all.
- Do not hold rate/concurrency permits while awaiting UI. No Swing/native API. Use conditions/futures with deterministic timeout/shutdown/cancellation cleanup. No watcher threads left alive. Rich synthetic concurrency tests incl >=5 worker global/perhost rate and no implicit permit recycling.

## UI task files (only GuardPanel.java + own ui tests and docs/UI.md)

`public final class dev.cairnguard.ui.GuardPanel extends javax.swing.JPanel implements AutoCloseable`:
- `GuardPanel(GuardUiAccess access)`; construct/use on Swing EDT, `close()` stops refresh timer.
- SIX tabs Dashboard / Rules / Scope / Traffic / Approval / Settings.
- Dashboard displays map status, local paused control. status keys at least projectId,projectName,revision,paused,closed,note,evidence (map above),gate (RateGate.snapshot),approvalCount. status contains ONLY safe operational metadata (controller sanitizes project fields).
- Rules: support add/edit/delete/toggle rule, Mode selection, full condition AND/OR JSON editor. Can implement bounded JSON list editor + table/toggle selection; edits must parse/validate atomically through access.updateConfig(newConfig, baselineProjectId, baselineRevision). The three-argument API must carry the editor draft's project/revision baseline (never substitute a fresh status at submit); controller atomically rejects stale drafts. Do not silently apply malformed config or log exception messages/cause.
- Scope: editable allow/block lists ScopeEntry fields; JSON list editors acceptable if documented and useful presets/new row support. Empty allowlist warning. No automatic broad wildcard.
- Settings: live global/perhost RPS, maxConcurrent,maxQueued,timeouts, host overrides; full config JSON backup/import may be bounded local file and no automatic export raw logs. Settings save preserving other sections, parse using model.Json.
- Traffic: masked table with URL/method/timestamp/status filters + project and bookmarked filters (client literal search only, not backtracking regex); display selected request/response and reason/hits/revision. preserve selection on refresh, model indices convert from sort; no native request editor which could send traffic. Bookmark selected.
- Approval: show pending IDs/evidence masked details; one-shot Approve/Deny; refresh queue via access.approvals. Local hard-block cannot be approved here.
- JSON/HAR export of FILTERED or selected displayed entries via chooser; explicit label describes redacted/omitted/truncated callback-copy not complete wire capture. Use background SwingWorker for serialize/write, atomic same-directory move, owner-only POSIX where available, reject symlink target, explicit overwrite confirm. No automatic paths outside user choice; no raw console logs. Failure dialog categorical only.
- Bound all text editors max2MiB, detail panes already bounded evidence. Clipboard/export strings not HTML interpreted; use JTextArea not HTML JEditorPane for captured text. Refresh timer1s, native capture/approval waits never EDT. avoid storing unlimited snapshots; max2000 entries.
- `refreshProject()` detects switch, loads project config safely; call at refresh, not accessing native sockets. guard callbacks check live project adjacent release. Config UI old draft must not overwrite new project's policy: track projectId+revision baseline when loading editors, on changed project require reload; reject/refresh stale edits, do not autoapply. external config updates while queued block stale approvals (controller responsibility).

## Template task revision: MUST be active web testing profile, not offline-only

Existing offline profile is good optional example but NOT user MVP by itself. Main `templates/native-pi-ko` MUST support authorized scoped bounded non-destructive web TEST PLANNING, discovery and validation through existing HTTP proxy with worker's builtin shell tools. No MCP/Pi extension/Burp control; CAIRN itself writes Korean Markdown reports. No login/session work and no destructive/DoS/credential attack. Do NOT forbid all network or set main target budget0. Supply explicit Origin/Goal/Hints budget defaults conservative per-intent 20 requests/2min, concurrency perworker1; engagement total<=100 across<=5 intents agreed in provided plan. Proxy settings inherited, fail stop if missing/unreachable, never fallback direct, don't modify proxy/policy or suggest bypass; no guarantee env enforcement. Report blocked or auth-unavailable items without reauth. Include optional offline fixture mode budget0 SEPARATELY, report its limits honestly. Full KISA official code mapping still unverified => label thematic adaptation. Existing verifier must validate main active templates and exact upstream contracts, and identify offline fixture vs actual E2E properly. No real target traffic in development.
