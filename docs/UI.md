# Human-only Swing UI

`dev.cairnguard.ui.GuardPanel` implements the in-process `GuardUiAccess` contract. Construct, interact with, and close the panel on the Swing event-dispatch thread (EDT). The public constructor is `GuardPanel(GuardUiAccess)`; `close()` is idempotent, stops the coalescing one-second refresh timer and cancels an outstanding export worker. It does **not** close the controller or recycle network permits.

This panel has no HTTP client, socket, MCP endpoint, agent-control API, native request sender/editor, authentication editor, session recovery or credential injection. It calls `refreshProject()` during refresh and before policy/approval actions, but never waits for an approval, rate admission or native HTTP completion. The controller/runtime still owns all final policy, project, queue and release checks.

## Six tabs

| Tab | Local human operations |
| --- | --- |
| **Dashboard** | Read safe operational status as plain-text JSON, including project ID, revision, paused/closed state, evidence statistics, shared-gate active/queued/stalled counters and approval count. Pause/resume new Proxy admissions. Clear retained redacted evidence only after confirmation. |
| **Rules** | Review the rule table; add a disabled rule, delete/toggle a selected rule, set its mode, or edit the full JSON list including nested AND/OR conditions. **Parse / preview draft** refreshes the table without applying policy. |
| **Scope** | Edit separate allow/block `ScopeEntry` JSON lists. **Add disabled … example** appends only `example.test`, HTTPS, port 443, exact path `/`, disabled. No automatic wildcard or broad allow entry is installed. |
| **Traffic** | Sort bounded masked observations; literal case-insensitive search across masked URL, method, timestamp, status, reason and evidence ID; additional method/status/time substring filters, exact project-ID and bookmarked-only filters. Toggle selected bookmarks. Read selected metadata/rule hits/revision, masked request and masked response. Export filtered or selected rows as redacted JSON/HAR. |
| **Approval** | View bounded pending IDs, evidence IDs, project IDs and timestamps. Resolve details only from the masked evidence snapshot; no raw fallback if evidence was evicted. Approve once or deny a selected pending ASK. Expired/stale decisions are not retried. Hard blocks never appear as approvable requests. |
| **Settings** | Edit global/default per-host RPS, concurrency, queue bound, queue/approval/in-flight timeouts, exact-host RPS overrides and default mode. Applying validates atomically and updates live runtime settings. |

All request/response/details/config widgets are `JTextArea`/plain text, not HTML viewers. Traffic and rules tables are read-only; captured text renderers and the project-filter renderer disable Swing HTML interpretation. There is no clickable captured-URL navigation or send/replay control.

## Policy editing and draft safety

The top-level **Apply ALL policy drafts** button commits Rules + both Scope lists + Settings together. It does not silently discard unsaved work in another tab. The section editors are loaded from one coherent `(projectId, revision, config)` observation. `schemaVersion` is preserved. All text editors accept at most **2,097,152 Java characters** (the same bounded input length used by `model.Json`); an over-limit interactive replacement is rejected with the categorical `EDITOR_LENGTH_LIMIT` status, not silently truncated into a different policy. Search fields are limited to 4,096 characters, and numeric editors to 32.

The controller's `updateConfig(candidate, draftProjectId, draftRevision)` always receives the **original loaded editor baseline**, never the current project's freshly fetched version. A timer refresh, project switch, external policy revision, pause/resume revision, controller closure or failed refresh makes the old draft stale and disables Apply. Old text stays visible for review, but cannot overwrite a new project's configuration. **Reload policy / discard drafts** explicitly loads the current project; if there are unsaved edits, discarding them requires confirmation. A race after the UI's preliminary check is rejected by the controller's atomic baseline comparison. A rejected/uncertain update requires reload rather than automatic retry.

JSON uses a per-read view of the shared `model.Json` mapper: unknown properties, duplicate keys, trailing tokens, overlong input and excessive nesting are rejected. The UI additionally rejects null/missing primitive values and fractional-to-integer coercion, so a missing/null scope port cannot silently become any-port and a fractional host rate is not truncated. It never changes global mapper settings. Preview is a structural JSON preview, **not** policy validation. Final full policy validation occurs atomically through `GuardUiAccess.updateConfig`. The UI additionally bounds rules, each scope list and host overrides to 256 rows, matching the policy limits. Errors display fixed categories only; exception messages, causes, operator-authored expressions and request values are never printed to a dialog or console.

For example, a complete condition may be:

```json
{
  "logic": "AND",
  "field": null,
  "name": null,
  "match": null,
  "value": null,
  "caseSensitive": false,
  "children": [
    {
      "logic": "LEAF", "field": "METHOD", "name": "",
      "match": "EXACT", "value": "POST", "caseSensitive": false, "children": []
    },
    {
      "logic": "LEAF", "field": "JSON", "name": "/operation",
      "match": "EXACT", "value": "review", "caseSensitive": false, "children": []
    }
  ]
}
```

Put it in a rule's `condition`; the Rules editor contains the **whole rules list**, not just one condition. Preserve the existing DELETE guards unless intentionally changing them. Rule actions use selected **IDs** after reparsing the current draft, so stale table indices cannot edit a different rule. Changing enabled/mode in the table tools remains a local draft until Apply.

Scope entries have `enabled`, `host`, `scheme`, `port`, `pathRegex`. An empty or wholly disabled allowlist permits **nothing**. Block scope and unsupported inspection are mandatory gates; neither ALLOW nor MONITOR overrides them. Path regex is a full path match, not a query match. See [POLICY.md](POLICY.md) for authority/IDN handling, RE2 syntax and inspection limits.

Host overrides use this Settings JSON wrapper (not a naked map):

```json
{"hostRps":{"example.test":2}}
```

Use `{ "hostRps": {} }` for defaults. Rates are 1–1000, concurrency 1–100, max queued 0–10000 and timeouts 1–600000 milliseconds. Invalid settings never partially apply. This UI intentionally does not automatically persist/export traffic, import arbitrary files, or create a full-policy backup file; operator-authored configuration sections may be copied/edited locally. It never harvests secret values into policy.

## Traffic and approvals

At most 2,000 evidence entries and 100 pending approvals are retained by the panel. It keeps only current bounded snapshots, not an accumulating event log. Table refreshes preserve selection by evidence/approval ID across sorting and new observations, convert view indices to model indices, and refresh read-only details. A project filter is retained even if its last entry disappears, rather than silently broadening to all projects. Filters combine with AND. Search treats punctuation such as `[` and `.*` literally; it never compiles traffic into a regex.

Only the evidence store's masked snapshots reach this UI. Missing responses remain empty, not invented successful responses. Details identify body omission/truncation and the policy revision/hits. **FORWARDED means native continuation released, not confirmed upstream delivery.** An in-flight timeout is operational uncertainty/quarantine, not proof that a request ended: the panel displays the gate's stalled counter and never frees its permits. Quiesce native traffic before starting a fresh run. See [EVIDENCE.md](EVIDENCE.md) and [INTERFACES.md](INTERFACES.md) for capture/enforcement limits.

Approvals contain references and safe timestamps, never raw request fields. Only matching project/evidence IDs resolve details. A decision is sent once to `decideApproval`; the bounded runtime queue owns timeout, stale-policy cancellation and one-shot semantics, and final native release remains subject to scope/policy/rate/concurrency checks. The UI rejects decisions for a different/closed/paused project and never manufactures a pending entry for a hard block.

## Explicit redacted JSON/HAR export

1. Choose **Export FILTERED JSON/HAR** for the currently displayed filtered rows, or **Export SELECTED JSON/HAR** for selected displayed rows in current view order.
2. A native human file chooser selects the destination. There is no automatic export directory or automatic background persistence; a cancelled chooser writes nothing.
3. Existing regular files require an explicit overwrite confirmation. Target symlinks (including dangling links), directories and missing/unavailable parents are rejected. The chosen parent directory is resolved before background work; an explicitly chosen symlinked parent resolves to that real directory, but the target itself is not dereferenced.
4. The panel freezes only the displayed immutable redacted selection. A `SwingWorker` calls the access-layer JSON/HAR serializer and performs UTF-8 filesystem I/O off the EDT. A second export cannot queue an unbounded backlog.
5. Output is written to a random **same-directory** temporary file, `0600` on POSIX filesystems. The write does not follow a temporary symlink. Publication uses `ATOMIC_MOVE`; there is **no non-atomic fallback**. A new destination is exclusively reserved with an owner-only empty file immediately before publication, because Java's atomic move may otherwise replace a concurrently appearing unconfirmed file. Only that reservation is replaced. Confirmed existing targets are checked for identity/size/timestamp changes before replacement. On ordinary failure, temporary files and this export's unchanged reservation are removed; another file is not deleted.
6. Replacing an existing file installs the owner-only temporary file rather than writing through the old inode/hard links. Non-POSIX permissions follow the provider's native behavior; owner-only ACLs are **not** claimed on unsupported filesystems. Failures show only `EXPORT_*` categories, never paths, raw exception content or credentials.

The chooser title, traffic footer and completion status all label exports **redacted, possibly omitted/truncated callback inspection copies — not complete wire capture or proof of delivery**. HAR schema/provenance and authenticity checks belong to the evidence serializer; the UI never reconstructs raw native messages. Export filenames are exactly those the human chooses (no hidden path or extension rewrite).

Use a trusted local directory. Java NIO cannot make consent checks and rename an atomic transaction against arbitrary concurrent malicious directory writers. Identity checks reject ordinary observed replacement races, but this is not a hardened sandbox for a hostile shared directory. Atomic rename is not a filesystem durability/fsync guarantee. A process crash between a new destination reservation and its rename can leave an empty `0600` reservation or an owner-only `.cairn-guard-*.tmp` file; inspect/remove that incomplete export locally before retrying. Never interpret it as complete evidence. There are no credentials in those serialized copies, but redacted evidence is still sensitive operational data.

## Verification and remaining scope

Run from the project root:

```sh
./gradlew test --tests 'dev.cairnguard.ui.*' --offline --no-daemon
```

**40 UI tests pass** (31 headless EDT/access tests + 9 temporary-filesystem tests). Two later regressions cover compact/reserved Traffic layout and strict application of the published native-fixture policy. Headless EDT tests use a purely in-process fake `GuardUiAccess` and synthetic masked observations. They cover exact tab names, EDT lifecycle/timer shutdown, rule AND/OR preservation and local add/delete/toggle/mode controls, scope presets, live-limit atomic saves, strict JSON/primitive-number/row/editor bounds, stale project/revision/race/coherent-load guards, draft preservation during refresh recovery, pause/clear confirmations, literal multi-filters, bounded/sorted/disappearing selection/bookmarks, disabled HTML interpretation, pending/missing/expired/other-project approvals, filtered/selected export snapshots, cancellation/overwrite consent/symlink errors, background error categories, and real `EvidenceStore` redacted JSON/HAR serialization through the UI worker/writer. Filesystem tests use only temporary local paths for UTF-8, owner-only permissions, no-clobber races, changed consent identities, symlink/hard-link safety, interruption and temporary-file cleanup.

These40 remain headless/filesystem tests: they do not themselves establish live/native Burp behavior, HiDPI behavior, non-POSIX ACLs, cross-platform atomic moves or hostile-directory concurrent-attacker resistance. The original isolated UI task did not include publication or native traffic. Subsequent Linux/Community native work found and corrected a collapsed Traffic pane; compact three-row filters, minimum split heights and an initial visible-tab divider ratio were then checked in the actual product. GUI search/bookmark/filter/selected exports and owner-only permissions were also observed. See [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md), not the unit count, for those limited native results and remaining gaps.
