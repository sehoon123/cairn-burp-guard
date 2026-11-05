# Verification status — v2 development checkpoints, 2026-11-05

**An explicitly requested development prerelease is NOT full acceptance, final
independent audit, installation or production approval. Native observations below
are artifact-specific results; later evidence does not upgrade older artifacts.** This is an independent development preview project, not a
certified safety boundary. Source, frozen snapshots, automated checks, disposable
Swing, exact JAR/native observations and independent review are separate evidence.
Historical counts/hashes never transfer to a new candidate.

## Current scope — all Proxy listeners, H explicitly deferred

The user explicitly deferred per-port protection H and asked to finish the rest first.
Current acceptance is A–G plus OFF/lifecycle/raw-history, with all Proxy listeners protected.
H is NOT a current gate or a claimed PASS. UI/JSON cannot create new unsupported restrictions;
old data is preserved until explicit confirmed clearing.

### Latest narrow follow-up — bounded WARN history, 2026-11-05

Baseline source `183e106` retained completed WARN paths until the fanout window ended.
A real isolated Burp run reproduced the availability defect: 2048 sequential distinct
paths arrived, then request2049 returned typed local `RESPONSE_WATCHER_CAPACITY` with
zero additional fixture arrivals. This is a reproduced baseline defect, not a PASS.

The correction stops adding completed-path retention for WARN and independently bounds
indexed fanout history to the existing global 2048-path capacity. New WARN identities
that cannot fit are omitted without denying traffic. Aggregate omission counts and
incomplete-history warnings remain visible. BLOCK/PAUSE fails closed until the latest
outstanding omission deadline (each from its original window); saves, OFF/ON, detector disabling and evidence/
overlay clearing do not erase that debt. Entering enforcing mode ends only stale WARN
latches, not history or enforcing protections. Cancellation can conservatively leave
an omission until its deadline. Separate host, physical-flight, path and overlay limits
still apply; this is not unlimited concurrency or cross-service scanning.

Exact corrected JAR SHA256:
`6133f1edc2f9ff0bfc2a97c018285f54b88c604f1c82b0abaad5da44ec90aff9`.
It was built before commit; the containing commit's production/build/lock/legal inputs
must match this artifact. No dependencies, handler continuation, native permits, listener
selection, authentication or worker APIs changed.

| Layer | Observed result / boundary |
|---|---|
| Red-before-fix | 76 focused tests on unchanged production, **3 expected failures**: WARN churn (watcher/controller) and live WARN-to-enforcing latch |
| Full Java | **1321 PASS /45 suites**, failures/errors/skips0 (baseline1305 +16). Worker and parent independently ran clean isolated builds/tests |
| Isolated Swing | **27 PASS each at scales1/2**, failures/errors/skips0; separate forced worker runs on owned Xvfb/WM, not native Burp or all-platform certification |
| Python / templates | **32 helper unit +18 local-template PASS**; parent repeated both (LinuxPython3.11 template fixtures). Actual upstream SKIP; offline fixture output is not native evidence |
| Reproducibility | Three clean worker builds and a separate parent clean build all produced the full6133f1e… hash above; parent verified XML totals and artifact byte hashes |
| Narrow independent review | `openai/gpt-6.1-sol` and `ica-se-claude/claude-advantage-assist` read the frozen diff and connected code, no blocking finding. They did not run tests/native; these are not the outstanding whole-v2 audits |

**Exact-artifact native observations:** the parent legitimately accepted the temporary
instance's terms and selected Community2026.10.1/build54773 under renewed user authorization.
Network-disabled container, independent temporary project/HOME/preferences/display,
Temurin21.0.11+10, owned numeric-loopback fixtures, HTTP/1.1 only. Loading/configuration/
OFF/release/export used the human GUI, not a Burp control API; existing user Burp,
activation, profiles and global proxy/trust settings were untouched. Load and final
extension Errors UI were empty.

- **WARN A/B:** identical human settings (50 global/per-host RPS, maxConcurrent5,
  heavy/circuit off, WARN1000/window3600sec) and bounded streaming fixture. Corrected
  JAR: **2200/2200 arrivals**, no local capacity denial, tested method/target/synthetic
  auth+cookie/empty body/response mismatches0. UI showed **2048 indexed /152 omitted**
  and both episode and incomplete-history warnings. Fixture retained only3 samples;
  bundled500-event fixture was not used for saturation. Timing is not a performance benchmark.
- **Saturated enforcement:** BLOCK and PAUSE each denied an indexed path, new path and
  separately allowed second actual service: typed local capacity451, **0 arrivals**.
  OFF allowed three owned requests; same-project save did not re-enable protection.
  ON restored all three capacity denials. Disabling the detector allowed the three;
  re-enabling BLOCK restored all three denials. No debt expiry was simulated.
- **Clean transitions:** after genuine extension reloads with all prior work completed,
  UI history/omissions reset to0. WARN-to-BLOCK enforced on the previously seen path,
  blocked both first-service probes and left the second service available. Separate
  clean WARN-to-PAUSE blocked all three. Active PAUSE survived detector disabling;
  explicit confirmed human release restored availability. These are not expiry tests.
- **Baseline regressions repeated on corrected bytes:** empty allowlist1, exact scope6,
  raw-target/optional-payload21 named cases passed, plus a response-only-grant fixture.
  Both owned inbound listeners blocked DELETE and allowed unchanged GET (four cases).
  The14 raw target spellings and6 payload types arrived unchanged in tested fields;
  fuzzed Host did not change the actual service or authorize the outside service.
- **True native work:** concurrent1/queued1/queue-timeout1sec, six held clients gave
  one fixture arrival/peak1, four `QUEUE_FULL` and one `QUEUE_TIMEOUT`; next request
  arrived after real completion. A separate500ms missing-response threshold gave
  `IN_FLIGHT_TIMEOUT` while the genuine1.5sec response remained held; its200 and later
  successful request established completion-based recovery, not permit recycling.
- **Representative existing protections:** first6291456-byte response matched exactly,
  next same path heavy-blocked without new arrival, unrelated path available. Five
  actual503 responses opened a circuit; one held half-open lease excluded a concurrent
  attempt, then success closed it (explicit1sec test open period).
- **Privacy/export:** GUI JSON30/HAR30 records were owner-only native-local files and
  parsed successfully; known synthetic secrets and tested hex/base64/percent variants
  absent. A response-only JSON grant remasked the earlier request URL in both formats.
  Human raw inspection remained separate. Saturation incident validated offline with
  `fanoutHistoryComplete=false`, `complete=false`, `truncated=true`, omitted152.
  Initial Docker/macOS bind-mount atomic export failed safely with no output; native
  local filesystem export succeeded. No unsafe fallback was added; export portability
  across filesystems is not established.

A supplemental macOS-host Python3.9.6 template CLI run passed all18 unit checks,
then its unchanged fixture-only setup failed with `TypeError` (NoneType path).
Repeating in isolated LinuxPython3.11 passed both fixture loaders and skipped actual
upstream as intended; the host setup issue was not patched or counted as success.
The disposable Burp then exited normally through its GUI (container exit0); native
active/queued/approval counts were0 before exit. Private state and rollback JARs retained.

The earlier `b921f6…` JAR was also actually loaded and passed the same empty/exact/
rawpaths/privacy-export checks before its WARN defect reproduction. Its initial EULA
stop below is historical, superseded by this newly authorized run.

**Not claimed:** full A–G acceptance, whole-v2 audit approval, H support, native4096-flight
ceiling, hour-long debt expiry, every cancellation/late/shutdown/cross-project race,
HTTP2/TLS or macOS/Windows native coverage, Professional/disk persistence, live upstream
or CAIRN/model/report E2E. Counter upper bounds, alias/multi-host, deadline/wrap,
health/EXEMPT/intent/probe competition and late-ticket cases also have deterministic
regressions; cases not actually observed above remain synthetic-only. Private original
logs/screenshots/exports/profiles stay outside Git. The user subsequently requested the
**development prerelease** `dev-2026-11-05-v2-warn-history`; its [publication record](PRERELEASE_2026-11-05_WARN_HISTORY.md)
separates this exact artifact, remaining limits and rollback precautions. Publication
preparation changes documentation only, not production/build/lock/legal inputs; no user installation.

### Historical published c61b7d… checkpoint

The user explicitly requested committing/pushing that checkpoint and publishing a
**development-only prerelease**, `dev-2026-11-04-v2-all-listeners-checkpoint`.
At that checkpoint isolated Java was **1302 PASS**, Python helper offline unit31 and local
template18 PASS (actual upstream SKIP). Clean/forced production builds reproduce
JAR `c61b7d1f869ec926c30f0e0fcc9cd188396f7fd694e9fc2cfac542a6d191f491`.
**That new JAR has NOT been run in native Burp or real Swing.** Prior native/desktop
results do not transfer. Two cold audits of older `7b974de` reported defects, not
approval; the third privacy/export review is blocked without a substantive report.
Updated-source final independent review and adjudication of remaining queue/fanout/
optional-capture findings remain incomplete. Publication does not waive those gates
or install into the user's Burp. See the [checkpoint record](PRERELEASE_2026-11-04_V2_CHECKPOINT.md)
and [current scope/results](ALL_LISTENERS_ACCEPTANCE.md).

### Earlier follow-up: disposed evidence selections no longer export (183e106)

Baseline `2096d50`. A pre-response snapshot of a row that later learned a response-only
secret used to export from its historical seal once the masked row was cleared or evicted.
`EvidenceStore` now rejects any selection containing a row that is not currently retained
(`INVALID_EVIDENCE_SELECTION`, whole selection, JSON and HAR); retained stale selections
still use the latest masked row. Expiry follows actual masked-row retention, not project
epoch (raw UI state is cleared by epoch changes; masked evidence may be retained).
Already-returned strings and files are not retroactively sanitized.

- Regression-before-fix: the focused 207-test run on unchanged production source had
  **5 expected failures** (clear JSON/HAR, eviction, the revised retention contract and
  UI cleared-export); all 207 passed with the fix. Mixed-selection ordering and both
  formats also pass in the green eviction regression.
- Isolated Java 21.0.11 container, no network after a dependency-cache warm-up of the
  locked/verified dependencies: **1305 JUnit PASS** (baseline 1302 + 3), desktop
  Swing 27 PASS at scale 1 and 27 at scale 2 on an isolated Xvfb display, Python helper
  unit 31 PASS, local template 18 PASS (upstream SKIP).
- Two clean `clean test jar` builds of the working tree gave identical bytes: SHA256
  `b921f62e959e47b1a51679a65d5a35c054f8b0efa85f8c14beaccc565a856048`. The JAR is of
  uncommitted source at build time; associate it with the commit that contains exactly
  these `src/` changes.
- Parent checked the XML totals and byte equality of **114 source/test/build/legal inputs**
  against both clean builds and both desktop workspaces, and rechecked both JAR hashes.
  Independent read-only reviews by `openai/gpt-6.1-sol` and
  `ica-se-claude/claude-advantage-assist` found no blocking issue in this narrow diff;
  neither reviewer independently ran the tests. These are not the three outstanding
  whole-v2 implementation audits and do not replace their model bindings or gates.
- **Initial native attempt: BLOCKED / NOT RUN (historical).** The official, checksum-verified
  generic Burp 2026.10.1 (build 54773) reached its first EULA screen in a fresh
  network-disabled container with an owned authenticated Xvfb display. At that attempt,
  no terms were accepted, edition selected, extension loaded or fixture traffic sent;
  explicit user consent was pending and the instance exited without accepting terms.
  The newly authorized native results above supersede that initial stop.
  Existing Burp, profiles, activation and global proxy/trust settings were untouched.
  Swing/loopback/harness results are not native results, and earlier
  artifact results do not transfer. All other release gates are unchanged.

### Historical956bcf… observations — not the published checkpoint's native result

That prior source was Java1235/Python31 PASS; clean/forced repeat builds matched
exact native JAR956bcf…, and real Swing was27 PASS at each of scales1/2.
Community2026.10.1 individually checked both inbound HTTP/HTTPS,
actual-service/raw paths, health, fanout modes, pacing/concurrency/queue/quarantine,
EXEMPT/intent/heavy/circuit, OFF old permits/ASK/queue cancellation/retained pause/debt,
human raw UI, JSON56/HAR56 and incident4 events/3 kinds. A human Repeater DELETE
passed without new Guard evidence while Proxy DELETE was locally denied.

Inbound H2→H1-origin has5 partial checks, NOT full H2 or literal lower-case-percent
preservation: `/c/%2e/main.do` reached the origin as `/c/%2E/main.do` even with Guard
fully unloaded. Unsafe-candidate ignore was observed after its overlay had already
expired; active-overlay persistence is not a native PASS. Cross-project/ABA,
Professional/disk/migration persistence, all saturation/shutdown races, opaque
protocols and CAIRN/model/report E2E remain unverified. Full facts, failed setup
attempts and limits are in [ALL_LISTENERS_ACCEPTANCE.md](ALL_LISTENERS_ACCEPTANCE.md).
At that checkpoint ten prior audit dispatches had produced no substantive report.
The later two cold reports and still-blocked privacy review are distinguished above.
No provider/model/auth/routing substitution was used. Historical native observations
and the user's later checkpoint-publication request do not clear acceptance or
independent-review gates. The following sections are also historical.

## Earlier437503 safe-source checkpoint — before H deferral

Main found two problems after user-authorized temporary-instance terms: native
listener ID correlation failed and a human JSON export retained a credential's
HEX reflection. The latter is fixed; weak cross-namespace proof production is
removed, **not replaced with a guessed listener identity**. Full native A–H and
three requested independent implementation audits remain incomplete. See
[V2_NATIVE_FINDINGS.md](V2_NATIVE_FINDINGS.md) for exact-case facts and limits.

| Latest layer | Direct result | Boundary |
|---|---|---|
| Safe source Java, including new HEX6 + namespace4 regressions | Fresh isolated clean **1231 PASS**, failures/errors/skips0 | Not native/audit approval; synthetic trusted registry tests do not establish Montoya identity |
| Focused Python harness | **27 PASS** | Fixture/client assertions, not27 native phases |
| Local templates | **18 PASS** plus two fixture-only loader checks; actual upstream **SKIP** | No live CAIRN/Pi/model/report E2E |
| Authenticated isolated Xvfb + owned WM, scale1 and2 | **27 PASS each**, failures/errors/skips0 | Same new source; no broad platform/accessibility certification |
| Clean isolated JAR and forced repeat | Both **43750326ca57a11fdb898850729c330d579538fb7d87261e0dc7b714993637b6** | Same bytes as Main's exact native test JAR; local reproducibility, not independent audit |
| Actual disposable Community2026.10.1 | Exact6/rawpaths21/intent2/exempt2/heavy3/circuit3 logical cases, WARN3 owned paths, human raw UI + actual0600 JSON/HAR/incident checked | Partial HTTP/1.1 observations only; H still FAIL, old-permit/OFF/full native matrix unverified |
| H mitigation | Both restricted inbound ports rejected before native content capture, zero target arrivals; no trusted native mappings | H desired selected protection/unselected bypass NOT supported. Empty guard list protects all; not a basic-protection outage |
| User-requested public-API type recheck | Separate disposable metadata-only probe:32 identical owned requests,16 per inbound; Proxy classifies both, HTTP32 objects are neither InterceptedRequest nor InterceptedHttpMessage; metadata errors0 | Not production Guard/H acceptance or proof every possible design is impossible; production code/JAR unchanged. Facts in V2_NATIVE_FINDINGS.md |
| Requested final audits A/B/C | Three waves/nine dispatches plus one user-requested fresh exact-model recheck: all ten stopped at credential rotator before substantive review | Zero reports/approvals, no provider/model/auth/routing substitution |

The first fresh desktop invocation could not start because xvfb-run was absent
from PATH (exit127, no desktop cases executed). Main reused the already extracted
read-only test dependency with explicit private authentication, then ran both
scales successfully; no system package install, test weakening or skipped assertion.
The temporary Burp/WM/runner and owned listener ports were confirmed closed.
Current user Burp/JAR/settings were not replaced. No public push/tag/release/install.
The old217730… prerelease bundle is a **rejected historical candidate**, not the
then-current safe checkpoint or a publishable artifact. After the user's later H
deferral, current gates are remaining A–G/OFF exact-artifact native acceptance and
fresh requested audits on the eventual final source; H is a separate future feature. Local commits/builds cannot clear these gates.

## Historical pre-authorization checkpoint (superseded status below)

**The following record describes the earlier82ec/217730 stage, before the user's
temporary-instance terms authorization and subsequent native findings.** Its EULA
stop, pending-only language and old counts are not current status; the latest
section/findings above take precedence. Historical design reports remain distinct.

### Then-current v2 source: established and pending

Implementation work for model/policy, watcher/budget/pacing, evidence/raw UI,
controller/listeners, human UI and native adapter is present in the worktree.
This is more than the earlier design proposal, **but not a shipped v2 artifact**.
[INTERFACES.md](INTERFACES.md) documents actual source APIs; design reports are not
implementation approval. The documentation task ran static checks only and did
not build, open Burp, touch credentials/display/network or publish anything.

The following are Main's integration observations supplied for this status update,
not fresh executions by the documentation worker:

| Layer / candidate | Recorded result | What it does not establish |
|---|---|---|
| Frozen clean locked153-file source snapshot, revision1 | **1220 Java PASS**, including real component dependencies, mocked adapter and owned socket tests | Not native Burp, desktop, remote CI or final audit |
| Revision2 → revision3 | BODY-help correction+regression, then two desktop tests' asynchronous geometry/click waits corrected; clean full **1221 Java PASS** | Existing focus/bottom-line assertions retained; no production focus-repair claim |
| Native-harness Python suite | **27 PASS**, including keyed candidate-ID regression | Focused harness/owned fixtures, not27 Burp phases |
| Local template checks | **18 PASS** plus both local fixtures | Actual upstream explicitly SKIP; no live CAIRN/model/dispatcher or report-file E2E |
| Isolated real Swing, UI scale1 | **27 PASS** with isolated Xvfb+owned WM | Swing/Robot/modal/layout only, not Burp LAF/native or platform certification |
| Isolated Swing, UI scale2 | **27 PASS**, followed by a second **27 PASS** run with isolated Xvfb+owned WM | Earlier asynchronous assertion failures retained in private records; no all-OS/HiDPI certification |
| Revision1 candidate (`bf327…`) | Same bytes reproduced twice locally, as reported by Main | Not independent implementation review or native acceptance |
| Revision2/3 candidate SHA256 | `217730d68b66f7ddb7f1c8d5ef4271873ac05e3e77efeb7dffb29c4bc105607d` matched across clean revision2, clean revision3 and a repeated rebuild | Local reproducibility, not a release hash, independent audit or native proof |
| Disposable real Burp attempt | Started in fully isolated HOME/display with owned ephemeral ports; **stopped at the FIRST EULA screen** | **No terms accepted, no extension loaded, no native phase run** |
| Requested independent reviews | A **design** attempted3 times and stopped by provider credential rotation; earlier B/C **DESIGN** reports exist. Integrated-source A/B/C had two requested waves (six dispatches), all exact provider/model metadata verified, all stopped in3–7s with no tool output or report | **Zero substantive final implementation audits/approvals**; no substitution or auth/routing changes |

### Recheck and local checkpoint, 2026-11-04

On the user's renewed test/commit/prerelease request, Main froze153 files again
(manifest `117162e481fdfb6bfc0225952b6c385ffd4ff697b5af9850aca7414399f1c59a`).
Only two status documents differed from revision4; Java/build/legal/harness inputs
were unchanged. Fresh clean Java1221 PASS (zero failures/errors/skips), Python27
harness +18 local-template PASS (actual upstream SKIP), and isolated Swing27 at
scale1,27 at scale2 and27 in its repeat all passed. Clean and forced repeated
builds again produced exactly217730… above. These are repeated local executions,
not native acceptance or independent audit.

The source checkpoint and local prerelease candidate preserve this tested work
with the outstanding gates explicit. They are not a public push/tag/release or
installation. No current user Burp/JAR/profile is replaced; no EULA accepted or
native phase run. Publication remains gated on the missing acceptance/reviews.

Revision3 has its own153-file frozen manifest and results. Its test-only geometry
synchronization changes do not change the production JAR bytes relative to
revision2. A later harness-only fix removed UUID/candidate-HMAC conflation; actual
network-free watcher output from that JAR (one event, nonempty top5xx/topBytes)
passed the corrected offline validator. This is not a human export from real Burp.
Raw private manifests, build logs, profiles, screenshots, reports and credential/
license material remain outside Git; reproduction paths use generic `$TMP`.

### Source semantics covered by synthetic tests, not yet native proof

- Actual `httpService` destination vs intentionally fuzzed Host; URL rules use
  actual target authority. Header/body optional capture failures and unsupported
  charset/media/encoding/malformed JSON are warnings, not automatic scope denials.
  Explicit authored rules still enforce available fields; unavailable conditions
  cannot grant EXEMPT.
- ALL-path `/c/;/main.do`, `/c/%2e/main.do` and encoded/nested/matrix/separator
  spellings remain unchanged. No unsolicited `AMBIGUOUS_PATH` sanitizer; restricted
  scope/block-path constraints still check bounded internal routing views.
- EXEMPT ordinary precedence without bypassing hard scope/lifecycle/availability/
  intent/rate. Strict schema2 codec, memory-only v1 migration, explicit human save,
  legacy rule preservation and exact optional removal.
- First-heavy response intact before later TTL overlay; actual native body-length
  scalar independent of copies/slots;5xx circuit, half-open GET/HEAD/cadence and
  missing-response logical timeout without recycling native permits; fanout and
  bounded candidates/incidents with retained-window/approximation metadata.
- Final watcher claim before intent consume; limit20 exact21st denial; local
  continuation/correlation/policy/watcher rejection does not spend new quota.
  Client labels remain untrusted; incomplete tags fail only when accounting enabled.
- Host FIFO/eligible round-robin, shared pacing, per-host quarantine and global
  stalled-slots-pinned failure, bounded host metrics. Admission is not delivery.
- Separate bounded memory-only human **unmasked** history vs sealed masked exports;
  raw lifecycle/HEX/omission, response-only secret remasking of watcher values and
  pending flights, no raw export or policy harvesting.
- Observer/lifecycle registration, ID registry, pre-capture mode(id), data-free
  unknown-listener denial, OFF/unselected no-capture, actual final-denial reason and
  additive typed451. Original objects/annotations and true permit lifetime.
- Guided UI risk confirmations/CAS, retained operator pause across OFF/ON,
  settings/listener/health controls, migration comparison, candidate-safe policyUrl
  drafts and explicit masked file exports.

Mocks, `javap` API compatibility, loopback sockets and fixtures cannot establish
actual observer→HttpHandler ID sharing/order, listenerInterface spelling or native
response correlation. External clients cannot prove extension memory non-capture
or storage immutability. These require human native inspection on the exact JAR.

### Outstanding acceptance gates

1. With legitimate user EULA/license handling, load the **exact intended candidate**
   in a disposable Burp and run owned native A–H. No acceptance letter is marked
   passed here. Listener ID/order/actual two inbound listeners is especially pending.
2. Native actual-destination/Host and raw target/body equality; unsupported-content
   warning behavior; first6MiB/actual bytes/circuit/EXEMPT/budget/local no-spend;
   retained pause/OFF/listener no-capture; safe masked export/incident acceptance.
3. Validate a human-produced native incident export. Network-free actual-watcher /
   offline-validator compatibility now passes; that is not a real Burp export,
   generic provenance validation or comprehensive redaction proof.
4. Requested final independent **implementation** audits on the integrated frozen
   source/artifact. Earlier design or historical scoped reviews do not substitute.
5. Only after explicit review/acceptance, deliberately decide publication/release.
   A local source checkpoint/candidate build is not public push/tag/install/release
   or completion, and does not clear the unmet native/independent-review gates.

[MANUAL_BURP_SMOKE.md](MANUAL_BURP_SMOKE.md) is a **future operator checklist**,
not a result log. [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md) records the EULA
stop and separately preserved historical native observations.

## Reproduction commands and evidence boundaries

Commands are for a **separately frozen isolated copy**, not an instruction to run
shared builds or start/accept/configure Burp as part of documentation work:

```sh
# Run in a private source snapshot with the reviewed lock/verification metadata.
./gradlew --offline --no-daemon --max-workers=2 clean test
python3 -m unittest discover -s scripts -p test_native_burp_smoke.py
# Only on an explicitly owned isolated display, separately from headless tests:
./gradlew --offline --no-daemon desktopTest -PdesktopUiScale=1
./gradlew --offline --no-daemon desktopTest -PdesktopUiScale=2
```

Default `test` excludes `desktop` tags and forces headless. `desktopTest` includes
only desktop tags, with inherited Wayland/session-bus hooks excluded. A Java PASS
therefore does not imply desktop PASS; a scale1 PASS does not imply scale2 PASS.
Build locking/strict SHA256 dependency verification remain enabled; they are not
an independent source audit. Local results do not assert an unobserved remote
[GitHub Actions](https://github.com/sehoon123/cairn-burp-guard/actions) run passed.
CI does not run licensed Burp or model E2E.

## Historical published modal / passthrough / condition-add preview

**HISTORICAL**, not the current v2 worktree:
`dev-2026-11-04-conditions-passthrough`, released-source baseline `738b41e`.

```text
JAR SHA256: 4232ae63d0a158d294fbe9ee3cf40cf58b9e8bdc85a300c8f829a5135b4bd159
```

At that time: **845 Java /25 suites**, **20 real Swing /2 suites**,14/28pt fonts,
UI scales1/2, **35 Python checks** (18 template +17 harness). Real keys/mouse were
Swing harness events, not native Burp. Condition tests used real add/AND/OR/save/
resize events but programmatically set field text. One Linux/nested X environment
was not full LAF/platform/accessibility certification. **Native Burp was not run
on that exact preview JAR.** Those old scale2 results are not current v2 proof;
revision3 has its own isolated scale1/2 records above and still lacks native proof.

Historical limited bug-fix reviews and the expanded-spec design process were
separate. One requested-model design review plus orchestrator draft completed;
two provider sessions were stopped, without substitution/consensus. A reviewer
reproduced an earlier frozen `5c7839e3…3a0a69` source/JAR and839/25 tests, not the
final above hash. Scoped implementation review accepted limited whitespace/
visibility/grant-masking fixes, found an in-pass wrapping parent-revalidation
issue, and a narrow follow-up accepted the deferred correction. None was a final
v2 implementation/native/four-way approval or independent rebuild of the final
4232 hash. [AVAILABILITY_REVIEW.md](AVAILABILITY_REVIEW.md) remains historical
proposal/review context, not proof v2 is accepted.

## Other historical artifacts — do not combine native totals

| Artifact SHA256 | Automated result then | Native result on that artifact only |
|---|---|---|
| `c07116e051f6f49f7e582ffd8490e2ae234a91b22b6a8958bb82e55e646cf508` | 783 Java /23 suites;18 template +14 harness checks |13 logical HTTP/1.1 scenarios /4 phases;14 evidence rows(6 upstream200 +8 local451), JSON14/HAR1 |
| `a924d6c5aa08a10c3eceaf32f5e442cb5e423dc3499b3f4c2b5b9528e51eb2cc` |771 Java /30 Python |12 logical HTTP scenarios /7 phases; JSON13/HAR1 |
| `56d0d1e3e02b6430352cd493bff97f8900eb4d5268140f44bac980d90c952d1a` |584 Java /28 Python |54 logical scenarios /14 phases, strict HTTPS/HTTP1.1, pacing/held responses/queue/quarantine,102-row exports |

The c071 run used normally available Community2026.10.1/bundled JVM26.0.2, fully
separate temporary HOME/preferences/profile/project/display, owned loopback
fixtures and external Python clients, **not CAIRN/Pi workers**. Human UI configured
policy/approvals and loaded/rechecked that clean-build JAR. It exercised URL draft
Enter, examples/navigation, approvals, pause and masked export, not its whole
backend native matrix/HTTPS/HTTP2. JSON14/HAR1 were0600 and lacked four known
synthetic secret values. Saving1/1/1 was a UI action, not a pacing measurement.
The instance exited through UI and only owned temporary artifacts were cleaned.
Details/timings/limits remain historical in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md).

Earlier template work also checked actual read-only upstream loader/renderer/parser,
`DispatchConfig.load` and `validate_prompt_resources` at CAIRN commit
`8e7e0ea67552383851dfcabfba0c4e9c8d007878`, with unchanged source/resource fingerprints:

```sh
uv run --no-project --with 'pydantic>=2,<3' --with PyYAML \
  python scripts/verify_templates.py --cairn-root /trusted/CAIRN --require-full-config
```

That was a contract check, **not dispatcher/worker/model/report-file E2E**, and
was not repeated by this documentation task. Fixture-only verifier success or
SKIP actual-upstream must not be described as that upstream check.

## Explicitly not established

- Production safety certification, absence of vulnerabilities, mandatory OS/network
  proxy enforcement, direct-socket prevention or strict target-arrival RPS.
- Complete wire equality/provenance, HTTP2 full native coverage, opaque CONNECT/
  TLS-pass-through/WebSocket-frame visibility or other extensions' later changes.
- Professional/disk projects, native cross-project atomicity/ABA, restart migration
  persistence and every worst-case capacity/shutdown/native race.
- Full HiDPI/OS/accessibility or native1100×760 window acceptance. Isolated
  revision3 scale1/2 passes do not certify every environment or Burp LAF; the
  product's minimum-window constraint limited old native runs.
- CAIRN/Pi/model/report-file E2E, prompt-budget sandboxing or guaranteed report
  completion after forced termination/write/auth/policy failures.
- Authentication/session/login/refresh/account/role management (excluded).
- KISA official code-by-code compliance or complete assessment coverage.

Only reviewed source/docs, synthetic fixtures and deliberately accepted artifacts
belong in publication. Private paths, original logs/screenshots, temporary Burp
profiles/projects, reports, certificates/keys, license/activation or auth material
must not be copied into this repository. This status update is not permission to
accept terms, bypass activation, perform unrelated testing or publish a candidate.
