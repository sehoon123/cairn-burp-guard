# Controller integration and owned-loopback verification

## Verification boundary

These tests invoke the **actual `GuardController`, `PolicyEngine`, `RateGate`,
`ApprovalQueue`, and `EvidenceStore`**. They do not substitute a policy-only fake
for the controller.

**`ProxyLoopbackTest` is a controlled forwarding harness, NOT a native Burp test,
an HTTP proxy implementation, a real-target test, or proof of forced network
routing.** No installed Burp instance/project, external target, authentication
service, TLS trust, desktop/system setting, proxy environment, or remote repository
is used or changed. Development performed no commit/tag/push/release actions, in
accordance with the project/task rules.

Owned files:

- `src/test/java/dev/cairnguard/runtime/GuardControllerTest.java`
- `src/test/java/dev/cairnguard/runtime/ProxyLoopbackTest.java`
- this document

The only production changes for this task are targeted regression fixes in
`src/main/java/dev/cairnguard/runtime/GuardController.java`, described below. No
shared model, policy, gate, approval, evidence, UI, or adapter file was changed.
The public `Prepared` / `Admission` / prepare-authorize-commit APIs are unchanged.

## Run and results

From the project root, using the existing Java 21 Gradle wrapper/dependency locks:

```sh
./gradlew test \
  --tests 'dev.cairnguard.runtime.GuardControllerTest' \
  --tests 'dev.cairnguard.runtime.ProxyLoopbackTest' \
  --offline --no-daemon --rerun-tasks
```

Verified on **2026-11-03**:

| Suite | Cases | Result |
| --- | ---: | --- |
| `GuardControllerTest` | 72 | Passed |
| `ProxyLoopbackTest` | 27 | Passed |
| Owned total | **99** | **Five consecutive forced-rebuild repeat runs passed**, no failures/errors/skips |

A subsequent full `./gradlew test --offline --no-daemon --rerun-tasks` run saw
521 cases and two failures in concurrently developed `BurpLifecycleTest` cases
(`failedSuiteTabRegistrationRollsBackPanelControllerAndUnloadingRegistration` and
`unloadReentrantDuringSuiteTabRegistrationCannotLeaveLateRegistrationOrTimer`).
The 99 owned cases passed in that run. The adapter owner was notified; these
results must not be presented as a passing full suite until separately rerun.

JUnit XML is generated under `build/test-results/test/` and the HTML report under
`build/reports/tests/test/`. These build outputs are not new source/evidence
artifacts to publish. The documented owned repeat result is independent of any
later concurrent worker's filtered Gradle run overwriting those outputs.

## Synthetic controller coverage

`GuardControllerTest` performs no socket or filesystem persistence I/O. Its
in-memory `ProjectAccess` has separate fabricated project documents and one-shot
hooks for a switch/failure during load or save. Native completions are explicitly
simulated by the test owner; the controller is never assumed to complete traffic
on its own.

Coverage includes:

- Missing/blank project config starts with the empty allowlist and performs no
  implicit save. Valid project config loads without rewriting it; a normal
  same-project refresh preserves the revision and editor baseline.
- Invalid, oversized, duplicate-key, unknown-property, trailing-token,
  unsupported-schema, and invalid-disabled-rule documents fail to default-deny
  **paused**, not to a partially applied configuration. Null/missing primitive
  ports/flags and fractional ports/RPS are regression cases.
- Project-local successful save/reload, validation-before-save, stale project and
  revision drafts, and two simultaneous drafts from one baseline. Exactly one
  concurrent draft can save; the other cannot overwrite the winner.
- Load failure, project lookup failure, uncertain partial save, failure before
  writing, and project switch/unavailability during load/save. Raw persistence
  exception text is not copied to public error/status strings.
- A prepared request is invalidated on policy/project changes, even before UI
  refresh. Switching away and back does not revive an old revision. An invalid
  new project's config never inherits the previous permissive config.
- Pending human approvals, approved-then-rate-queued requests, queued ordinary
  requests, and already-authorized/pre-commit requests are invalidated by each
  of policy update, unrefreshed project switch, refreshed project switch, pause,
  and close. Old approval IDs are never reusable.
- ASK waits have reference-only pending metadata and hold **no rate/concurrency
  permit**. Denial, expiration, interruption, late clicks, pause/resume and
  shutdown produce no release. Interrupt status is preserved and waits clean up.
- Queue full/timeout denial, latched in-flight timeout, no automatic permit
  recycling on longer timeouts/config/pause/close, and late completion-owned
  release. Successful final commit is tested separately from authorization.
- Actual evidence transitions, missing-response distinction, local versus
  nonlocal 451, redacted JSON/HAR provenance, bookmark/clear behavior, cumulative
  counters, and late responses after evidence was cleared.
- Header/cookie/Authorization/Proxy-Authorization/API-key and body inputs remain
  unchanged through approval, release, capture and export. Credentials are only
  **fabricated fixtures**. This tests inspection/evidence non-mutation, not
  native request identity or authentication/session management.

### Pipeline and permit ownership under test

```text
prepare(inspection copy) -> PENDING
  hard BLOCK -> authorize denies -> BLOCKED, local status 451
  ASK -> AWAITING_APPROVAL (no rate permit) -> one-shot human result
  allowed/current -> QUEUED -> authorize returns caller-owned permit
  final current check -> commit -> FORWARDED / NATIVE_RELEASED
  observed response -> evidence.response
  completion owner -> permit.close
```

Authorization returning a permit does **not** mean a request was dispatched.
`QUEUED` can remain the evidence disposition after admission and before commit.
`commit` must be immediately adjacent to the adapter's actual continuation;
authorization is not a substitute for that final check. A failed pre-dispatch
commit permits the caller to close its conclusively-unsent permit.

`controller.response()` only captures evidence. It does not own or close a permit.
The caller closes it after a simulated/observed actual completion, or after
conclusively ruling out dispatch. Pause/config/project changes, evidence clear,
ordinary timeouts and controller close never release an already-running permit.
No test treats a timer or lost response as proof of completion.

A local block decision sets status 451 but does not invent a captured response;
`localResponse()` records that separately. An upstream callback with HTTP 403 or
451 remains `FORWARDED`, not `BLOCKED`. JSON/HAR provenance distinguishes
`LOCAL_BLOCK` from `RESPONSE_CALLBACK`. `FORWARDED` alone remains
`NATIVE_RELEASE_NOT_PROVEN_DELIVERY`.

Evidence has its own fixed reason vocabulary. Newer runtime categories not in
that vocabulary (for example `PAUSED`) are conservatively represented there as
`OUTCOME_RECORDED`; the categorical admission reason and `BLOCKED` disposition
remain distinct. Tests do not confuse that fallback with a native/target error
or manufacture an unsupported exact evidence reason.

## Owned-loopback harness design

Each harness instance owns a fresh JDK `HttpServer` bound to **127.0.0.1 on an
OS-assigned ephemeral port**, with no wildcard bind. The numeric address is
constructed from bytes, without DNS. Only this harness's raw-socket transport
opens a connection; `GuardController` itself still performs no network I/O.

The transport uses a separate original synthetic request fixture for its method,
request target, ordered headers and body. The controller receives only the
immutable `RequestData` inspection copy. After `prepare -> authorize -> commit`,
the fixture is serialized to our pinned numeric address and port. The destination
is **never derived from an untrusted URL, redirect, DNS result or proxy setting**;
an independent endpoint assertion rejects mismatches. There is no redirect,
retry, fallback-to-direct or outside destination support.

The reply reader is intentionally only a bounded fixture reader: HTTP/1.1 with a
single Content-Length, maximum 64 response headers / 16 KiB header text / 64 KiB
body. It is not a general HTTP proxy/parser. Connect/read deadlines are 2/4
seconds; response-hold and future waits are finite. All fixture request bodies
are small and synthetic.

### Non-arrival assertions

- Dangerous DELETE methods, literal/mixed-case/multiply-percent-encoded URL
  actions, JSON/Unicode JSON/form/text body actions: **zero upstream hits and
  zero socket opens** for every denied fixture.
- Malformed JSON/percent encoding, unsupported binary/multipart/content encoding
  and WebSocket upgrades remain blocked even with MONITOR default.
- Empty allowlist, explicit block scope and a denied human approval also have
  zero hits. ASK performs no connection before the human decision; approving
  one safe fixture results in exactly one owned-server request.
- A revision change between authorization and final commit opens no socket.
- Policy/pause/close while a second request is queued adds **zero additional
  hits**. The earlier already-running request still has its permit and is allowed
  to complete; its existing one hit must not be misreported as zero total hits.
- An unanswered request beyond its budget quarantines all new admission without
  opening another socket, even with spare concurrency. Its permit remains active
  until the held, real owned-server reply is read. A late completion restores
  admission; no timeout/reset/retry releases it.

### Allowed fidelity and shared budget assertions

The owned server observes the allowed method, exact request target, repeated
ordinary header values, Cookie/Authorization/Proxy-Authorization/API-key values,
and **identical body bytes** for JSON, URL-encoded form and UTF-8 text fixtures.
The harness also receives the original synthetic response body and Set-Cookie
value; evidence copies are masked separately. JDK `HttpServer` normalizes header
names, so these assertions are about **observed values/duplicates and body
bytes**, not preservation of header-name casing, wire ordering, HTTP/2 framing,
TLS bytes or native Burp object identity.

One test starts **six workers together**, each sending two allowed requests
through **one controller** with global/per-host **5 RPS** and concurrency **2**.
The first two owned handlers deliberately withhold their responses. While both
are unanswered, the gate has two active permits and four queued workers, with
no third admission or completion. After releasing responses:

- all 12 requests/replies complete;
- the maximum active owned-handler count is exactly 2;
- all successive gate admission timestamps are at least **200,000,000 ns** apart;
- active and queued gauges return to zero.

Strict gaps use `Permit.admittedAtNanos()` (the package-private monotonic
observation already provided by RateGate), **not** a timestamp after thread
rescheduling, socket writes, or server receipt. Both budgets are 5 on the same
127.0.0.1 host; cross-host/canonical-alias gate coverage lives separately in
`RateGateTest` and [RATE_APPROVAL.md](RATE_APPROVAL.md).

The harness keeps each permit through the complete response read **and** a
conservative test-only rendezvous confirming that its owned server handler has
finished. Thus the observed server concurrency cannot be distorted by a race
between native reply receipt and trailing handler cleanup. This is stronger
local fixture coordination, not an assumed capability of Burp/native callbacks.
A post-commit I/O failure intentionally retains its uncertain permit; teardown
releases any remaining permit only after closing owned sockets and terminating
all owned transport/handler work.

Executors are joined with finite deadlines, response latches are released in
cleanup, the controller is closed before cancelling waits, open sockets are
closed, and `HttpServer.stop(0)` is called. No watcher/service is installed.

## Reproduced controller fixes and recovery behavior

Tests were added and run **before** the controller changes. Reproductions showed:

1. The generic persisted JSON read could coerce a null/missing scope port to
   `0` (**any port**) or truncate a fractional port/RPS. Oversized whitespace also
   skipped the prior JSON size check. The controller now uses an immutable reader
   inheriting the shared duplicate/unknown/trailing/depth protections, enables
   `FAIL_ON_NULL_FOR_PRIMITIVES`, disables `ACCEPT_FLOAT_AS_INT`, and checks the
   2 Mi-character document bound **before** accepting blank input. It does not
   mutate the shared mapper or change the JSON/model API.
2. A persistence save could write a stricter policy and then throw while the
   controller kept its older permissive cached policy. A generic Resume could
   unpause that cache, and normal same-project refresh skipped reloading it.
   The controller now latches **recovery required** on failed/ambiguous load,
   unavailable project, uncertain save, or project lookup/switch after saving.
   Resume throws the fixed category `PROJECT_POLICY_RELOAD_REQUIRED` while that
   latch remains set. Same-project refresh retries when recovering. A successful
   validated reload (including a new revision) or an explicit validated human
   policy save clears the latch; neither automatically unpauses. The human can
   then explicitly resume. Failed reloads remain default-deny and paused.
3. Native project lookup exceptions during pre/post-save checks previously
   escaped unchanged. Safe lookup now returns a mismatch categorically:
   `STALE_POLICY_DRAFT` before saving, or `PROJECT_CHANGED` with a recovery-required
   pause after saving. No raw native exception text/cause is exposed there.

These changes do not reset a gate, close outstanding permits, change
credentials, or start/retry traffic. Recovery of **policy persistence** is not
recovery of uncertain native in-flight operations; see
[RATE_APPROVAL.md](RATE_APPROVAL.md) for quarantine and quiescence obligations.

## Remaining independent verification

- Native Montoya capture/continuation/spoof/drop, response correlation, tool
  filtering, same request/response/annotation identity and extension lifecycle
  require the adapter suite and separate manual Burp smoke. This harness neither
  invokes the native adapter nor claims those checks passed.
- In-memory project fixtures establish the controller's observed project/revision
  checks, not atomicity of Burp's project persistence/switch implementation.
  `ProjectAccess.current/load/save` are separate operations; an unobserved native
  switch/ABA at that boundary cannot be ruled out by this fixture.
- No actual HTTP proxy listener, browser/CAIRN execution, proxy environment
  inheritance, HTTPS/CA validation, CONNECT tunnel, HTTP/2 native normalization,
  WebSocket frame, TLS pass-through, or real upstream application was exercised.
- Direct sockets/egress, other extensions, traffic absent from Proxy callbacks,
  on-wire arrival pacing and mandatory network enforcement remain outside this
  evidence. Prompt/proxy configuration alone does not establish a firewall.
- Authentication/session refresh, login/logout workflows and credential validity
  were deliberately not exercised. Fabricated auth fields are merely carried
  through unchanged to an owned local fixture.
