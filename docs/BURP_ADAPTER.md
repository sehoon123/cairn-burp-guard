# Native Burp adapter

`dev.cairnguard.GuardExtension` owns the human Swing tab, project-local storage, a **data-free Proxy request observer**, and a Montoya `HttpHandler`. Only `ToolType.PROXY` requests are protected; other tools continue with their original objects. No network sender, Burp admin interface, worker API, login or session management is added.

## Native identity and bounded inspection

Allowed requests, responses and annotations are the **same native objects**, not reconstructions. No `with*`, annotation changes, Host correction, HTTP/2 pseudo-header normalization, URL normalization, decompression or payload rewriting is performed. The extension does not infer complete wire equality from an inspection copy.

Scope uses **`httpService().host()/port()/secure()` and the untouched `request.path()` (path/query)**. It never trusts `request.url()` or Host/`:authority` for the transport authority. Explicit URL rules therefore inspect the **actual-service URL**, not a Host-derived authority. An actual out-of-scope service remains blocked even if Host claims an allowed one. A fuzzed, absent or duplicate Host/`:authority` is not an unconditional rejection.

All-path scope permits `/c/;/main.do`, `/c/%2e/main.do`, nested percent/matrix/separator variants and malformed-percent targets unchanged. Decoded/normalized aliases belong only to internal scope/rule/availability matching; they never replace the native request target. Restricted path scope must verify its bounded routing views. Authored health/response-limit routes remain strict exact routes; this is not a traffic sanitizer.

Inspection limits remain bounded: essential method/service/path metadata, 256 headers / 64 KiB header metadata, at most 1 MiB aggregate body inspection budget, 128 protected callback slots, 8 optional copy slots and 100 protected native flights. Optional header/body failures, oversized copies or unavailable copy slots produce explicit `headersComplete` / `bodyComplete` flags, **not an automatic451**. No oversized zero-filled body sentinel is shown as original data. Content rules are demand-driven: unavailable JSON/form/charset/binary/encoded/multipart inspection cannot be claimed evaluated, and cannot grant a content-dependent EXEMPT. Explicit inspectable operator BLOCK rules still apply. Essential scope uncertainty and enforcement capacity still fail closed.

Oversized optional query text is bounded to one character beyond the policy query limit, marking query inspection unavailable rather than matching a truncated prefix. The separate raw UI cache applies its shorter truncation limit and labels the display accordingly. Neither inspection string is a transmit target. An independently verified zero-length body stays EMPTY even when optional copying is unavailable; an unknown or omitted nonempty body never qualifies as a health probe. Health requires exact configured GET, no query, verified EMPTY body and ordinary scope/rules, and bypasses only operator pause/circuit.

Human request-history raw getters use a separate bounded memory-only cache, labeled **inspection copy, not wire proof**, with omission/truncation metadata. Exportable evidence, JSON/HAR, watcher diagnostics and incidents remain masked. No raw UI getter feeds policy, watcher display or exports. Project epoch changes, clear and eviction dispose raw UI data.

## Listener boundary and OFF

The pinned Montoya 2026.7 API exposes `InterceptedRequest.messageId()` and `listenerInterface()` through a `ProxyRequestHandler`. `ListenerObserver` is registered **before** the HTTP handler and records only these two metadata values on request received. Both Proxy callbacks continue the original request/annotations without interception changes. It does not record twice or use destination service port as a fallback. Deregistration handles initialization failures and synchronous unload during registration.

Before content capture, `HttpHandler` calls `controller.nativeMode(messageId)`:

* Human-confirmed global OFF returns a project/revision-bound, count-only bypass token first.
* A known unselected inbound listener returns a separate unguarded-listener bypass token.
* Missing, duplicate, stale, malformed, expired or capacity-exhausted mapping with configured listener restrictions yields **data-free `LISTENER_UNVERIFIED`**, before content capture.
* Selected/all-listener traffic follows protection.

OFF/unselected paths create no new evidence, approval, rate permit, watcher/budget state or response correlation. Untracked responses do not even read native response status/body-length scalars. Existing protected flights still complete their own permits and evidence across OFF/unselected traffic. Bypass construction is non-sending and its token is rechecked at final return; stale generation/project/shutdown/collisions cannot smuggle an old bypass. See [PASSTHROUGH.md](PASSTHROUGH.md).

The observer/HTTP ID relationship is an integration assumption **until verified with real Burp and two actual inbound listeners**. Mockito tests and `javap` prove the source API, not native callback order, ID correlation or the listener string's runtime spelling. Missing native correlation fails closed, not silently bypasses.

## Final handoff and local denial

Protected pipeline: mode/ID/slot checks → bounded inspection + policy/evidence → human approval without permit → rate/concurrency permit → **construct non-sending original-object continuation** → install bounded flight → atomic `commitDetailed` (watcher before intent) → immediately return continuation.

Factory null/throw, local correlation capacity, stale policy/project, final watcher/fanout or budget rejection never consumes a new intent quota or creates a successful watcher flight. Use the **actual `CommitResult.reason()`**, not generic `FINAL_CHECK_REJECTED`. Factories can reenter; preparing/flight ownership prevents ambiguous IDs from completing/replacing an earlier protected request. A duplicate ID is dropped, not spoofed as a response that could release an older permit. No adapter can prove that returning a native continuation means wire delivery; accounting is final accepted native handoff, never a delivery claim or automatic refund after uncertain dispatch.

Local HTTP451 preserves these original JSON keys **in their original order**:

```json
{"source":"cairn-proxy-guard","outcome":"blocked","reason":"PAUSED","evidenceId":"00000000-0000-4000-8000-000000000001","retryable":false,"guardState":"PAUSED_BY_OPERATOR","local":true,"policyRevision":7}
```

The appended guard state/revision come from typed `controller.denial`; append `overlayId` only for a valid opaque UUID. Reason/state/ID alphabets and numeric revision are independently bounded; no note inference, exception messages, host/path/tags or configurable serializer enters the local body. Native spoof failure falls back to drop, never allow. A target's unrelated451 is still an upstream response, not a local guard block.

## Responses and permit lifetime

A matching actual Proxy response closes only its own native permit, independently of capture or continuation-factory failure. Missing/timeout responses retain permits; shutdown and logical watcher deadlines never manufacture native completion. Stalled permits quarantine their host and still count toward global concurrency. Late and duplicate responses cannot release other permits.

On tracked responses, native status and `body().length()` are observed **outside optional copy-slot admission** and independently of each other. No full-body copy or attacker-provided Content-Length is used to measure actual bytes. The seven-argument `controller.response(..., actualBytes, headersComplete, bodyComplete)` bridge preserves scalars even for omitted 6 MiB bodies or saturated copy slots. Unknown size is `-1`, never a fake zero or declared length. Response content is still best-effort bounded; the first large response cannot be prevented, and originals/annotations continue unchanged.

## Owned external fixture clients

`scripts/native_burp_smoke.py` is **external test code**, not bundled extension logic or a control plane. It starts numeric-loopback-only owned fixtures and uses external clients through an already human-configured disposable Burp. It never loads/configures Burp, changes protection/policy/listeners, reads credentials, or calls any admin API. All request values are synthetic. Do not run it against a user's live project. No automatic URL-normalizing client: Python `http.client` preserves target spelling; curl reproductions must use **`--path-as-is`**.

Each phase requires the human UI to set its preconditions, separately, in a fresh disposable profile. Existing manual recipes predating v2 may have obsolete broad delete/unsupported-payload assumptions; use the following current phase contracts:

| Phase | Human precondition / external observation |
| --- | --- |
| `empty`, `exact` | Empty scope / exact `/safe` scope. v2 defaults retain DELETE method only; benign delete query text is allowed. |
| `rawpaths` | Actual first loopback service **all paths**, second service outside scope, no custom content/path BLOCK. Proves raw target, fuzzed owned Host, original binary/unsupported charset/multipart/encoded/malformed/oversized body at the owned socket. Fuzzed Host also names an owned loopback endpoint so proxy routing mistakes cannot send to a private/external target. |
| `heavy` | Per-path max5MiB, other detectors not interfering. First `/large` returns exact6MiB, next is local typed heavy451. Script waits for a **human UI overlay release** and Enter, then verifies another6MiB. It does not release the overlay itself. |
| `circuit --open-seconds 1` | Threshold5 in60s, open1s (must match flag), half-open1, health bypass disabled. Five actual503s → local circuit451 → one held half-open request, concurrent attempt denied → successful response closes. For failure/reopen/cadence repeat manually with a5xx probe; unit/controller tests cover missing/failing probe/deadlines. |
| `exempt` | Explicit BLOCK PATH exact`/broker` plus EXEMPT same exact path, ordinary DELETE default retained. Broker passes; DELETE elsewhere still blocks. Confirm EXEMPT evidence and hard scope separately in UI. |
| `intent` | Per-intent limit20; fresh synthetic run UUID isolates previous debt. Exactly20 target arrivals;21st same intent local typed budget451; other intent passes. |
| `listeners --proxy-port 8080 --unselected-proxy-port 8081` | Both actual inbound listeners exist; human restricts guard ports to8080. Selected DELETE denied; unselected DELETE arrives. Human additionally checks no unselected history/raw capture, watcher, intent or approval entry: external clients cannot prove in-memory non-capture. |
| `incident --incident-file /path/to/human-export.json` | **Offline only; no fixtures or clients started.** Bounded4MiB read checks retained `[from,to)` schema, events/top arrays, scalar types, IDs, approximation/retention/truncation flags and absence of known fixture secrets. Human performs export; script does not access Burp data. |

All denial phases validate the local source marker **plus `local:true`, typed guardState and numeric policyRevision**. They also assert zero new fixture arrivals. The fixture records the raw request line (not the standard library's normalized `self.path`), exact body bytes and Host for owned equality assertions. An upstream parser rejection is not a local451; the owned raw Java fixture specifically accepts malformed-percent bytes to prove handoff independent of a generic URI parser.

`python3 -m unittest discover -s scripts -p test_native_burp_smoke.py` checks fixture/client assertions and direct owned socket behavior, **not native Burp**. JUnit adapter/lifecycle tests use Mockito/native-action seams; `runtime/ProxyLoopbackTest` uses a bounded raw loopback fixture and the real controller. Keep these distinct from a real Burp smoke, exact final-JAR validation, release or independent review. Main alone performs native acceptance in a fresh profile; historical results elsewhere do not certify this v2 candidate.
