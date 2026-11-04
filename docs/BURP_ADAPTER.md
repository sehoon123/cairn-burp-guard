# Native Burp adapter

The production entrypoint is `dev.cairnguard.GuardExtension`. It creates the human Swing tab, project-local policy storage and one Montoya `HttpHandler`. Only requests/responses identified as **ToolType.PROXY** are inspected; Repeater/Scanner/other extensions are not silently brought into scope.

`ProxyGuardHandler` keeps original request/response/annotation objects. Inspection uses separate bounded copies (1 MiB request body, bounded metadata), and HTTP/2 pseudo-header normalization occurs in that copy only. Inconsistent/malformed pseudo fields fail closed. Native body length is checked before copying native body bytes. Callback/inspection/correlation capacities are bounded at 128/8/100.

With **protection ON**, the pipeline is capture -> policy/evidence -> approval (no native permit) -> shared rate/concurrency permit -> construct continuation -> final project/revision/pause check -> release original native object. Policy/queue/approval/capture failures never return an allowed continuation.

A block produces local HTTP451 JSON with `source: cairn-proxy-guard`, an opaque evidence ID, categorical reason and `retryable:false`. The finite native `model.DenialReasons.ALL` vocabulary is shared with evidence so runtime/capacity/capture labels survive snapshots and JSON/HAR without permitting arbitrary error text. It does not echo request data, exception messages or regex captures. Failure of the native spoof factory falls back to drop, never allow. An ambiguous repeated native message ID is dropped rather than fabricating a response that could release an older request's permit.

Response IDs correlate to the actual admitted native request. Only an observed matching Proxy response or a conclusively-unsent dispatch failure releases the permit. Missing/timeout responses retain their permits and quarantine new admissions; unloading does not invent completion. Response capture failures still continue the original native response without editing Cookie/Set-Cookie/Authorization/body. Oversized/unsafe evidence is omitted rather than storing a raw prefix.

Policies use project-local `extensionData` plus a project-ID-namespaced key, not global preferences. Load/save project checks fail closed, but separate native API calls cannot prove atomicity across an unobserved switch/ABA. UI stale-draft tokens and adjacent release checks reduce, not magically eliminate, that native boundary.

## Explicit temporary all-Proxy passthrough

The human-confirmed OFF path is deliberately before native capture and EDT/slot/policy/approval/rate checks. It constructs the SAME original-object action and then commits a data-free project/revision token under the release lock. A stale token, shutdown, factory failure or collision with an existing protected ID cannot release a request. OFF retains no new native object, URL, host, evidence or response correlation; only a saturating count is kept. It neither drains existing waits nor recycles old permits. Existing protected responses still complete their own permits and masked evidence, including while OFF. After restore, new OFF-originated responses remain untracked. The UI and docs warn that OFF concurrency cannot be reconstructed. No CAIRN/worker API is added. See [PASSTHROUGH.md](PASSTHROUGH.md) for state/reset contracts.

## Verification

The JUnit adapter/lifecycle suites use Mockito and a `NativeActions` seam. They test no mutation, tool filtering, bounded capture, malformed metadata, spoof/drop failure handling, duplicate IDs, permit ownership and EDT/lifecycle cleanup. These are not proof of installed Burp behavior. Current installed-Burp results are recorded separately in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md) and summarized in [VERIFICATION.md](VERIFICATION.md).

Use [MANUAL_BURP_SMOKE.md](MANUAL_BURP_SMOKE.md) before trusting a new Burp/JAR combination. No target requests are made by the extension itself; operator-side fixture/client scripts are separate test code, not bundled in the extension JAR and never provided to CAIRN workers.
