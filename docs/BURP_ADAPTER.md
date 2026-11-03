# Native Burp adapter

The production entrypoint is `dev.cairnguard.GuardExtension`. It creates the human Swing tab, project-local policy storage and one Montoya `HttpHandler`. Only requests/responses identified as **ToolType.PROXY** are inspected; Repeater/Scanner/other extensions are not silently brought into scope.

`ProxyGuardHandler` keeps original request/response/annotation objects. Inspection uses separate bounded copies (1 MiB request body, bounded metadata), and HTTP/2 pseudo-header normalization occurs in that copy only. Inconsistent/malformed pseudo fields fail closed. Native body length is checked before copying native body bytes. Callback/inspection/correlation capacities are bounded at 128/8/100.

The pipeline is capture -> policy/evidence -> approval (no native permit) -> shared rate/concurrency permit -> construct continuation -> final project/revision/pause check -> release original native object. Policy/queue/approval/capture failures never return an allowed continuation.

A block produces local HTTP451 JSON with `source: cairn-proxy-guard`, an opaque evidence ID, categorical reason and `retryable:false`. It does not echo request data, exception messages or regex captures. Failure of the native spoof factory falls back to drop, never allow. An ambiguous repeated native message ID is dropped rather than fabricating a response that could release an older request's permit.

Response IDs correlate to the actual admitted native request. Only an observed matching Proxy response or a conclusively-unsent dispatch failure releases the permit. Missing/timeout responses retain their permits and quarantine new admissions; unloading does not invent completion. Response capture failures still continue the original native response without editing Cookie/Set-Cookie/Authorization/body. Oversized/unsafe evidence is omitted rather than storing a raw prefix.

Policies use project-local `extensionData` plus a project-ID-namespaced key, not global preferences. Load/save project checks fail closed, but separate native API calls cannot prove atomicity across an unobserved switch/ABA. UI stale-draft tokens and adjacent release checks reduce, not magically eliminate, that native boundary.

## Verification

The JUnit adapter/lifecycle suites use Mockito and a `NativeActions` seam. They test no mutation, tool filtering, bounded capture, malformed metadata, spoof/drop failure handling, duplicate IDs, permit ownership and EDT/lifecycle cleanup. These are not proof of installed Burp behavior. Actual installed Burp results are recorded only in [VERIFICATION.md](VERIFICATION.md).

Use [MANUAL_BURP_SMOKE.md](MANUAL_BURP_SMOKE.md) before trusting a new Burp/JAR combination. No target requests are made by the extension itself; developer smoke drivers are separate, non-shipped test code, never provided to CAIRN workers.
