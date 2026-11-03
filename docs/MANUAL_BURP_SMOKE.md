# Isolated actual-Burp smoke checklist

Use a separate disposable Burp instance/project and an owned numeric-loopback HTTP server. Do not import a real browser profile, real credentials or a production project. Stop if licensing needs user input; never copy license/activation state or bypass checks. Keep raw logs/screenshots/profile data private and outside Git.

Record installed product version/build, exact distribution JAR SHA256, fixture protocol, test date, case results and limitations. Do not publish host paths or original runtime artifacts.

1. Load the distribution JAR. Confirm the independent tab/name and all six sections; no initialization exceptions. Empty allowlist must locally block.
2. Configure only the fixture's loopback host/port/path. Disable Proxy's own interactive intercept in this disposable instance. Verify a safe HTTP request reaches the fixture once.
3. Send DELETE, `/delete`, query/form/JSON `delete`, mixed case and percent/JSON-escaped variants. Confirm local451 marker/evidence ID **and zero fixture requests** for blocked cases.
4. Exercise explicit method/header/body/AND/OR/regex rules and toggles. A hard scope denial must never be overridden by Allow/Monitor/Ask approval.
5. Start at least six independent clients through the same Proxy. At global5RPS verify the observed fixture sequence and the native admission counters; document callback pacing versus arrival timing. Hold responses to check max concurrency, queue timeout and missing-response quarantine.
6. ASK: verify unresolved requests do not arrive, approve one and observe one arrival; deny another and observe zero; let another expire and verify zero. Change policy while waiting and reject the stale decision. Inspect masked UI evidence, not raw secrets.
7. Carry **synthetic** Cookie/Authorization and JSON/form data through an allowed request. Compare the fixture's values/body and returned response with intended values. Inspect JSON/HAR exports for masking/omission and local-versus-upstream provenance. Native Burp may independently normalize transport/hop-by-hop headers; do not misattribute that to extension mutation.
8. HTTPS requires a fixture certificate and explicit temporary client trust, never global CA changes or insecure verification flags. Verify safe/blocked HTTPS paths through Burp MITM. Separately label untested HTTP/2 or TLS-pass-through paths.
9. Unload/reload the extension and close only the disposable instance. No timer leak or already-started request completion should be invented. Unloaded extension is no protection. Remove only owned temporary artifacts after reviewing sanitized results.

CAIRN itself and forced network egress are separate acceptance tests. No Burp control API/extension is supplied to a worker by this checklist.
