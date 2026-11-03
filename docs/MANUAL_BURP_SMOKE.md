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

## Reproducible external fixture/client harness

`scripts/native_burp_smoke.py` uses Python's standard library, creates owned loopback echo servers and sends **only synthetic fixture traffic** through an already configured local Proxy. Strings such as `delete`/`purge` have no operation behind them: the servers only echo data. The script never starts, loads, configures, approves, or controls Burp. All policy/approval actions below are made in the disposable product's human UI. Do not give this operator workflow to a CAIRN worker.

1. Use an isolated, normally licensed/available Burp edition. A product-provided **Community Edition** selection is legitimate; copying Professional activation state or bypassing its activation is not. Use a temporary in-memory project if Community does not support a project file.
2. Load the exact JAR and record its SHA256. Confirm Proxy Intercept is off and the listener is exclusively the disposable instance's loopback listener (defaults below: `127.0.0.1:8080`). No live project or global proxy settings are needed.
3. With an empty allowlist run `python3 scripts/native_burp_smoke.py --phase empty`. The local451 must contain the fixed guard marker, categorical reason, UUID evidence ID, and `retryable:false`; the fixture must receive zero requests.
4. [guard.loopback-smoke.json](../templates/examples/guard.loopback-smoke.json) is a **full example policy**, NOT an import/control endpoint. Copy its `allowScope` and `blockScope` arrays into the corresponding Scope editors. Initially retain the two built-in rules and default limits. Click **Apply ALL policy drafts**. For example `jq '.allowScope' templates/examples/guard.loopback-smoke.json` prints an array for manual copying; do not paste the whole document into an array editor.
5. Run `python3 scripts/native_burp_smoke.py --phase default`. Six clients/two numeric-loopback hosts share global5RPS; the controlled 1.5s hold case measures fixture concurrency. The harness records arrival timing, **not a guaranteed wire-admission clock**.
6. Copy the example's full `rules` array into Rules and apply. Composite nodes deliberately include all record fields, including `caseSensitive:false`; missing primitive values are rejected by the strict UI parser. Run `--phase custom`. Use **Toggle selected** on `fixture-composite`, apply, run `--phase disabled`, then re-enable and apply it. These tests distinguish actual BLOCK categories from scope/inspection failures and check negative/case-sensitive conditions.

Additional phases require these explicit UI preconditions (other values remain at example defaults):

| Phase | UI configuration/action | Expected result |
|---|---|---|
| `approve` | `fixture-ask` enabled; select pending `/ask` and Approve selected ONCE | No unresolved arrival; one after approval |
| `deny` | Same, choose Deny selected | `DENIED`, zero arrivals |
| `expire` | Approval timeout4000ms; no decision | `APPROVAL_TIMEOUT`, zero arrivals |
| `stale` | Approval timeout30000ms; while pending, change queue timeout to29000ms and apply | `POLICY_CHANGED`, zero arrivals |
| `host` | Global5/default-host5; exact overrides `{"hostRps":{"127.0.0.1":2,"127.0.0.2":2}}` | Two hosts independently limited to2RPS, still sharing global5 |
| `queue` | Clear overrides; max concurrent1; queue timeout80ms; request timeout60000ms | One fixture arrival, five `QUEUE_TIMEOUT` local blocks |
| `quarantine` | Max concurrent1; queue timeout30000ms; request timeout500ms | Probe blocked with `IN_FLIGHT_TIMEOUT` while first response is held; real completion permits a later request |
| `paused` | Dashboard: pause new Proxy requests | `PAUSED`, zero arrivals |

Restore example limits and unpause when finished. Pause changes revision: use explicit **Reload policy / discard drafts** before the next policy edit if the draft is marked stale. Never lower the in-flight threshold to infer that an already sent request was cancelled.

### Strict TLS variant

The TLS tests use `localhost`, after checking it resolves **exclusively to loopback**, because the installed Burp's numeric-IP certificate did not satisfy strict IP-SAN verification. The test does not turn off chain/hostname verification or install a global CA. The harness refuses to label this single-host TLS variant as the two-host HTTP pacing experiment.

- Retain the explicit `https`/`localhost:18080` allow/block entries from the example.
- In the disposable Burp UI, Proxy settings → Import/export CA certificate → **Certificate in DER format**. Export **only the public certificate**, never the private key/keystore. This is not license or activation data.
- Generate a temporary fixture certificate/key outside the checkout, with owner-only permissions. Use no real credentials:

```sh
SMOKE_DIR="$(mktemp -d)"
chmod 700 "$SMOKE_DIR"
# Export Burp's PUBLIC certificate to "$SMOKE_DIR/disposable-burp-ca.der" in its UI first.
openssl x509 -inform DER -in "$SMOKE_DIR/disposable-burp-ca.der" \
  -out "$SMOKE_DIR/disposable-burp-ca.pem"
(umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$SMOKE_DIR/fixture-key.pem" -out "$SMOKE_DIR/fixture-cert.pem" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1')
python3 scripts/native_burp_smoke.py --phase basic --https \
  --fixture-cert "$SMOKE_DIR/fixture-cert.pem" --fixture-key "$SMOKE_DIR/fixture-key.pem" \
  --burp-ca "$SMOKE_DIR/disposable-burp-ca.pem"
python3 scripts/native_burp_smoke.py --phase custom --https \
  --fixture-cert "$SMOKE_DIR/fixture-cert.pem" --fixture-key "$SMOKE_DIR/fixture-key.pem" \
  --burp-ca "$SMOKE_DIR/disposable-burp-ca.pem"
```

These clients use CONNECT plus certificate-verified TLS with HTTP/1.1 inside the tunnel; HTTP/2 and opaque TLS pass-through remain separate, unverified cases. Keep generated keys, CA files, exports, screenshots and logs outside Git. Inspect masked JSON/HAR, test search/bookmarks and restore/unload/close only the owned disposable instance. The script closes its own servers on phase exit; the human is responsible for the Burp/profile/certificate cleanup.

Harness self-checks are **offline unit checks, not native experiments**:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Do not run the harness with `python -O` / `PYTHONOPTIMIZE`; it refuses optimized execution rather than silently disabling its checks. Observed results and gaps are recorded separately in [NATIVE_BURP_RESULTS.md](NATIVE_BURP_RESULTS.md).
