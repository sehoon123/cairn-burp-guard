# Controller, native-boundary mocks and owned-loopback verification

Current source removes automatic blocking, not just a toggle. This guide is not a
release/native/independent-review claim. Exact original-method dispositions are
in [AUTOBLOCK_REMOVAL_TEST_MAP.md](AUTOBLOCK_REMOVAL_TEST_MAP.md).

## Distinct evidence layers

- Pure model/policy/codec: actual destination scope, bounded routing aliases,
  explicit rules/EXEMPT/ASK, strict migration/config validation and0/off rates.
- Controller: project/revision/CAS/manual pause/approval/final-send/shutdown,
  authored pacing/intent and complete unmasked originals/exports.
- Mockito Montoya/native-action seams: same original native object/annotations,
  before-commit factories, local451/drop, callback/optional-inspection capacity,
  used-ID fencing and no response guessing. These are not installed Montoya.
- Owned raw numeric-loopback fixture: real sockets and real controller, synthetic
  bodies/credentials, explicit bounded test concurrency/teardown. No extension
  network sender or user's proxy/targets/profile/license is involved.
- Desktop-tag Swing: actual isolated authenticated display/window manager, modal
  lifecycle/geometry/Robot/focus, uiScale1/2 actual graphics transform assertions.
  This is Swing, not installed Burp/native callbacks.
- Historical installed Burp reports/old smoke phases describe their exact old
  artifact only. No new native callback-delivery/safety claim is inferred.

## Decisive removal regressions

`AutomaticBlockingRemovalTest` compiles as a real behavior-red against the old
admission design, then verifies: missing callback, advance well past old timeout,
125 more requests across same/different paths/hosts without native completion;
repeated500/oversize/fan-out BLOCK/PAUSE/WARN without autonomous denial/pause;
and inactive legacy data surviving unrelated save/reload.

`ProxyGuardHandlerTest` verifies normal matching500→next original-object allow,
missing callback past old timeout and beyond the old100-flight cliff, continued
admission for missing/reused IDs, ASK still required for duplicate IDs, fixed
scope/manual/project/shutdown/factory failure boundaries and wrong-tool/duplicate/
late/cleared callback behavior. Known protected ambiguous responses retain their
full originals in explicitly unpaired evidence, not either guessed request.
`ProxyPassthroughTest` covers OFF mixed/reused IDs, no OFF capture/association,
fresh protected pairing after OFF, old protected observations and token staleness.

`LateResponseRegressionTest`/`WatcherRoutingInteropTest` retain traffic spelling,
actual-service display, observational provenance/clear/reset and strict health
configuration; old actuator assertions are replaced, not routing tests filtered.
`ResponseWatcherTest` retains statistics/windows/histogram/unbounded observation
retention and original display. There are no ticket/overlay/half-open/Seen tests
pretending those removed mechanisms still execute.

## Preserved independent protection

Controller/policy/approval/lifecycle/adapter tests keep empty/outside scope and
blocked scope, explicit BLOCK/ALLOW/EXEMPT/ASK priority, provisional one-shot
approval timeout/cancel/stale/deny, manual pause with exact GET health exceptions,
policy save/project uncertainty, single-use Prepared ownership and native factory
checks immediately before commit. Inspection saturation/unsupported/oversized/
malformed body stays unavailable inspection, never dropped/altered original.

RateGate tests preserve exact returned-admission timing, no idle burst credit,
canonical/IDN/IPv6 overrides, fractional intervals, global/host independence,
FIFO/eligible round-robin/cancellation, queue shrink/fairness/capacity/deadline/
nano wrap, live rate/timeout updates, stale/throwing predicates, interruption/
shutdown and immutable bounded operational p95 metrics.0/off covers every axis,
disable drops only that axis's debt, positive overrides remain, reenable works.
ApprovalQueue tests remain unchanged. Native concurrency/permit/quarantine checks
are intentionally retired; no native count is reinterpreted as callback concurrency.

Evidence suites retain original header/body/URL/metadata, no masking/collection
quota, immutable snapshots/seals/forged selection rejection, HEX/base64/charset
truthfulness, all-row retention/large exports, consent/atomic file safety, source/
project/raw-generation checks and clear/unload disposal. New response-only export
coverage checks full bodies and unavailable requests across raw/schema2/human
JSON/HAR, without guessing local vs upstream origin.

UI tests keep human drafts/CAS/cancel/stale behavior, migration, rule/scope editing,
retained manual controls, original viewing/export/consent and accessibility.
Retired automatic-block/candidate/detector controls must be absent. Legacy settings
must survive edits. All-rates-off remains a draft through Cancel; normal modal
Save applies0 to global/default/every override, preserves spelling/unrelated data,
and reopens unchanged. Desktop and headless coverage remain separate.

## Owned-loopback semantics

The raw fixture records exact request line/Host/body; it does not normalize the
request target. Denials assert zero fixture arrivals/socket opens; allowed fuzzed
Host/malformed-percent/binary/unsupported content verifies unchanged owned bytes.
Queued state-change tests wait on authored1RPS pacing, not a native permit. Six
workers with5RPS and legacy maxConcurrent2 can have SIX unanswered owned operations:
there is no native concurrency gate. Exact pacing is checked at RateGate's own
returned timestamp; post-handoff loopback samples allow scheduling jitter and are
not wire-rate proof. Actual matching response500 is an observation, not a future
verdict. Teardown quiesces only fixture/caller resources this test created.

## Reproduction and acceptance boundary

```sh
./gradlew --offline --no-daemon --max-workers=2 --no-build-cache clean test jar
./gradlew --offline --no-daemon --max-workers=2 --no-build-cache clean jar
python3 -m unittest discover -s scripts -p 'test_*.py'
# On an isolated authenticated X display, not a user's live desktop:
./gradlew --offline --no-daemon --max-workers=2 --no-build-cache desktopTest -PdesktopUiScale=1
./gradlew --offline --no-daemon --max-workers=2 --no-build-cache desktopTest -PdesktopUiScale=2
```

Unfiltered clean tests/JAR, independent twin build/hash/CRC/class/legal checks,
complete frozen input membership/bytes/modes/live-copy comparison, Python/template
results and real graphics-transform desktop exits/XML/skips must be recorded for
the exact candidate. Focused green is not a substitute. Do not sum overlapping
slices or hide infra/capability failures as feature deletion. No source/count alone
establishes native callback delivery, target arrival, platform/file-system support,
authenticated quota, public release or independent acceptance.
