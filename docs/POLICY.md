# Bounded policy engine

`dev.cairnguard.policy.PolicyEngine` implements `validate(GuardConfig)` and
`evaluate(GuardConfig, RequestData)`. This package is network-free and examines
bounded inspection copies. It does not rewrite native requests, normalize the
forwarded path, repair Host headers, manage authentication, or log request data.

> **Implementation status:** this document describes the in-progress v2 policy
> implementation, not a claim that the existing development-preview JAR contains
> it. Full controller/UI/native integration and exact-artifact verification are
> separate acceptance gates.

## Scope is not a pentest-path sanitizer

Scope uses the **actual transport service host, scheme and port**, plus the actual
request-target path. A fuzzed `Host`/`:authority` header, or a header-derived URL
authority, cannot deny an otherwise permitted destination or authorize a different
one. The native adapter must construct the inspection URL from `httpService()` and
the untouched `path()` (including its query), not trust a Host-derived `url()`.
Explicit HEADER rules can still match a fuzzed header when inspection is available.

**Allowing all paths really allows all paths.** In particular, these targets must
not be denied merely as `AMBIGUOUS_PATH`:

```text
/c/;/main.do
/c/%2e/main.do
/c/%252e/main.do
/c/child/../main.do
/c/%3b/main.do
```

Semicolons/matrix parameters, dot segments, encoded separators and repeated
encoding are legitimate pentest inputs. They are forwarded unchanged. Bounded
raw, decoded and conservative normalized aliases exist **only inside scope,
rule matching and runtime route keys**; none replaces the native target.

For a **restricted** path scope, every known interpretation must fit one allow
entry. A block scope matching any interpretation wins. This prevents a scope such
as `/c/.*` from authorizing `/c/%2e%2e/private` solely because its raw spelling
starts with `/c/`. Query data never broadens scope. Empty allow scope allows nothing.
Empty path expression means all paths; port `0` and scheme `any` mean any port and
HTTP(S) scheme respectively.

Path decoding has a fixed work/depth limit. Invalid, non-text or deeper encodings
can pass explicit all-path scope with `PATH_INTERPRETATION_INCOMPLETE`, not a fake
successful decoding result. They cannot prove a restricted allow/block-path
constraint was satisfied. The explicit all-path UI setting and common universal
regex spellings are recognized; this is not an arbitrary RE2 universality proof.
Unknown method, invalid actual destination, unavailable target representation or
mandatory routing-capacity failure still fails closed.

This relaxed **traffic** handling does not relax authored health-probe or
per-path byte-limit configuration: those routes remain exact, unambiguous,
query-free, fragment-free and bounded. A pentest spelling is not automatically a
configured health probe.

## Evaluation and precedence

1. Validate/compile the complete configuration, including disabled entries.
   Invalid configuration gives categorical `INVALID_CONFIG`; explicit validation
   throws a fixed-category exception without offending input or a cause chain.
2. Check actual service/routing scope. Empty allow scope allows nothing. A rule,
   including EXEMPT, never overrides scope.
3. Inspect only fields demanded by enabled rules. Optional header/body/query/URL
   parsing or capture limitations are **inspection warnings, not automatic 451s**.
4. Record enabled known matches in configuration order. Ordinary action priority
   is **EXEMPT > BLOCK > ASK > ALLOW**; MONITOR only records. With no actionable
   hit, use the configured default. Defaults do not compete with explicit rules.
5. EXEMPT bypasses ordinary policy BLOCK/ASK only. It never bypasses project or
   lifecycle validity, automatic safety overlays, budgets, pacing, queue limits,
   shutdown or actual destination scope. It cannot be the default mode or a v1
   rule; empty/common syntactically universal exemptions are rejected.

Unknown inspection is not a match or a successful check. Known positive ordinary
OR/ANY branches (and known raw PATH matches) remain enforceable. A condition
requiring unavailable inspection **cannot grant EXEMPT**, even if another OR
branch matches. Routing-only conditions do not unnecessarily demand body parsing.

AND/OR groups have 1–64 children and no leaf metadata. LEAF conditions have no
children. CONTAINS/EXACT are literal; REGEX uses bounded RE2/J `find` semantics;
EXACT and scope expressions full-match. Unsupported RE2 syntax is rejected, never
run by Java backtracking regex. Case-insensitive matching uses RE2 case folding.

Automatic protections (large-response, 5xx circuit, distinct-path fan-out) are
NOT rules and never act as EXEMPT/ALLOW: their per-kind ON/OFF switches and exact
route exceptions (heavy size 0, circuit/fan-out exact routes) bypass only that
automatic actuator. Scope, these rules, approval, operator pause, rate, intent,
lifecycle, timeout and physical capacity still apply. See INTERFACES.md.

## Inspection views and limitations

- METHOD/PATH/URL/BODY use raw and bounded textual views. Path `+` is literal;
  query and form `+` can represent space. URL-rule authority is reconstructed from
  the actual destination, not the supplied Host header.
- QUERY/FORM examine raw/decoded keys and values, repeated parameters and bounded
  revealed `&`/`;` separators. A named selector selects values; an empty selector
  also examines keys.
- HEADER examines captured names/values, including repeats. Header selector names
  are case-insensitive. Incomplete capture is never treated as complete headers.
- JSON uses strict streaming parsing, duplicate-key detection, bounded nodes/depth,
  Unicode/percent views and RFC6901 selectors. Missing pointers do not match.
- ANY combines supported known views, not arbitrary application semantics or a
  proof that an operation is harmless.

Field scope, in brief: BODY matches the raw and bounded decoded text of the whole
body (it does not parse JSON or forms, so it can still match malformed JSON). JSON
with an empty selector examines every object key and scalar value; a RFC6901
pointer selects only that value and its nested keys/scalars. ANY is the broadest:
method, query, headers, BODY/JSON/FORM views and URL/PATH routing views together.
Prefer the narrowest field that expresses the rule.
`HEADERS_INCOMPLETE`/`BODY_INCOMPLETE` only report optional capture; a
field-unavailable warning appears only for a field that an enabled rule demanded.

Textual percent decoding uses strict UTF-8 and at most three transforming rounds;
replacement characters are not silently substituted. A malformed escape, literal
percent, unsupported charset/media/encoding, binary/multipart data, malformed JSON,
header ambiguity, incomplete capture or optional inspection/matching bound makes
the affected field unavailable with a categorical warning. It does **not** create
a blanket denial for otherwise in-scope traffic. An inspectable explicit text
rule can still match a malformed JSON body without claiming JSON parsing worked.

There is no general interpretation of XML/HTML entities, Base64, encryption,
custom serialization, recursive JSON-in-strings, WebSocket frames or unseen native
traffic. Inspection warnings disclose this limitation rather than pretend to
provide server-equivalent parsing. Evidence capture is complete and unmasked regardless
of these policy inspection bounds (an oversized/unsupported body is retained but
unavailable to rules); see `EVIDENCE.md` and the runtime/UI integration requirements.

## Authorities and bounds

Actual hosts use in-process Java IDN/STD3 normalization and case folding with one
terminal DNS dot removed. IPv4 is four decimal octets without leading-zero aliases;
IPv6 is parsed numerically without DNS/`InetAddress`. Zone IDs and short/integer/hex
IPv4 aliases are unsupported. `*.example.test` matches proper DNS-label subdomains,
not the apex or suffix lookalikes. This is not an IDNA2008 resolver-equivalence claim.

| Resource | Bound |
|---|---:|
| Persisted schema | v2; explicit strict v1 migration, no load-time write |
| Allow/block scopes / rules | 256 each |
| Condition nodes / depth / children per group | 2,048 / 16 / 64 |
| Rule ID / name / literal / selector | 128 / 256 / 4,096 / 512 characters |
| RE2 source / program | 2,048 characters / 4,096 instructions |
| Aggregate RE2 sources / programs | 65,536 characters / 131,072 instructions |
| Global/per-host/override RPS / overrides | 1–1,000 / 256 exact hosts |
| Concurrent / queued | 1–100 / 0–10,000 |
| Queue/approval/request timeout | 1–600,000 ms |
| Routing URL/path | 16,384 characters |
| Optional header count / text | 256 / 65,536 characters |
| Optional body inspection | 1,048,576 bytes |
| Query/form pairs / JSON nodes / JSON depth | 1,024 / 4,096 / 32 |
| Expanded text / produced views | 16 Mi characters / 32,768 |
| Estimated matching work | 64 Mi character-instruction units |

Configuration/mandatory routing capacity is distinct from optional content
inspection. Optional exhaustion reports unavailable inspection. These are ceilings,
not throughput guarantees. The compiled cache retains one immutable policy by
identity, not requests. `RequestData.body()` defensively clones; the native adapter
must bound its own copy before constructing it.

## Verification boundaries

The 2026-11-04 isolated model/policy/attribution slice passed **278 synthetic
JUnit cases**, including **23 `PentestRoutingTest` cases**. The new regression first
reproduced the blanket `AMBIGUOUS_PATH` failure, then covered all-path acceptance,
restricted-scope escape rejection, immutable input, incomplete-interpretation
warnings, and prevention of incomplete-path EXEMPT. Existing policy and strict
codec/migration cases passed in the same clean isolated rebuild.

This is **not** a full-repository build, native Burp delivery test, exact-JAR
verification, independent implementation approval, release, or completion claim.
Historical tests for the prior preview do not verify this new worktree.
