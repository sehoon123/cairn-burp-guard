# Bounded policy engine

`dev.cairnguard.policy.PolicyEngine` implements `validate(GuardConfig)` and
`evaluate(GuardConfig, RequestData)`. It consumes an inspection **copy**, not a
Burp request. There are no native Burp APIs, sockets, DNS lookups, file writes,
authentication changes, or logging in this package. Neither ALLOW nor MONITOR
constructs or modifies a request. The runtime alone controls native continuation.

## Evaluation and precedence

1. Validate/compile the entire configuration, including disabled entries. Invalid
   configuration evaluates to a categorical `INVALID_CONFIG` block. Explicit
   `validate` throws `IllegalArgumentException` with a fixed category and no cause
   chain containing the offending expression or input.
2. Validate absolute HTTP(S) URI, actual service authority, header structure, and
   raw/decoded scope paths. URI userinfo/fragments, invalid ports, authority
   disagreement, unsupported encodings/upgrades, and ambiguous paths block.
3. A matching block scope wins. At least one enabled allow scope must cover the
   authority **and every raw/decoded path view**; empty allow scope allows nothing.
   A block scope matching **any** path view blocks. Scope regular expressions
   full-match the path only, never query or the full URL. Empty path expression
   means any path. Scope port 0 and scheme `any` mean any port / HTTP(S) scheme.
4. Inspect all supported request structures before testing any rule. A true OR,
   an ALLOW, or an earlier matching BLOCK cannot hide a malformed input, exceed a
   budget silently, or omit unsupported structured data from an ALLOW decision.
5. Record all enabled matching rules, in configuration order. Rule actions have
   precedence BLOCK > ASK > ALLOW, independent of list order. MONITOR only records
   a hit. With no actionable hit, use the configured default mode. Defaults do
   not compete with explicit rule actions. Hard-gate failures have no rule hits.

AND/OR groups have 1–64 children and no leaf metadata (`field`/`match` null;
`name`/`value` null or empty). LEAF conditions have no children. CONTAINS and
EXACT treat the value literally; REGEX uses RE2/J **find** semantics. EXACT uses
full-value matching. Inline RE2 flags are supported; lookaround, backreferences,
and other expressions not supported by RE2/J are rejected, never run by Java's
backtracking regex engine. Case-insensitive matching uses RE2/J case folding.

## Authorities and scope boundaries

Hosts use Java IDN/STD3 ASCII normalization and case folding, with one terminal
ASCII DNS dot normalized away. IPv4 must have four decimal octets, with no
leading zero aliases; short/integer/hexadecimal IPv4 forms are rejected. IPv6 is
parsed numerically in-process and compared in expanded canonical form; no DNS or
`InetAddress` calls occur. Bracketed URI IPv6 and unbracketed service IPv6 agree
when numerically equivalent. Zone IDs are unsupported. This is Java IDN's
normalization, not a claim of IDNA2008 resolver equivalence.

`*.example.test` matches only proper DNS-label subdomains (including deeper
ones), not the apex, `notexample.test`, or `example.test.evil`. Wildcard IP scope
entries are rejected. URL scheme/effective port/host must agree with the actual
service's secure flag/port/host. If Host is present, exactly one Host is allowed
and its effective authority must also agree. Host absence is accepted because
`RequestData` carries no HTTP version; URI/service agreement is still mandatory.
Raw HTTP/2 pseudo-header names are not supported in this copy API and fail header
validation; the native adapter must supply an ordinary inspected header view.

Dot segments (`.` / `..`), backslashes, semicolon/matrix path parameters, decoded
`?` / `#` in paths, and path control characters fail closed instead of guessing
server normalization (including `..;` matrix-parameter traversal). A restrictive
allow path may therefore reject percent-escaped spelling that would decode into
an allowed path: both spellings must be covered. Query cannot broaden scope.

## Inspection views

- METHOD, URL, PATH, BODY: raw and bounded percent-decoded textual views. A path
  `+` stays literal, including within URL views. URL query components and form
  BODY views also include `+`-to-space decoding. Non-form body/header `+` stays
  literal.
- QUERY and FORM: raw/decoded keys and values, with `+` interpreted as space.
  Both `&` and `;` separators are inspected conservatively, including separators
  revealed by decoding. Duplicate parameters are all inspected. Key-only pairs
  mean an empty value; empty separator-only pairs are skipped. A named selector
  matches values for that name; an empty selector examines names **and** values.
- HEADER: all observed names and values, including repeated ordinary headers.
  Named header selectors always compare HTTP names case-insensitively; the
  condition case flag still controls value matching. Query/form selector names
  follow the condition's case flag.
- JSON: a strict **streaming** parse with duplicate-key detection, no comments,
  trailing tokens, non-finite numbers, or permissive escapes. JSON strings and
  keys are Unicode-unescaped, then their percent views are inspected. An empty
  selector flattens keys/scalars (including numbers, booleans, and null). A
  nonempty selector is an RFC6901 pointer, with `~0` / `~1`, exact-case object keys,
  canonical array indices, and subtree inspection. Percent-decoded key aliases
  also participate in selection; aliases colliding with another key block as
  ambiguous. A missing pointer does not match. A selected scalar examines the
  scalar, not the name of its parent field.
- ANY is the union of these supported inspection views. It is not arbitrary
  application semantic analysis or proof that an action is nondestructive.

Percent decoding is strict UTF-8, at most **three transforming rounds**. Malformed
escapes, invalid/overlong UTF-8, unpaired Unicode surrogates, disallowed controls,
or another encoded layer after the limit block. This intentionally conservative
recursive contract also rejects a literal `%` (including `%25` when it reveals a
dangling percent), so valid prose or credential strings containing literal
percent characters can be blocked. Replacement characters are never substituted
for invalid byte sequences. These bounds are not relaxed by ALLOW/MONITOR.

Nonempty JSON / `application/*+json` / `text/*+json` bodies are parsed as JSON.
Text bodies that start with an object, array, or quoted string are also checked
as JSON, to avoid a simple missing/mislabeled-content-type Unicode-escape bypass.
BOM-prefixed JSON-looking text is not exempted; a BOM that this strict String
parser does not support yields a block.
Form bodies use `application/x-www-form-urlencoded`. Other `text/*`, or absent
Content-Type, use strict UTF-8 text inspection (ASCII declarations are enforced).
Only UTF-8 and US-ASCII charset declarations are accepted. Unknown non-text media,
nonempty binary/multipart data, XML application media, nonidentity
Content-Encoding, Transfer-Encoding, and protocol upgrades fail closed. Bodyless
requests need not contain a JSON document even with JSON Content-Type. Duplicate
Content-Type/Content-Encoding/Content-Length, inconsistent Content-Length,
malformed media parameters, CR/LF in raw or decoded header values, and WebSocket
headers block. HTTP horizontal tabs in header values are permitted.

This does **not** interpret HTML/XML entities, Base64, encrypted payloads, custom
application serialization, arbitrary Unicode escape syntax outside parsed JSON,
or recursively deserialize JSON embedded inside JSON strings. It does not inspect
WebSocket frames or transport traffic absent from the native callback. Strict
text acceptance is not a claim to understand every server's parser. For formats
outside this MVP, narrow the allow scope and block the unsupported workflow rather
than assume application-level enforcement.

## Hard bounds

| Resource | Bound |
|---|---:|
| Schema version | 1 |
| Allow / block scope entries | 256 each |
| Rules | 256 |
| Total condition nodes / depth | 2,048 / 16 (root depth 0) |
| Children per boolean group | 64 |
| Rule ID / name | 128 / 256 characters (IDs ASCII letters/digits/`._-`) |
| Leaf literal / selector | 4,096 / 512 characters |
| Individual REGEX/scope RE2 source / program | 2,048 characters / 4,096 instructions |
| Aggregate pattern sources / programs | 65,536 characters / 131,072 instructions |
| Global / per-host / override RPS | 1–1,000 |
| Host rate overrides | 256 distinct canonical exact hosts |
| Concurrent / queued | 1–100 / 0–10,000 |
| Queue / approval / request timeout | 1–600,000 ms |
| URL | 16,384 characters |
| Header count / name | 256 / 256 characters |
| URL + method + header text | 65,536 characters |
| Request body, and body + above text | 1,048,576 bytes / conservative mixed-size units |
| Query / form pairs | 1,024 per structure (including revealed variants) |
| JSON nodes including keys / depth | 4,096 / 32 (root depth 0) |
| Expanded text / produced views | 16 Mi characters / 32,768 |
| Matching work | 64 Mi estimated character-instruction units |

RE2 matching work is charged by input length times compiled program size; literal
matching and selector comparisons use weight 1. Work exhaustion is a hard block,
including after an earlier ALLOW hit. These are implementation ceilings, not
benchmarked throughput guarantees. The engine caches only one immutable compiled
configuration, keyed by object identity, and retains no request/inspection after
evaluation. JSON node/depth ceilings are checked while streaming, before building
a large object tree. `RequestData.body()` supplies a defensive clone; native
capture must itself be bounded before constructing the inspection copy (the
engine cannot prevent memory already allocated by its caller).

## Verification boundaries

Synthetic JUnit fixtures live in `src/test/java/dev/cairnguard/policy/`. They cover
precedence, nested boolean logic, all fields, selectors, raw/decoded views,
Unicode JSON, malformed encodings/JSON/form, authority mismatch, wildcard
boundaries, URI/header ambiguity, unsupported formats, work/structure/config
limits, RE2 unsupported features, concurrent revision changes, no authentication
mutation, and categorical errors without source/pattern output. An isolated run
uses `./gradlew test --tests 'dev.cairnguard.policy.*'`.

Verified on 2026-11-03: `./gradlew test --tests 'dev.cairnguard.policy.*'
--no-daemon --offline --rerun-tasks` completed **142 synthetic cases**, zero
failures/errors/skips; Java compilation included the project's `-Xlint:all`.
These tests are not a live Burp smoke test, real-target test, delivery guarantee,
or measurement of the runtime pacing/queue implementation.
