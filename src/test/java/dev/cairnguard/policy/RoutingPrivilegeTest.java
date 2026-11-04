package dev.cairnguard.policy;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.RequestData;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for adjudicated audit findings B-1/B-7 (EXEMPT any-view privilege, URL alias
 * views) and A-1/A-2 (non-origin-form targets, raw control characters). Offline policy evidence
 * only; NOT native Burp proof.
 */
class RoutingPrivilegeTest {
    private final PolicyEngine engine = new PolicyEngine();

    private static Condition path(Match match, String value) { return Condition.leaf(Field.PATH, match, value); }
    private static Condition url(Match match, String value) { return Condition.leaf(Field.URL, match, value); }
    private static Rule rule(String id, Mode mode, Condition condition) { return new Rule(id, id, true, mode, condition); }
    private static ScopeEntry scope(String expression) { return new ScopeEntry(true, "owned.test", "https", 443, expression); }
    private static GuardConfig policy(String allow, List<ScopeEntry> blocked, List<Rule> rules) {
        return new GuardConfig(2, List.of(scope(allow)), blocked, rules, Mode.ALLOW, GuardConfig.defaults().limits());
    }
    private static GuardConfig all(Rule... rules) { return policy("", List.of(), List.of(rules)); }
    /** Legacy (no nativeTarget) request; the supplied URL authority is deliberately fuzzed. */
    private static RequestData legacy(String method, String target) {
        return new RequestData(method, "https://fuzzed-host.invalid" + target, "owned.test", 443, true,
                List.of(new RequestData.Header("Host", "fuzzed-host.invalid")), new byte[0]);
    }
    /** Native-capture shape: synthetic URL plus the separately preserved untouched native target. */
    private static RequestData nativeRequest(String method, String target) {
        return new RequestData(method, "https://owned.test:443" + target, "owned.test", 443, true,
                List.of(new RequestData.Header("Host", "fuzzed-host.invalid")), new byte[0], true, true, target);
    }
    private static List<String> hits(Decision decision) {
        return decision.hits().stream().map(Decision.RuleHit::id).toList();
    }
    private static String latin1(String text) {
        return new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    // ---- (1) B-1: EXEMPT requires EVERY routing view; ordinary rules keep any-view positives ----

    @ParameterizedTest
    @ValueSource(strings = {"/broker/../admin/delete", "/broker/..;/admin/delete", "/broker/%2e%2e/admin/delete",
            "/broker/%2e%2e%2fadmin/delete", "/broker/%252e%252e/admin/delete", "/broker/..%5cadmin/delete",
            "/broker/.%2e/admin/delete", "/broker//../../admin/delete"})
    void disagreeingRoutingAliasCannotGainExemptOverExplicitBlock(String target) {
        GuardConfig cfg = all(rule("block-admin", Mode.BLOCK, path(Match.REGEX, "^/admin(?:/|$)")),
                rule("exempt-broker", Mode.EXEMPT, path(Match.REGEX, "^/broker/")));
        for (RequestData request : List.of(legacy("GET", target), nativeRequest("GET", target))) {
            Decision decision = engine.evaluate(cfg, request);
            assertEquals("RULE_BLOCK", decision.reason(), target);
            assertEquals(List.of("block-admin"), hits(decision), target);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/broker/x", "/broker/a/b?q=1", "/broker//x", "/broker/./x", "/broker/%78"})
    void agreeingRoutingViewsStillGrantPathExempt(String target) {
        GuardConfig cfg = all(rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET")),
                rule("exempt-broker", Mode.EXEMPT, path(Match.REGEX, "^/broker/")));
        for (RequestData request : List.of(legacy("GET", target), nativeRequest("GET", target)))
            assertEquals("RULE_EXEMPT", engine.evaluate(cfg, request).reason(), target);
    }

    @Test void healthPresetStyleExemptIsNotGrantedThroughDotSegmentAlias() {
        Condition health = Condition.and(Condition.leaf(Field.METHOD, Match.EXACT, "GET"), path(Match.EXACT, "/health"));
        GuardConfig cfg = all(rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET")),
                rule("health", Mode.EXEMPT, health));
        assertEquals("RULE_EXEMPT", engine.evaluate(cfg, nativeRequest("GET", "/health")).reason());
        for (String alias : List.of("/admin/x/../../health", "/admin/%2e%2e/health", "/x/..;/health", "/health/.", "//health"))
            assertEquals("RULE_BLOCK", engine.evaluate(cfg, nativeRequest("GET", alias)).reason(), alias);
    }

    @Test void urlFieldExemptUsesTheSameAllViewsPrivilegeSemantics() {
        GuardConfig cfg = all(rule("block-admin", Mode.BLOCK, url(Match.REGEX, "^https://owned\\.test/admin")),
                rule("exempt-broker", Mode.EXEMPT, url(Match.REGEX, "^https://owned\\.test/broker/")));
        for (String target : List.of("/broker/../admin/delete", "/broker/..;/admin/delete", "/broker/%2e%2e/admin/delete"))
            assertEquals("RULE_BLOCK", engine.evaluate(cfg, nativeRequest("GET", target)).reason(), target);
        assertEquals("RULE_EXEMPT", engine.evaluate(cfg, nativeRequest("GET", "/broker/x?q=%41")).reason());
        // A malformed query is not interpretable: ordinary rules see the raw view, EXEMPT is not granted.
        Decision malformed = engine.evaluate(all(rule("exempt-broker", Mode.EXEMPT, url(Match.REGEX, "^https://owned\\.test/broker/")),
                rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET"))), nativeRequest("GET", "/broker/x?q=%zz"));
        assertEquals("RULE_BLOCK", malformed.reason());
        assertTrue(malformed.inspectionWarnings().contains("URL_INSPECTION_UNAVAILABLE_MALFORMED_PERCENT_ENCODING"));
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("raw", Mode.BLOCK, url(Match.EXACT, "https://owned.test/broker/x?q=%zz"))),
                nativeRequest("GET", "/broker/x?q=%zz")).reason());
    }

    @Test void privilegedAnyCannotUseASingleDisagreeingRoutingView() {
        GuardConfig cfg = all(rule("block-admin", Mode.BLOCK, path(Match.REGEX, "^/admin")),
                rule("exempt-any", Mode.EXEMPT, Condition.leaf(Field.ANY, Match.REGEX, "^/broker/")));
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, nativeRequest("GET", "/broker/../admin/x")).reason());
        assertEquals("RULE_EXEMPT", engine.evaluate(cfg, nativeRequest("GET", "/broker/x")).reason());
        // Ordinary ANY keeps any-view positives.
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("any", Mode.BLOCK, Condition.leaf(Field.ANY, Match.REGEX, "^/admin/"))),
                nativeRequest("GET", "/broker/../admin/x")).reason());
    }

    @Test void methodExemptIsPreservedAndOrdinaryAnyViewBlockAndAskPositivesRemain() {
        GuardConfig method = all(rule("block-admin", Mode.BLOCK, path(Match.REGEX, "^/admin")),
                rule("exempt-options", Mode.EXEMPT, Condition.leaf(Field.METHOD, Match.EXACT, "OPTIONS")));
        assertEquals("RULE_EXEMPT", engine.evaluate(method, nativeRequest("OPTIONS", "/broker/../admin/x")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(method, nativeRequest("GET", "/broker/../admin/x")).reason());
        for (String alias : List.of("/x/../admin/delete", "/admin/./delete", "/admin;v=1/delete", "/%61dmin/delete", "//admin//delete")) {
            assertEquals("RULE_BLOCK", engine.evaluate(all(rule("b", Mode.BLOCK, path(Match.EXACT, "/admin/delete"))),
                    nativeRequest("POST", alias)).reason(), alias);
            assertEquals("RULE_ASK", engine.evaluate(all(rule("a", Mode.ASK, path(Match.EXACT, "/admin/delete"))),
                    nativeRequest("POST", alias)).reason(), alias);
        }
    }

    @Test void incompleteBranchStillCannotGrantExemptEvenWithAKnownTrueBranch() {
        GuardConfig cfg = all(rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET")),
                rule("exempt", Mode.EXEMPT, Condition.or(Condition.leaf(Field.METHOD, Match.EXACT, "GET"), path(Match.EXACT, "/c/%zz"))));
        Decision decision = engine.evaluate(cfg, nativeRequest("GET", "/c/%zz"));
        assertEquals("RULE_BLOCK", decision.reason());
        assertTrue(decision.inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
    }

    // ---- (2) B-7: exact-URL BLOCK (candidate draft shape) catches routing aliases ----

    @Test void candidateExactUrlBlockDraftCatchesRoutingAliasesWithActualAuthorityAndQuery() {
        String draft = "^" + com.google.re2j.Pattern.quote("https://owned.test/big/file.zip") + "(?:\\?.*)?$";
        GuardConfig cfg = all(rule("draft", Mode.BLOCK, url(Match.REGEX, draft)));
        for (String alias : List.of("/big/file.zip", "/big/file.zip?x=1", "/big/%66ile.zip", "/big/./file.zip",
                "/big/file.zip;jsessionid=1", "/big//file.zip", "/x/../big/file.zip", "/big/%2e/file.zip",
                "/big/%252e/file.zip", "/big/..;/big/file.zip", "/big\\file.zip", "/big/./file.zip?x=%41"))
            for (RequestData request : List.of(nativeRequest("GET", alias), legacy("GET", alias)))
                assertEquals("RULE_BLOCK", engine.evaluate(cfg, request).reason(), alias);
        for (String other : List.of("/big/file.zip.bak", "/big/other.zip", "/bigfile.zip", "/big/file.zip/x"))
            assertEquals("DEFAULT_ALLOW", engine.evaluate(cfg, nativeRequest("GET", other)).reason(), other);
    }

    @Test void urlAliasViewsUseActualServiceAuthorityNotSuppliedUrlOrHostHeader() {
        RequestData request = new RequestData("GET", "http://evil.invalid:1/big/./file.zip", "owned.test", 8443, true,
                List.of(new RequestData.Header("Host", "evil.invalid")), new byte[0], true, true, "/big/./file.zip?a=%31");
        GuardConfig cfg = new GuardConfig(2, List.of(new ScopeEntry(true, "owned.test", "https", 8443, "")), List.of(),
                List.of(rule("draft", Mode.BLOCK, url(Match.EXACT, "https://owned.test:8443/big/file.zip?a=1"))),
                Mode.ALLOW, GuardConfig.defaults().limits());
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request).reason());
        GuardConfig spoof = new GuardConfig(2, cfg.allowScope(), List.of(),
                List.of(rule("spoof", Mode.BLOCK, url(Match.CONTAINS, "evil.invalid"))), Mode.ALLOW, cfg.limits());
        assertEquals("DEFAULT_ALLOW", engine.evaluate(spoof, request).reason());
    }

    @Test void oversizedOptionalQueryRemainsUnavailableNotATruncatedMatch() {
        String target = "/safe?x=" + "y".repeat(PolicySupport.MAX_URL + 1);
        Decision decision = engine.evaluate(all(rule("u", Mode.BLOCK, url(Match.CONTAINS, "/safe"))), nativeRequest("GET", target));
        assertEquals("DEFAULT_ALLOW", decision.reason());
        assertTrue(decision.inspectionWarnings().contains("URL_INSPECTION_UNAVAILABLE_REQUEST_TOO_LARGE"));
    }

    // ---- (3) A-1/B-9: non-origin-form native targets keep their prefix and are incomplete ----

    @ParameterizedTest
    @ValueSource(strings = {"admin/secret", "*", "@evil/admin", "x/health", "adminpanel/public/x", "http://other.test/admin/x", ""})
    void nonOriginFormTargetKeepsRawViewAndPassesOnlyExplicitAllPath(String target) {
        RequestData request = nativeRequest("GET", target);
        List<String> views = PolicyEngine.routingPaths(request);
        assertEquals(target, views.getFirst(), "the untouched native target is the first view");
        assertTrue(views.size() <= 16);
        for (String every : List.of("", ".*", "/.*", "^/.*$")) {
            Decision decision = engine.evaluate(policy(every, List.of(), List.of()), request);
            assertEquals(Mode.ALLOW, decision.mode(), target);
            assertTrue(decision.inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"), target);
        }
        for (String restricted : List.of("/public/.*", "/secret", "/admin/.*", "/.*secret", "/health", "/x/health", "/\\*"))
            assertEquals("SCOPE_NOT_ALLOWED", engine.evaluate(policy(restricted, List.of(), List.of()), request).reason(),
                    target + " restricted=" + restricted);
        // Any authority-matching block scope is either matched or unresolvable: never silently cleared.
        assertEquals(Mode.BLOCK, engine.evaluate(policy("", List.of(scope("/unrelated")), List.of()), request).mode());
        // Path EXEMPT can never be proven from an incomplete target.
        GuardConfig exempt = all(rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET")),
                rule("exempt", Mode.EXEMPT, path(Match.REGEX, ".")),
                rule("exempt-url", Mode.EXEMPT, url(Match.REGEX, "^https://owned\\.test/")));
        Decision decision = engine.evaluate(exempt, request);
        assertEquals("RULE_BLOCK", decision.reason(), target);
        assertEquals(List.of("block-get"), hits(decision), target);
    }

    @Test void nonOriginFormTargetStillHitsExplicitBlockScopeAndPathRules() {
        RequestData request = nativeRequest("GET", "admin/secret");
        assertEquals("SCOPE_BLOCKED", engine.evaluate(policy("", List.of(scope("/admin.*")), List.of()), request).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("raw", Mode.BLOCK, path(Match.REGEX, "^/?admin"))), request).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("alias", Mode.BLOCK, path(Match.REGEX, "^/admin/"))), request).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("url", Mode.BLOCK, url(Match.REGEX, "^https://owned\\.test/admin/"))),
                request).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("absolute", Mode.BLOCK, path(Match.REGEX, "^/admin/"))),
                nativeRequest("GET", "http://other.test/admin/x")).reason());
        // The old "re-derive from first '/'" bug evaluated adminpanel/public/x as /public/x.
        assertEquals(List.of("adminpanel/public/x", "/adminpanel/public/x"),
                PolicyEngine.routingPaths(nativeRequest("GET", "adminpanel/public/x")));
    }

    @Test void nativeTargetIsAuthoritativeOverTheSyntheticUrlAndOriginFormIsUnchanged() {
        RequestData misleading = new RequestData("GET", "https://owned.test/public/x", "owned.test", 443, true,
                List.of(), new byte[0], true, true, "adminpanel/public/x");
        assertEquals("SCOPE_NOT_ALLOWED", engine.evaluate(policy("/public/.*", List.of(), List.of()), misleading).reason());
        for (String target : List.of("/safe", "/c/;/main.do", "/c/%2e/main.do", "/del%2565te?q=1", "/c/%zz/main.do")) {
            assertEquals(PolicyEngine.routingPaths(legacy("GET", target)), PolicyEngine.routingPaths(nativeRequest("GET", target)), target);
            assertEquals(Mode.ALLOW, engine.evaluate(all(), nativeRequest("GET", target)).mode(), target);
        }
        assertEquals("/safe", PolicyEngine.routingPaths(nativeRequest("GET", "/safe?x")).getFirst());
    }

    @Test void routingViewCountStaysBoundedForHostileTargets() {
        for (String target : List.of("/%2525252e/%2525252e/x", "a%2525252e/../b", "http://h/%2525252e/..;/x",
                "/" + "a/".repeat(4000), latin1("/日/%252e/../x")))
            assertTrue(PolicyEngine.routingPaths(nativeRequest("GET", target)).size() <= 16, target);
        assertThrows(IllegalArgumentException.class,
                () -> PolicyEngine.routingPaths(nativeRequest("GET", "/" + "a".repeat(PolicySupport.MAX_URL))));
    }

    // ---- (4) A-2: raw control/DEL/C1 (Latin-1-mapped UTF-8) target is incomplete, not INVALID_URI ----

    @Test void rawControlAndLatin1MappedUtf8TargetsPassExplicitAllPathUnchanged() {
        for (String target : List.of(latin1("/search/日"), latin1("/x/€"), latin1("/k/한국어"), "/a\u007fb",
                "/c/\u0085/x", "/c/\u0001/x", "/c/\ud800/x", latin1("/search/日") + "?q=" + latin1("한"))) {
            RequestData request = nativeRequest("GET", target);
            assertEquals(target.indexOf('?') < 0 ? target : target.substring(0, target.indexOf('?')),
                    PolicyEngine.routingPaths(request).getFirst());
            for (RequestData input : List.of(request, legacy("GET", target))) {
                Decision allPath = engine.evaluate(all(), input);
                assertEquals(Mode.ALLOW, allPath.mode(), target + " " + allPath.reason());
                assertTrue(allPath.inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"), target);
            }
            assertEquals("SCOPE_NOT_ALLOWED", engine.evaluate(policy("/.+", List.of(), List.of()), request).reason(), target);
            GuardConfig exempt = all(rule("block-get", Mode.BLOCK, Condition.leaf(Field.METHOD, Match.EXACT, "GET")),
                    rule("exempt", Mode.EXEMPT, path(Match.REGEX, "^/")));
            assertEquals("RULE_BLOCK", engine.evaluate(exempt, request).reason(), target);
        }
    }

    @Test void rawControlTargetKeepsRawViewAndAliasesForExplicitBlocks() {
        String target = latin1("/search/日/../../admin/delete");
        // Authored condition values stay strict (no raw controls); the raw traffic view is still matched.
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("raw", Mode.BLOCK, path(Match.REGEX, "^/search/[^/]+/\\.\\./"))),
                nativeRequest("GET", target)).reason());
        assertEquals("INVALID_CONFIG", engine.evaluate(all(rule("authored", Mode.BLOCK, path(Match.CONTAINS, latin1("日")))),
                nativeRequest("GET", target)).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("alias", Mode.BLOCK, path(Match.EXACT, "/admin/delete"))),
                nativeRequest("GET", target)).reason());
        assertEquals("SCOPE_BLOCKED", engine.evaluate(policy("", List.of(scope("/admin/.*")), List.of()),
                nativeRequest("GET", target)).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(all(rule("encoded", Mode.BLOCK, path(Match.EXACT, "/admin"))),
                nativeRequest("GET", "/x\u0085/%2e%2e/admin")).reason());
    }

    @Test void authoredRuntimeRoutesStayStrictAndExact() {
        for (String bad : List.of("/h\u0085", "/a\u007fb", latin1("/日"), "health", "*", "/x/../health", "/%2e/health", "//health"))
            assertThrows(IllegalArgumentException.class, () -> engine.validate(withProbe(bad)), bad);
        assertDoesNotThrow(() -> engine.validate(withProbe("/health")));
    }

    private static GuardConfig withProbe(String probePath) {
        Limits d = GuardConfig.defaults().limits();
        Limits limits = new Limits(d.globalRps(), d.perHostRps(), d.hostRps(), d.maxConcurrent(), d.maxQueued(),
                d.queueTimeoutMillis(), d.approvalTimeoutMillis(), d.requestTimeoutMillis(), d.perPathMaxResponseBytes(),
                d.autoBlockMillis(), d.circuit5xx(), d.fanout(), d.perIntentMaxRequests(), true,
                List.of(new ProbePath("https", "owned.test", 443, probePath)), d.heavyPathLimits());
        return new GuardConfig(2, List.of(scope("")), List.of(), List.of(), Mode.ALLOW, limits);
    }
}
