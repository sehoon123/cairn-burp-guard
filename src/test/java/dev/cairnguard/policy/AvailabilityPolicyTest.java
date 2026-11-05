package dev.cairnguard.policy;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.policy.PolicyEngineTest.*;
import static org.junit.jupiter.api.Assertions.*;

class AvailabilityPolicyTest {
    private final PolicyEngine engine = new PolicyEngine();
    private static GuardConfig v2(List<Rule> rules, Mode defaultMode) {
        return new GuardConfig(2, List.of(scope("example.test", "https", 443, "")), List.of(), rules,
                defaultMode, GuardConfig.defaults().limits());
    }
    private static Condition safeGet() {
        return Condition.and(leaf(Field.METHOD, Match.EXACT, "GET"), leaf(Field.PATH, Match.EXACT, "/safe"));
    }

    @Test void exemptBeatsAllOrdinaryRulesAndDefaultRegardlessOfOrderButRetainsHits() {
        List<Rule> rules = List.of(rule("block", Mode.BLOCK, safeGet()), rule("ask", Mode.ASK, safeGet()),
                rule("allow", Mode.ALLOW, safeGet()), rule("monitor", Mode.MONITOR, safeGet()), rule("exempt", Mode.EXEMPT, safeGet()));
        for (Mode fallback : List.of(Mode.ALLOW, Mode.ASK, Mode.BLOCK, Mode.MONITOR)) {
            for (int shift = 0; shift < rules.size(); shift++) {
                List<Rule> reordered = new ArrayList<>(rules.subList(shift, rules.size()));
                reordered.addAll(rules.subList(0, shift));
                Decision decision = engine.evaluate(v2(reordered, fallback), request("/safe"));
                assertEquals(Mode.EXEMPT, decision.mode());
                assertEquals("RULE_EXEMPT", decision.reason());
                assertEquals(5, decision.hits().size());
                assertTrue(decision.inspectionWarnings().isEmpty());
            }
        }
        assertEquals(Mode.BLOCK, engine.evaluate(v2(rules, Mode.BLOCK), request("/other")).mode());
    }

    @Test void exemptNeverOverridesAllowScopeBlockScopeOrUnknownRoutingMetadata() {
        Rule exempt = rule("exempt", Mode.EXEMPT, safeGet());
        GuardConfig cfg = v2(List.of(exempt), Mode.ALLOW);
        assertEquals("SCOPE_NOT_ALLOWED", engine.evaluate(new GuardConfig(2, List.of(), List.of(), cfg.rules(), Mode.ALLOW, cfg.limits()), request("/safe")).reason());
        assertEquals("SCOPE_BLOCKED", engine.evaluate(new GuardConfig(2, cfg.allowScope(), cfg.allowScope(), cfg.rules(), Mode.ALLOW, cfg.limits()), request("/safe")).reason());
        for (RequestData outside : List.of(
                new RequestData("GET", "https://example.test/safe", "outside.test", 443, true, List.of(new Header("Host", "example.test")), new byte[0]),
                new RequestData("GET", "https://example.test/safe", "example.test", 444, true, List.of(), new byte[0]),
                new RequestData("GET", "https://example.test/safe", "example.test", 443, false, List.of(), new byte[0]),
                new RequestData("GET", "https://example.test/safe", "127.1", 443, true, List.of(), new byte[0]),
                new RequestData("GET", "relative-target", "example.test", 443, true, List.of(), new byte[0]))) {
            Decision result = engine.evaluate(cfg, outside);
            assertEquals(Mode.BLOCK, result.mode());
            assertTrue(result.hits().isEmpty());
        }
    }

    @Test void exemptCannotBeDefaultLegacyOrEmptyAndUniversalConditionsAreRejected() {
        for (int schema : new int[]{1, 2}) {
            GuardConfig cfg = v2(List.of(), Mode.ALLOW);
            assertThrows(IllegalArgumentException.class, () -> engine.validate(new GuardConfig(schema, cfg.allowScope(),
                    List.of(), List.of(), Mode.EXEMPT, cfg.limits())));
        }
        assertThrows(IllegalArgumentException.class, () -> engine.validate(config(List.of(rule("legacy", Mode.EXEMPT, safeGet())))));
        for (Condition broad : List.of(leaf(Field.ANY, Match.CONTAINS, ""), leaf(Field.PATH, Match.REGEX, ".*"),
                leaf(Field.PATH, Match.REGEX, "^.*$"), leaf(Field.PATH, Match.REGEX, "^/.*$"),
                leaf(Field.BODY, Match.EXACT, ""), Condition.or(safeGet(), leaf(Field.ANY, Match.REGEX, "(?s).*")),
                Condition.and(leaf(Field.ANY, Match.CONTAINS, ""), leaf(Field.PATH, Match.REGEX, ".*")))) {
            assertThrows(IllegalArgumentException.class, () -> engine.validate(v2(List.of(rule("broad", Mode.EXEMPT, broad)), Mode.ALLOW)));
            assertThrows(IllegalArgumentException.class, () -> engine.validate(v2(List.of(new Rule("broad", "Broad disabled", false, Mode.EXEMPT, broad)), Mode.ALLOW)));
        }
        // Broad but non-universal operator-authored exemptions remain possible (UI warns/asks).
        assertDoesNotThrow(() -> engine.validate(v2(List.of(rule("get", Mode.EXEMPT, leaf(Field.METHOD, Match.EXACT, "GET"))), Mode.BLOCK)));
    }

    @Test void exactUserRequestedGetPathPassesNewProfileWhileDeleteRemainsBlocked() {
        GuardConfig defaults = GuardConfig.defaults();
        GuardConfig cfg = new GuardConfig(2, List.of(scope("example.com", "https", 443, "")), List.of(),
                defaults.rules(), defaults.defaultMode(), defaults.limits());
        String path = "/ui/bp/common/board/deleteInfoBoardComnt.do";
        RequestData get = new RequestData("GET", "https://example.com" + path, "example.com", 443, true,
                List.of(new Header("Host", "synthetic.invalid")), new byte[0]);
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, get).mode());
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, new RequestData("DELETE", get.url(), get.host(), get.port(),
                get.secure(), get.headers(), get.body())).reason());
        for (String harmless : List.of("/deleteListTmp.do", "/undelete", "/token/delete", "/safe"))
            assertEquals(Mode.ALLOW, engine.evaluate(cfg, new RequestData("GET", "https://example.com" + harmless,
                    "example.com", 443, true, List.of(), new byte[0])).mode());
    }

    @Test void urlRulesUseActualTargetUrlNotFuzzedHostOrSuppliedUrlAuthority() {
        RequestData request = new RequestData("GET", "http://synthetic.invalid:1234/safe?q=1", "example.test", 443, true,
                List.of(new Header("Host", "synthetic.invalid")), new byte[0]);
        assertEquals(Mode.BLOCK, engine.evaluate(v2(List.of(rule("actual", Mode.BLOCK,
                leaf(Field.URL, Match.EXACT, "https://example.test/safe?q=1"))), Mode.ALLOW), request).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(v2(List.of(rule("spoof", Mode.BLOCK,
                leaf(Field.URL, Match.CONTAINS, "synthetic.invalid"))), Mode.ALLOW), request).mode());
        assertEquals(Mode.BLOCK, engine.evaluate(v2(List.of(rule("explicit-header", Mode.BLOCK,
                leaf(Field.HEADER, "Host", Match.EXACT, "synthetic.invalid", true))), Mode.ALLOW), request).mode());
        assertEquals(List.of("/safe"), PolicyEngine.routingPaths(request));
    }

    @Test void routingViewsDoNotDependOnHeadersBodyOrOptionalQueryAndNeverRetainQuery() {
        RequestData request = new RequestData("GET", "https://synthetic.invalid/del%2565te?q=%", "example.test", 443, true,
                List.of(new Header("Host", "%")), new byte[0], false, false);
        assertEquals(List.of("/del%2565te", "/del%65te", "/delete"), PolicyEngine.routingPaths(request));
        assertEquals(List.of("/%2e%2e/outside", "/../outside", "/outside"),
                PolicyEngine.routingPaths(request("/%2e%2e/outside")),
                "Interpretation aliases inform scope; they are not blanket path prohibitions");
    }

    @Test void incompleteOptionalCaptureNeverMatchesContentRulesOrExempt() {
        RequestData partial = new RequestData("GET", "https://example.test/safe", "example.test", 443, true,
                List.of(new Header("X-Action", "delete")), "delete".getBytes(StandardCharsets.UTF_8), false, false);
        List<Rule> content = List.of(rule("header", Mode.BLOCK, leaf(Field.HEADER, "X-Action", Match.EXACT, "delete", true)),
                rule("body", Mode.ASK, leaf(Field.BODY, Match.EXACT, "delete")), rule("exempt", Mode.EXEMPT, leaf(Field.BODY, Match.EXACT, "delete")));
        Decision result = engine.evaluate(v2(content, Mode.ALLOW), partial);
        assertEquals(Mode.ALLOW, result.mode());
        assertTrue(result.hits().isEmpty());
        assertTrue(result.inspectionWarnings().containsAll(List.of("HEADERS_INCOMPLETE", "BODY_INCOMPLETE",
                "HEADER_INSPECTION_UNAVAILABLE_CAPTURE_INCOMPLETE", "BODY_INSPECTION_UNAVAILABLE_CAPTURE_INCOMPLETE")));
        Decision routingExempt = engine.evaluate(v2(List.of(rule("path", Mode.EXEMPT, safeGet()), content.getFirst()), Mode.BLOCK), partial);
        assertEquals(Mode.EXEMPT, routingExempt.mode(), "A path-only EXEMPT does not demand body/header inspection");
        assertFalse(routingExempt.inspectionWarnings().isEmpty());
    }

    @Test void pathOnlyPolicyReportsCaptureFlagsWithoutClaimingADemandedFieldWasUninspected() {
        RequestData partial = new RequestData("POST", "https://example.test/safe", "example.test", 443, true,
                List.of(new Header("Content-Type", "application/json; charset=unsupported")), "{broken".getBytes(StandardCharsets.UTF_8), false, false);
        Decision result = engine.evaluate(v2(List.of(rule("path", Mode.BLOCK, leaf(Field.PATH, Match.EXACT, "/never"))), Mode.ALLOW), partial);
        assertEquals(Mode.ALLOW, result.mode());
        assertEquals(List.of("HEADERS_INCOMPLETE", "BODY_INCOMPLETE"), result.inspectionWarnings(),
                "Capture provenance only; field-unavailable IDs appear solely for rule-demanded fields");
    }

    @Test void exactRoutingPathIsOnlyAnUnambiguousCompleteNativeTargetAndIgnoresQueryAndHostFuzz() {
        java.util.function.Function<String, RequestData> native_ = target -> new RequestData("POST", "https://synthetic.invalid" + target,
                "example.test", 443, true, List.of(new Header("Host", "synthetic.invalid")), new byte[0], true, true, target);
        assertEquals("/expected-error", PolicyEngine.exactRoutingPath(native_.apply("/expected-error")));
        assertEquals("/expected-error", PolicyEngine.exactRoutingPath(native_.apply("/expected-error?x=1")), "query is not an identity");
        assertEquals("/expected-error", PolicyEngine.exactRoutingPath(native_.apply("/expected-error?x=%zz")));
        assertEquals("/", PolicyEngine.exactRoutingPath(native_.apply("/")));
        for (String ambiguous : List.of("/c/%2c", "/a%2fb", "/a;b", "/a/./b", "/a/../b", "/a//b", "/a%252fb", "/a%zz", "/a\\b",
                "relative", "*", "@h/x", "/a\u0001b")) {
            assertNull(PolicyEngine.exactRoutingPath(native_.apply(ambiguous)), ambiguous);
        }
        assertNull(PolicyEngine.exactRoutingPath(null));
    }

    @Test void unsupportedContentCannotGrantExemptThroughAnyAndOrOrBranches() {
        RequestData binary = request("GET", "/safe", "application/octet-stream", "synthetic");
        for (Condition condition : List.of(leaf(Field.ANY, Match.CONTAINS, "safe"),
                Condition.or(safeGet(), leaf(Field.JSON, "/action", Match.EXACT, "ok", true)),
                Condition.and(safeGet(), leaf(Field.BODY, Match.CONTAINS, "synthetic")))) {
            Decision result = engine.evaluate(v2(List.of(rule("block", Mode.BLOCK, safeGet()), rule("exempt", Mode.EXEMPT, condition)), Mode.ALLOW), binary);
            assertEquals(Mode.BLOCK, result.mode());
            assertEquals(List.of("block"), result.hits().stream().map(Decision.RuleHit::id).toList());
            assertFalse(result.inspectionWarnings().isEmpty());
        }
        // Positive ordinary ANY/OR conditions remain enforceable using an inspectable component.
        Decision positive = engine.evaluate(v2(List.of(rule("block", Mode.BLOCK, leaf(Field.ANY, Match.CONTAINS, "/safe"))), Mode.ALLOW), binary);
        assertEquals("RULE_BLOCK", positive.reason());
        assertFalse(positive.inspectionWarnings().isEmpty());
    }

    @ParameterizedTest @ValueSource(strings = {"{broken", "{\"x\":1,\"x\":2}", " ", "[1,,2]"})
    void malformedJsonCannotGrantExemptButKnownTextBodyRuleStillEnforces(String malformed) {
        Decision json = engine.evaluate(v2(List.of(rule("exempt", Mode.EXEMPT, leaf(Field.JSON, Match.CONTAINS, "x"))), Mode.ASK),
                request("GET", "/safe", "application/json", malformed));
        assertEquals(Mode.ASK, json.mode());
        assertTrue(json.hits().isEmpty());
        assertTrue(json.inspectionWarnings().stream().anyMatch(warning -> warning.startsWith("JSON_INSPECTION_UNAVAILABLE_")));
        Decision body = engine.evaluate(v2(List.of(rule("text", Mode.BLOCK, leaf(Field.BODY, Match.EXACT, malformed))), Mode.ALLOW),
                request("GET", "/safe", "application/json", malformed));
        assertEquals("RULE_BLOCK", body.reason(), "An explicit text condition need not parse JSON");
    }

    @Test void inspectableContentExemptAndLegacyConstructorsRemainImmutable() {
        GuardConfig cfg = v2(List.of(rule("block", Mode.BLOCK, safeGet()), rule("exempt", Mode.EXEMPT,
                leaf(Field.JSON, "/action", Match.EXACT, "ok", true))), Mode.ASK);
        RequestData request = request("GET", "/safe", "application/json", "{\"action\":\"ok\"}");
        assertEquals("RULE_EXEMPT", engine.evaluate(cfg, request).reason());
        assertTrue(request.headersComplete()); assertTrue(request.bodyComplete());
        byte[] body = request.body(); body[0] = 'x'; assertEquals('{', request.body()[0]);
        assertEquals(request.body().length, request.bodyLength());
        Decision old = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());
        assertTrue(old.inspectionWarnings().isEmpty());
        List<String> warnings = new ArrayList<>(List.of("BODY_INCOMPLETE"));
        Decision copy = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of(), warnings); warnings.clear();
        assertEquals(List.of("BODY_INCOMPLETE"), copy.inspectionWarnings());
        assertThrows(UnsupportedOperationException.class, () -> copy.inspectionWarnings().clear());
    }

    @Test void missingContentInspectionCapacitySkipsOnlyDemandedContentAndNeverGrantsExempt() {
        RequestData request = request("GET", "/safe", "application/json", "{\"action\":\"ok\"}");
        GuardConfig content = v2(List.of(rule("exempt", Mode.EXEMPT, leaf(Field.JSON, "/action", Match.EXACT, "ok", true)),
                rule("header", Mode.BLOCK, leaf(Field.HEADER, Match.CONTAINS, "never"))), Mode.ASK);
        assertEquals("RULE_EXEMPT", engine.evaluate(content, request, true).reason(), "control: capacity available");
        Decision saturated = engine.evaluate(content, request, false);
        assertEquals(Mode.ASK, saturated.mode(), "no EXEMPT from unavailable inspection and no automatic denial");
        assertEquals(List.of("HEADER_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY", "JSON_INSPECTION_UNAVAILABLE_INSPECTION_CAPACITY"),
                saturated.inspectionWarnings(), "only demanded content fields; completeness is not falsified");
        GuardConfig routing = v2(List.of(rule("block", Mode.BLOCK, safeGet())), Mode.ALLOW);
        Decision path = engine.evaluate(routing, request, false);
        assertEquals("RULE_BLOCK", path.reason(), "METHOD/PATH rules still enforce");
        assertTrue(path.inspectionWarnings().isEmpty(), "path-only rules never claim unavailable content inspection");
        Decision any = engine.evaluate(v2(List.of(rule("any", Mode.BLOCK, leaf(Field.ANY, Match.CONTAINS, "/safe"))), Mode.ALLOW), request, false);
        assertEquals("RULE_BLOCK", any.reason(), "ANY keeps conservative known positives");
    }
}
