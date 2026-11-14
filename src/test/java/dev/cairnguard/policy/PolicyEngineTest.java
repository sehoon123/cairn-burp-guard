package dev.cairnguard.policy;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.DestinationScopeMode;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Logic;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class PolicyEngineTest {
    private final PolicyEngine engine = new PolicyEngine();

    static ScopeEntry scope(String host, String scheme, int port, String path) {
        return new ScopeEntry(true, host, scheme, port, path);
    }

    static GuardConfig config(List<ScopeEntry> allow, List<ScopeEntry> block, List<Rule> rules, Mode mode) {
        return new GuardConfig(1, allow, block, rules, mode, GuardConfig.defaults().limits());
    }

    static GuardConfig config(List<Rule> rules) {
        return config(List.of(scope("example.test", "https", 443, "")), List.of(), rules, Mode.ALLOW);
    }

    static Condition leaf(Field field, String name, Match match, String value, boolean sensitive) {
        return new Condition(Logic.LEAF, field, name, match, value, sensitive, List.of());
    }

    static Condition leaf(Field field, Match match, String value) { return leaf(field, "", match, value, false); }

    static Rule rule(String id, Mode mode, Condition condition) {
        return new Rule(id, "Rule " + id, true, mode, condition);
    }

    static RequestData request(String method, String path, String type, String body) {
        List<Header> headers = new ArrayList<>(List.of(new Header("Host", "example.test")));
        if (!type.isEmpty()) headers.add(new Header("Content-Type", type));
        return new RequestData(method, "https://example.test" + path, "example.test", 443, true,
                headers, body.getBytes(StandardCharsets.UTF_8));
    }

    static RequestData request(String path) { return request("GET", path, "", ""); }

    private void blocked(GuardConfig config, RequestData request) {
        Decision result = assertDoesNotThrow(() -> engine.evaluate(config, request));
        assertEquals(Mode.BLOCK, result.mode());
        assertTrue(result.hits().isEmpty(), "Hard gates must precede all rule matching");
        assertTrue(result.reason().chars().allMatch(c -> c >= 'A' && c <= 'Z' || c == '_'));
    }

    private static GuardConfig allDestinations(List<ScopeEntry> allow, List<ScopeEntry> block, List<Rule> rules, Mode defaultMode) {
        return new GuardConfig(2, allow, block, rules, defaultMode, GuardConfig.defaults().limits(), List.of(), DestinationScopeMode.ALL_DESTINATIONS);
    }

    @Test void allDestinationsReachesEveryDefaultAtActualDnsIpv4Ipv6AndBoundaryPorts() {
        for (Mode mode : List.of(Mode.ALLOW, Mode.BLOCK, Mode.MONITOR, Mode.ASK)) {
            GuardConfig policy = allDestinations(List.of(scope("unused.test", "https", 443, "/never")), List.of(), List.of(), mode);
            engine.validate(policy);
            for (String host : List.of("outside.test", "127.0.0.1", "[2001:db8::1]")) for (int port : List.of(1, 65535)) for (boolean secure : List.of(false, true)) {
                RequestData input = new RequestData("GET", "https://display.invalid/ignored", host, port, secure,
                        List.of(new Header("Host", "fuzzed.invalid")), new byte[]{0, 1}, true, true, "/outside");
                Decision decision = engine.evaluate(policy, input, false);
                assertEquals(mode, decision.mode()); assertEquals("DEFAULT_" + mode.name(), decision.reason());
                assertTrue(decision.hits().isEmpty()); assertEquals("/outside", input.nativeTarget());
                assertArrayEquals(new byte[]{0, 1}, input.body()); assertEquals("fuzzed.invalid", input.header("Host"));
            }
        }
    }

    @Test void allDestinationsSkipsPositiveAllowWorkButValidatesDormantDataAndMandatoryTarget() {
        List<ScopeEntry> irrelevant = java.util.stream.IntStream.range(0, 256).mapToObj(i -> scope("example.test", "https", 443, "^/a{255}$")).toList();
        GuardConfig all = allDestinations(irrelevant, List.of(), List.of(), Mode.ALLOW);
        RequestData longPath = request("/" + "a".repeat(12_000));
        assertEquals("DEFAULT_ALLOW", engine.evaluate(all, longPath).reason());
        GuardConfig listed = new GuardConfig(2, irrelevant, List.of(), List.of(), Mode.ALLOW, all.limits());
        assertEquals(Mode.BLOCK, engine.evaluate(listed, longPath).mode());
        for (ScopeEntry invalid : List.of(new ScopeEntry(false, "example.test", "https", 443, "("), new ScopeEntry(false, "", "https", 443, ""))) {
            GuardConfig bad = allDestinations(List.of(invalid), List.of(), List.of(), Mode.ALLOW);
            assertThrows(IllegalArgumentException.class, () -> engine.validate(bad));
            assertEquals("INVALID_CONFIG", engine.evaluate(bad, request("/safe")).reason());
        }
        for (RequestData invalid : List.of(
                new RequestData("GET", "https://example.test/", "", 443, true, List.of(), new byte[0], true, true, "/safe"),
                new RequestData("GET", "https://example.test/", "example.test", 0, true, List.of(), new byte[0], true, true, "/safe"),
                new RequestData("G ET", "https://example.test/", "example.test", 443, true, List.of(), new byte[0], true, true, "/safe"))) blocked(all, invalid);
        GuardConfig nullMode = new GuardConfig(2, List.of(), List.of(), List.of(), Mode.ALLOW, all.limits(), List.of(), null);
        assertThrows(IllegalArgumentException.class, () -> engine.validate(nullMode));
    }

    @Test void allDestinationsPreservesOrderedRuleHitsAndHardBlockWinsOverMethodExempt() {
        Condition get = leaf(Field.METHOD, Match.EXACT, "GET");
        List<Rule> rules = List.of(rule("monitor", Mode.MONITOR, get), rule("allow", Mode.ALLOW, get), rule("ask", Mode.ASK, get), rule("block", Mode.BLOCK, get), rule("exempt", Mode.EXEMPT, get));
        GuardConfig all = allDestinations(List.of(), List.of(), rules, Mode.ALLOW);
        Decision decision = engine.evaluate(all, request("/private"));
        assertEquals("RULE_EXEMPT", decision.reason());
        assertEquals(List.of("monitor", "allow", "ask", "block", "exempt"), decision.hits().stream().map(Decision.RuleHit::id).toList());
        GuardConfig hard = allDestinations(List.of(), List.of(scope("example.test", "https", 443, "/private")), rules, Mode.ALLOW);
        assertEquals("SCOPE_BLOCKED", engine.evaluate(hard, request("/private")).reason());
        assertTrue(engine.evaluate(hard, request("/private")).hits().isEmpty());
        assertEquals("RULE_BLOCK", engine.evaluate(allDestinations(List.of(), List.of(), rules.subList(0, 4), Mode.ALLOW), request("/safe")).reason());
        assertEquals("RULE_ASK", engine.evaluate(allDestinations(List.of(), List.of(), rules.subList(0, 3), Mode.ALLOW), request("/safe")).reason());
        assertEquals("DEFAULT_BLOCK", engine.evaluate(allDestinations(List.of(), List.of(), rules.subList(0, 1), Mode.BLOCK), request("/safe")).reason());
    }

    @Test void destinationScopeModeDoesNotLeakThroughTheIdentityCacheUnderConcurrency() throws Exception {
        GuardConfig listed = new GuardConfig(2, List.of(), List.of(), List.of(), Mode.ALLOW, GuardConfig.defaults().limits());
        GuardConfig all = allDestinations(List.of(), List.of(), List.of(), Mode.ALLOW);
        try (var pool = Executors.newFixedThreadPool(4)) {
            List<Callable<Mode>> work = new ArrayList<>();
            for (int i = 0; i < 80; i++) {
                GuardConfig policy = i % 2 == 0 ? all : listed;
                work.add(() -> engine.evaluate(policy, request("/safe")).mode());
            }
            var values = pool.invokeAll(work);
            for (int i = 0; i < values.size(); i++) assertEquals(i % 2 == 0 ? Mode.ALLOW : Mode.BLOCK, values.get(i).get());
        }
    }

    @Test void emptyAllowScopeAllowsNothingEvenWithExplicitAllow() {
        blocked(GuardConfig.defaults(), request("/safe"));
        GuardConfig noScope = config(List.of(), List.of(), List.of(rule("allow", Mode.ALLOW,
                leaf(Field.ANY, Match.CONTAINS, ""))), Mode.ALLOW);
        blocked(noScope, request("/safe"));
    }

    @Test void newDefaultDeleteMethodIsCaseInsensitiveWithoutDeleteStringFalsePositives() {
        GuardConfig defaults = GuardConfig.defaults();
        GuardConfig cfg = config(List.of(scope("example.test", "any", 0, "")), List.of(), defaults.rules(), Mode.ALLOW);
        Decision decision = engine.evaluate(cfg, request("delete", "/safe", "", ""));
        assertEquals(Mode.BLOCK, decision.mode());
        assertEquals(List.of("delete-method"), decision.hits().stream().map(Decision.RuleHit::id).toList());
        assertEquals("RULE_BLOCK", decision.reason());
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, request("/safe")).mode());
    }

    @Test void blockAskAllowPrecedenceIsNotListOrderAndMonitorOnlyRecords() {
        Condition yes = leaf(Field.METHOD, Match.EXACT, "GET");
        List<Rule> rules = List.of(rule("allow", Mode.ALLOW, yes), rule("monitor", Mode.MONITOR, yes),
                rule("ask", Mode.ASK, yes), rule("block", Mode.BLOCK, yes));
        for (int shift = 0; shift < rules.size(); shift++) {
            List<Rule> reordered = new ArrayList<>(rules.subList(shift, rules.size()));
            reordered.addAll(rules.subList(0, shift));
            Decision decision = engine.evaluate(config(reordered), request("/safe"));
            assertEquals(Mode.BLOCK, decision.mode());
            assertEquals(4, decision.hits().size());
        }
        assertEquals(Mode.ASK, engine.evaluate(config(rules.subList(0, 3)), request("/safe")).mode());
        GuardConfig monitor = config(List.of(scope("example.test", "any", 0, "")), List.of(),
                List.of(rule("monitor", Mode.MONITOR, yes)), Mode.ASK);
        Decision decision = engine.evaluate(monitor, request("/safe"));
        assertEquals(Mode.ASK, decision.mode());
        assertEquals("DEFAULT_ASK", decision.reason());
        assertEquals(1, decision.hits().size());
        GuardConfig allow = config(monitor.allowScope(), List.of(), List.of(rule("allow", Mode.ALLOW, yes)), Mode.BLOCK);
        assertEquals(Mode.ALLOW, engine.evaluate(allow, request("/safe")).mode());
    }

    @Test void nestedAndOrAndDisabledRules() {
        Condition get = leaf(Field.METHOD, Match.EXACT, "GET");
        Condition safe = leaf(Field.PATH, Match.EXACT, "/safe");
        Condition other = leaf(Field.PATH, Match.EXACT, "/other");
        Condition either = new Condition(Logic.OR, null, null, null, null, false, List.of(safe, other));
        Condition both = new Condition(Logic.AND, null, "", null, "", false, List.of(get, either));
        GuardConfig cfg = config(List.of(rule("both", Mode.ASK, both),
                new Rule("disabled", "Disabled", false, Mode.BLOCK, get)));
        assertEquals(Mode.ASK, engine.evaluate(cfg, request("/safe")).mode());
        assertEquals(Mode.ASK, engine.evaluate(cfg, request("/other")).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, request("/different")).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, request("POST", "/safe", "", "")).mode());
        // No rule demands JSON here: malformed optional payloads do not become hard denials.
        assertEquals(Mode.ASK, engine.evaluate(cfg, request("GET", "/safe", "application/json", "{broken")).mode());
    }

    static Stream<Arguments> fields() {
        return Stream.of(
                Arguments.of(Field.METHOD, "", request("DELETE", "/safe", "", "")),
                Arguments.of(Field.URL, "", request("/safe?q=DELetE")),
                Arguments.of(Field.PATH, "", request("/del%65te")),
                Arguments.of(Field.QUERY, "action", request("/safe?%61ction=del%2565te")),
                Arguments.of(Field.HEADER, "x-action", new RequestData("GET", "https://example.test/safe", "example.test", 443,
                        true, List.of(new Header("X-Action", "del%65te")), new byte[0])),
                Arguments.of(Field.BODY, "", request("POST", "/safe", "text/plain", "DELetE")),
                Arguments.of(Field.JSON, "/action", request("POST", "/safe", "application/json", "{\"action\":\"del\\u0065te\"}")),
                Arguments.of(Field.FORM, "action", request("POST", "/safe", "application/x-www-form-urlencoded", "action=del%65te")),
                Arguments.of(Field.ANY, "", request("POST", "/safe", "application/json", "{\"del\\u0065te\":false}")));
    }

    @ParameterizedTest @MethodSource("fields")
    void everyInspectionFieldMatchesRawDecodedKeysOrValues(Field field, String name, RequestData request) {
        Decision decision = engine.evaluate(config(List.of(rule("matched", Mode.BLOCK,
                leaf(field, name, Match.CONTAINS, "delete", false)))), request);
        assertEquals(Mode.BLOCK, decision.mode());
        assertEquals("RULE_BLOCK", decision.reason());
        assertEquals(1, decision.hits().size());
    }

    @Test void exactContainsRegexAndCaseOptionsAreDistinct() {
        RequestData request = request("/Delete.txt");
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("exact", Mode.BLOCK,
                leaf(Field.PATH, Match.EXACT, "delete")))), request).mode());
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("contains", Mode.BLOCK,
                leaf(Field.PATH, Match.CONTAINS, "delete")))), request).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("case", Mode.BLOCK,
                leaf(Field.PATH, "", Match.CONTAINS, "delete", true)))), request).mode());
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("regex", Mode.BLOCK,
                leaf(Field.PATH, Match.REGEX, "del[a-z]+[.]txt$")))), request).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("literal", Mode.BLOCK,
                leaf(Field.PATH, Match.CONTAINS, "[a-z]")))), request).mode());
    }

    @Test void selectorsDoNotConfuseKeysAndValuesAndHttpHeaderNamesIgnoreCase() {
        RequestData request = request("/safe?Other=delete&ACTION=delete");
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("case", Mode.BLOCK,
                leaf(Field.QUERY, "action", Match.EXACT, "delete", false)))), request).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("case", Mode.BLOCK,
                leaf(Field.QUERY, "action", Match.EXACT, "delete", true)))), request).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("key", Mode.BLOCK,
                leaf(Field.QUERY, "Other", Match.EXACT, "Other", true)))), request).mode());
        RequestData header = new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("X-Action", "DELETE")), new byte[0]);
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("header", Mode.BLOCK,
                leaf(Field.HEADER, "x-action", Match.EXACT, "DELETE", true)))), header).mode());
    }

    @Test void plusIsLiteralInPathAndSpaceInQueryAndForm() {
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("path", Mode.BLOCK,
                leaf(Field.PATH, Match.EXACT, "/a+b")))), request("/a+b")).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of(rule("path", Mode.BLOCK,
                leaf(Field.PATH, Match.EXACT, "/a b")))), request("/a+b")).mode());
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("query", Mode.BLOCK,
                leaf(Field.QUERY, "q", Match.EXACT, "delete item", true)))), request("/safe?q=delete+item")).mode());
        assertEquals(Mode.BLOCK, engine.evaluate(config(List.of(rule("form", Mode.BLOCK,
                leaf(Field.FORM, "q", Match.EXACT, "delete item", true)))),
                request("POST", "/safe", "application/x-www-form-urlencoded", "q=delete+item")).mode());
        assertEquals("RULE_BLOCK", engine.evaluate(config(List.of(rule("url", Mode.BLOCK,
                leaf(Field.URL, Match.EXACT, "https://example.test/a+b?q=delete item")))),
                request("/a+b?q=delete+item")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(config(List.of(rule("body", Mode.BLOCK,
                leaf(Field.BODY, Match.EXACT, "q=delete item")))),
                request("POST", "/safe", "application/x-www-form-urlencoded", "q=delete+item")).reason());
    }

    @Test void rawAndThreeDecodedViewsAreKeptAndFourthIsUnavailableNotGloballyBlocked() {
        GuardConfig cfg = config(List.of(rule("raw", Mode.MONITOR, leaf(Field.PATH, Match.EXACT, "/del%65te")),
                rule("decoded", Mode.ASK, leaf(Field.PATH, Match.EXACT, "/delete"))));
        assertEquals(2, engine.evaluate(cfg, request("/del%65te")).hits().size());
        for (String value : List.of("del%65te", "del%2565te", "del%252565te")) {
            assertEquals("RULE_ASK", engine.evaluate(cfg, request("/" + value)).reason());
        }
        Decision limited = engine.evaluate(cfg, request("/del%25252565te"));
        assertEquals("DEFAULT_ALLOW", limited.reason(), "All-path scope is not an encoding-depth restriction");
        assertEquals(List.of("raw"), limited.hits().stream().map(Decision.RuleHit::id).toList(),
                "Keep the known raw MONITOR match, never claim the not-yet-decoded ASK matched");
        assertTrue(limited.inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
    }

    @Test void encodedSeparatorsAndRepeatedParameterNamesCannotHideValues() {
        GuardConfig cfg = config(List.of(rule("query", Mode.BLOCK,
                leaf(Field.QUERY, "action", Match.CONTAINS, "delete", true))));
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request("/safe?a=1%26action%3Ddelete")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request("/safe?action=read&action=delete")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request("/safe?a=1;action=delete")).reason());
        GuardConfig form = config(List.of(rule("key", Mode.BLOCK, leaf(Field.FORM, Match.EXACT, "delete"))));
        assertEquals("RULE_BLOCK", engine.evaluate(form,
                request("POST", "/safe", "application/x-www-form-urlencoded", "del%65te=1")).reason());
    }

    @Test void jsonPointersUnicodeEscapesDecodedKeysArraysAndRootScalars() {
        GuardConfig cfg = config(List.of(rule("json", Mode.BLOCK,
                leaf(Field.JSON, "/a~1b/~0key/0", Match.EXACT, "delete", true))));
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request("POST", "/safe", "application/problem+json",
                "{\"a/b\":{\"~key\":[\"del\\u0065te\"]}}")).reason());
        GuardConfig alias = config(List.of(rule("json", Mode.BLOCK,
                leaf(Field.JSON, "/action", Match.EXACT, "delete", true))));
        assertEquals("RULE_BLOCK", engine.evaluate(alias, request("POST", "/safe", "application/json",
                "{\"%61ct\\u0069on\":\"delete\"}")).reason());
        GuardConfig root = config(List.of(rule("json", Mode.BLOCK, leaf(Field.JSON, Match.EXACT, "delete"))));
        assertEquals("RULE_BLOCK", engine.evaluate(root, request("POST", "/safe", "application/json", "\"delete\"")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(root, request("POST", "/safe", "text/plain", "{\"x\":\"del\\u0065te\"}")).reason());
        assertEquals("RULE_BLOCK", engine.evaluate(root, request("POST", "/safe", "", "{\"x\":\"del\\u0065te\"}")).reason());
        GuardConfig canonicalIndex = config(List.of(rule("json", Mode.BLOCK,
                leaf(Field.JSON, "/a/00", Match.EXACT, "delete", true))));
        assertEquals(Mode.ALLOW, engine.evaluate(canonicalIndex,
                request("POST", "/safe", "application/json", "{\"a\":[\"delete\"]}")).mode());
    }

    @Test void scopeWildcardHasDnsLabelBoundaryAndNeverMatchesApex() {
        GuardConfig cfg = config(List.of(scope("*.example.test", "any", 0, "")), List.of(), List.of(), Mode.ALLOW);
        for (String host : List.of("sub.example.test", "deep.sub.example.test")) {
            assertEquals(Mode.ALLOW, engine.evaluate(cfg,
                    new RequestData("GET", "https://" + host + "/", host, 443, true, List.of(), new byte[0])).mode());
        }
        for (String host : List.of("example.test", "notexample.test", "example.test.evil", "aexample.test")) {
            blocked(cfg, new RequestData("GET", "https://" + host + "/", host, 443, true, List.of(), new byte[0]));
        }
    }

    @Test void scopePathFullMatchesNeverQueryAndBlockDominatesAllModes() {
        GuardConfig cfg = config(List.of(scope("example.test", "https", 443, "/safe(?:/.*)?")),
                List.of(scope("example.test", "any", 0, "/safe/delete")),
                List.of(rule("allow", Mode.ALLOW, leaf(Field.ANY, Match.CONTAINS, ""))), Mode.ALLOW);
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, request("/safe?q=outside")).mode());
        blocked(cfg, request("/outside?q=/safe"));
        blocked(cfg, request("/unsafe/safe"));
        assertEquals("SCOPE_BLOCKED", engine.evaluate(cfg, request("/safe/del%65te")).reason());
        GuardConfig exact = config(List.of(scope("example.test", "https", 443, "/safe")), List.of(), List.of(), Mode.ALLOW);
        blocked(exact, request("/%73afe")); // both raw AND decoded must be inside one allow entry
        assertEquals(Mode.ALLOW, engine.evaluate(exact, request("/safe?x=1")).mode());
    }

    @ParameterizedTest @ValueSource(strings = {"/safe/../delete", "/safe/%2e%2e/delete", "/safe/%255cdelete", "/safe/%3foutside", "/safe/%23outside",
            "/safe/..;/delete", "/safe/%2e%2e%3b/delete", "/safe/path;matrix=value"})
    void allPathScopeDoesNotBanAmbiguousPentestPaths(String path) {
        RequestData input = request(path);
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of()), input).mode());
        assertEquals("https://example.test" + path, input.url(), "Never normalize the forwarded request");
    }

    @Test void correlatedPortPathTuplesStaySparseAndExplicitProductStillHonorsHardBlocks() {
        ScopeEntry api = scope("example.test", "https", 80, "\\A\\Q/api\\E\\z");
        ScopeEntry manager = scope("example.test", "https", 443, "\\A\\Q/manager\\E\\z");
        GuardConfig sparse = config(List.of(api, manager), List.of(), List.of(), Mode.ALLOW);
        List<ScopeEntry> product = new ArrayList<>();
        for (int port : List.of(80, 443)) for (String path : List.of("/api", "/manager")) product.add(scope("example.test", "https", port, "\\A\\Q" + path + "\\E\\z"));
        GuardConfig explicit = config(product, List.of(), List.of(), Mode.ALLOW);
        GuardConfig blocked = new GuardConfig(2, product, List.of(manager), List.of(rule("exception", Mode.EXEMPT, leaf(Field.METHOD, Match.EXACT, "GET"))), Mode.ALLOW, GuardConfig.defaults().limits());
        engine.validate(blocked);
        for (int port : List.of(80, 443)) for (String path : List.of("/api", "/manager")) {
            RequestData target = new RequestData("GET", "https://allowed-looking.invalid/", "example.test", port, true,
                    List.of(new Header("Host", "fuzzed.invalid")), new byte[0], true, true, path);
            assertEquals(port == 80 && path.equals("/api") || port == 443 && path.equals("/manager") ? Mode.ALLOW : Mode.BLOCK, engine.evaluate(sparse, target).mode());
            assertEquals(Mode.ALLOW, engine.evaluate(explicit, target).mode());
            if (port == 443 && path.equals("/manager")) assertEquals("SCOPE_BLOCKED", engine.evaluate(blocked, target).reason());
        }
        for (String path : List.of("/admin", "/apix", "/api/child", "/manager/")) blocked(explicit, request(path));
    }

    @Test void aPathListNeverDistributesTheAllRoutingViewsProofAcrossEntriesOrExempt() {
        List<ScopeEntry> separate = List.of(scope("example.test", "https", 443, "\\A\\Q/%61pi\\E\\z"), scope("example.test", "https", 443, "\\A\\Q/api\\E\\z"));
        Rule exemption = rule("path-exception", Mode.EXEMPT, leaf(Field.PATH, Match.EXACT, "/api"));
        GuardConfig restricted = new GuardConfig(2, separate, List.of(), List.of(exemption), Mode.ALLOW, GuardConfig.defaults().limits());
        engine.validate(restricted);
        blocked(restricted, new RequestData("GET", "https://display.invalid/", "example.test", 443, true, List.of(), new byte[0], true, true, "/%61pi"));
        assertEquals(Mode.EXEMPT, engine.evaluate(restricted, request("/api")).mode());
        blocked(restricted, request("/%25252561pi"));
        GuardConfig all = new GuardConfig(2, List.of(scope("example.test", "https", 443, "")), List.of(), List.of(exemption), Mode.ALLOW, GuardConfig.defaults().limits());
        engine.validate(all);
        Decision incomplete = engine.evaluate(all, request("/%25252561pi"));
        assertEquals(Mode.ALLOW, incomplete.mode());
        assertTrue(incomplete.inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
    }

    @Test void scopeSchemePortAndDisabledEntriesMatter() {
        GuardConfig https = config(List.of(scope("example.test", "https", 443, "")), List.of(), List.of(), Mode.ALLOW);
        blocked(https, new RequestData("GET", "http://example.test/", "example.test", 80, false, List.of(), new byte[0]));
        blocked(https, new RequestData("GET", "https://example.test:444/", "example.test", 444, true, List.of(), new byte[0]));
        GuardConfig disabled = config(List.of(new ScopeEntry(false, "example.test", "any", 0, "")), List.of(), List.of(), Mode.ALLOW);
        blocked(disabled, request("/"));
    }

    @Test void idnCaseTrailingDotAndIpv6AuthoritiesAreComparedWithoutDns() {
        GuardConfig idn = config(List.of(scope("bücher.test", "https", 0, "")), List.of(), List.of(), Mode.ALLOW);
        assertEquals(Mode.ALLOW, engine.evaluate(idn, new RequestData("GET", "https://BÜCHER.test./", "xn--bcher-kva.test",
                443, true, List.of(new Header("Host", "xn--bcher-kva.test")), new byte[0])).mode());
        GuardConfig ip = config(List.of(scope("::1", "http", 8080, "")), List.of(), List.of(), Mode.ALLOW);
        assertEquals(Mode.ALLOW, engine.evaluate(ip, new RequestData("GET", "http://[::1]:8080/", "0:0:0:0:0:0:0:1",
                8080, false, List.of(new Header("Host", "[0:0:0:0:0:0:0:1]:8080")), new byte[0])).mode());
    }

    @Test void actualServiceControlsScopeAndHostHeaderNeverCreatesAConsistencyGate() {
        GuardConfig cfg = config(List.of());
        blocked(cfg, new RequestData("GET", "https://example.test/", "elsewhere.test", 443, true, List.of(), new byte[0]));
        blocked(cfg, new RequestData("GET", "https://example.test/", "example.test", 444, true, List.of(), new byte[0]));
        blocked(cfg, new RequestData("GET", "https://example.test/", "example.test", 443, false, List.of(), new byte[0]));
        for (String host : List.of("synthetic.invalid", "example.test:80", "example.test@evil.test", " example.test", "example.test:", "%", "")) {
            assertEquals(Mode.ALLOW, engine.evaluate(cfg, new RequestData("GET", "https://example.test/", "example.test", 443, true,
                    List.of(new Header("Host", host)), new byte[0])).mode());
        }
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("Host", "example.test"), new Header("host", "synthetic.invalid")), new byte[0])).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(cfg, new RequestData("GET", "https://synthetic.invalid/", "example.test",
                443, true, List.of(), new byte[0])).mode());
    }

    @ParameterizedTest @ValueSource(strings = {"ftp://example.test/a", "/relative", "https:opaque"})
    void missingOrUnsupportedTargetRepresentationStillFailsClosed(String url) {
        blocked(config(List.of()), new RequestData("GET", url, "example.test", 443, true, List.of(), new byte[0]));
    }

    @ParameterizedTest @ValueSource(strings = {"https://example.test/#f", "https://example.test/a b",
            "https://example.test/%zz", "https://example.test\\@evil.test/"})
    void targetSyntaxAndUntrustedUrlAuthorityDoNotOverrideActualServiceAllPathScope(String url) {
        RequestData input = new RequestData("GET", url, "example.test", 443, true, List.of(), new byte[0]);
        assertEquals(Mode.ALLOW, engine.evaluate(config(List.of()), input).mode());
        assertEquals(url, input.url());
    }

    @Test void allowedAndMonitorRequestsAreNeverMutated() {
        byte[] bytes = "action=read".getBytes(StandardCharsets.UTF_8);
        List<Header> headers = List.of(new Header("Host", "example.test"), new Header("Authorization", "Bearer synthetic-secret"),
                new Header("Cookie", "session=synthetic-cookie"), new Header("Content-Type", "application/x-www-form-urlencoded"));
        RequestData request = new RequestData("POST", "https://example.test/safe", "example.test", 443, true, headers, bytes);
        GuardConfig cfg = config(List.of(scope("example.test", "any", 0, "")), List.of(), List.of(), Mode.MONITOR);
        assertEquals(Mode.MONITOR, engine.evaluate(cfg, request).mode());
        assertEquals(headers, request.headers());
        assertArrayEquals(bytes, request.body());
        assertEquals("Bearer synthetic-secret", request.header("Authorization"));
        assertEquals("https://example.test/safe", request.url());
    }

    @Test void re2DoesNotBacktrackOnNestedQuantifiers() {
        GuardConfig cfg = config(List.of(rule("linear", Mode.BLOCK, leaf(Field.BODY, Match.REGEX, "(a+)+$"))));
        assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                assertEquals(Mode.ALLOW, engine.evaluate(cfg,
                        request("POST", "/safe", "text/plain", "a".repeat(100_000) + "!")).mode()));
    }

    @Test void compiledPolicyCacheIsRevisionSafeAndConcurrent() throws Exception {
        GuardConfig allow = config(List.of());
        GuardConfig block = config(allow.allowScope(), allow.allowScope(), List.of(), Mode.ALLOW);
        try (var pool = Executors.newFixedThreadPool(4)) {
            List<Callable<Mode>> work = new ArrayList<>();
            for (int i = 0; i < 80; i++) {
                GuardConfig cfg = i % 2 == 0 ? allow : block;
                work.add(() -> engine.evaluate(cfg, request("/safe")).mode());
            }
            var results = pool.invokeAll(work);
            for (int i = 0; i < results.size(); i++) assertEquals(i % 2 == 0 ? Mode.ALLOW : Mode.BLOCK, results.get(i).get());
        }
        blocked(allow, null);
        assertEquals("INVALID_CONFIG", engine.evaluate(null, request("/safe")).reason());
        assertEquals(Mode.ALLOW, engine.evaluate(allow, request("/safe")).mode());
    }
}
