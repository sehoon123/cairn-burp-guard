package dev.cairnguard.policy;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.policy.PolicyEngineTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** Latest user semantics: hostile optional payloads are unavailable inspection, not scope denials. */
class HostileInspectionTest {
    private final PolicyEngine engine = new PolicyEngine();
    private final GuardConfig allow = config(List.of(
            rule("inspect", Mode.MONITOR, leaf(Field.ANY, Match.CONTAINS, "not-present-fixture")),
            rule("allow", Mode.ALLOW, leaf(Field.METHOD, Match.EXACT, "GET"))));

    private Decision unavailable(RequestData request) {
        Decision result = assertDoesNotThrow(() -> engine.evaluate(allow, request));
        assertEquals(Mode.ALLOW, result.mode());
        assertEquals("RULE_ALLOW", result.reason());
        assertEquals(List.of("allow"), result.hits().stream().map(Decision.RuleHit::id).toList());
        assertFalse(result.inspectionWarnings().isEmpty());
        for (String warning : result.inspectionWarnings())
            assertTrue(warning.chars().allMatch(c -> c >= 'A' && c <= 'Z' || c == '_'), warning);
        return result;
    }

    private void hardBlock(RequestData request) {
        Decision result = assertDoesNotThrow(() -> engine.evaluate(allow, request));
        assertEquals(Mode.BLOCK, result.mode());
        assertTrue(result.hits().isEmpty());
    }

    @ParameterizedTest @ValueSource(strings = {"%", "%2", "%GG", "%FF", "%C3", "%C0%AF", "%ED%A0%80", "%00", "%0d", "%25252564", "%25"})
    void malformedOrOverNestedPercentQueryIsUnavailableNotAScopeFailure(String value) {
        assertTrue(unavailable(request("/safe?q=" + value)).inspectionWarnings().stream()
                .anyMatch(warning -> warning.startsWith("QUERY_INSPECTION_UNAVAILABLE_")));
    }

    @ParameterizedTest @ValueSource(strings = {"a=%", "a=%GG", "a=%FF", "a=%E2%82", "a=%00", "a=%25252564", "a=ok\nb=bad"})
    void malformedOrOverNestedFormIsUnavailable(String value) {
        unavailable(request("GET", "/safe", "application/x-www-form-urlencoded", value));
    }

    @Test void utf8PercentSequencesAreDecodedStrictlyRatherThanReplacingInvalidBytes() {
        GuardConfig cfg = config(List.of(rule("unicode", Mode.BLOCK,
                leaf(Field.QUERY, "q", Match.EXACT, "délete", true))));
        assertEquals("RULE_BLOCK", engine.evaluate(cfg, request("/safe?q=d%C3%A9lete")).reason());
        unavailable(request("/safe?q=d%C3%28lete"));
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("Content-Type", "text/plain")), new byte[]{(byte) 0xc3, 0x28}));
    }

    @ParameterizedTest @ValueSource(strings = {"{", "{\"a\":1,}", "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}",
            "{\"a\":1} {}", "{\"a\":NaN}", "/* comment */ {}", "{\"a\":\"\\x41\"}", "{\"a\":\"\\uD800\"}",
            "[1,,2]", " ", "{\"action\":1,\"%61ction\":2}"})
    void malformedOrAmbiguousJsonSkipsOnlyUnevaluableConditions(String json) {
        assertTrue(unavailable(request("GET", "/safe", "application/json", json)).inspectionWarnings().stream()
                .anyMatch(warning -> warning.startsWith("JSON_INSPECTION_UNAVAILABLE_")));
    }

    @Test void jsonDepthTokenAndNumberBoundsDoNotBecomeAutomaticDenials() {
        unavailable(request("GET", "/safe", "application/json", "[".repeat(40) + "0" + "]".repeat(40)));
        assertTrue(unavailable(request("GET", "/safe", "application/json", "[" + "0,".repeat(4_096) + "0]"))
                .inspectionWarnings().contains("JSON_INSPECTION_UNAVAILABLE_INSPECTION_LIMIT"));
        unavailable(request("GET", "/safe", "application/json", "1" + "2".repeat(130)));
    }

    @ParameterizedTest @ValueSource(strings = {"application/octet-stream", "image/png", "multipart/form-data; boundary=fixture", "multipart/anything+json", "application/xml"})
    void unsupportedBodiesContinueWithUnavailableInspection(String type) {
        assertTrue(unavailable(request("GET", "/safe", type, "synthetic-body")).inspectionWarnings()
                .contains("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_BODY"));
    }

    @ParameterizedTest @ValueSource(strings = {"text/plain; charset=iso-8859-1", "text/plain; charset=utf-16", "application/json; charset=utf-8; charset=utf-8",
            "text/plain; charset=\"broken", "text/plain; x", "bad", "text/plain; =bad"})
    void unsupportedOrAmbiguousContentTypeIsNotADenial(String type) {
        unavailable(request("GET", "/safe", type, "read"));
    }

    @Test void unsupportedContentEncodingAndInvalidAsciiAreUnavailable() {
        for (String encoding : List.of("gzip", "br", "identity,gzip", "", "deflate")) {
            RequestData request = new RequestData("GET", "https://example.test/", "example.test", 443, true,
                    List.of(new Header("Content-Encoding", encoding)), "synthetic".getBytes(StandardCharsets.UTF_8));
            assertTrue(unavailable(request).inspectionWarnings().contains("BODY_INSPECTION_UNAVAILABLE_UNSUPPORTED_CONTENT_ENCODING"));
        }
        assertEquals(Mode.ALLOW, engine.evaluate(allow, new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("Content-Encoding", "identity")), new byte[0])).mode());
        unavailable(request("GET", "/safe", "text/plain; charset=us-ascii", "é"));
        assertEquals(Mode.ALLOW, engine.evaluate(allow, request("GET", "/safe", "text/plain; charset=\"UTF-8\"", "safe")).mode());
        assertEquals(Mode.ALLOW, engine.evaluate(allow, request("GET", "/safe", "application/json", "")).mode());
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true, List.of(), new byte[]{0, 1, 2}));
    }

    @Test void nonprintingUnicodeAndBomJsonAreUnavailableRatherThanSilentlyNormalized() {
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("Content-Type", "text/plain")), new byte[]{(byte) 0xc2, (byte) 0x80}));
        unavailable(request("GET", "/safe", "", "\ufeff{\"x\":\"del\\u0065te\"}"));
    }

    @Test void headerProtocolMarkersDoNotIntroduceAnUnconditionalValidityBarrier() {
        for (Header header : List.of(new Header("Upgrade", "websocket"), new Header("Connection", "keep-alive, Upgrade"),
                new Header("Sec-WebSocket-Key", "synthetic"), new Header("Upgrade", "h2c"))) {
            assertEquals(Mode.ALLOW, engine.evaluate(allow, new RequestData("GET", "https://example.test/", "example.test",
                    443, true, List.of(header), new byte[0])).mode());
        }
        // WebSocket frame inspection remains a non-goal; no frame processing is added here.
    }

    @Test void malformedHeadersLengthsAndTransferMarkersNeverAutomaticallyDeny() {
        for (List<Header> headers : List.of(
                List.of(new Header("X-Header", "safe\r\nAuthorization: synthetic")),
                List.of(new Header("Bad Name", "value")),
                List.of(new Header("Content-Type", "text/plain"), new Header("content-type", "application/json")),
                List.of(new Header("Content-Type", "")),
                List.of(new Header("Content-Length", "0"), new Header("content-length", "0")),
                List.of(new Header("Content-Length", "1")),
                List.of(new Header("Content-Length", "+0")),
                List.of(new Header("Content-Length", "0,0")),
                List.of(new Header("Transfer-Encoding", "chunked")),
                List.of(new Header("X-Header", "safe%0D%0Ainjected")))) {
            assertEquals(Mode.ALLOW, engine.evaluate(allow,
                    new RequestData("GET", "https://example.test/", "example.test", 443, true, headers, new byte[0])).mode());
        }
    }

    @Test void optionalCaptureAndExpandedStructuresAreBoundedButScopeMetadataStillFailsClosed() {
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(), new byte[RequestData.MAX_INSPECT_BYTES + 1]));
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true,
                List.of(new Header("X-Long", "x".repeat(65_537))), new byte[0]));
        List<Header> many = new ArrayList<>();
        for (int i = 0; i < 257; i++) many.add(new Header("X-Fixture-" + i, "safe"));
        unavailable(new RequestData("GET", "https://example.test/", "example.test", 443, true, many, new byte[0]));
        unavailable(request("GET", "/safe", "application/x-www-form-urlencoded", "a=1&".repeat(1_025)));
        unavailable(request("/safe?" + "a=1&".repeat(1_025)));
        unavailable(request("/safe?" + "x".repeat(16_385)));
        hardBlock(request("/" + "a".repeat(16_385)));
        hardBlock(new RequestData("X".repeat(33), "https://example.test/", "example.test", 443, true, List.of(), new byte[0]));
    }

    @Test void aggregateOptionalMatchingWorkIsBoundedWithoutBlockingOrDefeatingMethodRules() {
        List<Rule> rules = new ArrayList<>();
        for (int i = 0; i < 100; i++) rules.add(rule("cost-" + i, Mode.MONITOR, leaf(Field.BODY, Match.REGEX, "(?:z|y|x)+")));
        rules.add(rule("allow", Mode.ALLOW, leaf(Field.METHOD, Match.EXACT, "GET")));
        RequestData request = request("GET", "/safe", "text/plain", "a".repeat(200_000));
        Decision result = engine.evaluate(config(rules), request);
        assertEquals(Mode.ALLOW, result.mode());
        assertTrue(result.inspectionWarnings().contains("BODY_INSPECTION_UNAVAILABLE_INSPECTION_LIMIT"));
        rules.add(rule("method-block", Mode.BLOCK, leaf(Field.METHOD, Match.EXACT, "GET")));
        assertEquals("RULE_BLOCK", engine.evaluate(config(rules), request).reason());
    }

    @Test void errorMessagesAndStreamsNeverExposeRequestSourceOrRegex() {
        String secret = "synthetic-private-credential-fixture";
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream errors = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        try (PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errors, true, StandardCharsets.UTF_8)) {
            System.setOut(out);
            System.setErr(err);
            Decision result = unavailable(request("GET", "/safe", "application/json", "{\"secret\":\"" + secret + "\", broken}"));
            assertFalse(result.toString().contains(secret));
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> engine.validate(config(List.of(
                    rule("bad", Mode.BLOCK, leaf(Field.BODY, Match.REGEX, "(?=" + secret + ")"))))));
            assertFalse(error.getMessage().contains(secret));
            assertNull(error.getCause());
            assertEquals("INVALID_CONFIG", engine.evaluate(config(List.of(rule("bad", Mode.BLOCK,
                    leaf(Field.BODY, Match.REGEX, "(?=" + secret + ")")))), request("/safe")).reason());
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
        assertEquals("", output.toString(StandardCharsets.UTF_8));
        assertEquals("", errors.toString(StandardCharsets.UTF_8));
    }
}
