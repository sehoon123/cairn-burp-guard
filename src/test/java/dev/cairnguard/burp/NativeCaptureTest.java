package dev.cairnguard.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;
import dev.cairnguard.model.RequestData;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Complete inspection-copy tests, NOT native Burp/wire proof. */
class NativeCaptureTest {
    @Test void actualServiceAndRawPathNotHostDerivedUrlEstablishInspectionUrl() {
        var request = request(1);
        when(request.url()).thenThrow(new AssertionError("Host-derived URL must never be used"));
        when(request.path()).thenReturn("/c/%2e/main.do?bad=%ZZ");
        when(request.headers()).thenReturn(List.of(header("Host", "synthetic.invalid")));
        var copy = NativeCapture.request(request);
        assertEquals("https://example.test:443/c/%2e/main.do?bad=%ZZ", copy.url());
        assertEquals("example.test", copy.host()); assertEquals(443, copy.port()); assertTrue(copy.secure());
        assertEquals("synthetic.invalid", copy.header("Host"));
        verify(request, never()).url(); verify(request, never()).httpVersion();
        verify(request, never()).toByteArray(); verify(request, never()).bodyToString();
    }
    @Test void capturesIndependentCopyWithExplicitCompleteness() {
        var request = request(1); byte[] json = "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        doReturn(bytes(json)).when(request).body();
        var copy = NativeCapture.request(request);
        assertEquals("GET", copy.method()); assertArrayEquals(json, copy.body());
        assertTrue(copy.headersComplete()); assertTrue(copy.bodyComplete()); assertEquals(2, copy.headers().size());
        verify(request.body()).getBytes();
    }
    @ParameterizedTest @ValueSource(ints = {1_048_577, Integer.MAX_VALUE, -1})
    void unreadableOrInvalidNativeBodyIsUnavailableNotInvented(int length) {
        var request = request(1); ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(length); when(request.body()).thenReturn(body); // mocked getBytes() supplies nothing
        var copy = NativeCapture.request(request);
        assertEquals(0, copy.bodyLength()); assertFalse(copy.bodyComplete()); assertTrue(copy.headersComplete());
        if (length < 0) verify(body, never()).getBytes();
    }
    @ParameterizedTest @ValueSource(strings = {"dishonest", "changed", "throw", "null", "body-api"})
    void optionalBodyFailuresNeverBecomeScopeFailuresOrFakeEmptyBodies(String kind) {
        var request = request(1); var body = mock(ByteArray.class); when(request.body()).thenReturn(body);
        when(body.length()).thenReturn(1); when(body.getBytes()).thenReturn(new byte[1]);
        switch (kind) {
            case "dishonest" -> when(body.getBytes()).thenReturn(new byte[2]);
            case "changed" -> when(body.length()).thenReturn(1, 2);
            case "throw" -> when(body.getBytes()).thenThrow(new IllegalArgumentException("SYNTHETIC"));
            case "null" -> when(body.getBytes()).thenReturn(null);
            case "body-api" -> when(request.body()).thenThrow(new LinkageError("SYNTHETIC"));
            default -> fail(kind);
        }
        var copy = NativeCapture.request(request);
        assertFalse(copy.bodyComplete()); assertEquals(0, copy.bodyLength()); assertEquals("example.test", copy.host());
    }
    @ParameterizedTest @ValueSource(strings = {"name", "value", "aggregate"})
    void formerHeaderBoundsAreCapturedCompletely(String kind) {
        var request = request(1);
        List<HttpHeader> headers = switch (kind) {
            case "name" -> List.of(header("A".repeat(257), "x"));
            case "value" -> List.of(header("A", "x".repeat(65_537)));
            default -> List.of(header("A", "x".repeat(33_000)), header("B", "y".repeat(33_000)));
        };
        when(request.headers()).thenReturn(headers);
        var copy = NativeCapture.request(request);
        assertTrue(copy.headersComplete()); assertEquals(headers.size(), copy.headers().size()); assertTrue(copy.bodyComplete());
        assertEquals(headers.getLast().value(), copy.headers().getLast().value());
    }
    @ParameterizedTest @ValueSource(strings = {"throw", "null", "null-entry", "null-value"})
    void headerReadFailuresAreExplicitlyIncompleteNotAutomaticDenials(String kind) {
        var request = request(1);
        switch (kind) {
            case "throw" -> when(request.headers()).thenThrow(new IllegalArgumentException("SYNTHETIC"));
            case "null" -> when(request.headers()).thenReturn(null);
            case "null-entry" -> when(request.headers()).thenReturn(java.util.Arrays.asList(header("A", "x"), null));
            case "null-value" -> when(request.headers()).thenReturn(List.of(header("A", null)));
            default -> fail(kind);
        }
        var copy = NativeCapture.request(request);
        assertFalse(copy.headersComplete()); assertTrue(copy.headers().isEmpty()); assertTrue(copy.bodyComplete());
    }
    @Test void headerReadFailureKeepsTheSmallBodyAndAdmissionAndItsCharsetIsUnknownNotAbsent() throws Exception {
        var request = request(1);
        // an unsupported declared charset may be hidden in headers that could not be read
        when(request.headers()).thenThrow(new IllegalStateException("SYNTHETIC"));
        byte[] eAcute = {(byte) 0xC3, (byte) 0xA9};
        doReturn(bytes(eAcute)).when(request).body();
        var copy = NativeCapture.request(request);
        assertFalse(copy.headersComplete()); assertTrue(copy.headers().isEmpty());
        assertTrue(copy.bodyComplete()); assertArrayEquals(eAcute, copy.body(), "the body survives header loss");
        var policy = new dev.cairnguard.model.GuardConfig(2, List.of(new dev.cairnguard.model.GuardConfig.ScopeEntry(true, "example.test", "https", 443, "")),
                List.of(), List.of(), dev.cairnguard.model.GuardConfig.Mode.ALLOW, dev.cairnguard.model.GuardConfig.defaults().limits());
        var decision = new dev.cairnguard.policy.PolicyEngine().evaluate(policy, copy);
        assertEquals(dev.cairnguard.model.GuardConfig.Mode.ALLOW, decision.mode(), "request inspection/admission is not newly rejected");
        var store = new dev.cairnguard.evidence.EvidenceStore();
        String id = store.begin("p", "p", copy, decision, 1);
        assertEquals("HEX", store.rawCaptureInfo(id).get("requestBodyDisplay"), "omitted headers are unknown, never a verified absent charset");
        var har = dev.cairnguard.model.Json.MAPPER.readTree(store.humanEvidence(List.of(id)).har(java.util.Map.of()));
        assertEquals("", har.at("/log/entries/0/request/postData/text").asText());
        assertArrayEquals(eAcute, java.util.Base64.getDecoder().decode(har.at("/log/entries/0/request/postData/_bodyBase64").asText()));
    }
    @Test void completeNativeHeadersWithoutCharsetRemainOrdinaryTextControl() throws Exception {
        var request = request(1);
        when(request.headers()).thenReturn(List.of(header("Content-Type", "text/plain")));
        doReturn(bytes(new byte[]{(byte) 0xC3, (byte) 0xA9})).when(request).body();
        var copy = NativeCapture.request(request);
        assertTrue(copy.headersComplete());
        var store = new dev.cairnguard.evidence.EvidenceStore();
        String id = store.begin("p", "p", copy, new dev.cairnguard.model.Decision(dev.cairnguard.model.GuardConfig.Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        assertEquals("UTF8_TEXT", store.rawCaptureInfo(id).get("requestBodyDisplay"));
    }
    @ParameterizedTest @ValueSource(strings = {"method", "service", "host", "port", "path"})
    void scopeEssentialMetadataStillFailsClosed(String kind) {
        var request = request(1);
        switch (kind) {
            case "method" -> when(request.method()).thenReturn(null);
            case "service" -> when(request.httpService()).thenReturn(null);
            case "host" -> when(request.httpService().host()).thenReturn(null);
            case "port" -> when(request.httpService().port()).thenReturn(0);
            case "path" -> when(request.path()).thenReturn(null);
            default -> fail(kind);
        }
        assertThrows(NativeCapture.Rejected.class, () -> NativeCapture.request(request)); verify(request, never()).body();
    }
    @ParameterizedTest @MethodSource("fuzzedHeaders")
    void duplicatesPartialPseudoFieldsAndHostFuzzArePreservedWithoutNormalization(List<HttpHeader> headers) {
        var request = request(1); when(request.httpVersion()).thenReturn("HTTP/2"); when(request.headers()).thenReturn(headers);
        var copy = NativeCapture.request(request);
        assertEquals(headers.stream().map(h -> new RequestData.Header(h.name(), h.value())).toList(), copy.headers());
        assertTrue(copy.headersComplete());
        assertTrue(mockingDetails(request).getInvocations().stream().noneMatch(i -> i.getMethod().getName().startsWith("with")));
    }
    static Stream<List<HttpHeader>> fuzzedHeaders() {
        List<List<HttpHeader>> cases = new ArrayList<>();
        cases.add(List.of()); cases.add(List.of(header("Host", "other.invalid"), header("host", "fuzz.invalid")));
        for (String name : List.of(":method", ":path", ":scheme", ":authority", ":protocol", ":METHOD")) {
            cases.add(List.of(header(name, "fuzz"))); cases.add(List.of(header(name, "first"), header(name, "second")));
        }
        cases.add(List.of(header("X-Regular", "x"), header(":authority", "other.invalid"), header("Host", "mismatch.invalid")));
        return cases.stream();
    }
    @Test void oversizedOptionalQueryIsKeptWholeAndOnlyUnavailableToQueryInspection() {
        var request = request(1); String target = "/safe?value=" + "x".repeat(2 * 16_384);
        when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertTrue(copy.url().endsWith(target)); assertEquals(target, copy.nativeTarget());
        assertEquals(target, request.path());
        var limits = dev.cairnguard.model.GuardConfig.defaults().limits();
        var policy = new dev.cairnguard.model.GuardConfig(2, List.of(new dev.cairnguard.model.GuardConfig.ScopeEntry(true, "example.test", "https", 443, "")),
                List.of(), List.of(new dev.cairnguard.model.GuardConfig.Rule("q", "q", true, dev.cairnguard.model.GuardConfig.Mode.BLOCK,
                        dev.cairnguard.model.GuardConfig.Condition.leaf(dev.cairnguard.model.GuardConfig.Field.QUERY, dev.cairnguard.model.GuardConfig.Match.CONTAINS, "never"))),
                dev.cairnguard.model.GuardConfig.Mode.ALLOW, limits);
        var decision = new dev.cairnguard.policy.PolicyEngine().evaluate(policy, copy);
        assertEquals(dev.cairnguard.model.GuardConfig.Mode.ALLOW, decision.mode(), "optional query size is not a scope denial");
        assertTrue(decision.inspectionWarnings().contains("QUERY_INSPECTION_UNAVAILABLE_REQUEST_TOO_LARGE"));
    }
    @ParameterizedTest @ValueSource(strings = {"admin/secret", "*", "@evil/admin", "x/health", "http://other.test/admin", ""})
    void nonOriginFormNativeTargetIsPreservedSeparatelyAndNeverReDerivedFromSyntheticUrl(String target) {
        var request = request(1); when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertEquals(target, copy.nativeTarget());
        assertEquals(target, request.path());
        List<String> views = dev.cairnguard.policy.PolicyEngine.routingPaths(copy);
        assertEquals(target, views.getFirst(), "prefix must not be dropped (old indexOf('/') re-derivation)");
        assertNotEquals("/health", views.getFirst());
    }
    @Test void rawControlAndLatin1MappedTargetsAreCopiedUntouchedNotRejected() {
        String target = new String("/search/\uD55C?q=1".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                java.nio.charset.StandardCharsets.ISO_8859_1) + "\u007f";
        var request = request(1); when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertEquals(target, copy.nativeTarget());
        assertEquals(target.substring(0, target.indexOf('?')), dev.cairnguard.policy.PolicyEngine.routingPaths(copy).getFirst());
    }
    @Test void completeQueryIsTheSameTargetPreservedForPolicyAndLegacyConstructorsHaveNoNativeTarget() {
        var request = request(1); String target = "/safe?value=" + "x".repeat(2 * 16_384);
        when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertTrue(copy.url().endsWith(copy.nativeTarget()));
        assertEquals(target, copy.nativeTarget());
        assertNull(new RequestData("GET", "https://e.test/", "e.test", 443, true, List.of(), new byte[0]).nativeTarget());
        assertNull(new RequestData("GET", "https://e.test/", "e.test", 443, true, List.of(), new byte[0], false, false).nativeTarget());
    }
    @Test void failedZeroByteCopyStillHasVerifiedEmptyBodyNotUnknownNonemptyMetadata() {
        var request = request(1); when(request.body().getBytes()).thenThrow(new IllegalArgumentException("SYNTHETIC"));
        assertTrue(NativeCapture.request(request).bodyComplete());
        assertEquals(0, NativeCapture.request(request).bodyLength());
    }
    @Test void ipv6AuthorityUsesSingleBracketsAndActualServicePort() {
        var request = request(1); when(request.httpService().host()).thenReturn("::1"); when(request.httpService().port()).thenReturn(8443);
        assertEquals("https://[::1]:8443/safe", NativeCapture.request(request).url());
        when(request.httpService().host()).thenReturn("[::1]");
        assertEquals("https://[::1]:8443/safe", NativeCapture.request(request).url());
    }
    @Test void responseScalarsAreIndependentOfTheCopyAndContentLengthAndNoZeroSentinelIsInvented() {
        var response = response(1, "{}"); ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(6 * 1_048_576); when(response.body()).thenReturn(body); when(response.statusCode()).thenReturn((short) 503);
        when(response.headers()).thenReturn(List.of(header("Content-Length", "1")));
        var observed = NativeCapture.observe(response); var copy = NativeCapture.response(response, observed); // mocked getBytes() supplies nothing
        assertEquals(503, copy.status()); assertEquals(6 * 1_048_576L, copy.actualBytes()); assertEquals(0, copy.body().length);
        assertFalse(copy.bodyComplete()); assertTrue(copy.headersComplete()); assertEquals("1", copy.headers().getFirst().value());
    }
    @Test void originalsBeyondOldHeaderBodyAndTargetCapsAreCopiedCompletely() {
        var request = request(1);
        List<HttpHeader> headers = new ArrayList<>();
        for (int i = 0; i < 256; i++) headers.add(header("X-H" + i, "v"));
        headers.add(header("X-" + "n".repeat(300), "V".repeat(70_000)));
        when(request.headers()).thenReturn(headers);
        byte[] body = new byte[1_100_000]; body[body.length - 1] = 7;
        doReturn(bytes(body)).when(request).body();
        String target = "/" + "p".repeat(9_000) + "?q=" + "x".repeat(2 * 16_384);
        when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertTrue(copy.headersComplete()); assertEquals(257, copy.headers().size());
        assertEquals(70_000, copy.headers().getLast().value().length());
        assertTrue(copy.bodyComplete()); assertArrayEquals(body, copy.body());
        assertEquals(target, copy.nativeTarget()); assertTrue(copy.url().endsWith(target));
    }
    @Test void originalsLongMethodHostAndPathAreCapturedForPolicyNotCaptureLimited() {
        var request = request(1); String method = "M".repeat(40), host = "h".repeat(300) + ".test", path = "/" + "a".repeat(20_000);
        when(request.method()).thenReturn(method); when(request.httpService().host()).thenReturn(host); when(request.path()).thenReturn(path);
        var copy = assertDoesNotThrow(() -> NativeCapture.request(request));
        assertEquals(method, copy.method()); assertEquals(host, copy.host()); assertEquals(path, copy.nativeTarget());
        var policy = new dev.cairnguard.model.GuardConfig(2, List.of(new dev.cairnguard.model.GuardConfig.ScopeEntry(true, host, "https", 443, "")),
                List.of(), List.of(), dev.cairnguard.model.GuardConfig.Mode.ALLOW, dev.cairnguard.model.GuardConfig.defaults().limits());
        assertEquals(dev.cairnguard.model.GuardConfig.Mode.BLOCK, new dev.cairnguard.policy.PolicyEngine().evaluate(policy, copy).mode(),
                "policy method/host/path validity still fails closed AFTER the original is recorded");
    }
    @Test void originalsResponseIsCopiedEvenWithoutAnInspectionSlot() {
        var response = response(1, "{\"grant\":\"SYNTH-NO-SLOT\"}");
        var copy = NativeCapture.response(response, NativeCapture.observe(response));
        assertTrue(copy.headersComplete()); assertTrue(copy.bodyComplete());
        assertEquals("{\"grant\":\"SYNTH-NO-SLOT\"}", new String(copy.body(), java.nio.charset.StandardCharsets.UTF_8));
    }
    @Test void failedStatusObservationDoesNotHideActualSizeAndFailedSizeDoesNotHideStatus() {
        var response = response(1, "{}"); when(response.statusCode()).thenThrow(new IllegalStateException("SYNTHETIC"));
        assertEquals(2, NativeCapture.observe(response).actualBytes()); assertEquals(0, NativeCapture.observe(response).status());
        var second = response(2, "{}"); when(second.body()).thenThrow(new LinkageError("SYNTHETIC"));
        assertEquals(200, NativeCapture.observe(second).status()); assertEquals(-1, NativeCapture.observe(second).actualBytes());
    }
}
