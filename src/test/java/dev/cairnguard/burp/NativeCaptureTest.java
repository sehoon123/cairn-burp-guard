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

/** Bounded inspection-copy tests, NOT native Burp/wire proof. */
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
    void oversizedOrInvalidOptionalBodyIsOmittedBeforeGetBytes(int length) {
        var request = request(1); ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(length); when(request.body()).thenReturn(body);
        var copy = NativeCapture.request(request);
        assertEquals(0, copy.bodyLength()); assertFalse(copy.bodyComplete()); assertTrue(copy.headersComplete());
        verify(body, never()).getBytes();
    }
    @Test void aggregateBudgetRemainsBoundedBeforeCopyAndExactBoundaryFits() {
        var request = request(1); when(request.headers()).thenReturn(List.of(header("Host", "example.test")));
        int head = "GEThttps://example.test:443/safeHostexample.test".length();
        var body = mock(ByteArray.class); when(body.length()).thenReturn(NativeCapture.MAX_BODY);
        when(request.body()).thenReturn(body);
        assertFalse(NativeCapture.request(request).bodyComplete()); verify(body, never()).getBytes();
        byte[] bounded = new byte[NativeCapture.MAX_BODY - head]; doReturn(bytes(bounded)).when(request).body();
        assertArrayEquals(bounded, NativeCapture.request(request).body());
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
    @ParameterizedTest @ValueSource(strings = {"count", "name", "value", "aggregate", "throw", "null"})
    void optionalHeaderBoundsAndFailuresAreExplicitlyIncompleteNotAutomaticDenials(String kind) {
        var request = request(1);
        switch (kind) {
            case "count" -> {
                @SuppressWarnings("unchecked") List<HttpHeader> headers = mock(List.class);
                when(headers.size()).thenReturn(257); when(request.headers()).thenReturn(headers);
                assertFalse(NativeCapture.request(request).headersComplete()); verify(headers, never()).get(anyInt()); return;
            }
            case "name" -> when(request.headers()).thenReturn(List.of(header("A".repeat(257), "x")));
            case "value" -> when(request.headers()).thenReturn(List.of(header("A", "x".repeat(65_537))));
            case "aggregate" -> when(request.headers()).thenReturn(List.of(header("A", "x".repeat(33_000)), header("B", "y".repeat(33_000))));
            case "throw" -> when(request.headers()).thenThrow(new IllegalArgumentException("SYNTHETIC"));
            case "null" -> when(request.headers()).thenReturn(null);
            default -> fail(kind);
        }
        var copy = NativeCapture.request(request);
        assertFalse(copy.headersComplete()); assertTrue(copy.headers().isEmpty()); assertTrue(copy.bodyComplete());
    }
    @Test void noCopySlotReadsOnlyEssentialScopeAndBodyLengthAndCanVerifyEmptyBody() {
        var request = request(1); var body = request.body(); clearInvocations(request);
        var copy = NativeCapture.request(request, false);
        assertTrue(copy.bodyComplete()); assertFalse(copy.headersComplete()); assertTrue(copy.headers().isEmpty());
        verify(body).length(); verify(body, never()).getBytes(); verify(request, never()).headers();
        when(body.length()).thenReturn(1);
        assertFalse(NativeCapture.request(request, false).bodyComplete());
    }
    @ParameterizedTest @ValueSource(strings = {"method", "service", "host", "port", "path", "long-path"})
    void scopeEssentialMetadataStillFailsClosed(String kind) {
        var request = request(1);
        switch (kind) {
            case "method" -> when(request.method()).thenReturn(null);
            case "service" -> when(request.httpService()).thenReturn(null);
            case "host" -> when(request.httpService().host()).thenReturn(null);
            case "port" -> when(request.httpService().port()).thenReturn(0);
            case "path" -> when(request.path()).thenReturn(null);
            case "long-path" -> when(request.path()).thenReturn("/".repeat(NativeCapture.MAX_URL + 1));
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
    @Test void oversizedOptionalQueryIsBoundedAsUnavailableWithoutRewritingNativeTarget() {
        var request = request(1); String target = "/safe?value=" + "x".repeat(2 * NativeCapture.MAX_URL);
        when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertTrue(copy.url().length() < 2 * NativeCapture.MAX_URL);
        assertEquals(NativeCapture.MAX_URL + 1, copy.url().substring(copy.url().indexOf('?') + 1).length());
        assertEquals(target, request.path());
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
    @Test void boundedQueryIsTheSameTargetPreservedForPolicyAndLegacyConstructorsHaveNoNativeTarget() {
        var request = request(1); String target = "/safe?value=" + "x".repeat(2 * NativeCapture.MAX_URL);
        when(request.path()).thenReturn(target);
        var copy = NativeCapture.request(request);
        assertTrue(copy.url().endsWith(copy.nativeTarget()));
        assertEquals(NativeCapture.MAX_URL + 1, copy.nativeTarget().length() - copy.nativeTarget().indexOf('?') - 1);
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
    @Test void responseScalarsAreIndependentOfSlotsAndContentLengthAndNoZeroSentinelIsInvented() {
        var response = response(1, "{}"); ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(6 * 1_048_576); when(response.body()).thenReturn(body); when(response.statusCode()).thenReturn((short) 503);
        when(response.headers()).thenReturn(List.of(header("Content-Length", "1")));
        var observed = NativeCapture.observe(response); var copy = NativeCapture.response(response, observed, false);
        assertEquals(503, copy.status()); assertEquals(6 * 1_048_576L, copy.actualBytes()); assertEquals(0, copy.body().length);
        assertFalse(copy.bodyComplete()); assertFalse(copy.headersComplete()); verify(body, never()).getBytes(); verify(response, never()).headers();
    }
    @Test void failedStatusObservationDoesNotHideActualSizeAndFailedSizeDoesNotHideStatus() {
        var response = response(1, "{}"); when(response.statusCode()).thenThrow(new IllegalStateException("SYNTHETIC"));
        assertEquals(2, NativeCapture.observe(response).actualBytes()); assertEquals(0, NativeCapture.observe(response).status());
        var second = response(2, "{}"); when(second.body()).thenThrow(new LinkageError("SYNTHETIC"));
        assertEquals(200, NativeCapture.observe(second).status()); assertEquals(-1, NativeCapture.observe(second).actualBytes());
    }
}
