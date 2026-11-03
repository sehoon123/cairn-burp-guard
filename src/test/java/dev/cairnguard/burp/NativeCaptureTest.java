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

/** In-process bounded-copy tests, not real Burp/wire behavior. */
class NativeCaptureTest {
    @Test void capturesOnlyInspectionCopyWithoutSerializingNativeMessage() {
        HttpRequestToBeSent nativeRequest = request(1);
        byte[] json = "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        doReturn(bytes(json)).when(nativeRequest).body();
        RequestData copy = NativeCapture.request(nativeRequest);
        assertEquals(nativeRequest.method(), copy.method());
        assertEquals(nativeRequest.url(), copy.url());
        assertEquals("example.test", copy.host());
        assertEquals(443, copy.port()); assertTrue(copy.secure());
        assertArrayEquals(json, copy.body());
        verify(nativeRequest, never()).toByteArray(); verify(nativeRequest, never()).bodyToString();
        verify(nativeRequest.body()).getBytes();
        assertEquals(2, copy.headers().size());
    }

    @ParameterizedTest @ValueSource(ints = {1_048_577, Integer.MAX_VALUE, -1})
    void rejectsOversizedOrInvalidBodyBeforeGetBytes(int length) {
        HttpRequestToBeSent request = request(1);
        ByteArray body = mock(ByteArray.class); when(body.length()).thenReturn(length); when(request.body()).thenReturn(body);
        assertCategory("CAPTURE_LIMIT", request);
        verify(body, never()).getBytes();
    }
    @Test void aggregateBodyPlusHeadMustFitBeforeCopy() {
        HttpRequestToBeSent request = request(1);
        ByteArray body = mock(ByteArray.class); when(body.length()).thenReturn(NativeCapture.MAX_BODY);
        when(request.body()).thenReturn(body);
        assertCategory("CAPTURE_LIMIT", request);
        verify(body, never()).getBytes();
    }
    @Test void exactlyBoundedAggregateFits() {
        HttpRequestToBeSent request = request(1);
        int head = "GET".length() + "https://example.test/safe".length() + "Hostexample.test".length();
        when(request.headers()).thenReturn(List.of(header("Host", "example.test")));
        byte[] body = new byte[NativeCapture.MAX_BODY - head]; doReturn(bytes(body)).when(request).body();
        assertEquals(body.length, NativeCapture.request(request).body().length);
    }
    @Test void changedOrDishonestNativeArrayIsRejected() {
        HttpRequestToBeSent request = request(1);
        ByteArray body = mock(ByteArray.class); when(body.length()).thenReturn(1); when(body.getBytes()).thenReturn(new byte[2]);
        when(request.body()).thenReturn(body);
        assertCategory("CAPTURE_FAILED", request);
    }
    @Test void rechecksLengthAfterGetBytes() {
        HttpRequestToBeSent request = request(1);
        ByteArray body = mock(ByteArray.class); when(body.length()).thenReturn(1, 2); when(body.getBytes()).thenReturn(new byte[1]);
        when(request.body()).thenReturn(body);
        assertCategory("CAPTURE_FAILED", request);
    }
    @Test void oversizedUrlIsRejectedBeforeAnyBodyRead() {
        HttpRequestToBeSent request = request(1); when(request.url()).thenReturn("x".repeat(NativeCapture.MAX_URL + 1));
        assertCategory("CAPTURE_LIMIT", request); verify(request, never()).body();
    }
    @Test void headerCountIsRejectedBeforeTraversalOrBody() {
        HttpRequestToBeSent request = request(1);
        @SuppressWarnings("unchecked") List<HttpHeader> headers = mock(List.class);
        when(headers.size()).thenReturn(257); when(request.headers()).thenReturn(headers);
        assertCategory("CAPTURE_LIMIT", request);
        verify(headers, never()).get(anyInt()); verify(request, never()).body();
    }
    @Test void headerNameBoundBeforeBody() {
        HttpRequestToBeSent request = request(1); when(request.headers()).thenReturn(List.of(header("A".repeat(257), "x")));
        assertCategory("CAPTURE_LIMIT", request); verify(request, never()).body();
    }
    @Test void headerValueBoundBeforeBody() {
        HttpRequestToBeSent request = request(1); when(request.headers()).thenReturn(List.of(header("A", "x".repeat(65_537))));
        assertCategory("CAPTURE_LIMIT", request); verify(request, never()).body();
    }
    @Test void aggregateHeadersBoundBeforeBody() {
        HttpRequestToBeSent request = request(1);
        when(request.headers()).thenReturn(List.of(header("A", "x".repeat(33_000)), header("B", "y".repeat(33_000))));
        assertCategory("CAPTURE_LIMIT", request); verify(request, never()).body();
    }
    @ParameterizedTest @ValueSource(strings = {"HTTP/3", "HTTP/0.9", "", "SYNTHETIC-SECRET"})
    void unknownVersionFailsClosedBeforeBody(String version) {
        HttpRequestToBeSent request = request(1); when(request.httpVersion()).thenReturn(version);
        assertCategory("UNSUPPORTED_HTTP_VERSION", request); verify(request, never()).body();
    }
    @Test void normalizesPseudoHeadersInCopyOnlyAndAddsValidatedHost() {
        HttpRequestToBeSent request = http2();
        List<HttpHeader> original = pseudos(); when(request.headers()).thenReturn(original);
        RequestData copy = NativeCapture.request(request);
        assertEquals(List.of(new RequestData.Header("Host", "example.test")), copy.headers());
        assertEquals(4, original.size()); assertEquals(":method", original.getFirst().name());
        assertTrue(mockingDetails(request).getInvocations().stream().noneMatch(i -> i.getMethod().getName().startsWith("with")));
    }
    @Test void http2WithAlreadyNormalizedHeadersIsAccepted() {
        HttpRequestToBeSent request = http2();
        assertEquals(2, NativeCapture.request(request).headers().size());
    }
    @Test void consistentExplicitDefaultPortAndHostAreAccepted() {
        HttpRequestToBeSent request = http2(); List<HttpHeader> headers = pseudos();
        headers.set(3, header(":authority", "EXAMPLE.TEST.:443")); headers.add(header("Host", "example.test"));
        when(request.headers()).thenReturn(headers);
        assertEquals(1, NativeCapture.request(request).headers().size());
    }
    @ParameterizedTest @MethodSource("inconsistentPseudoHeaders")
    void allUnknownDuplicatePartialAndMismatchCasesFailBeforeBody(List<HttpHeader> headers) {
        HttpRequestToBeSent request = http2(); when(request.headers()).thenReturn(headers);
        assertCategory("HTTP2_INCONSISTENT", request); verify(request, never()).body();
    }
    static Stream<List<HttpHeader>> inconsistentPseudoHeaders() {
        List<List<HttpHeader>> cases = new ArrayList<>();
        for (int i = 0; i < 4; i++) { List<HttpHeader> list = pseudos(); list.remove(i); cases.add(list); }
        for (int i = 0; i < 4; i++) { List<HttpHeader> list = pseudos(); list.add(list.get(i)); cases.add(list); }
        for (String name : List.of(":protocol", ":METHOD", ":status", ":unknown")) {
            List<HttpHeader> list = pseudos(); list.add(header(name, "x")); cases.add(list);
        }
        for (String method : List.of("POST", "get", "CONNECT", "SYNTHETIC-SECRET")) {
            List<HttpHeader> list = pseudos(); list.set(0, header(":method", method)); cases.add(list);
        }
        for (String path : List.of("/other", "/safe?unexpected=1", "https://example.test/safe", "*")) {
            List<HttpHeader> list = pseudos(); list.set(1, header(":path", path)); cases.add(list);
        }
        for (String scheme : List.of("http", "HTTPS", "ftp")) {
            List<HttpHeader> list = pseudos(); list.set(2, header(":scheme", scheme)); cases.add(list);
        }
        for (String authority : List.of("other.test", "example.test:80", "example.test:", "example.test:0", "example.test:65536",
                "example.test:443:443", "user@example.test", "example.test/path", "example.test#fragment", "[::1]")) {
            List<HttpHeader> list = pseudos(); list.set(3, header(":authority", authority)); cases.add(list);
        }
        List<HttpHeader> mismatchHost = pseudos(); mismatchHost.add(header("Host", "other.test")); cases.add(mismatchHost);
        List<HttpHeader> duplicateHost = pseudos(); duplicateHost.add(header("Host", "example.test")); duplicateHost.add(header("host", "example.test")); cases.add(duplicateHost);
        List<HttpHeader> wrongOrder = pseudos(); wrongOrder.addFirst(header("X-Regular", "x")); cases.add(wrongOrder);
        return cases.stream();
    }
    @Test void apiPathMismatchIsNotSilentlyDiscarded() {
        HttpRequestToBeSent request = http2(); when(request.headers()).thenReturn(pseudos()); when(request.path()).thenReturn("/other");
        assertCategory("HTTP2_INCONSISTENT", request); verify(request, never()).body();
    }
    @Test void pseudoHeadersOnHttp1AreRejected() {
        HttpRequestToBeSent request = request(1); when(request.headers()).thenReturn(pseudos());
        assertCategory("HTTP2_INCONSISTENT", request); verify(request, never()).body();
    }
    @Test void pseudoUrlAndServiceMismatchIsRejected() {
        HttpRequestToBeSent request = http2(); when(request.headers()).thenReturn(pseudos());
        when(request.url()).thenReturn("https://other.test/safe");
        assertCategory("HTTP2_INCONSISTENT", request); verify(request, never()).body();
    }
    private static HttpRequestToBeSent http2() {
        HttpRequestToBeSent request = request(1); when(request.httpVersion()).thenReturn("HTTP/2"); return request;
    }
    private static List<HttpHeader> pseudos() {
        return new ArrayList<>(List.of(header(":method", "GET"), header(":path", "/safe"), header(":scheme", "https"), header(":authority", "example.test")));
    }
    private static void assertCategory(String category, HttpRequestToBeSent request) {
        assertEquals(category, assertThrows(NativeCapture.Rejected.class, () -> NativeCapture.request(request)).category());
    }
}
