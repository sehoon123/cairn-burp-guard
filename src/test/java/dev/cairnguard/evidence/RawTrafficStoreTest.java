package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RawTrafficStoreTest {
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());
    private static RequestData request(List<Header> headers, byte[] body, boolean headersComplete, boolean bodyComplete) {
        return new RequestData("POST", "https://fixture.test/actual?echo=synthetic-auth-123456", "fixture.test", 443, true,
                headers, body, headersComplete, bodyComplete);
    }
    private static RequestData empty() { return request(List.of(), new byte[0], true, true); }
    private static long count(EvidenceStore store, String key) { return ((Number) store.stats().get(key)).longValue(); }

    @Test void humanLocalCopiesAreUnmaskedAndPreserveTamperedHostWhileAllSerializedEvidenceIsMasked() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request(List.of(new Header("Host", "synthetic.invalid"),
                new Header("Authorization", "Bearer synthetic-auth-123456"), new Header("Cookie", "sid=synthetic-cookie-345678"),
                new Header("X-Broker-Grant", "synthetic-grant-567890"), new Header("X-Cairn-Intent", "synthetic-auth-123456"),
                new Header("X-Cairn-Run", "synthetic-grant-567890"), new Header("Content-Type", "application/json")),
                "{\"echo\":\"synthetic-auth-123456\"}".getBytes(StandardCharsets.UTF_8), true, true), ALLOW, 1);
        store.response(id, 200, List.of(new Header("X-Broker-Grant", "synthetic-response-grant-789012"),
                new Header("Content-Type", "application/json")), "{\"echo\":\"synthetic-response-grant-789012\"}".getBytes(StandardCharsets.UTF_8));
        String ui = store.rawRequest(id) + store.rawResponse(id) + store.rawUrl(id) + store.rawCaptureInfo(id);
        for (String secret : List.of("synthetic-auth-123456", "synthetic-cookie-345678", "synthetic-grant-567890", "synthetic-response-grant-789012")) {
            assertTrue(ui.contains(secret));
            assertFalse(Json.write(store.snapshot()).contains(secret));
            assertFalse(store.exportJson(store.snapshot()).contains(secret));
            assertFalse(store.exportHar(store.snapshot()).contains(secret));
            assertFalse(Json.write(store.stats()).contains(secret));
        }
        assertTrue(store.rawRequest(id).contains("Host: synthetic.invalid\n"));
        assertTrue(store.rawRequest(id).contains("NOT wire proof"));
        assertEquals(true, store.rawCaptureInfo(id).get("available"));
        assertEquals(false, store.rawCaptureInfo(id).get("completeWireCapture"));
        assertEquals(false, store.rawCaptureInfo(id).get("requestTruncated"));
        assertEquals("synthetic-auth-123456", store.rawCaptureInfo(id).get("intentId"));
        assertThrows(UnsupportedOperationException.class, () -> store.rawCaptureInfo(id).clear());
        assertFalse(store.exportJson(store.snapshot()).contains("UNMASKED_INSPECTION"));
    }

    @Test void unsupportedCharsetAndBinaryHaveLosslessHexInsteadOfReplacementOrAutomaticOmission() {
        for (List<Header> headers : List.of(List.of(new Header("Content-Type", "application/json; charset=unknown-fixture")),
                List.of(new Header("Content-Type", "application/octet-stream")))) {
            EvidenceStore store = new EvidenceStore();
            byte[] original = new byte[] {0, 1, 10, 32, 65, (byte) 0xff};
            String id = store.begin("p", "p", request(headers, original, true, true), ALLOW, 1);
            assertEquals(0xff, original[5] & 255);
            assertTrue(store.rawRequest(id).contains("00 01 0a 20 41 ff"));
            assertEquals("HEX", store.rawCaptureInfo(id).get("requestBodyDisplay"));
            assertEquals(false, store.rawCaptureInfo(id).get("requestOmitted"));
            assertFalse(store.rawRequest(id).contains("\ufffd"));
            assertTrue(store.snapshot().getFirst().requestCapture().bodyOmitted());
        }
    }

    @Test void malformedJsonEncodedMultipartAndUnknownCharsetStillHaveRawInspectionCopies() {
        for (String type : List.of("application/json", "application/json; charset=synthetic-unknown", "multipart/form-data; boundary=fixture")) {
            EvidenceStore store = new EvidenceStore();
            String body = "{\"password\":\"synthetic-raw-only-secret\"";
            String id = store.begin("p", "p", request(List.of(new Header("Content-Type", type), new Header("Content-Encoding", "gzip")),
                    body.getBytes(StandardCharsets.UTF_8), true, true), ALLOW, 1);
            String raw = store.rawRequest(id);
            assertNotNull(raw);
            assertTrue(raw.contains("synthetic-raw-only-secret") || raw.contains("[HEX:") && raw.contains("73 79 6e"));
            assertFalse(store.exportJson(store.snapshot()).contains("synthetic-raw-only-secret"));
            assertFalse(store.exportHar(store.snapshot()).contains("synthetic-raw-only-secret"));
        }
    }

    @Test void incompletePrefixesAreLabeledAndOmittedFromExportRatherThanPresentedAsComplete() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", request(List.of(new Header("Host", "fuzz.invalid"),
                new Header("Content-Type", "application/json")), "{\"prefix\":true}".getBytes(StandardCharsets.UTF_8), false, false),
                new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of(), List.of("HEADER_INSPECTION_UNAVAILABLE_CAPTURE_INCOMPLETE")), 1);
        Map<String, Object> info = store.rawCaptureInfo(id);
        assertEquals(false, info.get("headersComplete"));
        assertEquals(false, info.get("bodyComplete"));
        assertEquals(true, info.get("requestTruncated"));
        assertTrue(store.rawRequest(id).contains("{\"prefix\":true}"));
        assertTrue(store.rawRequest(id).contains("incomplete capture"));
        TrafficEntry e = store.snapshot().getFirst();
        assertTrue(e.requestCapture().bodyOmitted());
        assertEquals(Redactor.OMITTED, e.requestCapture().body());
        assertTrue(e.inspectionWarnings().contains("HEADERS_INCOMPLETE"));
        assertTrue(e.inspectionWarnings().contains("BODY_INCOMPLETE"));
        store.responseBytes(id, 9_000_000);
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                "{\"responsePrefix\":true}".getBytes(StandardCharsets.UTF_8), true, false);
        assertTrue(store.rawResponse(id).contains("{\"responsePrefix\":true}"));
        assertEquals(true, store.rawCaptureInfo(id).get("responseTruncated"));
        assertTrue(store.snapshot().getFirst().responseCapture().bodyOmitted());
        assertEquals(9_000_000, store.snapshot().getFirst().responseBytes());
        assertFalse(store.exportJson(store.snapshot()).contains("responsePrefix"));
    }

    @Test void absentAndOversizedOmissionCopiesNeverBecomeInventedZeroByteTranscripts() {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("p", "p", empty(), ALLOW, 1);
        assertNull(store.rawResponse(id));
        assertEquals(false, store.rawCaptureInfo(id).get("responseAvailable"));
        store.response(id, 200, List.of(), new byte[0], false, false);
        assertTrue(store.rawResponse(id).contains("OMITTED"));
        assertEquals(true, store.rawCaptureInfo(id).get("responseOmitted"));
        assertEquals(-1, store.snapshot().getFirst().responseBytes());
        // Compatibility defense for the historical oversized zero-filled omission sentinel.
        store.response(id, 200, List.of(), new byte[RequestData.MAX_INSPECT_BYTES + 1]);
        assertTrue(store.rawResponse(id).contains("OMITTED"));
        assertFalse(store.rawResponse(id).contains("00 00 00"));
        assertEquals(-1, store.snapshot().getFirst().responseBytes());
    }

    @Test void clearEpochProjectSwitchAndEvictionDisposeRawWithoutLateResponseResurrection() {
        EvidenceStore store = new EvidenceStore(2, 100_000, 2048);
        assertNull(store.rawRequest("unknown"));
        store.response("never-begun", 200, List.of(), "not-captured".getBytes(StandardCharsets.UTF_8));
        assertEquals(0, count(store, "rawRetainedEntries"));
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.clearRawUi();
        assertNull(store.rawUrl(first));
        store.response(first, 200, List.of(), "late-raw".getBytes(StandardCharsets.UTF_8));
        assertNull(store.rawResponse(first));
        assertFalse(store.snapshot().isEmpty());
        String second = store.begin("p", "p", empty(), ALLOW, 1);
        assertNotNull(store.rawRequest(second));
        String third = store.begin("other-project", "p", empty(), ALLOW, 1);
        assertNull(store.rawRequest(second));
        store.response(second, 200, List.of(), "late-old-project".getBytes(StandardCharsets.UTF_8));
        assertNull(store.rawResponse(second));
        assertNotNull(store.rawRequest(third));
        store.begin("other-project", "p", empty(), ALLOW, 1);
        store.begin("other-project", "p", empty(), ALLOW, 1);
        assertNull(store.rawRequest(third));
        assertEquals(false, store.rawCaptureInfo(third).get("available"));
        store.clear();
        assertEquals(0, count(store, "rawRetainedEntries"));
        assertEquals(0, count(store, "rawRetainedBytes"));
    }

    @Test void rawContentIsBoundedIndependentlyAndRecordsCanBeEvictedWithoutLosingMaskedEvidence() {
        EvidenceStore store = new EvidenceStore(20, 30_000, 2048);
        RequestData large = request(List.of(new Header("Content-Type", "text/plain")),
                "한글😀".repeat(20_000).getBytes(StandardCharsets.UTF_8), true, true);
        for (int i = 0; i < 12; i++) {
            String id = store.begin("p", "p", large, ALLOW, 1);
            store.response(id, 200, List.of(), "x".repeat(9000).getBytes(StandardCharsets.UTF_8));
            assertTrue(count(store, "rawRetainedBytes") <= 30_000);
            for (TrafficEntry e : store.snapshot()) {
                if (store.rawRequest(e.id()) != null) {
                    assertTrue(Redactor.bytes(store.rawRequest(e.id())) <= 2048);
                    assertEquals(true, store.rawCaptureInfo(e.id()).get("requestTruncated"));
                }
                if (store.rawResponse(e.id()) != null) assertTrue(Redactor.bytes(store.rawResponse(e.id())) <= 2048);
            }
        }
        assertTrue(count(store, "rawRetainedEntries") < store.snapshot().size());
    }
}
