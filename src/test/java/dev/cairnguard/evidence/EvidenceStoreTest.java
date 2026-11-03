package dev.cairnguard.evidence;

import com.fasterxml.jackson.databind.JsonNode;
import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceStoreTest {
    private static final Decision ALLOW = new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of());
    private static RequestData request(String url, List<Header> headers, String body) {
        return new RequestData("POST", url, "fixture.test", 443, true, headers, body.getBytes(StandardCharsets.UTF_8));
    }
    private static RequestData empty() { return request("https://fixture.test/api?view=safe", List.of(), ""); }
    private static long count(EvidenceStore store, String key) { return ((Number) store.stats().get(key)).longValue(); }
    private static TrafficEntry only(EvidenceStore store) { return store.snapshot().getFirst(); }

    @Test void immutableSnapshotsSupportSearchAndBookmarksWithoutMutatingOldViews() {
        EvidenceStore store = new EvidenceStore();
        String first = store.begin("local", "Synthetic review", empty(), ALLOW, 7);
        List<TrafficEntry> before = store.snapshot();
        assertEquals("", before.getFirst().response());
        assertEquals("PENDING", before.getFirst().disposition());
        assertEquals(7, before.getFirst().revision());
        assertDoesNotThrow(() -> Instant.parse(before.getFirst().timestamp()));
        store.bookmark(first, true);
        String second = store.begin("local", "Other review", empty(), ALLOW, 8);
        assertEquals(List.of(second, first), store.snapshot().stream().map(TrafficEntry::id).toList());
        assertFalse(before.getFirst().bookmarked());
        assertTrue(store.snapshot().get(1).bookmarked());
        assertEquals(1, count(store, "bookmarked"));
        assertEquals(1, store.snapshot().stream().filter(e -> e.projectName().contains("Synthetic")).count());
        assertThrows(UnsupportedOperationException.class, () -> before.clear());
        assertThrows(UnsupportedOperationException.class, () -> only(store).hits().clear());
        assertThrows(UnsupportedOperationException.class, () -> only(store).requestCapture().headers().clear());
        assertThrows(UnsupportedOperationException.class, () -> store.stats().clear());
    }

    @Test void masksCredentialsAcrossMetadataHeadersBodiesAndExportsIncludingResponses() throws Exception {
        String secret = "fixture-credential-needle";
        EvidenceStore store = new EvidenceStore();
        RequestData request = request("https://user:" + secret + "@fixture.test/echo/" + secret + "?api_key=" + secret + "&echo=" + secret,
                List.of(new Header("Authorization", "Bearer " + secret), new Header("Cookie", "sid=" + secret),
                        new Header("X-Debug", "echo " + secret), new Header("Content-Type", "application/json")),
                "{\"password\":\"" + secret + "\",\"echo\":\"prefix-" + secret + "-suffix\",\"ok\":\"safe\"}");
        Decision decision = new Decision(Mode.BLOCK, "exception: " + secret,
                List.of(new Decision.RuleHit("id-" + secret, "rule " + secret, Mode.BLOCK)));
        String id = store.begin("project-" + secret, "Review " + secret, request, decision, 2);
        store.outcome(id, "BLOCKED", "native error " + secret, 451);
        store.response(id, 451, List.of(new Header("Set-Cookie", "session=" + secret), new Header("X-Echo", secret),
                new Header("Content-Type", "application/json")), ("{\"echo\":\"" + secret + "\",\"ok\":true}").getBytes(StandardCharsets.UTF_8));
        TrafficEntry entry = only(store);
        String all = Json.write(entry) + store.exportJson(store.snapshot()) + store.exportHar(store.snapshot());
        assertFalse(all.contains(secret), all);
        assertFalse(entry.url().contains("user:"));
        assertTrue(entry.request().contains("[REDACTED]"));
        assertEquals("OUTCOME_RECORDED", entry.reason());
        assertEquals("BLOCKED", entry.disposition());
        assertEquals(451, entry.statusCode());
        assertEquals(1, count(store, "blocked"));
        assertEquals(0, count(store, "forwarded"));
        assertEquals(1, count(store, "localResponses"));
        assertEquals(0, count(store, "upstreamResponses"));
        assertDoesNotThrow(() -> URI.create(entry.url()));
        assertEquals("safe", Json.MAPPER.readTree(entry.requestCapture().body()).path("ok").asText());
    }

    @Test void responseCredentialDiscoveryRemasksEarlierCopiesWithoutRetainingPlaintextSecrets() {
        String secret = "response-only-fixture-needle";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin(secret, "review " + secret,
                request("https://fixture.test/" + secret, List.of(new Header("X-Echo", secret)), ""), ALLOW, 1);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Set-Cookie", "sid=" + secret), new Header("Content-Type", "application/json")),
                ("{\"echo\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        assertFalse(Json.write(only(store)).contains(secret));
        assertFalse(store.exportHar(store.snapshot()).contains(secret));
        assertFalse(store.exportJson(stale).contains(secret));
        assertFalse(store.exportHar(stale).contains(secret));
    }

    @Test void responseSecretsRemaskEscapedStructuredValuesNotJustSerializedSubstrings() throws Exception {
        String secret = "fixture\nmultiline-value";
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "review", request("https://fixture.test/", List.of(new Header("Content-Type", "application/json")),
                "{\"echo\":\"fixture\\nmultiline-value\",\"safe\":\"visible\"}"), ALLOW, 1);
        List<TrafficEntry> stale = store.snapshot();
        store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                "{\"password\":\"fixture\\nmultiline-value\"}".getBytes(StandardCharsets.UTF_8));
        JsonNode body = Json.MAPPER.readTree(only(store).requestCapture().body());
        assertEquals(Redactor.REDACTED, body.path("echo").asText());
        assertEquals("visible", body.path("safe").asText());
        assertFalse(store.exportJson(stale).contains("multiline-value"));
        assertFalse(store.exportHar(stale).contains("multiline-value"));
        assertFalse(only(store).request().contains(secret));
    }

    @Test void releasesAreNotDeliveryAndLocalBlockCannotBeOverwrittenByGenericCallback() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String forwarded = store.begin("p", "p", empty(), ALLOW, 1);
        store.outcome(forwarded, "FORWARDED", "NATIVE_RELEASED", null);
        store.outcome(forwarded, "FORWARDED", "NATIVE_RELEASED", null);
        store.outcome(forwarded, "BLOCKED", "LOCAL_BLOCK", 451);
        assertEquals("FORWARDED", only(store).disposition());
        assertEquals(0, count(store, "blocked"));
        assertNull(only(store).statusCode());
        assertEquals(1, count(store, "forwarded"));
        assertEquals(0, count(store, "responses"));
        String blocked = store.begin("p", "p", empty(), ALLOW, 1);
        store.response(blocked, 451, List.of(), new byte[0]);
        store.outcome(blocked, "BLOCKED", "LOCAL_BLOCK", 451);
        store.outcome(blocked, "FORWARDED", "NATIVE_RELEASED", null);
        assertEquals("BLOCKED", only(store).disposition());
        assertEquals("LOCAL_BLOCK", only(store).reason());
        assertEquals(1, count(store, "blocked"));
        assertEquals(1, count(store, "localResponses"));
        assertEquals(0, count(store, "upstreamResponses"));
        JsonNode har = Json.MAPPER.readTree(store.exportHar(store.snapshot()));
        assertEquals("LOCAL_BLOCK", har.at("/log/entries/0/_cairnGuard/responseSource").asText());
        assertFalse(har.at("/log/entries/1/_cairnGuard/responseObserved").asBoolean());
        assertEquals("NATIVE_RELEASE_NOT_PROVEN_DELIVERY", har.at("/log/_cairnGuard/forwardedMeans").asText());
    }

    @Test void countEvictionIsOldestFirstEvenForBookmarksAndCountersSurviveClear() {
        EvidenceStore store = new EvidenceStore(2, 1024 * 1024, 1024);
        String first = store.begin("p", "p", empty(), ALLOW, 1);
        store.bookmark(first, true);
        store.outcome(first, "FORWARDED", "NATIVE_RELEASED", null);
        store.begin("p", "p", empty(), ALLOW, 1);
        store.begin("p", "p", empty(), ALLOW, 1);
        assertEquals(2, store.snapshot().size());
        assertEquals(1, count(store, "evictions"));
        assertFalse(store.snapshot().stream().anyMatch(e -> e.id().equals(first)));
        assertEquals(0, count(store, "bookmarked"));
        store.response(first, 200, List.of(), new byte[0]);
        assertEquals(1, count(store, "orphanUpdates"));
        store.clear();
        assertTrue(store.snapshot().isEmpty());
        assertEquals(0, count(store, "retainedBytes"));
        assertEquals(3, count(store, "begun"));
        assertEquals(1, count(store, "forwarded"));
        assertEquals(1, count(store, "evictions"));
        assertEquals(1, count(store, "clears"));
        assertEquals(2, count(store, "clearedEntries"));
    }

    @Test void totalBytesAndEachPartAreBoundedAfterMaskingNotBefore() {
        EvidenceStore store = new EvidenceStore(20, 20_000, 2048);
        String secret = "needle-after-the-capture-limit";
        String large = "x".repeat(12_000);
        RequestData request = request("https://fixture.test/?echo=" + secret,
                List.of(new Header("Content-Type", "application/json")),
                "{\"padding\":\"" + large + "\",\"password\":\"" + secret + "\"}");
        for (int i = 0; i < 20; i++) {
            String id = store.begin("p", "p", request, ALLOW, 1);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")),
                    ("{\"echo\":\"" + secret + "\",\"pad\":\"" + large + "\"}").getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(count(store, "retainedBytes") <= 20_000);
        assertTrue(count(store, "evictions") > 0);
        assertEquals(20, count(store, "truncations"));
        assertFalse(store.snapshot().isEmpty());
        for (TrafficEntry entry : store.snapshot()) {
            assertTrue(entry.truncated());
            assertTrue(Redactor.bytes(entry.request()) <= 2048);
            assertTrue(Redactor.bytes(entry.response()) <= 2048);
            assertFalse(entry.url().contains(secret), entry.url());
        }
        assertFalse(store.exportJson(store.snapshot()).contains(secret));
    }

    @Test void defaultBoundsAreEnforcedAndNeverDisabledByResponseGrowth() {
        EvidenceStore store = new EvidenceStore();
        String payload = "{\"safe\":\"" + "z".repeat(80_000) + "\"}";
        for (int i = 0; i < 300; i++) {
            String id = store.begin("p", "p", empty(), ALLOW, i);
            store.response(id, 200, List.of(new Header("Content-Type", "application/json")), payload.getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(count(store, "retainedBytes") <= EvidenceStore.MAX_TOTAL_BYTES);
        assertTrue(count(store, "evictions") > 0);
        for (TrafficEntry e : store.snapshot()) assertTrue(Redactor.bytes(e.response()) <= EvidenceStore.MAX_PART_BYTES);
        EvidenceStore smallMessages = new EvidenceStore();
        for (int i = 0; i <= EvidenceStore.MAX_ENTRIES; i++) smallMessages.begin("p", "p", empty(), ALLOW, i);
        assertEquals(EvidenceStore.MAX_ENTRIES, smallMessages.snapshot().size());
        assertEquals(1, count(smallMessages, "evictions"));
    }

    @Test void validHarHasRequiredFieldsNoClaimedWireSizesOrFakeMissingResponses() throws Exception {
        EvidenceStore store = new EvidenceStore();
        String id = store.begin("local", "fixture", empty(), ALLOW, 1);
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.response(id, 204, List.of(new Header("X-Safe", "ok")), new byte[0]);
        JsonNode document = Json.MAPPER.readTree(store.exportHar(store.snapshot()));
        assertEquals("1.2", document.at("/log/version").asText());
        assertEquals("Cairn Proxy Guard", document.at("/log/creator/name").asText());
        JsonNode e = document.at("/log/entries/0");
        assertDoesNotThrow(() -> Instant.parse(e.path("startedDateTime").asText()));
        assertTrue(e.has("cache"));
        assertEquals(0, e.path("time").asInt());
        for (String part : List.of("request", "response")) {
            for (String key : List.of("httpVersion", "headers", "cookies", "headersSize", "bodySize")) assertTrue(e.path(part).has(key), part + ":" + key);
            assertEquals(-1, e.path(part).path("bodySize").asInt());
        }
        assertEquals(204, e.path("response").path("status").asInt());
        assertTrue(e.at("/response/content").has("mimeType"));
        assertEquals(0, e.at("/timings/send").asInt());
        assertEquals(0, e.at("/timings/wait").asInt());
        assertEquals(0, e.at("/timings/receive").asInt());
        assertTrue(e.at("/_cairnGuard/responseObserved").asBoolean());
        assertFalse(e.at("/_cairnGuard/completeWireCapture").asBoolean());
        assertEquals("REDACTED_EVIDENCE_NOT_WIRE_CAPTURE", e.at("/_cairnGuard/label").asText());
        assertFalse(store.exportJson(store.snapshot()).contains("provenanceSeal"));
    }

    @Test void exportRejectsForeignOrForgedRecordsButOldSnapshotsRemainExportableAfterEviction() {
        EvidenceStore store = new EvidenceStore(1, 100_000, 1024);
        store.begin("p", "p", empty(), ALLOW, 1);
        List<TrafficEntry> old = store.snapshot();
        store.begin("p", "p", empty(), ALLOW, 2);
        assertDoesNotThrow(() -> store.exportJson(old));
        assertDoesNotThrow(() -> store.exportHar(old));
        TrafficEntry e = old.getFirst();
        TrafficEntry forged = new TrafficEntry(e.id(), e.projectId(), "raw-secret-must-not-export", e.timestamp(), e.method(), e.url(), e.mode(),
                e.disposition(), e.reason(), e.statusCode(), e.hits(), e.revision(), e.bookmarked(), e.requestCapture(), e.responseCapture(), e.truncated(), e.provenanceSeal());
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> store.exportJson(List.of(forged)));
        assertEquals("INVALID_EVIDENCE_SELECTION", failure.getMessage());
        assertThrows(IllegalArgumentException.class, () -> store.exportHar(List.of(forged)));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceStore().exportJson(old));
    }

    @Test void concurrentCallbacksAndExportsHaveNoMutableAliasesOrRaces() throws Exception {
        EvidenceStore store = new EvidenceStore();
        try (var executor = Executors.newFixedThreadPool(6)) {
            List<Callable<Void>> jobs = new ArrayList<>();
            for (int n = 0; n < 120; n++) jobs.add(() -> {
                String id = store.begin("p", "p", empty(), ALLOW, 1);
                store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
                store.response(id, 200, List.of(), new byte[0]);
                store.bookmark(id, true);
                Json.MAPPER.readTree(store.exportJson(store.snapshot()));
                return null;
            });
            for (var result : executor.invokeAll(jobs)) result.get();
        }
        assertEquals(120, count(store, "begun"));
        assertEquals(120, count(store, "responses"));
        assertEquals(120, count(store, "forwarded"));
        assertEquals(120, count(store, "bookmarked"));
        assertEquals(120, store.snapshot().size());
    }

    @Test void statsHaveFixedCredentialFreeKeysAndUnknownMessagesAreNeverRetained() {
        EvidenceStore store = new EvidenceStore();
        Map<String, Object> before = store.stats();
        String id = store.begin("p", "p", empty(), new Decision(Mode.BLOCK, "Bearer error-secret-fixture", List.of()), 1);
        store.outcome(id, "error-secret-fixture", "secret fixture debug", 999);
        assertEquals(before.keySet(), store.stats().keySet());
        assertEquals("ERROR", only(store).disposition());
        assertNull(only(store).statusCode());
        assertEquals("OUTCOME_RECORDED", only(store).reason());
        assertFalse(store.exportJson(store.snapshot()).contains("error-secret-fixture"));
    }
}
