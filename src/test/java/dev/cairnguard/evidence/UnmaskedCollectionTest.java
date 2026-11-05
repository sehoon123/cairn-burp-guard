package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic originals only. Collection has no masking and no capture/retention/export quota. */
class UnmaskedCollectionTest {
    private static final String AUTH = "Bearer SYNTH-AUTH-7731";
    private static final String COOKIE = "sid=SYNTH-COOKIE-7731";
    private static final String QUERY = "SYNTH-QUERY-7731";
    private static final String BODY = "<html>SYNTH-BODY-7731 [REDACTED] [OMITTED]</html>";
    private static final String SET_COOKIE = "grant=SYNTH-SETCOOKIE-7731";

    @Test void originalsAppearVerbatimAcrossRowsExportsAndHumanSnapshots() {
        EvidenceStore store = new EvidenceStore();
        RequestData request = new RequestData("POST", "https://example.test:443/p?token=" + QUERY, "example.test", 443, true,
                List.of(new Header("Authorization", AUTH), new Header("Cookie", COOKIE), new Header("Content-Type", "text/html")),
                BODY.getBytes(StandardCharsets.UTF_8), true, true, "/p?token=" + QUERY);
        Decision decision = new Decision(Mode.ALLOW, "RULE_ALLOW",
                List.of(new Decision.RuleHit("rule-SYNTH-RULE-ID", "SYNTH-RULE-NAME [REDACTED]", Mode.ALLOW)), List.of());
        String id = store.begin("project-7731", "Project SYNTH-PROJECT-7731", request, decision, 1);
        // The response reveals a value already seen in the request: nothing may be re-masked afterwards.
        store.response(id, 200, List.of(new Header("Set-Cookie", SET_COOKIE), new Header("Content-Type", "text/plain")),
                ("echo " + AUTH + " " + QUERY).getBytes(StandardCharsets.UTF_8), true, true);
        TrafficEntry row = store.entry(id);
        assertEquals("Project SYNTH-PROJECT-7731", row.projectName());
        assertEquals("SYNTH-RULE-NAME [REDACTED]", row.hits().getFirst().name());
        assertEquals("https://example.test:443/p?token=" + QUERY, row.url());
        for (String text : List.of(row.request(), store.exportJson(store.snapshot()), store.exportHar(store.snapshot()),
                new String(store.humanEvidence(List.of(id)).json(Map.of()), StandardCharsets.UTF_8))) {
            for (String original : List.of(AUTH, COOKIE, QUERY, "SYNTH-BODY-7731 [REDACTED] [OMITTED]"))
                assertTrue(text.contains(original), "missing original " + original);
        }
        assertTrue(row.response().contains(SET_COOKIE));
        assertTrue(row.response().contains("echo " + AUTH));
        assertTrue(store.exportJson(store.snapshot()).contains("SYNTH-PROJECT-7731"));
        assertTrue(store.exportHar(store.snapshot()).contains(SET_COOKIE));
        assertTrue(row.request().contains(AUTH), "request projection remains original after the response");
    }

    @Test void originalsBeyondOldHeaderPartBodyAndUrlBoundsAreRetainedWhole() {
        EvidenceStore store = new EvidenceStore();
        List<Header> headers = new ArrayList<>();
        for (int i = 0; i < 256; i++) headers.add(new Header("X-H" + i, "v" + i));
        String longValue = "V".repeat(70_000) + "-TAIL-HEADER";
        headers.add(new Header("X-Long-" + "n".repeat(300), longValue));
        byte[] body = ("B".repeat(1_100_000) + "-TAIL-BODY").getBytes(StandardCharsets.UTF_8);
        String target = "/" + "p".repeat(9_000) + "?q=" + "x".repeat(17_000) + "-TAIL-QUERY";
        String url = "https://example.test:443" + target;
        RequestData request = new RequestData("POST", url, "example.test", 443, true, headers, body, true, true, target);
        String id = store.begin("project", "Project", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        byte[] responseBody = ("R".repeat(1_100_000) + "-TAIL-RESPONSE").getBytes(StandardCharsets.UTF_8);
        store.response(id, 200, List.of(new Header("Content-Type", "text/plain")), responseBody);
        TrafficEntry row = store.entry(id);
        assertTrue(url.equals(row.url()), "complete URL");
        assertEquals(257, row.requestCapture().headers().size());
        assertTrue(longValue.equals(row.requestCapture().headers().getLast().value()), "complete header value");
        assertEquals(body.length, row.requestCapture().body().length());
        assertTrue(row.requestCapture().body().endsWith("-TAIL-BODY"));
        assertEquals(responseBody.length, row.responseCapture().body().length());
        assertEquals(responseBody.length, row.responseBytes());
        assertFalse(row.truncated());
        assertFalse(row.requestCapture().truncated() || row.responseCapture().truncated());
        String raw = store.rawRequest(id);
        assertTrue(raw.contains("-TAIL-HEADER") && raw.contains("-TAIL-BODY") && raw.contains("-TAIL-QUERY"));
        assertTrue(store.rawResponse(id).contains("-TAIL-RESPONSE"));
        assertTrue(url.equals(store.rawUrl(id)), "complete raw URL");
        assertEquals(0L, store.stats().get("evictions"));
    }

    @Test void originalsBeyondOldMetadataHitAndWarningBoundsAreRetainedWhole() {
        EvidenceStore store = new EvidenceStore();
        String name = "N".repeat(1_100) + "-TAIL-NAME";
        List<Decision.RuleHit> hits = IntStream.range(0, 129)
                .mapToObj(i -> new Decision.RuleHit("id-" + i + "-" + "i".repeat(600), "name-" + i, Mode.MONITOR)).toList();
        List<String> warnings = IntStream.range(0, 33).mapToObj(i -> "WARNING_" + i).toList();
        RequestData request = new RequestData("GET", "https://example.test:443/m", "example.test", 443, true,
                List.of(), new byte[0], true, true, "/m");
        String id = store.begin("project", name, request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", hits, warnings), 1);
        TrafficEntry row = store.entry(id);
        assertTrue(name.equals(row.projectName()), "complete project name");
        assertEquals(129, row.hits().size());
        assertTrue(hits.getLast().id().equals(row.hits().getLast().id()), "complete hit id");
        assertEquals(warnings, row.inspectionWarnings());
        assertFalse(row.truncated());
        assertTrue(name.equals(store.rawCaptureInfo(id).get("projectName")), "complete raw project name");
        assertEquals(129, ((List<?>) store.rawCaptureInfo(id).get("hits")).size());
    }

    @Test void originalsBeyondOldEntryCountAreRetainedAndExportable() {
        EvidenceStore store = new EvidenceStore();
        String first = null;
        for (int i = 0; i < 2_001; i++) {
            String id = store.begin("project", "Project", small("/e" + i), new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
            if (first == null) first = id;
        }
        assertEquals(2_001, store.snapshot().size());
        assertNotNull(store.entry(first));
        assertNotNull(store.rawRequest(first));
        assertEquals(0L, store.stats().get("evictions"));
        String exported = assertDoesNotThrow(() -> store.exportJson(store.snapshot()));
        assertTrue(exported.contains("/e0") && exported.contains("/e2000"));
    }

    @Test void originalsBeyondOldAggregateByteBudgetAreNotEvicted() {
        EvidenceStore store = new EvidenceStore();
        byte[] body = "A".repeat(65_536).getBytes(StandardCharsets.UTF_8);
        String first = null, last = null;
        for (int i = 0; i < 513; i++) {
            RequestData request = new RequestData("POST", "https://example.test:443/b" + i, "example.test", 443, true,
                    List.of(new Header("Content-Type", "text/plain")), body, true, true, "/b" + i);
            last = store.begin("project", "Project", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
            if (first == null) first = last;
        }
        assertEquals(513, store.snapshot().size());
        assertEquals(0L, store.stats().get("evictions"));
        assertEquals(65_536, store.entry(first).requestCapture().body().length());
        assertEquals(65_536, store.entry(last).requestCapture().body().length());
        assertNotNull(store.rawRequest(first));
    }

    @Test void originalsHumanSerializerHasNoOutputQuota() {
        String mebibyte = "S".repeat(1_048_576);
        Map<String, Object> document = Map.of("parts", Collections.nCopies(65, mebibyte), "tail", "SERIALIZER-TAIL");
        byte[] out = assertDoesNotThrow(() -> EvidenceStore.jsonBytes(document));
        assertTrue(out.length > 65L * 1_048_576);
        assertTrue(new String(out, out.length - 4_096, 4_096, StandardCharsets.UTF_8).contains("SERIALIZER-TAIL")
                || new String(out, 0, 4_096, StandardCharsets.UTF_8).contains("SERIALIZER-TAIL"));
    }

    private static RequestData small(String path) {
        return new RequestData("GET", "https://example.test:443" + path, "example.test", 443, true, List.of(), new byte[0], true, true, path);
    }
}
