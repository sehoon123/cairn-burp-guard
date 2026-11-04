package dev.cairnguard.evidence;

import dev.cairnguard.model.Decision;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EvidenceStoreWatcherMaskingTest {
    @Test void pathInterpretationWarningIsCategoricalAndSurvivesEveryResealAndExport() throws Exception {
        EvidenceStore store = new EvidenceStore();
        var request = new RequestData("GET", "https://owned.test/c/%zz/main.do", "owned.test", 443, true, List.of(), new byte[0]);
        String id = store.begin("p", "Synthetic", request,
                new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of(), List.of("PATH_INTERPRETATION_INCOMPLETE", "unsafe free form")), 1);
        store.context(id, "forwarded", "PROTECTED", "");
        store.outcome(id, "FORWARDED", "NATIVE_RELEASED", null);
        store.responseBytes(id, 0);
        store.response(id, 200, List.of(), new byte[0]);
        store.bookmark(id, true);
        assertEquals(List.of("PATH_INTERPRETATION_INCOMPLETE", "INSPECTION_UNAVAILABLE"), store.entry(id).inspectionWarnings());
        var document = Json.MAPPER.readTree(store.exportJson(store.snapshot()));
        assertEquals("PATH_INTERPRETATION_INCOMPLETE", document.path("entries").get(0).path("inspectionWarnings").get(0).asText());
        assertTrue(store.exportHar(store.snapshot()).contains("PATH_INTERPRETATION_INCOMPLETE"));
    }
    @Test void latestSameEntryFingerprintsSanitizeIndividualStructuredValuesNotSchemaOrRawUi() {
        EvidenceStore store = new EvidenceStore();
        String secret = "synthetic-response-only-3948";
        var request = new RequestData("GET", "https://owned.test/download/" + secret, "owned.test", 443, true, List.of(), new byte[0]);
        String id = store.begin("p", "Synthetic", request, new Decision(Mode.ALLOW, "DEFAULT_ALLOW", List.of()), 1);
        TrafficEntry old = store.entry(id);
        store.response(id, 200, List.of(new RequestData.Header("Content-Type", "application/json")),
                ("{\"grant\":\"" + secret + "\"}").getBytes(StandardCharsets.UTF_8));
        var sanitizer = store.displaySanitizer(id);
        assertFalse(sanitizer.apply(old.url()).contains(secret));
        assertFalse(sanitizer.apply("/download/" + secret).contains(secret));
        assertEquals("owned.test", sanitizer.apply("owned.test"));
        assertTrue(store.rawUrl(id).contains(secret));
        assertTrue(store.rawResponse(id).contains(secret));
        assertFalse(store.exportJson(List.of(old)).contains(secret));
        assertFalse(store.exportHar(List.of(old)).contains(secret));
        store.clear();
        assertEquals("[REDACTED]", store.displaySanitizer(id).apply(old.url()));
        assertNull(store.entry(id));
    }
}
