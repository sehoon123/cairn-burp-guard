package dev.cairnguard.model;

import dev.cairnguard.model.RequestData.Header;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RequestAttributionTest {
    @Test void absentLabelsAreExplicitAndUnrelatedHeadersAreIgnored() {
        assertEquals(new RequestAttribution("-", "-", true), RequestAttribution.parse(List.of()));
        assertEquals(new RequestAttribution("-", "-", true), RequestAttribution.parse(List.of(new Header("X-Other", "i048"))));
    }

    @Test void singleCaseInsensitiveHeadersPreserveExactValidValuesWithoutChangingHeaders() {
        List<Header> headers = List.of(new Header("x-CAIRN-intent", "i048_A.a:Z-9"), new Header("X-Cairn-Run", "R".repeat(64)));
        var attribution = RequestAttribution.parse(headers);
        assertTrue(attribution.valid());
        assertEquals("i048_A.a:Z-9", attribution.intentId());
        assertEquals("R".repeat(64), attribution.runId());
        assertEquals("i048_A.a:Z-9", headers.getFirst().value());
    }

    @ParameterizedTest @ValueSource(strings = {"", " ", " i048", "i048 ", "i048,i049", "i048/i049", "i048\r\nInjected", "한글", "i048?", "i048%31", "i048\t", "i048@run"})
    void invalidValuesAreNotTrimmedNormalizedOrRetained(String value) {
        var intent = RequestAttribution.parse(List.of(new Header("X-Cairn-Intent", value), new Header("X-Cairn-Run", "run")));
        assertFalse(intent.valid());
        assertEquals("?", intent.intentId());
        assertEquals("run", intent.runId());
        var run = RequestAttribution.parse(List.of(new Header("X-Cairn-Run", value)));
        assertFalse(run.valid());
        assertEquals("-", run.intentId());
        assertEquals("?", run.runId());
    }

    @Test void nullOverlengthAndSurrogateValuesCannotBeForgedAsValid() {
        for (String value : new String[] {null, "x".repeat(65), "\ud800"}) {
            assertFalse(RequestAttribution.parse(List.of(new Header("X-Cairn-Intent", value))).valid());
            assertEquals("?", new RequestAttribution(value, "run", true).intentId());
            assertFalse(new RequestAttribution(value, "run", true).valid());
        }
        assertFalse(RequestAttribution.parse(null).valid());
    }

    @Test void unicodeCaseFoldingCannotForgeAnAsciiHeaderAlias() {
        assertEquals(new RequestAttribution("-", "-", true),
                RequestAttribution.parse(List.of(new Header("X-Caırn-Intent", "injected"))));
    }

    @Test void duplicatesAreRejectedEvenIdenticalAndNeverRecoveredByAThirdHeader() {
        for (String name : List.of("X-Cairn-Intent", "X-Cairn-Run")) {
            var duplicate = RequestAttribution.parse(List.of(new Header(name, "same"), new Header(name.toLowerCase(), "same"), new Header(name, "other")));
            assertFalse(duplicate.valid());
            assertEquals("?", name.endsWith("Intent") ? duplicate.intentId() : duplicate.runId());
        }
    }
}
