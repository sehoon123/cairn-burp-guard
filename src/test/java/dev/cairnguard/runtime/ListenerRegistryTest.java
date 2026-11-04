package dev.cairnguard.runtime;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class ListenerRegistryTest {
    @ParameterizedTest @ValueSource(strings = {"127.0.0.1:8080", "localhost:8080", "0.0.0.0:8080", "[::1]:8080", "[2001:db8::1]:8080"})
    void acceptsStrictActualListenerAndConsumesOnce(String value) {
        ListenerRegistry registry = new ListenerRegistry();
        registry.record(10, value, 7);
        assertEquals(8080, registry.consume(10, 7).orElseThrow());
        assertTrue(registry.consume(10, 7).isEmpty());
        assertEquals(0, registry.snapshot().get("retained"));
        assertFalse(registry.snapshot().toString().contains("localhost"));
    }
    @ParameterizedTest @ValueSource(strings = {"", "8080", "http://127.0.0.1:8080", "127.0.0.1:8080/path", "127.0.0.1:8080?x",
            "127.0.0.1:8080#x", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:+8080", "127.0.0.1: 8080",
            " localhost:8080", "localhost:8080\n", "::1:8080", "[::1]8080", "[::1%zone]:8080", "[invalid]:8080", "a@b:8080",
            "localhost:8080:8081", "localhost:８０８０", "[::1]:8080]", "[::1]:"})
    void malformedIsUnknownAndNeverUsesDestinationOrSuffix(String value) {
        ListenerRegistry registry = new ListenerRegistry();
        registry.record(10, value, 7);
        assertTrue(registry.consume(10, 7).isEmpty());
    }
    @Test void nullUnknownGenerationTtlAndResetAreFailClosed() {
        AtomicLong clock = new AtomicLong();
        ListenerRegistry registry = new ListenerRegistry(clock::get, 3, 100);
        registry.record(1, null, 1);
        assertTrue(registry.consume(1, 1).isEmpty());
        registry.record(1, "127.0.0.1:8080", 1);
        assertTrue(registry.consume(1, 2).isEmpty());
        registry.record(2, "127.0.0.1:8080", 1);
        clock.set(100);
        assertTrue(registry.consume(2, 1).isEmpty());
        assertEquals(1L, registry.snapshot().get("expired"));
        registry.record(3, "127.0.0.1:8080", 2);
        registry.reset();
        assertTrue(registry.consume(3, 2).isEmpty());
    }
    @Test void identicalAndConflictingDuplicatesPoisonMappingWithoutExtendingTtl() {
        AtomicLong clock = new AtomicLong();
        ListenerRegistry registry = new ListenerRegistry(clock::get, 2, 100);
        registry.record(1, "localhost:8080", 1);
        registry.record(1, "localhost:8080", 1);
        assertTrue(registry.consume(1, 1).isEmpty());
        registry.record(2, "localhost:8080", 1);
        clock.set(99);
        registry.record(2, "localhost:8081", 2);
        clock.set(100);
        assertTrue(registry.consume(2, 2).isEmpty());
        assertEquals(2L, registry.snapshot().get("collisions"));
        assertEquals(1L, registry.snapshot().get("expired"));
    }
    @Test void capacityNeverEvictsKnownMappingsToMakeAnUnknownBypass() {
        ListenerRegistry registry = new ListenerRegistry(() -> 0L, 1, 100);
        registry.record(1, "localhost:8080", 1);
        registry.record(2, "localhost:8081", 1);
        assertTrue(registry.consume(2, 1).isEmpty());
        assertEquals(8080, registry.consume(1, 1).orElseThrow());
        assertEquals(1L, registry.snapshot().get("capacityRejected"));
    }
}
