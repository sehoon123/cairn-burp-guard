package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.PolicyCodec;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Bounded watcher/model interoperability only; no native request or Burp instance is used. */
@Timeout(15)
class WatcherRoutingInteropTest {
    private static RequestData request(String target) {
        return new RequestData("GET", "https://owned.test/health", "owned.test", 443, true,
                List.of(), new byte[0], true, true, target);
    }
    private static Limits limits(boolean probes) {
        return new Limits(100, 100, Map.of(), 100, 100, 1000, 1000, 1000,
                1, 60_000, null, null, 0, probes,
                probes ? List.of(new ProbePath("https", "owned.test", 443, "/health")) : List.of(), List.of());
    }
    private static ResponseWatcher watcher() { return new ResponseWatcher(limits(false), () -> 0, () -> 1_000_000); }
    private static ResponseWatcher.Endpoint endpoint(ResponseWatcher watcher, String target, List<String> views) {
        return watcher.endpoint(request(target), views);
    }

    @ParameterizedTest
    @ValueSource(strings = {"admin/x", "*", "@h/x", "x/health", "http://other.test/x", ""})
    void preservesAndHashesRawFirstViewAndProtectsEveryKnownAlias(String target) throws Exception {
        ResponseWatcher watcher = watcher();
        RequestData request = request(target);
        List<String> views = PolicyEngine.routingPaths(request);
        assertEquals(target, views.getFirst());
        var endpoint = endpoint(watcher, target, views);
        assertEquals(endpoint(watcher, target, List.of(target)).pathKeys().getFirst(), endpoint.pathKeys().getFirst());
        assertEquals(views.size(), endpoint.pathKeys().size());
        assertTrue(endpoint.pathKeys().stream().allMatch(k -> k.matches("[0-9a-f]{64}")));
        watcher.observe(endpoint, 200, 2);
        assertEquals(target, watcher.candidates().getFirst().path(), "the original untouched first view");
        assertEquals("owned.test", watcher.candidates().getFirst().host());
        assertEquals(target.startsWith("/") && !target.contains("?") ? "https://owned.test" + target : "", watcher.candidates().getFirst().policyUrl());
        assertEquals(target, request.nativeTarget(), "Inspection must not rewrite the request model");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 31, 127, 128, 159, 0xd800, 0xdc00})
    void acceptsRawControlC1AndLoneSurrogateViewsWithoutRawFallback(int codeUnit) throws Exception {
        ResponseWatcher watcher = watcher();
        String target = "/raw" + (char) codeUnit + "tail";
        List<String> views = PolicyEngine.routingPaths(request(target));
        assertEquals(target, views.getFirst());
        var endpoint = endpoint(watcher, target, views);
        watcher.observe(endpoint, 503, 2);
        assertEquals(target, endpoint.path(), "raw controls and lone surrogates stay original");
        assertEquals("owned.test", endpoint.host());
        assertEquals("", endpoint.policyUrl(), "an unfaithful ordinary URL is never drafted");
    }

    @Test void hashingIsLosslessForLoneSurrogatesAndLiteralQuestionMark() {
        ResponseWatcher watcher = watcher();
        var keys = new HashSet<String>();
        for (char codeUnit : new char[] {'?', '\ud800', '\ud801', '\udc00', '\udc01', '\ufffd'}) {
            String target = "/raw" + codeUnit + "tail";
            assertTrue(keys.add(endpoint(watcher, target, List.of(target)).pathKeys().getFirst()),
                    "Distinct UTF-16 inputs must not collapse through a charset replacement");
        }
    }

    @Test void exactlyNineViewsAreAcceptedButTenAreRejectedEvenWhenDuplicated() {
        ResponseWatcher watcher = watcher();
        List<String> views = new ArrayList<>();
        for (int i = 0; i < 9; i++) views.add("view" + i);
        assertEquals(9, endpoint(watcher, views.getFirst(), views).pathKeys().size());
        views.add(views.getFirst());
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, views.getFirst(), views));
    }

    @Test void firstAndLaterViewsHaveTheSameMaxUrlBound() {
        ResponseWatcher watcher = watcher();
        String maximum = "x".repeat(16_384);
        assertEquals(1, endpoint(watcher, maximum, List.of(maximum)).pathKeys().size());
        String excessive = maximum + "x";
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, excessive, List.of(excessive)));
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, "raw", List.of("raw", excessive)));
    }

    @Test void nullAndMissingViewsFailCategoricallyWithoutHashing() {
        ResponseWatcher watcher = watcher();
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, "raw", null));
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, "raw", List.of()));
        var views = new ArrayList<String>();
        views.add(null);
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, "raw", views));
        views.set(0, "raw"); views.add(null);
        assertThrows(IllegalArgumentException.class, () -> endpoint(watcher, "raw", views));
    }

    @Test void onlyStrictOriginFormCanBecomeAHealthProbe() {
        Limits limits = limits(true);
        GuardConfig config = new GuardConfig(2, List.of(new ScopeEntry(true, "owned.test", "https", 443, "")),
                List.of(), List.of(), Mode.ALLOW, limits);
        ProjectAccess projects = new ProjectAccess() {
            public Ref current() { return new Ref("synthetic", "Synthetic project"); }
            public String load() { return PolicyCodec.encode(config); }
            public void save(String ignored) { fail("No policy writes are needed"); }
        };
        try (GuardController controller = new GuardController(projects,
                new ResponseWatcher(limits, () -> 0, () -> 1_000_000), new IntentBudget(),
                new RateGate(limits), new ListenerRegistry())) {
            assertTrue(controller.prepare(request("/health")).healthProbe());
            for (String target : List.of("health", "@h/health", "x/health", "https://owned.test/health", "", "/x/../health")) {
                assertFalse(controller.prepare(request(target)).healthProbe(), target);
            }
        }
    }
}
