package dev.cairnguard.runtime;

import dev.cairnguard.evidence.TrafficEntry;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Condition;
import dev.cairnguard.model.GuardConfig.Field;
import dev.cairnguard.model.GuardConfig.Match;
import dev.cairnguard.model.GuardConfig.Rule;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.model.RequestData.Header;
import dev.cairnguard.runtime.GuardController.Admission;
import dev.cairnguard.runtime.GuardController.Prepared;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Bounded owned raw HTTP fixture + controlled forwarding HARNESS using the actual GuardController.
 * NOT a native Burp test, HTTP proxy implementation, TLS test or network-enforcement proof.
 */
@Timeout(30)
@SuppressWarnings("try") // Cleanup deliberately closes controller/sockets before bounded executor joins.
class ProxyLoopbackTest {
    private static final String SECRET = "fabricated-loopback-secret-6429";
    private static final String RESPONSE_COOKIE = "fixture=synthetic-upstream-cookie; HttpOnly";
    private static final byte[] RESPONSE_BODY = bytes("{\"fixture\":true}");

    static Stream<Arguments> dangerousRequests() {
        return Stream.of(
                Arguments.of("DELETE", "/safe", "application/json", ""),
                Arguments.of("GET", "/delete", "application/json", ""),
                Arguments.of("GET", "/safe?op=DeLeTe", "application/json", ""),
                Arguments.of("GET", "/safe?op=%2564elete", "application/json", ""),
                Arguments.of("POST", "/safe", "application/json", "{\"operation\":\"delete\"}"),
                Arguments.of("POST", "/safe", "application/json", "{\"nested\":[{\"op\":\"\\u0064elete\"}]}"),
                Arguments.of("POST", "/safe", "application/x-www-form-urlencoded", "operation=%64elete"),
                Arguments.of("POST", "/safe", "text/plain", "please DELETE this fixture"));
    }

    @ParameterizedTest(name = "dangerous fixture [{index}]") @MethodSource("dangerousRequests")
    void dangerousMethodUrlAndBodyNeverReachOwnedUpstream(String method, String target, String type, String body) throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            // New defaults contain ONLY method DELETE; explicitly author each content test's field.
            Field field = method.equals("DELETE") ? Field.METHOD : target.equals("/delete") ? Field.PATH
                    : target.contains("?") ? Field.QUERY : type.equals("application/json") ? Field.JSON
                    : type.equals("application/x-www-form-urlencoded") ? Field.FORM : Field.BODY;
            h.authorBlock(field, "delete");
            Wire request = h.wire(method, target, type, body, List.of());
            Reply reply = h.forward(request);
            assertLocalBlock(h, reply, "RULE_BLOCK");
            assertEquals(0, h.upstream.hits.get());
            assertEquals(0, h.socketOpens.get(), "blocked request never even opens the owned socket");
            assertEquals(0, h.gate("admitted"));
            assertTrue(h.controller.approvals().isEmpty());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"malformed-json", "malformed-percent", "binary", "multipart", "encoding", "charset", "websocket"})
    void optionalUnsupportedOrMalformedInspectionPassesUnchangedWithExplicitWarning(String kind) throws Exception {
        try (Harness h = new Harness(Mode.MONITOR, limits(5, 5, 3, 10_000))) {
            h.authorBlock(Field.ANY, "operator-denied-marker"); // demand optional inspection explicitly
            Wire request = switch (kind) {
                case "malformed-json" -> h.wire("POST", "/safe", "application/json", "{", List.of());
                case "malformed-percent" -> h.wire("GET", "/safe?value=%ZZ", "application/json", "", List.of());
                case "binary" -> h.wire("POST", "/safe", "application/octet-stream", "opaque", List.of());
                case "multipart" -> h.wire("POST", "/safe", "multipart/form-data; boundary=fixture", "opaque", List.of());
                case "encoding" -> h.wire("POST", "/safe", "application/json", "{}", List.of(new Header("Content-Encoding", "gzip")));
                case "charset" -> h.wire("POST", "/safe", "text/plain; charset=unsupported-fixture", "opaque", List.of());
                case "websocket" -> h.wire("GET", "/safe", "application/json", "", List.of(new Header("Upgrade", "websocket")));
                default -> throw new AssertionError(kind);
            };
            Reply reply = h.forward(request);
            assertTrue(reply.forwarded()); assertEquals(200, reply.status());
            assertEquals(1, h.upstream.hits.get()); assertEquals(1, h.socketOpens.get());
            Capture observed = h.upstream.captures.getFirst();
            assertEquals(request.target(), observed.target()); assertEquals(request.headers(), observed.headers());
            assertArrayEquals(request.body(), observed.body());
            assertEquals("FORWARDED", h.row(reply).disposition());
            if (kind.equals("websocket")) assertTrue(h.row(reply).inspectionWarnings().isEmpty(), "ordinary handshake fields are inspectable; no invented failure");
            else assertFalse(h.row(reply).inspectionWarnings().isEmpty(), "attempted unsupported inspection must be visible");
        }
    }

    @Test void explicitOperatorHeaderBlockHasNoSocketHandoff() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            h.authorBlock(Field.HEADER, "operator-denied-marker");
            assertLocalBlock(h, h.forward(h.wire("GET", "/safe", "text/plain", "", List.of(new Header("X-Action", "operator-denied-marker")))), "RULE_BLOCK");
            assertEquals(0, h.socketOpens.get()); assertEquals(0, h.upstream.hits.get());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"/ui/bp/common/board/deleteInfoBoardComnt.do", "/deleteListTmp.do", "/undelete",
            "/c/;/main.do", "/c/%2e/main.do", "/c/%252e/main.do", "/c/%25252e/main.do", "/c/a/../main.do",
            "/c/%3b/main.do", "/c/%253b/main.do", "/c%2fmain.do", "/c%252fmain.do", "//c///main.do", "/c\\main.do", "/c/%ZZ/main.do?bad=%ZZ"})
    void allPathDefaultsAndHostFuzzReachOwnedRawTargetWithExactTargetHeadersAndBody(String target) throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(1_000, 1_000, 3, 10_000))) {
            Wire original = h.wire("POST", target, "text/plain; charset=unsupported-fixture", "undelete explanation", List.of());
            List<Header> headers = original.headers().stream().map(v -> v.name().equals("Host") ? new Header("Host", "synthetic.invalid") : v).toList();
            RequestData inspection = new RequestData(original.method(), original.inspection().url(), "127.0.0.1", h.upstream.port(), false, headers, original.body());
            Wire fuzzed = new Wire(original.id(), original.method(), original.target(), headers, original.body(), inspection);
            Reply reply = h.forward(fuzzed); assertTrue(reply.forwarded()); assertEquals(200, reply.status());
            Capture observed = h.upstream.captures.getFirst();
            assertEquals(target, observed.target()); assertEquals(headers, observed.headers()); assertArrayEquals(original.body(), observed.body());
            assertEquals(1, h.socketOpens.get()); assertEquals(1, h.upstream.hits.get()); h.upstream.assertHealthy();
        }
    }

    @Test void emptyAllowlistAndExplicitBlockScopeProduceNoUpstreamRequests() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            GuardConfig valid = h.controller.config();
            h.apply(new GuardConfig(2, List.of(), List.of(), valid.rules(), Mode.ALLOW, valid.limits()));
            assertLocalBlock(h, h.forward(h.wire("GET", "/safe", "application/json", "", List.of())), "SCOPE_NOT_ALLOWED");
            h.apply(new GuardConfig(2, valid.allowScope(),
                    List.of(new ScopeEntry(true, "127.0.0.1", "http", h.upstream.port(), "/forbidden.*")),
                    valid.rules(), Mode.ALLOW, valid.limits()));
            assertLocalBlock(h, h.forward(h.wire("GET", "/forbidden", "application/json", "", List.of())), "SCOPE_BLOCKED");
            assertEquals(0, h.upstream.hits.get());
            assertEquals(0, h.socketOpens.get());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"application/json", "application/x-www-form-urlencoded", "text/plain; charset=UTF-8"})
    void allowedRequestsPreserveObservedHeaderCookieAuthorizationAndBodyValues(String type) throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            String body = switch (type) {
                case "application/json" -> "{\"token\":\"" + SECRET + "\",\"message\":\"한글 safe\"}";
                case "application/x-www-form-urlencoded" -> "token=" + SECRET + "&message=%ED%95%9C%EA%B8%80+safe";
                default -> "한글 safe text";
            };
            List<Header> headers = List.of(new Header("Authorization", "Bearer " + SECRET),
                    new Header("Proxy-Authorization", "Basic c3ludGhldGljOm9ubHk="),
                    new Header("Cookie", "session=" + SECRET + "; theme=light"), new Header("X-API-Key", SECRET),
                    new Header("X-Duplicate", "first"), new Header("X-Duplicate", "second"));
            Wire request = h.wire("POST", "/safe?search=unchanged+value", type, body, headers);
            byte[] originalBody = request.body().clone();
            List<Header> originalHeaders = List.copyOf(request.headers());
            Reply reply = h.forward(request);
            assertTrue(reply.forwarded());
            assertEquals(200, reply.status());
            assertArrayEquals(RESPONSE_BODY, reply.body());
            assertEquals(List.of(RESPONSE_COOKIE), values(reply.headers(), "Set-Cookie"));
            assertEquals(1, h.upstream.hits.get());
            Capture observed = h.upstream.captures.getFirst();
            assertEquals("POST", observed.method());
            assertEquals("/safe?search=unchanged+value", observed.target());
            assertArrayEquals(originalBody, observed.body());
            for (Header header : headers) assertTrue(values(observed.headers(), header.name()).contains(header.value()));
            assertEquals(List.of("first", "second"), values(observed.headers(), "X-Duplicate"));
            assertArrayEquals(originalBody, request.body());
            assertEquals(originalHeaders, request.headers());
            assertEquals("FORWARDED", h.row(reply).disposition());
            assertEquals(0, h.gate("active"));
            assertEquals(1, h.evidence("upstreamResponses"));
            String exported = h.controller.exportJson(h.controller.traffic());
            assertTrue(exported.contains(SECRET));
            assertTrue(exported.contains(RESPONSE_COOKIE));
            assertTrue(exported.contains("c3ludGhldGljOm9ubHk="));
            assertTrue(exported.contains("ORIGINAL_EVIDENCE_NOT_WIRE_CAPTURE"));
        }
    }

    @Test void humanDenialHasZeroHitsAndApprovalIsRequiredBeforeAnySocketOpens() throws Exception {
        try (Harness h = new Harness(Mode.ASK, limits(5, 5, 3, 10_000))) {
            Future<Reply> result = h.callers.submit(() -> h.forward(h.wire("GET", "/safe", "application/json", "", List.of())));
            await(() -> h.controller.approvals().size() == 1);
            assertEquals(0, h.socketOpens.get());
            assertEquals(0, h.upstream.hits.get());
            assertEquals(0, h.gate("active"));
            String id = h.controller.approvals().getFirst().id();
            assertTrue(h.controller.decideApproval(id, false));
            assertLocalBlock(h, get(result), "DENIED");
            assertFalse(h.controller.decideApproval(id, true));
            assertEquals(0, h.upstream.hits.get());
        }
    }

    @Test void humanApprovalAllowsExactlyOneOriginalFixtureToReachOwnedUpstream() throws Exception {
        try (Harness h = new Harness(Mode.ASK, limits(5, 5, 3, 10_000))) {
            Wire request = h.wire("POST", "/safe", "application/json", "{\"operation\":\"read\"}",
                    List.of(new Header("Cookie", "fixture=" + SECRET)));
            Future<Reply> result = h.callers.submit(() -> h.forward(request));
            await(() -> h.controller.approvals().size() == 1);
            assertEquals(0, h.upstream.hits.get());
            String id = h.controller.approvals().getFirst().id();
            assertTrue(h.controller.decideApproval(id, true));
            Reply reply = get(result);
            assertTrue(reply.forwarded());
            assertFalse(h.controller.decideApproval(id, true));
            assertEquals(1, h.upstream.hits.get());
            assertArrayEquals(request.body(), h.upstream.captures.getFirst().body());
            assertEquals(List.of("fixture=" + SECRET), values(h.upstream.captures.getFirst().headers(), "Cookie"));
        }
    }

    @Test void policyChangeAdjacentToCommitBlocksBeforeOpeningOwnedSocket() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            Wire request = h.wire("GET", "/safe", "application/json", "", List.of());
            Reply reply = h.forward(request, () -> h.apply(h.controller.config()));
            assertLocalBlock(h, reply, "POLICY_CHANGED");
            assertEquals(0, h.socketOpens.get());
            assertEquals(0, h.upstream.hits.get());
            assertEquals(0, h.gate("active"), "confirmed pre-dispatch rejection releases its own permit");
        }
    }

    private enum WaitingChange { POLICY, PAUSE, CLOSE }

    @ParameterizedTest @EnumSource(WaitingChange.class)
    void queuedStaleRequestAddsZeroHitsWhileAlreadyRunningRequestKeepsPermit(WaitingChange change) throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(1_000, 1_000, 1, 10_000))) {
            h.upstream.holdResponses();
            Wire first = h.wire("GET", "/first", "application/json", "", List.of());
            Future<Reply> running = h.callers.submit(() -> h.forward(first));
            await(() -> h.upstream.hits.get() == 1);
            Future<Reply> queued = h.callers.submit(() -> h.forward(h.wire("GET", "/second", "application/json", "", List.of())));
            await(() -> h.gate("queued") == 1);
            switch (change) {
                case POLICY -> h.apply(h.controller.config());
                case PAUSE -> h.controller.pause(true);
                case CLOSE -> h.controller.close();
            }
            Reply denied = get(queued);
            assertFalse(denied.forwarded());
            assertEquals(451, denied.status());
            assertEquals(1, h.upstream.hits.get(), "only the earlier, already-started request reached upstream");
            assertEquals(1, h.socketOpens.get());
            assertEquals(1, h.gate("active"));
            assertFalse(running.isDone(), "controller state change does not manufacture a real completion");
            h.upstream.releaseResponses();
            assertTrue(get(running).forwarded());
            assertEquals(0, h.gate("active"));
            assertEquals(List.of("/first"), h.upstream.captures.stream().map(Capture::target).toList());
        }
    }

    @Test void sixWorkersShareFiveRpsAndTwoActualUnansweredUpstreamOperations() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 2, 10_000))) {
            h.upstream.holdResponses();
            CountDownLatch ready = new CountDownLatch(6);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<List<Reply>>> results = new ArrayList<>();
            for (int worker = 0; worker < 6; worker++) {
                int index = worker;
                results.add(h.callers.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    List<Reply> replies = new ArrayList<>();
                    for (int sequence = 0; sequence < 2; sequence++)
                        replies.add(h.forward(h.wire("GET", "/safe?w=" + index + "&n=" + sequence, "application/json", "", List.of())));
                    return replies;
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            await(() -> h.upstream.hits.get() == 2 && h.gate("queued") == 4);
            assertEquals(2, h.upstream.active.get(), "two real owned handlers are still awaiting permission to respond");
            assertEquals(2, h.gate("active"));
            assertEquals(2, h.gate("admitted"), "rate slots alone do not recycle in-flight ownership");
            assertTrue(results.stream().noneMatch(Future::isDone));
            h.upstream.releaseResponses();
            List<Reply> replies = new ArrayList<>();
            for (Future<List<Reply>> result : results) replies.addAll(get(result));
            assertEquals(12, replies.size());
            assertTrue(replies.stream().allMatch(r -> r.forwarded() && r.status() == 200));
            assertEquals(12, h.upstream.hits.get());
            assertEquals(2, h.upstream.maxActive.get(), "no third unfinished owned operation while two permits are in flight");
            List<Long> admissions = h.admissionTimes.stream().sorted().toList();
            assertEquals(12, admissions.size());
            for (int i = 1; i < admissions.size(); i++)
                assertTrue(admissions.get(i) - admissions.get(i - 1) >= 200_000_000L,
                        "5 RPS minimum gap asserted at gate admission, NOT socket/server arrival timing");
            assertEquals(0, h.gate("active"));
            assertEquals(0, h.gate("queued"));
            assertEquals(12, h.evidence("forwarded"));
            assertEquals(12, h.evidence("upstreamResponses"));
            h.upstream.assertHealthy();
        }
    }

    @Test void lostResponseBudgetQuarantinesWithoutReusingPermitAndLateRealReplyRestoresAdmission() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(1_000, 1_000, 2, 1_000))) {
            h.upstream.holdResponses();
            Future<Reply> first = h.callers.submit(() -> h.forward(h.wire("GET", "/first", "application/json", "", List.of())));
            await(() -> h.upstream.hits.get() == 1);
            await(() -> h.gate("stalled") == 1);
            Reply denied = h.forward(h.wire("GET", "/new", "application/json", "", List.of()));
            assertLocalBlock(h, denied, "IN_FLIGHT_TIMEOUT");
            assertEquals(1, h.gate("active"));
            assertEquals(1, h.upstream.active.get());
            assertEquals(1, h.upstream.hits.get());
            assertEquals(1, h.socketOpens.get());
            assertFalse(first.isDone());
            h.upstream.releaseResponses();
            assertTrue(get(first).forwarded());
            assertEquals(0, h.gate("active"));
            assertEquals(0, h.gate("stalled"));
            Reply fresh = h.forward(h.wire("GET", "/fresh", "application/json", "", List.of()));
            assertTrue(fresh.forwarded());
            assertEquals(2, h.upstream.hits.get());
        }
    }

    @Test void realOwnedServer451IsNotMislabeledAsLocallyBlockedResponse() throws Exception {
        try (Harness h = new Harness(Mode.ALLOW, limits(5, 5, 3, 10_000))) {
            h.upstream.responseStatus = 451;
            Reply remote = h.forward(h.wire("GET", "/safe", "application/json", "", List.of()));
            Reply local = h.forward(h.wire("DELETE", "/safe", "application/json", "", List.of()));
            assertEquals(451, remote.status());
            assertEquals(451, local.status());
            assertTrue(remote.forwarded());
            assertFalse(local.forwarded());
            assertEquals("FORWARDED", h.row(remote).disposition());
            assertEquals("BLOCKED", h.row(local).disposition());
            assertEquals(1, h.evidence("upstreamResponses"));
            assertEquals(1, h.evidence("localResponses"));
            assertEquals(1, h.upstream.hits.get());
            assertEquals(List.of("owned-upstream"), values(remote.headers(), "X-Fixture-Source"));
            assertEquals(List.of("blocked"), values(local.headers(), "X-Cairn-Guard"));
            var entries = Json.MAPPER.readTree(h.controller.exportHar(h.controller.traffic())).path("log").path("entries");
            for (var entry : entries) {
                var detail = entry.path("_cairnGuard");
                assertEquals(detail.path("evidenceId").asText().equals(local.evidenceId()) ? "LOCAL_BLOCK" : "RESPONSE_CALLBACK",
                        detail.path("responseSource").asText());
            }
        }
    }

    private static void assertLocalBlock(Harness h, Reply reply, String reason) throws IOException {
        assertEquals(451, reply.status());
        assertFalse(reply.forwarded());
        assertEquals("BLOCKED", h.row(reply).disposition());
        var json = Json.MAPPER.readTree(reply.body());
        assertEquals("cairn-proxy-guard", json.path("source").asText());
        assertEquals("blocked", json.path("outcome").asText());
        assertEquals(reason, json.path("reason").asText());
        assertEquals(reply.evidenceId(), json.path("evidenceId").asText());
        assertFalse(json.path("retryable").asBoolean(true));
        assertFalse(new String(reply.body(), StandardCharsets.UTF_8).contains(SECRET));
    }

    private static Limits limits(int global, int host, int concurrent, long requestTimeout) {
        return new Limits(global, host, Map.of(), concurrent, 100, 10_000, 5_000, requestTimeout);
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static List<String> values(List<Header> headers, String name) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(name)).map(Header::value).toList();
    }
    private static <T> T get(Future<T> result) throws Exception { return result.get(12, TimeUnit.SECONDS); }
    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline >= 0) fail("finite wait expired for owned loopback fixture");
            Thread.sleep(5);
        }
    }

    /** Original synthetic transport values are separate from the immutable controller inspection copy. */
    private record Wire(String id, String method, String target, List<Header> headers, byte[] body, RequestData inspection) {}
    private record Reply(int status, List<Header> headers, byte[] body, String evidenceId, boolean forwarded) {}
    private record Capture(String method, String target, List<Header> headers, byte[] body) {}

    private static final class Harness implements AutoCloseable {
        final OwnedUpstream upstream = new OwnedUpstream();
        final GuardController controller;
        final ExecutorService callers = Executors.newFixedThreadPool(6);
        final AtomicInteger socketOpens = new AtomicInteger();
        final List<Long> admissionTimes = new CopyOnWriteArrayList<>();
        final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        final Map<String, RateGate.Permit> inFlight = new ConcurrentHashMap<>();
        final AtomicInteger ids = new AtomicInteger();

        Harness(Mode mode, Limits limits) throws IOException {
            GuardConfig config = new GuardConfig(2,
                    List.of(new ScopeEntry(true, "127.0.0.1", "http", upstream.port(), "/.*")), List.of(),
                    GuardConfig.defaults().rules(), mode, limits);
            controller = new GuardController(new ProjectAccess() {
                private String document = Json.write(config);
                @Override public Ref current() { return new Ref("owned-loopback-project", "Synthetic loopback project"); }
                @Override public synchronized String load() { return document; }
                @Override public synchronized void save(String json) { document = json; }
            });
        }
        void apply(GuardConfig config) {
            controller.updateConfig(config, "owned-loopback-project", ((Number) controller.status().get("revision")).longValue());
        }
        void authorBlock(Field field, String value) {
            GuardConfig c = controller.config();
            List<Rule> rules = new ArrayList<>(c.rules());
            rules.add(new Rule("operator-" + field.name().toLowerCase(java.util.Locale.ROOT), "Explicit fixture operator rule", true,
                    Mode.BLOCK, Condition.leaf(field, Match.CONTAINS, value)));
            apply(new GuardConfig(2, c.allowScope(), c.blockScope(), rules, c.defaultMode(), c.limits(), c.guardListenerPorts()));
        }
        Wire wire(String method, String target, String contentType, String body, List<Header> extra) {
            String id = Integer.toString(ids.incrementAndGet());
            byte[] data = bytes(body);
            List<Header> headers = new ArrayList<>(List.of(new Header("Host", "127.0.0.1:" + upstream.port()),
                    new Header("Content-Type", contentType), new Header("Content-Length", Integer.toString(data.length)),
                    new Header("Connection", "close"), new Header("X-Fixture-Id", id)));
            headers.addAll(extra);
            List<Header> immutable = List.copyOf(headers);
            RequestData inspection = new RequestData(method, "http://127.0.0.1:" + upstream.port() + target,
                    "127.0.0.1", upstream.port(), false, immutable, data);
            return new Wire(id, method, target, immutable, data, inspection);
        }
        Reply forward(Wire request) throws Exception { return forward(request, () -> {}); }
        Reply forward(Wire request, Runnable beforeCommit) throws Exception {
            Prepared p = controller.prepare(request.inspection());
            Admission admission = controller.authorize(p);
            if (!admission.allowed()) return local(p, admission.reason());
            RateGate.Permit permit = admission.permit();
            inFlight.put(p.evidenceId(), permit);
            admissionTimes.add(permit.admittedAtNanos());
            boolean committed = false;
            try {
                // Independent safety pin: transport ALWAYS connects to our own numeric address/port,
                // never a destination derived from policy input, DNS, proxy env or a redirect.
                if (request.inspection().secure() || !request.inspection().host().equals("127.0.0.1") || request.inspection().port() != upstream.port())
                    throw new IllegalStateException("HARNESS_REQUIRES_OWNED_ENDPOINT");
                beforeCommit.run();
                GuardController.CommitResult result = controller.commitDetailed(p);
                if (!result.allowed()) return local(p, result.reason());
                committed = true;
                Reply reply = exchange(request, p.evidenceId());
                controller.response(p.evidenceId(), reply.status(), reply.headers(), reply.body(), reply.body().length, true, true);
                // Extra conservative test-only rendezvous: both full response read and our owned
                // handler cleanup have completed before this completion owner releases its permit.
                upstream.awaitFinished(request.id());
                permit.close();
                inFlight.remove(p.evidenceId(), permit);
                return reply;
            } finally {
                if (!committed) {
                    permit.close(); // Conclusively no socket dispatch has begun.
                    inFlight.remove(p.evidenceId(), permit);
                }
                // An exception AFTER commit/possible dispatch intentionally does NOT recycle it.
            }
        }
        private Reply local(Prepared p, String reason) {
            byte[] body = bytes(Json.write(Map.of("source", "cairn-proxy-guard", "outcome", "blocked", "reason", reason,
                    "evidenceId", p.evidenceId(), "retryable", false)));
            controller.localResponse(p.evidenceId(), body);
            return new Reply(451, List.of(new Header("Content-Type", "application/json"), new Header("X-Cairn-Guard", "blocked")),
                    body, p.evidenceId(), false);
        }
        private Reply exchange(Wire request, String evidenceId) throws IOException {
            Socket socket = new Socket();
            sockets.add(socket);
            try (socket) {
                socket.connect(upstream.address, 2_000);
                socket.setSoTimeout(4_000);
                socketOpens.incrementAndGet();
                ByteArrayOutputStream head = new ByteArrayOutputStream();
                head.writeBytes((request.method() + " " + request.target() + " HTTP/1.1\r\n").getBytes(StandardCharsets.US_ASCII));
                for (Header header : request.headers())
                    head.writeBytes((header.name() + ": " + header.value() + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                head.writeBytes(bytes("\r\n"));
                socket.getOutputStream().write(head.toByteArray());
                socket.getOutputStream().write(request.body()); // Original fixture body, not masked evidence.
                socket.getOutputStream().flush();
                InputStream in = new BufferedInputStream(socket.getInputStream());
                String[] status = line(in).split(" ", 3);
                if (status.length < 2 || !status[0].equals("HTTP/1.1")) throw new IOException("FIXTURE_RESPONSE_STATUS");
                int code = Integer.parseInt(status[1]);
                List<Header> headers = new ArrayList<>();
                int total = 0;
                for (String line = line(in); !line.isEmpty(); line = line(in)) {
                    total += line.length();
                    int colon = line.indexOf(':');
                    if (headers.size() >= 64 || total > 16_384 || colon <= 0) throw new IOException("FIXTURE_RESPONSE_HEADERS");
                    headers.add(new Header(line.substring(0, colon), line.substring(colon + 1).trim()));
                }
                List<String> lengths = values(headers, "Content-Length");
                if (lengths.size() != 1 || !values(headers, "Transfer-Encoding").isEmpty()) throw new IOException("FIXTURE_RESPONSE_FRAMING");
                int length = Integer.parseInt(lengths.getFirst());
                if (length < 0 || length > 65_536) throw new IOException("FIXTURE_RESPONSE_LENGTH");
                byte[] body = in.readNBytes(length);
                if (body.length != length) throw new EOFException("FIXTURE_RESPONSE_INCOMPLETE");
                return new Reply(code, List.copyOf(headers), body, evidenceId, true);
            } finally { sockets.remove(socket); }
        }
        private static String line(InputStream in) throws IOException {
            ByteArrayOutputStream text = new ByteArrayOutputStream();
            while (text.size() <= 8_192) {
                int next = in.read();
                if (next < 0) throw new EOFException("FIXTURE_RESPONSE_INCOMPLETE");
                if (next == '\r') {
                    if (in.read() != '\n') throw new IOException("FIXTURE_RESPONSE_LINE");
                    return text.toString(StandardCharsets.ISO_8859_1);
                }
                if (next == '\n') throw new IOException("FIXTURE_RESPONSE_LINE");
                text.write(next);
            }
            throw new IOException("FIXTURE_RESPONSE_LINE_LIMIT");
        }
        TrafficEntry row(Reply reply) { return row(reply.evidenceId()); }
        TrafficEntry row(String id) {
            return controller.traffic().stream().filter(e -> e.id().equals(id)).findFirst().orElseThrow();
        }
        long gate(String key) { return metric("gate", key); }
        long evidence(String key) { return metric("evidence", key); }
        private long metric(String section, String key) {
            return ((Number) ((Map<?, ?>) controller.status().get(section)).get(key)).longValue();
        }
        @Override public void close() throws Exception {
            controller.close();
            upstream.releaseResponses();
            try {
                for (Socket socket : sockets) {
                    try { socket.close(); }
                    catch (IOException ignored) { /* Server shutdown below also closes its side. */ }
                }
                upstream.close(); // Stop sockets/handlers before claiming synthetic teardown completion.
            } finally {
                callers.shutdownNow();
                assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS), "forwarding harness workers terminated");
                if (upstream.handlers.isTerminated() && upstream.active.get() == 0) {
                    inFlight.values().forEach(RateGate.Permit::close); // Only after all owned transport quiesces.
                    inFlight.clear();
                    assertEquals(0, gate("active"));
                }
            }
        }
    }

    private static final class OwnedUpstream implements AutoCloseable {
        final ServerSocket server;
        final ExecutorService acceptor = Executors.newSingleThreadExecutor();
        final Set<Socket> connections = ConcurrentHashMap.newKeySet();
        final ExecutorService handlers = new java.util.concurrent.ThreadPoolExecutor(8, 8, 0, TimeUnit.SECONDS,
                new java.util.concurrent.ArrayBlockingQueue<>(16));
        final InetSocketAddress address;
        final AtomicInteger hits = new AtomicInteger();
        final AtomicInteger active = new AtomicInteger();
        final AtomicInteger maxActive = new AtomicInteger();
        final List<Capture> captures = new CopyOnWriteArrayList<>();
        final Map<String, CountDownLatch> finished = new ConcurrentHashMap<>();
        final AtomicReference<Throwable> error = new AtomicReference<>();
        volatile CountDownLatch responses = new CountDownLatch(0);
        volatile int responseStatus = 200;

        OwnedUpstream() throws IOException {
            // Byte-address construction avoids DNS; bind only 127.0.0.1, ephemeral port, not wildcard.
            server = new ServerSocket();
            server.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 16);
            address = (InetSocketAddress) server.getLocalSocketAddress();
            acceptor.submit(() -> {
                while (!server.isClosed()) {
                    try {
                        Socket socket = server.accept(); socket.setSoTimeout(12_000);
                        connections.add(socket);
                        try { handlers.submit(() -> handle(socket)); }
                        catch (java.util.concurrent.RejectedExecutionException full) { connections.remove(socket); socket.close(); }
                    } catch (IOException failure) { if (!server.isClosed()) error.compareAndSet(null, failure); }
                }
            });
        }
        int port() { return address.getPort(); }
        void holdResponses() { responses = new CountDownLatch(1); }
        void releaseResponses() { responses.countDown(); }
        void awaitFinished(String id) throws InterruptedException {
            CountDownLatch done = finished.get(id);
            assertNotNull(done, "owned handler registered completion");
            assertTrue(done.await(5, TimeUnit.SECONDS), "owned handler completed after full response");
        }
        void handle(Socket socket) {
            CountDownLatch done = new CountDownLatch(1);
            int current = active.incrementAndGet(); maxActive.accumulateAndGet(current, Math::max);
            try (socket) {
                InputStream in = new BufferedInputStream(socket.getInputStream());
                String[] request = Harness.line(in).split(" ", 3);
                if (request.length != 3 || !request[2].equals("HTTP/1.1")) throw new IOException("FIXTURE_REQUEST_LINE");
                List<Header> headers = new ArrayList<>(); int total = 0;
                for (String line = Harness.line(in); !line.isEmpty(); line = Harness.line(in)) {
                    int colon = line.indexOf(':'); total += line.length();
                    if (colon <= 0 || headers.size() >= 256 || total > 65_536) throw new IOException("FIXTURE_REQUEST_HEADERS");
                    headers.add(new Header(line.substring(0, colon), line.substring(colon + 1).trim()));
                }
                List<String> ids = values(headers, "X-Fixture-Id"), lengths = values(headers, "Content-Length");
                if (ids.size() != 1 || lengths.size() != 1 || !values(headers, "Transfer-Encoding").isEmpty()) throw new IOException("FIXTURE_REQUEST_FRAMING");
                finished.put(ids.getFirst(), done);
                int length = Integer.parseInt(lengths.getFirst());
                if (length < 0 || length > RequestData.MAX_INSPECT_BYTES) throw new IOException("FIXTURE_REQUEST_LENGTH");
                byte[] body = in.readNBytes(length);
                if (body.length != length) throw new IOException("FIXTURE_REQUEST_INCOMPLETE");
                // Raw bounded origin-target parser deliberately accepts invalid percent bytes. A
                // generic URI/HttpServer parser here would reject before observing the wire target.
                captures.add(new Capture(request[0], request[1], List.copyOf(headers), body)); hits.incrementAndGet();
                if (!responses.await(10, TimeUnit.SECONDS)) throw new IOException("FIXTURE_RESPONSE_RELEASE_TIMEOUT");
                String response = "HTTP/1.1 " + responseStatus + " Fixture\r\nContent-Type: application/json\r\nSet-Cookie: " + RESPONSE_COOKIE
                        + "\r\nX-Fixture-Source: owned-upstream\r\nContent-Length: " + RESPONSE_BODY.length + "\r\nConnection: close\r\n\r\n";
                socket.getOutputStream().write(bytes(response)); socket.getOutputStream().write(RESPONSE_BODY); socket.getOutputStream().flush();
            } catch (Exception failure) {
                error.compareAndSet(null, failure);
                if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
            } finally { connections.remove(socket); active.decrementAndGet(); done.countDown(); }
        }
        void assertHealthy() { assertNull(error.get(), "owned upstream handler had no failure"); }
        @Override public void close() throws IOException, InterruptedException {
            releaseResponses(); server.close();
            for (Socket socket : connections) socket.close();
            acceptor.shutdownNow(); handlers.shutdownNow();
            assertTrue(acceptor.awaitTermination(5, TimeUnit.SECONDS), "owned acceptor terminated");
            assertTrue(handlers.awaitTermination(5, TimeUnit.SECONDS), "owned raw fixture workers terminated");
            assertEquals(0, active.get());
        }
    }
}
