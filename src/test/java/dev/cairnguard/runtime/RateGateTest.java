package dev.cairnguard.runtime;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.HashMap;
import java.util.ArrayList;
import dev.cairnguard.model.GuardConfig;

import dev.cairnguard.model.GuardConfig.Limits;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

/** Authored pacing only. No synthetic native permits or completion claims. */
@Timeout(30)
@SuppressWarnings("try") // Explicit shutdown wakes pacing waiters before executor join.
class RateGateTest {
    private final AtomicLong clock = new AtomicLong(-9_000_000_000L);
    private static Limits limits(int global, int host, Map<String,Integer> overrides, int queued, long timeout) {
        return new Limits(global, host, overrides, 1, queued, timeout, 1000, 1);
    }
    private RateGate gate(Limits limits) { return new RateGate(limits, clock::get, 4); }
    private static long metric(RateGate gate, String key) { return ((Number)gate.snapshot().get(key)).longValue(); }
    private void advance(long millis) { clock.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)); }
    private static void rejected(RateGate gate, String host, String reason) {
        assertEquals(reason, assertThrows(RateGate.Rejected.class, () -> gate.acquire(host, () -> true)).reason());
    }
    private static void await(BooleanSupplier ready) throws Exception {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!ready.getAsBoolean()) { if (System.nanoTime() > end) fail("finite pacing wait"); Thread.sleep(2); }
    }
    @Test void zeroRatesHaveNoQueueDebtNativeLifetimeOrOldConcurrencyCliff() throws Exception {
        try (var gate = gate(limits(0,0,Map.of(),0,1))) {
            for (int i=0;i<250;i++) { gate.acquire(i%2==0?"one.test":"two.test",()->true); advance(1001); }
            assertEquals(250,metric(gate,"admitted")); assertEquals(0,metric(gate,"queued"));
            assertFalse(gate.snapshot().containsKey("stalled")); assertFalse(gate.snapshot().containsKey("active"));
        }
    }
    @Test void globalAndCanonicalHostOverrideIntervalsHaveNoIdleBurstCredit() throws Exception {
        try (var gate = gate(limits(1000,1000,Map.of("ExAmPlE.TeSt.",10),0,1000))) {
            long first=gate.acquire("example.test",()->true);
            rejected(gate,"other.test","QUEUE_FULL"); advance(1);
            gate.acquire("other.test",()->true); advance(98);
            rejected(gate,"EXAMPLE.TEST.","QUEUE_FULL"); advance(1);
            assertEquals(100_000_000,gate.acquire("example.test",()->true)-first);
            advance(10_000); gate.acquire("example.test",()->true);
            rejected(gate,"example.test","QUEUE_FULL");
        }
    }
    @Test void fractionalIntervalsRoundUpAndNegativeNanoOriginWorks() throws Exception {
        try (var gate = gate(limits(3,0,Map.of(),0,1000))) {
            long first=gate.acquire("one.test",()->true); clock.addAndGet(333_333_333);
            rejected(gate,"two.test","QUEUE_FULL"); clock.incrementAndGet();
            assertEquals(333_333_334,gate.acquire("two.test",()->true)-first);
        }
    }
    @Test void disablingRatesImmediatelyDropsOnlyTheirDebtAndPreservesPositiveOverrides() throws Exception {
        var on=limits(1,1,Map.of("slow.test",1),0,1000);
        try(var gate=gate(on)) {
            gate.acquire("slow.test",()->true);
            gate.update(limits(0,0,Map.of("slow.test",1),0,1000));
            gate.acquire("fresh.test",()->true); rejected(gate,"slow.test","QUEUE_FULL");
            gate.update(limits(0,0,Map.of("slow.test",0),0,1000));
            gate.acquire("slow.test",()->true); gate.acquire("slow.test",()->true);
            gate.update(limits(1,0,Map.of("slow.test",0),0,1000));
            rejected(gate,"fresh.test","QUEUE_FULL"); advance(1000); gate.acquire("fresh.test",()->true);
        }
    }
    @Test void slowHostDoesNotHoldAnotherHostAndHostHeadsRemainFifo() throws Exception {
        var rates=limits(0,0,Map.of("slow.test",1),8,5000);
        try(var gate=gate(rates);var workers=Executors.newVirtualThreadPerTaskExecutor()) {
            gate.acquire("slow.test",()->true);
            var first=workers.submit(()->gate.acquire("slow.test",()->true)); await(()->metric(gate,"queued")==1);
            var second=workers.submit(()->gate.acquire("slow.test",()->true)); await(()->metric(gate,"queued")==2);
            gate.acquire("fast.test",()->true); assertFalse(first.isDone());
            advance(1000); gate.update(rates); first.get(5,TimeUnit.SECONDS); assertFalse(second.isDone());
            advance(1000); gate.update(rates); second.get(5,TimeUnit.SECONDS);
        }
    }
    @Test void queueCapacityTimeoutCancellationAndShutdownRemainExplicitBoundaries() throws Exception {
        var rates=limits(1,0,Map.of(),1,50);
        try(var gate=gate(rates);var workers=Executors.newVirtualThreadPerTaskExecutor()) {
            gate.acquire("one.test",()->true);
            var queued=workers.submit(()->assertThrows(RateGate.Rejected.class,()->gate.acquire("two.test",()->true)).reason());
            await(()->metric(gate,"queued")==1); rejected(gate,"three.test","QUEUE_FULL");
            advance(50); gate.update(rates); assertEquals("QUEUE_TIMEOUT",queued.get(5,TimeUnit.SECONDS));
            AtomicBoolean current=new AtomicBoolean(true);
            var cancelled=workers.submit(()->assertThrows(RateGate.Rejected.class,()->gate.acquire("two.test",current::get)).reason());
            await(()->metric(gate,"queued")==1); current.set(false); gate.update(rates);
            assertEquals("POLICY_CHANGED",cancelled.get(5,TimeUnit.SECONDS));
            gate.close(); rejected(gate,"one.test","SHUTDOWN");
        }
    }
    @Test void concurrentWorkersShareAuthoredGlobalCadenceWithoutNativeCompletion() throws Exception {
        try(var gate=new RateGate(limits(50,0,Map.of(),20,5000));var workers=Executors.newVirtualThreadPerTaskExecutor()) {
            var results=List.of("one.test","two.test","three.test","four.test","five.test").stream()
                    .map(host->workers.submit(()->gate.acquire(host,()->true))).toList();
            var times=new java.util.ArrayList<Long>(); for(var r:results) times.add(r.get(5,TimeUnit.SECONDS));
            times.sort(Long::compare); for(int i=1;i<times.size();i++) assertTrue(times.get(i)-times.get(i-1)>=20_000_000);
        }
    }
    @Test void validationRejectsNegativeAndOverflowRatesButAcceptsZeroHostOverride() {
        assertDoesNotThrow(()->gate(limits(0,0,Map.of("owned.test",0),0,1000)).close());
        for(int n:List.of(-1,1001,Integer.MAX_VALUE)) {
            assertThrows(IllegalArgumentException.class,()->gate(limits(n,0,Map.of(),0,1000)));
            assertThrows(IllegalArgumentException.class,()->gate(limits(0,n,Map.of(),0,1000)));
            assertThrows(IllegalArgumentException.class,()->gate(limits(0,0,Map.of("owned.test",n),0,1000)));
        }
    }
    @Test void immediateAdmissionWithZeroQueueAndNoIdleBurstCredit() throws Exception {
        FakeTime time = new FakeTime(-9_000_000_000L);
        Limits limits = limits(1_000, 10, 1, 0, 1_000, 10_000);
        try (RateGate gate = new RateGate(limits, time, 4)) {
            long first = gate.acquire("EXAMPLE.TEST.", () -> true);
            assertEquals(0, number(gate, "queued"));
            rejected(gate, "other.test", "QUEUE_FULL");

            time.advanceMillis(99);
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(1);
            long second = gate.acquire("example.test", () -> true);
            assertEquals(100_000_000, second - first);

            time.advanceMillis(10_000);
            gate.acquire("example.test", () -> true);
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(100);
            gate.acquire("example.test", () -> true);
            assertEquals(4, number(gate, "admitted"));
            assertEquals(1, number(gate, "hosts"));
        }
    }

    @Test void fiveSimultaneousWorkersShareStrictGlobalSpacingAcrossHosts() throws Exception {
        Limits limits = limits(40, 1_000, 3, 100, 5_000, 10_000);
        try (RateGate gate = new RateGate(limits)) {
            List<Sample> samples = exerciseWorkers(gate,
                    List.of("one.test", "two.test", "three.test", "four.test", "five.test"), 3);
            assertSpacing(samples, 25_000_000);
            assertEquals(15, number(gate, "admitted"));
            assertEquals(0, number(gate, "queued"));
        }
    }

    @Test void fiveSimultaneousWorkersShareCanonicalPerHostOverride() throws Exception {
        Limits limits = new Limits(1_000, 1_000, Map.of("ExAmPlE.TeSt.", 25), 5, 100, 5_000, 5_000, 10_000);
        try (RateGate gate = new RateGate(limits)) {
            List<Sample> samples = exerciseWorkers(gate,
                    List.of("example.test", "EXAMPLE.TEST", "Example.Test.", "example.test.", "ExAmPlE.tEsT"), 2);
            assertSpacing(samples, 40_000_000);
            assertEquals(10, number(gate, "admitted"));
            assertEquals(1, number(gate, "hosts"));
        }
    }

    @Test void fiveWorkersShareBothGlobalAndTwoHostCadences() throws Exception {
        Limits limits = limits(50, 10, 5, 100, 5_000, 10_000);
        try (RateGate gate = new RateGate(limits)) {
            List<Sample> samples = exerciseWorkers(gate,
                    List.of("one.test", "two.test", "one.test", "two.test", "one.test"), 2);
            assertSpacing(samples, 20_000_000);
            for (String host : List.of("one.test", "two.test"))
                assertSpacing(samples.stream().filter(sample -> sample.host().equals(host)).toList(), 100_000_000);
        }
    }

    @Test void fractionalIntervalsRoundUpRatherThanOverrunTheRate() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(3, 1_000, 1, 0, 1_000, 10_000), time, 4)) {
            long first = gate.acquire("one.test", () -> true);

            time.advanceNanos(333_333_333);
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceNanos(1);
            long next = gate.acquire("two.test", () -> true);
            assertEquals(333_333_334, next - first);

        }
    }

    @Test void slowAHeadDoesNotBlockFastBAndReadyASoonGetsItsRoundRobinTurn() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = new Limits(1_000, 1_000, Map.of("slow.test", 1), 3, 10, 5_000, 1_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 16)) {
            try {
                gate.acquire("slow.test", () -> true);
                Future<Long> slow = admission(workers, gate, "slow.test");
                waitFor(() -> number(gate, "queued") == 1);
                List<Future<Long>> fast = new ArrayList<>();
                for (int i = 0; i < 3; i++) {
                    fast.add(admission(workers, gate, "fast.test"));
                    int count = i + 2;
                    waitFor(() -> number(gate, "queued") == count);
                }
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(1_000_000L, get(fast.get(0)));
                assertFalse(slow.isDone(), "slow host still owes its own cadence");
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(2_000_000L, get(fast.get(1)));
                // Both heads become eligible after this idle jump. Slow retained its RR turn,
                // despite fast's backlog; neither host receives catch-up burst credit.
                time.advanceMillis(998);
                gate.update(limits);
                assertEquals(1_000_000_000L, get(slow));
                assertFalse(fast.get(2).isDone());
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(1_001_000_000L, get(fast.get(2)));
                assertEquals(0, number(gate, "queued"));
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void eligibleHeadsRoundRobinWithoutStarvingAnyHostAndPreserveEachHostFifo() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 12, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            long pin = gate.acquire("pin.test", () -> true);
            try {
                Map<String, Future<Long>> waiting = new HashMap<>();
                for (String host : List.of("a", "b", "c")) {
                    for (int i = 0; i < 3; i++) {
                        waiting.put(host + i, admission(workers, gate, host + ".test"));
                        int count = waiting.size();
                        waitFor(() -> number(gate, "queued") == count);
                    }
                }
                time.advanceMillis(1);
                gate.update(limits);
                int slot = 1;
                for (String label : List.of("a0", "b0", "c0", "a1", "b1", "c1", "a2", "b2", "c2")) {
                    assertEquals(slot * 1_000_000L, get(waiting.get(label)), label);
                    assertEquals(slot + 1, number(gate, "admitted"));
                    time.advanceMillis(1);
                    gate.update(limits);
                    slot++;
                }
                assertEquals(0, number(gate, "queued"));
            } finally { gate.update(limits); gate.close(); workers.close(); }
        }
    }

    @Test void lowerLiveQueueBoundRejectsNewestAndPreservesOldestWaiter() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 3, 5_000, 10_000), time, 8)) {
            long permit = gate.acquire("one.test", () -> true);
            try {
                List<Future<String>> waiting = new ArrayList<>();
                for (int i = 0; i < 3; i++) {
                    int index = i;
                    waiting.add(workers.submit(() -> outcome(gate, "wait-" + index + ".test", () -> true)));
                    int count = i + 1;
                    waitFor(() -> number(gate, "queued") == count);
                }
                gate.update(limits(1_000, 1_000, 1, 1, 5_000, 10_000));
                assertEquals("QUEUE_FULL", get(waiting.get(1)));
                assertEquals("QUEUE_FULL", get(waiting.get(2)));
                assertFalse(waiting.getFirst().isDone());
                assertEquals(1, number(gate, "queued"));
                gate.update(limits(1_000, 1_000, 1, 0, 5_000, 10_000));
                assertEquals("QUEUE_FULL", get(waiting.getFirst()));
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void rateUpdatesPreserveCommittedDebtAndApplySlowerNewSpacing() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(10, 1_000, 1, 0, 1_000, 10_000), time, 8)) {
            gate.acquire("one.test", () -> true);
            time.advanceMillis(20);
            gate.update(limits(1_000, 1_000, 1, 0, 1_000, 10_000));
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceMillis(80);
            gate.acquire("two.test", () -> true);
            gate.update(limits(2, 1_000, 1, 0, 1_000, 10_000));
            time.advanceNanos(499_999_999);
            rejected(gate, "three.test", "QUEUE_FULL");
            time.advanceNanos(1);
            gate.acquire("three.test", () -> true);
        }
    }

    @Test void liveCanonicalOverrideUpdateExtendsHostDebt() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000), time, 8)) {
            gate.acquire("EXAMPLE.TEST.", () -> true);
            time.advanceMillis(10);
            gate.update(new Limits(1_000, 1_000, Map.of("Example.Test", 2), 1, 0, 1_000, 1_000, 10_000));
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(490);
            gate.acquire("example.test.", () -> true);
            assertEquals(1, number(gate, "hosts"));
        }
    }

    @Test void monotonicQueueDeadlineWorksAtExactBoundaryAndAcrossNanoTimeWrap() throws Exception {
        FakeTime time = new FakeTime(Long.MAX_VALUE - 50_000_000);
        Limits limits = limits(1, 1_000, 1, 10, 100, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 4)) {
            long first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(99);
                gate.update(limits);
                assertFalse(waiting.isDone());
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals("QUEUE_TIMEOUT", get(waiting));
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void lowerLiveQueueTimeoutUsesOriginalEnqueueTime() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1, 1_000, 1, 10, 5_000, 10_000), time, 4)) {
            long first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(60);
                gate.update(limits(1, 1_000, 1, 10, 50, 10_000));
                assertEquals("QUEUE_TIMEOUT", get(waiting));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void raisingQueueTimeoutCannotReviveAnExpiredButUnscheduledWaiter() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1, 1_000, 1, 10, 100, 10_000), time, 4)) {
            long first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(100);
                gate.update(limits(1, 1_000, 2, 10, 5_000, 10_000));
                assertEquals("QUEUE_TIMEOUT", get(waiting));
                assertEquals(1, number(gate, "admitted"));
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void staleAndThrowingPredicatesFailClosedWithoutLeakingMessages() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1, 1_000, 1, 10, 5_000, 10_000))) {
            assertEquals("POLICY_CHANGED", assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> false)).reason());
            RateGate.Rejected exception = assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> { throw new IllegalStateException("synthetic-secret"); }));
            assertEquals("POLICY_CHANGED", exception.getMessage());
            assertNull(exception.getCause());
            long first = gate.acquire("one.test", () -> true);
            AtomicBoolean current = new AtomicBoolean(true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", current::get));
                waitFor(() -> number(gate, "queued") == 1);
                current.set(false); // no external signal; bounded predicate poll still wakes
                assertEquals("POLICY_CHANGED", get(waiting));
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void staleAtFinalAdjacentCheckNeverGetsAdmission() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000))) {
            RateGate.Rejected exception = assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> checks.incrementAndGet() == 1));
            assertEquals("POLICY_CHANGED", exception.reason());
            assertEquals(0, number(gate, "admitted"));
        }
    }

    @Test void interruptionRemovesOnlyThePacingWaiter() throws Exception {
        AtomicReference<Throwable> result = new AtomicReference<>();
        try (RateGate gate = new RateGate(limits(1, 1_000, 1, 10, 5_000, 10_000))) {
            long permit = gate.acquire("one.test", () -> true);
            Thread waiting = Thread.ofVirtual().start(() -> {
                try { gate.acquire("two.test", () -> true); }
                catch (Throwable e) { result.set(e); }
            });
            try {
                waitFor(() -> number(gate, "queued") == 1);
                waiting.interrupt();
                waiting.join(2_000);
                assertFalse(waiting.isAlive());
                assertInstanceOf(InterruptedException.class, result.get());
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); waiting.interrupt(); waiting.join(2_000); }
        }
    }

    @Test void closeRejectsAndWakesAllPacingWaiters() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1, 1_000, 1, 10, 5_000, 10_000))) {
            long permit = gate.acquire("one.test", () -> true);
            try {
                List<Future<String>> waiting = new ArrayList<>();
                for (int i = 0; i < 5; i++) {
                    int index = i;
                    waiting.add(workers.submit(() -> outcome(gate, "wait-" + index + ".test", () -> true)));
                }
                waitFor(() -> number(gate, "queued") == 5);
                gate.close();
                gate.close();
                for (Future<String> result : waiting) assertEquals("SHUTDOWN", get(result));
                assertEquals(0, number(gate, "queued"));
                assertEquals(Boolean.TRUE, gate.snapshot().get("closed"));
                rejected(gate, "new.test", "SHUTDOWN");
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void hostCapacityPreservesRateDebtAndEvictsOnlyWhenItExpires() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1, 2, 0, 1_000, 10_000), time, 2)) {
            gate.acquire("one.test", () -> true);
            time.advanceMillis(1);
            gate.acquire("two.test", () -> true);
            time.advanceMillis(1);
            rejected(gate, "three.test", "HOST_CAPACITY");
            assertEquals(2, number(gate, "hosts"));
            time.advanceMillis(998);
            gate.acquire("three.test", () -> true);
            assertEquals(2, number(gate, "hosts"));
            rejected(gate, "one.test", "HOST_CAPACITY"); // two.test still owes 1ms; three owes 1s
        }
    }

    @Test void productionHostMapIsBoundedAt4096IncludingQueuedKeys() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10_000, 600_000, 600_000), time, 4_096)) {
            long first = gate.acquire("active.test", () -> true);
            try {
                List<Future<String>> results = new ArrayList<>();
                for (int i = 0; i < 4_095; i++) {
                    int index = i;
                    results.add(workers.submit(() -> outcome(gate, "queued-" + index + ".test", () -> true)));
                }
                waitFor(() -> number(gate, "queued") == 4_095);
                assertEquals(4_096, number(gate, "hosts"));
                assertEquals(64, metrics(gate).size());
                assertEquals(Boolean.TRUE, gate.snapshot().get("hostMetricsTruncated"));
                assertEquals(4_032, number(gate, "hostMetricsOmitted"));
                assertEquals("queued-0.test", metrics(gate).getFirst().get("host"));
                rejected(gate, "overflow.test", "HOST_CAPACITY");
                assertEquals(4_096, number(gate, "hosts"));
                gate.close();
                for (Future<String> result : results) assertEquals("SHUTDOWN", get(result));
                assertEquals(0, number(gate, "queued"));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void idnIpv6CaseAndTrailingDotAliasesUsePolicyCanonicalizationForOverrides() throws Exception {
        for (List<String> aliases : List.of(
                List.of("BÜCHER.example.", "xn--bcher-kva.example", "bücher.EXAMPLE"),
                List.of("[2001:DB8::1]", "2001:db8:0:0:0:0:0:1", "[2001:0db8:0000:0000:0000:0000:0000:0001]"))) {
            FakeTime time = new FakeTime(0);
            Limits limits = new Limits(1_000, 1_000, Map.of(aliases.getFirst(), 2), 1, 0, 1_000, 1_000, 10_000);
            try (RateGate gate = new RateGate(limits, time, 4)) {
                gate.acquire(aliases.get(0), () -> true);
                time.advanceMillis(499);
                rejected(gate, aliases.get(1), "QUEUE_FULL");
                time.advanceMillis(1);
                gate.acquire(aliases.get(2), () -> true);
                assertEquals(1, number(gate, "hosts"));
            }
        }
    }

    @Test void invalidHostsFailClosedCategoricallyWithoutRetainingInput() throws Exception {
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000))) {
            for (String value : List.of("https://user:synthetic-secret@host.test/", "127.1", "01.2.3.4", "*.test", "", "bad\nhost")) {
                RateGate.Rejected exception = assertThrows(RateGate.Rejected.class, () -> gate.acquire(value, () -> true));
                assertEquals("HOST_CAPACITY", exception.reason());
                assertEquals("HOST_CAPACITY", exception.getMessage());
                assertNull(exception.getCause());
            }
            assertEquals(0, number(gate, "hosts"));
            assertEquals(0, number(gate, "admitted"));
        }
    }

    @Test void validationUsesPolicyHardBoundsAndUpdatesAreAtomic() {
        List<Limits> invalid = new ArrayList<>();
        invalid.add(null);
        for (int value : List.of(-1, 1_001)) {
            invalid.add(limits(value, 5, 5, 100, 1_000, 1_000));
            invalid.add(limits(5, value, 5, 100, 1_000, 1_000));
            invalid.add(new Limits(5, 5, Map.of("example.test", value), 5, 100, 1_000, 1_000, 1_000));
        }
        for (int value : List.of(0, 101)) invalid.add(limits(5, 5, value, 100, 1_000, 1_000));
        for (int value : List.of(-1, 10_001)) invalid.add(limits(5, 5, 5, value, 1_000, 1_000));
        for (long value : List.of(0L, 600_001L)) {
            invalid.add(limits(5, 5, 5, 100, value, 1_000));
            invalid.add(limits(5, 5, 5, 100, 1_000, value));
            invalid.add(new Limits(5, 5, Map.of(), 5, 100, 1_000, value, 1_000));
        }
        invalid.add(new Limits(5, 5, Map.of("example.test", 5, "EXAMPLE.TEST.", 6), 5, 100, 1_000, 1_000, 1_000));
        invalid.add(new Limits(5, 5, Map.of("[::1]", 5, "0:0:0:0:0:0:0:1", 6), 5, 100, 1_000, 1_000, 1_000));
        invalid.add(new Limits(5, 5, Map.of("*.example.test", 5), 5, 100, 1_000, 1_000, 1_000));
        invalid.add(new Limits(5, 5, Map.of(), 5, 100, 1_000, 1_000, 1_000,
                -1, 600_000, null, null, 0, false, List.of(), List.of()));
        Map<String, Integer> excess = new HashMap<>();
        for (int i = 0; i < 257; i++) excess.put("host-" + i + ".test", 5);
        invalid.add(new Limits(5, 5, excess, 5, 100, 1_000, 1_000, 1_000));
        try (RateGate gate = new RateGate(limits(5, 5, 5, 100, 1_000, 1_000))) {
            Map<String, Object> before = gate.snapshot();
            for (Limits value : invalid) {
                assertEquals("INVALID_LIMITS", assertThrows(IllegalArgumentException.class,
                        () -> new RateGate(value)).getMessage());
                assertEquals("INVALID_LIMITS", assertThrows(IllegalArgumentException.class,
                        () -> gate.update(value)).getMessage());
                assertEquals(before, gate.snapshot());
            }
        }
    }

    @Test void inclusiveLimitEndpointsAreAcceptedAndSnapshotsRetainNumericCompatibilityAndBoundedRows() {
        for (Limits limits : List.of(limits(1, 1, 1, 0, 1, 1),
                new Limits(1_000, 1_000, Map.of(), 100, 10_000, 600_000, 600_000, 600_000),
                GuardConfig.defaults().limits())) {
            try (RateGate gate = new RateGate(limits)) {
                assertEquals(limits.globalRps(), number(gate, "globalRps"));
                assertEquals(limits.perHostRps(), number(gate, "perHostRps"));
                assertInstanceOf(Number.class, gate.snapshot().get("hosts"));
                assertEquals(List.of(), metrics(gate));
                assertEquals(Boolean.FALSE, gate.snapshot().get("hostMetricsTruncated"));
                assertEquals(0, number(gate, "hostMetricsOmitted"));
                assertThrows(UnsupportedOperationException.class, () -> gate.snapshot().put("host", "not-allowed"));
            }
        }
    }

    @Test void positiveQueueBoundCountsOnlyWaitingCallsAndOverflowDoesNotLoseOldest() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 1, 5_000, 10_000), time, 4)) {
            long first = gate.acquire("one.test", () -> true);
            try {
                Future<String> oldest = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                rejected(gate, "three.test", "QUEUE_FULL");
                assertEquals(1, number(gate, "queued"));
                assertEquals(2, number(gate, "hosts")); // failed attempt creates no retained host
                time.advanceMillis(1);
                gate.update(limits(1_000,1_000,1,1,5000,10000));
                assertEquals("ADMITTED", get(oldest));
            } finally { gate.update(limits(1_000,1_000,1,1,5000,10000)); gate.close(); workers.close(); }
        }
    }

    @Test void rateDebtUsesMonotonicTimeAcrossWrapWithoutRequestAging() throws Exception {
        FakeTime time = new FakeTime(Long.MAX_VALUE - 500_000);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 0, 1_000, 10), time, 4)) {
            long first = gate.acquire("one.test", () -> true);
            time.advanceNanos(999_999);
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceNanos(1);
            long second = gate.acquire("two.test", () -> true);
            assertEquals(1_000_000, second - first);
            time.advanceMillis(9);

        }
    }

    @Test void cancellingHostHeadPreservesItsNextWaiterAndOtherHostsRoundRobinTurn() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 10, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            long pin = gate.acquire("pin.test", () -> true);
            AtomicBoolean current = new AtomicBoolean(true);
            try {
                Future<String> cancelled = workers.submit(() -> outcome(gate, "a.test", current::get));
                waitFor(() -> number(gate, "queued") == 1);
                Future<Long> nextA = admission(workers, gate, "a.test");
                waitFor(() -> number(gate, "queued") == 2);
                Future<Long> b = admission(workers, gate, "b.test");
                waitFor(() -> number(gate, "queued") == 3);
                current.set(false);
                gate.update(limits);
                assertEquals("POLICY_CHANGED", get(cancelled));
                assertEquals(2, number(gate, "queued"));
                assertEquals(1, hostMetric(gate, "a.test").get("queued"));
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(1_000_000L, get(nextA));
                assertFalse(b.isDone());
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(2_000_000L, get(b));
                assertEquals(0, number(gate, "queued"));
            } finally { gate.update(limits); gate.close(); workers.close(); }
        }
    }

    @Test void soleHostMayFillQueueButCompetitorReclaimsHalfAndCancellationRelaxesBound() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 6, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            long pin = gate.acquire("pin.test", () -> true);
            AtomicBoolean bCurrent = new AtomicBoolean(true);
            try {
                List<Future<String>> a = new ArrayList<>();
                for (int i = 0; i < 6; i++) {
                    a.add(workers.submit(() -> outcome(gate, "a.test", () -> true)));
                    int count = i + 1;
                    waitFor(() -> number(gate, "queued") == count);
                }
                rejected(gate, "a.test", "QUEUE_FULL");
                List<Future<String>> b = new ArrayList<>();
                for (int i = 0; i < 3; i++) {
                    b.add(workers.submit(() -> outcome(gate, "b.test", bCurrent::get)));
                    int count = i + 4;
                    waitFor(() -> number(gate, "queued") == count);
                }
                assertEquals(3, hostMetric(gate, "a.test").get("queued"));
                assertEquals(3, hostMetric(gate, "b.test").get("queued"));
                for (int i = 0; i < 3; i++) assertFalse(a.get(i).isDone(), "oldest host waiters survive");
                for (int i = 3; i < 6; i++) assertEquals("QUEUE_FULL", get(a.get(i)));
                rejected(gate, "b.test", "QUEUE_FULL");
                bCurrent.set(false);
                gate.update(limits);
                for (Future<String> result : b) assertEquals("POLICY_CHANGED", get(result));
                for (int i = 0; i < 3; i++) {
                    a.add(workers.submit(() -> outcome(gate, "a.test", () -> true)));
                    int count = i + 4;
                    waitFor(() -> number(gate, "queued") == count);
                }
                assertEquals(6, hostMetric(gate, "a.test").get("queued"));
                gate.close();
                for (int i : List.of(0, 1, 2, 6, 7, 8)) assertEquals("SHUTDOWN", get(a.get(i)));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void oddCompetingQueueBoundRoundsUpAndLiveShrinkDropsOnlyNewestHostExcess() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000), time, 8)) {
            long pin = gate.acquire("pin.test", () -> true);
            try {
                List<Future<String>> a = new ArrayList<>();
                for (int i = 0; i < 4; i++) {
                    a.add(workers.submit(() -> outcome(gate, "a.test", () -> true)));
                    int count = i + 1;
                    waitFor(() -> number(gate, "queued") == count);
                }
                Future<String> b = workers.submit(() -> outcome(gate, "b.test", () -> true));
                waitFor(() -> number(gate, "queued") == 5);
                gate.update(limits(1_000, 1_000, 1, 5, 5_000, 10_000));
                assertEquals("QUEUE_FULL", get(a.get(3)));
                assertEquals(3, hostMetric(gate, "a.test").get("queued")); // ceil(5/2)
                assertEquals(1, hostMetric(gate, "b.test").get("queued"));
                rejected(gate, "a.test", "QUEUE_FULL");
                assertEquals(4, number(gate, "queued"));
                gate.close();
                for (int i = 0; i < 3; i++) assertEquals("SHUTDOWN", get(a.get(i)));
                assertEquals("SHUTDOWN", get(b));
            } finally {  gate.close(); workers.close(); }
        }
    }

    @Test void liveHostRateIncreaseRetainsOldDebtWhileOtherHostHeadsRemainEligible() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits slow = new Limits(1_000, 1_000, Map.of("a.test", 1), 2, 10, 5_000, 1_000, 10_000);
        Limits faster = limits(1_000, 1_000, 2, 10, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(slow, time, 8)) {
            try {
                gate.acquire("a.test", () -> true);
                Future<Long> a = admission(workers, gate, "a.test");
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(10);
                gate.update(faster);
                assertEquals(1_000, hostMetric(gate, "a.test").get("rps"));
                assertFalse(a.isDone(), "old one-second host debt cannot be erased");
                gate.acquire("b.test", () -> true); // immediate eligible host skips A
                time.advanceMillis(989);
                gate.update(faster);
                assertFalse(a.isDone());
                time.advanceMillis(1);
                gate.update(faster);
                assertEquals(1_000_000_000L, get(a));
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void hostMetricsAreCanonicalImmutableAndReflectPacingRateAndWait() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = new Limits(1_000, 1_000, Map.of("EXAMPLE.TEST.", 25), 2, 10, 5_000, 1_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            long first = gate.acquire("Example.Test.", () -> true);
            time.advanceMillis(1);
            long second = gate.acquire("other.test", () -> true);
            long third = 0;
            try {
                Future<Long> waiting = workers.submit(() -> gate.acquire("EXAMPLE.TEST", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                Map<String, Object> row = hostMetric(gate, "example.test");
                assertEquals(25, row.get("rps"));
                assertEquals(1, row.get("queued"));
                assertEquals(0L, row.get("p95WaitMillis"));
                assertThrows(UnsupportedOperationException.class, () -> row.put("host", "changed"));
                assertThrows(UnsupportedOperationException.class, () -> metrics(gate).add(Map.of()));
                time.advanceNanos(50_000_001);

                gate.update(limits); third = get(waiting);
                Map<String, Object> after = hostMetric(gate, "example.test");
                assertEquals(0, after.get("queued"));
                assertEquals(51L, after.get("p95WaitMillis")); // nanoseconds round up, never underreport
                assertEquals(2, number(gate, "hosts"));
                assertEquals(Boolean.FALSE, gate.snapshot().get("hostMetricsTruncated"));
            } finally {

                gate.close(); workers.close();
            }
        }
    }

    @Test void p95UsesOnlyBoundedRecentAdmissionsNotAnUnboundedLifetimeHistory() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 10, 5_000, 600_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            try {
                for (int i = 0; i < 64; i++) {
                    long pin = gate.acquire("pin.test", () -> true);
                    try {
                        Future<Long> waiting = admission(workers, gate, "sample.test");
                        waitFor(() -> number(gate, "queued") == 1);
                        time.advanceMillis(10);
                        gate.update(limits);
                        get(waiting);
                        time.advanceMillis(1);
                    } finally { gate.update(limits); }
                }
                assertEquals(10L, hostMetric(gate, "sample.test").get("p95WaitMillis"));
                for (int i = 0; i < 128; i++) {
                    time.advanceMillis(1);
                    gate.acquire("sample.test", () -> true);
                    if (i == 120) assertEquals(10L, hostMetric(gate, "sample.test").get("p95WaitMillis"));
                    if (i == 121) assertEquals(0L, hostMetric(gate, "sample.test").get("p95WaitMillis"));
                }
                // Lifetime p95 would still be 10ms; the 128-entry recent ring is now all zero.
                assertEquals(0L, hostMetric(gate, "sample.test").get("p95WaitMillis"));
                assertEquals(256, number(gate, "admitted"));
            } finally { gate.close(); workers.close(); }
        }
    }
    @Test void predicateCannotReentrantlyCloseOrLowerPacingAndThenObtainAdmission() throws Exception {
        var checks=new AtomicInteger();
        try(var gate=gate(limits(1000,0,Map.of(),0,1000))) {
            gate.acquire("one.test",()->true); advance(1);
            var failure=assertThrows(RateGate.Rejected.class,()->gate.acquire("two.test",()-> {
                if(checks.incrementAndGet()==2) gate.update(limits(1,0,Map.of(),0,1000));
                return true;
            }));
            assertEquals("QUEUE_FULL",failure.reason()); assertEquals(1,metric(gate,"admitted"));
        }
        checks.set(0);
        try(var gate=gate(limits(0,0,Map.of(),0,1000))) {
            var failure=assertThrows(RateGate.Rejected.class,()->gate.acquire("one.test",()-> {
                if(checks.incrementAndGet()==2) gate.close(); return true;
            }));
            assertEquals("SHUTDOWN",failure.reason()); assertEquals(0,metric(gate,"admitted"));
        }
    }

    private record Sample(String host, long admittedAt) {}
    private static List<Sample> exerciseWorkers(RateGate gate, List<String> workerHosts, int count) throws Exception {
        var ready=new java.util.concurrent.CountDownLatch(workerHosts.size());
        var start=new java.util.concurrent.CountDownLatch(1);
        var samples=java.util.Collections.synchronizedList(new java.util.ArrayList<Sample>());
        try(var workers=Executors.newVirtualThreadPerTaskExecutor()) {
            var results=workerHosts.stream().map(host->workers.submit(()-> {
                ready.countDown(); assertTrue(start.await(3,TimeUnit.SECONDS));
                for(int i=0;i<count;i++) samples.add(new Sample(host,gate.acquire(host,()->true)));
                return true;
            })).toList();
            assertTrue(ready.await(3,TimeUnit.SECONDS)); start.countDown();
            for(var result:results) assertTrue(get(result));
        }
        return samples;
    }
    private static void assertSpacing(List<Sample> samples,long interval) {
        var ordered=samples.stream().sorted(java.util.Comparator.comparingLong(Sample::admittedAt)).toList();
        for(int i=1;i<ordered.size();i++) assertTrue(ordered.get(i).admittedAt()-ordered.get(i-1).admittedAt()>=interval);
    }
    private static Limits limits(int global,int host,int concurrent,int queued,long timeout,long requestTimeout) {
        return new Limits(global,host,Map.of(),concurrent,queued,timeout,1000,requestTimeout);
    }
    private static long number(RateGate gate,String key) { return metric(gate,key); }
    private static List<Map<String,Object>> metrics(RateGate gate) {
        @SuppressWarnings("unchecked") var rows=(List<Map<String,Object>>)gate.snapshot().get("hostMetrics"); return rows;
    }
    private static Map<String,Object> hostMetric(RateGate gate,String host) {
        return metrics(gate).stream().filter(row->host.equals(row.get("host"))).findFirst().orElseThrow();
    }
    private static void waitFor(BooleanSupplier predicate) throws Exception { await(predicate); }
    private static <T> T get(java.util.concurrent.Future<T> future) throws Exception { return future.get(5,TimeUnit.SECONDS); }
    private static java.util.concurrent.Future<Long> admission(java.util.concurrent.ExecutorService workers,RateGate gate,String host) {
        return workers.submit(()->gate.acquire(host,()->true));
    }
    private static String outcome(RateGate gate,String host,BooleanSupplier current) throws InterruptedException {
        try { gate.acquire(host,current); return "ADMITTED"; } catch(RateGate.Rejected failure) { return failure.reason(); }
    }
    private static final class FakeTime implements java.util.function.LongSupplier {
        private final AtomicLong value;
        FakeTime(long initial) { value=new AtomicLong(initial); }
        public long getAsLong() { return value.get(); }
        void advanceMillis(long value) { advanceNanos(TimeUnit.MILLISECONDS.toNanos(value)); }
        void advanceNanos(long amount) { value.addAndGet(amount); }
    }
}
