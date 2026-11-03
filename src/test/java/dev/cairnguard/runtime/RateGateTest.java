package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig.Limits;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic callback admissions only: no sockets, Burp, target traffic, or wire-timing claims. */
@Timeout(20)
@SuppressWarnings("try") // Explicit shutdown-before-worker-join and idempotent close are under test.
class RateGateTest {
    @Test void immediateAdmissionWithZeroQueueAndNoIdleBurstCredit() throws Exception {
        FakeTime time = new FakeTime(-9_000_000_000L);
        Limits limits = limits(1_000, 10, 1, 0, 1_000, 10_000);
        try (RateGate gate = new RateGate(limits, time, 4)) {
            RateGate.Permit first = gate.acquire("EXAMPLE.TEST.", () -> true);
            assertEquals(1, number(gate, "active"));
            assertEquals(0, number(gate, "queued"));
            rejected(gate, "other.test", "QUEUE_FULL");
            first.close();
            time.advanceMillis(99);
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(1);
            RateGate.Permit second = gate.acquire("example.test", () -> true);
            assertEquals(100_000_000, second.admittedAtNanos() - first.admittedAtNanos());
            second.close();
            time.advanceMillis(10_000);
            gate.acquire("example.test", () -> true).close();
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(100);
            gate.acquire("example.test", () -> true).close();
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
            assertEquals(0, number(gate, "active"));
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
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            first.close();
            time.advanceNanos(333_333_333);
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceNanos(1);
            RateGate.Permit next = gate.acquire("two.test", () -> true);
            assertEquals(333_333_334, next.admittedAtNanos() - first.admittedAtNanos());
            next.close();
        }
    }

    @Test void fifoRetainsHeadOfLineAcrossHostsAndDoesNotCatchUpInABurst() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1, 5, 10, 5_000, 10_000);
        List<Integer> order = Collections.synchronizedList(new ArrayList<>());
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 16)) {
            try {
                gate.acquire("slow.test", () -> true).close();
                List<Future<Long>> results = new ArrayList<>();
                for (int i = 0; i < 6; i++) {
                    int index = i;
                    String host = i == 0 ? "slow.test" : "fast-" + i + ".test";
                    results.add(workers.submit(() -> {
                        try (RateGate.Permit permit = gate.acquire(host, () -> true)) {
                            order.add(index);
                            return permit.admittedAtNanos();
                        }
                    }));
                    int count = i + 1;
                    waitFor(() -> number(gate, "queued") == count);
                }
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals(1, number(gate, "admitted"));
                assertTrue(results.stream().noneMatch(Future::isDone));
                time.advanceMillis(999);
                gate.update(limits);
                assertEquals(1_000_000_000L, get(results.getFirst()));
                for (int i = 1; i < results.size(); i++) {
                    assertFalse(results.get(i).isDone(), "no idle catch-up credit");
                    time.advanceMillis(1);
                    gate.update(limits);
                    assertEquals(1_000_000_000L + i * 1_000_000L, get(results.get(i)));
                }
                assertEquals(List.of(0, 1, 2, 3, 4, 5), order);
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void concurrencyIsHeldUntilExplicitCompletionAndCloseIsIdempotentAcrossThreads() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 10, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 4)) {
            try {
                RateGate.Permit first = gate.acquire("one.test", () -> true);
                time.advanceMillis(2);
                Future<RateGate.Permit> second = workers.submit(() -> gate.acquire("two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(100);
                gate.update(limits);
                assertFalse(second.isDone());
                assertEquals(1, number(gate, "active"));
                get(workers.submit(() -> { first.close(); first.close(); return true; }));
                RateGate.Permit next = get(second);
                assertEquals(1, number(gate, "active"));
                next.close();
                next.close();
                assertEquals(0, number(gate, "active"));
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void timedOutPermitsQuarantineWithoutRecyclingAndOnlyActualCloseClearsThem() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 2, 10, 5_000, 100);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 8)) {
            try {
                RateGate.Permit first = gate.acquire("one.test", () -> true);
                time.advanceMillis(1);
                RateGate.Permit second = gate.acquire("two.test", () -> true);
                Future<String> waiting = workers.submit(() -> outcome(gate, "three.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(99);
                gate.update(limits);
                assertEquals("IN_FLIGHT_TIMEOUT", get(waiting));
                assertEquals(2, number(gate, "active"));
                assertEquals(1, number(gate, "stalled"));
                assertEquals(1, number(gate, "timedOut"));
                rejected(gate, "new.test", "IN_FLIGHT_TIMEOUT");
                first.close(); // synthetic late native completion, NOT an automatic timeout release
                assertEquals(1, number(gate, "active"));
                assertEquals(0, number(gate, "stalled"));
                RateGate.Permit third = gate.acquire("three.test", () -> true);
                time.advanceMillis(1);
                assertEquals(1, number(gate, "stalled"));
                gate.close();
                assertEquals(2, number(gate, "active"));
                assertEquals(1, number(gate, "stalled"));
                second.close();
                third.close();
                assertEquals(0, number(gate, "active"));
                assertEquals(0, number(gate, "stalled"));
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void outstandingTimeoutWakesWaiterWithoutAnySignalOrWatcherThread() throws Exception {
        Limits limits = limits(1_000, 1_000, 1, 10, 5_000, 80);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits)) {
            RateGate.Permit outstanding = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                assertEquals("IN_FLIGHT_TIMEOUT", waiting.get(2, TimeUnit.SECONDS));
                assertEquals(1, number(gate, "active"));
                assertEquals(1, number(gate, "stalled"));
            } finally { outstanding.close(); gate.close(); workers.close(); }
        }
    }

    @Test void raisingTimeoutCannotUnstallAnAlreadyExpiredUnobservedOperation() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 0, 1_000, 50), time, 4)) {
            RateGate.Permit permit = gate.acquire("one.test", () -> true);
            time.advanceMillis(51);
            gate.update(limits(1_000, 1_000, 2, 0, 1_000, 600_000));
            assertEquals(1, number(gate, "stalled"));
            rejected(gate, "two.test", "IN_FLIGHT_TIMEOUT");
            permit.close();
            gate.acquire("two.test", () -> true).close();
        }
    }

    @Test void loweringRequestTimeoutAppliesToOutstandingOperationsWithoutFreeingThem() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 0, 1_000, 5_000), time, 4)) {
            RateGate.Permit permit = gate.acquire("one.test", () -> true);
            time.advanceMillis(50);
            gate.update(limits(1_000, 1_000, 2, 0, 1_000, 20));
            assertEquals(1, number(gate, "active"));
            assertEquals(1, number(gate, "stalled"));
            rejected(gate, "two.test", "IN_FLIGHT_TIMEOUT");
            permit.close();
        }
    }

    @Test void lowerLiveConcurrencyNeverRevokesExistingPermits() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 3, 10, 5_000, 10_000), time, 8)) {
            try {
                List<RateGate.Permit> permits = new ArrayList<>();
                for (int i = 0; i < 3; i++) {
                    permits.add(gate.acquire("host-" + i + ".test", () -> true));
                    time.advanceMillis(1);
                }
                gate.update(limits(1_000, 1_000, 1, 10, 5_000, 10_000));
                assertEquals(3, number(gate, "active"));
                Future<RateGate.Permit> next = workers.submit(() -> gate.acquire("new.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                permits.get(0).close();
                permits.get(1).close();
                assertEquals(1, number(gate, "active"));
                assertFalse(next.isDone());
                permits.get(2).close();
                RateGate.Permit admitted = get(next);
                assertEquals(1, number(gate, "active"));
                admitted.close();
            } finally { gate.close(); workers.close(); }
        }
    }

    @Test void liveConcurrencyIncreaseWakesWaitersWithoutCompletingOutstandingNativeWork() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000))) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                Future<RateGate.Permit> next = workers.submit(() -> gate.acquire("two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                gate.update(limits(1_000, 1_000, 2, 10, 5_000, 10_000));
                RateGate.Permit second = get(next);
                assertEquals(2, number(gate, "active"));
                second.close();
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void lowerLiveQueueBoundRejectsNewestAndPreservesOldestWaiter() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 3, 5_000, 10_000), time, 8)) {
            RateGate.Permit permit = gate.acquire("one.test", () -> true);
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
                assertEquals(1, number(gate, "active"));
            } finally { permit.close(); gate.close(); workers.close(); }
        }
    }

    @Test void rateUpdatesPreserveCommittedDebtAndApplySlowerNewSpacing() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(10, 1_000, 1, 0, 1_000, 10_000), time, 8)) {
            gate.acquire("one.test", () -> true).close();
            time.advanceMillis(20);
            gate.update(limits(1_000, 1_000, 1, 0, 1_000, 10_000));
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceMillis(80);
            gate.acquire("two.test", () -> true).close();
            gate.update(limits(2, 1_000, 1, 0, 1_000, 10_000));
            time.advanceNanos(499_999_999);
            rejected(gate, "three.test", "QUEUE_FULL");
            time.advanceNanos(1);
            gate.acquire("three.test", () -> true).close();
        }
    }

    @Test void liveCanonicalOverrideUpdateExtendsHostDebt() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000), time, 8)) {
            gate.acquire("EXAMPLE.TEST.", () -> true).close();
            time.advanceMillis(10);
            gate.update(new Limits(1_000, 1_000, Map.of("Example.Test", 2), 1, 0, 1_000, 1_000, 10_000));
            rejected(gate, "example.test", "QUEUE_FULL");
            time.advanceMillis(490);
            gate.acquire("example.test.", () -> true).close();
            assertEquals(1, number(gate, "hosts"));
        }
    }

    @Test void monotonicQueueDeadlineWorksAtExactBoundaryAndAcrossNanoTimeWrap() throws Exception {
        FakeTime time = new FakeTime(Long.MAX_VALUE - 50_000_000);
        Limits limits = limits(1_000, 1_000, 1, 10, 100, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(99);
                gate.update(limits);
                assertFalse(waiting.isDone());
                time.advanceMillis(1);
                gate.update(limits);
                assertEquals("QUEUE_TIMEOUT", get(waiting));
                assertEquals(1, number(gate, "active"));
                assertEquals(0, number(gate, "queued"));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void lowerLiveQueueTimeoutUsesOriginalEnqueueTime() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000), time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(60);
                gate.update(limits(1_000, 1_000, 1, 10, 50, 10_000));
                assertEquals("QUEUE_TIMEOUT", get(waiting));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void raisingQueueTimeoutCannotReviveAnExpiredButUnscheduledWaiter() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 100, 10_000), time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(100);
                gate.update(limits(1_000, 1_000, 2, 10, 5_000, 10_000));
                assertEquals("QUEUE_TIMEOUT", get(waiting));
                assertEquals(1, number(gate, "active"));
                assertEquals(1, number(gate, "admitted"));
                assertEquals(0, number(gate, "queued"));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void staleAndThrowingPredicatesFailClosedWithoutLeakingMessages() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000))) {
            assertEquals("POLICY_CHANGED", assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> false)).reason());
            RateGate.Rejected exception = assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> { throw new IllegalStateException("synthetic-secret"); }));
            assertEquals("POLICY_CHANGED", exception.getMessage());
            assertNull(exception.getCause());
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            AtomicBoolean current = new AtomicBoolean(true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", current::get));
                waitFor(() -> number(gate, "queued") == 1);
                current.set(false); // no external signal; bounded predicate poll still wakes
                assertEquals("POLICY_CHANGED", get(waiting));
                assertEquals(0, number(gate, "queued"));
                assertEquals(1, number(gate, "active"));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void staleAtFinalAdjacentCheckNeverGetsAPermit() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000))) {
            RateGate.Rejected exception = assertThrows(RateGate.Rejected.class,
                    () -> gate.acquire("one.test", () -> checks.incrementAndGet() == 1));
            assertEquals("POLICY_CHANGED", exception.reason());
            assertEquals(0, number(gate, "active"));
            assertEquals(0, number(gate, "admitted"));
        }
    }

    @Test void interruptionRemovesWaiterButDoesNotFreeNativePermit() throws Exception {
        AtomicReference<Throwable> result = new AtomicReference<>();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000))) {
            RateGate.Permit permit = gate.acquire("one.test", () -> true);
            Thread waiting = Thread.ofVirtual().start(() -> {
                try { gate.acquire("two.test", () -> true).close(); }
                catch (Throwable e) { result.set(e); }
            });
            try {
                waitFor(() -> number(gate, "queued") == 1);
                waiting.interrupt();
                waiting.join(2_000);
                assertFalse(waiting.isAlive());
                assertInstanceOf(InterruptedException.class, result.get());
                assertEquals(0, number(gate, "queued"));
                assertEquals(1, number(gate, "active"));
            } finally { permit.close(); gate.close(); waiting.interrupt(); waiting.join(2_000); }
        }
    }

    @Test void closeRejectsAndWakesAllWaitersButDoesNotReleaseNativeWork() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10, 5_000, 10_000))) {
            RateGate.Permit permit = gate.acquire("one.test", () -> true);
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
                assertEquals(1, number(gate, "active"));
                assertEquals(0, number(gate, "queued"));
                assertEquals(Boolean.TRUE, gate.snapshot().get("closed"));
                rejected(gate, "new.test", "SHUTDOWN");
            } finally { permit.close(); gate.close(); workers.close(); }
            assertEquals(0, number(gate, "active"));
        }
    }

    @Test void hostCapacityPreservesRateDebtAndEvictsOnlyWhenItExpires() throws Exception {
        FakeTime time = new FakeTime(0);
        try (RateGate gate = new RateGate(limits(1_000, 1, 2, 0, 1_000, 10_000), time, 2)) {
            gate.acquire("one.test", () -> true).close();
            time.advanceMillis(1);
            gate.acquire("two.test", () -> true).close();
            time.advanceMillis(1);
            rejected(gate, "three.test", "HOST_CAPACITY");
            assertEquals(2, number(gate, "hosts"));
            time.advanceMillis(998);
            gate.acquire("three.test", () -> true).close();
            assertEquals(2, number(gate, "hosts"));
            rejected(gate, "one.test", "HOST_CAPACITY"); // two.test still owes 1ms; three owes 1s
        }
    }

    @Test void activeAndQueuedHostsCannotBeEvictedEvenAfterTheirRateWindowExpires() throws Exception {
        FakeTime time = new FakeTime(0);
        Limits limits = limits(1_000, 1_000, 1, 10, 5_000, 10_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits, time, 2)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            AtomicBoolean current = new AtomicBoolean(true);
            try {
                Future<String> waiting = workers.submit(() -> outcome(gate, "two.test", current::get));
                waitFor(() -> number(gate, "queued") == 1);
                time.advanceMillis(2_000);
                gate.update(limits);
                rejected(gate, "three.test", "HOST_CAPACITY");
                current.set(false);
                gate.update(limits);
                assertEquals("POLICY_CHANGED", get(waiting));
                first.close();
                gate.acquire("three.test", () -> true).close();
                assertTrue(number(gate, "hosts") <= 2);
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void productionHostMapIsBoundedAt4096IncludingQueuedKeys() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 10_000, 600_000, 600_000), time, 4_096)) {
            RateGate.Permit first = gate.acquire("active.test", () -> true);
            try {
                List<Future<String>> results = new ArrayList<>();
                for (int i = 0; i < 4_095; i++) {
                    int index = i;
                    results.add(workers.submit(() -> outcome(gate, "queued-" + index + ".test", () -> true)));
                }
                waitFor(() -> number(gate, "queued") == 4_095);
                assertEquals(4_096, number(gate, "hosts"));
                rejected(gate, "overflow.test", "HOST_CAPACITY");
                assertEquals(4_096, number(gate, "hosts"));
                gate.close();
                for (Future<String> result : results) assertEquals("SHUTDOWN", get(result));
                assertEquals(0, number(gate, "queued"));
                assertEquals(1, number(gate, "active"));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void idnIpv6CaseAndTrailingDotAliasesUsePolicyCanonicalizationForOverrides() throws Exception {
        for (List<String> aliases : List.of(
                List.of("BÜCHER.example.", "xn--bcher-kva.example", "bücher.EXAMPLE"),
                List.of("[2001:DB8::1]", "2001:db8:0:0:0:0:0:1", "[2001:0db8:0000:0000:0000:0000:0000:0001]"))) {
            FakeTime time = new FakeTime(0);
            Limits limits = new Limits(1_000, 1_000, Map.of(aliases.getFirst(), 2), 1, 0, 1_000, 1_000, 10_000);
            try (RateGate gate = new RateGate(limits, time, 4)) {
                gate.acquire(aliases.get(0), () -> true).close();
                time.advanceMillis(499);
                rejected(gate, aliases.get(1), "QUEUE_FULL");
                time.advanceMillis(1);
                gate.acquire(aliases.get(2), () -> true).close();
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
        for (int value : List.of(0, 1_001)) {
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

    @Test void inclusiveLimitEndpointsAreAcceptedAndSnapshotsContainOnlyFixedSafeMetadata() {
        for (Limits limits : List.of(limits(1, 1, 1, 0, 1, 1),
                new Limits(1_000, 1_000, Map.of(), 100, 10_000, 600_000, 600_000, 600_000))) {
            try (RateGate gate = new RateGate(limits)) {
                assertEquals(limits.globalRps(), number(gate, "globalRps"));
                assertEquals(limits.perHostRps(), number(gate, "perHostRps"));
                assertEquals(limits.maxConcurrent(), number(gate, "maxConcurrent"));
                assertTrue(gate.snapshot().values().stream().allMatch(value -> value instanceof Number || value instanceof Boolean));
                assertThrows(UnsupportedOperationException.class, () -> gate.snapshot().put("host", "not-allowed"));
            }
        }
    }

    @Test void fiveWorkersCannotExceedTrueInFlightMaximumEvenAfterRateDebtExpires() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(5);
        CountDownLatch ready = new CountDownLatch(5);
        CountDownLatch start = new CountDownLatch(1);
        java.util.concurrent.Semaphore completions = new java.util.concurrent.Semaphore(0);
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 10, 5_000, 10_000))) {
            try {
                List<Future<Boolean>> results = new ArrayList<>();
                for (int i = 0; i < 5; i++) {
                    int index = i;
                    results.add(workers.submit(() -> {
                        ready.countDown();
                        assertTrue(start.await(3, TimeUnit.SECONDS));
                        try (RateGate.Permit permit = gate.acquire("worker-" + index + ".test", () -> true)) {
                            assertNotNull(permit);
                            int count = inFlight.incrementAndGet();
                            peak.accumulateAndGet(count, Math::max);
                            try { assertTrue(completions.tryAcquire(5, TimeUnit.SECONDS)); }
                            finally { inFlight.decrementAndGet(); }
                        }
                        return true;
                    }));
                }
                assertTrue(ready.await(3, TimeUnit.SECONDS));
                start.countDown();
                waitFor(() -> number(gate, "active") == 2 && number(gate, "queued") == 3);
                assertEquals(2, number(gate, "admitted"));
                completions.release(); // exactly one synthetic native completion frees one slot
                waitFor(() -> number(gate, "admitted") == 3 && number(gate, "queued") == 2);
                assertEquals(2, number(gate, "active"));
                completions.release(4);
                for (Future<Boolean> result : results) assertTrue(get(result));
                assertEquals(2, peak.get());
                assertEquals(0, number(gate, "active"));
            } finally { start.countDown(); completions.release(5); gate.close(); workers.close(); }
        }
    }

    @Test void positiveQueueBoundCountsOnlyWaitingCallsAndOverflowDoesNotLoseOldest() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 1, 5_000, 10_000), time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                Future<String> oldest = workers.submit(() -> outcome(gate, "two.test", () -> true));
                waitFor(() -> number(gate, "queued") == 1);
                rejected(gate, "three.test", "QUEUE_FULL");
                assertEquals(1, number(gate, "queued"));
                assertEquals(2, number(gate, "hosts")); // failed attempt creates no retained host
                time.advanceMillis(1);
                first.close();
                assertEquals("ADMITTED", get(oldest));
            } finally { first.close(); gate.close(); workers.close(); }
        }
    }

    @Test void rateDebtAndRequestAgingUseMonotonicTimeAcrossWrap() throws Exception {
        FakeTime time = new FakeTime(Long.MAX_VALUE - 500_000);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 0, 1_000, 10), time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            time.advanceNanos(999_999);
            rejected(gate, "two.test", "QUEUE_FULL");
            time.advanceNanos(1);
            RateGate.Permit second = gate.acquire("two.test", () -> true);
            assertEquals(1_000_000, second.admittedAtNanos() - first.admittedAtNanos());
            time.advanceMillis(9);
            assertEquals(1, number(gate, "stalled"));
            assertEquals(2, number(gate, "active"));
            first.close();
            assertEquals(0, number(gate, "stalled"));
            second.close();
        }
    }

    @Test void predicateCannotReentrantlyCloseOrLowerBoundsAndThenObtainAPermit() throws Exception {
        FakeTime time = new FakeTime(0);
        AtomicInteger checks = new AtomicInteger();
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 2, 0, 1_000, 10_000), time, 4)) {
            RateGate.Permit first = gate.acquire("one.test", () -> true);
            try {
                time.advanceMillis(1);
                RateGate.Rejected failure = assertThrows(RateGate.Rejected.class, () -> gate.acquire("two.test", () -> {
                    if (checks.incrementAndGet() == 2) gate.update(limits(1_000, 1_000, 1, 0, 1_000, 10_000));
                    return true;
                }));
                assertEquals("QUEUE_FULL", failure.reason());
                assertEquals(1, number(gate, "active"));
                assertEquals(1, number(gate, "admitted"));
            } finally { first.close(); }
        }
        checks.set(0);
        try (RateGate gate = new RateGate(limits(1_000, 1_000, 1, 0, 1_000, 10_000), time, 4)) {
            RateGate.Rejected failure = assertThrows(RateGate.Rejected.class, () -> gate.acquire("one.test", () -> {
                if (checks.incrementAndGet() == 2) gate.close();
                return true;
            }));
            assertEquals("SHUTDOWN", failure.reason());
            assertEquals(0, number(gate, "active"));
        }
    }

    private static List<Sample> exerciseWorkers(RateGate gate, List<String> workerHosts, int count) throws Exception {
        CountDownLatch ready = new CountDownLatch(workerHosts.size());
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        List<Sample> samples = Collections.synchronizedList(new ArrayList<>());
        ExecutorService workers = Executors.newFixedThreadPool(workerHosts.size());
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (String host : workerHosts) results.add(workers.submit(() -> {
                ready.countDown();
                assertTrue(start.await(3, TimeUnit.SECONDS));
                for (int i = 0; i < count; i++) {
                    try (RateGate.Permit permit = gate.acquire(host, () -> true)) {
                        int concurrent = active.incrementAndGet();
                        peak.accumulateAndGet(concurrent, Math::max);
                        try {
                            // Timestamp at gate callback admission, not after caller rescheduling.
                            samples.add(new Sample(host, permit.admittedAtNanos()));
                            assertTrue(number(gate, "active") <= number(gate, "maxConcurrent"));
                            Thread.sleep(2); // purely synthetic native-completion stand-in
                        } finally { active.decrementAndGet(); }
                    }
                }
                return true;
            }));
            assertTrue(ready.await(3, TimeUnit.SECONDS));
            start.countDown();
            for (Future<Boolean> result : results) assertTrue(get(result));
            assertTrue(peak.get() <= number(gate, "maxConcurrent"));
            return List.copyOf(samples);
        } finally { start.countDown(); gate.close(); workers.close(); }
    }

    private static void assertSpacing(List<Sample> samples, long interval) {
        List<Sample> sorted = samples.stream().sorted(Comparator.comparingLong(Sample::nanos)).toList();
        for (int i = 1; i < sorted.size(); i++)
            assertTrue(sorted.get(i).nanos() - sorted.get(i - 1).nanos() >= interval,
                    "strict monotonic admission gap; this is NOT a wire-time assertion");
    }
    private static Limits limits(int global, int host, int concurrent, int queued, long queueMillis, long requestMillis) {
        return new Limits(global, host, Map.of(), concurrent, queued, queueMillis, 1_000, requestMillis);
    }
    private static long number(RateGate gate, String key) { return ((Number) gate.snapshot().get(key)).longValue(); }
    private static void rejected(RateGate gate, String host, String reason) {
        assertEquals(reason, assertThrows(RateGate.Rejected.class, () -> gate.acquire(host, () -> true)).reason());
    }
    private static String outcome(RateGate gate, String host, BooleanSupplier current) throws InterruptedException {
        try (RateGate.Permit permit = gate.acquire(host, current)) {
            assertNotNull(permit);
            return "ADMITTED";
        } catch (RateGate.Rejected e) { return e.reason(); }
    }
    private static <T> T get(Future<T> future) throws Exception { return future.get(5, TimeUnit.SECONDS); }
    private static void waitFor(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline >= 0) fail("synthetic condition did not settle");
            Thread.sleep(1);
        }
    }
    private record Sample(String host, long nanos) {}
    private static final class FakeTime implements java.util.function.LongSupplier {
        private final AtomicLong now;
        private FakeTime(long start) { now = new AtomicLong(start); }
        @Override public long getAsLong() { return now.get(); }
        private void advanceMillis(long millis) { advanceNanos(TimeUnit.MILLISECONDS.toNanos(millis)); }
        private void advanceNanos(long nanos) { now.addAndGet(nanos); }
    }
}
