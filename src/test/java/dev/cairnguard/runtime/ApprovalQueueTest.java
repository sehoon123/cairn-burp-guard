package dev.cairnguard.runtime;

import java.lang.reflect.RecordComponent;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic human-click/condition-wait fixtures; no native APIs, traffic, sockets, or Swing. */
@Timeout(15)
@SuppressWarnings("try") // Explicit shutdown-before-worker-join and idempotent close are under test.
class ApprovalQueueTest {
    @Test void approvalIsOneShotAndContainsOnlyImmutableEvidenceReferences() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence-1", "project-1", 5_000, () -> true));
                ApprovalQueue.Pending pending = pending(queue, 1).getFirst();
                assertEquals("evidence-1", pending.evidenceId());
                assertEquals("project-1", pending.projectId());
                assertTrue(Instant.parse(pending.expiresAt()).isAfter(Instant.parse(pending.createdAt())));
                assertThrows(UnsupportedOperationException.class, () -> queue.snapshot().clear());
                assertEquals(List.of("id", "evidenceId", "projectId", "createdAt", "expiresAt"),
                        Arrays.stream(ApprovalQueue.Pending.class.getRecordComponents()).map(RecordComponent::getName).toList());
                assertTrue(queue.decide(pending.id(), true));
                assertFalse(queue.decide(pending.id(), true));
                assertFalse(queue.decide(pending.id(), false));
                assertEquals(new ApprovalQueue.Result(true, "APPROVED"), get(result));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void humanDenialNeverAllowsAndUnknownIdsAreInert() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                assertFalse(queue.decide("missing", true));
                assertFalse(queue.decide(null, true));
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, () -> true));
                String id = pending(queue, 1).getFirst().id();
                assertTrue(queue.decide(id, false));
                assertEquals(new ApprovalQueue.Result(false, "DENIED"), get(result));
                assertFalse(queue.decide(id, true));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void fiveConcurrentWaitersStayOldestFirstAndDecisionsDoNotCrossReferences() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(5);
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                List<Future<ApprovalQueue.Result>> results = new ArrayList<>();
                for (int i = 0; i < 5; i++) {
                    int index = i;
                    results.add(workers.submit(() -> queue.await("evidence-" + index, "project", 5_000, () -> true)));
                    pending(queue, i + 1);
                }
                List<ApprovalQueue.Pending> rows = queue.snapshot();
                assertEquals(List.of("evidence-0", "evidence-1", "evidence-2", "evidence-3", "evidence-4"),
                        rows.stream().map(ApprovalQueue.Pending::evidenceId).toList());
                assertEquals(5, rows.stream().map(ApprovalQueue.Pending::id).distinct().count());
                for (int i = rows.size() - 1; i >= 0; i--) assertTrue(queue.decide(rows.get(i).id(), i % 2 == 0));
                for (int i = 0; i < results.size(); i++)
                    assertEquals(new ApprovalQueue.Result(i % 2 == 0, i % 2 == 0 ? "APPROVED" : "DENIED"), get(results.get(i)));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void productionCapacityIsExactly100AndShutdownWakesAllWaiters() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                List<Future<ApprovalQueue.Result>> results = new ArrayList<>();
                for (int i = 0; i < 100; i++) {
                    int index = i;
                    results.add(workers.submit(() -> queue.await("evidence-" + index, "project", 30_000, () -> true)));
                }
                List<ApprovalQueue.Pending> rows = pending(queue, 100);
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_CAPACITY"),
                        queue.await("overflow", "project", 1_000, () -> true));
                assertEquals(100, queue.snapshot().size());
                queue.close();
                queue.close();
                for (Future<ApprovalQueue.Result> result : results)
                    assertEquals(new ApprovalQueue.Result(false, "SHUTDOWN"), get(result));
                for (ApprovalQueue.Pending row : rows) assertFalse(queue.decide(row.id(), true));
                assertTrue(queue.snapshot().isEmpty());
                assertEquals(new ApprovalQueue.Result(false, "SHUTDOWN"),
                        queue.await("future", "project", 1_000, () -> true));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void realTimeoutCleansUpWithoutWatcherThreadsAndLateApprovalCannotAllow() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 150, () -> true));
                String id = pending(queue, 1).getFirst().id();
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(result));
                assertFalse(queue.decide(id, true));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void exactMonotonicExpiryRejectsAllowBeforeTheWaiterGetsScheduled() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 100, () -> true));
                ApprovalQueue.Pending row = pending(queue, 1).getFirst();
                assertEquals("2026-01-01T00:00:00Z", row.createdAt());
                assertEquals("2026-01-01T00:00:00.100Z", row.expiresAt());
                time.advanceMillis(100);
                assertFalse(queue.decide(row.id(), true));
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(result));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void monotonicExpiryWorksAcrossNanoTimeWrap() throws Exception {
        FakeTime time = new FakeTime(Long.MAX_VALUE - 10_000_000);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 50, () -> true));
                String id = pending(queue, 1).getFirst().id();
                time.advanceMillis(50);
                assertFalse(queue.decide(id, true));
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(result));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void wallClockJumpsCannotExpireOrExtendAnApproval() throws Exception {
        for (long jumpSeconds : List.of(-86_400L, 86_400L)) {
            FakeTime time = new FakeTime(0);
            MutableClock wall = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            try (ApprovalQueue queue = new ApprovalQueue(1, time, wall)) {
                try {
                    Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 100, () -> true));
                    String id = pending(queue, 1).getFirst().id();
                    wall.now.set(wall.instant().plusSeconds(jumpSeconds));
                    time.advanceMillis(99);
                    assertTrue(queue.decide(id, true));
                    assertEquals(new ApprovalQueue.Result(true, "APPROVED"), get(result));
                } finally { queue.close(); workers.close(); }
            }
        }
    }

    @Test void snapshotOrderIsEnqueueOrderNotAnAdjustableWallClockSort() throws Exception {
        FakeTime time = new FakeTime(0);
        MutableClock wall = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(2, time, wall)) {
            try {
                Future<ApprovalQueue.Result> first = workers.submit(() -> queue.await("first", "project", 1_000, () -> true));
                pending(queue, 1);
                wall.now.set(wall.instant().minusSeconds(3_600));
                Future<ApprovalQueue.Result> second = workers.submit(() -> queue.await("second", "project", 1_000, () -> true));
                List<ApprovalQueue.Pending> rows = pending(queue, 2);
                assertEquals(List.of("first", "second"), rows.stream().map(ApprovalQueue.Pending::evidenceId).toList());
                queue.cancelAll("DENIED");
                assertEquals("DENIED", get(first).reason());
                assertEquals("DENIED", get(second).reason());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void staleAndThrowingPredicatesDenyWithoutCapturingExceptionData() throws Exception {
        try (ApprovalQueue queue = new ApprovalQueue()) {
            assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"),
                    queue.await("evidence", "project", 1_000, () -> false));
            assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"),
                    queue.await("evidence", "project", 1_000, () -> { throw new IllegalStateException("synthetic-secret"); }));
            assertTrue(queue.snapshot().isEmpty());
        }
    }

    @Test void staleDecisionIsRejectedEvenWithoutAnExplicitCancelAll() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, current::get));
                String id = pending(queue, 1).getFirst().id();
                current.set(false);
                assertFalse(queue.decide(id, true));
                assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"), get(result));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void stalePendingWaiterWakesByPredicatePollWithoutAnyExternalSignal() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, current::get));
                pending(queue, 1);
                current.set(false);
                assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"), result.get(2, TimeUnit.SECONDS));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void acceptedClickIsRecheckedForStalenessBeforeAwaitCanReturnAllow() throws Exception {
        Thread clickingThread = Thread.currentThread();
        AtomicBoolean current = new AtomicBoolean(true);
        AtomicBoolean arm = new AtomicBoolean();
        BooleanSupplier predicate = () -> {
            boolean wasCurrent = current.get();
            if (Thread.currentThread() == clickingThread && arm.get()) current.set(false);
            return wasCurrent;
        };
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, predicate));
                String id = pending(queue, 1).getFirst().id();
                arm.set(true);
                assertTrue(queue.decide(id, true)); // click observed current; state changes right after that check
                assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"), get(result));
                assertTrue(queue.snapshot().isEmpty());
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void acceptedClickIsRecheckedForExpiryBeforeAwaitCanReturnAllow() throws Exception {
        FakeTime time = new FakeTime(0);
        Thread clickingThread = Thread.currentThread();
        AtomicBoolean arm = new AtomicBoolean();
        AtomicBoolean expireOnWorker = new AtomicBoolean();
        BooleanSupplier predicate = () -> {
            if (Thread.currentThread() == clickingThread && arm.get()) expireOnWorker.set(true);
            else if (expireOnWorker.getAndSet(false)) time.advanceMillis(100);
            return true;
        };
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 100, predicate));
                String id = pending(queue, 1).getFirst().id();
                arm.set(true);
                assertTrue(queue.decide(id, true));
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(result));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void predicateTimeCannotExtendAnExpiredClickDeadline() throws Exception {
        FakeTime time = new FakeTime(0);
        AtomicBoolean expire = new AtomicBoolean();
        BooleanSupplier predicate = () -> {
            if (expire.getAndSet(false)) time.advanceMillis(100);
            return true;
        };
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 100, predicate));
                String id = pending(queue, 1).getFirst().id();
                expire.set(true);
                assertFalse(queue.decide(id, true));
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(result));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void cancellationDeniesAndWakesAllNormalizesReasonsAndDoesNotCloseFutureApprovals() throws Exception {
        for (String reason : List.of("POLICY_CHANGED", "PROJECT_CHANGED", "PAUSED", "synthetic-secret", "DENIED", "SHUTDOWN")) {
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            try (ApprovalQueue queue = new ApprovalQueue()) {
                try {
                    List<Future<ApprovalQueue.Result>> results = new ArrayList<>();
                    for (int i = 0; i < 5; i++) {
                        int index = i;
                        results.add(workers.submit(() -> queue.await("evidence-" + index, "project", 5_000, () -> true)));
                    }
                    List<ApprovalQueue.Pending> rows = pending(queue, 5);
                    queue.cancelAll(reason);
                    String expected = reason.equals("DENIED") || reason.equals("SHUTDOWN") ? reason : "POLICY_CHANGED";
                    for (Future<ApprovalQueue.Result> result : results)
                        assertEquals(new ApprovalQueue.Result(false, expected), get(result));
                    for (ApprovalQueue.Pending row : rows) assertFalse(queue.decide(row.id(), true));
                    assertTrue(queue.snapshot().isEmpty());
                    Future<ApprovalQueue.Result> next = workers.submit(() -> queue.await("new-evidence", "project", 5_000, () -> true));
                    assertTrue(queue.decide(pending(queue, 1).getFirst().id(), true));
                    assertEquals(new ApprovalQueue.Result(true, "APPROVED"), get(next));
                } finally { queue.close(); workers.close(); }
            }
        }
    }

    @Test void expiredEntriesAreReapedToMakeCapacityAvailable() throws Exception {
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> first = workers.submit(() -> queue.await("old-evidence", "project", 100, () -> true));
                String oldId = pending(queue, 1).getFirst().id();
                time.advanceMillis(100);
                Future<ApprovalQueue.Result> next = workers.submit(() -> queue.await("new-evidence", "project", 100, () -> true));
                waitFor(() -> queue.snapshot().stream().anyMatch(row -> row.evidenceId().equals("new-evidence")));
                ApprovalQueue.Pending fresh = queue.snapshot().getFirst();
                assertNotEquals(oldId, fresh.id());
                assertFalse(queue.decide(oldId, true));
                assertTrue(queue.decide(fresh.id(), true));
                assertEquals(new ApprovalQueue.Result(false, "APPROVAL_TIMEOUT"), get(first));
                assertEquals(new ApprovalQueue.Result(true, "APPROVED"), get(next));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void staleEntriesAreReapedToMakeCapacityAvailable() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        FakeTime time = new FakeTime(0);
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue(1, time, fixedClock())) {
            try {
                Future<ApprovalQueue.Result> first = workers.submit(() -> queue.await("old", "project", 1_000, current::get));
                pending(queue, 1);
                current.set(false);
                Future<ApprovalQueue.Result> next = workers.submit(() -> queue.await("new", "project", 1_000, () -> true));
                waitFor(() -> queue.snapshot().stream().anyMatch(row -> row.evidenceId().equals("new")));
                assertTrue(queue.decide(queue.snapshot().getFirst().id(), true));
                assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"), get(first));
                assertEquals(new ApprovalQueue.Result(true, "APPROVED"), get(next));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void interruptedWaitCleansUpAndCannotBeApprovedLater() throws Exception {
        AtomicReference<Throwable> result = new AtomicReference<>();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            Thread waiting = Thread.ofVirtual().start(() -> {
                try { queue.await("evidence", "project", 5_000, () -> true); }
                catch (Throwable e) { result.set(e); }
            });
            try {
                String id = pending(queue, 1).getFirst().id();
                waiting.interrupt();
                waiting.join(2_000);
                assertFalse(waiting.isAlive());
                assertInstanceOf(InterruptedException.class, result.get());
                assertTrue(queue.snapshot().isEmpty());
                assertFalse(queue.decide(id, true));
            } finally { queue.close(); waiting.interrupt(); waiting.join(2_000); }
        }
    }

    @Test void anOldDecisionCannotApproveAReplacementForTheSameEvidenceId() throws Exception {
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        try (ApprovalQueue queue = new ApprovalQueue()) {
            try {
                Future<ApprovalQueue.Result> first = workers.submit(() -> queue.await("evidence", "project", 5_000, () -> true));
                String old = pending(queue, 1).getFirst().id();
                queue.cancelAll(null);
                assertEquals("POLICY_CHANGED", get(first).reason());
                Future<ApprovalQueue.Result> second = workers.submit(() -> queue.await("evidence", "project", 5_000, () -> true));
                String fresh = pending(queue, 1).getFirst().id();
                assertNotEquals(old, fresh);
                assertFalse(queue.decide(old, true));
                assertFalse(second.isDone());
                assertTrue(queue.decide(fresh, false));
                assertEquals(new ApprovalQueue.Result(false, "DENIED"), get(second));
            } finally { queue.close(); workers.close(); }
        }
    }

    @Test void invalidMetadataAndTimeoutsAreBoundedAndErrorsAreCategorical() {
        try (ApprovalQueue queue = new ApprovalQueue()) {
            for (String reference : Arrays.asList(null, "", " ", "x".repeat(513), "synthetic\nsecret", "\ud800")) {
                assertEquals("INVALID_APPROVAL_REFERENCE", assertThrows(IllegalArgumentException.class,
                        () -> queue.await(reference, "project", 1_000, () -> true)).getMessage());
                assertEquals("INVALID_APPROVAL_REFERENCE", assertThrows(IllegalArgumentException.class,
                        () -> queue.await("evidence", reference, 1_000, () -> true)).getMessage());
            }
            for (long timeout : List.of(0L, -1L, 600_001L, Long.MAX_VALUE))
                assertEquals("INVALID_APPROVAL_TIMEOUT", assertThrows(IllegalArgumentException.class,
                        () -> queue.await("evidence", "project", timeout, () -> true)).getMessage());
            assertTrue(queue.snapshot().isEmpty());
        }
    }

    @Test void approvalTimeoutEndpointsAndMaximumReferenceLengthAreAccepted() throws Exception {
        try (ApprovalQueue queue = new ApprovalQueue()) {
            for (long timeout : List.of(1L, 600_000L))
                assertEquals(new ApprovalQueue.Result(false, "POLICY_CHANGED"),
                        queue.await("e".repeat(512), "p".repeat(512), timeout, () -> false));
        }
    }

    @Test void cancellationOrShutdownDuringClickValidationCannotBeOverwrittenByAnAllow() throws Exception {
        for (boolean shutdown : List.of(false, true)) {
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            AtomicReference<ApprovalQueue> reference = new AtomicReference<>();
            AtomicBoolean arm = new AtomicBoolean();
            Thread clickingThread = Thread.currentThread();
            BooleanSupplier predicate = () -> {
                if (Thread.currentThread() == clickingThread && arm.getAndSet(false)) {
                    if (shutdown) reference.get().close();
                    else reference.get().cancelAll("POLICY_CHANGED");
                }
                return true;
            };
            try (ApprovalQueue queue = new ApprovalQueue()) {
                reference.set(queue);
                try {
                    Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, predicate));
                    String id = pending(queue, 1).getFirst().id();
                    arm.set(true);
                    assertFalse(queue.decide(id, true));
                    assertEquals(new ApprovalQueue.Result(false, shutdown ? "SHUTDOWN" : "POLICY_CHANGED"), get(result));
                    assertTrue(queue.snapshot().isEmpty());
                } finally { queue.close(); workers.close(); }
            }
        }
    }

    @Test void cancellationOrShutdownCanRevokeAnAcceptedButNotYetConsumedApproval() throws Exception {
        for (boolean shutdown : List.of(false, true)) {
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            AtomicReference<ApprovalQueue> reference = new AtomicReference<>();
            AtomicBoolean arm = new AtomicBoolean();
            AtomicBoolean cancelOnWorker = new AtomicBoolean();
            Thread clickingThread = Thread.currentThread();
            BooleanSupplier predicate = () -> {
                if (Thread.currentThread() == clickingThread && arm.get()) cancelOnWorker.set(true);
                else if (cancelOnWorker.getAndSet(false)) {
                    if (shutdown) reference.get().close();
                    else reference.get().cancelAll("PROJECT_CHANGED");
                }
                return true;
            };
            try (ApprovalQueue queue = new ApprovalQueue()) {
                reference.set(queue);
                try {
                    Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, predicate));
                    String id = pending(queue, 1).getFirst().id();
                    arm.set(true);
                    assertTrue(queue.decide(id, true));
                    assertEquals(new ApprovalQueue.Result(false, shutdown ? "SHUTDOWN" : "POLICY_CHANGED"), get(result));
                    assertTrue(queue.snapshot().isEmpty());
                } finally { queue.close(); workers.close(); }
            }
        }
    }

    @Test void snapshotReapingToleratesCancellationOrShutdownDuringCurrentStateValidation() throws Exception {
        for (boolean shutdown : List.of(false, true)) {
            ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
            AtomicReference<ApprovalQueue> reference = new AtomicReference<>();
            AtomicBoolean arm = new AtomicBoolean();
            Thread observingThread = Thread.currentThread();
            BooleanSupplier predicate = () -> {
                if (Thread.currentThread() == observingThread && arm.getAndSet(false)) {
                    if (shutdown) reference.get().close();
                    else reference.get().cancelAll("POLICY_CHANGED");
                }
                return true;
            };
            try (ApprovalQueue queue = new ApprovalQueue()) {
                reference.set(queue);
                try {
                    Future<ApprovalQueue.Result> result = workers.submit(() -> queue.await("evidence", "project", 5_000, predicate));
                    pending(queue, 1);
                    arm.set(true);
                    assertTrue(queue.snapshot().isEmpty());
                    assertEquals(new ApprovalQueue.Result(false, shutdown ? "SHUTDOWN" : "POLICY_CHANGED"), get(result));
                } finally { queue.close(); workers.close(); }
            }
        }
    }

    private static List<ApprovalQueue.Pending> pending(ApprovalQueue queue, int count) throws InterruptedException {
        waitFor(() -> queue.snapshot().size() == count);
        return queue.snapshot();
    }
    private static Clock fixedClock() { return Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC); }
    private static <T> T get(Future<T> future) throws Exception { return future.get(5, TimeUnit.SECONDS); }
    private static void waitFor(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline >= 0) fail("synthetic condition did not settle");
            Thread.sleep(1);
        }
    }
    private static final class FakeTime implements java.util.function.LongSupplier {
        private final AtomicLong now;
        private FakeTime(long start) { now = new AtomicLong(start); }
        @Override public long getAsLong() { return now.get(); }
        private void advanceMillis(long millis) { now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)); }
    }
    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;
        private MutableClock(Instant start) { now = new AtomicReference<>(start); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(instant(), zone); }
        @Override public Instant instant() { return now.get(); }
    }
}
