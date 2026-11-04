package dev.cairnguard.runtime;

import dev.cairnguard.model.RequestAttribution;
import dev.cairnguard.model.RequestData.Header;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class IntentBudgetTest {
    @Test void twentiethAllowedTwentyFirstRejectedAndOtherIntentRunIndependent() {
        IntentBudget budget = new IntentBudget();
        RequestAttribution one = tag("i048", "run-one");
        for (int i = 0; i < 20; i++) {
            assertNull(budget.check(one, 20));
            assertNull(budget.commit(one, 20));
        }
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.check(one, 20));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.commit(one, 20));
        assertNull(budget.commit(tag("i049", "run-one"), 20));
        assertNull(budget.commit(tag("i048", "run-two"), 20));
        assertEquals(3, number(budget, "keys"));
        assertEquals(22, number(budget, "consumed"));
        assertEquals(1, number(budget, "rejected"));
    }

    @Test void checkingDoesNotReserveOrConsumeCapacity() {
        IntentBudget budget = new IntentBudget(1);
        for (int i = 0; i < 100; i++) assertNull(budget.check(tag("i" + i, "run"), 1));
        assertEquals(0, number(budget, "keys"));
        assertEquals(0, number(budget, "consumed"));
        assertNull(budget.commit(tag("one", "run"), 1));
        assertEquals("INTENT_BUDGET_CAPACITY", budget.check(tag("two", "run"), 1));
    }

    @Test void concurrentFinalCommitsCannotOverrunTheLimitEvenAfterSuccessfulChecks() throws Exception {
        IntentBudget budget = new IntentBudget();
        RequestAttribution tag = tag("one", "shared");
        int workers = 64;
        CountDownLatch ready = new CountDownLatch(workers);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < workers; i++) futures.add(executor.submit(() -> {
                assertNull(budget.check(tag, 20));
                ready.countDown();
                assertTrue(go.await(5, TimeUnit.SECONDS));
                String reason = budget.commit(tag, 20);
                if (reason == null) allowed.incrementAndGet();
                else { assertEquals("INTENT_BUDGET_EXCEEDED", reason); rejected.incrementAndGet(); }
                return null;
            }));
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            for (Future<?> future : futures) future.get(5, TimeUnit.SECONDS);
        }
        assertEquals(20, allowed.get());
        assertEquals(44, rejected.get());
        assertEquals(20, number(budget, "consumed"));
    }

    @Test void capacityIsHardBoundAndExistingDebtIsNeverEvicted() {
        IntentBudget budget = new IntentBudget();
        for (int i = 0; i < 4_096; i++) assertNull(budget.commit(tag("i" + i, "run"), 2));
        assertEquals("INTENT_BUDGET_CAPACITY", budget.commit(tag("new", "run"), 2));
        assertEquals(4_096, number(budget, "keys"));
        assertNull(budget.commit(tag("i0", "run"), 2));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.commit(tag("i0", "run"), 2));
        for (int i = 0; i < 100; i++)
            assertEquals("INTENT_BUDGET_CAPACITY", budget.commit(tag("new-" + i, "run"), 2));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.check(tag("i0", "run"), 2));
    }

    @Test void missingIntentIsUnbudgetedAndInvalidTagsRejectedOnlyWhenEnabled() {
        IntentBudget budget = new IntentBudget(1);
        for (int i = 0; i < 10; i++) {
            assertNull(budget.commit(tag("-", "run-" + i), 1));
            assertNull(budget.commit(null, 1));
        }
        assertEquals(0, number(budget, "keys"));
        RequestAttribution bad = new RequestAttribution("?", "run", false);
        assertNull(budget.check(bad, 0));
        assertNull(budget.commit(bad, 0));
        assertEquals("INVALID_INTENT_TAG", budget.check(bad, 1));
        assertEquals("INVALID_INTENT_TAG", budget.commit(bad, 1));
        assertEquals("INVALID_INTENT_TAG", budget.commit(new RequestAttribution("-", "?", false), 1));
        assertEquals(0, number(budget, "keys"));
    }

    @Test void realHeaderParserSuppliesUnchangedBoundedLabelsAndRejectsDuplicateEvenIdentical() {
        IntentBudget budget = new IntentBudget();
        RequestAttribution parsed = RequestAttribution.parse(List.of(new Header("X-Cairn-Intent", "i048"),
                new Header("X-Cairn-Run", "Run:ONE")));
        assertEquals("i048", parsed.intentId());
        assertEquals("Run:ONE", parsed.runId());
        assertNull(budget.commit(parsed, 1));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.commit(parsed, 1));
        RequestAttribution duplicate = RequestAttribution.parse(List.of(new Header("X-Cairn-Intent", "i048"),
                new Header("x-cairn-intent", "i048")));
        assertEquals("INVALID_INTENT_TAG", budget.commit(duplicate, 1));
        assertNull(budget.commit(duplicate, 0));
        assertNull(budget.commit(RequestAttribution.parse(List.of()), 1));
        assertEquals(1, number(budget, "keys"));
    }

    @Test void publicRecordCannotSmuggleUnboundedOrMalformedKeys() {
        IntentBudget budget = new IntentBudget();
        for (RequestAttribution invalid : List.of(tag("bad value", "run"), tag("?", "run"),
                tag("x".repeat(65), "run"), tag("one", "x".repeat(65)), tag("", "run"))) {
            assertEquals("INVALID_INTENT_TAG", budget.commit(invalid, 20));
        }
        assertNull(budget.commit(tag("AZaz09._:-", "AZaz09._:-"), 1));
    }

    @Test void offAndLimitChangesDoNotClearPriorCounters() {
        IntentBudget budget = new IntentBudget();
        RequestAttribution tag = tag("one", "run");
        assertNull(budget.commit(tag, 1));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.check(tag, 1));
        for (int i = 0; i < 100; i++) assertNull(budget.commit(tag, 0));
        assertEquals(1, number(budget, "consumed"), "off suspends accounting, not a reset");
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.check(tag, 1));
        assertNull(budget.commit(tag, 2));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.commit(tag, 2));
        budget.reset();
        assertEquals(0, number(budget, "keys"));
        assertNull(budget.commit(tag, 1));
    }

    @Test void pairEncodingIsUnambiguousAndSnapshotContainsNoLabelsOrHashes() {
        IntentBudget budget = new IntentBudget();
        assertNull(budget.commit(tag("b:c", "a"), 1));
        assertNull(budget.commit(tag("c", "a:b"), 1));
        assertNull(budget.commit(tag("synthetic-intent-secret", "synthetic-run-secret"), 1));
        String snapshot = budget.snapshot().toString();
        assertFalse(snapshot.contains("synthetic-intent-secret"));
        assertFalse(snapshot.contains("synthetic-run-secret"));
        assertEquals(3, number(budget, "keys"));
    }

    @Test void finalCommitApiHasNoModeBasedExemptionForExemptOrProbes() {
        IntentBudget budget = new IntentBudget();
        RequestAttribution same = tag("one", "run");
        assertNull(budget.commit(same, 2)); // ordinary protected handoff
        assertNull(budget.commit(same, 2)); // EXEMPT/probe handoff uses the SAME API
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.commit(same, 2));
    }

    @Test void invalidLimitsOrCapacityAreRejectedWithoutClearingDebt() {
        assertThrows(IllegalArgumentException.class, () -> new IntentBudget(0));
        assertThrows(IllegalArgumentException.class, () -> new IntentBudget(4_097));
        IntentBudget budget = new IntentBudget();
        assertNull(budget.commit(tag("one", "run"), 1));
        assertThrows(IllegalArgumentException.class, () -> budget.commit(tag("one", "run"), -1));
        assertThrows(IllegalArgumentException.class, () -> budget.check(tag("one", "run"), 1_000_001));
        assertEquals("INTENT_BUDGET_EXCEEDED", budget.check(tag("one", "run"), 1));
    }

    private static RequestAttribution tag(String intent, String run) { return new RequestAttribution(intent, run, true); }
    private static long number(IntentBudget budget, String key) { return ((Number) budget.snapshot().get(key)).longValue(); }
}
