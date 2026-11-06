package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.PolicyCodec;
import dev.cairnguard.model.RequestData;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic controller behavior, not native Burp callback-delivery evidence. */
@Timeout(15)
class AutomaticBlockingRemovalTest {
    private final AtomicLong nano = new AtomicLong();
    private final Limits limits = new Limits(1000, 1000, Map.of(), 1, 100, 1000, 1000, 1000,
            1, 60_000, new Circuit5xx(60_000, 1, 1000, 1),
            new Fanout(60_000, 2, FanoutAction.PAUSE), 0, false, List.of(), List.of());
    private final class Projects implements ProjectAccess {
        private String json = PolicyCodec.encode(new GuardConfig(2,
                List.of(new ScopeEntry(true, "owned.test", "https", 443, ""),
                        new ScopeEntry(true, "other.test", "https", 443, "")),
                List.of(), List.of(), Mode.ALLOW, limits));
        public Ref current() { return new Ref("synthetic", "Synthetic"); }
        public String load() { return json; }
        public void save(String value) { json = value; }
    }
    private RequestData request(String host, String path) {
        return new RequestData("GET", "https://" + host + path, host, 443, true,
                List.of(), new byte[0], true, true, path);
    }
    private GuardController open() {
        return new GuardController(new Projects(), new ResponseWatcher(limits, nano::get,
                () -> TimeUnit.NANOSECONDS.toMillis(nano.get())), new IntentBudget(),
                new RateGate(limits, nano::get, 4096), new ListenerRegistry());
    }
    private GuardController.Prepared send(GuardController c, String host, String path) {
        nano.addAndGet(TimeUnit.MILLISECONDS.toNanos(2));
        var p = c.prepare(request(host, path));
        var a = c.authorize(p);
        assertTrue(a.allowed(), a.reason());
        assertTrue(c.commit(p));
        return p;
    }
    @Test void missingCallbackPastOldTimeoutNeverHoldsLaterRequestsHostage() {
        try (var c = open()) {
            send(c, "owned.test", "/missing");
            nano.addAndGet(TimeUnit.SECONDS.toNanos(10));
            for (int i = 0; i < 125; i++)
                send(c, i % 2 == 0 ? "owned.test" : "other.test", i % 3 == 0 ? "/missing" : "/later/" + i);
            assertEquals(126, c.traffic().size());
        }
    }
    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.EnumSource(FanoutAction.class)
    void repeatedFiveHundredsLargeResponsesAndFanoutNeverBlockOrPause(FanoutAction action) {
        try (var c = open()) {
            var original=c.config();
            var configured=new Limits(1000,1000,Map.of(),1,100,1000,1000,1000,
                    1,60_000,new Circuit5xx(60_000,1,1000,1),new Fanout(60_000,2,action),0,false,List.of(),List.of());
            c.updateConfig(new GuardConfig(2,original.allowScope(),original.blockScope(),original.rules(),Mode.ALLOW,configured),
                    "synthetic",((Number)c.status().get("revision")).longValue());
            for (int i = 0; i < 125; i++) {
                var p = send(c, "owned.test", "/route/" + i);
                c.response(p.evidenceId(), 500, List.of(), new byte[]{1, 2, 3}, 3);
            }
            send(c, "owned.test", "/next");
            assertEquals("PROTECTED", c.status().get("guardState"));
            assertEquals(126, c.traffic().size());
        }
    }
    @Test void legacyAutomaticSettingsStayInactiveAfterAnUnrelatedSaveAndReload() {
        var projects=new Projects();
        try(var c=new GuardController(projects,new ResponseWatcher(limits,nano::get,()->1_000_000L),new IntentBudget(),
                new RateGate(limits,nano::get,4096),new ListenerRegistry())) {
            var before=c.config().limits(); var p=send(c,"owned.test","/error");
            c.response(p.evidenceId(),500,List.of(),new byte[]{1,2},2);
            c.updateConfig(c.config(),"synthetic",((Number)c.status().get("revision")).longValue());
            assertEquals(before,c.config().limits()); send(c,"owned.test","/error");
        }
        try(var c=new GuardController(projects,new ResponseWatcher(limits,nano::get,()->1_000_000L),new IntentBudget(),
                new RateGate(limits,nano::get,4096),new ListenerRegistry())) {
            assertEquals(limits,c.config().limits());
            var p=send(c,"owned.test","/error"); c.response(p.evidenceId(),500,List.of(),new byte[]{1,2},2);
            send(c,"owned.test","/next"); assertEquals("PROTECTED",c.status().get("guardState"));
        }
    }

}
