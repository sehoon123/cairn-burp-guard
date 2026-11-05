package dev.cairnguard.runtime;

import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.*;
import dev.cairnguard.model.PolicyCodec;
import dev.cairnguard.model.RequestData;
import dev.cairnguard.policy.PolicyEngine;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Offline scalar/epoch/true-permit regressions; NOT native Burp evidence. */
@Timeout(15)
class LateResponseRegressionTest {
    private final AtomicLong nano = new AtomicLong();
    private ResponseWatcher watcher(Limits limits) {
        return new ResponseWatcher(limits, nano::get, () -> 1_000_000 + TimeUnit.NANOSECONDS.toMillis(nano.get()));
    }
    private void advance(long millis) { nano.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)); }
    private static Limits limits(long bytes, Circuit5xx circuit) {
        return new Limits(1000,1000,Map.of(),100,100,1000,1000,1000,
                bytes,60_000,circuit,null,0,false,List.of(),List.of());
    }
    private static RequestData request(String target) {
        return new RequestData("GET","https://owned.test"+target,"owned.test",443,true,
                List.of(),new byte[0],true,true,target);
    }
    private static ResponseWatcher.Endpoint endpoint(ResponseWatcher w, String target) {
        RequestData r=request(target);
        return w.endpoint(r,PolicyEngine.routingPaths(r));
    }
    private static long metric(ResponseWatcher w,String key) { return ((Number)w.snapshot().get(key)).longValue(); }
    private static long metric(RateGate gate,String key) { return ((Number)gate.snapshot().get(key)).longValue(); }
    private static GuardConfig policy(Limits limits) {
        return new GuardConfig(2,List.of(new ScopeEntry(true,"owned.test","https",443,"")),List.of(),List.of(),Mode.ALLOW,limits);
    }
    private static final class Projects implements ProjectAccess {
        String id="a";String document;
        Projects(Limits limits){document=PolicyCodec.encode(policy(limits));}
        public Ref current(){return new Ref(id,"Synthetic project");}
        public String load(){return document;}
        public void save(String replacement){document=replacement;}
    }

    @Test void lateHeavyScalarStillCreatesOverlayAndIsObservedOnce() throws Exception {
        ResponseWatcher w=watcher(limits(10,null));var e=endpoint(w,"/slow");var ticket=w.commit(e,false,"");
        advance(1001);assertEquals(0,metric(w,"activeTickets"));assertEquals(1,metric(w,"lateTickets"));
        w.observe(ticket,200,15_200_000);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED",w.check(e,false).reason());
        assertEquals(15_200_000,w.candidates().getFirst().maxBytes());assertEquals(0,metric(w,"lateTickets"));
        w.observe(ticket,503,30_000_000);assertEquals(1,w.candidates().getFirst().count());
    }

    @Test void lateFiveXxCountAtActualCompletionInsideResponseWindow() throws Exception {
        ResponseWatcher w=watcher(limits(0,new Circuit5xx(60_000,5,1000,1)));var e=endpoint(w,"/slow-504");
        var tickets=new java.util.ArrayList<ResponseWatcher.Ticket>();
        for(int i=0;i<5;i++)tickets.add(w.commit(e,false,""));
        advance(1001);assertEquals(5,metric(w,"lateTickets"));
        for(var ticket:tickets)w.observe(ticket,504,0);
        assertEquals("CIRCUIT_OPEN",w.check(e,false).reason());assertEquals(1,metric(w,"circuits"));
        assertEquals(5,w.candidates().getFirst().count5xx());
    }

    @Test void lateProbeCannotHealReplacementButStillContributesHeavyObservation() throws Exception {
        ResponseWatcher w=watcher(limits(10,new Circuit5xx(60_000,1,1000,1)));var e=endpoint(w,"/slow-probe");
        w.observe(w.commit(e,false,""),503,0);advance(1000);
        var old=w.commit(e,false,"");advance(1001);assertEquals(1,metric(w,"lateTickets"));
        advance(28_999);var replacement=w.commit(e,false,"");
        w.observe(old,200,11);
        assertEquals(1,metric(w,"halfOpen"));assertEquals(1,metric(w,"circuits"));
        assertTrue(w.overlays().stream().anyMatch(o->o.reason().equals("HEAVY_ENDPOINT_AUTO_BLOCKED")));
        w.cancel(replacement);
    }

    @Test void timeoutRetainsOriginalEndpointUntilCompletionAndResetInvalidatesIt() throws Exception {
        ResponseWatcher w=watcher(limits(10,null));var e=endpoint(w,"/synthetic-late-secret");var ticket=w.commit(e,false,"");
        advance(1001);w.observe(ticket,200,11);
        assertEquals(1,w.candidates().size(),"A late observation is preserved, not silently dropped");
        assertEquals("/synthetic-late-secret",w.candidates().getFirst().path());
        assertTrue(w.incidentJson(1_000_000,1_002_000).contains("/synthetic-late-secret"));
        var stale=w.commit(endpoint(w,"/different"),false,"");advance(1001);w.snapshot();w.reset();
        w.observe(stale,503,100_000);assertTrue(w.overlays().isEmpty());assertTrue(w.candidates().isEmpty());
    }

    @Test void clearBetweenCommitAndLateCompletionNeverResurrectsClearedDisplayOriginals() throws Exception {
        ResponseWatcher w=watcher(limits(10,null));var e=endpoint(w,"/synthetic-late-secret");var ticket=w.commit(e,false,"");
        advance(1001);w.clearEvidence();w.observe(ticket,200,11);
        assertEquals("HEAVY_ENDPOINT_AUTO_BLOCKED",w.check(e,false).reason(),"enforcement identity is unchanged by an explicit clear");
        assertFalse(w.overlays().toString().contains("synthetic-late-secret"));
        assertFalse(w.candidates().toString().contains("synthetic-late-secret"));
        assertFalse(w.incidentJson(1_000_000,1_002_000).contains("synthetic-late-secret"));
    }

    @Test void controllerRetainsLateObservationTicketWithoutReturningNativePermit() {
        Limits l=limits(10,null);Projects projects=new Projects(l);ResponseWatcher w=watcher(l);RateGate gate=new RateGate(l,nano::get,4096);
        try(GuardController c=new GuardController(projects,w,new IntentBudget(),gate,new ListenerRegistry(),nano::get,4096)) {
            var p=c.prepare(request("/slow"));var admission=c.authorize(p);assertTrue(admission.allowed());
            try(var permit=admission.permit()) {
                assertTrue(c.commit(p));advance(1001);var status=c.status();
                assertEquals(0,((Number)status.get("watcherTickets")).intValue());
                assertEquals(1,((Number)status.get("watcherLateTickets")).intValue());assertEquals(1,metric(gate,"active"));
                c.response(p.evidenceId(),200,List.of(),new byte[0],11);
                assertEquals(1,c.overlays().size());assertEquals(1,metric(gate,"active"),"Only real adapter completion owns this permit");
            }
            assertEquals(0,metric(gate,"active"));
        }
    }

    @Test void incompleteRawTargetsReachControllerAllPathWithoutWatcherCapacityFalseDenial() {
        Limits l=limits(0,null);Projects projects=new Projects(l);ResponseWatcher w=watcher(l);RateGate gate=new RateGate(l,nano::get,4096);
        try(GuardController c=new GuardController(projects,w,new IntentBudget(),gate,new ListenerRegistry(),nano::get,4096)) {
            for(String target:List.of("admin/x","*","@h/x","x/health","","http://other.test/x","/raw\u0081")) {
                advance(2);var p=c.prepare(request(target));var admission=c.authorize(p);assertTrue(admission.allowed(),target+": "+admission.reason());
                try(var permit=admission.permit()) {assertTrue(c.commit(p));c.response(p.evidenceId(),200,List.of(),new byte[0],0);}
                assertTrue(p.decision().inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
            }
        }
    }

    @Test void exceptionAfterRateAcquireClosesOnlyConclusiveUnsentPermit() {
        Limits l=limits(0,null);Projects projects=new Projects(l);ResponseWatcher w=spy(watcher(l));RateGate gate=new RateGate(l,nano::get,4096);
        AtomicInteger checks=new AtomicInteger();
        doAnswer(call->{if(checks.incrementAndGet()==3)throw new IllegalStateException("SYNTHETIC_CHECK_FAILURE");return call.callRealMethod();})
                .when(w).check(any(),anyBoolean());
        try(GuardController c=new GuardController(projects,w,new IntentBudget(),gate,new ListenerRegistry(),nano::get,4096)) {
            var p=c.prepare(request("/safe"));assertThrows(IllegalStateException.class,()->c.authorize(p));
            assertEquals(3,checks.get());assertEquals(1,metric(gate,"admitted"));assertEquals(0,metric(gate,"active"));
        }
    }
}
