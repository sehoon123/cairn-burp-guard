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

/** Offline observational scalar/epoch regressions; NOT native Burp evidence. */
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

    @Test void lateHeavyAndFiveXxAreObservationsOnlyAndNeverAnAdmissionGate() {
        ResponseWatcher w=watcher(limits(1,new Circuit5xx(60_000,1,1000,1)));
        var endpoint=endpoint(w,"/slow"); advance(60_001);
        w.observe(endpoint,500,15_200_000);
        assertEquals(15_200_000,w.candidates().getFirst().maxBytes());
        assertEquals(1,w.candidates().getFirst().count5xx());
        assertTrue(w.incidentJson(1_000_000,1_100_000).contains("/slow"));
    }
    @Test void clearResetAndForeignEndpointsCannotResurrectOriginals() {
        ResponseWatcher w=watcher(limits(1,null)); var old=endpoint(w,"/secret");
        w.clearEvidence(); w.observe(old,500,20); assertTrue(w.candidates().isEmpty());
        var current=endpoint(w,"/current"); w.reset(); w.observe(current,500,20);
        assertTrue(w.candidates().isEmpty());
        var foreign=watcher(limits(1,null)); w.observe(endpoint(foreign,"/foreign"),500,20);
        assertTrue(w.candidates().isEmpty());
    }
    @Test void incompleteRawTargetsReachControllerAllPathWithoutObservationalFalseDenial() {
        Limits l=limits(0,null); Projects projects=new Projects(l); ResponseWatcher w=watcher(l);
        try(var c=new GuardController(projects,w,new IntentBudget(),new RateGate(l,nano::get,4096),new ListenerRegistry())) {
            for(String target:List.of("admin/x","*","@h/x","x/health","","http://other.test/x","/raw\u0081")) {
                advance(2); var p=c.prepare(request(target)); assertTrue(c.authorize(p).allowed());
                assertTrue(c.commit(p)); c.response(p.evidenceId(),200,List.of(),new byte[0],0);
                assertTrue(p.decision().inspectionWarnings().contains("PATH_INTERPRETATION_INCOMPLETE"));
            }
        }
    }
}
