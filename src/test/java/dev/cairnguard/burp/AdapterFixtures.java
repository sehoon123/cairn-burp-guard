package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import dev.cairnguard.model.GuardConfig;
import dev.cairnguard.model.GuardConfig.Limits;
import dev.cairnguard.model.GuardConfig.Mode;
import dev.cairnguard.model.GuardConfig.ScopeEntry;
import dev.cairnguard.model.Json;
import dev.cairnguard.runtime.GuardController;
import dev.cairnguard.runtime.ProjectAccess;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Synthetic Mockito/native-action fixtures, NOT a running Burp integration. Never opens sockets. */
final class AdapterFixtures {
    private AdapterFixtures() {}
    static final class MemoryProject implements ProjectAccess {
        volatile Ref ref = new Ref("fixture-project", "Synthetic project");
        volatile String json;
        MemoryProject(GuardConfig config) { json = Json.write(config); }
        @Override public Ref current() { return ref; }
        @Override public String load() { return json; }
        @Override public void save(String value) { json = value; }
    }
    static GuardConfig config(Mode mode, int maxConcurrent, long requestTimeout) {
        return new GuardConfig(1, List.of(new ScopeEntry(true, "example.test", "https", 443, "/.*")), List.of(), List.of(), mode,
                new Limits(1_000, 1_000, Map.of(), maxConcurrent, 128, 500, 5_000, requestTimeout));
    }
    static GuardController controller() { return new GuardController(new MemoryProject(config(Mode.ALLOW, 5, 60_000))); }
    private record HeaderValue(String name, String value) implements HttpHeader {}
    static HttpHeader header(String name, String value) { return new HeaderValue(name, value); }
    static ByteArray bytes(byte[] body) {
        ByteArray result = mock(ByteArray.class);
        when(result.length()).thenReturn(body.length); when(result.getBytes()).thenReturn(body.clone());
        return result;
    }
    private record SourceValue(ToolType toolType) implements ToolSource {
        @Override public boolean isFromTool(ToolType... types) { return java.util.Arrays.asList(types).contains(toolType); }
    }
    static ToolSource source(ToolType type) { return new SourceValue(type); }
    static HttpRequestToBeSent request(int id) {
        HttpRequestToBeSent result = mock(HttpRequestToBeSent.class);
        when(result.messageId()).thenReturn(id); when(result.toolSource()).thenReturn(source(ToolType.PROXY));
        doReturn(mock(Annotations.class)).when(result).annotations();
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("example.test"); when(service.port()).thenReturn(443); when(service.secure()).thenReturn(true);
        when(result.httpService()).thenReturn(service); when(result.method()).thenReturn("GET");
        when(result.url()).thenReturn("https://example.test/safe"); when(result.path()).thenReturn("/safe");
        when(result.httpVersion()).thenReturn("HTTP/1.1");
        when(result.headers()).thenReturn(List.of(header("Host", "example.test"), header("Authorization", "Bearer SYNTHETIC-SECRET")));
        doReturn(bytes(new byte[0])).when(result).body();
        return result;
    }
    static HttpResponseReceived response(int id, String body) {
        HttpResponseReceived result = mock(HttpResponseReceived.class);
        when(result.messageId()).thenReturn(id); when(result.toolSource()).thenReturn(source(ToolType.PROXY));
        doReturn(mock(Annotations.class)).when(result).annotations(); when(result.statusCode()).thenReturn((short) 200);
        when(result.headers()).thenReturn(List.of(header("Content-Type", "application/json")));
        doReturn(bytes(body.getBytes(StandardCharsets.UTF_8))).when(result).body();
        return result;
    }
    static final record RequestResult(RequestAction action, HttpRequest request, Annotations annotations) implements RequestToBeSentAction {}
    static final record ResponseResult(HttpResponse response, Annotations annotations) implements ResponseReceivedAction {
        @Override public ResponseAction action() { return ResponseAction.CONTINUE; }
    }
    static class Actions implements NativeActions {
        volatile String local;
        volatile int drops;
        @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) {
            return new RequestResult(RequestAction.CONTINUE, request, annotations);
        }
        @Override public ResponseReceivedAction continueResponse(HttpResponseReceived response, Annotations annotations) {
            return new ResponseResult(response, annotations);
        }
        @Override public RequestToBeSentAction spoof(String localResponse, Annotations annotations) {
            local = localResponse; return new RequestResult(RequestAction.SPOOF_RESPONSE, null, annotations);
        }
        @Override public RequestToBeSentAction drop() { drops++; return new RequestResult(RequestAction.DROP, null, null); }
    }
    @SuppressWarnings("unchecked") static Map<String,Object> gate(GuardController controller) {
        return (Map<String,Object>) controller.status().get("gate");
    }
}
