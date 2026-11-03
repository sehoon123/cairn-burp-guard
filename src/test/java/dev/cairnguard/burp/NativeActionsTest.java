package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import static dev.cairnguard.burp.AdapterFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Verifies actual Montoya static-factory binding with Mockito. Still NOT running native Burp. */
class NativeActionsTest {
    @Test void productionFactoriesContinueOriginalObjectsAndSpoofOnlyANewLocalResponse() {
        NativeActions actions = NativeActions.montoya();
        HttpRequestToBeSent request = request(1); HttpResponseReceived response = response(1, "{}");
        Annotations annotations = request.annotations();
        RequestToBeSentAction continued = mock(RequestToBeSentAction.class), spoofed = mock(RequestToBeSentAction.class), dropped = mock(RequestToBeSentAction.class);
        ResponseReceivedAction responseAction = mock(ResponseReceivedAction.class); HttpResponse local = mock(HttpResponse.class);
        String wire = "HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n{}";
        try (MockedStatic<RequestToBeSentAction> requests = mockStatic(RequestToBeSentAction.class);
             MockedStatic<ResponseReceivedAction> responses = mockStatic(ResponseReceivedAction.class);
             MockedStatic<HttpResponse> messages = mockStatic(HttpResponse.class)) {
            requests.when(() -> RequestToBeSentAction.continueWith(request, annotations)).thenReturn(continued);
            responses.when(() -> ResponseReceivedAction.continueWith(response, response.annotations())).thenReturn(responseAction);
            messages.when(() -> HttpResponse.httpResponse(wire)).thenReturn(local);
            requests.when(() -> RequestToBeSentAction.spoof(local, annotations)).thenReturn(spoofed);
            requests.when(RequestToBeSentAction::drop).thenReturn(dropped);
            assertSame(continued, actions.continueRequest(request, annotations));
            assertSame(responseAction, actions.continueResponse(response, response.annotations()));
            assertSame(spoofed, actions.spoof(wire, annotations)); assertSame(dropped, actions.drop());
            requests.verify(() -> RequestToBeSentAction.continueWith(request, annotations));
            requests.verify(() -> RequestToBeSentAction.spoof(local, annotations)); requests.verify(RequestToBeSentAction::drop);
            responses.verify(() -> ResponseReceivedAction.continueWith(response, response.annotations())); messages.verify(() -> HttpResponse.httpResponse(wire));
            requests.verifyNoMoreInteractions(); responses.verifyNoMoreInteractions(); messages.verifyNoMoreInteractions();
        }
        verifyNoInteractions(local, annotations, response.annotations());
    }
}
