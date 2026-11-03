package dev.cairnguard.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Native action factories only. The seam permits in-process tests without a running Burp instance. */
public interface NativeActions {
    RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations);
    ResponseReceivedAction continueResponse(HttpResponseReceived response, Annotations annotations);
    RequestToBeSentAction spoof(String localResponse, Annotations annotations);
    RequestToBeSentAction drop();

    /** No sends, authentication/session APIs, or changes to an allowed native message. */
    static NativeActions montoya() {
        return new NativeActions() {
            @Override public RequestToBeSentAction continueRequest(HttpRequestToBeSent request, Annotations annotations) {
                return RequestToBeSentAction.continueWith(request, annotations);
            }
            @Override public ResponseReceivedAction continueResponse(HttpResponseReceived response, Annotations annotations) {
                return ResponseReceivedAction.continueWith(response, annotations);
            }
            @Override public RequestToBeSentAction spoof(String localResponse, Annotations annotations) {
                return RequestToBeSentAction.spoof(HttpResponse.httpResponse(localResponse), annotations);
            }
            @Override public RequestToBeSentAction drop() { return RequestToBeSentAction.drop(); }
        };
    }
}
