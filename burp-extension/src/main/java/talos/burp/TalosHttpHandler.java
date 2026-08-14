package talos.burp;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

/**
 * Last-mile strip: every Burp tool's outbound request is cleaned of
 * X-Talos-* before it leaves for the target. Grouping is done by the
 * proxy handler, which sees the headers first.
 *
 * Also records the HTTP response. Proxy and HTTP message ids are
 * different spaces; indexRequest links them so the Talos tab can
 * show status + body.
 */
final class TalosHttpHandler implements HttpHandler {
    private final TalosStore store;

    TalosHttpHandler(TalosStore store) {
        this.store = store;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        store.indexRequest(request.messageId(), request);
        if (!TalosHeaders.hasMetadata(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        return RequestToBeSentAction.continueWith(TalosHeaders.strip(request));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        store.recordResponse(response.messageId(), response, response.initiatingRequest());
        return ResponseReceivedAction.continueWith(response);
    }
}
