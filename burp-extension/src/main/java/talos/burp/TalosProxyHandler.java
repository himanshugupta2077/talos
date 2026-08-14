package talos.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.Optional;

/**
 * Reads X-Talos-* on proxy-received requests, records the stripped copy,
 * and continues with headers removed so HTTP history never keeps them.
 * The HTTP handler does the last-mile strip before the target.
 */
final class TalosProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final TalosStore store;
    private final TalosIngestQueue ingest;
    private final TalosProjectSession session;

    TalosProxyHandler(TalosStore store, TalosIngestQueue ingest, TalosProjectSession session) {
        this.store = store;
        this.ingest = ingest;
        this.session = session;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        HttpRequest outbound = TalosHeaders.hasMetadata(request)
                ? TalosHeaders.strip(request)
                : request;
        Optional<TalosTrace> trace = TalosHeaders.parse(request);
        if (trace.isEmpty()) {
            trace = ingest.claim(request);
        }
        trace.ifPresent(found -> {
            if (session.accept(found)) {
                store.recordRequest(request.messageId(), outbound, found);
            }
        });
        return ProxyRequestReceivedAction.continueWith(outbound);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        if (TalosHeaders.hasMetadata(request)) {
            return ProxyRequestToBeSentAction.continueWith(TalosHeaders.strip(request));
        }
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        store.recordResponse(response.messageId(), response, response.initiatingRequest());
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }
}
