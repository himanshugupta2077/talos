package talos.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Talos Burp Suite extension.
 *
 * Groups Talos attack traffic into Engine → Endpoint. Preferred path
 * is a localhost ingest (no X-Talos-* on the proxied request) because
 * Burp HTTP history always keeps the original inbound headers.
 * Legacy X-Talos-* headers are still parsed and stripped.
 */
public final class TalosBurpExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Talos");
        TalosPersistence persistence = new TalosPersistence(api.persistence().extensionData());
        TalosStore store = new TalosStore();
        TalosProjectSession session = new TalosProjectSession(persistence, store);
        session.restore();
        TalosIngestQueue ingest = new TalosIngestQueue();
        TalosIngestServer server = new TalosIngestServer(
                ingest,
                message -> api.logging().logToOutput(message)
        );
        TalosSnapshotWatcher watcher = new TalosSnapshotWatcher(session);
        try {
            server.start();
        } catch (Throwable exc) {
            api.logging().logToError("Talos ingest failed to start: " + exc);
        }
        watcher.start();
        api.extension().registerUnloadingHandler(() -> {
            watcher.stop();
            server.stop();
        });
        TalosProxyHandler proxyHandler = new TalosProxyHandler(store, ingest, session);
        api.userInterface().registerSuiteTab("Talos", new TalosSuiteTab(api, store, session));
        api.proxy().registerRequestHandler(proxyHandler);
        api.proxy().registerResponseHandler(proxyHandler);
        // Last-mile strip if an older Talos still stamps X-Talos-*.
        // Also attaches the HTTP response (proxy and HTTP message ids differ).
        api.http().registerHttpHandler(new TalosHttpHandler(store));
        api.logging().logToOutput("Talos extension loaded. Snapshot auto-refresh is on.");
    }
}
