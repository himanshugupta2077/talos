package talos.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tree: Engine → Endpoint → requests. Hydrated from a Talos snapshot
 * and appended by live ingest for the bound project only.
 */
final class TalosStore {
    private final Map<Integer, RequestRecord> byMessageId = new ConcurrentHashMap<>();
    private final Map<String, RequestRecord> byRecordId = new ConcurrentHashMap<>();
    private final Map<String, EngineNode> engines = new LinkedHashMap<>();
    private final List<Listener> listeners = new ArrayList<>();
    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("Talos");
    private final DefaultTreeModel treeModel = new DefaultTreeModel(root);
    private volatile String boundProjectId = "";

    TalosStore() {
    }

    void setBoundProjectId(String projectId) {
        this.boundProjectId = projectId == null ? "" : projectId;
    }

    synchronized void addListener(Listener listener) {
        listeners.add(listener);
    }

    DefaultTreeModel treeModel() {
        return treeModel;
    }

    boolean isEmpty() {
        return byRecordId.isEmpty() && engines.isEmpty();
    }

    void replaceAll(List<RequestRecord> records) {
        Runnable apply = () -> {
            byMessageId.clear();
            byRecordId.clear();
            engines.clear();
            root.removeAllChildren();
            for (RequestRecord record : records) {
                insert(record);
            }
            treeModel.reload();
            notifyReplaced();
        };
        if (SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            SwingUtilities.invokeLater(apply);
        }
    }

    void recordRequest(int messageId, HttpRequest request, TalosTrace trace) {
        String id = (trace.recordId == null || trace.recordId.isBlank())
                ? UUID.randomUUID().toString()
                : trace.recordId;
        RequestRecord existing = byRecordId.get(id);
        RequestRecord record = new RequestRecord(
                id,
                messageId,
                existing == null ? Instant.now() : existing.capturedAt,
                request,
                trace,
                existing == null ? null : existing.response,
                existing == null ? 0 : existing.status
        );
        if (messageId >= 0) {
            byMessageId.put(messageId, record);
        }
        Runnable apply = () -> {
            if (existing != null) {
                replaceRecord(existing, record);
            } else {
                insert(record);
            }
            notifyListeners(record, false);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            SwingUtilities.invokeLater(apply);
        }
    }

    /**
     * Index a later Burp message id onto an already-recorded request.
     * Proxy and HTTP handlers use different id spaces; this links them.
     */
    void indexRequest(int messageId, HttpRequest request) {
        if (messageId < 0 || request == null) {
            return;
        }
        Runnable apply = () -> {
            if (byMessageId.containsKey(messageId)) {
                return;
            }
            RequestRecord match = findUnpaired(request);
            if (match != null) {
                byMessageId.put(messageId, match);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            SwingUtilities.invokeLater(apply);
        }
    }

    void recordResponse(int messageId, HttpResponse response) {
        recordResponse(messageId, response, null);
    }

    void recordResponse(int messageId, HttpResponse response, HttpRequest initiatingRequest) {
        if (response == null) {
            return;
        }
        Runnable apply = () -> {
            RequestRecord record = messageId >= 0 ? byMessageId.get(messageId) : null;
            if (record == null && initiatingRequest != null) {
                record = findUnpaired(initiatingRequest);
                if (record != null && messageId >= 0) {
                    byMessageId.put(messageId, record);
                }
            }
            if (record == null) {
                return;
            }
            boolean hadResponse = record.response != null;
            record.response = response;
            record.status = response.statusCode();
            if (record.endpoint != null) {
                record.endpoint.refreshLabel();
                treeModel.nodeChanged(record.endpoint.treeNode);
            }
            if (!hadResponse) {
                persistResponse(record);
            }
            notifyListeners(record, true);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            SwingUtilities.invokeLater(apply);
        }
    }

    /**
     * Fold snapshot rows into the live tree. New records are added;
     * incoming responses fill empty slots. Existing live responses stay.
     */
    void mergeFrom(List<RequestRecord> records) {
        if (records == null || records.isEmpty()) {
            return;
        }
        Runnable apply = () -> {
            for (RequestRecord next : records) {
                if (next == null || next.recordId == null || next.recordId.isBlank()) {
                    continue;
                }
                RequestRecord existing = byRecordId.get(next.recordId);
                if (existing == null) {
                    insert(next);
                    notifyListeners(next, false);
                    continue;
                }
                boolean changed = false;
                if (existing.response == null && next.response != null) {
                    existing.response = next.response;
                    changed = true;
                }
                if (next.status > 0 && existing.status != next.status) {
                    existing.status = next.status;
                    changed = true;
                }
                if (changed) {
                    if (existing.endpoint != null) {
                        existing.endpoint.refreshLabel();
                        treeModel.nodeChanged(existing.endpoint.treeNode);
                    }
                    notifyListeners(existing, true);
                }
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            SwingUtilities.invokeLater(apply);
        }
    }

    synchronized List<RequestRecord> requestsFor(Object nodeUserObject) {
        if (nodeUserObject instanceof EndpointNode endpoint) {
            return List.copyOf(endpoint.requests);
        }
        if (nodeUserObject instanceof EngineNode engine) {
            List<RequestRecord> all = new ArrayList<>();
            for (EndpointNode endpoint : engine.endpoints.values()) {
                all.addAll(endpoint.requests);
            }
            all.sort(Comparator.comparing(r -> r.capturedAt));
            return all;
        }
        return List.of();
    }

    private void insert(RequestRecord record) {
        TalosTrace trace = record.trace;
        boolean newEngine = !engines.containsKey(trace.engine);
        EngineNode engine = engines.computeIfAbsent(trace.engine, token -> {
            EngineNode node = new EngineNode(token, trace.engineLabel());
            if ("findings".equalsIgnoreCase(token)) {
                root.insert(node.treeNode, 0);
            } else {
                root.add(node.treeNode);
            }
            return node;
        });
        boolean newEndpoint = !engine.endpoints.containsKey(trace.endpointKey());
        EndpointNode endpoint = engine.endpoints.computeIfAbsent(trace.endpointKey(), key -> {
            EndpointNode node = new EndpointNode(key, trace.endpointLabel, trace.endpointId);
            engine.treeNode.add(node.treeNode);
            return node;
        });
        endpoint.requests.add(record);
        record.endpoint = endpoint;
        byRecordId.put(record.recordId, record);
        endpoint.refreshLabel();
        if (newEngine) {
            treeModel.nodesWereInserted(root, new int[]{root.getIndex(engine.treeNode)});
        } else if (newEndpoint) {
            treeModel.nodesWereInserted(engine.treeNode, new int[]{engine.treeNode.getIndex(endpoint.treeNode)});
        } else {
            treeModel.nodeChanged(endpoint.treeNode);
        }
    }

    private void replaceRecord(RequestRecord previous, RequestRecord next) {
        byRecordId.put(next.recordId, next);
        if (previous.endpoint == null) {
            insert(next);
            return;
        }
        List<RequestRecord> list = previous.endpoint.requests;
        int index = list.indexOf(previous);
        if (index >= 0) {
            list.set(index, next);
        } else {
            list.add(next);
        }
        next.endpoint = previous.endpoint;
        previous.endpoint.refreshLabel();
        treeModel.nodeChanged(previous.endpoint.treeNode);
    }

    private RequestRecord findUnpaired(HttpRequest request) {
        String method = request.method() == null ? "" : request.method();
        String path = normalizePath(request.pathWithoutQuery());
        String host = hostOf(request);
        RequestRecord best = null;
        for (RequestRecord candidate : byRecordId.values()) {
            if (candidate.response != null) {
                continue;
            }
            String candidateMethod = candidate.request.method() == null
                    ? ""
                    : candidate.request.method();
            if (!method.equalsIgnoreCase(candidateMethod)) {
                continue;
            }
            if (!path.equals(normalizePath(candidate.request.pathWithoutQuery()))) {
                continue;
            }
            String candidateHost = hostOf(candidate.request);
            if (!host.isEmpty() && !candidateHost.isEmpty()
                    && !host.equalsIgnoreCase(candidateHost)) {
                continue;
            }
            if (best == null || candidate.capturedAt.isBefore(best.capturedAt)) {
                best = candidate;
            }
        }
        return best;
    }

    private static String hostOf(HttpRequest request) {
        if (request.httpService() != null && request.httpService().host() != null) {
            return request.httpService().host().trim();
        }
        return "";
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        String trimmed = path.trim();
        int q = trimmed.indexOf('?');
        if (q >= 0) {
            trimmed = trimmed.substring(0, q);
        }
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed;
        }
        return trimmed;
    }

    private void persistResponse(RequestRecord record) {
        String projectId = boundProjectId;
        if (projectId.isBlank() || record.response == null) {
            return;
        }
        String recordId = record.recordId;
        int status = record.status;
        HttpResponse response = record.response;
        Thread writer = new Thread(
                () -> TalosSnapshots.appendResponse(projectId, recordId, status, response),
                "talos-burp-snapshot"
        );
        writer.setDaemon(true);
        writer.start();
    }

    private void notifyListeners(RequestRecord record, boolean responseOnly) {
        for (Listener listener : List.copyOf(listeners)) {
            listener.storeUpdated(record, responseOnly);
        }
    }

    private void notifyReplaced() {
        for (Listener listener : List.copyOf(listeners)) {
            listener.storeReplaced();
        }
    }

    interface Listener {
        void storeUpdated(RequestRecord record, boolean responseOnly);

        default void storeReplaced() {
        }
    }

    static final class EngineNode {
        final String token;
        final String label;
        final Map<String, EndpointNode> endpoints = new LinkedHashMap<>();
        final DefaultMutableTreeNode treeNode;

        EngineNode(String token, String label) {
            this.token = token;
            this.label = label;
            this.treeNode = new DefaultMutableTreeNode(this);
        }

        @Override
        public String toString() {
            return label;
        }
    }

    static final class EndpointNode {
        final String key;
        final String label;
        final String endpointId;
        final List<RequestRecord> requests = new ArrayList<>();
        final DefaultMutableTreeNode treeNode;

        EndpointNode(String key, String label, String endpointId) {
            this.key = key;
            this.label = label;
            this.endpointId = endpointId;
            this.treeNode = new DefaultMutableTreeNode(this);
        }

        void refreshLabel() {
            treeNode.setUserObject(this);
        }

        @Override
        public String toString() {
            return label + " (" + requests.size() + ")";
        }
    }

    static final class RequestRecord {
        final String recordId;
        final int messageId;
        final Instant capturedAt;
        final HttpRequest request;
        final TalosTrace trace;
        HttpResponse response;
        int status;
        EndpointNode endpoint;

        RequestRecord(
                String recordId,
                int messageId,
                Instant capturedAt,
                HttpRequest request,
                TalosTrace trace,
                HttpResponse response,
                int status
        ) {
            this.recordId = recordId;
            this.messageId = messageId;
            this.capturedAt = capturedAt;
            this.request = request;
            this.trace = trace;
            this.response = response;
            this.status = status;
        }
    }

    static Object userObject(TreeNode node) {
        if (node instanceof DefaultMutableTreeNode treeNode) {
            return treeNode.getUserObject();
        }
        return null;
    }
}
