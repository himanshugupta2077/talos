package talos.burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Traces posted by Talos over the localhost ingest server, waiting
 * to be claimed by the next matching proxy request.
 */
final class TalosIngestQueue {
    private static final long TTL_MS = 30_000L;

    private final List<Entry> entries = new ArrayList<>();

    synchronized void offer(String jsonBody) {
        Map<String, String> fields = TalosJson.parseFlatObject(jsonBody);
        String engine = value(fields, "engine");
        String endpoint = value(fields, "endpoint");
        if (engine.isEmpty() || endpoint.isEmpty()) {
            return;
        }
        pruneLocked();
        entries.add(new Entry(
                new TalosTrace(
                        engine,
                        orDefault(value(fields, "group"), "endpoints"),
                        endpoint,
                        value(fields, "endpoint_id"),
                        value(fields, "host"),
                        value(fields, "param"),
                        value(fields, "location"),
                        value(fields, "analysis"),
                        value(fields, "payload_type"),
                        value(fields, "technique"),
                        value(fields, "variant"),
                        value(fields, "detail"),
                        value(fields, "project_id"),
                        value(fields, "project_name"),
                        value(fields, "record_id")
                ),
                value(fields, "method"),
                value(fields, "host"),
                normalizePath(value(fields, "path")),
                System.currentTimeMillis()
        ));
    }

    synchronized Optional<TalosTrace> claim(HttpRequest request) {
        pruneLocked();
        String method = request.method() == null ? "" : request.method();
        String path = normalizePath(request.pathWithoutQuery());
        String host = hostFromRequest(request);
        for (Iterator<Entry> it = entries.iterator(); it.hasNext(); ) {
            Entry entry = it.next();
            if (entry.matches(method, host, path)) {
                it.remove();
                return Optional.of(entry.trace);
            }
        }
        return Optional.empty();
    }

    private void pruneLocked() {
        long cutoff = System.currentTimeMillis() - TTL_MS;
        entries.removeIf(entry -> entry.createdAt < cutoff);
    }

    static String hostFromRequest(HttpRequest request) {
        HttpService service = request.httpService();
        if (service == null || service.host() == null || service.host().isBlank()) {
            return "";
        }
        String host = service.host().trim();
        int port = service.port();
        if (port > 0 && port != 80 && port != 443) {
            return host + ":" + port;
        }
        return host;
    }

    static String normalizePath(String path) {
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

    static boolean hostsEqual(String left, String right) {
        if (left.equalsIgnoreCase(right)) {
            return true;
        }
        HostPort a = HostPort.parse(left);
        HostPort b = HostPort.parse(right);
        if (!a.host.equalsIgnoreCase(b.host)) {
            return false;
        }
        return a.port.isEmpty() || b.port.isEmpty() || a.port.equals(b.port);
    }

    private static String value(Map<String, String> fields, String key) {
        String raw = fields.get(key);
        return raw == null ? "" : raw.trim();
    }

    private static String orDefault(String value, String fallback) {
        return value.isEmpty() ? fallback : value;
    }

    private static final class Entry {
        final TalosTrace trace;
        final String method;
        final String host;
        final String path;
        final long createdAt;

        Entry(TalosTrace trace, String method, String host, String path, long createdAt) {
            this.trace = trace;
            this.method = method;
            this.host = host;
            this.path = path;
            this.createdAt = createdAt;
        }

        boolean matches(String method, String host, String path) {
            if (!this.method.isEmpty() && !this.method.equalsIgnoreCase(method)) {
                return false;
            }
            if (!this.path.isEmpty() && !this.path.equals(path)) {
                return false;
            }
            return this.host.isEmpty() || hostsEqual(this.host, host);
        }
    }

    private static final class HostPort {
        final String host;
        final String port;

        HostPort(String host, String port) {
            this.host = host;
            this.port = port;
        }

        static HostPort parse(String raw) {
            String text = raw == null ? "" : raw.trim();
            if (text.startsWith("[")) {
                int close = text.indexOf(']');
                if (close > 0) {
                    String host = text.substring(1, close);
                    String port = "";
                    if (close + 1 < text.length() && text.charAt(close + 1) == ':') {
                        port = text.substring(close + 2);
                    }
                    return new HostPort(host, port);
                }
            }
            int colon = text.lastIndexOf(':');
            if (colon > 0 && text.indexOf(':') == colon) {
                return new HostPort(
                        text.substring(0, colon),
                        text.substring(colon + 1)
                );
            }
            return new HostPort(text.toLowerCase(Locale.ROOT), "");
        }
    }
}
