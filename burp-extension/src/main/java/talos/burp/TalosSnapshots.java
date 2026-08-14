package talos.burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reads Talos-owned per-project snapshots from ~/.talos/burp/*.jsonl.
 */
final class TalosSnapshots {
    private TalosSnapshots() {
    }

    static Path root() {
        return Path.of(System.getProperty("user.home"), ".talos", "burp");
    }

    static List<ProjectRef> listProjects() {
        List<ProjectRef> found = new ArrayList<>();
        Path dir = root();
        if (!Files.isDirectory(dir)) {
            return found;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.jsonl")) {
            for (Path file : stream) {
                ProjectRef ref = readMeta(file);
                if (ref != null) {
                    found.add(ref);
                }
            }
        } catch (IOException ignored) {
            return found;
        }
        found.sort(Comparator
                .comparing((ProjectRef item) -> item.name.toLowerCase(Locale.ROOT))
                .thenComparing(item -> item.projectId));
        return found;
    }

    static List<TalosStore.RequestRecord> load(String projectId) {
        List<TalosStore.RequestRecord> records = new ArrayList<>();
        Path file = fileFor(projectId);
        if (file == NonePath() || !Files.isRegularFile(file)) {
            return records;
        }
        Map<String, TalosStore.RequestRecord> byId = new LinkedHashMap<>();
        List<Map<String, String>> responses = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                Map<String, String> row = TalosJson.parseFlatObject(line);
                String kind = row.getOrDefault("kind", "");
                if ("record".equals(kind)) {
                    TalosStore.RequestRecord record = toRecord(row);
                    if (record != null) {
                        records.add(record);
                        byId.put(record.recordId, record);
                    }
                } else if ("response".equals(kind)) {
                    responses.add(row);
                }
            }
        } catch (IOException ignored) {
            return records;
        }
        for (Map<String, String> row : responses) {
            String id = firstNonBlank(row.get("record_id"), row.get("id"));
            TalosStore.RequestRecord record = byId.get(id);
            if (record == null) {
                continue;
            }
            int status = parseInt(row.get("status"));
            if (status > 0) {
                record.status = status;
            }
            HttpResponse response = toResponse(row.get("response_http"), record.status);
            if (response != null) {
                record.response = response;
                if (record.status == 0) {
                    record.status = response.statusCode();
                }
            }
        }
        return records;
    }

    static void appendResponse(String projectId, String recordId, int status, HttpResponse response) {
        Path file = fileFor(projectId);
        if (file.equals(NonePath()) || recordId == null || recordId.isBlank() || response == null) {
            return;
        }
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            String raw = toRawResponse(response);
            String line = "{\"kind\":\"response\",\"id\":\"" + escapeJson(recordId)
                    + "\",\"record_id\":\"" + escapeJson(recordId)
                    + "\",\"status\":\"" + status
                    + "\",\"response_http\":\"" + escapeJson(raw) + "\"}\n";
            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Snapshot write is best-effort.
        }
    }

    static String displayName(String projectId) {
        for (ProjectRef ref : listProjects()) {
            if (ref.projectId.equals(projectId)) {
                return ref.name;
            }
        }
        return projectId;
    }

    static Path fileFor(String projectId) {
        String id = safeId(projectId);
        if (id.isEmpty()) {
            return NonePath();
        }
        return root().resolve(id + ".jsonl");
    }

    static String safeId(String projectId) {
        if (projectId == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < projectId.length() && out.length() < 128; i++) {
            char c = projectId.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-') {
                out.append(c);
            }
        }
        String cleaned = out.toString();
        if (cleaned.isEmpty() || cleaned.equals(".") || cleaned.equals("..") || cleaned.startsWith(".")) {
            return "";
        }
        return cleaned;
    }

    private static Path NonePath() {
        return Path.of("");
    }

    private static ProjectRef readMeta(Path file) {
        String stem = file.getFileName().toString();
        if (stem.endsWith(".jsonl")) {
            stem = stem.substring(0, stem.length() - 6);
        }
        String id = safeId(stem);
        String name = id;
        int count = 0;
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                Map<String, String> row = TalosJson.parseFlatObject(line);
                String kind = row.getOrDefault("kind", "");
                if ("meta".equals(kind)) {
                    String metaId = safeId(row.getOrDefault("project_id", ""));
                    if (!metaId.isEmpty()) {
                        id = metaId;
                    }
                    String metaName = row.getOrDefault("project_name", "").trim();
                    if (!metaName.isEmpty()) {
                        name = metaName;
                    }
                } else if ("record".equals(kind)) {
                    count += 1;
                }
            }
        } catch (IOException ignored) {
            return null;
        }
        if (id.isEmpty()) {
            return null;
        }
        return new ProjectRef(id, name.isEmpty() ? id : name, count);
    }

    private static TalosStore.RequestRecord toRecord(Map<String, String> row) {
        String engine = nz(row.get("engine"));
        String endpoint = nz(row.get("endpoint"));
        if (engine.isEmpty() || endpoint.isEmpty()) {
            return null;
        }
        TalosTrace trace = new TalosTrace(
                engine,
                orDefault(row.get("group"), "endpoints"),
                endpoint,
                nz(row.get("endpoint_id")),
                nz(row.get("host")),
                nz(row.get("param")),
                nz(row.get("location")),
                nz(row.get("analysis")),
                nz(row.get("payload_type")),
                nz(row.get("technique")),
                nz(row.get("variant")),
                nz(row.get("detail")),
                nz(row.get("project_id")),
                nz(row.get("project_name")),
                firstNonBlank(row.get("record_id"), row.get("id"))
        );
        HttpRequest request = toRequest(row);
        if (request == null) {
            return null;
        }
        String id = firstNonBlank(row.get("id"), row.get("record_id"));
        if (id.isEmpty()) {
            id = java.util.UUID.randomUUID().toString();
        }
        long epoch = parseLong(row.get("captured_at"));
        Instant when = epoch > 0 ? Instant.ofEpochMilli(epoch) : Instant.now();
        int status = parseInt(row.get("status"));
        HttpResponse response = toResponse(row.get("response_http"), status);
        return new TalosStore.RequestRecord(id, -1, when, request, trace, response, status);
    }

    private static HttpResponse toResponse(String raw, int status) {
        String text = raw == null ? "" : raw;
        if (text.isBlank()) {
            if (status <= 0) {
                return null;
            }
            text = "HTTP/1.1 " + status + " \r\n\r\n";
        }
        try {
            return HttpResponse.httpResponse(text);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String toRawResponse(HttpResponse response) {
        String version = response.httpVersion() == null ? "HTTP/1.1" : response.httpVersion();
        if (!version.toUpperCase(Locale.ROOT).startsWith("HTTP")) {
            version = "HTTP/1.1";
        }
        StringBuilder raw = new StringBuilder();
        raw.append(version).append(' ').append(response.statusCode()).append(" \r\n");
        for (HttpHeader header : response.headers()) {
            raw.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        raw.append("\r\n");
        String body = response.bodyToString();
        if (body != null && !body.isEmpty()) {
            raw.append(body);
        }
        return raw.toString();
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 32) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static HttpRequest toRequest(Map<String, String> row) {
        String raw = withHeaderTerminator(rawHttp(row.get("request_http")));
        if (raw.isEmpty()) {
            raw = synthesize(row);
        }
        String host = hostOnly(nz(row.get("host")));
        boolean secure = isTrue(row.get("secure")) || looksHttps(row.get("url"));
        int port = parseInt(row.get("port"));
        if (port <= 0) {
            port = portFromHost(nz(row.get("host")), secure);
        }
        try {
            if (!host.isEmpty()) {
                return HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw);
            }
            return HttpRequest.httpRequest(raw);
        } catch (RuntimeException ignored) {
            // Origin-as-host (http://example:3000) used to fail HttpService
            // and fall back to a method+Host stub, dropping the real headers.
            try {
                return HttpRequest.httpRequest(raw);
            } catch (RuntimeException failedRaw) {
                try {
                    return HttpRequest.httpRequest(synthesize(row));
                } catch (RuntimeException failed) {
                    return null;
                }
            }
        }
    }

    private static String synthesize(Map<String, String> row) {
        String method = orDefault(row.get("method"), "GET").toUpperCase(Locale.ROOT);
        String path = nz(row.get("path"));
        if (path.isEmpty()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        String host = nz(row.get("host"));
        StringBuilder raw = new StringBuilder();
        raw.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        if (!host.isEmpty()) {
            raw.append("Host: ").append(host).append("\r\n");
        }
        raw.append("\r\n\r\n");
        return raw.toString();
    }

    /**
     * Snapshot request_http must keep trailing CRLFs. {@link #nz} trims
     * them, which is why bodyless GETs (unauth strip, empty Authorization)
     * arrived in Repeater without a header terminator.
     */
    private static String rawHttp(String value) {
        return value == null ? "" : value;
    }

    /**
     * Bodyless requests end with two blank lines so Burp Repeater accepts
     * an empty last header. Requests that already have a body are unchanged.
     */
    private static String withHeaderTerminator(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String normalized = raw.replace("\r\n", "\n").replace('\r', '\n');
        int sep = normalized.indexOf("\n\n");
        if (sep >= 0) {
            String after = normalized.substring(sep + 2);
            if (!after.isEmpty()) {
                return raw;
            }
        }
        int end = raw.length();
        while (end > 0 && Character.isWhitespace(raw.charAt(end - 1))) {
            end -= 1;
        }
        return raw.substring(0, end) + "\r\n\r\n\r\n";
    }

    private static String hostOnly(String host) {
        String text = stripScheme(host.trim());
        if (text.startsWith("[")) {
            int close = text.indexOf(']');
            if (close > 0) {
                return text.substring(1, close);
            }
        }
        int slash = text.indexOf('/');
        if (slash >= 0) {
            text = text.substring(0, slash);
        }
        int colon = text.lastIndexOf(':');
        if (colon > 0 && text.indexOf(':') == colon) {
            return text.substring(0, colon);
        }
        return text;
    }

    private static int portFromHost(String host, boolean secure) {
        String text = stripScheme(host.trim());
        int slash = text.indexOf('/');
        if (slash >= 0) {
            text = text.substring(0, slash);
        }
        int colon = text.lastIndexOf(':');
        if (colon > 0 && text.indexOf(':') == colon) {
            try {
                return Integer.parseInt(text.substring(colon + 1));
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return secure ? 443 : 80;
    }

    private static String stripScheme(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        if (lower.startsWith("https://")) {
            return host.substring(8);
        }
        if (lower.startsWith("http://")) {
            return host.substring(7);
        }
        return host;
    }

    private static boolean looksHttps(String url) {
        return url != null && url.toLowerCase(Locale.ROOT).startsWith("https://");
    }

    private static boolean isTrue(String value) {
        if (value == null) {
            return false;
        }
        String text = value.trim();
        return "1".equals(text) || "true".equalsIgnoreCase(text);
    }

    private static String nz(String value) {
        return value == null ? "" : value.trim();
    }

    private static String orDefault(String value, String fallback) {
        String text = nz(value);
        return text.isEmpty() ? fallback : text;
    }

    private static String firstNonBlank(String left, String right) {
        if (left != null && !left.isBlank()) {
            return left.trim();
        }
        if (right != null && !right.isBlank()) {
            return right.trim();
        }
        return "";
    }

    private static long parseLong(String value) {
        if (value == null || value.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    private static int parseInt(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    static final class ProjectRef {
        final String projectId;
        final String name;
        final int records;

        ProjectRef(String projectId, String name, int records) {
            this.projectId = projectId;
            this.name = name;
            this.records = records;
        }

        @Override
        public String toString() {
            if (name.equals(projectId)) {
                return projectId + " (" + records + ")";
            }
            return name + " — " + projectId + " (" + records + ")";
        }
    }
}
