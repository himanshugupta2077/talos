package talos.burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parsed X-Talos-* grouping for one request.
 */
final class TalosTrace {
    private static final Map<String, String> ENGINE_LABELS = Map.ofEntries(
            Map.entry("findings", "Findings"),
            Map.entry("input-validation", "Input Validation"),
            Map.entry("unauth", "Unauthenticated Execution"),
            Map.entry("bac", "BAC"),
            Map.entry("auth-session", "Auth-Session Testing"),
            Map.entry("cors", "CORS Misconfiguration"),
            Map.entry("sqli", "SQL Injection"),
            Map.entry("intruder", "Intruder"),
            Map.entry("passive", "Secret Detection"),
            Map.entry("error-intel", "Error Intelligence")
    );

    final String engine;
    final String group;
    final String endpointLabel;
    final String endpointId;
    final String host;
    final String param;
    final String location;
    final String analysis;
    final String payloadType;
    final String technique;
    final String variant;
    final String detail;
    final String projectId;
    final String projectName;
    final String recordId;

    TalosTrace(
            String engine,
            String group,
            String endpointLabel,
            String endpointId,
            String host,
            String param,
            String location,
            String analysis,
            String payloadType,
            String technique,
            String variant,
            String detail
    ) {
        this(
                engine, group, endpointLabel, endpointId, host, param, location,
                analysis, payloadType, technique, variant, detail, "", "", ""
        );
    }

    TalosTrace(
            String engine,
            String group,
            String endpointLabel,
            String endpointId,
            String host,
            String param,
            String location,
            String analysis,
            String payloadType,
            String technique,
            String variant,
            String detail,
            String projectId,
            String projectName,
            String recordId
    ) {
        this.engine = engine;
        this.group = group;
        this.endpointLabel = endpointLabel;
        this.endpointId = endpointId;
        this.host = host;
        this.param = param;
        this.location = location;
        this.analysis = analysis;
        this.payloadType = payloadType;
        this.technique = technique;
        this.variant = variant;
        this.detail = detail;
        this.projectId = projectId == null ? "" : projectId;
        this.projectName = projectName == null ? "" : projectName;
        this.recordId = recordId == null ? "" : recordId;
    }

    String engineLabel() {
        return ENGINE_LABELS.getOrDefault(engine.toLowerCase(Locale.ROOT), title(engine));
    }

    String endpointKey() {
        if (!endpointId.isBlank()) {
            return engine + "|" + endpointId;
        }
        return engine + "|" + host + "|" + endpointLabel;
    }

    String summary() {
        if (detail != null && !detail.isBlank()) {
            return detail;
        }
        List<String> parts = new ArrayList<>();
        add(parts, analysis);
        add(parts, param);
        add(parts, location);
        add(parts, payloadType);
        add(parts, technique);
        add(parts, variant);
        return String.join(" · ", parts);
    }

    private static void add(List<String> parts, String value) {
        if (value != null && !value.isBlank()) {
            parts.add(value);
        }
    }

    private static String title(String token) {
        if (token == null || token.isBlank()) {
            return "Unknown";
        }
        String[] bits = token.replace('-', ' ').replace('_', ' ').split("\\s+");
        StringBuilder out = new StringBuilder();
        for (String part : bits) {
            if (part.isEmpty()) {
                continue;
            }
            if (out.length() > 0) {
                out.append(' ');
            }
            out.append(Character.toUpperCase(part.charAt(0)));
            if (part.length() > 1) {
                out.append(part.substring(1).toLowerCase(Locale.ROOT));
            }
        }
        return out.toString();
    }
}
