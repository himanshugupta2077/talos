package talos.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Header contract shared with talos.burp.headers (default prefix X-Talos).
 *
 * The extension reads these, groups the request, then strips every
 * {prefix}-* header so HTTP history, the Talos viewers, and the
 * target never keep the metadata.
 */
final class TalosHeaders {
    static final String DEFAULT_PREFIX = "X-Talos";

    static final String SUFFIX_ENGINE = "Engine";
    static final String SUFFIX_GROUP = "Group";
    static final String SUFFIX_ENDPOINT = "Endpoint";
    static final String SUFFIX_ENDPOINT_ID = "Endpoint-Id";
    static final String SUFFIX_HOST = "Host";
    static final String SUFFIX_PARAM = "Param";
    static final String SUFFIX_LOCATION = "Location";
    static final String SUFFIX_ANALYSIS = "Analysis";
    static final String SUFFIX_PAYLOAD_TYPE = "Payload-Type";
    static final String SUFFIX_TECHNIQUE = "Technique";
    static final String SUFFIX_VARIANT = "Variant";
    static final String SUFFIX_DETAIL = "Detail";
    static final String SUFFIX_PROJECT = "Project";
    static final String SUFFIX_PROJECT_NAME = "Project-Name";
    static final String SUFFIX_RECORD_ID = "Record-Id";

    private static final String PREFIX_DASH = DEFAULT_PREFIX + "-";

    private TalosHeaders() {
    }

    static boolean hasTrace(HttpRequest request) {
        return header(request, name(DEFAULT_PREFIX, SUFFIX_ENGINE)).isPresent();
    }

    static boolean hasMetadata(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if (isMetadataHeader(header.name())) {
                return true;
            }
        }
        return false;
    }

    static boolean isMetadataHeader(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        return name.regionMatches(true, 0, PREFIX_DASH, 0, PREFIX_DASH.length());
    }

    static Optional<TalosTrace> parse(HttpRequest request) {
        String engine = header(request, name(DEFAULT_PREFIX, SUFFIX_ENGINE)).orElse("");
        String group = header(request, name(DEFAULT_PREFIX, SUFFIX_GROUP)).orElse("endpoints");
        String endpoint = header(request, name(DEFAULT_PREFIX, SUFFIX_ENDPOINT)).orElse("");
        if (engine.isBlank() || endpoint.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new TalosTrace(
                engine,
                group,
                endpoint,
                header(request, name(DEFAULT_PREFIX, SUFFIX_ENDPOINT_ID)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_HOST)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_PARAM)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_LOCATION)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_ANALYSIS)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_PAYLOAD_TYPE)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_TECHNIQUE)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_VARIANT)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_DETAIL)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_PROJECT)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_PROJECT_NAME)).orElse(""),
                header(request, name(DEFAULT_PREFIX, SUFFIX_RECORD_ID)).orElse("")
        ));
    }

    static HttpRequest strip(HttpRequest request) {
        List<HttpHeader> remove = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            if (isMetadataHeader(header.name())) {
                remove.add(header);
            }
        }
        if (remove.isEmpty()) {
            return request;
        }
        HttpRequest stripped = request.withRemovedHeaders(remove);
        if (!hasMetadata(stripped)) {
            return stripped;
        }
        return rebuildWithoutMetadata(request);
    }

    /**
     * Last-resort rebuild when withRemovedHeaders leaves X-Talos-* in place
     * (case / HTTP/2 mismatches in some Burp versions).
     */
    private static HttpRequest rebuildWithoutMetadata(HttpRequest request) {
        List<HttpHeader> keep = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            if (!isMetadataHeader(header.name())) {
                keep.add(header);
            }
        }
        String version = request.httpVersion() == null ? "" : request.httpVersion();
        if (version.toUpperCase(Locale.ROOT).contains("HTTP/2")) {
            if (request.httpService() == null) {
                return request.withRemovedHeaders(metadataHeaders(request));
            }
            return HttpRequest.http2Request(request.httpService(), keep, request.body());
        }
        StringBuilder raw = new StringBuilder();
        raw.append(request.method()).append(' ')
                .append(request.path()).append(' ')
                .append(version.isBlank() ? "HTTP/1.1" : version)
                .append("\r\n");
        for (HttpHeader header : keep) {
            raw.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        raw.append("\r\n");
        ByteArray body = request.body();
        if (body == null || body.length() == 0) {
            raw.append("\r\n");
        }
        HttpRequest rebuilt = request.httpService() == null
                ? HttpRequest.httpRequest(raw.toString())
                : HttpRequest.httpRequest(request.httpService(), raw.toString());
        if (body != null && body.length() > 0) {
            rebuilt = rebuilt.withBody(body);
        }
        return rebuilt;
    }

    private static List<HttpHeader> metadataHeaders(HttpRequest request) {
        List<HttpHeader> found = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            if (isMetadataHeader(header.name())) {
                found.add(header);
            }
        }
        return found;
    }

    static String name(String prefix, String suffix) {
        return prefix + "-" + suffix;
    }

    static Optional<String> header(HttpRequest request, String name) {
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase(name)) {
                String value = header.value();
                if (value != null && !value.isBlank()) {
                    return Optional.of(value.trim());
                }
            }
        }
        return Optional.empty();
    }
}
