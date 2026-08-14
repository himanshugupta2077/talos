package talos.burp;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tiny parser for a flat JSON object of string values.
 * The ingest wire format is fully under Talos control.
 */
final class TalosJson {
    private TalosJson() {
    }

    static Map<String, String> parseFlatObject(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null) {
            return out;
        }
        String text = json.trim();
        if (text.length() < 2 || text.charAt(0) != '{') {
            return out;
        }
        int i = 1;
        int n = text.length();
        while (i < n) {
            i = skipWs(text, i);
            if (i >= n || text.charAt(i) == '}') {
                break;
            }
            if (text.charAt(i) != '"') {
                break;
            }
            ParseString key = readString(text, i);
            i = skipWs(text, key.end);
            if (i >= n || text.charAt(i) != ':') {
                break;
            }
            i = skipWs(text, i + 1);
            if (i >= n) {
                break;
            }
            if (text.charAt(i) == '"') {
                ParseString value = readString(text, i);
                out.put(key.value, value.value);
                i = skipWs(text, value.end);
            } else {
                int end = i;
                while (end < n) {
                    char c = text.charAt(end);
                    if (c == ',' || c == '}' || c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                        break;
                    }
                    end += 1;
                }
                String token = text.substring(i, end);
                out.put(key.value, "null".equals(token) ? "" : token);
                i = skipWs(text, end);
            }
            if (i < n && text.charAt(i) == ',') {
                i += 1;
            }
        }
        return out;
    }

    private static int skipWs(String text, int i) {
        int n = text.length();
        while (i < n) {
            char c = text.charAt(i);
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                break;
            }
            i += 1;
        }
        return i;
    }

    private static ParseString readString(String text, int startQuote) {
        StringBuilder buf = new StringBuilder();
        int i = startQuote + 1;
        int n = text.length();
        while (i < n) {
            char c = text.charAt(i);
            if (c == '"') {
                return new ParseString(buf.toString(), i + 1);
            }
            if (c == '\\' && i + 1 < n) {
                char next = text.charAt(i + 1);
                switch (next) {
                    case '"':
                    case '\\':
                    case '/':
                        buf.append(next);
                        break;
                    case 'n':
                        buf.append('\n');
                        break;
                    case 'r':
                        buf.append('\r');
                        break;
                    case 't':
                        buf.append('\t');
                        break;
                    default:
                        buf.append(next);
                        break;
                }
                i += 2;
                continue;
            }
            buf.append(c);
            i += 1;
        }
        return new ParseString(buf.toString(), n);
    }

    private static final class ParseString {
        final String value;
        final int end;

        ParseString(String value, int end) {
            this.value = value;
            this.end = end;
        }
    }
}
