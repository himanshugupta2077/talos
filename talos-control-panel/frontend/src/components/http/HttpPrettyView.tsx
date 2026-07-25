/**
 * Burp-style Pretty HTTP message view.
 *
 * Same message as Raw (start-line + headers + blank line + body), but:
 * - Body pretty-printed for JSON / XML / HTML / CSS / JS / form
 * - Syntax colorization (method, path, query params, headers, body tokens)
 * - Line numbers + wrap always on
 * - All headers shown (no low-signal hide toggle)
 *
 * @see https://portswigger.net/burp/documentation/desktop/tools/message-editor
 * @see https://portswigger.net/burp/documentation/desktop/tools/message-editor/text-editor
 */

import { useMemo, type ReactNode } from "react";
import {
  buildPrettyMessage,
  type PrettyBodyKind,
  type PrettyHeaderLine,
} from "./parseHttp";

interface Props {
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
  side?: "request" | "response";
}

type Tok =
  | "method"
  | "path"
  | "query-name"
  | "query-value"
  | "query-punct"
  | "version"
  | "status"
  | "reason"
  | "header-name"
  | "header-sep"
  | "header-value"
  | "cookie-name"
  | "cookie-value"
  | "cookie-punct"
  | "json-key"
  | "json-string"
  | "json-number"
  | "json-literal"
  | "json-punct"
  | "markup-tag"
  | "markup-attr"
  | "markup-value"
  | "markup-punct"
  | "form-name"
  | "form-value"
  | "form-punct"
  | "plain"
  | "muted";

interface Seg {
  t: Tok;
  v: string;
}

function seg(t: Tok, v: string): Seg {
  return { t, v };
}

/** Request or response start-line tokens. */
function tokenizeStartLine(line: string): Seg[] {
  // Request: METHOD SP path[?query] SP HTTP/x.y
  const req = line.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\S+))?\s*$/);
  if (req) {
    const out: Seg[] = [seg("method", req[1]), seg("plain", " ")];
    out.push(...tokenizePathAndQuery(req[2]));
    if (req[3]) {
      out.push(seg("plain", " "), seg("version", req[3]));
    }
    return out;
  }
  // Response: HTTP/x.y SP status SP reason
  const res = line.match(/^(HTTP\/\S+)\s+(\d{3})(?:\s+(.*))?$/);
  if (res) {
    const out: Seg[] = [
      seg("version", res[1]),
      seg("plain", " "),
      seg("status", res[2]),
    ];
    if (res[3] != null && res[3] !== "") {
      out.push(seg("plain", " "), seg("reason", res[3]));
    }
    return out;
  }
  return [seg("plain", line)];
}

function tokenizePathAndQuery(pathWithQuery: string): Seg[] {
  const q = pathWithQuery.indexOf("?");
  if (q < 0) return [seg("path", pathWithQuery)];
  const path = pathWithQuery.slice(0, q);
  const query = pathWithQuery.slice(q + 1);
  const out: Seg[] = [seg("path", path), seg("query-punct", "?")];
  const parts = query.split("&");
  parts.forEach((part, i) => {
    if (i > 0) out.push(seg("query-punct", "&"));
    const eq = part.indexOf("=");
    if (eq < 0) {
      out.push(seg("query-name", part));
    } else {
      out.push(
        seg("query-name", part.slice(0, eq)),
        seg("query-punct", "="),
        seg("query-value", part.slice(eq + 1))
      );
    }
  });
  return out;
}

function tokenizeHeader(h: PrettyHeaderLine): Seg[] {
  const name = h.name;
  const value = h.value;
  const key = name.toLowerCase();
  const base: Seg[] = [seg("header-name", name), seg("header-sep", ": "),];

  if (key === "cookie") {
    return [...base, ...tokenizeCookieValue(value)];
  }
  if (key === "set-cookie") {
    // name=value; Attr=...
    const semi = value.indexOf(";");
    const first = semi >= 0 ? value.slice(0, semi) : value;
    const rest = semi >= 0 ? value.slice(semi) : "";
    const eq = first.indexOf("=");
    const segs: Seg[] = [...base];
    if (eq >= 0) {
      segs.push(
        seg("cookie-name", first.slice(0, eq)),
        seg("cookie-punct", "="),
        seg("cookie-value", first.slice(eq + 1))
      );
    } else {
      segs.push(seg("header-value", first));
    }
    if (rest) segs.push(seg("muted", rest));
    return segs;
  }
  return [...base, seg("header-value", value)];
}

function tokenizeCookieValue(value: string): Seg[] {
  const out: Seg[] = [];
  const parts = value.split(";").map((p) => p.trim()).filter(Boolean);
  parts.forEach((part, i) => {
    if (i > 0) out.push(seg("cookie-punct", "; "));
    const eq = part.indexOf("=");
    if (eq < 0) {
      out.push(seg("cookie-name", part));
    } else {
      out.push(
        seg("cookie-name", part.slice(0, eq)),
        seg("cookie-punct", "="),
        seg("cookie-value", part.slice(eq + 1))
      );
    }
  });
  return out;
}

function tokenizeFormLine(line: string): Seg[] {
  const eq = line.indexOf("=");
  if (eq < 0) return [seg("form-name", line)];
  return [
    seg("form-name", line.slice(0, eq)),
    seg("form-punct", "="),
    seg("form-value", line.slice(eq + 1)),
  ];
}

/** Tokenize a prettified JSON line (string-aware). */
function tokenizeJsonLine(line: string): Seg[] {
  const out: Seg[] = [];
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    if (ch === " " || ch === "\t") {
      let j = i;
      while (j < line.length && (line[j] === " " || line[j] === "\t")) j++;
      out.push(seg("plain", line.slice(i, j)));
      i = j;
      continue;
    }
    if (ch === '"' ) {
      let j = i + 1;
      let esc = false;
      while (j < line.length) {
        if (esc) {
          esc = false;
          j++;
          continue;
        }
        if (line[j] === "\\") {
          esc = true;
          j++;
          continue;
        }
        if (line[j] === '"') {
          j++;
          break;
        }
        j++;
      }
      const str = line.slice(i, j);
      // key if followed by optional space and colon
      let k = j;
      while (k < line.length && (line[k] === " " || line[k] === "\t")) k++;
      if (line[k] === ":") {
        out.push(seg("json-key", str));
      } else {
        out.push(seg("json-string", str));
      }
      i = j;
      continue;
    }
    if (/[0-9\-]/.test(ch)) {
      let j = i + 1;
      while (j < line.length && /[0-9.eE+\-]/.test(line[j])) j++;
      out.push(seg("json-number", line.slice(i, j)));
      i = j;
      continue;
    }
    if (/[a-zA-Z]/.test(ch)) {
      let j = i + 1;
      while (j < line.length && /[a-zA-Z]/.test(line[j])) j++;
      const word = line.slice(i, j);
      if (word === "true" || word === "false" || word === "null") {
        out.push(seg("json-literal", word));
      } else {
        out.push(seg("plain", word));
      }
      i = j;
      continue;
    }
    if ("{}[],:".includes(ch)) {
      out.push(seg("json-punct", ch));
      i++;
      continue;
    }
    out.push(seg("plain", ch));
    i++;
  }
  return out.length ? out : [seg("plain", line)];
}

/** Lightweight HTML/XML line highlighter. */
function tokenizeMarkupLine(line: string): Seg[] {
  if (!line.includes("<")) return [seg("plain", line)];
  const out: Seg[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] !== "<") {
      let j = i;
      while (j < line.length && line[j] !== "<") j++;
      out.push(seg("plain", line.slice(i, j)));
      i = j;
      continue;
    }
    // tag
    let j = i + 1;
    while (j < line.length && line[j] !== ">") j++;
    if (j >= line.length) {
      out.push(seg("plain", line.slice(i)));
      break;
    }
    const inner = line.slice(i + 1, j); // without < >
    out.push(seg("markup-punct", "<"));
    // parse tag name + attrs roughly
    const m = inner.match(/^(\/?[a-zA-Z][\w:.-]*)(.*)$/);
    if (m) {
      out.push(seg("markup-tag", m[1]));
      tokenizeMarkupAttrs(m[2], out);
    } else if (inner.startsWith("!") || inner.startsWith("?")) {
      out.push(seg("muted", inner));
    } else {
      out.push(seg("plain", inner));
    }
    out.push(seg("markup-punct", ">"));
    i = j + 1;
  }
  return out;
}

function tokenizeMarkupAttrs(attrs: string, out: Seg[]) {
  // attr="value" or attr='value' or attr=bare
  const re = /(\s+)([a-zA-Z_:][\w:.-]*)(?:(=)("([^"]*)"|'([^']*)'|(\S+)))?/g;
  let m: RegExpExecArray | null;
  let last = 0;
  while ((m = re.exec(attrs)) !== null) {
    if (m.index > last) out.push(seg("plain", attrs.slice(last, m.index)));
    out.push(seg("plain", m[1]), seg("markup-attr", m[2]));
    if (m[3]) {
      out.push(seg("markup-punct", "="));
      const quoted = m[4] || "";
      out.push(seg("markup-value", quoted));
    }
    last = m.index + m[0].length;
  }
  if (last < attrs.length) out.push(seg("plain", attrs.slice(last)));
}

function tokenizeBodyLine(line: string, kind: PrettyBodyKind): Seg[] {
  switch (kind) {
    case "json":
      return tokenizeJsonLine(line);
    case "html":
    case "xml":
      return tokenizeMarkupLine(line);
    case "form":
      return tokenizeFormLine(line);
    case "css":
    case "javascript":
      // brace-aware color for structure
      return tokenizeCssOrJsLine(line);
    default:
      return [seg("plain", line)];
  }
}

function tokenizeCssOrJsLine(line: string): Seg[] {
  // Highlight strings and numbers lightly
  const out: Seg[] = [];
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const q = ch;
      let j = i + 1;
      let esc = false;
      while (j < line.length) {
        if (esc) {
          esc = false;
          j++;
          continue;
        }
        if (line[j] === "\\") {
          esc = true;
          j++;
          continue;
        }
        if (line[j] === q) {
          j++;
          break;
        }
        j++;
      }
      out.push(seg("json-string", line.slice(i, j)));
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < line.length && /[0-9.a-fA-FxX%]/.test(line[j])) j++;
      out.push(seg("json-number", line.slice(i, j)));
      i = j;
      continue;
    }
    if ("{}[];:,()".includes(ch)) {
      out.push(seg("json-punct", ch));
      i++;
      continue;
    }
    out.push(seg("plain", ch));
    i++;
  }
  return out.length ? out : [seg("plain", line)];
}

const TOK_CLASS: Record<Tok, string> = {
  method: "hp-method",
  path: "hp-path",
  "query-name": "hp-query-name",
  "query-value": "hp-query-value",
  "query-punct": "hp-punct",
  version: "hp-version",
  status: "hp-status",
  reason: "hp-reason",
  "header-name": "hp-header-name",
  "header-sep": "hp-punct",
  "header-value": "hp-header-value",
  "cookie-name": "hp-cookie-name",
  "cookie-value": "hp-cookie-value",
  "cookie-punct": "hp-punct",
  "json-key": "hp-json-key",
  "json-string": "hp-json-string",
  "json-number": "hp-json-number",
  "json-literal": "hp-json-literal",
  "json-punct": "hp-punct",
  "markup-tag": "hp-markup-tag",
  "markup-attr": "hp-markup-attr",
  "markup-value": "hp-markup-value",
  "markup-punct": "hp-punct",
  "form-name": "hp-query-name",
  "form-value": "hp-query-value",
  "form-punct": "hp-punct",
  plain: "",
  muted: "hp-muted",
};

function renderSegs(segs: Seg[]): ReactNode {
  return segs.map((s, i) => {
    const cls = TOK_CLASS[s.t];
    if (!cls) return <span key={i}>{s.v}</span>;
    return (
      <span key={i} className={cls}>
        {s.v}
      </span>
    );
  });
}

interface EditorLine {
  segs: Seg[];
  /** Visual blank line between headers and body */
  isBlank?: boolean;
}

export default function HttpPrettyView({
  startLine,
  headers,
  cookies,
  body,
  bodyEncoding,
  contentType,
  side = "request",
}: Props) {
  const model = useMemo(
    () =>
      buildPrettyMessage({
        startLine,
        headers,
        cookies,
        body,
        bodyEncoding,
        contentType,
        side,
      }),
    [startLine, headers, cookies, body, bodyEncoding, contentType, side]
  );

  const lines = useMemo((): EditorLine[] => {
    const out: EditorLine[] = [{ segs: tokenizeStartLine(model.startLine) }];
    for (const h of model.headers) {
      out.push({ segs: tokenizeHeader(h) });
    }
    out.push({ segs: [], isBlank: true });
    if (model.body.kind === "empty") {
      // Empty body: blank line only (no status banner).
    } else if (model.body.kind === "binary") {
      out.push({ segs: [seg("muted", model.body.text)] });
    } else {
      const bodyLines = model.body.text.split("\n");
      for (const bl of bodyLines) {
        out.push({ segs: tokenizeBodyLine(bl, model.body.kind) });
      }
    }
    return out;
  }, [model]);

  const lineCount = lines.length;

  return (
    <div className="http-pretty">
      <div className="http-pretty-editor mono text-xs http-pretty-wrap">
        <div className="http-pretty-gutter" aria-hidden>
          {lines.map((_, i) => (
            <div key={i} className="http-pretty-ln">
              {i + 1}
            </div>
          ))}
        </div>
        <div className="http-pretty-code" style={{ minHeight: `${lineCount * 1.35}em` }}>
          {lines.map((ln, i) => (
            <div key={i} className={`http-pretty-line ${ln.isBlank ? "http-pretty-blank" : ""}`}>
              {ln.isBlank ? "\u00a0" : renderSegs(ln.segs)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
