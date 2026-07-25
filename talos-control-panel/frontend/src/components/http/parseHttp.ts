/**
 * Pure HTTP presentation parsers for the Flow inspection workspace.
 *
 * One source of truth per view mode — cookies/JWT/params must not be expanded
 * under Headers when a dedicated tab exists. Dual cookie storage (Cookie header
 * + request_cookies map) is a capture design; this module canonicalizes for UI.
 */

export interface NormalizedHeader {
  /** Display name (first-seen casing preferred). */
  name: string;
  /** Lowercase key for grouping. */
  key: string;
  value: string;
  /** Cookie/Set-Cookie pair count when applicable. */
  cookieCount?: number;
  isCookie: boolean;
  isSetCookie: boolean;
  isAuthorization: boolean;
  looksLikeJwt: boolean;
}

export interface CookiePair {
  name: string;
  value: string;
  /** Extra attributes for Set-Cookie (Path, HttpOnly, …). */
  attributes?: Record<string, string | boolean>;
  source: "cookies_map" | "cookie_header" | "set_cookie";
}

export interface JwtDecodeResult {
  raw: string;
  token: string;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  error?: string;
  claimsSummary?: { exp?: number; sub?: string; iat?: number; iss?: string };
}

export interface BodyParam {
  name: string;
  value: string;
}

function b64urlDecode(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return decodeURIComponent(
    atob(padded)
      .split("")
      .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
      .join("")
  );
}

/** True if value is a JWT or `Bearer <jwt>`. */
export function looksLikeJwt(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const token = value.replace(/^Bearer\s+/i, "").trim();
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  // Header segment must be valid base64url JSON-ish
  try {
    const h = b64urlDecode(parts[0]);
    return h.includes("{") && (h.includes("alg") || h.includes("typ"));
  } catch {
    return false;
  }
}

export function decodeJwt(value: string): JwtDecodeResult | null {
  if (!value) return null;
  const raw = value;
  const token = value.replace(/^Bearer\s+/i, "").trim();
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0])) as Record<string, unknown>;
    const payload = JSON.parse(b64urlDecode(parts[1])) as Record<string, unknown>;
    const claimsSummary: JwtDecodeResult["claimsSummary"] = {};
    if (typeof payload.exp === "number") claimsSummary.exp = payload.exp;
    if (typeof payload.sub === "string") claimsSummary.sub = payload.sub;
    if (typeof payload.iat === "number") claimsSummary.iat = payload.iat;
    if (typeof payload.iss === "string") claimsSummary.iss = payload.iss;
    return { raw, token, header, payload, claimsSummary };
  } catch (e) {
    return {
      raw,
      token,
      header: null,
      payload: null,
      error: e instanceof Error ? e.message : "decode failed",
    };
  }
}

/** Case-insensitive header lookup. */
export function getHeader(
  headers: Record<string, string> | null | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return v;
  }
  return undefined;
}

/**
 * Normalize headers: one entry per case-insensitive name.
 * Cookie / Authorization stay opaque (full value, no expand).
 * Multi-value collapse is a mitmproxy capture limitation — last/joined wins.
 */
export function normalizeHeaders(
  headers: Record<string, string> | null | undefined,
  cookiePairs?: CookiePair[]
): NormalizedHeader[] {
  const map = new Map<string, NormalizedHeader>();
  for (const [name, value] of Object.entries(headers || {})) {
    const key = name.toLowerCase();
    const isCookie = key === "cookie";
    const isSetCookie = key === "set-cookie";
    const isAuthorization = key === "authorization";
    const entry: NormalizedHeader = {
      name,
      key,
      value: value ?? "",
      isCookie,
      isSetCookie,
      isAuthorization,
      looksLikeJwt: isAuthorization || looksLikeJwt(value ?? ""),
    };
    if (isCookie && cookiePairs) {
      entry.cookieCount = cookiePairs.filter((c) => c.source !== "set_cookie").length;
    } else if (isCookie) {
      entry.cookieCount = parseCookieHeader(value).length;
    } else if (isSetCookie) {
      entry.cookieCount = 1;
    }
    // Prefer first-seen casing; later duplicates overwrite value (capture collapse)
    map.set(key, entry);
  }
  return Array.from(map.values());
}

/** Parse a Cookie request header into name/value pairs. */
export function parseCookieHeader(header: string | undefined | null): CookiePair[] {
  if (!header || !header.trim()) return [];
  return header
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq < 0) return { name: pair, value: "", source: "cookie_header" as const };
      return {
        name: pair.slice(0, eq).trim(),
        value: pair.slice(eq + 1).trim(),
        source: "cookie_header" as const,
      };
    });
}

/** Parse a single Set-Cookie header value. */
export function parseSetCookie(header: string): CookiePair {
  const parts = header.split(";").map((p) => p.trim()).filter(Boolean);
  const first = parts[0] || "";
  const eq = first.indexOf("=");
  const name = eq >= 0 ? first.slice(0, eq).trim() : first;
  const value = eq >= 0 ? first.slice(eq + 1).trim() : "";
  const attributes: Record<string, string | boolean> = {};
  for (const attr of parts.slice(1)) {
    const aeq = attr.indexOf("=");
    if (aeq < 0) {
      attributes[attr.toLowerCase()] = true;
    } else {
      attributes[attr.slice(0, aeq).trim().toLowerCase()] = attr.slice(aeq + 1).trim();
    }
  }
  return { name, value, attributes, source: "set_cookie" };
}

/**
 * Canonical cookies for the Cookies tab.
 * Prefer `request_cookies` map when non-empty; else parse Cookie header once.
 * Never merge both into a doubled list for the same names from dual storage.
 */
export function resolveRequestCookies(
  cookiesMap: Record<string, string> | null | undefined,
  headers: Record<string, string> | null | undefined
): CookiePair[] {
  const mapEntries = Object.entries(cookiesMap || {}).filter(
    ([k]) => k != null && String(k).length > 0
  );
  if (mapEntries.length > 0) {
    return mapEntries.map(([name, value]) => ({
      name,
      value: value ?? "",
      source: "cookies_map" as const,
    }));
  }
  const cookieHeader = getHeader(headers, "Cookie");
  return parseCookieHeader(cookieHeader);
}

/** Response Set-Cookie entries from headers (single collapsed value or multi). */
export function resolveResponseCookies(
  headers: Record<string, string> | null | undefined
): CookiePair[] {
  const raw = getHeader(headers, "Set-Cookie");
  if (!raw) return [];
  // Capture may join multiple Set-Cookie with ", " — split carefully is hard;
  // treat whole value as one cookie first; if multiple `name=` patterns, split on ", ".
  if (raw.includes(", ") && /,\s*[A-Za-z0-9_\-]+=/.test(raw)) {
    return raw.split(/,\s*(?=[A-Za-z0-9_\-]+=)/).map(parseSetCookie);
  }
  return [parseSetCookie(raw)];
}

/** First JWT-like value from Authorization or any header. */
export function findJwt(
  headers: Record<string, string> | null | undefined
): JwtDecodeResult | null {
  if (!headers) return null;
  const auth = getHeader(headers, "Authorization");
  if (auth && looksLikeJwt(auth)) return decodeJwt(auth);
  for (const v of Object.values(headers)) {
    if (looksLikeJwt(v)) return decodeJwt(v);
  }
  return null;
}

/** Parse query string into name/value pairs (no leading ?). */
export function parseQueryParams(query: string | null | undefined): BodyParam[] {
  if (!query || !query.trim()) return [];
  const q = query.startsWith("?") ? query.slice(1) : query;
  return q.split("&").filter(Boolean).map((part) => {
    const eq = part.indexOf("=");
    if (eq < 0) {
      return { name: decodeURIComponentSafe(part), value: "" };
    }
    return {
      name: decodeURIComponentSafe(part.slice(0, eq)),
      value: decodeURIComponentSafe(part.slice(eq + 1)),
    };
  });
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

/**
 * Extract body form fields for urlencoded (and simple multipart name list).
 * Does not dump the raw body again — names/values only for Params/Inspector.
 */
export function parseBodyParams(
  body: string | null | undefined,
  contentType: string | null | undefined,
  bodyEncoding?: string
): BodyParam[] {
  if (!body || bodyEncoding === "base64") return [];
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("application/x-www-form-urlencoded") || looksUrlEncoded(body, ct)) {
    return parseQueryParams(body);
  }
  if (ct.includes("multipart/form-data")) {
    // Name-only extraction from Content-Disposition lines
    const names: BodyParam[] = [];
    const re = /Content-Disposition:[^\n]*name="([^"]+)"/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      names.push({ name: m[1], value: "(multipart part)" });
    }
    return names;
  }
  return [];
}

function looksUrlEncoded(body: string, ct: string): boolean {
  if (ct.includes("json") || ct.includes("xml") || ct.includes("html")) return false;
  if (!body.includes("=")) return false;
  // Heuristic: mostly key=value& pairs
  const parts = body.split("&");
  if (parts.length < 1) return false;
  return parts.every((p) => p.length < 2000 && /^[^=\s]+=/.test(p));
}

/**
 * Reconstruct raw HTTP message.
 * Cookie line: use header if present; else synthesize from cookies map once.
 * Never double Cookie lines. No JWT expand, no cookie split.
 */
export function buildRawMessage(opts: {
  startLine: string;
  headers: Record<string, string> | null | undefined;
  cookies?: Record<string, string> | null;
  body?: string | null;
}): string {
  const headers = opts.headers || {};
  const entries = Object.entries(headers);
  const hasCookie = entries.some(([k]) => k.toLowerCase() === "cookie");
  const lines = [opts.startLine, ...entries.map(([k, v]) => `${k}: ${v}`)];
  if (!hasCookie && opts.cookies && Object.keys(opts.cookies).length > 0) {
    lines.push(
      `Cookie: ${Object.entries(opts.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ")}`
    );
  }
  lines.push("");
  lines.push(opts.body || "");
  return lines.join("\n");
}

/**
 * Body format kinds Burp Pretty supports (plus form for operator readability).
 * @see https://portswigger.net/burp/documentation/desktop/tools/message-editor/text-editor#pretty-printing
 */
export type PrettyBodyKind =
  | "json"
  | "xml"
  | "html"
  | "css"
  | "javascript"
  | "form"
  | "text"
  | "binary"
  | "empty";

export interface PrettyBodyResult {
  text: string;
  kind: PrettyBodyKind;
  /** True when indentation/line-breaks were applied (Burp Pretty would show this tab). */
  prettified: boolean;
}

/**
 * Burp-style pretty-print of an HTTP body.
 * Supported: JSON, XML, HTML, CSS, JavaScript; also form-urlencoded (one field per line).
 */
export function prettyBody(
  body: string | null | undefined,
  contentType: string | null | undefined,
  bodyEncoding?: string
): PrettyBodyResult {
  if (bodyEncoding === "base64") {
    return {
      text: `[binary body — base64, ${body?.length || 0} chars]`,
      kind: "binary",
      prettified: false,
    };
  }
  if (body == null || body === "") {
    return { text: "", kind: "empty", prettified: false };
  }

  const ct = (contentType || "").toLowerCase();
  const trimmed = body.trimStart();

  // JSON (Content-Type or heuristic)
  if (
    ct.includes("json") ||
    trimmed.startsWith("{") ||
    trimmed.startsWith("[")
  ) {
    try {
      return {
        text: JSON.stringify(JSON.parse(body), null, 4),
        kind: "json",
        prettified: true,
      };
    } catch {
      /* fall through */
    }
  }

  // Form urlencoded — one param per line (highly readable; not in Burp's format list)
  if (ct.includes("application/x-www-form-urlencoded") || looksUrlEncoded(body, ct)) {
    const lines = body.split("&").filter(Boolean);
    if (lines.length > 1 || (lines.length === 1 && lines[0].includes("="))) {
      return {
        text: lines.join("\n"),
        kind: "form",
        prettified: lines.length > 1,
      };
    }
  }

  // HTML
  if (
    ct.includes("text/html") ||
    ct.includes("application/xhtml") ||
    /^\s*<(!doctype\s+html|html[\s>])/i.test(body)
  ) {
    const pretty = prettyPrintMarkup(body, "html");
    return { text: pretty, kind: "html", prettified: pretty !== body };
  }

  // XML / SVG
  if (
    ct.includes("xml") ||
    ct.includes("svg") ||
    /^\s*<\?xml/i.test(body) ||
    /^\s*<[a-zA-Z][\w:.-]*[\s/>]/.test(body)
  ) {
    // Prefer HTML path only when clearly HTML; otherwise XML
    if (!/^\s*<(!doctype\s+html|html[\s>])/i.test(body)) {
      const pretty = prettyPrintMarkup(body, "xml");
      return { text: pretty, kind: "xml", prettified: pretty !== body };
    }
  }

  // CSS
  if (ct.includes("text/css") || looksLikeCss(body, ct)) {
    const pretty = prettyPrintCss(body);
    return { text: pretty, kind: "css", prettified: pretty !== body };
  }

  // JavaScript
  if (
    ct.includes("javascript") ||
    ct.includes("ecmascript") ||
    ct.includes("application/js")
  ) {
    const pretty = prettyPrintJs(body);
    return { text: pretty, kind: "javascript", prettified: pretty !== body };
  }

  return { text: body, kind: "text", prettified: false };
}

function looksLikeCss(body: string, ct: string): boolean {
  if (ct.includes("json") || ct.includes("html") || ct.includes("xml")) return false;
  // Minified CSS heuristic: many `{` `}` and `;` with few newlines
  const braces = (body.match(/[{}]/g) || []).length;
  const semis = (body.match(/;/g) || []).length;
  return braces >= 2 && semis >= 1 && body.includes("{") && body.includes("}");
}

/** Indent HTML/XML with 4 spaces (Burp-style standardized indentation). */
export function prettyPrintMarkup(input: string, _mode: "html" | "xml" = "html"): string {
  // Normalize newlines; keep text content roughly intact
  let s = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!s) return s;

  // Insert breaks between tags
  s = s
    .replace(/>\s*</g, ">\n<")
    .replace(/(<(?:script|style|pre)[^>]*>)\n?/gi, "$1\n")
    .replace(/\n?(<\/(?:script|style|pre)>)/gi, "\n$1");

  const lines = s.split("\n");
  const out: string[] = [];
  let depth = 0;
  const voidish =
    /^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      out.push("");
      continue;
    }

    const isClosing = /^<\//.test(line);
    const isComment = /^<!--/.test(line) || /^<!\[/.test(line);
    const isDoctype = /^<!doctype/i.test(line) || /^<\?xml/i.test(line);
    const isSelfClosing = /\/>$/.test(line) || isComment || isDoctype;
    const openTag = line.match(/^<([a-zA-Z][\w:.-]*)/);
    const tagName = openTag?.[1] || "";
    const isVoid = voidish.test(tagName);

    if (isClosing) depth = Math.max(0, depth - 1);
    out.push("    ".repeat(depth) + line);
    if (!isClosing && !isSelfClosing && !isVoid && /^</.test(line) && !/^<\//.test(line)) {
      // Opening tag (not self-closing)
      if (!/\/>$/.test(line) && !isComment && !isDoctype) {
        depth += 1;
      }
    }
  }
  return out.join("\n");
}

/** Light CSS formatter: break after { } ; */
export function prettyPrintCss(input: string): string {
  const s = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!s || s.includes("\n") && s.split("\n").length > 3) {
    // Already multi-line enough — still normalize braces lightly
    if (s.includes("\n")) return s;
  }
  let out = "";
  let depth = 0;
  let i = 0;
  let inStr: string | null = null;
  while (i < s.length) {
    const ch = s[i];
    if (inStr) {
      out += ch;
      if (ch === "\\" && i + 1 < s.length) {
        out += s[i + 1];
        i += 2;
        continue;
      }
      if (ch === inStr) inStr = null;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === "{") {
      out += " {\n";
      depth++;
      out += "    ".repeat(depth);
      i++;
      // skip following space
      while (s[i] === " ") i++;
      continue;
    }
    if (ch === "}") {
      depth = Math.max(0, depth - 1);
      out = out.replace(/[ \t]+$/, "");
      if (!out.endsWith("\n")) out += "\n";
      out += "    ".repeat(depth) + "}";
      i++;
      if (s[i] && s[i] !== "\n") out += "\n" + "    ".repeat(depth);
      continue;
    }
    if (ch === ";") {
      out += ";\n" + "    ".repeat(depth);
      i++;
      while (s[i] === " ") i++;
      continue;
    }
    if (ch === "\n") {
      out += "\n" + "    ".repeat(depth);
      i++;
      while (s[i] === " ") i++;
      continue;
    }
    out += ch;
    i++;
  }
  return out.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

/** Light JS brace indent (best-effort for minified one-liners). */
export function prettyPrintJs(input: string): string {
  const s = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!s) return s;
  // Already reasonably multi-line
  if (s.split("\n").length > 5) return s;

  let out = "";
  let depth = 0;
  let i = 0;
  let inStr: string | null = null;
  let inLineComment = false;
  let inBlockComment = false;

  while (i < s.length) {
    const ch = s[i];
    const next = s[i + 1];

    if (inLineComment) {
      out += ch;
      if (ch === "\n") inLineComment = false;
      i++;
      continue;
    }
    if (inBlockComment) {
      out += ch;
      if (ch === "*" && next === "/") {
        out += "/";
        i += 2;
        inBlockComment = false;
        continue;
      }
      i++;
      continue;
    }
    if (inStr) {
      out += ch;
      if (ch === "\\" && i + 1 < s.length) {
        out += s[i + 1];
        i += 2;
        continue;
      }
      if (ch === inStr) inStr = null;
      i++;
      continue;
    }

    if (ch === "/" && next === "/") {
      inLineComment = true;
      out += "//";
      i += 2;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      out += "/*";
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inStr = ch;
      out += ch;
      i++;
      continue;
    }

    if (ch === "{" || ch === "[") {
      out += ch + "\n";
      depth++;
      out += "    ".repeat(depth);
      i++;
      while (s[i] === " ") i++;
      continue;
    }
    if (ch === "}" || ch === "]") {
      depth = Math.max(0, depth - 1);
      out = out.replace(/[ \t]+$/, "");
      if (!out.endsWith("\n")) out += "\n";
      out += "    ".repeat(depth) + ch;
      i++;
      if (s[i] === "," || s[i] === ";") {
        out += s[i];
        i++;
      }
      if (s[i] && s[i] !== "\n" && s[i] !== "}" && s[i] !== "]") {
        out += "\n" + "    ".repeat(depth);
      }
      continue;
    }
    if (ch === ";") {
      out += ";\n" + "    ".repeat(depth);
      i++;
      while (s[i] === " ") i++;
      continue;
    }
    if (ch === "," && depth > 0) {
      out += ",\n" + "    ".repeat(depth);
      i++;
      while (s[i] === " ") i++;
      continue;
    }
    out += ch;
    i++;
  }
  return out.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

/** Headers Burp often hides by default in Pretty (noise for app behavior). */
export const DEFAULT_HIDDEN_REQUEST_HEADERS = [
  "accept-encoding",
  "accept-language",
  "connection",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "upgrade-insecure-requests",
  "priority",
  "dnt",
];

export const DEFAULT_HIDDEN_RESPONSE_HEADERS = [
  "date",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-encoding",
  "vary",
  "x-content-type-options",
  "x-frame-options",
  "x-xss-protection",
  "strict-transport-security",
  "referrer-policy",
  "permissions-policy",
  "content-security-policy",
  "content-security-policy-report-only",
  "report-to",
  "nel",
  "alt-svc",
  "cf-ray",
  "cf-cache-status",
  "server-timing",
];

export interface PrettyHeaderLine {
  name: string;
  value: string;
  hiddenByDefault: boolean;
}

/**
 * Build the Pretty-tab message model (same structure as Raw, body prettified).
 * Cookie: use header if present; else synthesize once from cookies map.
 */
export function buildPrettyMessage(opts: {
  startLine: string;
  headers: Record<string, string> | null | undefined;
  cookies?: Record<string, string> | null;
  body?: string | null;
  bodyEncoding?: string;
  contentType?: string;
  side?: "request" | "response";
}): {
  startLine: string;
  headers: PrettyHeaderLine[];
  body: PrettyBodyResult;
  side: "request" | "response";
} {
  const side = opts.side || "request";
  const hideList =
    side === "request" ? DEFAULT_HIDDEN_REQUEST_HEADERS : DEFAULT_HIDDEN_RESPONSE_HEADERS;
  const hideSet = new Set(hideList);

  const entries = Object.entries(opts.headers || {});
  const hasCookie = entries.some(([k]) => k.toLowerCase() === "cookie");
  const headers: PrettyHeaderLine[] = entries.map(([name, value]) => ({
    name,
    value: value ?? "",
    hiddenByDefault: hideSet.has(name.toLowerCase()),
  }));
  if (!hasCookie && opts.cookies && Object.keys(opts.cookies).length > 0) {
    headers.push({
      name: "Cookie",
      value: Object.entries(opts.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; "),
      hiddenByDefault: false,
    });
  }

  const ct =
    opts.contentType ||
    getHeader(opts.headers, "Content-Type") ||
    getHeader(opts.headers, "content-type");

  return {
    startLine: opts.startLine,
    headers,
    body: prettyBody(opts.body, ct, opts.bodyEncoding),
    side,
  };
}

/** Headers for Inspector summary: names + Cookie(N) badge, no values expanded. */
export function inspectorHeaderSummary(
  headers: NormalizedHeader[]
): { name: string; badge?: string }[] {
  return headers.map((h) => {
    if (h.isCookie || h.isSetCookie) {
      const n = h.cookieCount ?? 0;
      return { name: h.name, badge: n > 0 ? String(n) : undefined };
    }
    if (h.isAuthorization) {
      return { name: h.name, badge: h.looksLikeJwt ? "JWT" : undefined };
    }
    return { name: h.name };
  });
}
