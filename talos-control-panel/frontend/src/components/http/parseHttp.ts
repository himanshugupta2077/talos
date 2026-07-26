/**
 * Pure HTTP presentation parsers for the Flow inspection workspace.
 *
 * One source of truth per view mode — cookies / encoded values / params must not
 * be expanded under Headers when a dedicated tab exists. Dual cookie storage
 * (Cookie header + request_cookies map) is a capture design; this module
 * canonicalizes for UI.
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

/** Encoded/encrypted value kinds shown in the Encoded tab. */
export type EncodedKind = "jwt" | "jwe" | "basic_auth" | "base64";

export interface EncodedArtifact {
  /** Stable-ish key for React lists. */
  id: string;
  kind: EncodedKind;
  /** Where it was found, e.g. `header:Authorization`, `cookie:sid`, `query:token`, `body.access_token`. */
  location: string;
  /** Short title for the fold row. */
  label: string;
  /** Original string (may be truncated for huge bodies). */
  raw: string;
  jwt?: JwtDecodeResult;
  jwe?: {
    token: string;
    header: Record<string, unknown> | null;
    error?: string;
  };
  basicAuth?: { username: string; password: string };
  base64?: {
    decoded: string;
    isJson: boolean;
    error?: string;
  };
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

/** Strip optional Bearer prefix. */
function stripBearer(value: string): string {
  return value.replace(/^Bearer\s+/i, "").trim();
}

/** True if value is a JWT or `Bearer <jwt>`. */
export function looksLikeJwt(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const token = stripBearer(value);
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

/** True if value looks like a JWE (5 compact segments, encrypted JWT). */
export function looksLikeJwe(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const token = stripBearer(value);
  const parts = token.split(".");
  if (parts.length !== 5) return false;
  try {
    const h = b64urlDecode(parts[0]);
    return h.includes("{") && (h.includes("enc") || h.includes("alg"));
  } catch {
    return false;
  }
}

export function decodeJwt(value: string): JwtDecodeResult | null {
  if (!value) return null;
  const raw = value;
  const token = stripBearer(value);
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

export function decodeJweHeader(value: string): EncodedArtifact["jwe"] | null {
  if (!value) return null;
  const token = stripBearer(value);
  const parts = token.split(".");
  if (parts.length !== 5) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0])) as Record<string, unknown>;
    return { token, header };
  } catch (e) {
    return {
      token,
      header: null,
      error: e instanceof Error ? e.message : "decode failed",
    };
  }
}

/**
 * True only when value is base64 *and* decodes to readable text/JSON.
 * Opaque tokens (session IDs, nanoids, random key material) share the
 * base64 alphabet but decode to binary noise — those must not surface here.
 */
export function looksLikeBase64(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const s = value.trim();
  // Long enough to be interesting; not a JWT/JWE (dots) or multi-line
  if (s.length < 16 || s.includes(".") || s.includes(" ") || s.includes("\n")) return false;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return false;
  // Standard base64 length: remainder 1 is never valid
  if (s.replace(/=+$/, "").length % 4 === 1) return false;
  // Pure hex short hashes / UUID-ish without padding are not base64 payloads
  if (!/[+/=]/.test(s) && /^[0-9a-fA-F]+$/.test(s)) return false;
  try {
    const decoded = decodeBase64Flexible(s);
    if (decoded == null || decoded.length < 4) return false;
    // Require readable text — binary garbage is not useful in Encoded tab
    if (!isMostlyPrintable(decoded)) return false;
    // Avoid single high-entropy control-ish blobs that are "printable" but nonsense:
    // need at least one letter or common structure char in the decode
    if (!/[A-Za-z{["'0-9]/.test(decoded)) return false;
    return true;
  } catch {
    return false;
  }
}

function decodeBase64Flexible(s: string): string | null {
  try {
    const stripped = s.replace(/=+$/, "");
    // Invalid length for base64 (cannot pad to multiple of 4)
    if (stripped.length % 4 === 1) return null;
    const normalized = stripped.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (normalized.length % 4)) % 4;
    return atob(normalized + "=".repeat(pad));
  } catch {
    return null;
  }
}

function isMostlyPrintable(s: string): boolean {
  if (!s) return false;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ok++;
  }
  return ok / s.length >= 0.9;
}

/** Text form of an artifact for the "copy decoded" action. */
export function encodedArtifactDecodedText(a: EncodedArtifact): string | null {
  switch (a.kind) {
    case "jwt":
      if (!a.jwt || a.jwt.error) return null;
      return JSON.stringify(
        { header: a.jwt.header, payload: a.jwt.payload },
        null,
        2
      );
    case "jwe":
      if (!a.jwe || a.jwe.error || !a.jwe.header) return null;
      return JSON.stringify(a.jwe.header, null, 2);
    case "basic_auth":
      if (!a.basicAuth) return null;
      return `${a.basicAuth.username}:${a.basicAuth.password}`;
    case "base64":
      if (!a.base64 || a.base64.error) return null;
      return a.base64.decoded;
    default:
      return null;
  }
}

export function decodeBasicAuth(value: string): { username: string; password: string } | null {
  if (!value) return null;
  const m = value.match(/^Basic\s+([A-Za-z0-9+/_=]+)\s*$/i);
  if (!m) return null;
  const decoded = decodeBase64Flexible(m[1]);
  if (decoded == null || !decoded.includes(":")) return null;
  const colon = decoded.indexOf(":");
  return {
    username: decoded.slice(0, colon),
    password: decoded.slice(colon + 1),
  };
}

export function tryDecodeBase64(value: string): EncodedArtifact["base64"] | null {
  const decoded = decodeBase64Flexible(value.trim());
  if (decoded == null) return { decoded: "", isJson: false, error: "invalid base64" };
  let isJson = false;
  let text = decoded;
  // Prefer UTF-8-ish presentation; atob already gives binary string
  try {
    const asUtf8 = decodeURIComponent(
      decoded
        .split("")
        .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
    );
    text = asUtf8;
  } catch {
    // keep latin1-ish decoded
  }
  const trimmed = text.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      text = JSON.stringify(JSON.parse(trimmed), null, 2);
      isJson = true;
    } catch {
      /* keep raw */
    }
  }
  return { decoded: text, isJson };
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

/**
 * Collect every encoded/encrypted-looking value in a request or response.
 * Multiple JWTs (or other kinds) become separate foldable entries.
 */
export function findEncodedArtifacts(opts: {
  headers?: Record<string, string> | null;
  cookies?: Record<string, string> | null;
  query?: string | null;
  body?: string | null;
  bodyEncoding?: string;
  contentType?: string | null;
  side: "request" | "response";
}): EncodedArtifact[] {
  const out: EncodedArtifact[] = [];
  const seen = new Set<string>();

  const push = (a: EncodedArtifact) => {
    // Dedupe same kind+location+token (not cross-location — two places stay two rows)
    const key = `${a.kind}|${a.location}|${a.raw.slice(0, 200)}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(a);
  };

  let seq = 0;
  const nextId = (kind: EncodedKind, location: string) =>
    `${kind}:${location}:${seq++}`;

  const considerValue = (location: string, value: string) => {
    if (!value || typeof value !== "string") return;
    const v = value.trim();
    if (!v) return;

    // Basic auth (before JWT — Authorization can be either)
    if (/^Basic\s+/i.test(v)) {
      const basic = decodeBasicAuth(v);
      if (basic) {
        push({
          id: nextId("basic_auth", location),
          kind: "basic_auth",
          location,
          label: "Basic Auth",
          raw: v,
          basicAuth: basic,
        });
        return;
      }
    }

    if (looksLikeJwe(v)) {
      const jwe = decodeJweHeader(v);
      push({
        id: nextId("jwe", location),
        kind: "jwe",
        location,
        label: "JWE (encrypted)",
        raw: stripBearer(v),
        jwe: jwe || undefined,
      });
      return;
    }

    if (looksLikeJwt(v)) {
      const jwt = decodeJwt(v);
      push({
        id: nextId("jwt", location),
        kind: "jwt",
        location,
        label: "JWT",
        raw: jwt?.token || stripBearer(v),
        jwt: jwt || undefined,
      });
      return;
    }

    // Embedded JWT inside a larger string (e.g. "token=eyJ…")
    const embedded = extractEmbeddedJwts(v);
    if (embedded.length > 0) {
      for (const token of embedded) {
        const jwt = decodeJwt(token);
        push({
          id: nextId("jwt", location),
          kind: "jwt",
          location,
          label: "JWT",
          raw: token,
          jwt: jwt || undefined,
        });
      }
      return;
    }

    if (looksLikeBase64(v)) {
      push({
        id: nextId("base64", location),
        kind: "base64",
        location,
        label: "Base64",
        raw: v,
        base64: tryDecodeBase64(v) || undefined,
      });
    }
  };

  // Headers
  for (const [name, value] of Object.entries(opts.headers || {})) {
    const key = name.toLowerCase();
    // Cookie / Set-Cookie handled via cookie pairs to get per-name locations
    if (key === "cookie" || key === "set-cookie") continue;
    considerValue(`header:${name}`, value ?? "");
  }

  // Cookies
  if (opts.side === "request") {
    const pairs = resolveRequestCookies(opts.cookies, opts.headers);
    for (const c of pairs) {
      considerValue(`cookie:${c.name}`, c.value);
    }
  } else {
    const pairs = resolveResponseCookies(opts.headers);
    for (const c of pairs) {
      considerValue(`set-cookie:${c.name}`, c.value);
    }
  }

  // Query (request)
  if (opts.side === "request" && opts.query) {
    for (const p of parseQueryParams(opts.query)) {
      considerValue(`query:${p.name}`, p.value);
    }
  }

  // Body
  if (opts.body && opts.bodyEncoding !== "base64") {
    const body = opts.body;
    const ct = (opts.contentType || "").toLowerCase();

    // Structured form fields
    const formParams = parseBodyParams(body, opts.contentType, opts.bodyEncoding);
    if (formParams.length > 0) {
      for (const p of formParams) {
        if (p.value && p.value !== "(multipart part)") {
          considerValue(`body:${p.name}`, p.value);
        }
      }
    }

    // JSON leaf strings
    if (ct.includes("json") || looksLikeJson(body)) {
      walkJsonStrings(body, (path, str) => {
        considerValue(path ? `body.${path}` : "body", str);
      });
    } else if (formParams.length === 0) {
      // Raw body: scan for embedded JWTs; whole-body base64
      const jwts = extractEmbeddedJwts(body);
      for (const token of jwts) {
        const jwt = decodeJwt(token);
        push({
          id: nextId("jwt", "body"),
          kind: "jwt",
          location: "body",
          label: "JWT",
          raw: token,
          jwt: jwt || undefined,
        });
      }
      if (jwts.length === 0 && looksLikeBase64(body.trim())) {
        considerValue("body", body.trim());
      }
    }
  } else if (opts.body && opts.bodyEncoding === "base64") {
    // Stored binary — surface as opaque base64 blob (no full dump of huge payloads)
    const raw = opts.body.length > 4000 ? opts.body.slice(0, 4000) + "…" : opts.body;
    push({
      id: nextId("base64", "body"),
      kind: "base64",
      location: "body",
      label: "Binary body (base64)",
      raw,
      base64: {
        decoded: `[binary body — ${opts.body.length} base64 chars stored]`,
        isJson: false,
      },
    });
  }

  // Prefer JWT/JWE/Basic before base64 for stable reading; keep discovery order within kind
  const rank: Record<EncodedKind, number> = {
    jwt: 0,
    jwe: 1,
    basic_auth: 2,
    base64: 3,
  };
  out.sort((a, b) => rank[a.kind] - rank[b.kind] || a.location.localeCompare(b.location));
  return out;
}

/** Compact JWT tokens embedded in a larger string. */
function extractEmbeddedJwts(text: string): string[] {
  if (!text || text.length < 20) return [];
  const re =
    /\b(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)/g;
  const found: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const token = m[1];
    if (looksLikeJwt(token) && !found.includes(token)) found.push(token);
  }
  return found;
}

function looksLikeJson(body: string): boolean {
  const t = body.trim();
  return (
    (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))
  );
}

function walkJsonStrings(
  body: string,
  visit: (path: string, value: string) => void
): void {
  try {
    const data = JSON.parse(body) as unknown;
    const walk = (node: unknown, path: string) => {
      if (typeof node === "string") {
        visit(path, node);
        return;
      }
      if (Array.isArray(node)) {
        node.forEach((v, i) => walk(v, path ? `${path}[${i}]` : `[${i}]`));
        return;
      }
      if (node && typeof node === "object") {
        for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
          walk(v, path ? `${path}.${k}` : k);
        }
      }
    };
    walk(data, "");
  } catch {
    // not JSON
  }
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
