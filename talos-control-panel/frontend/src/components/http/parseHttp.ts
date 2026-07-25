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

export function prettyBody(
  body: string | null | undefined,
  contentType: string | null | undefined,
  bodyEncoding?: string
): { text: string; kind: "json" | "text" | "binary" | "empty" } {
  if (bodyEncoding === "base64") {
    return {
      text: `[binary body — base64, ${body?.length || 0} chars]`,
      kind: "binary",
    };
  }
  if (body == null || body === "") return { text: "—", kind: "empty" };
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("json") || body.trimStart().startsWith("{") || body.trimStart().startsWith("[")) {
    try {
      return { text: JSON.stringify(JSON.parse(body), null, 2), kind: "json" };
    } catch {
      return { text: body, kind: "text" };
    }
  }
  return { text: body, kind: "text" };
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
