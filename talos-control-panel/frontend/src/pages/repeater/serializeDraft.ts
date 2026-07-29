/**
 * serializeDraft — single client path from editor document → raw HTTP bytes.
 *
 * Mode is source of truth:
 *   raw            → raw_text / raw_base64 only
 *   pretty|params|json-assist → rebuild from structured fields (cookies table wins)
 *
 * Must stay aligned with talos.send.raw_http.serialize_request.
 */

import type { SendEditorMode } from "../../types";

export interface RequestDraft {
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  request_headers: Record<string, string>;
  request_cookies: Record<string, string>;
  request_body: string | null;
  request_body_base64: string | null;
  request_body_encoding: "utf8" | "base64" | string;
  raw_text: string | null;
  raw_base64: string | null;
  raw_encoding: "utf8" | "base64" | string;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function tryUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Case-insensitive header set/remove. */
export function setOrRemoveHeader(
  headers: Record<string, string>,
  name: string,
  value: string | null
): Record<string, string> {
  const lower = name.toLowerCase();
  const next: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== lower) next[k] = v;
  }
  if (value !== null) next[name] = value;
  return next;
}

/**
 * Cookies table owns the Cookie header (engine apply_cookie / buildCurl parity).
 * Empty cookies → remove Cookie header.
 */
export function setOrRemoveCookieHeader(
  headers: Record<string, string>,
  cookies: Record<string, string>
): Record<string, string> {
  const entries = Object.entries(cookies || {}).filter(
    ([k]) => k !== undefined && k !== null && String(k).length > 0
  );
  if (entries.length === 0) {
    return setOrRemoveHeader(headers, "Cookie", null);
  }
  const value = entries.map(([k, v]) => `${k}=${v}`).join("; ");
  return setOrRemoveHeader(headers, "Cookie", value);
}

function bodyBytesFromDraft(draft: RequestDraft): Uint8Array | null {
  if (draft.request_body_encoding === "base64" && draft.request_body_base64) {
    return base64ToBytes(draft.request_body_base64);
  }
  if (draft.request_body != null && draft.request_body !== "") {
    return utf8Encode(draft.request_body);
  }
  return null;
}

/**
 * Mirror of talos.send.raw_http.serialize_request.
 */
export function serializeLikePython(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Uint8Array | null
): Uint8Array {
  let path = "/";
  let query = "";
  let netloc = "";
  try {
    const u = new URL(url);
    path = u.pathname || "/";
    query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
    netloc = u.host; // includes port
  } catch {
    // fall through with defaults
  }
  const requestTarget = query ? `${path}?${query}` : path;
  const lines: string[] = [
    `${(method || "GET").toUpperCase()} ${requestTarget} HTTP/1.1\r\n`,
  ];

  const headerItems = Object.entries(headers);
  const hasHost = headerItems.some(([k]) => k.toLowerCase() === "host");
  if (!hasHost && netloc) {
    headerItems.unshift(["Host", netloc]);
  }

  for (const [name, value] of headerItems) {
    lines.push(`${name}: ${value}\r\n`);
  }
  lines.push("\r\n");

  const head = utf8Encode(lines.join(""));
  if (!body || body.length === 0) return head;
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

/**
 * Serialize draft for POST /api/send/once.
 * Returns raw HTTP message bytes.
 */
export function serializeDraft(
  draft: RequestDraft,
  mode: SendEditorMode
): Uint8Array {
  if (mode === "raw") {
    if (draft.raw_encoding === "base64" && draft.raw_base64) {
      return base64ToBytes(draft.raw_base64);
    }
    if (draft.raw_text != null) {
      return utf8Encode(draft.raw_text);
    }
    throw new Error("empty raw message");
  }

  // pretty | params | json-assist — structured fields authoritative
  let headers = { ...(draft.request_headers || {}) };
  headers = setOrRemoveCookieHeader(headers, draft.request_cookies || {});
  const body = bodyBytesFromDraft(draft);
  return serializeLikePython(draft.method, draft.url, headers, body);
}

/** After structured serialize, refresh dual raw_* storage on draft. */
export function refreshRawOnDraft(
  draft: RequestDraft,
  mode: SendEditorMode
): RequestDraft {
  try {
    const bytes = serializeDraft(draft, mode === "raw" ? "pretty" : mode);
    const text = tryUtf8(bytes);
    if (text != null) {
      return {
        ...draft,
        raw_text: text,
        raw_base64: null,
        raw_encoding: "utf8",
      };
    }
    return {
      ...draft,
      raw_text: null,
      raw_base64: bytesToBase64(bytes),
      raw_encoding: "base64",
    };
  } catch {
    return draft;
  }
}

/**
 * Parse raw HTTP request into structured draft fields (client-side).
 * Mirrors talos.send.raw_http.parse_request for mode switches.
 */
export function parseRawToDraft(
  rawBytes: Uint8Array,
  fallback: RequestDraft
): RequestDraft {
  const text = utf8Decode(rawBytes);
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const splitIdx = normalized.indexOf("\n\n");
  const head = splitIdx >= 0 ? normalized.slice(0, splitIdx) : normalized;
  const bodyText = splitIdx >= 0 ? normalized.slice(splitIdx + 2) : "";
  const lines = head.split("\n").filter((l, i, arr) => !(i === arr.length - 1 && l === ""));
  if (lines.length === 0) throw new Error("raw HTTP request has no request line");

  const parts = lines[0].trim().split(/\s+/);
  if (parts.length < 2) throw new Error(`invalid request line: ${lines[0]}`);
  const method = parts[0].toUpperCase();
  const requestTarget = parts[1];

  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    if (!line.trim()) continue;
    const colon = line.indexOf(":");
    if (colon < 0) throw new Error(`invalid header line: ${line}`);
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    headers[name] = value;
  }

  // Reconstruct URL
  let url = fallback.url;
  let host = fallback.host;
  let path = fallback.path;
  let query = fallback.query;

  if (requestTarget.startsWith("http://") || requestTarget.startsWith("https://")) {
    try {
      const u = new URL(requestTarget);
      url = requestTarget;
      host = u.hostname;
      path = u.pathname || "/";
      query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
    } catch {
      /* keep fallback */
    }
  } else {
    const hostHeader =
      Object.entries(headers).find(([k]) => k.toLowerCase() === "host")?.[1] ||
      fallback.host;
    let pathQ = requestTarget.startsWith("/") ? requestTarget : `/${requestTarget}`;
    if (pathQ === "*") pathQ = "/";
    if (pathQ.includes("?")) {
      const qi = pathQ.indexOf("?");
      path = pathQ.slice(0, qi) || "/";
      query = pathQ.slice(qi + 1);
    } else {
      path = pathQ || "/";
      query = "";
    }
    host = hostHeader.split(":")[0] || host;
    try {
      const base = new URL(fallback.url || `https://${hostHeader}${path}`);
      const proto = base.protocol || "https:";
      url = `${proto}//${hostHeader}${path}${query ? `?${query}` : ""}`;
    } catch {
      url = `https://${hostHeader}${path}${query ? `?${query}` : ""}`;
    }
  }

  // Cookies from Cookie header
  const cookies: Record<string, string> = {};
  const cookieHdr = Object.entries(headers).find(
    ([k]) => k.toLowerCase() === "cookie"
  )?.[1];
  if (cookieHdr) {
    for (const part of cookieHdr.split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0) continue;
      const n = part.slice(0, eq).trim();
      const v = part.slice(eq + 1).trim();
      if (n) cookies[n] = v;
    }
  }

  // Body: raw bytes after blank line (use original split for binary safety)
  let request_body: string | null = bodyText || null;
  let request_body_base64: string | null = null;
  let request_body_encoding: "utf8" | "base64" = "utf8";
  // Prefer binary-safe body from rawBytes
  const crlf = indexOfBytes(rawBytes, [13, 10, 13, 10]);
  const lf = indexOfBytes(rawBytes, [10, 10]);
  let bodyStart = -1;
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) bodyStart = crlf + 4;
  else if (lf >= 0) bodyStart = lf + 2;
  if (bodyStart >= 0 && bodyStart < rawBytes.length) {
    const bodyBytes = rawBytes.subarray(bodyStart);
    const decoded = tryUtf8(bodyBytes);
    if (decoded != null) {
      request_body = decoded || null;
      request_body_base64 = null;
      request_body_encoding = "utf8";
    } else {
      request_body = null;
      request_body_base64 = bytesToBase64(bodyBytes);
      request_body_encoding = "base64";
    }
  } else {
    request_body = null;
  }

  const rawText = tryUtf8(rawBytes);
  return {
    method,
    url,
    host,
    path,
    query,
    request_headers: headers,
    request_cookies: cookies,
    request_body,
    request_body_base64,
    request_body_encoding,
    raw_text: rawText,
    raw_base64: rawText == null ? bytesToBase64(rawBytes) : null,
    raw_encoding: rawText == null ? "base64" : "utf8",
  };
}

function indexOfBytes(hay: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export function draftFromSendResponse(d: {
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  request_headers: Record<string, string>;
  request_cookies: Record<string, string>;
  request_body: string | null;
  request_body_base64: string | null;
  request_body_encoding: string;
  raw: string | null;
  raw_base64: string | null;
  raw_encoding: string;
}): RequestDraft {
  return {
    method: d.method,
    url: d.url,
    host: d.host,
    path: d.path,
    query: d.query || "",
    request_headers: { ...(d.request_headers || {}) },
    request_cookies: { ...(d.request_cookies || {}) },
    request_body: d.request_body,
    request_body_base64: d.request_body_base64,
    request_body_encoding: d.request_body_encoding || "utf8",
    raw_text: d.raw,
    raw_base64: d.raw_base64,
    raw_encoding: d.raw_encoding || "utf8",
  };
}

export function emptyDraft(): RequestDraft {
  return {
    method: "GET",
    url: "",
    host: "",
    path: "/",
    query: "",
    request_headers: {},
    request_cookies: {},
    request_body: null,
    request_body_base64: null,
    request_body_encoding: "utf8",
    raw_text: null,
    raw_base64: null,
    raw_encoding: "utf8",
  };
}

/** Short tab title: METHOD + short path */
export function draftTitle(draft: RequestDraft): string {
  const path = draft.path || "/";
  const short = path.length > 40 ? path.slice(0, 37) + "…" : path;
  return `${(draft.method || "GET").toUpperCase()} ${short}`;
}
