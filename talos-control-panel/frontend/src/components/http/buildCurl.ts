/**
 * Client-side curl reconstruction from stored flow fields.
 * Not a Core export format — clipboard helper only.
 */

import { getHeader } from "./parseHttp";

export interface CurlInput {
  method: string;
  url: string;
  headers?: Record<string, string> | null;
  cookies?: Record<string, string> | null;
  body?: string | null;
  bodyEncoding?: string;
}

function shellEscape(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

export function buildCurl(input: CurlInput): string {
  const method = (input.method || "GET").toUpperCase();
  const parts: string[] = ["curl", "-X", method, shellEscape(input.url || "")];

  const headers = { ...(input.headers || {}) };
  const hasCookie = Object.keys(headers).some((k) => k.toLowerCase() === "cookie");
  if (!hasCookie && input.cookies && Object.keys(input.cookies).length > 0) {
    headers["Cookie"] = Object.entries(input.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  for (const [k, v] of Object.entries(headers)) {
    // Skip pseudo / hop-by-hop that confuse curl replays
    if (["content-length", "transfer-encoding"].includes(k.toLowerCase())) continue;
    parts.push("-H", shellEscape(`${k}: ${v}`));
  }

  if (input.body && input.bodyEncoding !== "base64" && method !== "GET" && method !== "HEAD") {
    parts.push("--data-binary", shellEscape(input.body));
  } else if (input.body && input.bodyEncoding === "base64") {
    parts.push("# body is binary (base64 in store) — not included in curl");
  }

  return parts.join(" ");
}

/** Reconstruct a minimal raw request string for clipboard. */
export function buildRawRequest(input: {
  method: string;
  path: string;
  query?: string;
  host?: string;
  headers?: Record<string, string> | null;
  cookies?: Record<string, string> | null;
  body?: string | null;
}): string {
  const path = input.path || "/";
  const q = input.query ? (input.query.startsWith("?") ? input.query : `?${input.query}`) : "";
  const start = `${(input.method || "GET").toUpperCase()} ${path}${q} HTTP/1.1`;
  const headers = { ...(input.headers || {}) };
  if (!getHeader(headers, "Host") && input.host) {
    headers["Host"] = input.host;
  }
  const hasCookie = Object.keys(headers).some((k) => k.toLowerCase() === "cookie");
  const lines = [start, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`)];
  if (!hasCookie && input.cookies && Object.keys(input.cookies).length > 0) {
    lines.push(
      `Cookie: ${Object.entries(input.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ")}`
    );
  }
  lines.push("");
  lines.push(input.body || "");
  return lines.join("\n");
}
