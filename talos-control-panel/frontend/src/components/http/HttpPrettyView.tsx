/**
 * Pretty HTTP view: start-line + headers + pretty-printed body.
 * No cookie expansion or JWT decode panels (those live elsewhere if needed).
 */

import { useMemo } from "react";
import { normalizeHeaders, prettyBody } from "./parseHttp";

interface Props {
  startLine: string;
  headers: Record<string, string>;
  /** Request cookies map — synthesized into Cookie header only if missing. */
  cookies?: Record<string, string>;
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
  wrap?: boolean;
}

export default function HttpPrettyView({
  startLine,
  headers,
  cookies,
  body,
  bodyEncoding,
  contentType,
  wrap = true,
}: Props) {
  const headerLines = useMemo(() => {
    const normalized = normalizeHeaders(headers, []);
    // Prefer stored Cookie header; synthesize only when absent (same rule as Raw).
    const hasCookie = normalized.some((h) => h.name.toLowerCase() === "cookie");
    const lines = normalized.map((h) => `${h.name}: ${h.value}`);
    if (!hasCookie && cookies && Object.keys(cookies).length > 0) {
      const cookieLine = Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
      lines.push(`Cookie: ${cookieLine}`);
    }
    return lines;
  }, [headers, cookies]);

  const bodySection = useMemo(() => {
    if (bodyEncoding === "base64") {
      return {
        kind: "binary" as const,
        text: `Binary body stored as base64 (${body?.length || 0} chars).\n${(body || "").slice(0, 2000)}${(body?.length || 0) > 2000 ? "…" : ""}`,
      };
    }
    if (body == null || body === "") {
      return { kind: "empty" as const, text: "" };
    }
    const pretty = prettyBody(body, contentType, bodyEncoding);
    return { kind: pretty.kind, text: pretty.text };
  }, [body, bodyEncoding, contentType]);

  const preClass = `mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto ${
    wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"
  }`;

  return (
    <div className={`${preClass} space-y-0`}>
      <div className="text-secondary font-medium">{startLine}</div>
      {headerLines.length > 0 && (
        <div className="mt-1 text-base-content/80">
          {headerLines.map((line, i) => (
            <div key={i}>{line}</div>
          ))}
        </div>
      )}
      {bodySection.kind !== "empty" && (
        <>
          <div className="my-2 border-t border-base-content/15" />
          <div className={bodySection.kind === "json" ? "text-info" : ""}>
            {bodySection.text}
          </div>
        </>
      )}
      {bodySection.kind === "empty" && (
        <>
          <div className="my-2 border-t border-base-content/15" />
          <div className="text-base-content/40">Empty body.</div>
        </>
      )}
    </div>
  );
}
