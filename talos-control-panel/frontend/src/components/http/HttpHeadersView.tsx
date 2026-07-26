import { useState } from "react";
import { CookiePair, NormalizedHeader, normalizeHeaders } from "./parseHttp";

interface Props {
  headers: Record<string, string>;
  /** Optional pre-resolved cookies for Cookie count badge only. */
  cookiePairs?: CookiePair[];
  wrap?: boolean;
}

/**
 * Headers tab: opaque rows. Cookie/Authorization are single lines (count/JWT badge).
 * Expanded cookies and decoded JWT/base64 live in their own tabs — never here.
 */
export default function HttpHeadersView({ headers, cookiePairs, wrap = true }: Props) {
  const rows = normalizeHeaders(headers, cookiePairs);
  if (rows.length === 0) {
    return <div className="text-xs text-base-content/40 p-2">No headers.</div>;
  }
  return (
    <div
      className={`mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto space-y-1.5 ${
        wrap ? "" : "overflow-x-auto"
      }`}
    >
      {rows.map((h) => (
        <HeaderLine key={h.key} header={h} />
      ))}
    </div>
  );
}

function HeaderLine({ header }: { header: NormalizedHeader }) {
  const [expanded, setExpanded] = useState(false);
  const long = (header.value || "").length > 120;
  const display =
    long && !expanded ? header.value.slice(0, 120) + "…" : header.value;

  let badge: string | null = null;
  if (header.isCookie || header.isSetCookie) {
    const n = header.cookieCount ?? 0;
    badge = n > 0 ? `${n}` : null;
  } else if (header.isAuthorization && header.looksLikeJwt) {
    badge = "JWT";
  }

  return (
    <div className="flex gap-2 items-start">
      <span className="text-primary/80 shrink-0">
        {header.name}
        {badge != null && (
          <span className="badge badge-ghost badge-xs ml-1 align-middle">{badge}</span>
        )}
        :
      </span>
      <span className="break-all min-w-0">
        {display || <span className="text-base-content/30">—</span>}
        {long && (
          <button
            type="button"
            className="link link-hover text-[10px] ml-1"
            onClick={() => setExpanded((e) => !e)}
          >
            {expanded ? "collapse" : "expand"}
          </button>
        )}
      </span>
    </div>
  );
}
