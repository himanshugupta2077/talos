import { useState } from "react";

type Mode = "pretty" | "raw";

function decodeJwt(value: string): string | null {
  const token = value.replace(/^Bearer\s+/i, "").trim();
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = (s: string) => {
      const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
      return decodeURIComponent(
        atob(padded)
          .split("")
          .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
          .join("")
      );
    };
    const header = JSON.parse(b64(parts[0]));
    const payload = JSON.parse(b64(parts[1]));
    return JSON.stringify({ header, payload }, null, 2);
  } catch {
    return null;
  }
}

function prettyBody(body: string | null, contentType: string): { text: string; isJson: boolean } {
  if (!body) return { text: "—", isJson: false };
  if (contentType && contentType.includes("json")) {
    try {
      return { text: JSON.stringify(JSON.parse(body), null, 2), isJson: true };
    } catch {
      return { text: body, isJson: false };
    }
  }
  return { text: body, isJson: false };
}

function HeaderRow({ name, value }: { name: string; value: string }) {
  const jwt = decodeJwt(value);
  const isCookieHeader = name.toLowerCase() === "cookie" || name.toLowerCase() === "set-cookie";
  return (
    <div className="mb-1.5">
      <div className="flex gap-2">
        <span className="text-primary/80 shrink-0">{name}:</span>
        <span className="break-all">{value}</span>
      </div>
      {isCookieHeader && (
        <div className="pl-4 mt-0.5 text-base-content/50">
          {value.split(";").map((pair, i) => {
            const [k, ...rest] = pair.trim().split("=");
            return (
              <div key={i}>
                {k}
                {rest.length > 0 && <>={rest.join("=")}</>}
              </div>
            );
          })}
        </div>
      )}
      {jwt && (
        <pre className="pl-4 mt-1 text-base-content/50 whitespace-pre-wrap break-all">{jwt}</pre>
      )}
    </div>
  );
}

interface HttpViewProps {
  /** e.g. "GET /path?x=1 HTTP/1.1" or "HTTP/1.1 200 OK" */
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
}

/**
 * Burp-style request/response viewer: a raw mode (byte-for-byte, word-wrapped,
 * no section labels) and a pretty mode (headers with inline JWT decoding,
 * cookies broken out, JSON body indented).
 */
export default function HttpView({ startLine, headers, cookies, body, bodyEncoding, contentType }: HttpViewProps) {
  const [mode, setMode] = useState<Mode>("pretty");
  const [wrap, setWrap] = useState(true);

  const headerEntries = Object.entries(headers || {});
  const hasCookieHeader = headerEntries.some(([k]) => k.toLowerCase() === "cookie");
  const cookieEntries = Object.entries(cookies || {});

  const rawLines = [startLine, ...headerEntries.map(([k, v]) => `${k}: ${v}`)];
  if (!hasCookieHeader && cookieEntries.length > 0) {
    rawLines.push(`Cookie: ${cookieEntries.map(([k, v]) => `${k}=${v}`).join("; ")}`);
  }
  const rawText = [...rawLines, "", body || ""].join("\n");

  const pretty = prettyBody(body, contentType || "");

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="join">
          <button
            className={`btn btn-xs join-item ${mode === "pretty" ? "btn-active" : ""}`}
            onClick={() => setMode("pretty")}
          >
            Pretty
          </button>
          <button
            className={`btn btn-xs join-item ${mode === "raw" ? "btn-active" : ""}`}
            onClick={() => setMode("raw")}
          >
            Raw
          </button>
        </div>
        <label className="flex items-center gap-1 text-xs cursor-pointer">
          <input type="checkbox" className="checkbox checkbox-xs" checked={wrap} onChange={(e) => setWrap(e.target.checked)} />
          Wrap
        </label>
      </div>

      {mode === "raw" ? (
        <pre className={`mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto ${wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"}`}>
          {rawText}
        </pre>
      ) : (
        <div className={`mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto ${wrap ? "" : "overflow-x-auto"}`}>
          <div className="text-secondary mb-2">{startLine}</div>
          {headerEntries.map(([k, v]) => (
            <HeaderRow key={k} name={k} value={v} />
          ))}
          {!hasCookieHeader && cookieEntries.length > 0 && (
            <div className="mb-1.5">
              <div className="text-primary/80">Cookie:</div>
              <div className="pl-4 text-base-content/50">
                {cookieEntries.map(([k, v]) => <div key={k}>{k}={v}</div>)}
              </div>
            </div>
          )}
          <div className="divider my-2" />
          {bodyEncoding === "base64" ? (
            <div className="text-base-content/40">[binary body — base64, {body?.length || 0} chars]</div>
          ) : (
            <pre className={`${wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre"} ${pretty.isJson ? "text-info" : ""}`}>
              {pretty.text}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
