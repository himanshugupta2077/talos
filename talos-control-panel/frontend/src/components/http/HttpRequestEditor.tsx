/**
 * Editable request surface for the Repeater.
 * Modes: raw | pretty | params | json-assist (mutually exclusive).
 * Shares parse helpers with HttpInspector; never used for Flow Detail.
 */

import { useMemo, useState } from "react";
import type { SendEditorMode } from "../../types";
import { getHeader } from "./parseHttp";
import {
  parseRawToDraft,
  refreshRawOnDraft,
  serializeDraft,
  type RequestDraft,
} from "../../pages/repeater/serializeDraft";

const MODES: { id: SendEditorMode; label: string }[] = [
  { id: "pretty", label: "Pretty" },
  { id: "raw", label: "Raw" },
  { id: "params", label: "Params" },
  { id: "json-assist", label: "JSON" },
];

interface Props {
  draft: RequestDraft;
  onChange: (next: RequestDraft) => void;
  mode: SendEditorMode;
  onModeChange: (m: SendEditorMode) => void;
  disabled?: boolean;
  onModeError?: (msg: string) => void;
}

function isJsonObjectBody(body: string | null, encoding: string): boolean {
  if (!body || encoding === "base64") return false;
  try {
    const v = JSON.parse(body);
    return v !== null && typeof v === "object" && !Array.isArray(v);
  } catch {
    return false;
  }
}

function contentType(draft: RequestDraft): string {
  return getHeader(draft.request_headers, "Content-Type") || "";
}

export default function HttpRequestEditor({
  draft,
  onChange,
  mode,
  onModeChange,
  disabled,
  onModeError,
}: Props) {
  const jsonOk = useMemo(
    () => isJsonObjectBody(draft.request_body, draft.request_body_encoding),
    [draft.request_body, draft.request_body_encoding]
  );

  const switchMode = (next: SendEditorMode) => {
    if (next === mode) return;
    if (next === "json-assist" && !jsonOk) {
      onModeError?.("JSON assist needs a top-level JSON object body");
      return;
    }
    try {
      if (mode === "raw" && next !== "raw") {
        // raw → structured: parse raw_*
        const bytes = serializeDraft(draft, "raw");
        const parsed = parseRawToDraft(bytes, draft);
        onChange(parsed);
      } else if (mode !== "raw" && next === "raw") {
        // structured → raw: serialize and set raw_*
        onChange(refreshRawOnDraft(draft, mode));
      } else if (mode !== "raw" && next !== "raw") {
        // structured → structured: keep fields; refresh raw for consistency
        onChange(refreshRawOnDraft(draft, mode));
      }
      onModeChange(next);
    } catch (err) {
      onModeError?.(err instanceof Error ? err.message : String(err));
    }
  };

  const setHeaderRow = (oldKey: string, newKey: string, value: string) => {
    const headers = { ...draft.request_headers };
    if (oldKey !== newKey) delete headers[oldKey];
    if (newKey) headers[newKey] = value;
    // Cookie header is owned by cookies table in pretty — ignore direct Cookie edits
    if (newKey.toLowerCase() === "cookie") return;
    onChange({ ...draft, request_headers: headers });
  };

  const removeHeader = (key: string) => {
    if (key.toLowerCase() === "cookie") return;
    const headers = { ...draft.request_headers };
    delete headers[key];
    onChange({ ...draft, request_headers: headers });
  };

  const addHeader = () => {
    const headers = { ...draft.request_headers, "": "" };
    onChange({ ...draft, request_headers: headers });
  };

  const setCookieRow = (oldKey: string, newKey: string, value: string) => {
    const cookies = { ...draft.request_cookies };
    if (oldKey !== newKey) delete cookies[oldKey];
    if (newKey) cookies[newKey] = value;
    onChange({ ...draft, request_cookies: cookies });
  };

  const removeCookie = (key: string) => {
    const cookies = { ...draft.request_cookies };
    delete cookies[key];
    onChange({ ...draft, request_cookies: cookies });
  };

  const addCookie = () => {
    onChange({
      ...draft,
      request_cookies: { ...draft.request_cookies, "": "" },
    });
  };

  const updateUrl = (url: string) => {
    let host = draft.host;
    let path = draft.path;
    let query = draft.query;
    try {
      const u = new URL(url);
      host = u.hostname;
      path = u.pathname || "/";
      query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
      // Sync Host header when present
      const headers = { ...draft.request_headers };
      let found = false;
      for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === "host") {
          headers[k] = u.host;
          found = true;
          break;
        }
      }
      if (!found && u.host) headers["Host"] = u.host;
      onChange({ ...draft, url, host, path, query, request_headers: headers });
    } catch {
      onChange({ ...draft, url });
    }
  };

  const updateQueryParams = (pairs: { name: string; value: string }[]) => {
    const q = pairs
      .filter((p) => p.name !== "")
      .map(
        (p) =>
          `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value)}`
      )
      .join("&");
    try {
      const u = new URL(draft.url || `https://${draft.host || "example.com"}${draft.path || "/"}`);
      u.search = q ? `?${q}` : "";
      onChange({
        ...draft,
        url: u.toString(),
        query: q,
        path: u.pathname || draft.path,
      });
    } catch {
      onChange({ ...draft, query: q });
    }
  };

  const updateFormParams = (pairs: { name: string; value: string }[]) => {
    const body = pairs
      .filter((p) => p.name !== "")
      .map(
        (p) =>
          `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value)}`
      )
      .join("&");
    onChange({
      ...draft,
      request_body: body || null,
      request_body_base64: null,
      request_body_encoding: "utf8",
    });
  };

  const updateJsonKey = (oldKey: string, newKey: string, value: string) => {
    let obj: Record<string, unknown> = {};
    try {
      obj = JSON.parse(draft.request_body || "{}");
    } catch {
      obj = {};
    }
    if (oldKey !== newKey) delete obj[oldKey];
    // Try parse value as JSON literal, else string
    let parsed: unknown = value;
    try {
      parsed = JSON.parse(value);
    } catch {
      parsed = value;
    }
    if (newKey) obj[newKey] = parsed;
    onChange({
      ...draft,
      request_body: JSON.stringify(obj, null, 2),
      request_body_base64: null,
      request_body_encoding: "utf8",
    });
  };

  const removeJsonKey = (key: string) => {
    let obj: Record<string, unknown> = {};
    try {
      obj = JSON.parse(draft.request_body || "{}");
    } catch {
      return;
    }
    delete obj[key];
    onChange({
      ...draft,
      request_body: JSON.stringify(obj, null, 2),
    });
  };

  const addJsonKey = () => {
    let obj: Record<string, unknown> = {};
    try {
      obj = JSON.parse(draft.request_body || "{}");
    } catch {
      obj = {};
    }
    obj[""] = "";
    onChange({
      ...draft,
      request_body: JSON.stringify(obj, null, 2),
    });
  };

  const queryPairs = useMemo(() => {
    const q = draft.query || "";
    if (!q) return [] as { name: string; value: string }[];
    return q.split("&").filter(Boolean).map((part) => {
      const eq = part.indexOf("=");
      if (eq < 0) return { name: decodeURIComponent(part), value: "" };
      return {
        name: decodeURIComponent(part.slice(0, eq)),
        value: decodeURIComponent(part.slice(eq + 1)),
      };
    });
  }, [draft.query]);

  const formPairs = useMemo(() => {
    const ct = contentType(draft).toLowerCase();
    if (!ct.includes("application/x-www-form-urlencoded")) return null;
    const body = draft.request_body || "";
    if (!body) return [] as { name: string; value: string }[];
    return body.split("&").filter(Boolean).map((part) => {
      const eq = part.indexOf("=");
      if (eq < 0) return { name: decodeURIComponent(part), value: "" };
      return {
        name: decodeURIComponent(part.slice(0, eq)),
        value: decodeURIComponent(part.slice(eq + 1)),
      };
    });
  }, [draft]);

  const jsonEntries = useMemo(() => {
    if (!jsonOk || !draft.request_body) return [] as [string, string][];
    try {
      const obj = JSON.parse(draft.request_body) as Record<string, unknown>;
      return Object.entries(obj).map(([k, v]) => [
        k,
        typeof v === "string" ? v : JSON.stringify(v),
      ]);
    } catch {
      return [];
    }
  }, [draft.request_body, jsonOk]);

  const headerEntries = Object.entries(draft.request_headers || {}).filter(
    ([k]) => k.toLowerCase() !== "cookie"
  );
  const cookieEntries = Object.entries(draft.request_cookies || {});

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2 mb-2 flex-wrap shrink-0">
        <div className="join">
          {MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              className={`btn btn-xs join-item ${mode === m.id ? "btn-active" : ""}`}
              disabled={disabled || (m.id === "json-assist" && !jsonOk && mode !== "json-assist")}
              title={
                m.id === "json-assist" && !jsonOk
                  ? "Body must be a top-level JSON object"
                  : undefined
              }
              onClick={() => switchMode(m.id)}
            >
              {m.label}
            </button>
          ))}
        </div>
        <span className="text-[10px] text-base-content/40">
          Structured modes rebuild full raw on Send · cookies table owns Cookie header
        </span>
      </div>

      <div className="flex-1 min-h-0 overflow-auto">
        {mode === "raw" && (
          <textarea
            className="textarea textarea-bordered w-full h-full min-h-[280px] font-mono text-xs leading-relaxed"
            disabled={disabled}
            spellCheck={false}
            value={
              draft.raw_encoding === "base64"
                ? draft.raw_base64
                  ? `[binary raw — base64]\n${draft.raw_base64}`
                  : ""
                : draft.raw_text || ""
            }
            onChange={(e) => {
              const v = e.target.value;
              if (v.startsWith("[binary raw — base64]")) {
                const b64 = v.replace(/^\[binary raw — base64\]\n?/, "");
                onChange({
                  ...draft,
                  raw_text: null,
                  raw_base64: b64,
                  raw_encoding: "base64",
                });
              } else {
                onChange({
                  ...draft,
                  raw_text: v,
                  raw_base64: null,
                  raw_encoding: "utf8",
                });
              }
            }}
          />
        )}

        {mode === "pretty" && (
          <div className="space-y-3">
            <div className="flex gap-2 items-center">
              <input
                className="input input-bordered input-xs mono w-24"
                disabled={disabled}
                value={draft.method}
                onChange={(e) =>
                  onChange({ ...draft, method: e.target.value.toUpperCase() })
                }
              />
              <input
                className="input input-bordered input-xs mono flex-1"
                disabled={disabled}
                value={draft.url}
                onChange={(e) => updateUrl(e.target.value)}
                placeholder="https://host/path?query"
              />
            </div>

            <div>
              <div className="text-[10px] uppercase text-base-content/50 mb-1">
                Headers
              </div>
              <table className="table table-xs">
                <tbody>
                  {headerEntries.map(([k, v]) => (
                    <tr key={k || "empty"}>
                      <td className="w-1/3">
                        <input
                          className="input input-ghost input-xs mono w-full"
                          disabled={disabled}
                          value={k}
                          onChange={(e) => setHeaderRow(k, e.target.value, v)}
                        />
                      </td>
                      <td>
                        <input
                          className="input input-ghost input-xs mono w-full"
                          disabled={disabled}
                          value={v}
                          onChange={(e) => setHeaderRow(k, k, e.target.value)}
                        />
                      </td>
                      <td className="w-8">
                        <button
                          type="button"
                          className="btn btn-ghost btn-xs"
                          disabled={disabled}
                          onClick={() => removeHeader(k)}
                        >
                          ×
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                disabled={disabled}
                onClick={addHeader}
              >
                + header
              </button>
            </div>

            <div>
              <div className="text-[10px] uppercase text-base-content/50 mb-1">
                Cookies <span className="normal-case opacity-60">(owns Cookie header)</span>
              </div>
              <table className="table table-xs">
                <tbody>
                  {cookieEntries.map(([k, v]) => (
                    <tr key={k || "ck"}>
                      <td className="w-1/3">
                        <input
                          className="input input-ghost input-xs mono w-full"
                          disabled={disabled}
                          value={k}
                          onChange={(e) => setCookieRow(k, e.target.value, v)}
                        />
                      </td>
                      <td>
                        <input
                          className="input input-ghost input-xs mono w-full"
                          disabled={disabled}
                          value={v}
                          onChange={(e) => setCookieRow(k, k, e.target.value)}
                        />
                      </td>
                      <td className="w-8">
                        <button
                          type="button"
                          className="btn btn-ghost btn-xs"
                          disabled={disabled}
                          onClick={() => removeCookie(k)}
                        >
                          ×
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                disabled={disabled}
                onClick={addCookie}
              >
                + cookie
              </button>
            </div>

            <div>
              <div className="text-[10px] uppercase text-base-content/50 mb-1">
                Body
              </div>
              {draft.request_body_encoding === "base64" ? (
                <div className="text-xs text-warning p-2">
                  Binary body (base64). Switch to Raw to edit, or clear body.
                  <button
                    type="button"
                    className="btn btn-xs ml-2"
                    disabled={disabled}
                    onClick={() =>
                      onChange({
                        ...draft,
                        request_body: null,
                        request_body_base64: null,
                        request_body_encoding: "utf8",
                      })
                    }
                  >
                    Clear
                  </button>
                </div>
              ) : (
                <textarea
                  className="textarea textarea-bordered w-full min-h-[140px] font-mono text-xs"
                  disabled={disabled}
                  spellCheck={false}
                  value={draft.request_body || ""}
                  onChange={(e) =>
                    onChange({
                      ...draft,
                      request_body: e.target.value || null,
                      request_body_base64: null,
                      request_body_encoding: "utf8",
                    })
                  }
                />
              )}
            </div>
          </div>
        )}

        {mode === "params" && (
          <div className="space-y-4">
            <KvTable
              title="Query parameters"
              pairs={queryPairs}
              disabled={disabled}
              onChange={updateQueryParams}
            />
            {formPairs ? (
              <KvTable
                title="Form body (x-www-form-urlencoded)"
                pairs={formPairs}
                disabled={disabled}
                onChange={updateFormParams}
              />
            ) : (
              <p className="text-xs text-base-content/50">
                Form params available when Content-Type is{" "}
                <span className="mono">application/x-www-form-urlencoded</span>.
              </p>
            )}
          </div>
        )}

        {mode === "json-assist" && (
          <div>
            <p className="text-[10px] text-base-content/50 mb-2">
              Top-level JSON object keys only (engine json_sets parity). Nested paths
              are not supported.
            </p>
            <table className="table table-xs">
              <tbody>
                {jsonEntries.map(([k, v]) => (
                  <tr key={k || "jk"}>
                    <td className="w-1/3">
                      <input
                        className="input input-ghost input-xs mono w-full"
                        disabled={disabled}
                        value={k}
                        onChange={(e) => updateJsonKey(k, e.target.value, v)}
                      />
                    </td>
                    <td>
                      <input
                        className="input input-ghost input-xs mono w-full"
                        disabled={disabled}
                        value={v}
                        onChange={(e) => updateJsonKey(k, k, e.target.value)}
                      />
                    </td>
                    <td className="w-8">
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        disabled={disabled}
                        onClick={() => removeJsonKey(k)}
                      >
                        ×
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              disabled={disabled}
              onClick={addJsonKey}
            >
              + key
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function KvTable({
  title,
  pairs,
  disabled,
  onChange,
}: {
  title: string;
  pairs: { name: string; value: string }[];
  disabled?: boolean;
  onChange: (pairs: { name: string; value: string }[]) => void;
}) {
  const [local, setLocal] = useState(pairs);
  // Sync when pairs prop identity changes significantly
  const key = pairs.map((p) => `${p.name}=${p.value}`).join("&");
  const [prevKey, setPrevKey] = useState(key);
  if (key !== prevKey) {
    setPrevKey(key);
    setLocal(pairs);
  }

  const commit = (next: { name: string; value: string }[]) => {
    setLocal(next);
    onChange(next);
  };

  return (
    <div>
      <div className="text-[10px] uppercase text-base-content/50 mb-1">{title}</div>
      <table className="table table-xs">
        <tbody>
          {local.map((p, i) => (
            <tr key={i}>
              <td className="w-1/3">
                <input
                  className="input input-ghost input-xs mono w-full"
                  disabled={disabled}
                  value={p.name}
                  onChange={(e) => {
                    const next = local.map((row, j) =>
                      j === i ? { ...row, name: e.target.value } : row
                    );
                    commit(next);
                  }}
                />
              </td>
              <td>
                <input
                  className="input input-ghost input-xs mono w-full"
                  disabled={disabled}
                  value={p.value}
                  onChange={(e) => {
                    const next = local.map((row, j) =>
                      j === i ? { ...row, value: e.target.value } : row
                    );
                    commit(next);
                  }}
                />
              </td>
              <td className="w-8">
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  disabled={disabled}
                  onClick={() => commit(local.filter((_, j) => j !== i))}
                >
                  ×
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button
        type="button"
        className="btn btn-ghost btn-xs"
        disabled={disabled}
        onClick={() => commit([...local, { name: "", value: "" }])}
      >
        + row
      </button>
    </div>
  );
}
