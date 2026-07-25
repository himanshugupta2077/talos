/**
 * Burp-style HTTP inspector for Flow detail.
 *
 * Strict non-duplication: Cookies/JWT/params appear in dedicated tabs only;
 * Headers keeps opaque Cookie / Authorization rows (count / JWT badge).
 */

import { useMemo, useState, type ReactNode } from "react";
import HttpRawView from "./HttpRawView";
import HttpHeadersView from "./HttpHeadersView";
import HttpCookiesView from "./HttpCookiesView";
import HttpJwtView from "./HttpJwtView";
import HttpParamsView from "./HttpParamsView";
import HttpBodyView from "./HttpBodyView";
import {
  findJwt,
  inspectorHeaderSummary,
  normalizeHeaders,
  parseBodyParams,
  parseQueryParams,
  resolveRequestCookies,
  resolveResponseCookies,
} from "./parseHttp";

export type RequestTab =
  | "raw"
  | "inspector"
  | "headers"
  | "cookies"
  | "jwt"
  | "params"
  | "body";

export type ResponseTab = "raw" | "headers" | "cookies" | "body" | "pretty";

interface SideProps {
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
  /** Request-only: query string for Params / Inspector */
  query?: string;
  side: "request" | "response";
}

const REQ_TABS: { id: RequestTab; label: string }[] = [
  { id: "raw", label: "Raw" },
  { id: "inspector", label: "Inspector" },
  { id: "headers", label: "Headers" },
  { id: "cookies", label: "Cookies" },
  { id: "jwt", label: "JWT" },
  { id: "params", label: "Params" },
  { id: "body", label: "Body" },
];

const RESP_TABS: { id: ResponseTab; label: string }[] = [
  { id: "raw", label: "Raw" },
  { id: "headers", label: "Headers" },
  { id: "cookies", label: "Cookies" },
  { id: "pretty", label: "Pretty" },
  { id: "body", label: "Body" },
];

export default function HttpInspector(props: SideProps) {
  const isReq = props.side === "request";
  const [reqTab, setReqTab] = useState<RequestTab>("inspector");
  const [respTab, setRespTab] = useState<ResponseTab>("pretty");
  const [wrap, setWrap] = useState(true);

  const cookiePairs = useMemo(() => {
    if (isReq) {
      return resolveRequestCookies(props.cookies, props.headers);
    }
    return resolveResponseCookies(props.headers);
  }, [isReq, props.cookies, props.headers]);

  const jwt = useMemo(
    () => (isReq ? findJwt(props.headers) : null),
    [isReq, props.headers]
  );

  const queryParams = useMemo(
    () => (isReq ? parseQueryParams(props.query) : []),
    [isReq, props.query]
  );

  const bodyParams = useMemo(
    () =>
      isReq
        ? parseBodyParams(props.body, props.contentType, props.bodyEncoding)
        : [],
    [isReq, props.body, props.contentType, props.bodyEncoding]
  );

  const normalized = useMemo(
    () => normalizeHeaders(props.headers, cookiePairs),
    [props.headers, cookiePairs]
  );

  const tab = isReq ? reqTab : respTab;
  const tabs = isReq ? REQ_TABS : RESP_TABS;

  return (
    <div>
      <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
        <div className="join flex-wrap">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              className={`btn btn-xs join-item ${tab === t.id ? "btn-active" : ""}`}
              onClick={() =>
                isReq ? setReqTab(t.id as RequestTab) : setRespTab(t.id as ResponseTab)
              }
            >
              {t.label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1 text-xs cursor-pointer shrink-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={wrap}
            onChange={(e) => setWrap(e.target.checked)}
          />
          Wrap
        </label>
      </div>

      {tab === "raw" && (
        <HttpRawView
          startLine={props.startLine}
          headers={props.headers}
          cookies={isReq ? props.cookies : undefined}
          body={props.body}
          wrap={wrap}
        />
      )}

      {tab === "headers" && (
        <HttpHeadersView
          headers={props.headers}
          cookiePairs={cookiePairs}
          wrap={wrap}
        />
      )}

      {tab === "cookies" && (
        <HttpCookiesView
          cookies={cookiePairs}
          emptyLabel={
            isReq ? "No request cookies." : "No Set-Cookie on this response."
          }
        />
      )}

      {isReq && tab === "jwt" && <HttpJwtView jwt={jwt} />}

      {isReq && tab === "params" && (
        <HttpParamsView query={queryParams} bodyParams={bodyParams} />
      )}

      {(tab === "body" || tab === "pretty") && (
        <HttpBodyView
          body={props.body}
          bodyEncoding={props.bodyEncoding}
          contentType={props.contentType}
          mode={tab === "body" && !isReq ? "raw" : tab === "pretty" ? "pretty" : "pretty"}
          wrap={wrap}
        />
      )}

      {isReq && tab === "inspector" && (
        <InspectorSummary
          startLine={props.startLine}
          headers={normalized}
          cookieNames={cookiePairs.map((c) => c.name)}
          query={queryParams}
          bodyParams={bodyParams}
          jwt={jwt}
        />
      )}
    </div>
  );
}

function InspectorSummary({
  startLine,
  headers,
  cookieNames,
  query,
  bodyParams,
  jwt,
}: {
  startLine: string;
  headers: ReturnType<typeof normalizeHeaders>;
  cookieNames: string[];
  query: { name: string; value: string }[];
  bodyParams: { name: string; value: string }[];
  jwt: ReturnType<typeof findJwt>;
}) {
  const headerSummary = inspectorHeaderSummary(headers);
  return (
    <div className="mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto space-y-3">
      <div className="text-secondary">{startLine}</div>

      <SummaryRow label="Headers">
        {headerSummary.length === 0 ? (
          <span className="text-base-content/40">—</span>
        ) : (
          <span className="flex flex-wrap gap-1">
            {headerSummary.map((h) => (
              <span key={h.name} className="badge badge-ghost badge-sm">
                {h.name}
                {h.badge != null && (
                  <span className="opacity-60 ml-0.5">({h.badge})</span>
                )}
              </span>
            ))}
          </span>
        )}
      </SummaryRow>

      <SummaryRow label="Cookies">
        {cookieNames.length === 0 ? (
          <span className="text-base-content/40">—</span>
        ) : (
          cookieNames.join(", ")
        )}
      </SummaryRow>

      <SummaryRow label="Query">
        {query.length === 0 ? (
          <span className="text-base-content/40">—</span>
        ) : (
          query.map((q) => q.name).join(", ")
        )}
      </SummaryRow>

      <SummaryRow label="Body params">
        {bodyParams.length === 0 ? (
          <span className="text-base-content/40">—</span>
        ) : (
          bodyParams.map((p) => p.name).join(", ")
        )}
      </SummaryRow>

      <SummaryRow label="JWT">
        {!jwt || !jwt.payload ? (
          <span className="text-base-content/40">—</span>
        ) : (
          <span>
            {jwt.claimsSummary?.sub != null && (
              <span className="mr-2">sub={String(jwt.claimsSummary.sub)}</span>
            )}
            {jwt.claimsSummary?.exp != null && (
              <span className="mr-2">exp={jwt.claimsSummary.exp}</span>
            )}
            <span className="text-base-content/40">(see JWT tab)</span>
          </span>
        )}
      </SummaryRow>
    </div>
  );
}

function SummaryRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex gap-3">
      <span className="text-base-content/50 w-24 shrink-0 uppercase text-[10px] tracking-wide pt-0.5">
        {label}
      </span>
      <div className="min-w-0 break-all">{children}</div>
    </div>
  );
}
