/**
 * HTTP request/response viewer for Flow detail.
 *
 * Tabs (both sides): Pretty (default) · Raw · Params (request) · JWT (request).
 * Pretty shows start-line, all headers, and pretty-printed body. Wrap is always on.
 */

import { useMemo, useState } from "react";
import HttpRawView from "./HttpRawView";
import HttpPrettyView from "./HttpPrettyView";
import HttpJwtView from "./HttpJwtView";
import HttpParamsView from "./HttpParamsView";
import {
  findJwt,
  parseBodyParams,
  parseQueryParams,
} from "./parseHttp";

export type RequestTab = "pretty" | "raw" | "params" | "jwt";
export type ResponseTab = "pretty" | "raw";

interface SideProps {
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
  /** Request-only: query string for Params */
  query?: string;
  side: "request" | "response";
}

const REQ_TABS: { id: RequestTab; label: string }[] = [
  { id: "pretty", label: "Pretty" },
  { id: "raw", label: "Raw" },
  { id: "params", label: "Params" },
  { id: "jwt", label: "JWT" },
];

const RESP_TABS: { id: ResponseTab; label: string }[] = [
  { id: "pretty", label: "Pretty" },
  { id: "raw", label: "Raw" },
];

export default function HttpInspector(props: SideProps) {
  const isReq = props.side === "request";
  const [reqTab, setReqTab] = useState<RequestTab>("pretty");
  const [respTab, setRespTab] = useState<ResponseTab>("pretty");

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

  const tab = isReq ? reqTab : respTab;
  const tabs = isReq ? REQ_TABS : RESP_TABS;

  return (
    <div>
      <div className="flex items-center mb-2 gap-2 flex-wrap">
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
      </div>

      {tab === "pretty" && (
        <HttpPrettyView
          startLine={props.startLine}
          headers={props.headers}
          cookies={isReq ? props.cookies : undefined}
          body={props.body}
          bodyEncoding={props.bodyEncoding}
          contentType={props.contentType}
          side={props.side}
        />
      )}

      {tab === "raw" && (
        <HttpRawView
          startLine={props.startLine}
          headers={props.headers}
          cookies={isReq ? props.cookies : undefined}
          body={props.body}
        />
      )}

      {isReq && tab === "params" && (
        <HttpParamsView query={queryParams} bodyParams={bodyParams} />
      )}

      {isReq && tab === "jwt" && <HttpJwtView jwt={jwt} />}
    </div>
  );
}
