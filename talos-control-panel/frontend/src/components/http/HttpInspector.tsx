/**
 * HTTP request/response viewer for Flow detail.
 *
 * Tabs (both sides): Pretty (default) · Raw · Params (request) · Encoded.
 * Pretty shows start-line, all headers, and pretty-printed body. Wrap is always on.
 * Encoded folds every JWT / JWE / Basic auth / base64 blob found in the message.
 */

import { useMemo, useState } from "react";
import HttpRawView from "./HttpRawView";
import HttpPrettyView from "./HttpPrettyView";
import HttpEncodedView from "./HttpEncodedView";
import HttpParamsView from "./HttpParamsView";
import {
  findEncodedArtifacts,
  parseBodyParams,
  parseQueryParams,
} from "./parseHttp";

export type RequestTab = "pretty" | "raw" | "params" | "encoded";
export type ResponseTab = "pretty" | "raw" | "encoded";

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
  { id: "encoded", label: "Encoded" },
];

const RESP_TABS: { id: ResponseTab; label: string }[] = [
  { id: "pretty", label: "Pretty" },
  { id: "raw", label: "Raw" },
  { id: "encoded", label: "Encoded" },
];

export default function HttpInspector(props: SideProps) {
  const isReq = props.side === "request";
  const [reqTab, setReqTab] = useState<RequestTab>("pretty");
  const [respTab, setRespTab] = useState<ResponseTab>("pretty");

  const encoded = useMemo(
    () =>
      findEncodedArtifacts({
        headers: props.headers,
        cookies: props.cookies,
        query: isReq ? props.query : undefined,
        body: props.body,
        bodyEncoding: props.bodyEncoding,
        contentType: props.contentType,
        side: props.side,
      }),
    [
      isReq,
      props.headers,
      props.cookies,
      props.query,
      props.body,
      props.bodyEncoding,
      props.contentType,
      props.side,
    ]
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
                isReq
                  ? setReqTab(t.id as RequestTab)
                  : setRespTab(t.id as ResponseTab)
              }
            >
              {t.label}
              {t.id === "encoded" && encoded.length > 0 && (
                <span className="badge badge-ghost badge-xs ml-1">{encoded.length}</span>
              )}
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

      {tab === "encoded" && <HttpEncodedView artifacts={encoded} />}
    </div>
  );
}
