import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { UuidChip } from "../../components/Common";
import HttpInspector from "../../components/http/HttpInspector";
import { methodBadgeClass } from "../../lib/flowFlags";
import { formatIST } from "../../lib/time";
import { useProject } from "../../state/ProjectContext";
import { FlowDetail, FlowDetailBundle } from "../../types";

export interface FindingFlowSummary {
  id: string;
  missing?: boolean;
  method?: string | null;
  url?: string | null;
  path?: string | null;
  status_code?: number | null;
  replay_reason?: string | null;
}

export default function FindingFlowHttp({
  title,
  badgeClass,
  summary,
  emptyLabel,
}: {
  title: string;
  badgeClass: string;
  summary: FindingFlowSummary | null | undefined;
  emptyLabel: string;
}) {
  const { selected } = useProject();
  const flowId = summary && !summary.missing ? summary.id : null;
  const [flow, setFlow] = useState<FlowDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!selected || !flowId) {
      setFlow(null);
      setFailed(false);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    api
      .get<FlowDetailBundle>(`/api/flows/${flowId}`, { project_id: selected.id })
      .then((b) => {
        if (!cancelled) setFlow(b.flow);
      })
      .catch(() => {
        if (!cancelled) {
          setFlow(null);
          setFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected, flowId]);

  if (!summary) {
    return (
      <div className="panel p-3">
        <span className={`badge badge-sm ${badgeClass}`}>{title}</span>
        <p className="text-sm text-base-content/40 mt-2">{emptyLabel}</p>
      </div>
    );
  }

  if (summary.missing) {
    return (
      <div className="panel p-3">
        <div className="flex items-center gap-2 mb-2 flex-wrap">
          <span className={`badge badge-sm ${badgeClass}`}>{title}</span>
          <UuidChip value={summary.id} />
        </div>
        <p className="text-sm text-warning">
          Flow row missing from project DB (id may be stale).
        </p>
        <Link to={`/flows/${summary.id}`} className="btn btn-xs btn-outline mt-2">
          Open flow
        </Link>
      </div>
    );
  }

  const method = flow?.method || summary.method || "?";
  const url = flow?.url || summary.url || flow?.path || summary.path || "—";
  const status = flow?.status_code ?? summary.status_code;
  const replayReason = flow?.replay_reason || summary.replay_reason;

  return (
    <div className="panel p-3 border-l-4 border-l-primary/40">
      <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <span className={`badge badge-sm ${badgeClass}`}>{title}</span>
          <span className={`badge badge-outline badge-sm mono ${methodBadgeClass(method)}`}>
            {method}
          </span>
          {status != null && (
            <span className="badge badge-outline badge-sm mono">{status}</span>
          )}
          {replayReason && (
            <span className="badge badge-ghost badge-xs" title={replayReason}>
              {replayReason}
            </span>
          )}
          {flow?.captured_at && (
            <span className="text-xs text-base-content/50">{formatIST(flow.captured_at)}</span>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <Link to={`/flows/${summary.id}`} className="btn btn-xs btn-outline">
            Open flow
          </Link>
          <Link to={`/repeater?flow=${summary.id}`} className="btn btn-xs btn-outline">
            Send to Repeater
          </Link>
        </div>
      </div>
      <div className="text-sm mono break-all mb-3 text-base-content/80">{url}</div>
      {loading && (
        <div className="py-6 text-center">
          <span className="loading loading-spinner loading-sm" />
        </div>
      )}
      {failed && !loading && (
        <p className="text-sm text-warning">Could not load full HTTP for this flow.</p>
      )}
      {flow && !loading && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <div className="min-w-0">
            <h3 className="font-semibold text-sm mb-2">Request</h3>
            <HttpInspector
              side="request"
              startLine={`${flow.method} ${flow.path}${flow.query ? `?${flow.query}` : ""} HTTP/1.1`}
              headers={flow.request_headers || {}}
              cookies={flow.request_cookies || {}}
              body={flow.request_body}
              bodyEncoding={flow.request_body_encoding}
              contentType={flow.content_type}
              query={flow.query}
            />
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold text-sm mb-2">Response</h3>
            <HttpInspector
              side="response"
              startLine={`HTTP/1.1 ${flow.status_code ?? ""}`}
              headers={flow.response_headers || {}}
              body={flow.response_body}
              bodyEncoding={flow.response_body_encoding}
              contentType={
                (flow.response_headers &&
                  (flow.response_headers["Content-Type"] ||
                    flow.response_headers["content-type"])) ||
                flow.content_type
              }
            />
          </div>
        </div>
      )}
      <div className="mt-2">
        <UuidChip value={summary.id} />
      </div>
    </div>
  );
}
