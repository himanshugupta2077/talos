import { useEffect, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { Section } from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import HttpView from "../components/HttpView";
import { formatIST } from "../lib/time";
import { FlowDetail as FlowDetailT } from "../types";

interface Bundle {
  flow: FlowDetailT;
  diff: any;
  bac_result: any;
  unauth_result: any;
  auth_test_result: any;
}

export default function FlowDetail() {
  const { flowId } = useParams();
  const { selected } = useProject();
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [adjacent, setAdjacent] = useState<{ prev_id: string | null; next_id: string | null }>({ prev_id: null, next_id: null });
  const navigate = useNavigate();

  const load = () => {
    if (!selected || !flowId) return;
    api.get<Bundle>(`/api/flows/${flowId}`, { project_id: selected.id }).then(setBundle);
    api.get(`/api/flows/${flowId}/adjacent`, { project_id: selected.id }).then(setAdjacent as any);
  };

  useEffect(load, [selected, flowId]);

  const replayNow = useAction("Replay flow now", () =>
    api.post(`/api/replay/flow/${flowId}`, { right_now: true }, { project_id: selected!.id })
  );
  const enqueueReplay = useAction("Enqueue flow replay", () =>
    api.post("/api/scheduler/enqueue/flow", { flow_id: flowId }, { project_id: selected!.id })
  );
  const exportFlow = useAction("Export flow", () =>
    api.post(`/api/flows/${flowId}/export`, {}, { project_id: selected!.id })
  );

  if (!bundle) return <div className="loading loading-spinner" />;
  const { flow, diff, bac_result, unauth_result, auth_test_result } = bundle;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <button className="btn btn-xs" disabled={!adjacent.prev_id} onClick={() => navigate(`/flows/${adjacent.prev_id}`)}>← newer</button>
          <button className="btn btn-xs" disabled={!adjacent.next_id} onClick={() => navigate(`/flows/${adjacent.next_id}`)}>older →</button>
        </div>
        <Link to="/flows" className="link link-sm">back to list</Link>
      </div>

      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="badge badge-outline mono">{flow.method}</span>
          <span className="mono">{flow.url}</span>
          <StatusBadge value={flow.status_code} />
        </div>
        <div className="text-xs text-base-content/50 flex gap-3 flex-wrap">
          <span>{formatIST(flow.captured_at)}</span>
          <span>role: {flow.role_name}</span>
          <span>module: {flow.module_name}</span>
          <span>source: {flow.source}</span>
          {flow.endpoint_id && (
            <Link to={`/endpoints/${flow.endpoint_id}`} className="link">endpoint</Link>
          )}
          {flow.original_flow_id && (
            <Link to={`/flows/${flow.original_flow_id}`} className="link">original flow</Link>
          )}
        </div>
      </div>

      <Section title="Actions">
        <div className="flex gap-2 flex-wrap">
          <button className="btn btn-xs" onClick={() => replayNow.run()}>Replay now</button>
          <button className="btn btn-xs" onClick={() => enqueueReplay.run()}>Enqueue replay</button>
          <button className="btn btn-xs" onClick={() => exportFlow.run()}>Export</button>
        </div>
      </Section>

      {(diff || bac_result || unauth_result || auth_test_result) && (
        <Section title="Attack / replay results">
          <div className="flex flex-wrap gap-4 text-sm">
            {diff && (
              <div className="panel p-3">
                <div className="text-xs uppercase text-base-content/50 mb-1">Diff</div>
                <StatusBadge value={diff.verdict} />
                {diff.status_diff && <div className="mono text-xs mt-1">{diff.status_diff}</div>}
                <div className="text-xs mt-1">length Δ {diff.length_diff}</div>
              </div>
            )}
            {bac_result && (
              <div className="panel p-3">
                <div className="text-xs uppercase text-base-content/50 mb-1">BAC result</div>
                <StatusBadge value={bac_result.verdict} />
                <div className="text-xs mt-1">{bac_result.attack_type} / {bac_result.variant}</div>
              </div>
            )}
            {unauth_result && (
              <div className="panel p-3">
                <div className="text-xs uppercase text-base-content/50 mb-1">Unauth result</div>
                <StatusBadge value={unauth_result.verdict} />
                <div className="text-xs mt-1">{unauth_result.auth_mutation}</div>
              </div>
            )}
            {auth_test_result && (
              <div className="panel p-3">
                <div className="text-xs uppercase text-base-content/50 mb-1">Auth-bypass test</div>
                <StatusBadge value={auth_test_result.verdict} />
              </div>
            )}
          </div>
        </Section>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Section title="Request">
          <HttpView
            startLine={`${flow.method} ${flow.path}${flow.query ? `?${flow.query}` : ""} HTTP/1.1`}
            headers={flow.request_headers}
            cookies={flow.request_cookies}
            body={flow.request_body}
            bodyEncoding={flow.request_body_encoding}
            contentType={flow.content_type}
          />
        </Section>

        <Section title="Response">
          <HttpView
            startLine={`HTTP/1.1 ${flow.status_code ?? ""}`}
            headers={flow.response_headers}
            body={flow.response_body}
            bodyEncoding={flow.response_body_encoding}
            contentType={flow.content_type}
          />
        </Section>
      </div>
    </div>
  );
}
