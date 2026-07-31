import { Link } from "react-router-dom";
import { UuidChip } from "../../components/Common";
import { URL_SINKS_BASE } from "../attack/registry";
import { inventoryHref } from "../url-sinks/shared";

interface UrlSinksStrip {
  nrs_count?: number;
  max_score?: number;
  count?: number;
  endpoint_id?: string | null;
}

interface Props {
  roleName?: string;
  moduleName?: string;
  endpointId?: string | null;
  originalFlowId?: string | null;
  childrenCount: number;
  findings: {
    finding_id: string;
    title: string;
    status: string;
    evidence_type: string;
  }[];
  jobs: {
    job_id: string;
    job_type: string;
    status: string;
  }[];
  paramCount?: number;
  /** Passive URL sink strip for this flow's endpoint (PR5). */
  urlSinks?: UrlSinksStrip | null;
}

export default function FlowRelatedPanel({
  roleName,
  moduleName,
  endpointId,
  originalFlowId,
  childrenCount,
  findings,
  jobs,
  paramCount,
  urlSinks,
}: Props) {
  const sinkEndpointId = urlSinks?.endpoint_id || endpointId || null;
  const showSinks =
    sinkEndpointId &&
    urlSinks &&
    ((urlSinks.count ?? 0) > 0 || (urlSinks.nrs_count ?? 0) > 0);

  return (
    <div className="space-y-2 text-xs">
      <Item label="Role" value={roleName || "—"} />
      <Item label="Module" value={moduleName || "—"} />
      {endpointId && (
        <div>
          <span className="text-base-content/50">Endpoint </span>
          <Link to={`/endpoints/${endpointId}`} className="link">
            <UuidChip value={endpointId} />
          </Link>
          {paramCount != null && (
            <span className="text-base-content/40 ml-1">· {paramCount} params</span>
          )}
        </div>
      )}
      {showSinks && (
        <div className="pt-1 border-t border-base-300/60">
          <div className="text-base-content/50 mb-1">URL sinks on endpoint</div>
          <div className="mb-1">
            <span className="mono tabular-nums">{urlSinks!.nrs_count ?? 0}</span>{" "}
            NRS · max score{" "}
            <span className="mono tabular-nums">{urlSinks!.max_score ?? 0}</span>
            {(urlSinks!.count ?? 0) > 0 && (
              <span className="text-base-content/40 ml-1">
                · {urlSinks!.count} with features
              </span>
            )}
          </div>
          <p className="text-[10px] text-base-content/45 mb-1">
            Prioritization only — not confirmed SSRF.
          </p>
          <div className="flex flex-wrap gap-1">
            <Link
              to={inventoryHref({
                endpoint_id: sinkEndpointId!,
                nrs_only: true,
                min_score: 45,
              })}
              className="btn btn-xs btn-ghost"
            >
              View inventory
            </Link>
            <Link
              to={`${URL_SINKS_BASE}?tab=overview`}
              className="btn btn-xs btn-ghost"
            >
              URL sinks hub
            </Link>
          </div>
        </div>
      )}
      {originalFlowId && (
        <div>
          <span className="text-base-content/50">Original </span>
          <Link to={`/flows/${originalFlowId}`} className="link">
            <UuidChip value={originalFlowId} />
          </Link>
        </div>
      )}
      <Item label="Child replays" value={String(childrenCount)} />

      {findings.length > 0 && (
        <div className="pt-1">
          <div className="text-base-content/50 mb-1">Findings (evidence)</div>
          <ul className="space-y-1">
            {findings.map((f) => (
              <li key={f.finding_id + f.evidence_type}>
                <Link to={`/findings/${f.finding_id}`} className="link">
                  {f.title || f.finding_id.slice(0, 8)}
                </Link>
                <span className="text-base-content/40 ml-1">
                  {f.status} · {f.evidence_type}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {jobs.length > 0 && (
        <div className="pt-1">
          <div className="text-base-content/50 mb-1">Scheduler jobs</div>
          <ul className="space-y-1">
            {jobs.map((j) => (
              <li key={j.job_id} className="mono">
                <Link to="/scheduler" className="link">
                  {j.job_id.slice(0, 8)}
                </Link>
                <span className="text-base-content/40 ml-1">
                  {j.job_type} · {j.status}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-base-content/50">{label}: </span>
      <span>{value}</span>
    </div>
  );
}
