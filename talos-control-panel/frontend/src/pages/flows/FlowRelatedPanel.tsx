import { Link } from "react-router-dom";
import { UuidChip } from "../../components/Common";

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
}: Props) {
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
