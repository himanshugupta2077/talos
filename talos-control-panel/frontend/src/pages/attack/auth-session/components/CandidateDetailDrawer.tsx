import { Link } from "react-router-dom";
import { Modal, UuidChip } from "../../../../components/Common";
import StatusBadge from "../../../../components/StatusBadge";
import type { AuthSessionCandidate } from "../shared";

export default function CandidateDetailDrawer({
  candidate,
  onClose,
  onApprove,
  onReject,
  busy,
}: {
  candidate: AuthSessionCandidate | null;
  onClose: () => void;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
  busy?: boolean;
}) {
  if (!candidate) return null;

  const canApprove =
    candidate.status === "pending" ||
    candidate.status === "failed" ||
    candidate.status === "done";
  const canReject = candidate.status === "pending";
  const canUnapprove = candidate.status === "approved";

  return (
    <Modal
      open
      title={`Candidate · ${candidate.test_id}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-2 text-sm">
        <div className="flex flex-wrap gap-2 items-center">
          <StatusBadge value={candidate.status} />
          {candidate.risk_hint && (
            <span className="badge badge-xs badge-outline">{candidate.risk_hint}</span>
          )}
          <span className="badge badge-xs badge-ghost mono">{candidate.test_family}</span>
        </div>

        <div>
          <div className="text-xs text-base-content/50">Title</div>
          <div>{candidate.title || "—"}</div>
        </div>

        <div>
          <div className="text-xs text-base-content/50">Mutation summary</div>
          <div className="text-xs">{candidate.mutation_summary || "—"}</div>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <div className="text-base-content/50">ID</div>
            <UuidChip value={candidate.id} />
          </div>
          <div>
            <div className="text-base-content/50">Binding</div>
            <UuidChip value={candidate.binding_id} />
          </div>
          <div>
            <div className="text-base-content/50">Token fingerprint</div>
            <span className="mono">{candidate.token_fingerprint || "—"}</span>
          </div>
          <div>
            <div className="text-base-content/50">Endpoint</div>
            {candidate.endpoint_id ? (
              <Link
                className="link link-primary mono"
                to={`/endpoints/${candidate.endpoint_id}`}
              >
                {candidate.endpoint_method || ""}{" "}
                {candidate.endpoint_path || candidate.endpoint_id.slice(0, 8)}
              </Link>
            ) : (
              "—"
            )}
          </div>
          <div>
            <div className="text-base-content/50">Baseline flow</div>
            {candidate.baseline_flow_id ? (
              <Link
                className="link link-primary"
                to={`/flows/${candidate.baseline_flow_id}`}
              >
                <UuidChip value={candidate.baseline_flow_id} />
              </Link>
            ) : (
              "—"
            )}
          </div>
          <div>
            <div className="text-base-content/50">Updated</div>
            <span className="mono">{candidate.updated_at || "—"}</span>
          </div>
        </div>

        {candidate.reject_reason && (
          <div className="text-xs">
            <div className="text-base-content/50">Reject reason</div>
            {candidate.reject_reason}
          </div>
        )}
        {candidate.skip_reason && (
          <div className="text-xs">
            <div className="text-base-content/50">Skip reason</div>
            {candidate.skip_reason}
          </div>
        )}

        {candidate.meta_json && candidate.meta_json !== "{}" && (
          <div>
            <div className="text-xs text-base-content/50 mb-1">meta_json</div>
            <pre className="text-[11px] bg-base-200 p-2 rounded overflow-auto max-h-40">
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(candidate.meta_json), null, 2);
                } catch {
                  return candidate.meta_json;
                }
              })()}
            </pre>
          </div>
        )}

        <div className="flex flex-wrap gap-2 mt-3">
          {canApprove && onApprove && (
            <button
              type="button"
              className="btn btn-xs btn-primary"
              disabled={busy}
              onClick={() => onApprove(candidate.id)}
            >
              Approve
            </button>
          )}
          {canReject && onReject && (
            <button
              type="button"
              className="btn btn-xs btn-outline"
              disabled={busy}
              onClick={() => onReject(candidate.id)}
            >
              Reject
            </button>
          )}
          {canUnapprove && (
            <p className="text-[11px] text-base-content/50 self-center">
              Unapprove from the bulk bar (or CLI) to return to pending.
            </p>
          )}
        </div>

        <p className="text-[11px] text-base-content/45 mt-1">
          Status transitions: pending → approved → running → done|failed.
          Rejected stays rejected until re-generated. Only{" "}
          <strong>approved</strong> candidates enqueue on Run.
        </p>
      </div>
    </Modal>
  );
}
