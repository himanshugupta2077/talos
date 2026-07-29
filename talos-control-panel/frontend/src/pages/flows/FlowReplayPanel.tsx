import { Link } from "react-router-dom";
import { UuidChip } from "../../components/Common";
import StatusBadge from "../../components/StatusBadge";
import { formatIST } from "../../lib/time";

export interface RelatedChild {
  id: string;
  method: string;
  host: string;
  path: string;
  status_code: number | null;
  source: string;
  captured_at: string;
  replay_reason: string | null;
  replay_error: string | null;
  diff_verdict?: string | null;
  status_diff?: string | null;
  length_diff?: number | null;
}

export interface RelatedOriginal {
  id: string;
  method: string;
  host: string;
  path: string;
  status_code: number | null;
  source: string;
  captured_at: string;
  replay_reason: string | null;
}

export default function FlowReplayPanel({
  originalFlowId,
  original,
  children,
  diff,
}: {
  originalFlowId?: string | null;
  original?: RelatedOriginal | null;
  children: RelatedChild[];
  diff?: any;
}) {
  return (
    <div className="space-y-4">
      <p className="text-xs text-base-content/60">
        Replays are stored as separate flows linked by{" "}
        <span className="mono">original_flow_id</span>. Core{" "}
        <span className="mono">talos replay flow</span> re-sends the request as stored.
      </p>

      {originalFlowId && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">Original flow</div>
          {original ? (
            <Link to={`/flows/${original.id}`} className="link text-sm mono">
              {original.method} {original.host}
              {original.path}
              <span className="ml-2">
                <UuidChip value={original.id} />
              </span>
            </Link>
          ) : (
            <Link to={`/flows/${originalFlowId}`} className="link">
              <UuidChip value={originalFlowId} />
            </Link>
          )}
        </div>
      )}

      {diff && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">Diff summary</div>
          <StatusBadge value={diff.verdict} />
          {diff.status_diff && <div className="mono text-xs mt-1">{diff.status_diff}</div>}
          {diff.length_diff != null && (
            <div className="text-xs mt-1">length Δ {diff.length_diff}</div>
          )}
        </div>
      )}

      <div className="panel p-3">
        <div className="text-xs uppercase text-base-content/50 mb-2">
          Child replays ({children.length})
        </div>
        {children.length === 0 ? (
          <div className="text-xs text-base-content/40">No child replays of this flow.</div>
        ) : (
          <ul className="space-y-2">
            {children.map((c) => (
              <li key={c.id} className="text-xs flex flex-wrap items-center gap-2">
                <Link to={`/flows/${c.id}`} className="link mono">
                  {c.method} {c.path}
                </Link>
                <UuidChip value={c.id} />
                {c.status_code != null && <StatusBadge value={c.status_code} />}
                {c.diff_verdict && <StatusBadge value={c.diff_verdict} />}
                <span className="text-base-content/40">{formatIST(c.captured_at)}</span>
                {c.replay_reason && (
                  <span className="badge badge-ghost badge-xs">{c.replay_reason}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {children.some(
        (c) => c.source === "manual_send" || c.source === "ai_send"
      ) && (
        <div className="panel p-3">
          <Link
            to={`/repeater?flow=${originalFlowId || children[0]?.id || ""}`}
            className="link text-sm"
          >
            Open send history in Repeater
          </Link>
          <p className="text-[10px] text-base-content/50 mt-1">
            Mode 2 sends are edited/re-fired from the Repeater workspace — not
            listed here as exact replays.
          </p>
        </div>
      )}
    </div>
  );
}
