import { Link } from "react-router-dom";
import { formatIST } from "../../lib/time";

export interface SessionIntel {
  role_id: string;
  role_name?: string | null;
  provider?: string | null;
  artifact_keys?: string[];
  artifact_count?: number;
  collected_at?: string | null;
  ttl_seconds?: number | null;
  suspicion_count?: number;
  last_checked_at?: string | null;
  health_degraded?: boolean;
  has_artifacts?: boolean;
}

export default function FlowSessionPanel({ session }: { session: SessionIntel | null }) {
  if (!session) {
    return (
      <div className="text-xs text-base-content/50 p-2">
        No role on this flow — session intelligence unavailable.
      </div>
    );
  }

  return (
    <div className="space-y-2 text-xs">
      <p className="text-base-content/50 leading-snug">
        Snapshot from Core auth tables for this flow&apos;s role — not a browser-side
        health score.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {session.provider && (
          <span className="badge badge-sm badge-outline uppercase">{session.provider}</span>
        )}
        {session.has_artifacts ? (
          <span className="badge badge-sm badge-success">Artifacts present</span>
        ) : (
          <span className="badge badge-sm badge-ghost">No artifacts</span>
        )}
        {session.health_degraded && (
          <span className="badge badge-sm badge-warning">Health degraded</span>
        )}
      </div>
      <dl className="space-y-1">
        <Row label="Role" value={session.role_name || session.role_id} />
        <Row
          label="TTL"
          value={session.ttl_seconds != null ? `${session.ttl_seconds}s` : "—"}
        />
        <Row
          label="Collected"
          value={session.collected_at ? formatIST(session.collected_at) : "—"}
        />
        <Row
          label="Last check"
          value={session.last_checked_at ? formatIST(session.last_checked_at) : "—"}
        />
        <Row label="Suspicion" value={String(session.suspicion_count ?? 0)} />
        {session.artifact_keys && session.artifact_keys.length > 0 && (
          <Row label="Keys" value={session.artifact_keys.join(", ")} />
        )}
      </dl>
      <Link to="/auth" className="link link-hover">
        Open Auth for role
      </Link>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-base-content/50 w-20 shrink-0">{label}</span>
      <span className="mono break-all">{value}</span>
    </div>
  );
}
