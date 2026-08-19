import { Link } from "react-router-dom";
import { Section } from "../../../components/Common";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import type { PathTraversalOverview, PathTraversalTab } from "./shared";
import PathTraversalDisclaimer from "./components/PathTraversalDisclaimer";

export default function OverviewTab({
  overview,
  onGoTab,
}: {
  projectId: string;
  overview: PathTraversalOverview | null;
  onRefresh: () => void;
  onGoTab: (t: PathTraversalTab) => void;
}) {
  const counts = overview?.counts || {};
  const issues = counts.PATH_TRAVERSAL ?? 0;
  const secure = counts.SECURE ?? 0;
  const unknown = counts.UNKNOWN ?? 0;
  const pending = overview?.jobs_pending ?? 0;
  const running = overview?.jobs_running ?? 0;
  const empty = overview?.empty_state || {};

  return (
    <div>
      <PathTraversalDisclaimer />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className="badge badge-ghost">
          {overview?.total_techniques ?? "—"} payloads
        </span>
        {(pending > 0 || running > 0) && (
          <span className="badge badge-warning badge-outline">
            jobs: {running} running · {pending} pending
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <button className="btn btn-xs btn-primary" onClick={() => onGoTab("run")}>
          Scan a flow
        </button>
        <Link to="/flows" className="btn btn-xs btn-ghost">
          Pick from Flows
        </Link>
        <Link to="/scheduler" className="btn btn-xs btn-ghost">
          Scheduler
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
        <div className="panel p-3">
          <div className="text-xs text-base-content/50">Confirmed LFI / traversal</div>
          <div className={`text-2xl font-semibold ${issues > 0 ? "text-error" : ""}`}>
            {issues}
          </div>
        </div>
        <div className="panel p-3">
          <div className="text-xs text-base-content/50">Secure probes</div>
          <div className="text-2xl font-semibold">{secure}</div>
        </div>
        <div className="panel p-3">
          <div className="text-xs text-base-content/50">Unknown / errors</div>
          <div className="text-2xl font-semibold">{unknown}</div>
        </div>
      </div>

      {empty.no_results && (
        <div className="alert text-xs mb-4">
          No path-traversal probes yet. Open a captured flow and run Path
          Traversal, or paste a flow UUID on the Run tab.
        </div>
      )}

      <Section title="Recent issues">
        {(overview?.recent_issues || []).length === 0 ? (
          <p className="text-sm text-base-content/50">No PATH_TRAVERSAL results yet.</p>
        ) : (
          <ul className="space-y-2">
            {(overview?.recent_issues || []).map((row) => (
              <li key={row.replay_flow_id} className="panel p-3 text-xs">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <StatusBadge value={row.verdict} />
                  <span className="mono">{row.technique}</span>
                  <span className="text-base-content/50">
                    {row.method} {row.path}
                  </span>
                  <span className="ml-auto text-base-content/40">
                    {formatIST(row.captured_at)}
                  </span>
                </div>
                <div className="mono text-base-content/60 break-all">
                  {row.param_name} {row.os_hint ? `· ${row.os_hint}` : ""}{" "}
                  {row.evidence ? `· ${row.evidence}` : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}
