import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import type { CorsOverview, CorsTab } from "./shared";
import CorsDisclaimer from "./components/CorsDisclaimer";

export default function OverviewTab({
  projectId,
  overview,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  overview: CorsOverview | null;
  onRefresh: () => void;
  onGoTab: (t: CorsTab) => void;
}) {
  const runAll = useAction("Run CORS attack (all techniques)", () =>
    api.post("/api/attack/cors/run", {}, { project_id: projectId })
  );

  const counts = overview?.counts || {};
  const issues = counts.CORS_MISCONFIG ?? 0;
  const secure = counts.SECURE ?? 0;
  const unknown = counts.UNKNOWN ?? 0;
  const candidates = overview?.candidates ?? 0;
  const pending = overview?.jobs_pending ?? 0;
  const running = overview?.jobs_running ?? 0;
  const estimate = overview?.estimated_jobs_all ?? 0;
  const empty = overview?.empty_state || {};

  return (
    <div>
      <CorsDisclaimer />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className="badge badge-outline">
          {candidates} candidate{candidates === 1 ? "" : "s"}
        </span>
        <span className="badge badge-ghost">
          {overview?.total_techniques ?? "—"} techniques
        </span>
        {(pending > 0 || running > 0) && (
          <span className="badge badge-warning badge-outline">
            jobs: {running} running · {pending} pending
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        {estimate > 50 ? (
          <ConfirmButton
            className="btn btn-xs btn-primary"
            confirmText={`Enqueue up to ~${estimate} CORS jobs (all techniques)?`}
            onConfirm={async () => {
              try {
                await runAll.run();
                onRefresh();
              } catch {
                /* logged by useAction */
              }
            }}
          >
            {runAll.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Run all techniques"
            )}
          </ConfirmButton>
        ) : (
          <button
            className="btn btn-xs btn-primary"
            disabled={runAll.running || candidates === 0}
            onClick={async () => {
              try {
                await runAll.run();
                onRefresh();
              } catch {
                /* logged */
              }
            }}
          >
            {runAll.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Run all techniques"
            )}
          </button>
        )}
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("run")}>
          Configure run
        </button>
        <Link to="/scheduler" className="btn btn-xs btn-ghost">
          Scheduler
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
        <div className="panel p-3">
          <div className="text-xs text-base-content/50">Reflected origins</div>
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

      {empty.no_candidates && (
        <div className="alert text-xs mb-4">
          No in-scope 200 OK POST/PATCH/PUT/GET captures yet. Browse the target
          with the proxy on, then refresh.
        </div>
      )}

      <Section title="Recent issues">
        {(overview?.recent_issues || []).length === 0 ? (
          <p className="text-sm text-base-content/50">
            No CORS_MISCONFIG results yet.
          </p>
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
                  Origin {row.origin_sent} → ACAO {row.acao || "—"}
                  {row.acac ? ` · ACAC ${row.acac}` : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}
