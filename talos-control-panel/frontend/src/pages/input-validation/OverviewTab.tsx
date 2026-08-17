import { Link, useNavigate } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import CandidateScore from "./components/CandidateScore";
import IvDisclaimer from "./components/IvDisclaimer";
import type { CandidateRow, IvConfig, IvStatus } from "./shared";
import { IV_BASE } from "./shared";

export default function OverviewTab({
  projectId,
  config,
  status,
  topCandidates,
  emptyState,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  config: IvConfig | null;
  status: IvStatus | null;
  topCandidates: CandidateRow[];
  emptyState: {
    no_probes?: boolean;
    no_profiles?: boolean;
    no_candidates_ge_60?: boolean;
    has_jobs?: boolean;
  };
  onRefresh: () => void;
  onGoTab: (tab: string) => void;
}) {
  const navigate = useNavigate();
  const conf = status?.confidence || {};
  const buckets = conf.buckets || {};
  const total = status?.total_params ?? 0;
  const completed = status?.completed ?? 0;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

  const autoRunOn = Boolean(Number(config?.auto_run ?? 0)) || Boolean(status?.auto_run);

  const enable = useAction("Enable IV engine", () =>
    api.post("/api/input-validation/config", { enable: true }, { project_id: projectId }),
  );
  const enableAutoRun = useAction("Enable IV auto-run", () =>
    api.post("/api/input-validation/config", { auto_run: true }, { project_id: projectId }),
  );
  const run = useAction("Run IV", () =>
    api.post(
      "/api/input-validation/run",
      { ignore_cache: false },
      { project_id: projectId },
    ),
  );

  return (
    <div>
      <IvDisclaimer />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className={`badge ${config?.enabled ? "badge-success" : "badge-ghost"}`}>
          {config?.enabled ? "enabled" : "disabled"}
        </span>
        <span className={`badge ${autoRunOn ? "badge-success" : "badge-ghost"}`}>
          auto-run {autoRunOn ? "on" : "off"}
        </span>
        <span className="badge badge-outline">
          scan: {status?.budget_tier || config?.probe_strategy || "deep"}
        </span>
        <span className="badge badge-ghost">
          {completed}/{total || "—"} params done ({pct}%)
        </span>
        <span className="badge badge-ghost">
          running {status?.running ?? 0} · queued {status?.queued ?? 0}
        </span>
        {(status?.pending_plan_params ?? 0) > 0 && (
          <span className="badge badge-info badge-outline">
            plan: {status?.pending_plan_params} param(s)
          </span>
        )}
        <span className="badge badge-ghost">
          requests used: {status?.requests_used ?? "—"}
        </span>
        {emptyState.has_jobs && (
          <span className="badge badge-warning badge-outline">jobs in flight — auto-refreshing</span>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3">
          <div className="font-medium mb-1">Progress</div>
          <div>Params: {status?.total_params ?? "—"}</div>
          <div>Completed: {status?.completed ?? "—"}</div>
          <div>Running: {status?.running ?? "—"}</div>
          <div>Queued: {status?.queued ?? "—"}</div>
          <div>Failed: {status?.failed ?? "—"}</div>
          <div>Skipped: {status?.skipped ?? "—"}</div>
          {total > 0 && (
            <progress className="progress progress-info w-full mt-2 h-1.5" value={pct} max={100} />
          )}
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Requests</div>
          <div>Coverage: {status?.budget_tier ?? "—"}</div>
          <div>Max req/param: {status?.max_requests_per_param ?? "—"}</div>
          <div>Requests used: {status?.requests_used ?? "—"}</div>
          <div>Params probed: {status?.params_probed ?? "—"}</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Profiles</div>
          <div>Param: {status?.profiles ?? "—"}</div>
          <div>Endpoint: {status?.endpoint_profiles ?? "—"}</div>
          <div>App: {status?.app_profiles ?? "—"}</div>
          <div>With caps: {conf.profiles_with_capabilities ?? "—"}</div>
          <div>With candidates: {conf.profiles_with_candidates ?? "—"}</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Confidence</div>
          <div>trust ≥90: {buckets.trust ?? 0}</div>
          <div>verify 60–89: {buckets.verify ?? 0}</div>
          <div>reprobe &lt;60: {buckets.reprobe ?? 0}</div>
          <div>unknown: {buckets.unknown ?? 0}</div>
          <div className="mt-1 text-base-content/50">
            refl avg: {conf.avg_reflection_confidence ?? "—"}
          </div>
        </div>
      </div>

      {/* Empty / next-action states */}
      {!config?.enabled && (
        <div className="panel p-4 mb-4 text-sm">
          <div className="font-medium mb-1">IV is off</div>
          <p className="text-base-content/60 mb-2">
            Enable the engine to characterize inputs and build intelligence profiles.
          </p>
          <button
            className="btn btn-sm btn-primary"
            disabled={enable.running}
            onClick={async () => {
              await enable.run();
              onRefresh();
            }}
          >
            Enable IV
          </button>
        </div>
      )}

      {config?.enabled && emptyState.no_probes && (
        <div className="panel p-4 mb-4 text-sm">
          <div className="font-medium mb-1">No probes yet</div>
          <p className="text-base-content/60 mb-2">
            Run the unified scan once, or turn on auto-run so unique parameters
            are characterized as traffic arrives. Candidates appear automatically
            after analysis.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              className="btn btn-sm btn-primary"
              disabled={run.running}
              onClick={async () => {
                await run.run();
                onRefresh();
              }}
            >
              Run
            </button>
            {!autoRunOn && (
              <button
                className="btn btn-sm"
                disabled={enableAutoRun.running}
                onClick={async () => {
                  await enableAutoRun.run();
                  onRefresh();
                }}
              >
                Enable auto-run
              </button>
            )}
          </div>
        </div>
      )}

      {config?.enabled && !emptyState.no_probes && emptyState.no_profiles && (
        <div className="panel p-4 mb-4 text-sm">
          <div className="font-medium mb-1">Probes in progress</div>
          <p className="text-base-content/60 mb-2">
            Profiles and candidates are built automatically when the planner
            finishes each parameter. Wait for the scheduler or resume unfinished
            work.
          </p>
          <button className="btn btn-sm" onClick={() => onGoTab("run")}>
            Open Run
          </button>
        </div>
      )}

      <Section title="What to look at next">
        <div className="flex flex-wrap gap-2 mb-3">
          <button className="btn btn-xs btn-primary" disabled={run.running} onClick={async () => { await run.run(); onRefresh(); }}>
            Run
          </button>
          <button className="btn btn-xs" onClick={() => onGoTab("candidates")}>
            Open candidates
          </button>
          <Link
            className="btn btn-xs"
            to={`${IV_BASE}?tab=candidates&capability=network_resource_sink&min_score=60`}
            title="Server-filtered URL-family prioritization (not confirmed SSRF)"
          >
            NRS candidates ≥60
          </Link>
          <Link
            className="btn btn-xs"
            to={`${IV_BASE}?tab=candidates&attack=ssrf&min_score=60`}
          >
            SSRF ≥60
          </Link>
          <Link
            className="btn btn-xs"
            to={`${IV_BASE}?tab=candidates&attack=open_redirect&min_score=60`}
          >
            Open redirect ≥60
          </Link>
          <Link className="btn btn-xs" to="/scheduler">
            Scheduler
          </Link>
        </div>
        <p className="text-xs text-base-content/50 mb-2">
          Candidate scores are prioritization only. NRS / SSRF / redirect presets use
          server-side filters — they do not confirm vulnerabilities.
        </p>

        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Attack</th>
                <th>Name</th>
                <th>Host</th>
                <th>Score</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {topCandidates.map((c, i) => (
                <tr
                  key={`${c.param_uuid}-${c.attack}-${i}`}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() => {
                    if (c.param_uuid) {
                      navigate(`${IV_BASE}/params/${c.param_uuid}`);
                    }
                  }}
                >
                  <td className="mono">{c.attack}</td>
                  <td className="mono">{c.name}</td>
                  <td className="mono text-xs">{c.host}</td>
                  <td>
                    <CandidateScore score={c.score} confidence={c.confidence} />
                  </td>
                  <td className="max-w-md truncate text-xs">
                    {(c.reasons || [])[0] || "—"}
                  </td>
                </tr>
              ))}
              {topCandidates.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-center text-base-content/40 py-6">
                    {emptyState.no_candidates_ge_60
                      ? "No candidates with score ≥ 60 yet. Run or enable auto-run, then wait for analysis — or lower filters on the Candidates tab."
                      : "No prioritization targets yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>

      {status?.pending_plan_actions && Object.keys(status.pending_plan_actions).length > 0 && (
        <div className="text-xs panel p-2 mb-3">
          <span className="font-medium">Pending plan actions: </span>
          {Object.entries(status.pending_plan_actions)
            .map(([k, v]) => `${k}=${v}`)
            .join(", ")}
        </div>
      )}

      {status?.param_cache && (
        <details className="text-xs">
          <summary className="cursor-pointer text-base-content/50">Legacy cache counts</summary>
          <div className="grid grid-cols-3 gap-3 mt-2">
            <div className="panel p-2">
              <div className="font-medium mb-1">Param cache</div>
              {Object.entries(status.param_cache || {}).map(([k, v]) => (
                <div key={k}>{k}: {String(v)}</div>
              ))}
            </div>
            <div className="panel p-2">
              <div className="font-medium mb-1">Reflection cache</div>
              {Object.entries(status.reflection_cache || {}).map(([k, v]) => (
                <div key={k}>{k}: {String(v)}</div>
              ))}
            </div>
            <div className="panel p-2">
              <div className="font-medium mb-1">Probe results</div>
              {Object.entries(status.probe_results || {}).map(([k, v]) => (
                <div key={k}>{k}: {String(v)}</div>
              ))}
            </div>
          </div>
        </details>
      )}
    </div>
  );
}
