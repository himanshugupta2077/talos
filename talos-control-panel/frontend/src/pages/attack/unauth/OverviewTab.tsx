import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import type { UnauthOverview, UnauthTab } from "./shared";
import UnauthDisclaimer from "./components/UnauthDisclaimer";

export default function OverviewTab({
  projectId,
  overview,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  overview: UnauthOverview | null;
  onRefresh: () => void;
  onGoTab: (t: UnauthTab) => void;
}) {
  const runAll = useAction("Run unauth attack (all recipes)", () =>
    api.post("/api/attack/unauth/run", {}, { project_id: projectId })
  );

  const counts = overview?.counts || {};
  const bypass = counts.BYPASS ?? 0;
  const secure = counts.SECURE ?? 0;
  const unknown = counts.UNKNOWN ?? 0;
  const testable = overview?.testable_endpoints ?? 0;
  const pending = overview?.jobs_pending ?? 0;
  const running = overview?.jobs_running ?? 0;
  const estimate = overview?.estimated_jobs_all ?? 0;
  const empty = overview?.empty_state || {};
  const autoOn = overview?.auto_run?.enabled ?? false;

  return (
    <div>
      <UnauthDisclaimer />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className={`badge ${autoOn ? "badge-success" : "badge-ghost"}`}>
          auto-run {autoOn ? "on" : "off"}
        </span>
        <span className="badge badge-outline">
          {testable} testable endpoint{testable === 1 ? "" : "s"}
        </span>
        <span className="badge badge-ghost">
          {overview?.total_recipes ?? "—"} recipes
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
            confirmText={`Enqueue up to ~${estimate} jobs (all recipes)?`}
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
              "Run all recipes"
            )}
          </ConfirmButton>
        ) : (
          <button
            className="btn btn-xs btn-primary"
            disabled={runAll.running || testable === 0}
            onClick={async () => {
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
              "Run all recipes"
            )}
          </button>
        )}
        <button className="btn btn-xs btn-outline" onClick={() => onGoTab("run")}>
          Choose technique…
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("results")}>
          All results
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("config")}>
          Filter & config
        </button>
        <Link to="/scheduler" className="btn btn-xs btn-ghost">
          Scheduler
        </Link>
        <Link to="/findings" className="btn btn-xs btn-ghost">
          Findings
        </Link>
        <button className="btn btn-xs btn-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {empty.no_testable && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No testable endpoints yet. Capture traffic through the proxy, ensure
          endpoints are qualified with a 2xx baseline flow, and clear logout /
          dangerous exclusions.{" "}
          <Link className="link link-primary" to="/endpoints">
            Open Endpoints →
          </Link>
        </div>
      )}

      {!empty.no_testable && empty.no_results && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No unauth results yet. Enqueue jobs from{" "}
          <button type="button" className="link link-primary" onClick={() => onGoTab("run")}>
            Run
          </button>
          , then watch the{" "}
          <Link className="link link-primary" to="/scheduler">
            Scheduler
          </Link>
          .
        </div>
      )}

      {empty.jobs_in_flight && (
        <div className="alert alert-info text-xs py-2 mb-4">
          Unauth jobs in flight ({running} running, {pending} pending).{" "}
          <Link className="link" to="/scheduler">
            Open Scheduler
          </Link>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3 text-center">
          <div className="text-xl font-semibold text-error">{bypass}</div>
          <StatusBadge value="BYPASS" />
        </div>
        <div className="panel p-3 text-center">
          <div className="text-xl font-semibold">{secure}</div>
          <StatusBadge value="SECURE" />
        </div>
        <div className="panel p-3 text-center">
          <div className="text-xl font-semibold">{unknown}</div>
          <StatusBadge value="UNKNOWN" />
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Coverage</div>
          <div>Testable: {testable}</div>
          <div>Est. jobs (all): ~{estimate}</div>
          <div className="mt-1">
            Auto-run:{" "}
            <span className={autoOn ? "text-success" : "text-base-content/50"}>
              {autoOn ? "enabled" : "disabled"}
            </span>
          </div>
          <p className="text-[10px] text-base-content/40 mt-1 leading-snug">
            Auto-run enqueues classic auth_test jobs — not unauth recipe runs.
          </p>
        </div>
      </div>

      <Section
        title="Recent BYPASS"
        action={
          bypass > 0 ? (
            <button
              className="btn btn-xs btn-ghost"
              onClick={() => onGoTab("results")}
            >
              View all
            </button>
          ) : undefined
        }
      >
        {overview?.recent_bypass?.length ? (
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Auth mutation</th>
                  <th>Request mutation</th>
                </tr>
              </thead>
              <tbody>
                {overview.recent_bypass.map((r) => (
                  <tr key={r.replay_flow_id}>
                    <td className="text-xs whitespace-nowrap">
                      {formatIST(r.captured_at)}
                    </td>
                    <td className="mono">{r.method}</td>
                    <td>
                      <Link
                        className="link link-hover mono text-xs"
                        to={`/flows/${r.replay_flow_id}`}
                      >
                        {r.path}
                      </Link>
                    </td>
                    <td className="text-xs">{r.auth_mutation || "—"}</td>
                    <td className="text-xs">{r.request_mutation || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-base-content/40">No BYPASS results yet.</p>
        )}
      </Section>

      <Section title="How it works">
        <ol className="text-xs text-base-content/60 list-decimal list-inside space-y-1 max-w-2xl">
          <li>Strip all configured authentication from the baseline flow</li>
          <li>Apply the selected unauth technique</li>
          <li>Apply optional request mutation from the recipe</li>
          <li>
            Replay and classify: <span className="mono">SECURE</span> |{" "}
            <span className="mono">BYPASS</span> |{" "}
            <span className="mono">UNKNOWN</span>
          </li>
        </ol>
        <p className="text-xs text-base-content/50 mt-2">
          Maps to{" "}
          <span className="mono">talos attack unauth run [--technique NAME]</span>
          . Endpoint inclusion is owned by Endpoint Policy.
        </p>
      </Section>
    </div>
  );
}
