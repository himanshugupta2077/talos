import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import type { BacOverview, BacTab } from "./shared";
import { techniqueLabel } from "./shared";
import BacDisclaimer from "./components/BacDisclaimer";

export default function OverviewTab({
  projectId,
  overview,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  overview: BacOverview | null;
  onRefresh: () => void;
  onGoTab: (t: BacTab) => void;
}) {
  const runAll = useAction("Run all BAC techniques", () =>
    api.post("/api/attack/bac/run", {}, { project_id: projectId })
  );

  const counts = overview?.counts || {};
  const possible = counts.POSSIBLE_BAC ?? 0;
  const secure = counts.SECURE ?? 0;
  const unknown = counts.UNKNOWN ?? 0;
  const cand = overview?.candidates;
  const candidateCount = cand?.candidate_count ?? 0;
  const flowCount = cand?.flow_count ?? 0;
  const pending = overview?.jobs_pending ?? 0;
  const running = overview?.jobs_running ?? 0;
  const estimate = overview?.estimated_jobs_all ?? 0;
  const empty = overview?.empty_state || {};
  const auth = overview?.auth;
  const authFailed = (auth?.failed_count ?? 0) > 0;

  return (
    <div>
      <BacDisclaimer authMode={overview?.auth_model?.mode} />
      {overview?.auth_model && (
        <div className="text-xs mb-3">
          Identity injector:{" "}
          <span className="font-medium">
            {overview.auth_model.identity === "ntlm_profile"
              ? "NTLM profile (bound per role)"
              : "cookie / header session"}
          </span>
          <span className="text-base-content/50"> · {overview.auth_model.label}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className="badge badge-outline">
          {candidateCount} candidate{candidateCount === 1 ? "" : "s"}
        </span>
        {cand?.by_source && Object.keys(cand.by_source).length > 0 && (
          <span className="badge badge-ghost">
            {cand.by_source.access_map
              ? `${cand.by_source.access_map} access-map`
              : ""}
            {cand.by_source.access_map && cand.by_source.privilege_diff
              ? " · "
              : ""}
            {cand.by_source.privilege_diff
              ? `${cand.by_source.privilege_diff} privilege-diff`
              : ""}
            {cand.by_source.both ? ` · ${cand.by_source.both} both` : ""}
          </span>
        )}
        <span className="badge badge-ghost">
          {flowCount} flow{flowCount === 1 ? "" : "s"}
        </span>
        <span className="badge badge-ghost">
          {overview?.total_variants ?? "—"} variants
        </span>
        {auth && candidateCount > 0 && (
          <span
            className={`badge ${
              authFailed ? "badge-warning" : "badge-success"
            } badge-outline`}
          >
            auth: {auth.passed_count} ready
            {authFailed ? ` · ${auth.failed_count} blocked` : ""}
          </span>
        )}
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
            confirmText={`Enqueue up to ~${estimate} BAC jobs across all techniques?`}
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
            disabled={runAll.running || candidateCount === 0}
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
              "Run all techniques"
            )}
          </button>
        )}
        <button className="btn btn-xs btn-outline" onClick={() => onGoTab("run")}>
          Customize run…
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("results")}>
          All results
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("config")}>
          Filter
        </button>
        <Link to="/scheduler" className="btn btn-xs btn-ghost">
          Scheduler
        </Link>
        <Link to="/access" className="btn btn-xs btn-ghost">
          Access
        </Link>
        <Link to="/auth" className="btn btn-xs btn-ghost">
          Auth
        </Link>
        <Link to="/findings" className="btn btn-xs btn-ghost">
          Findings
        </Link>
        <button className="btn btn-xs btn-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {empty.no_candidates && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No BAC candidates yet. Candidates come from the access matrix: a target
          role with <span className="mono">ALLOW</span> and an attacker role with{" "}
          <span className="mono">DENY</span>/<span className="mono">UNKNOWN</span>{" "}
          on the same module, plus successful 2xx proxy flows on qualified
          endpoints.{" "}
          <Link className="link link-primary" to="/access">
            Open Access →
          </Link>{" "}
          <Link className="link link-primary" to="/endpoints">
            Endpoints →
          </Link>
        </div>
      )}

      {!empty.no_candidates && empty.auth_failed && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          Some attacker roles fail auth prerequisites (login flow, extractor,
          auth config, or collected session state). Fix{" "}
          <Link className="link link-primary" to="/auth">
            Auth
          </Link>{" "}
          / Auth Config, or re-run with{" "}
          <span className="mono">--auto-generate</span> from the Run tab.
          {auth?.roles
            ?.filter((r) => !r.passed)
            .slice(0, 4)
            .map((r) => (
              <div key={r.role_id} className="text-xs mt-1 text-warning">
                <span className="font-medium">{r.role_name}</span>
                {r.errors?.[0] ? `: ${r.errors[0]}` : ""}
              </div>
            ))}
        </div>
      )}

      {!empty.no_candidates && empty.no_results && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No BAC results yet. Enqueue with{" "}
          <strong>Run all techniques</strong> or open{" "}
          <button
            type="button"
            className="link link-primary"
            onClick={() => onGoTab("run")}
          >
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
          BAC jobs in flight ({running} running, {pending} pending).{" "}
          <Link className="link" to="/scheduler">
            Open Scheduler
          </Link>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3 text-center">
          <div className="text-xl font-semibold text-error">{possible}</div>
          <StatusBadge value="POSSIBLE_BAC" />
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
          <div>Candidates: {candidateCount}</div>
          <div>Flows: {flowCount}</div>
          <div>Est. jobs (all): ~{estimate.toLocaleString()}</div>
          {cand && cand.modules.length > 0 && (
            <div className="mt-1 text-[10px] text-base-content/50 truncate" title={cand.modules.join(", ")}>
              Modules: {cand.modules.slice(0, 3).join(", ")}
              {cand.modules.length > 3 ? "…" : ""}
            </div>
          )}
        </div>
      </div>

      <Section
        title="Recent POSSIBLE_BAC"
        action={
          possible > 0 ? (
            <button
              className="btn btn-xs btn-ghost"
              onClick={() => onGoTab("results")}
            >
              View all
            </button>
          ) : undefined
        }
      >
        {overview?.recent_possible?.length ? (
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Attacker</th>
                  <th>Target</th>
                  <th>Technique</th>
                  <th>Variant</th>
                </tr>
              </thead>
              <tbody>
                {overview.recent_possible.map((r) => (
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
                    <td className="text-xs">{r.attacker_role_name || "—"}</td>
                    <td className="text-xs">{r.target_role_name || "—"}</td>
                    <td className="mono text-xs">
                      {techniqueLabel(r.attack_type)}
                    </td>
                    <td className="text-xs">{r.variant || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-base-content/40">
            No POSSIBLE_BAC results yet.
          </p>
        )}
      </Section>

      <Section title="How it works">
        <ol className="text-xs text-base-content/60 list-decimal list-inside space-y-1 max-w-2xl">
          <li>
            Scan the access matrix for ALLOW (target) vs DENY/UNKNOWN (attacker)
            pairs with 2xx flows on testable endpoints
          </li>
          <li>Validate auth prerequisites per attacker role</li>
          <li>
            Enqueue one scheduler job per flow × mutation variant for each
            selected technique family
          </li>
          <li>
            Classify responses: <span className="mono">POSSIBLE_BAC</span> |{" "}
            <span className="mono">SECURE</span> |{" "}
            <span className="mono">UNKNOWN</span>
          </li>
        </ol>
        <p className="text-xs text-base-content/50 mt-2">
          Maps to{" "}
          <span className="mono">
            talos attack bac &lt;technique&gt; [--role] [--module|--endpoint]
            [--auto-generate]
          </span>
          . “Run all” enqueues every technique family sequentially.
        </p>
      </Section>
    </div>
  );
}
