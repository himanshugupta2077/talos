import { Link } from "react-router-dom";
import { Section } from "../../../components/Common";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import type { AuthSessionOverview, AuthSessionTab } from "./shared";
import AuthSessionDisclaimer from "./components/AuthSessionDisclaimer";
import DistinctionBanner from "./components/DistinctionBanner";

export default function OverviewTab({
  overview,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  overview: AuthSessionOverview | null;
  onRefresh: () => void;
  onGoTab: (t: AuthSessionTab) => void;
}) {
  const byStatus = overview?.candidates_by_status || {};
  const byVerdict = overview?.results_by_verdict || overview?.counts || {};
  const weak = byVerdict.WEAK_VALIDATION ?? 0;
  const secure = byVerdict.SECURE ?? 0;
  const unknown = byVerdict.UNKNOWN ?? 0;
  const pending = byStatus.pending ?? 0;
  const approved = byStatus.approved ?? 0;
  const jobsPending = overview?.jobs_pending ?? 0;
  const jobsRunning = overview?.jobs_running ?? 0;
  const empty = overview?.empty_state || {};
  const bindings = overview?.bindings ?? 0;

  return (
    <div>
      <AuthSessionDisclaimer />
      <DistinctionBanner />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className="badge badge-outline">
          {bindings} binding{bindings === 1 ? "" : "s"}
        </span>
        <span className="badge badge-ghost">
          {overview?.candidates_total ?? 0} candidates
        </span>
        <span
          className={`badge badge-outline ${
            pending > 0 ? "badge-warning" : ""
          }`}
        >
          {pending} pending
        </span>
        <span
          className={`badge badge-outline ${
            approved > 0 ? "badge-info" : ""
          }`}
        >
          {approved} approved
        </span>
        {(jobsPending > 0 || jobsRunning > 0) && (
          <span className="badge badge-warning badge-outline">
            jobs: {jobsRunning} running · {jobsPending} pending
          </span>
        )}
        {overview && !overview.auth_config_ready && (
          <span className="badge badge-error badge-outline">auth_config empty</span>
        )}
        {overview && overview.auth_config_ready && !overview.bindings_valid && (
          <span className="badge badge-warning badge-outline">
            binding not in auth_config
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <button
          type="button"
          className="btn btn-xs btn-primary"
          onClick={() => onGoTab("bindings")}
        >
          Bindings
        </button>
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={() => onGoTab("candidates")}
        >
          Candidates / Approve
        </button>
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={() => onGoTab("run")}
        >
          Run
        </button>
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={() => onGoTab("results")}
        >
          Results
        </button>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => onGoTab("config")}
        >
          Filter & Suite
        </button>
        <Link to="/auth" className="btn btn-xs btn-ghost">
          Auth page (prereq)
        </Link>
        <Link to="/scheduler" className="btn btn-xs btn-ghost">
          Scheduler
        </Link>
        <Link
          to="/findings?attack_type=auth_session"
          className="btn btn-xs btn-ghost"
        >
          Findings
        </Link>
        <button type="button" className="btn btn-xs btn-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {empty.no_auth_config && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No auth_config artifacts yet. Set header/cookie names on the Auth page
          before binding.{" "}
          <Link className="link link-primary" to="/auth">
            Open Auth →
          </Link>
        </div>
      )}

      {!empty.no_auth_config && empty.no_bindings && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No auth-session bindings. Bind a JWT field (e.g. Authorization) on the{" "}
          <button
            type="button"
            className="link link-primary"
            onClick={() => onGoTab("bindings")}
          >
            Bindings
          </button>{" "}
          tab.
        </div>
      )}

      {!empty.no_bindings && empty.no_candidates && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No candidates yet. Use{" "}
          <button
            type="button"
            className="link link-primary"
            onClick={() => onGoTab("candidates")}
          >
            Generate
          </button>{" "}
          to create pending mutation tests (no HTTP).
        </div>
      )}

      {pending > 0 && (
        <div className="alert alert-warning text-xs py-2 mb-4">
          {pending} pending candidate{pending === 1 ? "" : "s"} need approval
          before run.{" "}
          <button
            type="button"
            className="link link-primary"
            onClick={() => onGoTab("candidates")}
          >
            Open Candidates → approve
          </button>
        </div>
      )}

      {approved > 0 && (
        <div className="alert alert-info text-xs py-2 mb-4">
          {approved} approved candidate{approved === 1 ? "" : "s"} ready to run.{" "}
          <button
            type="button"
            className="link link-primary"
            onClick={() => onGoTab("run")}
          >
            Open Run →
          </button>
        </div>
      )}

      {empty.jobs_in_flight && (
        <div className="alert alert-info text-xs py-2 mb-4">
          Auth-session jobs in flight ({jobsRunning} running, {jobsPending}{" "}
          pending).{" "}
          <Link className="link" to="/scheduler">
            Open Scheduler
          </Link>
          {" · "}
          <button
            type="button"
            className="link"
            onClick={() => onGoTab("results")}
          >
            Results
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
        <div className="panel p-3">
          <div className="text-xs text-base-content/50 mb-1">Verdicts</div>
          <div className="flex flex-wrap gap-2 text-sm">
            <span>
              <span className="font-semibold text-error tabular-nums">{weak}</span>{" "}
              <span className="text-base-content/50">weak</span>
            </span>
            <span>
              <span className="font-semibold text-success tabular-nums">{secure}</span>{" "}
              <span className="text-base-content/50">secure</span>
            </span>
            <span>
              <span className="font-semibold tabular-nums">{unknown}</span>{" "}
              <span className="text-base-content/50">unknown</span>
            </span>
          </div>
          {weak > 0 && (
            <p className="text-[11px] text-base-content/50 mt-2">
              <Link
                className="link"
                to="/findings?attack_type=auth_session&verdict=WEAK_VALIDATION"
              >
                Open WEAK_VALIDATION findings →
              </Link>
            </p>
          )}
        </div>
        <div className="panel p-3">
          <div className="text-xs text-base-content/50 mb-1">Candidates by status</div>
          <div className="flex flex-wrap gap-1">
            {Object.entries(byStatus).map(([st, n]) => (
              <span key={st} className="inline-flex items-center gap-1 text-xs">
                <StatusBadge value={st} />
                <span className="tabular-nums font-medium">{n}</span>
              </span>
            ))}
            {Object.keys(byStatus).length === 0 && (
              <span className="text-xs text-base-content/40">none</span>
            )}
          </div>
        </div>
        <div className="panel p-3">
          <div className="text-xs text-base-content/50 mb-1">Readiness</div>
          <ul className="text-xs space-y-1">
            <li>
              Auth config:{" "}
              {overview?.auth_config_ready ? (
                <span className="text-success">ready</span>
              ) : (
                <span className="text-error">missing</span>
              )}
            </li>
            <li>
              Bindings valid:{" "}
              {overview?.bindings_valid !== false ? (
                <span className="text-success">yes</span>
              ) : (
                <span className="text-warning">check names</span>
              )}
            </li>
            <li>
              Approved ready to run:{" "}
              <span className="tabular-nums font-medium">
                {overview?.estimated_jobs_approved ?? 0}
              </span>
            </li>
            <li>
              Decision filter:{" "}
              {overview?.filter_exists ? (
                <span className="text-success">present</span>
              ) : (
                <span className="text-base-content/50">not initialized</span>
              )}
            </li>
          </ul>
        </div>
      </div>

      <Section title="Recent WEAK_VALIDATION">
        {(overview?.recent_weak || []).length === 0 ? (
          <p className="text-sm text-base-content/50">
            No weak-validation results yet.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>test_id</th>
                  <th>Flow</th>
                </tr>
              </thead>
              <tbody>
                {overview!.recent_weak.map((r) => (
                  <tr key={r.replay_flow_id}>
                    <td className="whitespace-nowrap text-xs">
                      {formatIST(r.captured_at || r.created_at)}
                    </td>
                    <td className="mono">{r.method || "—"}</td>
                    <td className="mono text-xs">{r.path || "—"}</td>
                    <td className="mono text-xs">{r.test_id || "—"}</td>
                    <td>
                      <Link
                        className="link link-primary text-xs"
                        to={`/flows/${r.replay_flow_id}`}
                      >
                        open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
