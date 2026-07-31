/**
 * Auth-Session Testing workspace — full CLI parity (Phases 1–5):
 * Overview | Bindings | Candidates | Run | Results | Filter & Suite
 *
 * Mutations go through CP API → CLI; inventory is read-only SQL.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../auth-session/OverviewTab";
import BindingsTab from "../auth-session/BindingsTab";
import CandidatesTab from "../auth-session/CandidatesTab";
import RunTab from "../auth-session/RunTab";
import ResultsTab from "../auth-session/ResultsTab";
import ConfigTab from "../auth-session/ConfigTab";
import {
  AUTH_SESSION_TABS,
  isAuthSessionTab,
  type AuthSessionOverview,
  type AuthSessionTab,
} from "../auth-session/shared";

const module = getAttackModule("auth-session")!;

export default function AuthSessionModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: AuthSessionTab = isAuthSessionTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<AuthSessionOverview | null>(null);

  const setTab = (t: AuthSessionTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;
    api
      .get<AuthSessionOverview>("/api/attack/auth-session/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then(setOverview)
      .catch(() => setOverview(null));
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  // Light poll while jobs in flight
  useEffect(() => {
    if (!selected) return;
    const inFlight =
      (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;
    if (!inFlight) return;
    const id = window.setInterval(load, 10000);
    return () => window.clearInterval(id);
  }, [selected, overview?.jobs_pending, overview?.jobs_running, load]);

  if (!selected) return <NoProjectNotice />;

  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;

  return (
    <ModuleShell
      module={module}
      helpTitle="How Auth-Session Testing works"
      help={
        <>
          <p>
            <strong>Authentication & Session Testing</strong> mutates a
            presented JWT (algorithm, signature, claims, structure, kid) and
            checks whether the target still accepts it. Distinct from Unauth
            (strip), BAC (role swap), and Auth page (config only).
          </p>
          <p>
            <strong>Workflow:</strong> Auth page (header/cookie names) → Bind →
            Generate candidates → <strong>Approve</strong> → Run → triage{" "}
            <span className="mono">WEAK_VALIDATION</span> → tune decision filter
            / suite and re-run.
          </p>
          <p>
            <strong>Overview</strong> — readiness KPIs and recent weak results.
          </p>
          <p>
            <strong>Bindings</strong> — map auth_config fields to jwt mutator.
          </p>
          <p>
            <strong>Candidates</strong> — generate pending tests; approve /
            reject / unapprove (operator gate before HTTP).
          </p>
          <p>
            <strong>Run</strong> — enqueue approved tests (or right-now for ≤20).
          </p>
          <p>
            <strong>Results</strong> — WEAK_VALIDATION / SECURE / UNKNOWN triage.
          </p>
          <p>
            <strong>Filter & Suite</strong> — decision filter init/show/validate
            and JWT suite catalog (no apply in v1).
          </p>
          <p>
            Example: bind <span className="mono">Authorization</span>, generate
            for an endpoint, approve <span className="mono">jwt.alg_none</span>,
            run — WEAK_VALIDATION means the mutated token was accepted.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack auth-session bind|generate|approve|run|results|filter|suite …
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {AUTH_SESSION_TABS.map(({ id, label }) => (
          <button
            key={id}
            role="tab"
            type="button"
            className={`tab ${tab === id ? "tab-active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <OverviewTab
          projectId={selected.id}
          overview={overview}
          onRefresh={load}
          onGoTab={setTab}
        />
      )}
      {tab === "bindings" && (
        <BindingsTab projectId={selected.id} onChanged={load} />
      )}
      {tab === "candidates" && (
        <CandidatesTab projectId={selected.id} onChanged={load} />
      )}
      {tab === "run" && (
        <RunTab
          projectId={selected.id}
          overview={overview}
          onRefresh={load}
        />
      )}
      {tab === "results" && (
        <ResultsTab projectId={selected.id} jobsInFlight={jobsInFlight} />
      )}
      {tab === "config" && (
        <ConfigTab
          projectId={selected.id}
          overview={overview}
          onRefresh={load}
        />
      )}
    </ModuleShell>
  );
}
