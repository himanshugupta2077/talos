/**
 * Auth-Session Testing workspace — progressive tabs (Phase 2):
 * Overview | Bindings | Candidates
 *
 * Full CLI parity for `talos attack auth-session …` grows across phases.
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
            Generate candidates → Approve (CLI until Phase 3) → Run (Phase 4) →
            triage WEAK_VALIDATION.
          </p>
          <p>
            <strong>Overview</strong> — readiness KPIs and recent weak results.
          </p>
          <p>
            <strong>Bindings</strong> — map auth_config fields to jwt mutator.
          </p>
          <p>
            <strong>Candidates</strong> — generate pending tests and browse
            inventory (approve UI Phase 3).
          </p>
          <p>
            Example: bind <span className="mono">Authorization</span>, generate
            for an endpoint, approve <span className="mono">jwt.alg_none</span>,
            run — WEAK_VALIDATION means the mutated token was accepted.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack auth-session bind|generate|approve|run …
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
    </ModuleShell>
  );
}
