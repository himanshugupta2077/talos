/**
 * CORS misconfiguration workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack cors …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../cors/OverviewTab";
import RunTab from "../cors/RunTab";
import ResultsTab from "../cors/ResultsTab";
import {
  CORS_TABS,
  isCorsTab,
  type CorsOverview,
  type CorsTab,
  type CorsTechnique,
} from "../cors/shared";

const module = getAttackModule("cors")!;

export default function CorsModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: CorsTab = isCorsTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<CorsOverview | null>(null);
  const [techniques, setTechniques] = useState<CorsTechnique[]>([]);

  const setTab = (t: CorsTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<CorsOverview>("/api/attack/cors/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: CorsTechnique[] }>("/api/attack/cors/techniques")
      .then((r) => {
        if (r.items?.length) setTechniques(r.items);
      })
      .catch(() => undefined);
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

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
      help={
        <>
          <p>
            <strong>CORS Misconfiguration</strong> picks in-scope 200 OK
            captures (POST / PATCH / PUT, then GET), prefers a captured Origin,
            and otherwise synthesizes one from the request host.
          </p>
          <p>
            Each technique is one <span className="mono">cors_attack</span> job
            and one unique replay flow — same contract as unauth / BAC.
          </p>
          <p>
            A finding is created only when a random attacker domain or
            subdomain is reflected. Credentials / wildcard are extra evidence
            on that one PRIMARY finding.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack cors run|candidates|results|status
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {CORS_TABS.map(({ id, label }) => (
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
      {tab === "run" && (
        <RunTab
          projectId={selected.id}
          overview={overview}
          techniques={techniques}
          onRefresh={load}
        />
      )}
      {tab === "results" && (
        <ResultsTab projectId={selected.id} jobsInFlight={jobsInFlight} />
      )}
    </ModuleShell>
  );
}
