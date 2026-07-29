/**
 * Unauthenticated Execution workspace — Overview | Run | Results | Filter & Config
 *
 * Full CLI parity for `talos attack unauth …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../unauth/OverviewTab";
import RunTab from "../unauth/RunTab";
import ResultsTab from "../unauth/ResultsTab";
import ConfigTab from "../unauth/ConfigTab";
import {
  UNAUTH_TABS,
  isUnauthTab,
  type UnauthOverview,
  type UnauthTab,
  type UnauthTechnique,
} from "../unauth/shared";

const module = getAttackModule("unauth")!;

export default function UnauthModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: UnauthTab = isUnauthTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<UnauthOverview | null>(null);
  const [techniques, setTechniques] = useState<UnauthTechnique[]>([]);
  const [totalRecipes, setTotalRecipes] = useState(0);

  const setTab = (t: UnauthTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<UnauthOverview>("/api/attack/unauth/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) {
          setTechniques(r.techniques);
          setTotalRecipes(r.total_recipes || 0);
        }
      })
      .catch(() => setOverview(null));

    // Fallback / refresh technique meta even if overview fails
    api
      .get<{
        techniques: string[];
        items?: UnauthTechnique[];
        total_recipes?: number;
      }>("/api/attack/unauth/techniques")
      .then((r) => {
        if (r.items?.length) {
          setTechniques(r.items);
          setTotalRecipes(r.total_recipes || 0);
        } else if (r.techniques?.length) {
          setTechniques(
            r.techniques.map((name) => ({
              name,
              description: "",
              mutation_family: "",
              recipe_count: 1,
            }))
          );
        }
      })
      .catch(() => undefined);
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  // Light poll on overview while jobs in flight
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
            <strong>Unauthenticated Execution</strong> strips configured auth,
            applies techniques and optional request mutations, then classifies
            responses as SECURE / BYPASS / UNKNOWN.
          </p>
          <p>
            <strong>Overview</strong> — readiness, verdict KPIs, recent bypasses,
            quick run.
          </p>
          <p>
            <strong>Run</strong> — pick a technique (or all recipes) and enqueue{" "}
            <span className="mono">unauth_attack</span> jobs.
          </p>
          <p>
            <strong>Results</strong> — triage table with filters; open a row for
            the replay flow.
          </p>
          <p>
            <strong>Filter & Config</strong> — decision filter init/show/validate
            and auto-run for classic <span className="mono">auth_test</span>{" "}
            jobs (distinct from recipe runs).
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack unauth run|config|filter …
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {UNAUTH_TABS.map(({ id, label }) => (
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
          totalRecipes={totalRecipes || overview?.total_recipes || 0}
          onRefresh={load}
        />
      )}
      {tab === "results" && (
        <ResultsTab projectId={selected.id} jobsInFlight={jobsInFlight} />
      )}
      {tab === "config" && (
        <ConfigTab
          projectId={selected.id}
          autoRunEnabled={overview?.auto_run?.enabled ?? false}
          autoRunSource={overview?.auto_run?.source}
          onRefresh={load}
        />
      )}
    </ModuleShell>
  );
}
