/**
 * SQL injection workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack sqli …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../sqli/OverviewTab";
import RunTab from "../sqli/RunTab";
import ResultsTab from "../sqli/ResultsTab";
import {
  SQLI_TABS,
  isSqliTab,
  type SqliOverview,
  type SqliTab,
  type SqliTechnique,
} from "../sqli/shared";

const module = getAttackModule("sqli")!;

export default function SqliModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: SqliTab = isSqliTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<SqliOverview | null>(null);
  const [techniques, setTechniques] = useState<SqliTechnique[]>([]);

  const setTab = (t: SqliTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<SqliOverview>("/api/attack/sqli/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: SqliTechnique[] }>("/api/attack/sqli/techniques")
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
            <strong>SQL Injection</strong> scans operator-picked flows. Every
            query parameter, JSON field or array index, and form field is an
            entry point.
          </p>
          <p>
            Each payload is one <span className="mono">sqli_attack</span> job
            and one unique replay flow — same contract as CORS / unauth / BAC.
          </p>
          <p>
            A finding is created when a probe shows a new DBMS error versus the
            captured baseline, a UNION column-count leak, or a time delay.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack sqli run --flow &lt;uuid&gt;
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {SQLI_TABS.map(({ id, label }) => (
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
