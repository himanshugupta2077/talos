/**
 * BAC (Broken Access Control) workspace — Overview | Run | Results | Filter
 *
 * Full CLI parity for `talos attack bac …` under the Testing hub.
 * Default action: enqueue all technique families.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../bac/OverviewTab";
import RunTab from "../bac/RunTab";
import ResultsTab from "../bac/ResultsTab";
import ConfigTab from "../bac/ConfigTab";
import {
  BAC_TABS,
  isBacTab,
  type BacOverview,
  type BacTab,
  type BacTechnique,
} from "../bac/shared";

const module = getAttackModule("bac")!;

export default function BacModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: BacTab = isBacTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<BacOverview | null>(null);
  const [techniques, setTechniques] = useState<BacTechnique[]>([]);
  const [totalVariants, setTotalVariants] = useState(0);

  const setTab = (t: BacTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<BacOverview>("/api/attack/bac/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) {
          setTechniques(r.techniques);
          setTotalVariants(r.total_variants || 0);
        }
      })
      .catch(() => setOverview(null));

    api
      .get<{
        techniques: string[];
        items?: BacTechnique[];
        total_variants?: number;
      }>(
        "/api/attack/bac/techniques",
        { project_id: pid }
      )
      .then((r) => {
        if (r.items?.length) {
          setTechniques(r.items);
          setTotalVariants(r.total_variants || 0);
        } else if (r.techniques?.length) {
          setTechniques(
            r.techniques.map((name) => ({
              name,
              description: "",
              attack_type: `bac_${name.replace(/-/g, "_")}`,
              variant_count: 1,
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
            <strong>Broken Access Control</strong> generates scheduler jobs from
            the access matrix: attacker roles attempt target-role flows using
            technique-specific mutations (session swap, method/url/host fuzz,
            role inject, parser confusion, …).
          </p>
          <p>
            <strong>Overview</strong> — readiness, verdict KPIs, recent
            POSSIBLE_BAC, one-click run all.
          </p>
          <p>
            <strong>Run</strong> — default all techniques; customize role,
            module/endpoint scope, auto-generate, and technique subset.
          </p>
          <p>
            <strong>Results</strong> — triage table with filters; open a row for
            the replay flow.
          </p>
          <p>
            <strong>Filter</strong> — decision filter init/show/validate/apply for{" "}
            <span className="mono">BAC-decision-filter.yaml</span> (offline
            reclassify of stored results and auto-reject FP findings).
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack bac &lt;technique&gt; [--role] [--module|--endpoint]
              [--auto-generate]
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {BAC_TABS.map(({ id, label }) => (
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
          totalVariants={totalVariants || overview?.total_variants || 0}
          onRefresh={load}
        />
      )}
      {tab === "results" && (
        <ResultsTab
          projectId={selected.id}
          techniques={techniques}
          jobsInFlight={jobsInFlight}
        />
      )}
      {tab === "config" && (
        <ConfigTab projectId={selected.id} onRefresh={load} />
      )}
    </ModuleShell>
  );
}
