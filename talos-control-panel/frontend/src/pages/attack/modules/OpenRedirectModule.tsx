/**
 * Open redirect workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack open-redirect …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../open-redirect/OverviewTab";
import RunTab from "../open-redirect/RunTab";
import ResultsTab from "../open-redirect/ResultsTab";
import {
  OPEN_REDIRECT_TABS,
  isOpenRedirectTab,
  type OpenRedirectOverview,
  type OpenRedirectTab,
  type OpenRedirectTechnique,
} from "../open-redirect/shared";

const module = getAttackModule("open-redirect")!;

export default function OpenRedirectModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: OpenRedirectTab = isOpenRedirectTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<OpenRedirectOverview | null>(null);
  const [techniques, setTechniques] = useState<OpenRedirectTechnique[]>([]);

  const setTab = (t: OpenRedirectTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<OpenRedirectOverview>("/api/attack/open-redirect/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: OpenRedirectTechnique[] }>("/api/attack/open-redirect/techniques")
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
            <strong>Open Redirect</strong> scans operator-picked flows.
            Query parameters, JSON fields, form fields, multipart filenames, and
            path parameters are entry points. Optionally restrict to one
            parameter.
          </p>
          <p>
            Each payload is one{" "}
            <span className="mono">open_redirect_attack</span> job and one
            unique replay flow — same contract as SQLi / CORS. Probe flows show
            under <strong>Open Redirect</strong> in the Talos Burp extension.
          </p>
          <p>
            A finding is created when Location, Refresh, meta refresh, or
            JavaScript navigation points at the canary host{" "}
            <span className="mono">talos-or.invalid</span> and that sink was not
            already in the captured baseline.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack open-redirect run --flow &lt;uuid&gt; [--param name]
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {OPEN_REDIRECT_TABS.map(({ id, label }) => (
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
