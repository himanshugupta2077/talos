/**
 * SSRF workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack ssrf …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../ssrf/OverviewTab";
import RunTab from "../ssrf/RunTab";
import ResultsTab from "../ssrf/ResultsTab";
import {
  SSRF_TABS,
  isSsrfTab,
  type SsrfOverview,
  type SsrfTab,
  type SsrfTechnique,
} from "../ssrf/shared";

const module = getAttackModule("ssrf")!;

export default function SsrfModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: SsrfTab = isSsrfTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<SsrfOverview | null>(null);
  const [techniques, setTechniques] = useState<SsrfTechnique[]>([]);

  const setTab = (t: SsrfTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<SsrfOverview>("/api/attack/ssrf/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: SsrfTechnique[] }>("/api/attack/ssrf/techniques")
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
            <strong>SSRF</strong> scans operator-picked flows.
            Query parameters, JSON fields, form fields, multipart filenames, and
            path parameters are entry points. Optionally restrict to one
            parameter.
          </p>
          <p>
            Each payload is one{" "}
            <span className="mono">ssrf_attack</span> job and one
            unique replay flow — same contract as SQLi / CORS. Probe flows show
            under <strong>SSRF</strong> in the Talos Burp extension.
          </p>
          <p>
            A finding is created when the HTTP response contains a new fetch
            signature versus the captured baseline (cloud metadata, well-known
            files, internal-service banners, Collaborator HTTP body). Optional{" "}
            <span className="mono">--collaborator</span> enables OAST payloads;
            check Burp Collaborator for blind hits.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack ssrf run --flow &lt;uuid&gt; [--param name]
              [--collaborator host]
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {SSRF_TABS.map(({ id, label }) => (
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
