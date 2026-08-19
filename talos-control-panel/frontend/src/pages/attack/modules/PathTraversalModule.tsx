/**
 * Path traversal / LFI workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack path-traversal …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../path-traversal/OverviewTab";
import RunTab from "../path-traversal/RunTab";
import ResultsTab from "../path-traversal/ResultsTab";
import {
  PATH_TRAVERSAL_TABS,
  isPathTraversalTab,
  type PathTraversalOverview,
  type PathTraversalTab,
  type PathTraversalTechnique,
} from "../path-traversal/shared";

const module = getAttackModule("path-traversal")!;

export default function PathTraversalModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: PathTraversalTab = isPathTraversalTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<PathTraversalOverview | null>(null);
  const [techniques, setTechniques] = useState<PathTraversalTechnique[]>([]);

  const setTab = (t: PathTraversalTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<PathTraversalOverview>("/api/attack/path-traversal/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: PathTraversalTechnique[] }>("/api/attack/path-traversal/techniques")
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
            <strong>Path Traversal / LFI</strong> scans operator-picked flows.
            Query parameters, JSON fields, form fields, multipart filenames, and
            path parameters are entry points. Optionally restrict to one
            parameter.
          </p>
          <p>
            Each payload is one{" "}
            <span className="mono">path_traversal_attack</span> job and one
            unique replay flow — same contract as SQLi / CORS. Probe flows show
            under <strong>Path Traversal</strong> in the Talos Burp extension.
          </p>
          <p>
            A finding is created when a probe leaks a well-known file that was
            not in the captured baseline (
            <span className="mono">/etc/passwd</span>,{" "}
            <span className="mono">win.ini</span>, PHP filter base64, …).
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack path-traversal run --flow &lt;uuid&gt; [--param name]
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {PATH_TRAVERSAL_TABS.map(({ id, label }) => (
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
