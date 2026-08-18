/**
 * HTTP request smuggling workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack smuggle …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../smuggle/OverviewTab";
import RunTab from "../smuggle/RunTab";
import ResultsTab from "../smuggle/ResultsTab";
import {
  SMUGGLE_TABS,
  isSmuggleTab,
  type SmuggleOverview,
  type SmuggleTab,
  type SmuggleTechnique,
} from "../smuggle/shared";

const module = getAttackModule("smuggle")!;

export default function SmuggleModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: SmuggleTab = isSmuggleTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<SmuggleOverview | null>(null);
  const [techniques, setTechniques] = useState<SmuggleTechnique[]>([]);

  const setTab = (t: SmuggleTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<SmuggleOverview>("/api/attack/smuggle/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: SmuggleTechnique[] }>("/api/attack/smuggle/techniques")
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
            <strong>HTTP Request Smuggling</strong> needs a captured flow UUID.
            Each technique is one <span className="mono">smuggle_attack</span>{" "}
            job and one unique replay flow. Probes are raw HTTP/1.1 to the
            origin so CL/TE conflicts stay intact.
          </p>
          <p>
            NTLM / platform-auth hosts complete the handshake on the same
            keep-alive connection, then send the probe. Requests appear in the
            Talos Burp extension under HTTP Request Smuggling.
          </p>
          <p>
            A finding is created only when the follow-up is poisoned (400/404/405
            vs baseline, canary echo, or an extra queued response).
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack smuggle run --flow &lt;uuid&gt;
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {SMUGGLE_TABS.map(({ id, label }) => (
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
