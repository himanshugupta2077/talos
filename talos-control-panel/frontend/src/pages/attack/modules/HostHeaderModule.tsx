/**
 * Host-header injection workspace — Overview | Run | Results
 *
 * CLI parity for `talos attack host-header …` under the Testing hub.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../../../state/ProjectContext";
import { api } from "../../../api/client";
import { NoProjectNotice } from "../../../components/Common";
import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import OverviewTab from "../host-header/OverviewTab";
import RunTab from "../host-header/RunTab";
import ResultsTab from "../host-header/ResultsTab";
import {
  HOST_HEADER_TABS,
  isHostHeaderTab,
  type HostHeaderOverview,
  type HostHeaderTab,
  type HostHeaderTechnique,
} from "../host-header/shared";

const module = getAttackModule("host-header")!;

export default function HostHeaderModule() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: HostHeaderTab = isHostHeaderTab(tabParam) ? tabParam : "overview";

  const [overview, setOverview] = useState<HostHeaderOverview | null>(null);
  const [techniques, setTechniques] = useState<HostHeaderTechnique[]>([]);

  const setTab = (t: HostHeaderTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    api
      .get<HostHeaderOverview>("/api/attack/host-header/overview", {
        project_id: pid,
        top_n: 8,
      })
      .then((r) => {
        setOverview(r);
        if (r.techniques?.length) setTechniques(r.techniques);
      })
      .catch(() => setOverview(null));

    api
      .get<{ items?: HostHeaderTechnique[] }>("/api/attack/host-header/techniques")
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
            <strong>Host Header Injection</strong> scans operator-picked
            flows. Host, X-Forwarded-Host, X-Host, Forwarded, and related
            override headers are entry points. Connection stays on the
            captured origin. Optionally restrict to one header.
          </p>
          <p>
            Each payload is one{" "}
            <span className="mono">host_header_attack</span> job and one
            unique replay flow — same contract as path traversal / SSRF.
            Probe flows show under <strong>Host Header Injection</strong> in
            the Talos Burp extension.
          </p>
          <p>
            A finding is created when a probe reflects{" "}
            <span className="mono">talos-hhi.invalid</span> in a URL-shaped
            sink (Location, HTML/JSON absolute URLs, CORS ACAO, Set-Cookie
            Domain) that was not in the captured baseline.
          </p>
          <p>
            CLI:{" "}
            <span className="mono">
              talos attack host-header run --flow &lt;uuid&gt; [--header Host]
            </span>
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {HOST_HEADER_TABS.map(({ id, label }) => (
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
