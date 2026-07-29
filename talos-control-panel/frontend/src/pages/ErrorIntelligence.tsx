/**
 * Error Intelligence workspace — Overview | Errors | Rollups | Settings
 *
 * Nested under Testing hub as Passive module (`/testing/errors`).
 * Intelligence only — no Findings bridge in v1.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { NoProjectNotice } from "../components/Common";
import OverviewTab from "./error-intelligence/OverviewTab";
import ErrorsTab from "./error-intelligence/ErrorsTab";
import RollupsTab from "./error-intelligence/RollupsTab";
import SettingsTab from "./error-intelligence/SettingsTab";
import {
  ERROR_INTEL_TABS,
  ErrorClusterRow,
  ErrorIntelConfig,
  ErrorIntelEmptyState,
  ErrorIntelStatus,
  ErrorIntelTab,
  isErrorIntelTab,
} from "./error-intelligence/shared";
import ModuleShell from "./attack/ModuleShell";
import { getAttackModule } from "./attack/registry";

const module = getAttackModule("errors")!;

export default function ErrorIntelligence() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: ErrorIntelTab = isErrorIntelTab(tabParam) ? tabParam : "overview";

  const [config, setConfig] = useState<ErrorIntelConfig | null>(null);
  const [status, setStatus] = useState<ErrorIntelStatus | null>(null);
  const [topClusters, setTopClusters] = useState<ErrorClusterRow[]>([]);
  const [emptyState, setEmptyState] = useState<ErrorIntelEmptyState>({});
  const [scannerVersion, setScannerVersion] = useState("");

  const setTab = (t: ErrorIntelTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;

    api
      .get<{ config: ErrorIntelConfig; scanner_version: string }>(
        "/api/error-intel/config",
        { project_id: selected.id },
      )
      .then((r) => {
        setConfig(r.config);
        setScannerVersion(r.scanner_version || "");
      })
      .catch(() => setConfig(null));

    api
      .get<{
        status: ErrorIntelStatus;
        top_clusters: ErrorClusterRow[];
        empty_state: ErrorIntelEmptyState;
      }>("/api/error-intel/overview", { project_id: selected.id, top_n: 8 })
      .then((r) => {
        setStatus(r.status || null);
        setTopClusters(r.top_clusters || []);
        setEmptyState(r.empty_state || {});
        if (r.status?.scanner_version) {
          setScannerVersion((v) => v || r.status.scanner_version);
        }
      })
      .catch(() => {
        api
          .get<ErrorIntelStatus>("/api/error-intel/status", {
            project_id: selected.id,
          })
          .then(setStatus)
          .catch(() => setStatus(null));
      });
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  if (!selected) return <NoProjectNotice />;

  return (
    <ModuleShell
      module={module}
      help={
        <>
          <p>
            After proxy capture or active tests, error-like response bodies
            (stacks, SQL, framework pages, disclosures) are clustered for triage.
          </p>
          <p>
            <strong>Overview</strong> — scanner status, severity distribution,
            rescan, top clusters.
          </p>
          <p>
            <strong>Errors</strong> — filterable cluster inventory (default
            medium+ severity); open a cluster for evidence and observations.
          </p>
          <p>
            <strong>Rollups</strong> — parameter and endpoint × error views.
          </p>
          <p>
            <strong>Settings</strong> — enable, caps, rescan (maps to{" "}
            <span className="mono">talos error-intel config|rescan</span>).
          </p>
          <p>
            Intelligence only in v1 — no auto Findings. Full response bodies
            remain on Flow HTTP.
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {ERROR_INTEL_TABS.map(({ id, label }) => (
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
          config={config}
          status={status}
          topClusters={topClusters}
          emptyState={emptyState}
          onRefresh={load}
          onGoTab={(t) => isErrorIntelTab(t) && setTab(t)}
        />
      )}
      {tab === "errors" && (
        <ErrorsTab
          projectId={selected.id}
          scannerVersion={scannerVersion || status?.scanner_version}
        />
      )}
      {tab === "rollups" && <RollupsTab projectId={selected.id} />}
      {tab === "settings" && (
        <SettingsTab
          projectId={selected.id}
          config={config}
          scannerVersion={scannerVersion || status?.scanner_version}
          onRefresh={load}
        />
      )}
    </ModuleShell>
  );
}
