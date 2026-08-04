/**
 * Secret Detection workspace — Overview | Detections | Documents |
 * Rules | Settings
 *
 * Nested under Testing hub as Passive module (`/testing/secrets`).
 * Full CLI parity for `talos passive …` (Phase 13 Control Panel).
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { NoProjectNotice } from "../components/Common";
import OverviewTab from "./secret-detection/OverviewTab";
import DetectionsTab from "./secret-detection/DetectionsTab";
import DocumentsTab from "./secret-detection/DocumentsTab";
import RulesTab from "./secret-detection/RulesTab";
import SettingsTab from "./secret-detection/SettingsTab";
import {
  DetectionRow,
  PASSIVE_TABS,
  PassiveConfig,
  PassiveStatus,
  PassiveTab,
  isPassiveTab,
} from "./secret-detection/shared";
import ModuleShell from "./attack/ModuleShell";
import { getAttackModule } from "./attack/registry";

const module = getAttackModule("secrets")!;

export default function SecretDetection() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: PassiveTab = isPassiveTab(tabParam) ? tabParam : "overview";

  const [config, setConfig] = useState<PassiveConfig | null>(null);
  const [status, setStatus] = useState<PassiveStatus | null>(null);
  const [topDetections, setTopDetections] = useState<DetectionRow[]>([]);
  const [emptyState, setEmptyState] = useState<Record<string, boolean>>({});
  const [scannerVersion, setScannerVersion] = useState("");

  const setTab = (t: PassiveTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;

    api
      .get<{ config: PassiveConfig; scanner_version: string }>(
        "/api/passive/config",
        { project_id: selected.id },
      )
      .then((r) => {
        setConfig(r.config);
        setScannerVersion(r.scanner_version || "");
      })
      .catch(() => setConfig(null));

    api
      .get<{
        status: PassiveStatus;
        top_detections: DetectionRow[];
        empty_state: Record<string, boolean>;
      }>("/api/passive/overview", { project_id: selected.id, top_n: 8 })
      .then((r) => {
        setStatus(r.status || null);
        setTopDetections(r.top_detections || []);
        setEmptyState(r.empty_state || {});
      })
      .catch(() => {
        api
          .get<PassiveStatus>("/api/passive/status", {
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
            After proxy capture, source-like response bodies (HTML, JS, JSON,
            CSS, source maps) are scanned for secrets and infrastructure
            disclosures.
          </p>
          <p>
            <strong>Overview</strong> — engine status, counts, rescan, recent
            hits.
          </p>
          <p>
            <strong>Detections</strong> — redacted intelligence inventory;
            filter by category, confidence, finding link.
          </p>
          <p>
            <strong>Documents</strong> — unique body identities, occurrences
            (URLs/flows), virtual children from HTML/source maps.
          </p>
          <p>
            <strong>Rules</strong> — loaded YAML detector packs (read-only).
          </p>
          <p>
            <strong>Settings</strong> — secret detection master switch (
            <span className="mono">enabled</span>), thresholds, content types,
            limits (maps to{" "}
            <span className="mono">talos passive config set</span>).
          </p>
          <p>
            Turn secret detection off with{" "}
            <span className="mono">talos passive config set enabled false</span>{" "}
            or the Overview/Settings Turn off button.
          </p>
          <p>
            High-confidence secrets become Findings (
            <span className="mono">attack_type=passive_secret</span>). Manage
            lifecycle on the Findings page.
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {PASSIVE_TABS.map(({ id, label }) => (
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
          topDetections={topDetections}
          emptyState={emptyState}
          onRefresh={load}
          onGoTab={(t) => isPassiveTab(t) && setTab(t)}
        />
      )}
      {tab === "detections" && <DetectionsTab projectId={selected.id} />}
      {tab === "documents" && <DocumentsTab projectId={selected.id} />}
      {tab === "rules" && <RulesTab projectId={selected.id} />}
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
