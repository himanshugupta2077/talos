/**
 * Input Validation workspace — Overview | Candidates | Parameters |
 * Multi-level | Run | Settings
 *
 * Nested under Testing hub as Active module (`/testing/input-validation`).
 * Surfaces M1–M12 intelligence for operators: status, candidates,
 * parameter/endpoint/host dossiers, adaptive run controls, full config.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { NoProjectNotice } from "../components/Common";
import OverviewTab from "./input-validation/OverviewTab";
import CandidatesTab from "./input-validation/CandidatesTab";
import ParametersTab from "./input-validation/ParametersTab";
import MultiLevelTab from "./input-validation/MultiLevelTab";
import RunTab from "./input-validation/RunTab";
import SettingsTab from "./input-validation/SettingsTab";
import {
  CandidateRow,
  IV_TABS,
  IvConfig,
  IvStatus,
  IvTab,
  isIvTab,
} from "./input-validation/shared";
import ModuleShell from "./attack/ModuleShell";
import { getAttackModule } from "./attack/registry";

const module = getAttackModule("iv")!;

export default function InputValidation() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: IvTab = isIvTab(tabParam) ? tabParam : "overview";

  const [config, setConfig] = useState<IvConfig | null>(null);
  const [status, setStatus] = useState<IvStatus | null>(null);
  const [topCandidates, setTopCandidates] = useState<CandidateRow[]>([]);
  const [emptyState, setEmptyState] = useState<Record<string, boolean>>({});

  const setTab = (t: IvTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(() => {
    if (!selected) return;
    api
      .get<{ config: IvConfig }>("/api/input-validation/config", {
        project_id: selected.id,
      })
      .then((r) => {
        setConfig(r.config);
      })
      .catch(() => setConfig(null));

    api
      .get<{
        status: IvStatus;
        top_candidates: CandidateRow[];
        empty_state: Record<string, boolean>;
      }>("/api/input-validation/overview", {
        project_id: selected.id,
        top_n: 10,
      })
      .then((r) => {
        setStatus(r.status || null);
        setTopCandidates(r.top_candidates || []);
        setEmptyState(r.empty_state || {});
      })
      .catch(() => {
        // Fallback to status-only if overview fails.
        api
          .get<IvStatus>("/api/input-validation/status", {
            project_id: selected.id,
          })
          .then(setStatus)
          .catch(() => setStatus(null));
      });
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh while jobs are active (Overview / Run).
  useEffect(() => {
    if (!selected) return;
    const hasJobs =
      (status?.running ?? 0) + (status?.queued ?? 0) > 0 || emptyState.has_jobs;
    if (!hasJobs) return;
    if (typeof document !== "undefined" && document.hidden) return;
    const id = window.setInterval(() => {
      if (typeof document !== "undefined" && document.hidden) return;
      load();
    }, 5000);
    return () => window.clearInterval(id);
  }, [selected, status?.running, status?.queued, emptyState.has_jobs, load]);

  if (!selected) return <NoProjectNotice />;

  return (
    <ModuleShell
      module={module}
      helpTitle="How Input Validation works"
      help={
        <>
          <p>
            <strong>Overview</strong> shows progress, confidence, and top
            prioritization targets after a run.
          </p>
          <p>
            <strong>Candidates</strong> ranks attack surfaces (XSS, SQLi, redirect, …)
            for manual follow-up — scores are prioritization only.
          </p>
          <p>
            <strong>Parameters</strong> lists intelligence profiles. Open a row for the
            full dossier (reflection, taxonomy, types, parser, evidence flows).
          </p>
          <p>
            <strong>Multi-level</strong> shows endpoint and host inheritance (Module 10).
          </p>
          <p>
            <strong>Run</strong> schedules the full IV probe set (
            <span className="mono">talos input-validation run</span>
            ). <strong>Settings</strong> covers enable, phases, auth artifacts,
            exclusions.
          </p>
          <p>
            Happy path: Enable → Run → wait for scheduler → Synthesize → review
            Candidates → open parameter dossiers.
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {IV_TABS.map(({ id, label }) => (
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
          topCandidates={topCandidates}
          emptyState={emptyState}
          onRefresh={load}
          onGoTab={(t) => isIvTab(t) && setTab(t)}
        />
      )}
      {tab === "candidates" && <CandidatesTab projectId={selected.id} />}
      {tab === "parameters" && <ParametersTab projectId={selected.id} />}
      {tab === "multi-level" && <MultiLevelTab projectId={selected.id} />}
      {tab === "run" && (
        <RunTab
          projectId={selected.id}
          status={status}
          onRefresh={load}
        />
      )}
      {tab === "settings" && (
        <SettingsTab
          projectId={selected.id}
          config={config}
          onRefresh={load}
        />
      )}
    </ModuleShell>
  );
}
