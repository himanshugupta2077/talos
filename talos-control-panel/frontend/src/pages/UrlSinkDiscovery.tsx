/**
 * URL Sink Discovery workspace — Overview | Inventory (PR4).
 *
 * Nested under Testing hub as Passive module (`/testing/url-sinks`).
 * Prioritization intelligence only — not confirmed SSRF Findings.
 * Rollups + Settings tabs deferred to PR5.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { NoProjectNotice } from "../components/Common";
import ModuleShell from "./attack/ModuleShell";
import { getAttackModule } from "./attack/registry";
import OverviewTab from "./url-sinks/OverviewTab";
import InventoryTab from "./url-sinks/InventoryTab";
import {
  URL_SINK_TABS,
  UrlSinkEmptyState,
  UrlSinkStatus,
  UrlSinkTab,
  SinkRow,
  applyFiltersToSearchParams,
  defaultInventoryFilters,
  isUrlSinkTab,
} from "./url-sinks/shared";

const module = getAttackModule("url-sinks")!;

export default function UrlSinkDiscovery() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: UrlSinkTab = isUrlSinkTab(tabParam) ? tabParam : "overview";

  const [status, setStatus] = useState<UrlSinkStatus | null>(null);
  const [topSinks, setTopSinks] = useState<SinkRow[]>([]);
  const [emptyState, setEmptyState] = useState<UrlSinkEmptyState>({});

  const setTab = (t: UrlSinkTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const goInventory = (opts?: {
    nrs_only?: boolean;
    min_score?: number;
  }) => {
    const thr = status?.score_threshold ?? 45;
    const filters = defaultInventoryFilters({
      nrs_only: opts?.nrs_only ?? true,
      min_score: opts?.min_score ?? thr,
      offset: 0,
    });
    setSearchParams(
      applyFiltersToSearchParams(new URLSearchParams(), filters, {
        tab: "inventory",
      }),
      { replace: true },
    );
  };

  const load = useCallback(() => {
    if (!selected) return;

    api
      .get<{
        status: UrlSinkStatus;
        top_sinks: SinkRow[];
        empty_state: UrlSinkEmptyState;
      }>("/api/url-sink/overview", { project_id: selected.id, top_n: 10 })
      .then((r) => {
        setStatus(r.status || null);
        setTopSinks(r.top_sinks || []);
        setEmptyState(r.empty_state || {});
      })
      .catch(() => {
        api
          .get<UrlSinkStatus>("/api/url-sink/status", {
            project_id: selected.id,
          })
          .then(setStatus)
          .catch(() => setStatus(null));
        setTopSinks([]);
        setEmptyState({});
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
            After proxy capture, parameters that look like URLs, hostnames, IPs,
            or other network resources are scored on{" "}
            <span className="mono">url_features</span> — regardless of name.
          </p>
          <p>
            <strong>Overview</strong> — project knobs, NRS / score KPIs,
            category distributions, top sinks, and optional IV URL-family
            candidates.
          </p>
          <p>
            <strong>Inventory</strong> — filterable passive table (default{" "}
            <span className="mono">min_score=45</span>,{" "}
            <span className="mono">nrs_only</span>). Open a row → evidence
            drawer; primary next step is the IV parameter dossier.
          </p>
          <p>
            Example: after browsing an app that posts{" "}
            <span className="mono">callback=https://…</span>, open Inventory
            (NRS) and jump to the dossier to run URL-sink canaries if warranted.
          </p>
          <p>
            Scores and NRS are <strong>prioritization only</strong> — not
            confirmed SSRF or Findings. Active canaries stay on Input Validation
            (<span className="mono">talos-canary.invalid</span>).
          </p>
        </>
      }
    >
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {URL_SINK_TABS.map(({ id, label }) => (
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
          status={status}
          topSinks={topSinks}
          emptyState={emptyState}
          onRefresh={load}
          onGoInventory={goInventory}
        />
      )}
      {tab === "inventory" && <InventoryTab projectId={selected.id} />}
    </ModuleShell>
  );
}
