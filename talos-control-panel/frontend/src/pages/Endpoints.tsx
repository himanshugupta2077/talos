/**
 * Endpoint Workspace — Inventory | Policy | Rules | Coverage
 *
 * Inventory = endpoint operations (browse, filter, bulk mutate, test)
 * Policy    = Talos decisions (testable/skipped + explain)
 * Rules     = path-level policy configuration + preview
 * Coverage  = read-only model quality over Talos state
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { ModuleHelp, NoProjectNotice } from "../components/Common";
import CoverageTab from "./endpoints/CoverageTab";
import InventoryTab from "./endpoints/InventoryTab";
import PolicyTab from "./endpoints/PolicyTab";
import RulesTab from "./endpoints/RulesTab";
import {
  EndpointFilters,
  FilterState,
  WorkspaceTab,
} from "./endpoints/shared";

const EMPTY_OPTIONS: EndpointFilters = {
  methods: [],
  roles: [],
  modules: [],
  priorities: [],
  priority_sources: [],
  qualification_reasons: [],
  tags: [],
  origins: [],
};

export default function Endpoints() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = (searchParams.get("tab") as WorkspaceTab) || "inventory";
  const tab: WorkspaceTab = ["inventory", "policy", "rules", "coverage"].includes(tabParam)
    ? tabParam
    : "inventory";

  const [filterOptions, setFilterOptions] = useState<EndpointFilters>(EMPTY_OPTIONS);
  const [inventorySeed, setInventorySeed] = useState<Partial<FilterState> | undefined>();
  const [focusRuleId, setFocusRuleId] = useState<string | null>(
    searchParams.get("rule") || null
  );
  const [seedPattern, setSeedPattern] = useState<string | null>(null);

  useEffect(() => {
    if (!selected) return;
    api
      .get<EndpointFilters>("/api/endpoints/filters", { project_id: selected.id })
      .then(setFilterOptions)
      .catch(() => setFilterOptions(EMPTY_OPTIONS));
  }, [selected]);

  const setTab = (t: WorkspaceTab, extra?: Record<string, string>) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    if (extra) {
      for (const [k, v] of Object.entries(extra)) {
        if (v) next.set(k, v);
        else next.delete(k);
      }
    }
    setSearchParams(next, { replace: true });
  };

  const openRules = useCallback(
    (ruleId?: string) => {
      setFocusRuleId(ruleId || null);
      setTab("rules", ruleId ? { rule: ruleId } : { rule: "" });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [searchParams]
  );

  const jumpInventory = useCallback(
    (filters: Partial<FilterState>) => {
      setInventorySeed(filters);
      setTab("inventory");
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [searchParams]
  );

  const createRuleFromSelection = useCallback(
    (pattern: string) => {
      setSeedPattern(pattern);
      setTab("rules");
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [searchParams]
  );

  if (!selected) return <NoProjectNotice />;

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h1 className="text-xl font-semibold">Endpoints</h1>
          <p className="text-sm text-base-content/60 mt-0.5">
            Endpoint Workspace — inventory, policy decisions, path rules, and coverage.
          </p>
        </div>
        <ModuleHelp title="How the Endpoint Workspace works">
          <p>
            <strong>Inventory</strong> is where you browse discovered endpoints, filter by
            resolved policy fields, multi-select, and run bulk mark/priority/exclusion/tag/test
            operations or <strong>run attacks</strong> on the top 1–5 test flows per
            selected endpoint (same catalog as Flows). Mutations use multi-ID Talos CLI
            commands atomically — the panel never invents its own policy engine.
          </p>
          <p>
            <strong>Policy</strong> answers what Talos will test, skip, or prioritize, and why.
            Use Explain policy for the same structure as{" "}
            <span className="mono">talos endpoint policy</span>.
          </p>
          <p>
            <strong>Rules</strong> is the UI for path policy rules (add/update/delete/preview).
            Preview calls the same core matcher as live policy.
          </p>
          <p>
            <strong>Coverage</strong> is a read-only quality view (qualification, baseline, roles
            observed, parameters). Role coverage is traffic observation, not the Access Model.
          </p>
        </ModuleHelp>
      </div>

      <div role="tablist" className="tabs tabs-boxed w-fit mb-6 flex-wrap">
        {(
          [
            ["inventory", "Inventory"],
            ["policy", "Policy"],
            ["rules", "Rules"],
            ["coverage", "Coverage"],
          ] as const
        ).map(([id, label]) => (
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

      {tab === "inventory" && (
        <InventoryTab
          projectId={selected.id}
          filterOptions={filterOptions}
          initialFilters={inventorySeed}
          onOpenRules={openRules}
          onCreateRuleFromSelection={createRuleFromSelection}
        />
      )}
      {tab === "policy" && (
        <PolicyTab
          projectId={selected.id}
          onOpenRules={openRules}
          onJumpInventory={jumpInventory}
        />
      )}
      {tab === "rules" && (
        <RulesTab
          projectId={selected.id}
          focusRuleId={focusRuleId}
          seedPattern={seedPattern}
          onConsumedSeed={() => setSeedPattern(null)}
        />
      )}
      {tab === "coverage" && (
        <CoverageTab projectId={selected.id} onJumpInventory={jumpInventory} />
      )}
    </div>
  );
}
