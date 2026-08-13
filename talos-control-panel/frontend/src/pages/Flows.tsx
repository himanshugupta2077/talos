/**
 * Flows list — dense table with optional intelligence flags and shared FlowActions.
 */

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { ModuleHelp, NoProjectNotice } from "../components/Common";
import DataTable, { Column } from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import { attackModuleShortLabel } from "../lib/attackDisplay";
import { FlowRow, Role } from "../types";
import FlowActions from "./flows/FlowActions";
import FlowsAttackBar from "./flows/FlowsAttackBar";
import {
  defaultSelectedAttackIds,
  runFlowAttacks,
} from "./flows/flowAttacks";

interface Filters {
  sources: string[];
  methods: string[];
  hosts: string[];
  statuses: number[];
  roles: string[];
  modules: string[];
  attack_modules: string[];
}

interface FlowListRow extends FlowRow {
  is_replay?: boolean;
  body_truncated?: boolean;
  has_diff?: boolean;
  has_bac?: boolean;
  has_unauth?: boolean;
  has_finding_evidence?: boolean;
  attack_module?: string | null;
  attack_verdict?: string | null;
}

export default function Flows() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const endpointFilter = searchParams.get("endpoint") || "";
  const [rows, setRows] = useState<FlowListRow[]>([]);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState<Filters>({
    sources: [],
    methods: [],
    hosts: [],
    statuses: [],
    roles: [],
    modules: [],
    attack_modules: [],
  });
  const [source, setSource] = useState(searchParams.get("source") || "");
  const [method, setMethod] = useState(searchParams.get("method") || "");
  const [host, setHost] = useState(searchParams.get("host") || "");
  const [status, setStatus] = useState(searchParams.get("status_code") || "");
  const [role, setRole] = useState(searchParams.get("role") || "");
  const [module, setModule] = useState(searchParams.get("module") || "");
  const [attackModule, setAttackModule] = useState(
    searchParams.get("attack_module") || ""
  );
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [loading, setLoading] = useState(false);
  const [menuFlow, setMenuFlow] = useState<FlowListRow | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectedAttackIds, setSelectedAttackIds] = useState<string[]>(
    defaultSelectedAttackIds
  );
  const navigate = useNavigate();

  const projectId = selected?.id;
  const runAttacks = useAction(
    "Run attacks on selected flows",
    (ids: string[]) => runFlowAttacks(projectId || "", ids, selectedAttackIds)
  );

  useEffect(() => {
    if (!selected) return;
    api.get<Filters>("/api/flows/filters", { project_id: selected.id }).then(setFilters);
    api.get<{ roles: Role[] }>("/api/roles", { project_id: selected.id }).then((r) => setRoles(r.roles));
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    api
      .get<{ flows: FlowListRow[]; total: number }>("/api/flows", {
        project_id: selected.id,
        limit: 200,
        source,
        method,
        host,
        status_code: status,
        role,
        module,
        attack_module: attackModule,
        search,
        endpoint: endpointFilter || undefined,
        include: "flags",
      })
      .then((r) => {
        setRows(r.flows);
        setTotal(r.total);
      })
      .finally(() => {
        setLoading(false);
        setSelectedIds(new Set());
      });
  }, [
    selected,
    source,
    method,
    host,
    status,
    role,
    module,
    attackModule,
    search,
    endpointFilter,
  ]);

  // Keep list filters in URL so detail adjacent can stay filter-aware
  useEffect(() => {
    const next = new URLSearchParams();
    if (endpointFilter) next.set("endpoint", endpointFilter);
    if (source) next.set("source", source);
    if (method) next.set("method", method);
    if (host) next.set("host", host);
    if (status) next.set("status_code", status);
    if (role) next.set("role", role);
    if (module) next.set("module", module);
    if (attackModule) next.set("attack_module", attackModule);
    if (search) next.set("search", search);
    setSearchParams(next, { replace: true });
  }, [
    source,
    method,
    host,
    status,
    role,
    module,
    attackModule,
    search,
    endpointFilter,
    setSearchParams,
  ]);

  if (!selected) return <NoProjectNotice />;

  const visibleIds = rows.map((r) => r.id);
  const allVisibleSelected =
    visibleIds.length > 0 && visibleIds.every((id) => selectedIds.has(id));

  const toggleRow = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAllVisible = () => {
    setSelectedIds((prev) => {
      if (allVisibleSelected) return new Set();
      return new Set(visibleIds);
    });
  };

  const openDetail = (id: string, hash?: string) => {
    const qs = searchParams.toString();
    navigate(`/flows/${id}${qs ? `?${qs}` : ""}${hash || ""}`);
  };

  const columns: Column<FlowListRow>[] = [
    {
      key: "select",
      header: (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={allVisibleSelected}
          onChange={toggleAllVisible}
          title="Select all visible"
          onClick={(e) => e.stopPropagation()}
        />
      ),
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 48,
      minWidth: 40,
      render: (r) => (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={selectedIds.has(r.id)}
          onChange={() => toggleRow(r.id)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
    },
    {
      key: "captured_at",
      header: "Time",
      className: "text-xs whitespace-nowrap",
      defaultWidth: 140,
      sortValue: (r) => r.captured_at,
      render: (r) => formatIST(r.captured_at),
    },
    {
      key: "method",
      header: "Method",
      defaultWidth: 80,
      minWidth: 64,
      render: (r) => <span className="badge badge-outline badge-sm mono">{r.method}</span>,
    },
    { key: "host", header: "Host", className: "mono text-xs", defaultWidth: 160 },
    { key: "path", header: "Path", className: "mono text-xs", defaultWidth: 220 },
    {
      key: "status_code",
      header: "Status",
      defaultWidth: 72,
      minWidth: 56,
      render: (r) => <StatusBadge value={r.status_code} />,
    },
    {
      key: "signals",
      header: "Signals",
      sortable: false,
      defaultWidth: 100,
      render: (r) => (
        <div className="flex flex-wrap gap-0.5" onClick={(e) => e.stopPropagation()}>
          {r.is_replay && (
            <button
              type="button"
              className="badge badge-xs badge-ghost"
              title="Replay of another flow"
              onClick={() => openDetail(r.id, "#section=replay")}
            >
              ↺
            </button>
          )}
          {r.has_diff && (
            <button
              type="button"
              className="badge badge-xs badge-info"
              title="Has replay diff"
              onClick={() => openDetail(r.id, "#section=replay")}
            >
              Δ
            </button>
          )}
          {(r.has_bac || r.has_unauth) && (
            <button
              type="button"
              className="badge badge-xs badge-warning"
              title="Attack result"
              onClick={() => openDetail(r.id)}
            >
              A
            </button>
          )}
          {r.has_finding_evidence && (
            <button
              type="button"
              className="badge badge-xs badge-error"
              title="Finding evidence"
              onClick={() => openDetail(r.id)}
            >
              F
            </button>
          )}
          {r.body_truncated && (
            <span className="badge badge-xs badge-ghost" title="Body truncated">
              trunc
            </span>
          )}
        </div>
      ),
    },
    { key: "source", header: "Source", defaultWidth: 96 },
    {
      key: "attack_module",
      header: "Attack",
      defaultWidth: 120,
      sortValue: (r) => r.attack_module || "",
      render: (r) =>
        r.attack_module ? (
          <span
            className="badge badge-xs badge-outline whitespace-nowrap"
            title={attackModuleShortLabel(r.attack_module)}
          >
            {r.attack_module === "cors"
              ? "CORS"
              : attackModuleShortLabel(r.attack_module)}
          </span>
        ) : (
          <span className="text-base-content/35">—</span>
        ),
    },
    ...(attackModule
      ? [
          {
            key: "attack_verdict",
            header: "Verdict",
            defaultWidth: 140,
            sortValue: (r: FlowListRow) => r.attack_verdict || "",
            render: (r: FlowListRow) => (
              <StatusBadge value={r.attack_verdict} />
            ),
          } satisfies Column<FlowListRow>,
        ]
      : []),
    { key: "role_name", header: "Role", defaultWidth: 100 },
    { key: "module_name", header: "Module", defaultWidth: 100 },
    {
      key: "actions",
      header: "Actions",
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 72,
      minWidth: 56,
render: (r) => {
        const open = menuFlow?.id === r.id;
        return (
          <div
            className={`dropdown dropdown-end ${open ? "dropdown-open" : ""}`}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              tabIndex={0}
              type="button"
              className="btn btn-xs btn-ghost"
              aria-label="Flow actions"
              aria-expanded={open}
              onClick={() => setMenuFlow(open ? null : r)}
            >
              ⋮
            </button>
            {open && (
              <div
                className="dropdown-content z-[60] shadow-lg bg-base-200 rounded-box w-56 border border-base-300 text-sm p-1"
                style={{ position: "absolute", right: 0, top: "100%" }}
              >
                <FlowActions
                  variant="menu"
                  projectId={selected.id}
                  roles={roles}
                  flow={{
                    id: r.id,
                    method: r.method,
                    host: r.host,
                    path: r.path,
                    query: r.query,
                    endpoint_id: r.endpoint_id,
                  }}
                  onDone={() => setMenuFlow(null)}
                  onRequestAttacks={() => setSelectedIds(new Set([r.id]))}
                  className="menu menu-sm p-0"
                />
              </div>
            )}
          </div>
        );
      },
    },
  ];

  const selectClass = "select select-xs select-bordered";

  return (
    <div>
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <h1 className="text-xl font-semibold">Flows ({total})</h1>
      </div>

      <ModuleHelp title="How Flows work">
        <p>
          Flows are stored HTTP transactions from proxy capture, replay, IV, and
          attacks. Filter the table (including <strong>attack</strong> for IV,
          BAC, CORS, unauth, …). An attack filter also shows each row’s engine
          verdict (CORS_MISCONFIG, POSSIBLE_BAC, BYPASS, …). Open a row for the
          inspection workspace (request/response, replay chain, attack results).
        </p>
        <p>
          Select one or more rows and use the bar to run attacks on those
          flows only — CORS, Unauth, BAC, IV, or generate Auth-session
          candidates. Intruder still needs a configured session. Row{" "}
          <strong>⋮</strong> matches the detail Actions panel (run attacks,
          replay, export, assign login/control). Signal icons (↺ Δ A F) appear
          only when Core tables have related rows.
        </p>
        <p>
          Table: drag a column’s right edge to resize, drag a header to reorder,
          use Columns to show/hide. Layout is saved for this browser.
        </p>
      </ModuleHelp>

      {endpointFilter && (
        <div className="alert alert-info text-sm py-2 mb-3 mt-3">
          Filtered to endpoint <span className="mono">{endpointFilter.slice(0, 8)}…</span>
          <button
            type="button"
            className="btn btn-xs ml-2"
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              next.delete("endpoint");
              setSearchParams(next);
            }}
          >
            Clear
          </button>
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-4 mt-3">
        <input
          className="input input-xs input-bordered mono w-56"
          placeholder="Search host / path / query…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className={selectClass} value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">source: any</option>
          {filters.sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className={selectClass} value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="">method: any</option>
          {filters.methods.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select className={selectClass} value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">host: any</option>
          {filters.hosts.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
        <select className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">status: any</option>
          {filters.statuses.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className={selectClass} value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">role: any</option>
          {filters.roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select className={selectClass} value={module} onChange={(e) => setModule(e.target.value)}>
          <option value="">module: any</option>
          {filters.modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={attackModule}
          onChange={(e) => setAttackModule(e.target.value)}
        >
          <option value="">attack: any</option>
          {(filters.attack_modules || []).map((m) => (
            <option key={m} value={m}>
              {attackModuleShortLabel(m)}
            </option>
          ))}
        </select>
      </div>

      <p className="text-[11px] text-base-content/45 mb-2">
        Signals: ↺ replay · Δ diff · A attack · F finding evidence · trunc body truncated.
        Filters are kept when opening detail so ←/→ stays in the same subset.
      </p>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        loading={loading}
        storageKey="flows-v2"
        onRowClick={(r) => openDetail(r.id)}
        rowClassName={(r) => (selectedIds.has(r.id) ? "bg-primary/10" : "")}
        emptyLabel="No flows captured yet."
      />

      <FlowsAttackBar
        flowCount={selectedIds.size}
        selectedAttackIds={selectedAttackIds}
        busy={runAttacks.running}
        onToggleAttack={(id) => {
          setSelectedAttackIds((prev) =>
            prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
          );
        }}
        onClear={() => setSelectedIds(new Set())}
        onRun={async () => {
          const ids = [...selectedIds];
          if (!ids.length) return;
          await runAttacks.run(ids);
          setSelectedIds(new Set());
        }}
      />
    </div>
  );
}
