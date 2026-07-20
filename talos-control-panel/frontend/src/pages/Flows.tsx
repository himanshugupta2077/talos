import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { NoProjectNotice, Modal } from "../components/Common";
import DataTable, { Column } from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import { FlowRow, Role } from "../types";

interface Filters {
  sources: string[]; methods: string[]; hosts: string[]; statuses: number[]; roles: string[]; modules: string[];
}

export default function Flows() {
  const { selected } = useProject();
  const [searchParams] = useSearchParams();
  const endpointFilter = searchParams.get("endpoint") || "";
  const [rows, setRows] = useState<FlowRow[]>([]);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState<Filters>({ sources: [], methods: [], hosts: [], statuses: [], roles: [], modules: [] });
  const [source, setSource] = useState(""); const [method, setMethod] = useState("");
  const [host, setHost] = useState(""); const [status, setStatus] = useState("");
  const [role, setRole] = useState(""); const [module, setModule] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [menuFlow, setMenuFlow] = useState<FlowRow | null>(null);
  const [assignFlow, setAssignFlow] = useState<FlowRow | null>(null);
  const [assignRoleId, setAssignRoleId] = useState("");
  const [roles, setRoles] = useState<Role[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    if (!selected) return;
    api.get<Filters>("/api/flows/filters", { project_id: selected.id }).then(setFilters);
    api.get<{ roles: Role[] }>("/api/roles", { project_id: selected.id }).then((r) => setRoles(r.roles));
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    api
      .get<{ flows: FlowRow[]; total: number }>("/api/flows", {
        project_id: selected.id, limit: 200, source, method, host, status_code: status, role, module, search,
        endpoint: endpointFilter || undefined,
      })
      .then((r) => { setRows(r.flows); setTotal(r.total); })
      .finally(() => setLoading(false));
  }, [selected, source, method, host, status, role, module, search, endpointFilter]);

  const replayNow = useAction("Replay flow now", (id: string) =>
    api.post(`/api/replay/flow/${id}`, { right_now: true }, { project_id: selected!.id })
  );
  const enqueueReplay = useAction("Enqueue replay", (id: string) =>
    api.post("/api/scheduler/enqueue/flow", { flow_id: id }, { project_id: selected!.id })
  );
  const exportFlow = useAction("Export flow", (id: string) =>
    api.post(`/api/flows/${id}/export`, {}, { project_id: selected!.id })
  );
  const setLoginFlow = useAction("Set as login flow", (roleId: string, flowId: string) =>
    api.post(`/api/auth-config/${roleId}/flows/${flowId}`, {}, { project_id: selected!.id })
  );
  const setControlFlow = useAction("Set as control/validation flow", (roleId: string, flowId: string) =>
    api.post(`/api/auth-config/${roleId}/control-flows/${flowId}`, {}, { project_id: selected!.id })
  );

  if (!selected) return <NoProjectNotice />;

  const columns: Column<FlowRow>[] = [
    { key: "captured_at", header: "Time", className: "text-xs whitespace-nowrap", sortValue: (r) => r.captured_at, render: (r) => formatIST(r.captured_at) },
    { key: "method", header: "Method", render: (r) => <span className="badge badge-outline badge-sm mono">{r.method}</span> },
    { key: "host", header: "Host", className: "mono text-xs" },
    { key: "path", header: "Path", className: "mono text-xs" },
    { key: "status_code", header: "Status", render: (r) => <StatusBadge value={r.status_code} /> },
    { key: "source", header: "Source" },
    { key: "role_name", header: "Role" },
    { key: "module_name", header: "Module" },
    {
      key: "actions",
      header: "",
      sortable: false,
      alwaysVisible: true,
      render: (r) => (
        <div className="dropdown dropdown-end" onClick={(e) => e.stopPropagation()}>
          <button
            tabIndex={0}
            className="btn btn-xs btn-ghost"
            onClick={() => setMenuFlow(menuFlow?.id === r.id ? null : r)}
          >
            ⋮
          </button>
          {menuFlow?.id === r.id && (
            <ul className="dropdown-content z-30 menu p-2 shadow bg-base-200 rounded-box w-52 border border-base-300 text-sm">
              <li><button onClick={async () => { setMenuFlow(null); await replayNow.run(r.id); }}>Replay now</button></li>
              <li><button onClick={async () => { setMenuFlow(null); await enqueueReplay.run(r.id); }}>Enqueue replay</button></li>
              <li><button onClick={async () => { setMenuFlow(null); await exportFlow.run(r.id); }}>Export</button></li>
              <li><button onClick={() => { setMenuFlow(null); setAssignFlow(r); setAssignRoleId(roles[0]?.id || ""); }}>Set as login/control flow…</button></li>
            </ul>
          )}
        </div>
      ),
    },
  ];

  const selectClass = "select select-xs select-bordered";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold">Flows ({total})</h1>
      </div>
      {endpointFilter && (
        <div className="alert alert-info text-sm py-2 mb-3">
          Filtered to endpoint <span className="mono">{endpointFilter.slice(0, 8)}…</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-4">
        <input
          className="input input-xs input-bordered mono w-56"
          placeholder="Search host / path / query…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className={selectClass} value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">source: any</option>
          {filters.sources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className={selectClass} value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="">method: any</option>
          {filters.methods.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <select className={selectClass} value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">host: any</option>
          {filters.hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">status: any</option>
          {filters.statuses.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className={selectClass} value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">role: any</option>
          {filters.roles.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <select className={selectClass} value={module} onChange={(e) => setModule(e.target.value)}>
          <option value="">module: any</option>
          {filters.modules.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        loading={loading}
        storageKey="flows"
        onRowClick={(r) => navigate(`/flows/${r.id}`)}
        emptyLabel="No flows captured yet."
      />

      <Modal open={!!assignFlow} onClose={() => setAssignFlow(null)} title="Assign flow to a role">
        {assignFlow && (
          <div className="flex flex-col gap-3">
            <div className="text-xs mono text-base-content/60">
              {assignFlow.method} {assignFlow.host}{assignFlow.path}
            </div>
            <label className="form-control">
              <span className="label-text text-xs">Role</span>
              <select className="select select-sm select-bordered" value={assignRoleId} onChange={(e) => setAssignRoleId(e.target.value)}>
                {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <div className="flex gap-2">
              <button
                className="btn btn-sm btn-primary"
                disabled={!assignRoleId}
                onClick={async () => {
                  await setLoginFlow.run(assignRoleId, assignFlow.id);
                  setAssignFlow(null);
                }}
              >
                Set as login flow
              </button>
              <button
                className="btn btn-sm"
                disabled={!assignRoleId}
                onClick={async () => {
                  await setControlFlow.run(assignRoleId, assignFlow.id);
                  setAssignFlow(null);
                }}
              >
                Set as control/validation flow
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
