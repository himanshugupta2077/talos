import { useEffect, useState } from "react";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { NoProjectNotice } from "../components/Common";
import { StepsResponse } from "../types";

interface Cell {
  role_id: string;
  role_name: string;
  module_id: string;
  module_name: string;
  client_allowed: string | null;
  server_expected: string | null;
}

const VALUES = ["ALLOW", "DENY", "UNKNOWN"];

function ValueBadge({ v }: { v: string | null }) {
  if (!v) return <span className="text-base-content/30">·</span>;
  const cls = v === "ALLOW" ? "badge-success" : v === "DENY" ? "badge-error" : "badge-ghost";
  return <span className={`badge badge-xs ${cls}`}>{v}</span>;
}

export default function Access() {
  const { selected } = useProject();
  const [cells, setCells] = useState<Cell[]>([]);
  const [report, setReport] = useState<StepsResponse | null>(null);

  const load = () =>
    selected && api.get<{ cells: Cell[] }>("/api/access/matrix", { project_id: selected.id }).then((r) => setCells(r.cells));

  useEffect(() => {
    load();
  }, [selected]);

  const setClient = useAction("Set client access", (role: string, module: string, value: string) =>
    api.post("/api/access/client", { role, module, value }, { project_id: selected!.id })
  );
  const setServer = useAction("Set server access", (role: string, module: string, value: string) =>
    api.post("/api/access/server", { role, module, value }, { project_id: selected!.id })
  );
  const coverage = useAction("Access coverage", () =>
    api.post("/api/access/coverage", {}, { project_id: selected!.id })
  );
  const signals = useAction("Access signals", () =>
    api.post("/api/access/signals", {}, { project_id: selected!.id })
  );

  if (!selected) return <NoProjectNotice />;

  const roles = [...new Map(cells.map((c) => [c.role_id, c.role_name])).entries()];
  const modules = [...new Map(cells.map((c) => [c.module_id, c.module_name])).entries()];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold">Access Model</h1>
        <div className="flex gap-2">
          <button
            className="btn btn-sm"
            disabled={coverage.running}
            onClick={async () => {
              const r = await coverage.run();
              setReport(r);
            }}
          >
            Coverage report
          </button>
          <button
            className="btn btn-sm"
            disabled={signals.running}
            onClick={async () => {
              const r = await signals.run();
              setReport(r);
            }}
          >
            BAC/IDOR signals
          </button>
        </div>
      </div>

      {roles.length === 0 || modules.length === 0 ? (
        <div className="panel p-8 text-center text-base-content/50">
          Create at least one role and one module first.
        </div>
      ) : (
        <div className="overflow-x-auto panel">
          <table className="table table-tight">
            <thead>
              <tr>
                <th>Role \ Module</th>
                {modules.map(([id, name]) => (
                  <th key={id}>{name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {roles.map(([roleId, roleName]) => (
                <tr key={roleId}>
                  <td className="font-medium">{roleName}</td>
                  {modules.map(([moduleId, moduleName]) => {
                    const cell = cells.find((c) => c.role_id === roleId && c.module_id === moduleId);
                    return (
                      <td key={moduleId}>
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] text-base-content/40 w-10">client</span>
                            <ValueBadge v={cell?.client_allowed || null} />
                            <select
                              className="select select-xs select-bordered ml-1"
                              value=""
                              onChange={async (e) => {
                                if (!e.target.value) return;
                                await setClient.run(roleName, moduleName, e.target.value);
                                await load();
                                e.target.value = "";
                              }}
                            >
                              <option value="">set…</option>
                              {VALUES.map((v) => (
                                <option key={v} value={v}>
                                  {v}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] text-base-content/40 w-10">server</span>
                            <ValueBadge v={cell?.server_expected || null} />
                            <select
                              className="select select-xs select-bordered ml-1"
                              value=""
                              onChange={async (e) => {
                                if (!e.target.value) return;
                                await setServer.run(roleName, moduleName, e.target.value);
                                await load();
                                e.target.value = "";
                              }}
                            >
                              <option value="">set…</option>
                              {VALUES.map((v) => (
                                <option key={v} value={v}>
                                  {v}
                                </option>
                              ))}
                            </select>
                          </div>
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {report && (
        <div className="panel p-4 mt-6 mono text-xs whitespace-pre-wrap">
          {report.steps.map((s, i) => (
            <pre key={i}>{s.stdout || s.stderr}</pre>
          ))}
        </div>
      )}
    </div>
  );
}
