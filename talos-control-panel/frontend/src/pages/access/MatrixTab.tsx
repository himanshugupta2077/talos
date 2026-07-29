/**
 * Interactive access matrix — proper client/server columns, click-to-cycle values.
 */

import { type MouseEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import type {
  AccessBulkOp,
  AccessBulkResponse,
  AccessCell,
  AccessValue,
  StepsResponse,
} from "../../types";
import BulkBar from "./BulkBar";
import {
  bacReadyModuleIds,
  cellKey,
  cellMatchesFilter,
  displayValue,
  GLOBAL_NAME,
  isSet,
  MatrixFilter,
  nextAccessValue,
  prevAccessValue,
  uniqueModules,
  uniqueRoles,
  valueBadgeClass,
} from "./shared";

type LayerKind = "client" | "server";

export default function MatrixTab({
  projectId,
  cells,
  onReload,
  jumpFilter = null,
  onJumpFilterConsumed,
}: {
  projectId: string;
  cells: AccessCell[];
  onReload: () => Promise<void> | void;
  jumpFilter?: MatrixFilter | null;
  onJumpFilterConsumed?: () => void;
}) {
  const [filter, setFilter] = useState<MatrixFilter>("all");
  const [hideGlobal, setHideGlobal] = useState(true);
  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  /** Keys currently saving (roleId::moduleId::layer). */
  const [pending, setPending] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (jumpFilter && jumpFilter !== "all") {
      setFilter(jumpFilter);
      onJumpFilterConsumed?.();
    }
  }, [jumpFilter, onJumpFilterConsumed]);

  const bacModules = useMemo(() => bacReadyModuleIds(cells), [cells]);

  const roles = useMemo(() => {
    let list = uniqueRoles(cells);
    if (hideGlobal) list = list.filter((r) => r.name !== GLOBAL_NAME);
    return list;
  }, [cells, hideGlobal]);

  const modules = useMemo(() => {
    let list = uniqueModules(cells);
    if (hideGlobal) list = list.filter((m) => m.name !== GLOBAL_NAME);
    return list;
  }, [cells, hideGlobal]);

  const cellMap = useMemo(() => {
    const m = new Map<string, AccessCell>();
    for (const c of cells) m.set(cellKey(c.role_id, c.module_id), c);
    return m;
  }, [cells]);

  const filteredKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const c of cells) {
      if (
        hideGlobal &&
        (c.role_name === GLOBAL_NAME || c.module_name === GLOBAL_NAME)
      ) {
        continue;
      }
      if (cellMatchesFilter(c, filter, bacModules)) {
        keys.add(cellKey(c.role_id, c.module_id));
      }
    }
    return keys;
  }, [cells, filter, bacModules, hideGlobal]);

  const setClient = useAction(
    "Set client access",
    (role: string, module: string, value: string) =>
      api.post(
        "/api/access/client",
        { role, module, value },
        { project_id: projectId }
      )
  );
  const setServer = useAction(
    "Set server access",
    (role: string, module: string, value: string) =>
      api.post(
        "/api/access/server",
        { role, module, value },
        { project_id: projectId }
      )
  );
  const unsetClient = useAction(
    "Unset client access",
    (role: string, module: string) =>
      api.post(
        "/api/access/client/unset",
        { role, module },
        { project_id: projectId }
      )
  );
  const unsetServer = useAction(
    "Unset server access",
    (role: string, module: string) =>
      api.post(
        "/api/access/server/unset",
        { role, module },
        { project_id: projectId }
      )
  );
  const bulk = useAction(
    "Bulk access update",
    (operations: AccessBulkOp[]) =>
      api.post<AccessBulkResponse>(
        "/api/access/bulk",
        { operations },
        { project_id: projectId }
      ) as Promise<StepsResponse>
  );

  const busy = bulk.running;

  const afterMutate = useCallback(async () => {
    await onReload();
  }, [onReload]);

  const markPending = (key: string, on: boolean) => {
    setPending((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  const cycleLayer = async (
    cell: AccessCell,
    layer: LayerKind,
    reverse: boolean
  ) => {
    const current =
      layer === "client" ? cell.client_allowed : cell.server_expected;
    const next = reverse ? prevAccessValue(current) : nextAccessValue(current);
    const pendKey = `${cellKey(cell.role_id, cell.module_id)}::${layer}`;
    if (pending.has(pendKey)) return;

    markPending(pendKey, true);
    try {
      if (layer === "client") {
        if (next == null) {
          await unsetClient.run(cell.role_name, cell.module_name);
        } else {
          await setClient.run(cell.role_name, cell.module_name, next);
        }
      } else {
        if (next == null) {
          await unsetServer.run(cell.role_name, cell.module_name);
        } else {
          await setServer.run(cell.role_name, cell.module_name, next);
        }
      }
      await afterMutate();
    } catch {
      /* logged by useAction */
    } finally {
      markPending(pendKey, false);
    }
  };

  const onValueClick = (
    e: MouseEvent,
    cell: AccessCell,
    layer: LayerKind
  ) => {
    e.stopPropagation();
    if (selectMode || e.metaKey || e.ctrlKey) {
      const key = cellKey(cell.role_id, cell.module_id);
      setSelectMode(true);
      setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(key)) next.delete(key);
        else next.add(key);
        return next;
      });
      return;
    }
    void cycleLayer(cell, layer, e.shiftKey);
  };

  const selectRole = (roleId: string) => {
    setSelectMode(true);
    setSelected((prev) => {
      const next = new Set(prev);
      for (const m of modules) {
        const k = cellKey(roleId, m.id);
        if (filteredKeys.has(k)) next.add(k);
      }
      return next;
    });
  };

  const selectModule = (moduleId: string) => {
    setSelectMode(true);
    setSelected((prev) => {
      const next = new Set(prev);
      for (const r of roles) {
        const k = cellKey(r.id, moduleId);
        if (filteredKeys.has(k)) next.add(k);
      }
      return next;
    });
  };

  const selectedCells = useMemo(() => {
    return [...selected]
      .map((k) => cellMap.get(k))
      .filter((c): c is AccessCell => !!c);
  }, [selected, cellMap]);

  const runBulk = async (operations: AccessBulkOp[]) => {
    if (!operations.length) return;
    try {
      await bulk.run(operations);
      setSelected(new Set());
      setSelectMode(false);
      await afterMutate();
    } catch {
      /* logged */
    }
  };

  if (roles.length === 0 || modules.length === 0) {
    return (
      <div className="panel p-8 text-center text-sm text-base-content/60 space-y-3">
        <p>
          {hideGlobal
            ? "No non-global roles or modules to show. Create identities and feature areas first, or show global."
            : "Create at least one role and one module first."}
        </p>
        <div className="flex justify-center gap-2">
          <Link to="/roles-modules" className="btn btn-sm btn-primary">
            Roles &amp; Modules
          </Link>
          {hideGlobal && (
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => setHideGlobal(false)}
            >
              Show global
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3 pb-16">
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="select select-xs select-bordered"
          value={filter}
          onChange={(e) => setFilter(e.target.value as MatrixFilter)}
        >
          <option value="all">Filter: all cells</option>
          <option value="unset">Unset (either layer)</option>
          <option value="mismatch">Client ≠ server</option>
          <option value="client_deny">Client DENY</option>
          <option value="server_deny">Server DENY</option>
          <option value="bac_ready">BAC-ready modules</option>
          <option value="has_traffic">Has traffic</option>
        </select>

        <label className="label cursor-pointer gap-1.5 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hideGlobal}
            onChange={(e) => setHideGlobal(e.target.checked)}
          />
          <span className="label-text text-xs">Hide global</span>
        </label>

        <label className="label cursor-pointer gap-1.5 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={selectMode}
            onChange={(e) => {
              setSelectMode(e.target.checked);
              if (!e.target.checked) setSelected(new Set());
            }}
          />
          <span className="label-text text-xs">Multi-select</span>
        </label>

        {selectMode && selected.size > 0 && (
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        )}

        <span className="text-[11px] text-base-content/40 ml-auto">
          Click Client / Server to cycle: — → ALLOW → DENY → UNKNOWN → —
          {" · "}
          Shift+click reverse · Ctrl/Cmd+click select
        </span>
      </div>

      <div className="flex flex-wrap gap-3 text-[11px] text-base-content/50">
        <span>
          <span className={`badge badge-sm ${valueBadgeClass("ALLOW")}`}>
            ALLOW
          </span>
        </span>
        <span>
          <span className={`badge badge-sm ${valueBadgeClass("DENY")}`}>
            DENY
          </span>
        </span>
        <span>
          <span className={`badge badge-sm ${valueBadgeClass("UNKNOWN")}`}>
            UNKNOWN
          </span>
        </span>
        <span>
          <span className={`badge badge-sm ${valueBadgeClass(null)}`}>—</span>{" "}
          unset
        </span>
        {bacModules.size > 0 && (
          <span className="text-warning">
            Modules with BAC surface highlighted
          </span>
        )}
      </div>

      <div className="panel overflow-auto max-h-[min(70vh,720px)]">
        <table className="table table-sm table-pin-rows table-pin-cols w-max min-w-full">
          <thead>
            <tr>
              <th className="bg-base-200 z-20 min-w-[8rem] sticky left-0">
                Role \ Module
              </th>
              {modules.map((m) => (
                <th
                  key={m.id}
                  className={`bg-base-200 text-center min-w-[9.5rem] cursor-pointer hover:bg-base-300 ${
                    bacModules.has(m.id)
                      ? "ring-1 ring-inset ring-warning/40"
                      : ""
                  }`}
                  title={
                    bacModules.has(m.id)
                      ? `${m.name} — BAC surface (click to select column)`
                      : `Select column: ${m.name}`
                  }
                  onClick={() => selectModule(m.id)}
                >
                  <span className="text-xs font-semibold">{m.name}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id}>
                <th
                  className="bg-base-200 font-medium text-sm cursor-pointer hover:bg-base-300 whitespace-nowrap sticky left-0 z-10"
                  title={`Select row: ${r.name}`}
                  onClick={() => selectRole(r.id)}
                >
                  {r.name}
                </th>
                {modules.map((m) => {
                  const key = cellKey(r.id, m.id);
                  const cell = cellMap.get(key);
                  const dimmed = filter !== "all" && !filteredKeys.has(key);
                  const isSelected = selected.has(key);
                  const cPend = pending.has(`${key}::client`);
                  const sPend = pending.has(`${key}::server`);

                  return (
                    <td
                      key={m.id}
                      className={`p-2 align-middle transition-colors ${
                        isSelected
                          ? "bg-primary/10 ring-1 ring-inset ring-primary/30"
                          : dimmed
                            ? "opacity-30"
                            : ""
                      }`}
                      onClick={(e) => {
                        if (!selectMode && !e.metaKey && !e.ctrlKey) return;
                        e.preventDefault();
                        setSelectMode(true);
                        setSelected((prev) => {
                          const next = new Set(prev);
                          if (next.has(key)) next.delete(key);
                          else next.add(key);
                          return next;
                        });
                      }}
                    >
                      {cell ? (
                        <div className="flex flex-col gap-1 min-w-[8.5rem]">
                          <ValueChip
                            label="Client"
                            value={cell.client_allowed}
                            pending={cPend}
                            onClick={(e) => onValueClick(e, cell, "client")}
                          />
                          <ValueChip
                            label="Server"
                            value={cell.server_expected}
                            pending={sPend}
                            onClick={(e) => onValueClick(e, cell, "server")}
                          />
                          {(cell.flow_count ?? 0) > 0 && (
                            <span
                              className="text-[10px] tabular-nums text-base-content/40 pl-0.5"
                              title={`${cell.flow_count} flow(s), ${cell.endpoint_count ?? 0} endpoint(s)`}
                            >
                              {cell.flow_count} flows
                              {(cell.endpoint_count ?? 0) > 0
                                ? ` · ${cell.endpoint_count} ep`
                                : ""}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-base-content/20">—</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <BulkBar
        count={selected.size}
        busy={busy}
        onClearSelection={() => {
          setSelected(new Set());
          setSelectMode(false);
        }}
        onApplyClient={(v: AccessValue) =>
          runBulk(
            selectedCells.map((c) => ({
              op: "client_set",
              role: c.role_name,
              module: c.module_name,
              value: v,
            }))
          )
        }
        onApplyServer={(v: AccessValue) =>
          runBulk(
            selectedCells.map((c) => ({
              op: "server_set",
              role: c.role_name,
              module: c.module_name,
              value: v,
            }))
          )
        }
        onApplyBoth={(v: AccessValue) =>
          runBulk(
            selectedCells.flatMap((c) => [
              {
                op: "client_set" as const,
                role: c.role_name,
                module: c.module_name,
                value: v,
              },
              {
                op: "server_set" as const,
                role: c.role_name,
                module: c.module_name,
                value: v,
              },
            ])
          )
        }
        onUnsetClient={() =>
          runBulk(
            selectedCells.map((c) => ({
              op: "client_unset",
              role: c.role_name,
              module: c.module_name,
            }))
          )
        }
        onUnsetServer={() =>
          runBulk(
            selectedCells.map((c) => ({
              op: "server_unset",
              role: c.role_name,
              module: c.module_name,
            }))
          )
        }
        onMirrorClientToServer={() => {
          const ops: AccessBulkOp[] = [];
          for (const c of selectedCells) {
            if (isSet(c.client_allowed)) {
              ops.push({
                op: "server_set",
                role: c.role_name,
                module: c.module_name,
                value: c.client_allowed!,
              });
            }
          }
          runBulk(ops);
        }}
        onDelete={() => {
          if (
            !window.confirm(
              `Delete access mappings for ${selectedCells.length} cell(s)?`
            )
          ) {
            return;
          }
          runBulk(
            selectedCells.map((c) => ({
              op: "delete",
              role: c.role_name,
              module: c.module_name,
            }))
          );
        }}
      />
    </div>
  );
}

function ValueChip({
  label,
  value,
  pending,
  onClick,
}: {
  label: string;
  value: string | null;
  pending: boolean;
  onClick: (e: MouseEvent) => void;
}) {
  const shown = displayValue(value);
  return (
    <button
      type="button"
      className={`btn btn-xs h-auto min-h-0 py-1 px-2 justify-between gap-2 w-full font-normal normal-case border border-base-300 bg-base-100 hover:border-primary/50 ${
        pending ? "opacity-60 pointer-events-none" : ""
      }`}
      title={`${label}: ${shown} — click to cycle, Shift+click reverse`}
      disabled={pending}
      onClick={onClick}
    >
      <span className="text-[10px] uppercase tracking-wide text-base-content/45 shrink-0">
        {label}
      </span>
      {pending ? (
        <span className="loading loading-spinner loading-xs" />
      ) : (
        <span className={`badge badge-sm ${valueBadgeClass(value)}`}>
          {shown}
        </span>
      )}
    </button>
  );
}
