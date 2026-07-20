import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useCommandLog } from "../state/CommandLogContext";
import { useProject } from "../state/ProjectContext";
import { useStatus } from "../state/StatusContext";
import { Module, Role, StepsResponse } from "../types";
import HoverMenu from "./HoverMenu";

/**
 * Header active role + module chip with a combined hover menu.
 * Top action resets both; Role and Module switch lists stay as separate sections below.
 */
export default function HeaderRoleModule() {
  const { selected } = useProject();
  const { roles, modules, activeRole, activeModule, refreshStatus } = useStatus();
  const { log } = useCommandLog();
  const [busy, setBusy] = useState<"role" | "module" | "both" | null>(null);

  if (!selected) {
    return (
      <span className="badge badge-ghost badge-sm text-base-content/50">
        Role / Module: —
      </span>
    );
  }

  const runScoped = async (
    kind: "role" | "module" | "both",
    label: string,
    request: () => Promise<StepsResponse>
  ) => {
    if (busy) return;
    setBusy(kind);
    try {
      const result = await request();
      log(label, result.steps || []);
      await refreshStatus();
    } catch (err: any) {
      log(label, [
        {
          cmd: [],
          cmd_str: label,
          stdout: "",
          stderr: err?.message || String(err),
          exit_code: 1,
          duration_ms: 0,
          ok: false,
        },
      ]);
      await refreshStatus();
    } finally {
      setBusy(null);
    }
  };

  const setRole = (name: string) =>
    runScoped("role", `Use role for capture: ${name}`, () =>
      api.post("/api/roles/set", { name }, { project_id: selected.id })
    );

  const unsetRole = () =>
    runScoped("role", "Reset role to global", () =>
      api.post("/api/roles/unset", {}, { project_id: selected.id })
    );

  const setModule = (name: string) =>
    runScoped("module", `Use module for capture: ${name}`, () =>
      api.post("/api/modules/set", { name }, { project_id: selected.id })
    );

  const unsetModule = () =>
    runScoped("module", "Reset module to global", () =>
      api.post("/api/modules/unset", {}, { project_id: selected.id })
    );

  /** Reset role and module to global in one action (sequential API calls, one log entry). */
  const unsetBoth = async () => {
    if (busy) return;
    setBusy("both");
    const label = "Reset role & module to global";
    try {
      const roleResult = await api.post(
        "/api/roles/unset",
        {},
        { project_id: selected.id }
      );
      const moduleResult = await api.post(
        "/api/modules/unset",
        {},
        { project_id: selected.id }
      );
      const steps = [
        ...(roleResult.steps || []),
        ...(moduleResult.steps || []),
      ];
      log(label, steps);
      await refreshStatus();
    } catch (err: any) {
      log(label, [
        {
          cmd: [],
          cmd_str: label,
          stdout: "",
          stderr: err?.message || String(err),
          exit_code: 1,
          duration_ms: 0,
          ok: false,
        },
      ]);
      await refreshStatus();
    } finally {
      setBusy(null);
    }
  };

  const roleName = activeRole?.name;
  const moduleName = activeModule?.name;
  const roleIsGlobal = !roleName || roleName === "global";
  const moduleIsGlobal = !moduleName || moduleName === "global";
  const bothGlobal = roleIsGlobal && moduleIsGlobal;
  const anyScoped = !roleIsGlobal || !moduleIsGlobal;

  return (
    <HoverMenu
      align="start"
      trigger={
        <div
          tabIndex={0}
          role="button"
          className={`inline-flex items-center gap-1.5 h-6 px-2 max-w-[18rem] rounded border text-xs cursor-pointer select-none transition-colors ${
            anyScoped
              ? "border-base-300 bg-base-100 hover:bg-base-200"
              : "border-base-300 bg-transparent hover:bg-base-300/50"
          } ${busy ? "opacity-70" : ""}`}
        >
          {busy ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${
                anyScoped ? "bg-success" : "bg-base-content/30"
              }`}
            />
          )}
          <span className="text-base-content/50 font-normal shrink-0">Role:</span>
          <span className="truncate font-medium">
            {roleName ? displayName(roleName) : "—"}
          </span>
          <span className="text-base-content/25 select-none" aria-hidden>
            ·
          </span>
          <span className="text-base-content/50 font-normal shrink-0">Module:</span>
          <span className="truncate font-medium">
            {moduleName ? displayName(moduleName) : "—"}
          </span>
        </div>
      }
    >
      <div className="w-56">
        {/* Combined reset */}
        <div className="border-b border-base-300 pb-1 mb-0.5">
          <button
            type="button"
            className="btn btn-ghost btn-xs text-error w-full justify-start"
            disabled={!!busy || bothGlobal}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              if (busy || bothGlobal) return;
              void unsetBoth();
            }}
          >
            Reset both
          </button>
        </div>

        {/* Role section */}
        <ContextSection
          heading="Switch Role"
          items={roles}
          busy={busy === "role" || busy === "both"}
          emptyHint="No roles yet — create one on Roles & Modules"
          onSelect={(name) => void setRole(name)}
          onClear={() => void unsetRole()}
          clearDisabled={roleIsGlobal}
        />

        {/* Module section */}
        <ContextSection
          heading="Switch Module"
          items={modules}
          busy={busy === "module" || busy === "both"}
          emptyHint="No modules yet — create one on Roles & Modules"
          onSelect={(name) => void setModule(name)}
          onClear={() => void unsetModule()}
          clearDisabled={moduleIsGlobal}
        />

        {/* Footer */}
        <div className="border-t border-base-300 mt-1 pt-1">
          <Link
            to="/roles-modules"
            className="btn btn-ghost btn-xs w-full justify-start"
            role="menuitem"
          >
            Manage more
          </Link>
        </div>
      </div>
    </HoverMenu>
  );
}

function displayName(name: string): string {
  return name === "global" ? "Global" : name;
}

function ContextSection({
  heading,
  items,
  busy,
  emptyHint,
  onSelect,
  onClear,
  clearDisabled,
}: {
  heading: string;
  items: Array<Role | Module>;
  busy: boolean;
  emptyHint: string;
  onSelect: (name: string) => void;
  onClear: () => void;
  clearDisabled: boolean;
}) {
  return (
    <div className="border-b border-base-300 last:border-b-0 py-1">
      <div className="flex items-center justify-between gap-1 px-2 pt-1 pb-0.5">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-base-content/40">
          {heading}
        </span>
        <button
          type="button"
          className="btn btn-ghost btn-xs text-error h-5 min-h-0 px-1.5"
          disabled={busy || clearDisabled}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            if (busy || clearDisabled) return;
            onClear();
          }}
        >
          Reset
        </button>
      </div>

      <ul className="menu menu-sm p-0 max-h-40 overflow-y-auto">
        {items.length === 0 && (
          <li className="disabled">
            <span className="text-base-content/50 text-xs whitespace-normal">
              {emptyHint}
            </span>
          </li>
        )}
        {items.map((item) => {
          const isActive = !!item.is_active;
          return (
            <li key={item.id}>
              <button
                type="button"
                role="menuitem"
                className={isActive ? "active" : ""}
                disabled={busy || isActive}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (busy || isActive) return;
                  onSelect(item.name);
                }}
              >
                <span className="truncate">{displayName(item.name)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
