import type { Module, Role } from "../../../../types";
import {
  inputClass,
  selectClass,
  type BacScopeMode,
} from "../shared";

/**
 * Role + execution scope controls mapped to CLI --role / --module / --endpoint.
 */
export default function ScopeControls({
  roles,
  modules,
  role,
  scopeMode,
  moduleName,
  endpointId,
  autoGenerate,
  onRole,
  onScopeMode,
  onModule,
  onEndpoint,
  onAutoGenerate,
  disabled,
}: {
  roles: Role[];
  modules: Module[];
  role: string;
  scopeMode: BacScopeMode;
  moduleName: string;
  endpointId: string;
  autoGenerate: boolean;
  onRole: (v: string) => void;
  onScopeMode: (m: BacScopeMode) => void;
  onModule: (v: string) => void;
  onEndpoint: (v: string) => void;
  onAutoGenerate: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 items-end">
        <label className="form-control">
          <span className="label-text text-xs">Attacker role</span>
          <select
            className={`${selectClass} min-w-[10rem]`}
            value={role}
            disabled={disabled}
            onChange={(e) => onRole(e.target.value)}
          >
            <option value="">all roles (default)</option>
            {roles.map((r) => (
              <option key={r.id} value={r.name}>
                {r.name}
              </option>
            ))}
          </select>
        </label>

        <div className="form-control">
          <span className="label-text text-xs mb-1">Execution scope</span>
          <div className="join">
            {(
              [
                ["project", "Project"],
                ["module", "Module"],
                ["endpoint", "Endpoint"],
              ] as const
            ).map(([mode, label]) => (
              <button
                key={mode}
                type="button"
                disabled={disabled}
                className={`btn btn-xs join-item ${
                  scopeMode === mode ? "btn-primary" : "btn-ghost"
                }`}
                onClick={() => onScopeMode(mode)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {scopeMode === "module" && (
          <label className="form-control">
            <span className="label-text text-xs">Module</span>
            <select
              className={`${selectClass} min-w-[10rem]`}
              value={moduleName}
              disabled={disabled}
              onChange={(e) => onModule(e.target.value)}
            >
              <option value="">select module…</option>
              {modules.map((m) => (
                <option key={m.id} value={m.name}>
                  {m.name}
                </option>
              ))}
            </select>
          </label>
        )}

        {scopeMode === "endpoint" && (
          <label className="form-control">
            <span className="label-text text-xs">Endpoint UUID</span>
            <input
              className={`${inputClass} w-64 mono`}
              value={endpointId}
              disabled={disabled}
              placeholder="endpoint UUID"
              onChange={(e) => onEndpoint(e.target.value.trim())}
            />
          </label>
        )}

        <label className="label cursor-pointer gap-2 items-center pb-1">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={autoGenerate}
            disabled={disabled}
            onChange={(e) => onAutoGenerate(e.target.checked)}
          />
          <span className="label-text text-xs">
            --auto-generate{" "}
            <span className="text-base-content/40">
              (login replay for missing tokens)
            </span>
          </span>
        </label>
      </div>

      <p className="text-[10px] text-base-content/40 leading-snug max-w-2xl">
        Scope is mutually exclusive: project (default),{" "}
        <span className="mono">--module</span>, or{" "}
        <span className="mono">--endpoint</span>. Role restricts the attacker
        side of the access matrix only.
      </p>
    </div>
  );
}
