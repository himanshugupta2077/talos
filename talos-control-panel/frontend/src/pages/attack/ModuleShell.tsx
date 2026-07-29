import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ModuleHelp } from "../../components/Common";
import {
  AttackModuleDef,
  classBadgeClass,
  riskBadgeClass,
} from "./registry";

/**
 * Shared chrome for every Testing module workspace.
 * Keeps navigation and risk/class cues consistent as modules grow.
 */
export default function ModuleShell({
  module,
  helpTitle,
  help,
  actions,
  children,
}: {
  module: AttackModuleDef;
  helpTitle?: string;
  help?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="mb-1">
        <Link to="/testing" className="link link-hover text-xs text-base-content/50">
          ← All modules
        </Link>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <h1 className="text-xl font-semibold">{module.name}</h1>
            <span className={`badge badge-sm ${classBadgeClass(module.class)}`}>
              {module.class === "passive" ? "Passive" : "Active"}
            </span>
            {module.risk !== "none" && (
              <span className={`badge badge-sm ${riskBadgeClass(module.risk)}`}>
                risk: {module.risk}
              </span>
            )}
            {module.risk === "none" && module.class === "passive" && (
              <span className="badge badge-sm badge-ghost">no outbound</span>
            )}
          </div>
          <p className="text-sm text-base-content/60 max-w-2xl">{module.description}</p>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          {actions}
          {help && (
            <ModuleHelp title={helpTitle || `How ${module.name} works`}>{help}</ModuleHelp>
          )}
        </div>
      </div>

      {children}
    </div>
  );
}
