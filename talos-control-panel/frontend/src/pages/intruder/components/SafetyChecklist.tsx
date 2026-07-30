import { CONFIRM_THRESHOLD } from "../shared";
import type { IntruderConfig } from "../types";

export interface SafetyState {
  logoutBlocked: boolean;
  dangerous: boolean;
  estimate: number | null;
  storageAllFlows: boolean;
  authMutable: boolean;
  dirty: boolean;
}

export default function SafetyChecklist({
  config,
  estimate,
  dirty,
}: {
  config: IntruderConfig;
  estimate: number | null;
  dirty: boolean;
}) {
  const safety = config.safety || {};
  const storage = (config.storage?.mode || "metrics_only") as string;
  const authMutable = safety.skip_auth_artifacts !== true;
  const items: { ok: boolean | "warn" | "block"; label: string }[] = [
    {
      ok: !dirty,
      label: dirty
        ? "Unsaved configuration — Save on Configure before Validate/Run"
        : "Configuration saved",
    },
    {
      ok: true,
      label: `Scope: require_in_scope = ${safety.require_in_scope !== false ? "true" : "false"}`,
    },
    {
      ok: "block",
      label: "Logout endpoints: hard-blocked (respect_logout cannot be disabled in UI)",
    },
    {
      ok: authMutable ? "warn" : true,
      label: authMutable
        ? "Auth headers/cookies can be mutated (unlike IV)"
        : "Auth artifacts skipped (skip_auth_artifacts)",
    },
    {
      ok: storage === "all_flows" ? "warn" : true,
      label: `Storage: ${storage}`,
    },
    {
      ok:
        estimate != null && estimate > CONFIRM_THRESHOLD
          ? "warn"
          : estimate == null
            ? "warn"
            : true,
      label:
        estimate == null
          ? "Estimate: unknown — Validate first"
          : `Estimate: ${estimate.toLocaleString()} attempts`,
    },
  ];

  return (
    <div className="rounded-md border border-base-300 p-3 space-y-1.5">
      <div className="text-sm font-medium mb-1">Pre-flight checklist</div>
      <ul className="space-y-1 text-xs">
        {items.map((it, i) => (
          <li key={i} className="flex items-start gap-2">
            <span
              className={
                it.ok === true
                  ? "text-success"
                  : it.ok === "block"
                    ? "text-error"
                    : it.ok === false
                      ? "text-error"
                      : "text-warning"
              }
            >
              {it.ok === true ? "✓" : it.ok === "block" || it.ok === false ? "!" : "⚠"}
            </span>
            <span className="text-base-content/80">{it.label}</span>
          </li>
        ))}
      </ul>
      <div className="text-[11px] text-base-content/50 pt-1 border-t border-base-300 mt-2">
        Global Scheduler Pause/Resume does <strong>not</strong> resume Intruder
        sessions. After a global pause, open each paused session and click{" "}
        <strong>Resume</strong> here.
      </div>
    </div>
  );
}
