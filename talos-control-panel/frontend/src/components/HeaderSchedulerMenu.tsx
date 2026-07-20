import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useCommandLog } from "../state/CommandLogContext";
import { useProject } from "../state/ProjectContext";
import { useStatus } from "../state/StatusContext";
import { StepsResponse } from "../types";
import HoverMenu from "./HoverMenu";

/** Status dot only — chip boundary matches Role/Module (border-base-300, both themes). */
function schedulerDotClass(label: string): string {
  if (label === "RUNNING") return "bg-success";
  if (label === "PAUSED" || label === "WAITING") return "bg-warning animate-pulse";
  return "bg-base-content/30";
}

const chipTriggerClass =
  "inline-flex items-center gap-1 h-6 px-2 rounded border border-base-300 bg-base-100 text-xs cursor-pointer select-none transition-colors hover:bg-base-200";

const chipIdleClass =
  "inline-flex items-center gap-1 h-6 px-2 rounded border border-base-300 bg-transparent text-xs text-base-content/50 select-none opacity-60 pointer-events-none";

function PlayIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M8 5.14v13.72a1 1 0 0 0 1.5.86l11-6.86a1 1 0 0 0 0-1.72l-11-6.86a1 1 0 0 0-1.5.86z" />
    </svg>
  );
}

function PauseIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <rect x="6" y="5" width="4" height="14" rx="1.2" />
      <rect x="14" y="5" width="4" height="14" rx="1.2" />
    </svg>
  );
}

/**
 * Header scheduler status chip with queue depth and pause/resume actions.
 * Reflects project DB execution state + active queue counts. Process
 * start/stop lives primarily on the Scheduler page; this menu surfaces
 * process alive/dead when the status payload includes `process`.
 */
export default function HeaderSchedulerMenu() {
  const { selected } = useProject();
  const {
    schedulerStatus,
    schedulerStateLabel,
    schedulerQueueCount,
    refreshStatus,
  } = useStatus();
  const { log } = useCommandLog();
  const [busy, setBusy] = useState(false);

  if (!selected) {
    return (
      <span className={chipIdleClass}>
        <span className="inline-block w-1.5 h-1.5 rounded-full shrink-0 bg-base-content/30" />
        <span className="font-normal shrink-0">Scheduler:</span>
        <span className="font-medium">—</span>
      </span>
    );
  }

  const stateRaw = (schedulerStatus?.state?.state || "").toLowerCase();
  const isRunning = stateRaw === "running";
  const counts = schedulerStatus?.counts || {};
  const processState = (schedulerStatus?.process?.state || "").toLowerCase();
  const processLive = processState === "running" || processState === "starting";
  const processLabel = processLive
    ? processState === "starting"
      ? "STARTING"
      : "LIVE"
    : "OFF";

  const runAction = async (label: string, request: () => Promise<StepsResponse>) => {
    if (busy) return;
    setBusy(true);
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
      setBusy(false);
    }
  };

  const canPause = !busy && isRunning;
  const canPlay = !busy && !isRunning;

  return (
    <HoverMenu
      align="end"
      trigger={
        <div
          tabIndex={0}
          role="button"
          className={`${chipTriggerClass} ${busy ? "opacity-70" : ""}`}
        >
          {busy ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${schedulerDotClass(
                schedulerStateLabel
              )}`}
            />
          )}
          <span className="text-base-content/50 font-normal shrink-0">Scheduler:</span>
          <span className="mono font-medium truncate">
            {schedulerStateLabel}
            <span className="text-base-content/50 font-normal"> · {schedulerQueueCount}</span>
          </span>
        </div>
      }
    >
      <div className="w-52 flex flex-col gap-2">
        <div className="flex items-center justify-between text-[10px] px-0.5 text-base-content/50">
          <span>
            Queue: <span className="font-medium text-base-content/80">{schedulerStateLabel}</span>
          </span>
          <span>
            Process:{" "}
            <span
              className={
                processLive
                  ? "font-medium text-success"
                  : "font-medium text-base-content/60"
              }
            >
              {processLabel}
              {processLive && schedulerStatus?.process?.pid != null
                ? ` · ${schedulerStatus.process.pid}`
                : ""}
            </span>
          </span>
        </div>
        {/* Media transport controls (queue pause/resume — start/stop on page) */}
        <div className="flex items-center justify-center gap-3 py-2">
          <button
            type="button"
            role="menuitem"
            disabled={!canPause}
            aria-label="Pause scheduler"
            className={[
              "h-10 w-10 rounded-full flex items-center justify-center transition-all",
              "border border-base-300",
              canPause
                ? "bg-base-200 text-base-content hover:bg-warning/20 hover:border-warning/50 hover:text-warning hover:scale-105 active:scale-95"
                : "bg-base-200/40 text-base-content/30 cursor-not-allowed",
            ].join(" ")}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              if (!canPause) return;
              void runAction("Pause scheduler", () =>
                api.post("/api/scheduler/pause", {}, { project_id: selected.id })
              );
            }}
          >
            <PauseIcon className="h-4 w-4" />
          </button>

          <button
            type="button"
            role="menuitem"
            disabled={!canPlay}
            aria-label="Resume scheduler"
            className={[
              "h-11 w-11 rounded-full flex items-center justify-center transition-all",
              "border",
              canPlay
                ? "bg-success/15 border-success/40 text-success hover:bg-success/25 hover:border-success/60 hover:scale-105 active:scale-95 shadow-sm shadow-success/10"
                : "bg-base-200/40 border-base-300 text-base-content/30 cursor-not-allowed",
            ].join(" ")}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              if (!canPlay) return;
              void runAction("Resume scheduler", () =>
                api.post("/api/scheduler/resume", {}, { project_id: selected.id })
              );
            }}
          >
            <PlayIcon className="h-5 w-5 ml-0.5" />
          </button>
        </div>

        {/* Compact queue strip */}
        <div className="grid grid-cols-3 gap-1 text-[10px]">
          {(["pending", "running", "paused", "done", "failed", "cancelled"] as const).map(
            (key) => (
              <div
                key={key}
                className="rounded bg-base-200/80 px-1.5 py-1 flex flex-col min-w-0"
              >
                <span className="text-base-content/50 capitalize truncate">{key}</span>
                <span className="font-medium mono text-xs">{counts[key] ?? 0}</span>
              </div>
            )
          )}
        </div>

        <div className="border-t border-base-300 pt-1">
          <Link
            to="/scheduler"
            className="btn btn-ghost btn-xs w-full justify-start"
            role="menuitem"
          >
            Open Scheduler page →
          </Link>
        </div>
      </div>
    </HoverMenu>
  );
}
