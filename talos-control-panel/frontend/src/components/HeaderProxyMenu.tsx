import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useCommandLog } from "../state/CommandLogContext";
import { useStatus } from "../state/StatusContext";
import { StepsResponse } from "../types";
import HoverMenu from "./HoverMenu";

/** Status dot only — chip boundary matches Role/Module (border-base-300, both themes). */
function proxyDotClass(
  state: string,
  running: boolean,
  transitional: boolean,
  failed: boolean
): string {
  if (failed) return "bg-error";
  if (transitional) return "bg-warning animate-pulse";
  if (running || state === "running") return "bg-success";
  return "bg-error";
}

const chipTriggerClass =
  "inline-flex items-center gap-1 h-6 px-2 rounded border border-base-300 bg-base-100 text-xs cursor-pointer select-none transition-colors hover:bg-base-200";

type ActionKey = "start" | "stop" | "restart" | "kill" | "forceKill";

function actionAvailability(status: {
  state: string;
  running: boolean;
  transitional: boolean;
  busy: boolean;
}): Record<ActionKey, { enabled: boolean; reason?: string }> {
  const state = (status.state || "stopped").toLowerCase();
  const { running, transitional, busy } = status;

  if (busy) {
    const reason = "Action in progress…";
    return {
      start: { enabled: false, reason },
      stop: { enabled: false, reason },
      restart: { enabled: false, reason },
      kill: { enabled: false, reason },
      forceKill: { enabled: false, reason },
    };
  }

  // Start only from a fully idle stopped/failed surface.
  const canStart = !running && !transitional && (state === "stopped" || state === "");
  // Stop when something is live or mid-transition (except already stopping — still allow kill).
  const canStop = running || state === "starting" || state === "running";
  // Restart only when stably running (not mid start/stop).
  const canRestart = running && !transitional && state === "running";
  // Kill is recovery: always useful when not mid-kill busy; prefer when stuck/failed/running.
  const canKill = true;
  const canForce = true;

  return {
    start: {
      enabled: canStart,
      reason: canStart
        ? undefined
        : running
          ? "Already running"
          : transitional
            ? `Busy (${state})`
            : "Unavailable",
    },
    stop: {
      enabled: canStop,
      reason: canStop
        ? undefined
        : state === "stopping" || state === "draining"
          ? "Already stopping"
          : "Not running",
    },
    restart: {
      enabled: canRestart,
      reason: canRestart
        ? undefined
        : transitional
          ? `Busy (${state})`
          : running
            ? "Unavailable"
            : "Not running",
    },
    kill: {
      enabled: canKill,
      reason: undefined,
    },
    forceKill: {
      enabled: canForce,
      reason: undefined,
    },
  };
}

function ActionBox({
  label,
  enabled,
  danger,
  onClick,
}: {
  label: string;
  enabled: boolean;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={!enabled}
      className={[
        "rounded-md border px-2 py-1.5 text-xs font-medium transition-colors",
        "flex items-center justify-center min-h-[2rem]",
        danger
          ? enabled
            ? "border-error/40 bg-error/10 text-error hover:bg-error/20 hover:border-error/60"
            : "border-error/20 bg-error/5 text-error/40"
          : enabled
            ? "border-base-300 bg-base-200/60 text-base-content hover:bg-base-200 hover:border-base-content/20"
            : "border-base-300/60 bg-base-200/30 text-base-content/40",
        !enabled ? "cursor-not-allowed opacity-60" : "cursor-pointer",
      ].join(" ")}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!enabled) return;
        onClick();
      }}
    >
      {label}
    </button>
  );
}

/**
 * Header proxy status pill with hover menu for lifecycle actions.
 * Invokes Talos core via Control Panel API; never invents restart policy.
 */
export default function HeaderProxyMenu() {
  const { proxyStatus, proxyRunning, proxyStateLabel, refreshStatus } = useStatus();
  const { log } = useCommandLog();
  const [busy, setBusy] = useState(false);

  const proxyFailed = proxyStatus.state === "stopped" && !!proxyStatus.last_error;
  // restart_pending is a Talos-owned transition even while state is still "running".
  const proxyTransitional = !!proxyStatus.transitional || !!proxyStatus.restart_pending;
  const port = proxyStatus.listen_port ?? 8080;
  const host = proxyStatus.listen_host ?? "127.0.0.1";
  const actions = actionAvailability({
    state: proxyStatus.state,
    running: proxyRunning,
    transitional: proxyTransitional,
    busy,
  });

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

  const kill = (force: boolean) => {
    const target = `${host}:${port}`;
    if (force) {
      const ok = window.confirm(
        `Force-kill any process on ${target}?\n\nThis will kill non-mitmdump listeners too.`
      );
      if (!ok) return;
    }
    void runAction(force ? "Force kill proxy port" : "Kill proxy / free port", () =>
      api.post("/api/proxy/kill", {
        listen_host: host,
        port,
        force,
      })
    );
  };

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
              className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${proxyDotClass(
                proxyStatus.state,
                proxyRunning,
                proxyTransitional,
                proxyFailed
              )}`}
            />
          )}
          <span className="text-base-content/50 font-normal shrink-0">Proxy:</span>
          <span className="mono font-medium truncate">{proxyStateLabel}</span>
        </div>
      }
    >
      <div className="w-52 flex flex-col gap-1.5">
        {/* Start | Stop */}
        <div className="grid grid-cols-2 gap-1.5">
          <ActionBox
            label="Start"
            enabled={actions.start.enabled}
            onClick={() =>
              void runAction("Start proxy", () =>
                api.post("/api/proxy/start", { listen_host: host, port })
              )
            }
          />
          <ActionBox
            label="Stop"
            enabled={actions.stop.enabled}
            onClick={() => void runAction("Stop proxy", () => api.post("/api/proxy/stop", {}))}
          />
        </div>

        {/* Restart — full width */}
        <ActionBox
          label="Restart"
          enabled={actions.restart.enabled}
          onClick={() =>
            void runAction("Restart proxy", () =>
              api.post("/api/proxy/restart", { listen_host: host, port })
            )
          }
        />

        {/* Kill | Force Kill — danger row */}
        <div className="grid grid-cols-2 gap-1.5 pt-0.5">
          <ActionBox
            label="Kill"
            enabled={actions.kill.enabled}
            danger
            onClick={() => kill(false)}
          />
          <ActionBox
            label="Force Kill"
            enabled={actions.forceKill.enabled}
            danger
            onClick={() => kill(true)}
          />
        </div>

        {proxyStatus.last_error && (
          <div className="text-[11px] text-error line-clamp-2 px-0.5 pt-0.5">
            {proxyStatus.last_error}
          </div>
        )}

        <div className="border-t border-base-300 mt-0.5 pt-1">
          <Link
            to="/proxy"
            className="btn btn-ghost btn-xs w-full justify-start"
            role="menuitem"
          >
            Open Proxy page →
          </Link>
        </div>
      </div>
    </HoverMenu>
  );
}
