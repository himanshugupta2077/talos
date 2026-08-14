import { createContext, useContext, useEffect, useState, ReactNode, useCallback } from "react";
import {
  api,
  formatProxyStateLabel,
  formatSchedulerStateLabel,
  ProxyRuntimeStatus,
  ProjectSummary,
  SchedulerStatus,
  schedulerActiveQueueCount,
} from "../api/client";
import { useProject } from "./ProjectContext";
import { Role, Module } from "../types";

interface StatusContextValue {
  /** Full Talos runtime snapshot (observational only). */
  proxyStatus: ProxyRuntimeStatus;
  /** Convenience: state === "running". */
  proxyRunning: boolean;
  /** Header-ready label, e.g. "RUNNING", "STARTING", "RESTARTING". */
  proxyStateLabel: string;
  /** Project scheduler DB state + queue counts (null when no project). */
  schedulerStatus: SchedulerStatus | null;
  /** Header-ready scheduler execution label. */
  schedulerStateLabel: string;
  /** Active queue depth (pending + running + paused). */
  schedulerQueueCount: number;
  /** PRIMARY findings count (header first number; null when no project). */
  findingsPrimary: number | null;
  /** PRIMARY + LINKED findings count (header second number). */
  findingsTotal: number | null;
  /** Actionable findings signal: TRIAGING count (null when no project). */
  findingsTriaging: number | null;
  /** Confirmed findings count (header badge context). */
  findingsConfirmed: number | null;
  /** All project roles (for header switcher). */
  roles: Role[];
  /** All project modules (for header switcher). */
  modules: Module[];
  activeRole: Role | null;
  activeModule: Module | null;
  refreshStatus: () => Promise<void>;
}

const defaultProxyStatus: ProxyRuntimeStatus = {
  state: "stopped",
  running: false,
  transitional: false,
};

const StatusContext = createContext<StatusContextValue | null>(null);

/**
 * Single shared poller for the global top header: proxy runtime, scheduler
 * status/queue, findings signal, and active role/module chips.
 * Individual pages (e.g. Proxy, Scheduler) may still poll their own richer
 * status/logs — this context exists so pages never own global lifecycle UI.
 *
 * Proxy lifecycle decisions are never made here — Talos core auto-restarts
 * when its own notify path says so; we only re-read runtime state.
 */
export function StatusProvider({ children }: { children: ReactNode }) {
  const { selected } = useProject();
  const [proxyStatus, setProxyStatus] = useState<ProxyRuntimeStatus>(defaultProxyStatus);
  const [schedulerStatus, setSchedulerStatus] = useState<SchedulerStatus | null>(null);
  const [findingsPrimary, setFindingsPrimary] = useState<number | null>(null);
  const [findingsTotal, setFindingsTotal] = useState<number | null>(null);
  const [findingsTriaging, setFindingsTriaging] = useState<number | null>(null);
  const [findingsConfirmed, setFindingsConfirmed] = useState<number | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [modules, setModules] = useState<Module[]>([]);
  const [activeRole, setActiveRole] = useState<Role | null>(null);
  const [activeModule, setActiveModule] = useState<Module | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.get<ProxyRuntimeStatus>("/api/proxy/status");
      setProxyStatus({
        ...defaultProxyStatus,
        ...s,
        state: (s.state || "stopped").toLowerCase(),
        running: !!s.running || (s.state || "").toLowerCase() === "running",
        transitional: !!s.transitional,
      });
    } catch {
      setProxyStatus(defaultProxyStatus);
    }

    if (selected) {
      try {
        const [{ roles: roleList }, { modules: moduleList }, sched, summary] =
          await Promise.all([
            api.get<{ roles: Role[] }>("/api/roles", { project_id: selected.id }),
            api.get<{ modules: Module[] }>("/api/modules", {
              project_id: selected.id,
            }),
            api.get<SchedulerStatus>("/api/scheduler/status", {
              project_id: selected.id,
            }),
            api.get<ProjectSummary>(`/api/projects/${selected.id}/summary`),
          ]);
        setRoles(roleList);
        setModules(moduleList);
        setActiveRole(roleList.find((r) => !!r.is_active) || null);
        setActiveModule(moduleList.find((m) => !!m.is_active) || null);
        setSchedulerStatus(sched);
        setFindingsPrimary(summary.findings_primary ?? 0);
        setFindingsTotal(summary.findings_total ?? 0);
        setFindingsTriaging(summary.findings_triaging ?? 0);
        setFindingsConfirmed(summary.findings_confirmed ?? 0);
      } catch {
        setRoles([]);
        setModules([]);
        setActiveRole(null);
        setActiveModule(null);
        setSchedulerStatus(null);
        setFindingsPrimary(null);
        setFindingsTotal(null);
        setFindingsTriaging(null);
        setFindingsConfirmed(null);
      }
    } else {
      setRoles([]);
      setModules([]);
      setActiveRole(null);
      setActiveModule(null);
      setSchedulerStatus(null);
      setFindingsPrimary(null);
      setFindingsTotal(null);
      setFindingsTriaging(null);
      setFindingsConfirmed(null);
    }
  }, [selected]);

  useEffect(() => {
    refreshStatus();
    // Faster while transitional so auto-restarts surface quickly in the header.
    const intervalMs = proxyStatus.transitional || proxyStatus.restart_pending ? 1000 : 3000;
    const id = setInterval(refreshStatus, intervalMs);
    return () => clearInterval(id);
  }, [refreshStatus, proxyStatus.transitional, proxyStatus.restart_pending]);

  const proxyRunning = proxyStatus.running;
  const proxyStateLabel = formatProxyStateLabel(proxyStatus);
  const schedulerStateRaw = schedulerStatus?.state?.state ?? null;
  const schedulerStateLabel = selected
    ? formatSchedulerStateLabel(schedulerStateRaw)
    : "—";
  const schedulerQueueCount = schedulerActiveQueueCount(schedulerStatus?.counts);

  return (
    <StatusContext.Provider
      value={{
        proxyStatus,
        proxyRunning,
        proxyStateLabel,
        schedulerStatus,
        schedulerStateLabel,
        schedulerQueueCount,
        findingsPrimary,
        findingsTotal,
        findingsTriaging,
        findingsConfirmed,
        roles,
        modules,
        activeRole,
        activeModule,
        refreshStatus,
      }}
    >
      {children}
    </StatusContext.Provider>
  );
}

export function useStatus() {
  const ctx = useContext(StatusContext);
  if (!ctx) throw new Error("useStatus must be used within StatusProvider");
  return ctx;
}
