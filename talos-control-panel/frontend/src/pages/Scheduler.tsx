/**
 * Scheduler control page — process daemon + queue execution + job inventory.
 *
 * Mental model: rate-limited priority job queue + managed daemon (not cron).
 * Process (start/stop) and queue state (pause/resume) are distinct.
 * Enqueue lives on Flow / Endpoint pages.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type SchedulerStatus } from "../api/client";
import { ModuleHelp, NoProjectNotice } from "../components/Common";
import { useAction } from "../hooks/useAction";
import { useProject } from "../state/ProjectContext";
import { useStatus } from "../state/StatusContext";
import type { SchedulerJob } from "../types";
import HistoryTab from "./scheduler/HistoryTab";
import JobDetailDrawer from "./scheduler/JobDetailDrawer";
import JobsTab from "./scheduler/JobsTab";
import MetricsStrip from "./scheduler/MetricsStrip";
import Toolbar from "./scheduler/Toolbar";
import {
  DEFAULT_HISTORY_FILTERS,
  DEFAULT_JOBS_FILTERS,
  isProcessLive,
  type JobFilterState,
  type JobsListResponse,
  type SchedulerFiltersApi,
  type SchedulerTab,
} from "./scheduler/shared";

interface ConfigSetting {
  key: string;
  effective_value: unknown;
  source: string;
}

const EMPTY_FILTERS: SchedulerFiltersApi = {
  job_types: [],
  statuses: [],
  roles: [],
  modules: [],
};

export default function Scheduler() {
  const { selected } = useProject();
  const { refreshStatus } = useStatus();
  const [searchParams, setSearchParams] = useSearchParams();

  const tabParam = (searchParams.get("tab") as SchedulerTab) || "jobs";
  const tab: SchedulerTab = tabParam === "history" ? "history" : "jobs";

  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [jobs, setJobs] = useState<SchedulerJob[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filterOptions, setFilterOptions] =
    useState<SchedulerFiltersApi>(EMPTY_FILTERS);
  const [jobFilters, setJobFilters] = useState<JobFilterState>(() => {
    const statusQ = searchParams.get("status");
    const typeQ = searchParams.get("type");
    const base =
      tabParam === "history" ? DEFAULT_HISTORY_FILTERS : DEFAULT_JOBS_FILTERS;
    return {
      ...base,
      status: statusQ ?? base.status,
      jobType: typeQ ?? base.jobType,
    };
  });
  const [detailJob, setDetailJob] = useState<SchedulerJob | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [rateConfig, setRateConfig] = useState<{
    min_delay: unknown;
    max_delay: unknown;
    max_queue_size: unknown;
    sources: Record<string, string>;
  } | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const deepLinkHandled = useRef<string | null>(null);

  const setTab = (t: SchedulerTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    if (t === "history" && !next.get("status")) {
      setJobFilters((f) => ({ ...f, status: "failed" }));
    } else if (t === "jobs" && searchParams.get("tab") === "history") {
      setJobFilters((f) => ({
        ...f,
        status: f.status === "failed" ? "active" : f.status,
      }));
    }
    setSearchParams(next, { replace: true });
  };

  const patchFilters = (patch: Partial<JobFilterState>) => {
    setJobFilters((f) => ({ ...f, ...patch }));
    if (patch.status !== undefined) {
      const next = new URLSearchParams(searchParams);
      if (patch.status) next.set("status", patch.status);
      else next.delete("status");
      setSearchParams(next, { replace: true });
    }
    if (patch.jobType !== undefined) {
      const next = new URLSearchParams(searchParams);
      if (patch.jobType) next.set("type", patch.jobType);
      else next.delete("type");
      setSearchParams(next, { replace: true });
    }
  };

  const load = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const statusParams = { project_id: selected.id };
      const jobParams: Record<string, string | number> = {
        project_id: selected.id,
        limit: jobFilters.limit,
        offset: 0,
      };
      if (jobFilters.status) jobParams.status = jobFilters.status;
      if (jobFilters.jobType) jobParams.job_type = jobFilters.jobType;
      if (jobFilters.role) jobParams.role = jobFilters.role;
      if (jobFilters.module) jobParams.module = jobFilters.module;

      const [s, j] = await Promise.all([
        api.get<SchedulerStatus>("/api/scheduler/status", statusParams),
        api.get<JobsListResponse>("/api/scheduler/jobs", jobParams),
      ]);
      setStatus(s);
      setJobs(j.jobs || []);
      setTotal(j.total ?? (j.jobs || []).length);
    } finally {
      setLoading(false);
    }
  }, [
    selected,
    jobFilters.status,
    jobFilters.jobType,
    jobFilters.role,
    jobFilters.module,
    jobFilters.limit,
  ]);

  const loadRateConfig = useCallback(() => {
    if (!selected) return;
    api
      .get<{ settings: ConfigSetting[] }>("/api/configuration/settings", {
        project_id: selected.id,
        section: "scheduler",
      })
      .then((r) => {
        const byKey: Record<string, ConfigSetting> = {};
        for (const row of r.settings || []) byKey[row.key] = row;
        setRateConfig({
          min_delay: byKey["scheduler.min_delay"]?.effective_value ?? 2,
          max_delay: byKey["scheduler.max_delay"]?.effective_value ?? 6,
          max_queue_size:
            byKey["scheduler.max_queue_size"]?.effective_value ?? 200,
          sources: {
            min_delay: byKey["scheduler.min_delay"]?.source || "default",
            max_delay: byKey["scheduler.max_delay"]?.source || "default",
            max_queue_size:
              byKey["scheduler.max_queue_size"]?.source || "default",
          },
        });
      })
      .catch(() => setRateConfig(null));
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    api
      .get<SchedulerFiltersApi>("/api/scheduler/filters", {
        project_id: selected.id,
      })
      .then(setFilterOptions)
      .catch(() => setFilterOptions(EMPTY_FILTERS));
    loadRateConfig();
  }, [selected, loadRateConfig]);

  useEffect(() => {
    if (!selected) return;
    void load();
    const id = setInterval(() => {
      if (document.visibilityState === "hidden") return;
      void load();
    }, 4000);
    return () => clearInterval(id);
  }, [selected, load]);

  useEffect(() => {
    if (!selected) return;
    const jobQ = searchParams.get("job");
    if (!jobQ || deepLinkHandled.current === jobQ) return;
    deepLinkHandled.current = jobQ;
    api
      .get<{ job: SchedulerJob }>(
        `/api/scheduler/jobs/${encodeURIComponent(jobQ)}`,
        { project_id: selected.id }
      )
      .then((r) => {
        setDetailJob(r.job);
        setDrawerOpen(true);
      })
      .catch(() => {
        /* job missing — ignore */
      });
  }, [selected, searchParams]);

  const afterMutation = async () => {
    await load();
    await refreshStatus();
  };

  const start = useAction("Start scheduler process", () =>
    api.post("/api/scheduler/start", {}, { project_id: selected!.id })
  );
  const stop = useAction("Stop scheduler process", () =>
    api.post("/api/scheduler/stop", {}, { project_id: selected!.id })
  );
  const pause = useAction("Pause scheduler", () =>
    api.post("/api/scheduler/pause", {}, { project_id: selected!.id })
  );
  const resume = useAction("Resume scheduler", () =>
    api.post("/api/scheduler/resume", {}, { project_id: selected!.id })
  );
  const clearPending = useAction("Clear pending jobs", () =>
    api.post(
      "/api/scheduler/clear",
      {},
      { project_id: selected!.id, force: true }
    )
  );
  const prune = useAction("Prune jobs", (status: string) =>
    api.post(
      "/api/scheduler/prune",
      { status, force: true },
      { project_id: selected!.id }
    )
  );
  const cancelOne = useAction("Cancel job", (jobId: string) =>
    api.post(
      "/api/scheduler/cancel",
      { job_id: jobId },
      { project_id: selected!.id }
    )
  );

  const runBusy = async (fn: () => Promise<unknown>) => {
    setActionBusy(true);
    try {
      await fn();
      await afterMutation();
    } finally {
      setActionBusy(false);
    }
  };

  const openJob = async (job: SchedulerJob) => {
    setDetailJob(job);
    setDrawerOpen(true);
    const next = new URLSearchParams(searchParams);
    next.set("job", job.job_id);
    setSearchParams(next, { replace: true });
    if (selected) {
      try {
        const r = await api.get<{ job: SchedulerJob }>(
          `/api/scheduler/jobs/${encodeURIComponent(job.job_id)}`,
          { project_id: selected.id }
        );
        setDetailJob(r.job);
      } catch {
        /* keep list row */
      }
    }
  };

  const closeDrawer = () => {
    setDrawerOpen(false);
    const next = new URLSearchParams(searchParams);
    next.delete("job");
    setSearchParams(next, { replace: true });
  };

  const handleCancel = async (jobId: string) => {
    await cancelOne.run(jobId);
    await afterMutation();
    if (detailJob?.job_id === jobId) {
      try {
        const r = await api.get<{ job: SchedulerJob }>(
          `/api/scheduler/jobs/${encodeURIComponent(jobId)}`,
          { project_id: selected!.id }
        );
        setDetailJob(r.job);
      } catch {
        closeDrawer();
      }
    }
  };

  const handleBulkCancel = async (jobIds: string[]) => {
    for (const id of jobIds) {
      await cancelOne.run(id);
    }
    await afterMutation();
  };

  if (!selected) return <NoProjectNotice />;

  const processLive = isProcessLive(status?.process);
  const activeQueue =
    Number(status?.counts?.pending || 0) +
    Number(status?.counts?.running || 0) +
    Number(status?.counts?.paused || 0);
  const waiting =
    (status?.state?.state || "").toLowerCase() === "waiting_for_session";
  const busy =
    actionBusy ||
    start.running ||
    stop.running ||
    pause.running ||
    resume.running;

  return (
    <div>
      <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">Scheduler</h1>
        <Toolbar
          status={status}
          busy={busy}
          onPlay={() => void runBusy(() => resume.run())}
          onPause={() => void runBusy(() => pause.run())}
          onRefresh={() => void load()}
          onClear={async () => {
            await clearPending.run();
            await afterMutation();
          }}
          onPrune={async (s) => {
            await prune.run(s);
            await afterMutation();
          }}
          onStart={() => void runBusy(() => start.run())}
          onStop={() => void runBusy(() => stop.run())}
        />
      </div>

      <div className="mb-3">
        <ModuleHelp title="Process vs queue">
          <p>
            <strong>Process</strong> (switch) is the managed daemon — jobs only
            drain when it is ON. <strong>Play/Pause</strong> is queue execution
            in the project DB. Enqueue from Flow or Endpoint pages. Rate limits
            live under Talos Configuration.
          </p>
        </ModuleHelp>
      </div>

      {!processLive && activeQueue > 0 && (
        <div className="alert alert-warning py-2 text-sm mb-3">
          <span>
            Queue has <strong>{activeQueue}</strong> active job(s) but the
            process is off — turn Process on to drain.
          </span>
        </div>
      )}

      {waiting && status?.state?.reason && (
        <div className="alert alert-warning py-2 text-sm mb-3">
          <div className="flex flex-wrap items-center gap-2">
            <span>{status.state.reason}</span>
            <Link to="/auth" className="link link-primary text-xs">
              Open Auth →
            </Link>
          </div>
        </div>
      )}

      <MetricsStrip
        status={status}
        selectedStatus={jobFilters.status}
        onStatusChip={(s) => {
          patchFilters({ status: s });
          if (["failed", "done", "skipped", "cancelled"].includes(s)) {
            setTab("history");
          } else if (
            tab === "history" &&
            (s === "active" ||
              s === "pending" ||
              s === "running" ||
              s === "paused" ||
              s === "")
          ) {
            setTab("jobs");
          }
        }}
        rateConfig={rateConfig}
      />

      <div className="tabs tabs-bordered mb-3">
        <button
          type="button"
          className={`tab tab-sm ${tab === "jobs" ? "tab-active" : ""}`}
          onClick={() => setTab("jobs")}
        >
          Jobs
        </button>
        <button
          type="button"
          className={`tab tab-sm ${tab === "history" ? "tab-active" : ""}`}
          onClick={() => setTab("history")}
        >
          History
        </button>
      </div>

      {tab === "jobs" ? (
        <JobsTab
          jobs={jobs}
          total={total}
          loading={loading}
          filters={jobFilters}
          filterOptions={filterOptions}
          onFiltersChange={patchFilters}
          onOpenJob={(j) => void openJob(j)}
          onCancelOne={(id) => void handleCancel(id)}
          onBulkCancel={handleBulkCancel}
          emptyHint={
            !processLive
              ? "No jobs match filters. Process is off — turn it on to drain when jobs exist."
              : "No jobs match filters."
          }
        />
      ) : (
        <HistoryTab
          jobs={jobs}
          total={total}
          loading={loading}
          filters={jobFilters}
          filterOptions={filterOptions}
          counts={status?.counts || {}}
          onFiltersChange={patchFilters}
          onOpenJob={(j) => void openJob(j)}
          onCancelOne={(id) => void handleCancel(id)}
          onBulkCancel={handleBulkCancel}
          onPrune={async (s) => {
            await prune.run(s);
            await afterMutation();
          }}
          pruneBusy={prune.running}
        />
      )}

      <JobDetailDrawer
        job={detailJob}
        open={drawerOpen}
        onClose={closeDrawer}
        onCancel={(id) => void handleCancel(id)}
        cancelling={cancelOne.running}
      />
    </div>
  );
}
