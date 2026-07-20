/** Shared types and helpers for the Scheduler control page. */

import type { SchedulerStatus } from "../../api/client";
import type { SchedulerJob as JobRow } from "../../types";

// Re-export for local modules.
export type { JobRow as SchedulerJob };
export type { SchedulerStatus };

export type SchedulerTab = "jobs" | "history";

export const JOB_STATUSES = [
  "pending",
  "running",
  "paused",
  "done",
  "failed",
  "skipped",
  "cancelled",
] as const;

export type JobStatus = (typeof JOB_STATUSES)[number];

export const ACTIVE_STATUSES = ["pending", "running", "paused"] as const;

export const TERMINAL_STATUSES = [
  "done",
  "failed",
  "skipped",
  "cancelled",
] as const;

export const PRUNEABLE_STATUSES = [
  "done",
  "failed",
  "skipped",
  "cancelled",
] as const;

export const FAMILY_OPTIONS = [
  { value: "replay", label: "replay" },
  { value: "bac", label: "bac" },
  { value: "iv", label: "iv" },
  { value: "unauth", label: "unauth" },
  { value: "auth_test", label: "auth_test" },
] as const;

export const LIMIT_OPTIONS = [50, 100, 200, 500, 1000] as const;

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export interface SchedulerFiltersApi {
  job_types: string[];
  statuses: string[];
  families?: string[];
  roles: string[];
  modules: string[];
  pruneable_statuses?: string[];
}

export interface JobsListResponse {
  jobs: JobRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface JobFilterState {
  status: string;
  jobType: string;
  role: string;
  module: string;
  limit: number;
  search: string;
}

export const DEFAULT_JOBS_FILTERS: JobFilterState = {
  status: "active",
  jobType: "",
  role: "",
  module: "",
  limit: 100,
  search: "",
};

export const DEFAULT_HISTORY_FILTERS: JobFilterState = {
  status: "failed",
  jobType: "",
  role: "",
  module: "",
  limit: 100,
  search: "",
};

/** Map job_type → family for chips/colors. */
export function jobFamily(jobType: string | null | undefined): string {
  if (!jobType) return "other";
  if (jobType === "auth_test") return "auth";
  if (jobType.startsWith("replay")) return "replay";
  if (jobType.startsWith("bac")) return "bac";
  if (jobType.startsWith("iv")) return "iv";
  if (jobType.startsWith("unauth")) return "unauth";
  if (!jobType.includes("_")) return jobType;
  return jobType.split("_")[0] || "other";
}

const FAMILY_BADGE: Record<string, string> = {
  replay: "badge-info",
  bac: "badge-warning",
  iv: "badge-secondary",
  unauth: "badge-accent",
  auth: "badge-primary",
  other: "badge-ghost",
};

export function familyBadgeClass(family: string): string {
  return FAMILY_BADGE[family] || "badge-ghost";
}

export function isCancellable(status: string | null | undefined): boolean {
  const s = (status || "").toLowerCase();
  return s === "pending" || s === "paused";
}

export function isProcessLive(
  process: SchedulerStatus["process"] | null | undefined
): boolean {
  const s = (process?.state || "").toLowerCase();
  return s === "running" || s === "starting";
}

export function processStateLabel(
  process: SchedulerStatus["process"] | null | undefined
): string {
  const raw = (process?.state || "stopped").toLowerCase();
  if (raw === "running") return "RUNNING";
  if (raw === "starting") return "STARTING";
  if (raw === "stopping" || raw === "draining") return "STOPPING";
  if (raw === "stopped") return "STOPPED";
  return raw.replace(/_/g, " ").toUpperCase();
}

export function queueStateLabel(
  state: string | null | undefined
): string {
  const raw = (state || "").toLowerCase().trim();
  if (!raw) return "—";
  if (raw === "running") return "RUNNING";
  if (raw === "paused") return "PAUSED";
  if (raw === "waiting_for_session" || raw === "waiting-for-session") {
    return "WAITING";
  }
  return raw.replace(/_/g, " ").toUpperCase();
}

/** Client-side free-text filter on job id / type / reason. */
export function filterJobsClient(
  jobs: JobRow[],
  search: string
): JobRow[] {
  const q = search.trim().toLowerCase();
  if (!q) return jobs;
  return jobs.filter((j) => {
    const id = (j.job_id || "").toLowerCase();
    const type = (j.job_type || "").toLowerCase();
    const reason = (j.failure_reason || "").toLowerCase();
    const verdict = (j.verdict || "").toLowerCase();
    return (
      id.includes(q) ||
      type.includes(q) ||
      reason.includes(q) ||
      verdict.includes(q)
    );
  });
}

export function shortJobId(jobId: string): string {
  return jobId.slice(0, 8);
}

/** Status chip keys shown in the metrics strip (includes synthetic active/all). */
export const COUNT_CHIP_KEYS = [
  "active",
  "pending",
  "running",
  "paused",
  "done",
  "failed",
  "skipped",
  "cancelled",
  "all",
] as const;
