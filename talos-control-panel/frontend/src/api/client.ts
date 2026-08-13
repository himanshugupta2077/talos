const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8420";

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(status: number, body: any) {
    super(`API error ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(
  method: string,
  path: string,
  { params, body }: { params?: Record<string, any>; body?: any } = {}
): Promise<T> {
  const url = new URL(API_BASE + path);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === "") continue;
      url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}

export const api = {
  get: <T = any>(path: string, params?: Record<string, any>) =>
    request<T>("GET", path, { params }),
  post: <T = any>(path: string, body?: any, params?: Record<string, any>) =>
    request<T>("POST", path, { params, body: body ?? {} }),
  del: <T = any>(path: string, params?: Record<string, any>) =>
    request<T>("DELETE", path, { params }),
  /**
   * Multipart file upload (scope/outscope import). Do not set Content-Type —
   * the browser supplies the boundary for FormData.
   */
  postForm: async <T = any>(
    path: string,
    form: FormData,
    params?: Record<string, any>
  ): Promise<T> => {
    const url = new URL(API_BASE + path);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === "") continue;
        url.searchParams.set(k, String(v));
      }
    }
    const res = await fetch(url.toString(), { method: "POST", body: form });
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) throw new ApiError(res.status, data);
    return data as T;
  },
};

export { API_BASE };

/**
 * Talos core proxy runtime snapshot (from `talos proxy status --format json`
 * via GET /api/proxy/status). Lifecycle ownership stays in Talos core; the UI
 * only observes and requests explicit operator start/stop/restart/kill.
 */
export type ProxyLifecycleState =
  | "stopped"
  | "starting"
  | "running"
  | "draining"
  | "stopping"
  | string;

export interface ProxyRuntimeStatus {
  state: ProxyLifecycleState;
  running: boolean;
  transitional: boolean;
  pid?: number | null;
  project_id?: string | null;
  role_id?: string | null;
  module_id?: string | null;
  listen_host?: string | null;
  listen_port?: number | null;
  upstream_url?: string | null;
  startup_time?: string | null;
  applied_project_id?: string | null;
  applied_generation?: number | null;
  restart_pending?: boolean;
  last_error?: string | null;
  validation_deferred?: boolean;
  log_path?: string | null;
  cli_ok?: boolean;
}

/**
 * Human label for header / badges — derived only from Talos-reported state.
 * Transitional auto-restarts surface as RESTARTING so operators never have to
 * infer lifecycle from the initiating page.
 */
export function formatProxyStateLabel(
  status: Pick<
    ProxyRuntimeStatus,
    "state" | "running" | "transitional" | "restart_pending" | "last_error"
  >
): string {
  const state = (status.state || "stopped").toLowerCase();
  // restart_pending or mid-cycle start after a reconcile → RESTARTING
  if (status.restart_pending) return "RESTARTING";
  if (state === "starting") return "STARTING";
  if (state === "draining" || state === "stopping") return "STOPPING";
  if (state === "running") return "RUNNING";
  if (state === "stopped" && status.last_error) return "FAILED";
  if (state === "stopped") return "STOPPED";
  return state.toUpperCase();
}

/** Project summary counters used by the header findings signal + Projects strip. */
export interface ProjectSummary {
  flows: number;
  endpoints: number;
  findings_triaging: number;
  findings_confirmed: number;
  scheduler_pending: number;
  roles: number;
  modules: number;
}

/** Managed daemon process snapshot (SchedulerRuntimeManager). */
export interface SchedulerProcessStatus {
  state?: string;
  pid?: number | null;
  create_time?: number | null;
  project_id?: string | null;
  startup_time?: string | null;
  runtime_version?: number;
  last_error?: string | null;
  validation_deferred?: boolean;
  transitional?: boolean;
  log_path?: string | null;
}

/**
 * Scheduler observational snapshot from GET /api/scheduler/status.
 * `process` = daemon runtime; `state` = project DB queue execution state;
 * `counts` = queue depth by job status (always includes known keys at 0).
 */
export interface SchedulerStatus {
  counts: Record<string, number>;
  config: {
    min_delay?: number;
    max_delay?: number;
    max_queue_size?: number;
  } | null;
  state: { state?: string; reason?: string | null } | null;
  process?: SchedulerProcessStatus | null;
  metrics?: {
    total_jobs?: number;
    avg_execution_delay_s?: number | null;
    last_executed_at?: string | null;
  } | null;
  active_queue?: number;
  queue_fill_pct?: number;
  /** Total jobs per exact job_type (all statuses). */
  by_job_type?: { job_type: string; family: string; n: number }[];
  /** Total jobs rolled up by attack/replay family (all statuses). */
  by_family?: { family: string; n: number }[];
}

/** Header label for scheduler execution state (uppercase, glanceable). */
export function formatSchedulerStateLabel(
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

/**
 * Active workload indicator: pending + running + paused jobs.
 * Terminal statuses (done/failed/cancelled) are excluded so the number
 * reflects what Talos still has to do.
 */
export function schedulerActiveQueueCount(
  counts: Record<string, number> | null | undefined
): number {
  if (!counts) return 0;
  const active = ["pending", "running", "paused"] as const;
  return active.reduce((sum, key) => sum + (Number(counts[key]) || 0), 0);
}
