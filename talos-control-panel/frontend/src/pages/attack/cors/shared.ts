/** Shared types for the CORS misconfiguration workspace. */

export type CorsTab = "overview" | "run" | "results";

export const CORS_TABS: { id: CorsTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isCorsTab(v: string | null): v is CorsTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["CORS_MISCONFIG", "SECURE", "UNKNOWN"] as const;

export interface CorsTechnique {
  name: string;
  family: string;
  description: string;
}

export interface CorsResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  origin_sent?: string;
  acao?: string | null;
  acac?: string | null;
  reflected?: number | boolean;
  credentials?: number | boolean;
  wildcard?: number | boolean;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  captured_at?: string;
}

export interface CorsOverview {
  counts: Record<string, number>;
  candidates: number;
  total_techniques: number;
  estimated_jobs_all: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: CorsTechnique[];
  recent_issues: CorsResultRow[];
  empty_state: {
    no_candidates?: boolean;
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}

export function estimateJobs(candidates: number, techniqueCount: number): number {
  return Math.max(0, candidates) * Math.max(0, techniqueCount);
}
