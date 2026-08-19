/** Shared types for the SSRF workspace. */

export type SsrfTab = "overview" | "run" | "results";

export const SSRF_TABS: { id: SsrfTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isSsrfTab(v: string | null): v is SsrfTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["SSRF", "SECURE", "UNKNOWN"] as const;
export const FAMILIES = [
  "loopback",
  "cloud",
  "protocol",
  "bypass",
  "encoded",
  "internal",
  "oast",
] as const;

export interface SsrfTechnique {
  name: string;
  family: string;
  description: string;
  sink?: string;
  inject_mode?: string;
  requires_collaborator?: boolean;
}

export interface SsrfResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  location?: string;
  param_name?: string;
  payload_sent?: string;
  sink_hint?: string | null;
  oast_host?: string;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  elapsed_ms?: number | null;
  captured_at?: string;
}

export interface SsrfOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: SsrfTechnique[];
  families: string[];
  recent_issues: SsrfResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
