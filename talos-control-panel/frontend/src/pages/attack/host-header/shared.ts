/** Shared types for the host-header injection workspace. */

export type HostHeaderTab = "overview" | "run" | "results";

export const HOST_HEADER_TABS: { id: HostHeaderTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isHostHeaderTab(v: string | null): v is HostHeaderTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["HOST_HEADER", "SECURE", "UNKNOWN"] as const;
export const FAMILIES = [
  "absolute",
  "port",
  "ambiguous",
  "absolute_url",
  "encoded",
  "bypass",
  "crlf",
] as const;

export interface HostHeaderTechnique {
  name: string;
  family: string;
  description: string;
  headers?: string[];
  inject_mode?: string;
}

export interface HostHeaderResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  location?: string;
  param_name?: string;
  payload_sent?: string;
  reflected_url?: string | null;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  elapsed_ms?: number | null;
  captured_at?: string;
}

export interface HostHeaderOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: HostHeaderTechnique[];
  families: string[];
  recent_issues: HostHeaderResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
