/** Shared types for the HTTP request smuggling workspace. */

export type SmuggleTab = "overview" | "run" | "results";

export const SMUGGLE_TABS: { id: SmuggleTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isSmuggleTab(v: string | null): v is SmuggleTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["SMUGGLE", "SECURE", "UNKNOWN"] as const;

export interface SmuggleTechnique {
  name: string;
  family: string;
  description: string;
}

export interface SmuggleResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  canary_path?: string;
  ntlm_used?: number | boolean;
  baseline_status?: number | null;
  probe_status?: number | null;
  followup_status?: number | null;
  desync_signal?: string;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  captured_at?: string;
}

export interface SmuggleOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: SmuggleTechnique[];
  recent_issues: SmuggleResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
