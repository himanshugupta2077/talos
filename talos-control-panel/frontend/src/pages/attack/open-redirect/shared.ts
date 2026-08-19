/** Shared types for the open-redirect workspace. */

export type OpenRedirectTab = "overview" | "run" | "results";

export const OPEN_REDIRECT_TABS: { id: OpenRedirectTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isOpenRedirectTab(v: string | null): v is OpenRedirectTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["OPEN_REDIRECT", "SECURE", "UNKNOWN"] as const;
export const FAMILIES = [
  "absolute",
  "proto_rel",
  "slash",
  "encoded",
  "userinfo",
  "data_js",
  "fragment",
  "crlf",
] as const;

export interface OpenRedirectTechnique {
  name: string;
  family: string;
  description: string;
  os?: string;
  inject_mode?: string;
}

export interface OpenRedirectResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  location?: string;
  param_name?: string;
  payload_sent?: string;
  redirect_url?: string | null;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  elapsed_ms?: number | null;
  captured_at?: string;
}

export interface OpenRedirectOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: OpenRedirectTechnique[];
  families: string[];
  recent_issues: OpenRedirectResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
