/** Shared types for the XSS / HTML injection workspace. */

export type XssTab = "overview" | "run" | "results";

export const XSS_TABS: { id: XssTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isXssTab(v: string | null): v is XssTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["XSS", "HTMLI", "SECURE", "UNKNOWN"] as const;
export const FAMILIES = [
  "html_tag",
  "htmli",
  "html_attr",
  "event",
  "js",
  "url",
  "encoded",
  "bypass",
  "polyglot",
] as const;

export interface XssTechnique {
  name: string;
  family: string;
  description: string;
  risk_class?: string;
  context?: string;
  inject_mode?: string;
}

export interface XssResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  location?: string;
  param_name?: string;
  payload_sent?: string;
  context_hint?: string | null;
  encoding_hint?: string | null;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  elapsed_ms?: number | null;
  captured_at?: string;
}

export interface XssOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: XssTechnique[];
  families: string[];
  recent_issues: XssResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
