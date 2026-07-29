/** Shared types and constants for the Input Validation workspace. */

export { IV_BASE } from "../attack/registry";

export type IvTab =
  | "overview"
  | "candidates"
  | "parameters"
  | "multi-level"
  | "run"
  | "settings";

export const IV_TABS: { id: IvTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "candidates", label: "Candidates" },
  { id: "parameters", label: "Parameters" },
  { id: "multi-level", label: "Multi-level" },
  { id: "run", label: "Run" },
  { id: "settings", label: "Settings" },
];

export const BUDGETS = ["quick", "standard", "deep", "exhaustive"] as const;

/** CLI-toggleable / phase-shortcut names (must match talos input-validation). */
export const PHASES = [
  "baseline",
  "multiprobe",
  "identifier",
  "characters",
  "length",
  "types",
  "transformations",
  "reflection",
  "validation",
] as const;

export const ATTACKS = [
  "",
  "xss",
  "sqli",
  "open_redirect",
  "ssrf",
  "hpp",
  "header_injection",
  "path_traversal",
  "mass_assignment",
] as const;

export const LOCATIONS = [
  "",
  "query",
  "body",
  "header",
  "cookie",
  "path",
  "multipart",
  "graphql",
  "xml",
] as const;

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export interface IvConfig {
  enabled: number;
  workers: number;
  analyses_baseline?: number;
  analyses_multiprobe?: number;
  analyses_identifier?: number;
  analyses_characters?: number;
  analyses_length?: number;
  analyses_types?: number;
  analyses_transformations?: number;
  analyses_reflection?: number;
  analyses_validation?: number;
  probe_strategy?: string;
  max_requests_per_param?: number;
  include_auth_artifacts?: number;
  excluded_hosts: string[];
  excluded_endpoints: string[];
}

/** Sink summary from cross-flow / stored reflection (prioritization evidence). */
export interface StoredReflectionSink {
  method?: string;
  path?: string;
  endpoint_id?: string;
  flow_id?: string;
  context?: string;
  encoding?: string;
  reason?: string;
}

export interface StoredReflection {
  link_count?: number;
  sinks?: StoredReflectionSink[];
}

export interface CandidateRow {
  param_uuid?: string;
  host?: string;
  name?: string;
  location?: string;
  attack?: string;
  score?: number;
  confidence?: number;
  reasons?: string[];
  evidence_flow_ids?: string[];
  capabilities?: string[];
  /** e.g. ["same_request", "cross_flow"] */
  reflection_modes?: string[];
  /** Present when XSS (or other) score used stored/cross-page evidence */
  stored_reflection?: StoredReflection | null;
}

export interface ProfileRow {
  param_uuid?: string;
  host?: string;
  location?: string;
  name?: string;
  schema_version?: number;
  engine_version?: string;
  profile_version?: number;
  updated_at?: string;
  capabilities?: string[];
  candidates?: CandidateRow[];
  candidate_count?: number;
  capability_count?: number;
  requests_used?: number;
  budget_tier?: string;
  reflection_state?: string;
  reflection_confidence?: number;
  length_state?: string;
  max_accepted_length?: number | null;
  primary_type?: string | null;
  top_candidate?: { attack?: string; score?: number; confidence?: number } | null;
}

export interface IvStatus {
  total_params?: number;
  completed?: number;
  running?: number;
  queued?: number;
  failed?: number;
  skipped?: number;
  budget_tier?: string;
  max_requests_per_param?: number;
  max_requests_override?: number;
  requests_used?: number;
  params_probed?: number;
  profiles?: number;
  endpoint_profiles?: number;
  app_profiles?: number;
  pending_plan_params?: number;
  pending_plan_actions?: Record<string, number>;
  confidence?: {
    buckets?: Record<string, number>;
    profiles_with_capabilities?: number;
    profiles_with_candidates?: number;
    candidates_total?: number;
    candidates_score_ge_60?: number;
    avg_reflection_confidence?: number;
  };
  param_cache?: Record<string, number>;
  reflection_cache?: Record<string, number>;
  probe_results?: Record<string, number>;
}

export function isIvTab(v: string | null): v is IvTab {
  return !!v && IV_TABS.some((t) => t.id === v);
}

export function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function scoreBand(score: number | undefined): "high" | "mid" | "low" {
  const s = Number(score ?? 0);
  if (s >= 70) return "high";
  if (s >= 40) return "mid";
  return "low";
}
