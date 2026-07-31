/**
 * Shared types and constants for Auth-Session Testing workspace.
 *
 * Progressive tabs (K3 / K15): only ship interactive tabs for the current phase.
 * Phase 2 exit: overview | bindings | candidates.
 */

export type AuthSessionTab = "overview" | "bindings" | "candidates" | "run" | "results" | "config";

/** Progressive ship set — Phase 2. */
export const SHIPPED_TABS: readonly AuthSessionTab[] = [
  "overview",
  "bindings",
  "candidates",
] as const;

const ALL_TAB_DEFS: { id: AuthSessionTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "bindings", label: "Bindings" },
  { id: "candidates", label: "Candidates" },
  // Phase 4+: { id: "run", label: "Run" }, { id: "results", label: "Results" }
  // Phase 5: { id: "config", label: "Filter & Suite" }
];

export const AUTH_SESSION_TABS: { id: AuthSessionTab; label: string }[] =
  ALL_TAB_DEFS.filter((t) =>
    (SHIPPED_TABS as readonly AuthSessionTab[]).includes(t.id)
  );

export function isAuthSessionTab(v: string | null): v is AuthSessionTab {
  return (
    !!v && (SHIPPED_TABS as readonly string[]).includes(v)
  );
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const CANDIDATE_STATUSES = [
  "pending",
  "approved",
  "rejected",
  "running",
  "done",
  "failed",
] as const;

export const VERDICTS = ["WEAK_VALIDATION", "SECURE", "UNKNOWN"] as const;

export const KNOWN_FAMILIES = [
  "signature",
  "algorithm",
  "algorithm_degrade",
  "structure",
  "claims",
  "kid",
] as const;

/** Hub status line for Phase 2. */
export const HUB_STATUS_LINE = "Inventory — generate OK; approve next";

export interface AuthSessionBinding {
  id: string;
  location: string;
  name: string;
  auth_type: string;
  role_id?: string | null;
  config_json?: string;
  created_at?: string;
  updated_at?: string;
  in_auth_config?: boolean;
  candidate_counts?: Record<string, number>;
}

export interface AuthSessionCandidate {
  id: string;
  binding_id: string;
  baseline_flow_id: string;
  auth_type: string;
  test_id: string;
  test_family: string;
  title?: string;
  mutation_summary?: string;
  status: string;
  endpoint_id?: string | null;
  token_fingerprint?: string | null;
  risk_hint?: string | null;
  reject_reason?: string | null;
  skip_reason?: string | null;
  meta_json?: string;
  created_at?: string;
  updated_at?: string;
  endpoint_method?: string | null;
  endpoint_path?: string | null;
}

export interface AuthSessionResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  candidate_id?: string;
  binding_id?: string;
  test_id?: string;
  test_family?: string;
  verdict?: string;
  endpoint_id?: string | null;
  mutation_summary?: string;
  method?: string;
  path?: string;
  host?: string;
  status_code?: number;
  captured_at?: string;
  created_at?: string;
  failure_reason?: string | null;
}

export interface AuthSessionOverview {
  bindings: number;
  binding_details: {
    id: string;
    location: string;
    name: string;
    auth_type: string;
    role_id?: string | null;
    in_auth_config: boolean;
  }[];
  candidates_total: number;
  candidates_by_status: Record<string, number>;
  results_total: number;
  results_by_verdict: Record<string, number>;
  counts?: Record<string, number>;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  estimated_jobs_approved: number;
  auth_config_ready: boolean;
  bindings_valid: boolean;
  filter_filename?: string;
  filter_path?: string;
  filter_exists?: boolean;
  recent_weak: AuthSessionResultRow[];
  empty_state: {
    no_bindings?: boolean;
    no_candidates?: boolean;
    no_results?: boolean;
    jobs_in_flight?: boolean;
    no_auth_config?: boolean;
  };
  disclaimer?: string;
}

export type GenerateScopeMode = "project" | "endpoint" | "module" | "flow";
