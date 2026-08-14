/**
 * Shared types and constants for Auth-Session Testing workspace.
 *
 * Progressive tabs (K3 / K15): full six-tab ship at Phase 5 exit.
 * Overview | Bindings | Candidates | Run | Results | Filter & Suite
 */

export type AuthSessionTab =
  | "overview"
  | "bindings"
  | "candidates"
  | "run"
  | "results"
  | "config";

/** Full CLI-parity ship set (Phase 5). */
export const SHIPPED_TABS: readonly AuthSessionTab[] = [
  "overview",
  "bindings",
  "candidates",
  "run",
  "results",
  "config",
] as const;

const ALL_TAB_DEFS: { id: AuthSessionTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "bindings", label: "Bindings" },
  { id: "candidates", label: "Target flows" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
  { id: "config", label: "Filter & Suite" },
];

export const AUTH_SESSION_TABS: { id: AuthSessionTab; label: string }[] =
  ALL_TAB_DEFS.filter((t) =>
    (SHIPPED_TABS as readonly AuthSessionTab[]).includes(t.id)
  );

export function isAuthSessionTab(v: string | null): v is AuthSessionTab {
  return !!v && (SHIPPED_TABS as readonly string[]).includes(v);
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

/** Hub status line — cleared at full parity (Phase 5). */
export const HUB_STATUS_LINE: string | undefined = undefined;

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

/** Unique baseline flow selected as a JWT test target. */
export interface AuthSessionTarget {
  flow_id: string;
  binding_id: string;
  endpoint_id?: string | null;
  test_count: number;
  runnable_count: number;
  running_count: number;
  created_at?: string;
  method?: string | null;
  path?: string | null;
  host?: string | null;
  url?: string | null;
  status_code?: number | null;
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
  original_status?: number | null;
  replay_status?: number | null;
  matched_section?: string | null;
  matched_group?: string | null;
  matched_rules?: string | null;
  method?: string;
  path?: string;
  host?: string;
  status_code?: number;
  captured_at?: string;
  created_at?: string;
  failure_reason?: string | null;
  finding_id?: string | null;
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
  estimated_jobs?: number;
  targets_total?: number;
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

export interface AuthSessionSuiteCase {
  test_id: string;
  title: string;
  family: string;
  description?: string;
  risk_hint?: string;
  source: string;
  requires_claims?: string[];
  observed_alg?: string;
}

export type GenerateScopeMode = "project" | "endpoint" | "module" | "flow";

/** Right-now hard refuse threshold (K11). */
export const RIGHT_NOW_MAX = 20;
/** Confirm when estimate exceeds this (K11 FE). */
export const CONFIRM_ESTIMATE_THRESHOLD = 5;
