/** Intruder Control Panel types — mirror engine fields (no parallel models). */

export type IntruderSessionStatus =
  | "draft"
  | "configured"
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled";

export type IntruderStrategy =
  | "single"
  | "sniper"
  | "pitchfork"
  | "zip"
  | "cluster_bomb"
  | "cartesian";

export type IntruderStorageMode = "metrics_only" | "sample_flows" | "all_flows";

export type IntruderTimingMode = "fixed" | "token_bucket" | "adaptive";

export type VariableLocation =
  | "path"
  | "query"
  | "body"
  | "header"
  | "cookie"
  | "raw";

/** All engine generators (CLI Phase 1–4). */
export type GeneratorType =
  | "wordlist"
  | "numbers"
  | "static"
  | "uuid"
  | "csv"
  | "json"
  | "example_values"
  | "pool"
  | "dates"
  | "bruteforce"
  | "random"
  | "pattern";

/** @deprecated use GeneratorType */
export type MvpGenerator = Extract<
  GeneratorType,
  "wordlist" | "numbers" | "static"
>;

export interface IntruderProgress {
  sent?: number;
  matched?: number;
  interesting?: number;
  estimate_total?: number | null;
  active_duration_s?: number;
  stopped_reason?: string | null;
  [key: string]: unknown;
}

export interface IntruderSessionSummary {
  id: string;
  name: string;
  status: IntruderSessionStatus;
  base_flow_id: string | null;
  endpoint_id: string | null;
  job_id: string | null;
  progress: IntruderProgress;
  estimate_attempts?: number | null;
  updated_at: string;
  created_at: string;
  failure_reason?: string | null;
  /** Compact "GET /path" from template for list density. */
  baseline_label?: string | null;
}

export interface TemplateVariable {
  name: string;
  location: VariableLocation;
  path?: string | null;
  original_value?: string | null;
  encoding?: string;
  semantic_type?: string;
  param_id?: string | null;
  fixed_value?: string | null;
}

export interface PayloadSetConfig {
  generator: string;
  options: Record<string, unknown>;
  processors?: string[];
}

export interface IntruderTemplate {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string | null;
  normalized_path?: string | null;
  variables?: TemplateVariable[];
}

export interface MatchRule {
  tag?: string;
  status?: number;
  body_contains?: string;
  regex?: string;
  length_delta_gt?: number;
  time_gt_ms?: number;
  [key: string]: unknown;
}

export interface GrepRule {
  name: string;
  regex: string;
  group?: number;
  source?: string;
  ignore_case?: boolean;
  max_matches?: number;
  to_pool?: boolean;
  tag_interesting?: boolean;
  [key: string]: unknown;
}

export interface IntruderConfig {
  schema_version?: number;
  session?: Record<string, unknown>;
  template?: IntruderTemplate;
  payload_sets?: Record<string, PayloadSetConfig>;
  strategy?: {
    type?: string;
    options?: Record<string, unknown>;
    primary?: string;
    sets?: string[];
  };
  timing?: {
    mode?: string;
    rps?: number;
    max_concurrency?: number;
    max_concurrency_per_host?: number | null;
    jitter_ms?: number;
    timeout_s?: number;
    burst_size?: number;
    min_rps?: number;
    max_rps?: number;
    slow_ms?: number;
  };
  slice?: { max_attempts?: number; max_wall_s?: number };
  storage?: {
    mode?: IntruderStorageMode | string;
    sample_rate?: number;
    store_interesting_bodies?: boolean;
    max_body_bytes?: number;
    max_results?: number;
  };
  match?: MatchRule[];
  grep?: GrepRule[];
  findings?: {
    promote?: boolean;
    on?: string;
    max_findings?: number;
    only_success?: boolean;
    cluster_by?: string;
  };
  safety?: {
    respect_logout?: boolean;
    respect_dangerous?: boolean;
    require_in_scope?: boolean;
    skip_auth_artifacts?: boolean;
    max_attempts?: number;
    max_duration_s?: number;
    auth_fail_threshold?: number;
  };
  [key: string]: unknown;
}

export interface IntruderSessionDetail extends IntruderSessionSummary {
  config: IntruderConfig;
  checkpoint?: Record<string, unknown>;
  control_flag?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  schema_version?: number;
}

export interface IntruderResultRow {
  id: string;
  session_id?: string;
  attempt_index: number;
  variables: Record<string, string>;
  status_code: number | null;
  success: boolean;
  failure_reason?: string | null;
  duration_ms: number | null;
  body_length: number | null;
  interesting: boolean;
  match_tags: string[];
  grepped?: Record<string, unknown>;
  fingerprint?: Record<string, unknown>;
  flow_id: string | null;
  finding_id: string | null;
  created_at?: string;
}

/** UI-only pending path-backed generator text keyed by variable name. */
export type ArtifactDrafts = Record<
  string,
  { kind: "wordlist" | "csv" | "json"; text: string }
>;

export interface SessionDraft {
  config: IntruderConfig;
  artifacts: ArtifactDrafts;
  serverUpdatedAt: string;
  dirty: boolean;
}

export type IntruderTab = "configure" | "run" | "results" | "advanced";

export interface IntruderSummary {
  running: number;
  paused: number;
  queued?: number;
  interesting_total: number;
  session_total?: number;
  last_activity_at?: string | null;
}

export type BaselineSource = "last_send" | "capture" | "flow";

export interface PoolSummary {
  name: string;
  count: number;
  session_id?: string | null;
  source_rule?: string | null;
  updated_at?: string;
  created_at?: string;
}

export interface PoolDetail extends PoolSummary {
  values: string[];
  truncated?: boolean;
}

/** UI suggestion from click-to-mark discovery. */
export interface InjectSuggestion {
  name: string;
  location: VariableLocation;
  path: string;
  original_value?: string | null;
  source: string;
}
