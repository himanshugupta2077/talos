export interface ProjectConstraints {
  capture_in_scope_only: boolean;
  store_bodies: boolean;
  max_body_size: number;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  scope: string[];
  created_at?: string;
  status?: "active" | "inactive" | string;
  constraints?: ProjectConstraints;
  data_dir: string;
  db_path?: string;
  db_exists: boolean;
  active: boolean;
}

export interface ProjectSummary {
  flows: number;
  endpoints: number;
  findings_triaging: number;
  findings_confirmed: number;
  scheduler_pending: number;
  roles: number;
  modules: number;
}

/** Out-of-scope Basic Scope prefix entry (domain field is a legacy alias). */
export interface OutscopeDomain {
  id?: string | number;
  prefix?: string;
  domain: string;
  created_at?: string;
}

export interface ScopePrefixEntry {
  prefix: string;
}

export interface CommandResult {
  cmd: string[];
  cmd_str: string;
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
  ok: boolean;
  timed_out?: boolean;
}

export interface StepsResponse {
  steps: CommandResult[];
}

export interface Role {
  id: string;
  name: string;
  is_active: number;
}

export interface Module {
  id: string;
  name: string;
  description: string;
  is_active: number;
}

export interface EndpointRow {
  id: string;
  method: string;
  host: string;
  origin?: string;
  normalized_path: string;
  path?: string;
  auth_required?: number | boolean;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  parameter_count?: number;
  roles: string | null;
  roles_list?: string[];
  modules: string | null;
  /** Resolved effective priority (CRITICAL|HIGH|NORMAL|LOW). */
  effective_priority?: string | null;
  /** MANUAL | RULE | AUTO */
  priority_source?: string | null;
  priority_rule_id?: string | null;
  matching_rule?: string | null;
  auto_priority: string | null;
  manual_priority: string | null;
  excluded: number | boolean | null;
  exclusion_source?: string | null;
  dangerous: number | boolean | null;
  logout: number | boolean | null;
  qualified: number | boolean | null;
  qualification_reason: string | null;
  baseline_flow_id?: string | null;
  baseline_status?: number | null;
  tags?: string[];
  decision?: "TESTABLE" | "SKIPPED" | string;
  state?: string;
}

export interface EndpointInventorySummary {
  total: number;
  testable: number;
  excluded: number;
  dangerous: number;
  logout: number;
  unqualified: number;
}

export interface EndpointPolicySummary {
  total: number;
  testable: number;
  excluded: number;
  unqualified: number;
  manual_overrides: number;
  rule_controlled: number;
  auto_controlled: number;
  by_priority: Record<string, number>;
}

export interface EndpointPolicyExplanation {
  endpoint?: {
    id: string;
    method?: string;
    origin?: string;
    host?: string;
    path?: string;
    label?: string;
  };
  decision?: string;
  priority?: {
    effective: string;
    source: string;
    manual?: string | null;
    rule?: { id?: string; pattern?: string; priority?: string } | null;
    auto?: { priority?: string; score?: number; breakdown?: Record<string, number> };
  };
  exclusion?: {
    effective: boolean;
    source?: string | null;
    rule_id?: string | null;
    rule_pattern?: string | null;
  };
  qualification?: { qualified: boolean; reason?: string };
  safety?: { dangerous: boolean; logout: boolean };
  baseline?: { flow_id?: string | null; status?: number | null };
  tags?: string[];
  notes?: string;
  // flat compat
  effective_level?: string;
  source?: string;
  excluded?: boolean;
  dangerous?: boolean;
  logout?: boolean;
  qualified?: boolean;
  qualification_reason?: string;
  baseline_flow_id?: string | null;
  baseline_status?: number | null;
}

export interface PolicyRule {
  id: string;
  pattern: string;
  priority: string | null;
  excluded: boolean;
  created_at?: string;
  matches?: number;
  multi_rule_matches?: number;
  effect?: string;
  priority_changes?: number;
  newly_excluded?: number;
}

export interface BulkMutationResult {
  steps: CommandResult[];
  bulk?: {
    action?: string;
    affected?: number;
    unchanged?: number;
    affected_ids?: string[];
    unchanged_ids?: string[];
    count?: number;
    endpoints?: any[];
  };
  ok?: boolean;
}

export interface EndpointCoverage {
  total: number;
  cards: {
    qualified_pct: number;
    baseline_pct: number;
    multi_role_pct: number;
    parameters_pct: number;
    excluded_pct: number;
    qualified: number;
    with_baseline: number;
    multi_role: number;
    with_parameters: number;
    excluded: number;
  };
  qualification: Record<string, any>;
  baseline: {
    ready: number;
    missing: number;
    missing_by_reason: Record<string, number>;
  };
  roles: {
    by_role: { name: string; endpoints: number }[];
    coverage_buckets: Record<string, number>;
    role_names: string[];
    table: {
      id: string;
      method: string;
      path: string;
      roles: Record<string, boolean>;
      coverage: string;
      role_count: number;
    }[];
  };
  parameters: {
    endpoints_with_parameters: number;
    by_location: Record<string, number>;
    heavy: any[];
  };
}

export interface Parameter {
  id: string;
  endpoint_id: string;
  name: string;
  location: string;
  param_type: string;
  semantic_type: string;
  source: string;
  volatility: string;
  sensitivity: string;
  example_values: string[];
  seen_count: number;
  appears_in_roles: string[];
  appears_in_modules: string[];
  is_reflected: number;
  reflection_count: number;
  reflection_locations: string[];
  reflection_encoding: string;
}

export interface FlowRow {
  id: string;
  method: string;
  host: string;
  path: string;
  query: string;
  status_code: number | null;
  source: string;
  captured_at: string;
  endpoint_id: string | null;
  original_flow_id: string | null;
  replay_reason: string | null;
  role_name: string;
  module_name: string;
}

export interface FlowDetail {
  id: string;
  project_id: string;
  captured_at: string;
  response_end: string | null;
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  request_headers: Record<string, string>;
  request_cookies: Record<string, string>;
  request_body: string | null;
  request_body_encoding?: string;
  status_code: number | null;
  response_headers: Record<string, string>;
  response_body: string | null;
  response_body_encoding?: string;
  content_type: string;
  session_id: string | null;
  endpoint_id: string | null;
  role_name: string;
  module_name: string;
  tags: string[];
  source: string;
  original_flow_id: string | null;
  replay_error: string | null;
  replay_reason: string | null;
  flow_meta: Record<string, any>;
}

export interface Finding {
  id: string;
  project_id: string;
  attack_type: string;
  verdict: string;
  endpoint_id: string | null;
  status: "TRIAGING" | "CONFIRMED" | "REJECTED" | "DUPLICATE";
  duplicate_of: string | null;
  created_at: string;
  updated_at: string;
  title: string;
  notes: string;
  role_name?: string | null;
  module_name?: string | null;
}

export interface FindingGroup {
  id: string;
  project_id: string;
  name: string;
  created_at: string;
  member_count: number;
}

export interface SchedulerJob {
  job_id: string;
  endpoint_id: string | null;
  resolved_endpoint_id?: string | null;
  flow_id: string | null;
  job_type: string;
  priority: number;
  status: string;
  created_at: string;
  scheduled_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  failure_reason: string | null;
  replayed_flow_id: string | null;
  verdict: string | null;
  role_name?: string | null;
  module_name?: string | null;
  meta: Record<string, any>;
}

export interface CommandArgSpec {
  name: string;
  label: string;
  flag: string | null;
  kind: "text" | "number" | "boolean" | "select" | "multi";
  required: boolean;
  help: string;
  options: string[];
  default: any;
}

export interface CommandSpec {
  id: string;
  path: string[];
  summary: string;
  args: CommandArgSpec[];
  background: boolean;
}

export interface CommandGroup {
  group: string;
  label: string;
  commands: CommandSpec[];
}
