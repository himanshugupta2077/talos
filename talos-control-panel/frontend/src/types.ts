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

/** Role×module access map cell (GET /api/access/matrix). */
export interface AccessCell {
  role_id: string;
  role_name: string;
  module_id: string;
  module_name: string;
  client_allowed: string | null;
  server_expected: string | null;
  flow_count?: number;
  endpoint_count?: number;
}

export type AccessValue = "ALLOW" | "DENY" | "UNKNOWN";

export type AccessBulkOpName =
  | "client_set"
  | "server_set"
  | "client_unset"
  | "server_unset"
  | "delete";

export interface AccessBulkOp {
  op: AccessBulkOpName;
  role: string;
  module: string;
  value?: string;
}

export interface AccessBulkResponse extends StepsResponse {
  ok: boolean;
  applied: number;
  failed: number;
}

export interface AccessCoverageRow {
  role_name: string;
  module_name: string;
  client_allowed: string | null;
  server_expected: string | null;
  flow_count: number;
  endpoint_count: number;
}

export interface AccessMultiRoleEndpoint {
  endpoint_id: string;
  method: string;
  host: string;
  normalized_path: string;
  role_count: number;
  role_names: string;
}

export interface AccessServerDenyEndpoint {
  endpoint_id: string;
  method: string;
  host: string;
  normalized_path: string;
  role_name: string;
  module_name: string;
  client_allowed: string | null;
  server_expected: string;
  flow_count: number;
  flow_ids?: string[];
}

export interface AccessPairSignal {
  role_id?: string;
  role_name: string;
  module_id?: string;
  module_name: string;
  client_allowed: string | null;
  server_expected?: string | null;
  flow_count?: number;
}

export interface AccessSignals {
  multi_role: AccessMultiRoleEndpoint[];
  server_deny_endpoints: AccessServerDenyEndpoint[];
  deny_with_flows: AccessPairSignal[];
  allow_without_flows: AccessPairSignal[];
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
  /** Present when list is called with include=flags */
  is_replay?: boolean;
  body_truncated?: boolean;
  has_diff?: boolean;
  has_bac?: boolean;
  has_unauth?: boolean;
  has_finding_evidence?: boolean;
}

/** Presentation helpers from GET /api/flows/{id} — not Core verdicts. */
export interface FlowDerived {
  duration_ms?: number | null;
  request_body_size?: number;
  response_body_size?: number;
  has_auth_material?: boolean;
  request_body_truncated?: boolean;
  response_body_truncated?: boolean;
  is_replay?: boolean;
  has_request_body?: boolean;
  has_response_body?: boolean;
}

export interface FlowResults {
  diff?: Record<string, any> | null;
  bac?: Record<string, any> | null;
  unauth?: Record<string, any> | null;
  auth_test?: Record<string, any> | null;
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
  request_body_truncated?: boolean;
  status_code: number | null;
  response_headers: Record<string, string>;
  response_body: string | null;
  response_body_encoding?: string;
  response_body_truncated?: boolean;
  content_type: string;
  session_id: string | null;
  endpoint_id: string | null;
  role_id?: string;
  module_id?: string;
  role_name: string;
  module_name: string;
  tags: string[];
  source: string;
  original_flow_id: string | null;
  replay_error: string | null;
  replay_reason: string | null;
  flow_meta: Record<string, any>;
}

/** Full detail API envelope (preferred shape). */
export interface FlowDetailBundle {
  flow: FlowDetail;
  derived?: FlowDerived;
  results?: FlowResults;
  endpoint_policy?: Record<string, any> | null;
  /** @deprecated use results.diff */
  diff?: Record<string, any> | null;
  /** @deprecated use results.bac */
  bac_result?: Record<string, any> | null;
  /** @deprecated use results.unauth */
  unauth_result?: Record<string, any> | null;
  /** @deprecated use results.auth_test */
  auth_test_result?: Record<string, any> | null;
}

// ------------------------------------------------------------------ #
// Repeater / send API                                                 #
// ------------------------------------------------------------------ #

export type SendEditorMode = "raw" | "pretty" | "params" | "json-assist";

/** One HTTP side (request or response) returned on send hydrate. */
export interface FlowHttpSide {
  method?: string;
  url?: string;
  host?: string;
  path?: string;
  query?: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  body_base64?: string | null;
  body_encoding?: "utf8" | "base64" | string;
  body_len?: number;
  status_code?: number | null;
  content_type?: string;
}

export interface SendDraftResponse {
  parent_flow_id: string;
  original_flow_id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  request_headers: Record<string, string>;
  request_cookies: Record<string, string>;
  request_body: string | null;
  request_body_base64: string | null;
  request_body_encoding: "utf8" | "base64" | string;
  request_body_len: number;
  raw: string | null;
  raw_base64: string | null;
  raw_encoding: "utf8" | "base64" | string;
  endpoint_id: string | null;
  parent_source: string | null;
  baseline_status_code: number | null;
  endpoint_annotations: string[];
}

export interface SendOutcomeDto {
  execution_flow_id: string | null;
  parent_flow_id: string;
  original_flow_id: string;
  status_code: number | null;
  success: boolean;
  failure_reason: string | null;
  verdict: "SAME" | "DIFFERENT" | "ERROR" | string | null;
  request_body_len: number;
  response_body_len: number;
  source: "manual_send" | "ai_send" | string;
  session_id: string | null;
  profile: string;
  profile_index: number;
  profile_count: number;
  note: string | null;
  duration_ms: number | null;
  normalizers?: string[];
  response?: FlowHttpSide;
  request_as_sent?: FlowHttpSide;
}

export interface SendMutationResponse {
  steps: CommandResult[];
  result: {
    profile: string;
    profile_count: number;
    original_flow_id: string;
    parent_flow_id: string;
    outcomes: SendOutcomeDto[];
  };
}

export interface SendHistoryRow {
  id: string;
  parent_flow_id: string | null;
  session_id: string | null;
  method: string;
  url: string;
  status_code: number | null;
  source: string;
  verdict: string | null;
  note: string | null;
  profile: string | null;
  profile_index: number | null;
  profile_count: number | null;
  request_body_len: number;
  response_body_len: number;
  captured_at: string;
  replay_error: string | null;
  duration_ms: number | null;
}

export interface SendHistoryResponse {
  original_flow_id: string;
  count: number;
  executions: SendHistoryRow[];
}

export interface SendTreeNode {
  id: string;
  parent_flow_id: string | null;
  depth: number;
  method: string;
  url: string;
  status_code: number | null;
  verdict: string | null;
  session_id: string | null;
  note: string | null;
  captured_at: string;
  duration_ms: number | null;
  children: SendTreeNode[];
}

export interface SendTreeResponse {
  original_flow_id: string;
  count: number;
  nodes: SendTreeNode[];
  lines: string[];
}

export interface SendDupResponse {
  steps: CommandResult[];
  result: {
    session_id: string;
    parent_flow_id: string;
    original_flow_id: string;
  };
}

export interface SendExportResponse {
  steps: CommandResult[];
  result: {
    flow_id: string;
    request_http_base64: string;
    response_http_base64: string;
    request_bytes: number;
    response_bytes: number;
  };
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
  /** PRIMARY (default cluster head) or LINKED (technique variant under a PRIMARY). */
  relation_type?: "PRIMARY" | "LINKED" | string | null;
  parent_finding_id?: string | null;
  cluster_key?: string | null;
  /** Number of LINKED children (PRIMARY rows only; from list/detail SQL). */
  linked_count?: number;
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
