import type { ProxyRuntimeStatus } from "../../api/client";

export interface DashboardProject {
  id: string;
  name: string;
  description: string;
  active: boolean;
  status: string;
  db_exists: boolean;
  data_dir: string;
  scope: string[];
  scope_count: number;
  outscope_count: number;
  constraints: {
    capture_in_scope_only: boolean;
    store_bodies: boolean;
    max_body_size: number;
  };
  roles: number;
  modules: number;
  created_at?: string | null;
}

export interface DashboardReadiness {
  active: boolean;
  db: boolean;
  scope: boolean;
  proxy: boolean;
  session: "ok" | "degraded" | "unconfigured" | string;
  queue_pressure: boolean;
  triaging: number;
}

export interface DashboardFindings {
  by_status: Record<string, number>;
  by_attack_type: { type: string; n: number }[];
  groups_open: number;
  recent_triaging: {
    id: string;
    title?: string | null;
    attack_type?: string | null;
    verdict?: string | null;
    status?: string | null;
    created_at?: string | null;
  }[];
}

export interface DashboardScheduler {
  state: { state?: string; reason?: string | null } | null;
  counts: Record<string, number>;
  config: {
    min_delay?: number | null;
    max_delay?: number | null;
    max_queue_size?: number | null;
  } | null;
  active_queue: number;
  queue_fill_pct: number;
  recent_failed: {
    id: string;
    job_type?: string | null;
    status?: string | null;
    failure_reason?: string | null;
    priority?: number | null;
    created_at?: string | null;
    updated_at?: string | null;
  }[];
  by_job_type_active: { job_type: string; n: number }[];
}

export interface DashboardEndpoints {
  inventory: {
    total: number;
    testable: number;
    excluded: number;
    dangerous: number;
    logout: number;
    unqualified: number;
  };
  policy: {
    by_priority: Record<string, number>;
    manual_overrides: number;
    rule_controlled: number;
    auto_controlled: number;
    total: number;
  };
  coverage: {
    qualified_pct: number;
    baseline_pct: number;
    multi_role_pct: number;
    params_pct: number;
    excluded_pct: number;
  };
}

export interface DashboardFlows {
  total: number;
  by_source: Record<string, number>;
  by_status_class: Record<string, number>;
  distinct_hosts: number;
  distinct_methods: number;
  last_captured_at: string | null;
}

export interface DashboardSessionRole {
  role_id: string;
  role_name: string;
  is_active: boolean;
  provider: string | null;
  configured: boolean;
  health_degraded: boolean;
  suspicion_count: number;
  suspicion_threshold: number;
  expires_in_seconds: number | null;
  session_age_seconds: number | null;
  control_flow_count: number;
  artifact_count: number;
}

export interface DashboardHttpRules {
  enabled: boolean;
  summary: {
    active: number;
    request: number;
    response: number;
    disabled: number;
    total: number;
  };
}

export interface DashboardTalosConfig {
  source_counts: Record<string, number>;
  sections: {
    section: string;
    label: string;
    summary: string;
    source: string;
  }[];
  key_flags: Record<string, unknown>;
}

export interface DashboardPassive {
  enabled: boolean;
  scanner_version: string | null;
  documents: number;
  documents_pending: number;
  detections: number;
  detections_with_finding: number;
  stale_documents: number;
}

export interface ProjectDashboard {
  project: DashboardProject;
  readiness: DashboardReadiness;
  findings: DashboardFindings;
  scheduler: DashboardScheduler;
  proxy: ProxyRuntimeStatus;
  endpoints: DashboardEndpoints;
  flows: DashboardFlows;
  session_health: DashboardSessionRole[];
  http_rules: DashboardHttpRules;
  talos_config: DashboardTalosConfig;
  passive?: DashboardPassive;
}
