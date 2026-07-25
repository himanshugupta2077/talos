/**
 * Pure helpers for flow health chips and list signal icons.
 * Only derive from known flags Core stores — hide when unknown.
 */

export interface FlowFlagSources {
  request_body?: string | null;
  response_body?: string | null;
  request_body_truncated?: boolean | number | null;
  response_body_truncated?: boolean | number | null;
  original_flow_id?: string | null;
  method?: string | null;
  host?: string | null;
  has_auth_material?: boolean;
  derived?: {
    has_auth_material?: boolean;
    has_request_body?: boolean;
    has_response_body?: boolean;
    request_body_truncated?: boolean;
    response_body_truncated?: boolean;
    duration_ms?: number | null;
  };
  diff?: unknown | null;
  bac_result?: unknown | null;
  unauth_result?: unknown | null;
  auth_test_result?: unknown | null;
  results?: {
    diff?: unknown | null;
    bac?: unknown | null;
    unauth?: unknown | null;
    auth_test?: unknown | null;
  };
  endpoint_policy?: {
    qualified?: boolean | number | null;
    logout?: boolean | number | null;
    baseline_flow_id?: string | null;
  } | null;
  flow_meta?: Record<string, unknown> | null;
  replay_reason?: string | null;
  has_diff?: boolean;
  has_bac?: boolean;
  has_unauth?: boolean;
  has_finding_evidence?: boolean;
  is_replay?: boolean;
  body_truncated?: boolean;
}

export type HealthChipKind =
  | "body_stored"
  | "body_truncated"
  | "replay_available"
  | "diff_available"
  | "attack_result"
  | "auth_present"
  | "session_refresh"
  | "qualified"
  | "baseline"
  | "is_replay";

export interface HealthChip {
  kind: HealthChipKind;
  label: string;
  tone: "neutral" | "success" | "warning" | "info" | "error";
}

function truthy(v: unknown): boolean {
  return v === true || v === 1 || v === "1";
}

export function buildHealthChips(src: FlowFlagSources): HealthChip[] {
  const chips: HealthChip[] = [];
  const d = src.derived || {};
  const hasBody =
    d.has_request_body ||
    d.has_response_body ||
    !!src.request_body ||
    !!src.response_body;
  const truncated =
    truthy(d.request_body_truncated) ||
    truthy(d.response_body_truncated) ||
    truthy(src.request_body_truncated) ||
    truthy(src.response_body_truncated) ||
    truthy(src.body_truncated);

  if (truncated) {
    chips.push({ kind: "body_truncated", label: "Body truncated", tone: "warning" });
  } else if (hasBody) {
    chips.push({ kind: "body_stored", label: "Body stored", tone: "success" });
  }

  if (src.method && src.host) {
    const logout = truthy(src.endpoint_policy?.logout);
    if (!logout) {
      chips.push({ kind: "replay_available", label: "Replay available", tone: "neutral" });
    }
  }

  const diff = src.results?.diff ?? src.diff;
  if (diff || src.has_diff) {
    chips.push({ kind: "diff_available", label: "Diff", tone: "info" });
  }

  const attack =
    src.results?.bac ||
    src.results?.unauth ||
    src.results?.auth_test ||
    src.bac_result ||
    src.unauth_result ||
    src.auth_test_result ||
    src.has_bac ||
    src.has_unauth;
  if (attack) {
    chips.push({ kind: "attack_result", label: "Attack result", tone: "warning" });
  }

  if (d.has_auth_material || src.has_auth_material) {
    chips.push({ kind: "auth_present", label: "Auth present", tone: "info" });
  }

  const reason = (src.replay_reason || "").toLowerCase();
  const meta = src.flow_meta || {};
  const gen = String((meta as any).generated_by || (meta as any).reason || "").toLowerCase();
  if (reason.includes("refresh") || gen.includes("refresh") || gen.includes("session_refresh")) {
    chips.push({ kind: "session_refresh", label: "Session refresh", tone: "info" });
  }

  if (src.endpoint_policy) {
    if (truthy(src.endpoint_policy.qualified)) {
      chips.push({ kind: "qualified", label: "Qualified", tone: "success" });
    }
    if (src.endpoint_policy.baseline_flow_id) {
      chips.push({ kind: "baseline", label: "Has baseline", tone: "neutral" });
    }
  }

  if (src.original_flow_id || src.is_replay) {
    chips.push({ kind: "is_replay", label: "Replay", tone: "neutral" });
  }

  return chips;
}

export function formatDurationMs(ms: number | null | undefined): string | null {
  if (ms == null || Number.isNaN(ms)) return null;
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function methodBadgeClass(method: string): string {
  const m = (method || "").toUpperCase();
  switch (m) {
    case "GET":
      return "badge-info";
    case "POST":
      return "badge-success";
    case "PUT":
    case "PATCH":
      return "badge-warning";
    case "DELETE":
      return "badge-error";
    default:
      return "badge-ghost";
  }
}
