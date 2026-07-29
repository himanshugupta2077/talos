/** Shared types and constants for Error Intelligence workspace. */

export { ERRORS_BASE } from "../attack/registry";

export type ErrorIntelTab = "overview" | "errors" | "rollups" | "settings";

export const ERROR_INTEL_TABS: { id: ErrorIntelTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "errors", label: "Errors" },
  { id: "rollups", label: "Rollups" },
  { id: "settings", label: "Settings" },
];

export function isErrorIntelTab(v: string | null): v is ErrorIntelTab {
  return (
    v === "overview" || v === "errors" || v === "rollups" || v === "settings"
  );
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

/** From talos.error_intel.constants.ERROR_SEVERITIES */
export const ERROR_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type ErrorSeverity = (typeof ERROR_SEVERITIES)[number];

/** Default list filter: medium+ (excludes low only). Locked KD #11. */
export const DEFAULT_SEVERITY_FILTER: ErrorSeverity[] = [
  "medium",
  "high",
  "critical",
];

/** From talos.error_intel.constants.ERROR_CATEGORIES */
export const ERROR_CATEGORIES = [
  "stack_trace",
  "database",
  "framework",
  "infrastructure",
  "security",
  "validation",
  "http",
  "disclosure",
  "unknown",
] as const;
export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

export const ATTACK_TYPES = [
  "proxy",
  "replay",
  "iv",
  "bac",
  "unauth",
  "unknown",
] as const;
export type AttackType = (typeof ATTACK_TYPES)[number];

/** CLI _cluster_row shape */
export interface ErrorClusterRow {
  id: string;
  project_id: string;
  fingerprint: string;
  category: string;
  severity: string;
  language: string;
  framework: string | null;
  database: string | null;
  server: string | null;
  exception_type: string | null;
  message_norm: string | null;
  technologies: string[];
  has_stack_trace: boolean;
  has_path_leak: boolean;
  has_internal_host: boolean;
  has_version_leak: boolean;
  confidence: number;
  evidence_snippet: string | null;
  first_seen: string | null;
  last_seen: string | null;
  observation_count: number;
  scanner_version: string | null;
}

/** CLI _obs_row shape */
export interface ErrorObservationRow {
  id: string;
  error_id: string;
  flow_id: string | null;
  endpoint_id: string | null;
  parameter_uuid: string | null;
  parameter_name: string | null;
  attack_type: string;
  payload_redacted: string | null;
  response_status: number | null;
  response_length: number | null;
  duration_ms: number | null;
  response_hash: string | null;
  detectors: string[];
  artifacts: { kind: string; value: string; normalized?: string | null }[];
  observed_at: string | null;
}

export interface ErrorIntelConfig {
  enabled: boolean;
  store_generic_http_errors: boolean;
  max_body_scan: number;
  gate_sniff_bytes: number;
  queue_maxsize: number;
  evidence_snippet_max: number;
  error_header_names: string[];
}

export interface ErrorIntelStatus {
  enabled: boolean;
  store_generic_http_errors: boolean;
  scanner_version: string;
  clusters: number;
  observations: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  queue_maxsize: number;
  max_body_scan: number;
}

export interface ErrorIntelEmptyState {
  disabled?: boolean;
  no_clusters?: boolean;
  no_observations?: boolean;
}

export interface ErrorByFlowResponse {
  observation_count: number;
  observations: ErrorObservationRow[];
  clusters: ErrorClusterRow[];
  scanner_enabled: boolean;
}

export interface ParameterRollupRow {
  parameter_uuid?: string | null;
  parameter_name?: string | null;
  error_id?: string | null;
  category?: string | null;
  severity?: string | null;
  exception_type?: string | null;
  observation_count?: number;
  attack_types?: string[];
  [key: string]: unknown;
}

export interface EndpointRollupRow {
  endpoint_id?: string | null;
  error_id?: string | null;
  category?: string | null;
  severity?: string | null;
  exception_type?: string | null;
  observation_count?: number;
  attack_types?: string[];
  [key: string]: unknown;
}

export function severityBadgeClass(severity: string): string {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "badge-error";
    case "high":
      return "badge-warning";
    case "medium":
      return "badge-info";
    case "low":
      return "badge-ghost";
    default:
      return "badge-ghost";
  }
}

export function categoryBadgeClass(category: string): string {
  switch (category) {
    case "stack_trace":
    case "database":
      return "badge-error badge-outline";
    case "security":
    case "disclosure":
      return "badge-warning badge-outline";
    case "framework":
    case "validation":
      return "badge-info badge-outline";
    case "infrastructure":
    case "http":
      return "badge-ghost";
    default:
      return "badge-ghost";
  }
}

export function attackTypeBadgeClass(attackType: string): string {
  switch ((attackType || "").toLowerCase()) {
    case "iv":
    case "bac":
    case "unauth":
      return "badge-secondary badge-outline";
    case "proxy":
      return "badge-success badge-outline";
    case "replay":
      return "badge-info badge-outline";
    default:
      return "badge-ghost";
  }
}

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "—";
  return id.length > n ? id.slice(0, n) : id;
}

export function clusterTitle(c: ErrorClusterRow): string {
  if (c.exception_type) return c.exception_type;
  if (c.message_norm) {
    return c.message_norm.length > 80
      ? `${c.message_norm.slice(0, 80)}…`
      : c.message_norm;
  }
  return c.category || "error cluster";
}

export function severityParam(severities: ErrorSeverity[] | null): string | undefined {
  if (!severities || severities.length === 0) return undefined;
  if (severities.length === ERROR_SEVERITIES.length) return undefined;
  return severities.join(",");
}

/** Best-effort display mask for obvious secrets in evidence snippets (not complete redaction). */
export function maskSensitiveDisplay(text: string): string {
  return text
    .replace(/(password\s*[=:]\s*)([^\s&;,"']+)/gi, "$1***")
    .replace(/(jdbc:[^\s"']+)/gi, "jdbc:***")
    .replace(/(api[_-]?key\s*[=:]\s*)([^\s&;,"']+)/gi, "$1***")
    .replace(/(authorization\s*[=:]\s*)([^\s&;,"']+)/gi, "$1***")
    .replace(/(bearer\s+)([a-z0-9._\-]+)/gi, "$1***");
}
