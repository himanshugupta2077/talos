/** Shared types and constants for Secret Detection (passive scan) workspace. */

export type PassiveTab =
  | "overview"
  | "detections"
  | "documents"
  | "rules"
  | "settings";

export const PASSIVE_TABS: { id: PassiveTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "detections", label: "Detections" },
  { id: "documents", label: "Documents" },
  { id: "rules", label: "Rules" },
  { id: "settings", label: "Settings" },
];

export function isPassiveTab(v: string | null): v is PassiveTab {
  return (
    v === "overview" ||
    v === "detections" ||
    v === "documents" ||
    v === "rules" ||
    v === "settings"
  );
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const CONFIDENCE_LEVELS = [
  "",
  "CONFIRMED_PATTERN",
  "HIGH",
  "MEDIUM",
  "OBSERVATION_ONLY",
] as const;

export const CATEGORIES = [
  "",
  "secret",
  "infrastructure_disclosure",
  "sensitive_info",
] as const;

export const SOURCE_KINDS = [
  "",
  "html",
  "javascript",
  "json",
  "xml",
  "text",
  "css",
  "sourcemap",
  "wasm",
  "unknown",
] as const;

export const SCAN_STATUSES = [
  "",
  "pending",
  "scanned",
  "skipped",
  "error",
  "too_large",
] as const;

export const AUTO_FINDING_THRESHOLDS = [
  "CONFIRMED_PATTERN",
  "HIGH",
  "MEDIUM",
  "OFF",
] as const;

export interface PassiveConfig {
  enabled: boolean;
  auto_finding_threshold: string;
  max_document_size: number;
  max_decode_depth: number;
  max_decode_bytes: number;
  max_candidates_per_document: number;
  scan_html: boolean;
  scan_javascript: boolean;
  scan_json: boolean;
  scan_xml: boolean;
  scan_text: boolean;
  scan_css: boolean;
  scan_sourcemaps: boolean;
  scan_wasm: boolean;
  store_raw_secret_in_evidence: boolean;
  store_suppressed_detections: boolean;
  queue_maxsize: number;
  max_scan_time_ms: number;
}

export interface PassiveStatus {
  enabled: boolean;
  auto_finding_threshold: string;
  scanner_version: string;
  documents: number;
  documents_scanned: number;
  documents_pending: number;
  documents_error: number;
  documents_too_large: number;
  detections: number;
  detections_with_finding: number;
  stale_documents: number;
  queue_maxsize: number;
  by_confidence: Record<string, number>;
  by_category: Record<string, number>;
  by_source_kind: Record<string, number>;
  by_scan_status: Record<string, number>;
}

export interface DetectionRow {
  id: string;
  document_id: string;
  occurrence_id: string | null;
  detector_id: string;
  detector_family: string;
  category: string;
  secret_type: string;
  matched_key: string | null;
  redacted_value: string;
  value_fingerprint: string;
  confidence_score: number;
  confidence_level: string;
  entropy: number | null;
  encoding_chain: string[];
  decode_depth: number;
  match_start?: number;
  match_end?: number;
  context_before?: string;
  context_after?: string;
  suppressed: boolean;
  suppression_reason: string | null;
  finding_id: string | null;
  raw_value_stored?: boolean;
  created_at: string | null;
}

export interface DocumentRow {
  id: string;
  project_id?: string;
  body_hash: string;
  source_kind: string;
  body_size: number;
  truncated: boolean;
  scanner_version: string | null;
  scan_status: string;
  first_flow_id: string | null;
  parent_document_id: string | null;
  logical_source_name: string | null;
  first_seen: string | null;
  last_seen: string | null;
  last_scanned_at: string | null;
  error_message?: string | null;
  stale?: boolean;
}

export interface OccurrenceRow {
  id: string;
  document_id: string;
  flow_id: string;
  endpoint_id: string | null;
  url: string;
  host: string;
  path: string;
  logical_source_name: string | null;
  content_type: string;
  observed_at: string;
  role_id: string;
  module_id: string;
}

export interface RuleRow {
  id: string;
  name: string;
  family: string;
  secret_type: string;
  confidence_level: string;
  enabled: boolean;
  pack: string;
  finding_title: string;
}

export function confidenceChipClass(level: string): string {
  switch ((level || "").toUpperCase()) {
    case "CONFIRMED_PATTERN":
      return "badge-success";
    case "HIGH":
      return "badge-warning";
    case "MEDIUM":
      return "badge-info badge-outline";
    default:
      return "badge-ghost";
  }
}

export function categoryChipClass(category: string): string {
  switch (category) {
    case "secret":
      return "badge-error badge-outline";
    case "infrastructure_disclosure":
      return "badge-warning badge-outline";
    case "sensitive_info":
      return "badge-info badge-outline";
    default:
      return "badge-ghost";
  }
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "—";
  return id.length > n ? id.slice(0, n) : id;
}
