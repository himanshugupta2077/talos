/**
 * Shared types and K13 query helpers for URL Sink Discovery workspace.
 *
 * FE searchParams keys must equal API inventory query param names (K13).
 * Forbidden aliases: nrs, q, has_iv.
 */

import { IV_BASE, URL_SINKS_BASE } from "../attack/registry";

export { IV_BASE, URL_SINKS_BASE };

export type UrlSinkTab = "overview" | "inventory" | "rollups" | "settings";

export const URL_SINK_TABS: { id: UrlSinkTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "inventory", label: "Inventory" },
  { id: "rollups", label: "Rollups" },
  { id: "settings", label: "Settings" },
];

export function isUrlSinkTab(v: string | null): v is UrlSinkTab {
  return (
    v === "overview" ||
    v === "inventory" ||
    v === "rollups" ||
    v === "settings"
  );
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

/** Defaults match API / design K7 + K13. */
export const DEFAULT_MIN_SCORE = 45;
export const DEFAULT_NRS_ONLY = true;
export const DEFAULT_SORT = "score_desc";
export const DEFAULT_LIMIT = 200;

export const SORT_OPTIONS = [
  { value: "score_desc", label: "score ↓" },
  { value: "score_asc", label: "score ↑" },
  { value: "name", label: "name" },
  { value: "host", label: "host" },
] as const;

export type InventorySort = (typeof SORT_OPTIONS)[number]["value"];

/** Stable name categories from talos.url_sink.catalog (Appendix A). */
export const SINK_CATEGORIES = [
  "redirect",
  "webhook",
  "remote_fetch",
  "remote_asset",
  "import_metadata",
  "infrastructure",
  "network_probe",
  "path_like",
  "oauth",
] as const;

export const LOOKS_LIKE_OPTIONS = [
  "url",
  "hostname",
  "ip",
  "path",
  "unc",
  "scheme",
] as const;

export const LOCATION_OPTIONS = [
  "query",
  "body",
  "header",
  "cookie",
  "path",
  "response",
] as const;

/** Tri-state filter: null = any, true/false = require yes/no. */
export type TriBool = boolean | null;

/** Canonical inventory filter state (K13). */
export interface InventoryFilters {
  min_score: number;
  nrs_only: boolean;
  category: string;
  looks_like: string;
  location: string;
  host: string;
  endpoint_id: string;
  /** PR5 — require IV profile presence */
  has_iv_profile: TriBool;
  /** PR5 — require observed.url_sink.confidence > 0 */
  has_url_sink_obs: TriBool;
  search: string;
  sort: InventorySort;
  limit: number;
  offset: number;
  include_iv: boolean;
}

export function defaultInventoryFilters(
  overrides: Partial<InventoryFilters> = {},
): InventoryFilters {
  return {
    min_score: DEFAULT_MIN_SCORE,
    nrs_only: DEFAULT_NRS_ONLY,
    category: "",
    looks_like: "",
    location: "",
    host: "",
    endpoint_id: "",
    has_iv_profile: null,
    has_url_sink_obs: null,
    search: "",
    sort: DEFAULT_SORT,
    limit: DEFAULT_LIMIT,
    offset: 0,
    include_iv: false,
    ...overrides,
  };
}

/** Parse bool query: true/false/1/0 (case-insensitive). Empty → default. */
export function parseBoolParam(
  raw: string | null,
  defaultValue: boolean,
): boolean {
  if (raw == null || raw === "") return defaultValue;
  const s = raw.trim().toLowerCase();
  if (s === "1" || s === "true" || s === "yes" || s === "on") return true;
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return defaultValue;
}

/**
 * Optional tri-state bool: missing/empty → null; true/false when set.
 * Used for has_iv_profile / has_url_sink_obs.
 */
export function parseOptionalBoolParam(raw: string | null): TriBool {
  if (raw == null || raw === "") return null;
  const s = raw.trim().toLowerCase();
  if (s === "1" || s === "true" || s === "yes" || s === "on") return true;
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return null;
}

export function parseIntParam(
  raw: string | null,
  defaultValue: number,
  min?: number,
  max?: number,
): number {
  if (raw == null || raw === "") return defaultValue;
  const n = Number(raw);
  if (!Number.isFinite(n)) return defaultValue;
  let v = Math.trunc(n);
  if (min != null) v = Math.max(min, v);
  if (max != null) v = Math.min(max, v);
  return v;
}

export function parseSortParam(raw: string | null): InventorySort {
  if (
    raw === "score_desc" ||
    raw === "score_asc" ||
    raw === "name" ||
    raw === "host"
  ) {
    return raw;
  }
  return DEFAULT_SORT;
}

/**
 * Read inventory filters from URLSearchParams (K13 keys only).
 * Does not require `tab` — caller handles tab separately.
 */
export function filtersFromSearchParams(
  params: URLSearchParams,
): InventoryFilters {
  return defaultInventoryFilters({
    min_score: parseIntParam(params.get("min_score"), DEFAULT_MIN_SCORE, 0, 100),
    nrs_only: parseBoolParam(params.get("nrs_only"), DEFAULT_NRS_ONLY),
    category: params.get("category") || "",
    looks_like: params.get("looks_like") || "",
    location: params.get("location") || "",
    host: params.get("host") || "",
    endpoint_id: params.get("endpoint_id") || "",
    has_iv_profile: parseOptionalBoolParam(params.get("has_iv_profile")),
    has_url_sink_obs: parseOptionalBoolParam(params.get("has_url_sink_obs")),
    search: params.get("search") || "",
    sort: parseSortParam(params.get("sort")),
    limit: parseIntParam(params.get("limit"), DEFAULT_LIMIT, 1, 1000),
    offset: parseIntParam(params.get("offset"), 0, 0),
    include_iv: parseBoolParam(params.get("include_iv"), false),
  });
}

/**
 * Write inventory filters into URLSearchParams.
 * Omits empty optionals; always writes defaults for min_score / nrs_only / sort
 * when on inventory tab so deep-links are shareable and match API.
 */
export function applyFiltersToSearchParams(
  base: URLSearchParams,
  filters: InventoryFilters,
  opts: { tab?: UrlSinkTab; compactDefaults?: boolean } = {},
): URLSearchParams {
  const next = new URLSearchParams(base);
  if (opts.tab) next.set("tab", opts.tab);

  const compact = opts.compactDefaults !== false;

  const setOrDelete = (key: string, value: string, isDefault: boolean) => {
    if (compact && isDefault) next.delete(key);
    else if (value) next.set(key, value);
    else next.delete(key);
  };

  // Always persist core filter state for shareable inventory deep-links
  next.set("min_score", String(filters.min_score));
  next.set("nrs_only", filters.nrs_only ? "true" : "false");

  setOrDelete("category", filters.category, !filters.category);
  setOrDelete("looks_like", filters.looks_like, !filters.looks_like);
  setOrDelete("location", filters.location, !filters.location);
  setOrDelete("host", filters.host, !filters.host);
  setOrDelete("endpoint_id", filters.endpoint_id, !filters.endpoint_id);
  setOrDelete("search", filters.search, !filters.search);

  if (filters.has_iv_profile == null) next.delete("has_iv_profile");
  else next.set("has_iv_profile", filters.has_iv_profile ? "true" : "false");

  if (filters.has_url_sink_obs == null) next.delete("has_url_sink_obs");
  else
    next.set("has_url_sink_obs", filters.has_url_sink_obs ? "true" : "false");

  if (compact && filters.sort === DEFAULT_SORT) next.delete("sort");
  else next.set("sort", filters.sort);

  if (compact && filters.limit === DEFAULT_LIMIT) next.delete("limit");
  else next.set("limit", String(filters.limit));

  if (compact && filters.offset === 0) next.delete("offset");
  else next.set("offset", String(filters.offset));

  if (compact && !filters.include_iv) next.delete("include_iv");
  else next.set("include_iv", filters.include_iv ? "true" : "false");

  return next;
}

/** Build API query object for GET /api/url-sink/inventory (K13). */
export function inventoryApiParams(
  projectId: string,
  filters: InventoryFilters,
): Record<string, string | number | boolean> {
  const q: Record<string, string | number | boolean> = {
    project_id: projectId,
    min_score: filters.min_score,
    nrs_only: filters.nrs_only,
    sort: filters.sort,
    limit: filters.limit,
    offset: filters.offset,
    include_iv: filters.include_iv,
  };
  if (filters.category) q.category = filters.category;
  if (filters.looks_like) q.looks_like = filters.looks_like;
  if (filters.location) q.location = filters.location;
  if (filters.host) q.host = filters.host;
  if (filters.endpoint_id) q.endpoint_id = filters.endpoint_id;
  if (filters.search) q.search = filters.search;
  if (filters.has_iv_profile != null) q.has_iv_profile = filters.has_iv_profile;
  if (filters.has_url_sink_obs != null)
    q.has_url_sink_obs = filters.has_url_sink_obs;
  return q;
}

/** Inventory deep-link path with optional filter overrides. */
export function inventoryHref(overrides: Partial<InventoryFilters> = {}): string {
  const f = defaultInventoryFilters(overrides);
  const params = applyFiltersToSearchParams(new URLSearchParams(), f, {
    tab: "inventory",
    compactDefaults: true,
  });
  // Ensure inventory defaults are explicit for CTA links
  params.set("tab", "inventory");
  params.set("min_score", String(f.min_score));
  params.set("nrs_only", f.nrs_only ? "true" : "false");
  return `${URL_SINKS_BASE}?${params.toString()}`;
}

export interface SinkRow {
  parameter_id?: string | null;
  param_uuid?: string | null;
  endpoint_id?: string | null;
  name?: string | null;
  location?: string | null;
  param_type?: string | null;
  semantic_type?: string | null;
  host?: string | null;
  method?: string | null;
  normalized_path?: string | null;
  seen_count?: number;
  example_values?: unknown[];
  url_features?: Record<string, unknown>;
  url_score?: number;
  possible_network_resource?: boolean;
  name_category?: string | null;
  name_categories?: string[];
  looks_like?: string[];
  inventory_only?: boolean;
  iv?: {
    has_profile?: boolean;
    capabilities?: string[];
    url_sink_confidence?: number | null;
    top_url_candidate?: {
      attack?: string;
      score?: number;
      confidence?: number;
    } | null;
  };
}

export interface UrlSinkStatus {
  enabled_passive?: boolean;
  enabled_html_js?: boolean;
  enabled_iv_probes?: boolean;
  score_threshold?: number;
  total_params?: number;
  with_url_features?: number;
  nrs_count?: number;
  score_ge_threshold?: number;
  score_ge_70?: number;
  by_category?: Record<string, number>;
  by_looks_like?: Record<string, number>;
  by_location?: Record<string, number>;
  iv_characterized_count?: number | null;
  disclaimer?: string;
}

export interface UrlSinkEmptyState {
  no_params?: boolean;
  no_nrs?: boolean;
  passive_disabled?: boolean;
}

export interface UrlFamilyCandidate {
  param_uuid?: string;
  parameter_name?: string;
  host?: string;
  endpoint_id?: string | null;
  attack?: string;
  score?: number;
  confidence?: number;
  [key: string]: unknown;
}

export interface HostRollupRow {
  key?: string;
  count?: number;
  nrs_count?: number;
  max_score?: number;
  categories?: Record<string, number>;
  top_categories?: string[];
}

export interface EndpointRollupRow {
  key?: string;
  endpoint_id?: string;
  method?: string | null;
  host?: string | null;
  normalized_path?: string | null;
  count?: number;
  nrs_count?: number;
  max_score?: number;
}

export interface CategoryRollupRow {
  key?: string;
  count?: number;
  max_score?: number;
  median_score?: number;
}

export type RollupKind = "host" | "endpoint" | "category";

export const CONFIG_URL_SINK_KEYS = [
  "url_sink.passive.enabled",
  "url_sink.html_js.enabled",
  "url_sink.iv_probes.enabled",
  "url_sink.score_threshold",
] as const;

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "—";
  return id.length > n ? id.slice(0, n) : id;
}

export function endpointLabel(row: {
  method?: string | null;
  normalized_path?: string | null;
}): string {
  const m = (row.method || "").toUpperCase();
  const p = row.normalized_path || "";
  if (!m && !p) return "—";
  return `${m} ${p}`.trim();
}

export function truncateValue(v: unknown, max = 48): string {
  if (v == null) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…`;
}

export function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Dist counts as sorted [key, count] pairs (desc by count). */
export function sortedCounts(
  map: Record<string, number> | undefined | null,
): [string, number][] {
  if (!map) return [];
  return Object.entries(map).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Talos Config deep-link for url_sink section. */
export const TALOS_CONFIG_URL_SINK =
  "/talos-config?tab=settings&section=url_sink";
