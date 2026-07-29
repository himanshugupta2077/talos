/**
 * Access Model workspace helpers — pure types and derived stats.
 * Values are never auto-inferred; helpers only classify existing matrix state.
 */

import type { AccessCell, AccessCoverageRow, AccessValue } from "../../types";

export type AccessTab = "matrix" | "coverage" | "signals";

export type LayerView = "both" | "client" | "server";

export type MatrixFilter =
  | "all"
  | "unset"
  | "mismatch"
  | "client_deny"
  | "server_deny"
  | "bac_ready"
  | "has_traffic";

export const ACCESS_VALUES: AccessValue[] = ["ALLOW", "DENY", "UNKNOWN"];

/** Cycle order for click-to-toggle: unset → ALLOW → DENY → UNKNOWN → unset */
export const ACCESS_CYCLE: Array<AccessValue | null> = [
  null,
  "ALLOW",
  "DENY",
  "UNKNOWN",
];

export const GLOBAL_NAME = "global";

export function cellKey(roleId: string, moduleId: string): string {
  return `${roleId}::${moduleId}`;
}

export function normalizeAccessValue(
  v: string | null | undefined
): AccessValue | null {
  if (!v) return null;
  const upper = v.toUpperCase();
  if (upper === "ALLOW" || upper === "DENY" || upper === "UNKNOWN") {
    return upper;
  }
  return null;
}

/** Next value when clicking a client/server chip (forward). */
export function nextAccessValue(
  current: string | null | undefined
): AccessValue | null {
  const cur = normalizeAccessValue(current);
  const i = ACCESS_CYCLE.indexOf(cur);
  const idx = i < 0 ? 0 : i;
  return ACCESS_CYCLE[(idx + 1) % ACCESS_CYCLE.length];
}

/** Previous value (Shift+click). */
export function prevAccessValue(
  current: string | null | undefined
): AccessValue | null {
  const cur = normalizeAccessValue(current);
  const i = ACCESS_CYCLE.indexOf(cur);
  const idx = i < 0 ? 0 : i;
  return ACCESS_CYCLE[(idx - 1 + ACCESS_CYCLE.length) % ACCESS_CYCLE.length];
}

export function valueBadgeClass(v: string | null | undefined): string {
  if (!v) return "badge-ghost opacity-50";
  if (v === "ALLOW") return "badge-success";
  if (v === "DENY") return "badge-error";
  return "badge-ghost";
}

export function displayValue(v: string | null | undefined): string {
  return normalizeAccessValue(v) || "—";
}

export function shortValue(v: string | null | undefined): string {
  if (!v) return "·";
  if (v === "ALLOW") return "A";
  if (v === "DENY") return "D";
  if (v === "UNKNOWN") return "U";
  return v.slice(0, 1);
}

export function isSet(v: string | null | undefined): boolean {
  return v != null && v !== "";
}

export function cellMatchesFilter(
  cell: AccessCell,
  filter: MatrixFilter,
  bacModuleIds: Set<string>
): boolean {
  const c = cell.client_allowed;
  const s = cell.server_expected;
  switch (filter) {
    case "all":
      return true;
    case "unset":
      return !isSet(c) || !isSet(s);
    case "mismatch":
      return isSet(c) && isSet(s) && c !== s;
    case "client_deny":
      return c === "DENY";
    case "server_deny":
      return s === "DENY";
    case "bac_ready":
      return bacModuleIds.has(cell.module_id);
    case "has_traffic":
      return (cell.flow_count ?? 0) > 0;
    default:
      return true;
  }
}

/**
 * Modules where at least one role is ALLOW and another is DENY or UNKNOWN
 * on the same layer (client or server). Mirrors BAC candidate surface wording.
 */
export function bacReadyModuleIds(
  cells: AccessCell[],
  layer: "client" | "server" | "either" = "either"
): Set<string> {
  const byModule = new Map<string, { allow: boolean; denyOrUnknown: boolean }>();

  for (const cell of cells) {
    if (cell.role_name === GLOBAL_NAME || cell.module_name === GLOBAL_NAME) {
      continue;
    }
    const entry = byModule.get(cell.module_id) || {
      allow: false,
      denyOrUnknown: false,
    };
    const vals: (string | null)[] = [];
    if (layer === "client" || layer === "either") vals.push(cell.client_allowed);
    if (layer === "server" || layer === "either") vals.push(cell.server_expected);
    for (const v of vals) {
      if (v === "ALLOW") entry.allow = true;
      if (v === "DENY" || v === "UNKNOWN") entry.denyOrUnknown = true;
    }
    byModule.set(cell.module_id, entry);
  }

  const ready = new Set<string>();
  for (const [id, e] of byModule) {
    if (e.allow && e.denyOrUnknown) ready.add(id);
  }
  return ready;
}

export interface AccessStats {
  roleCount: number;
  moduleCount: number;
  cellCount: number;
  clientSet: number;
  serverSet: number;
  bothSet: number;
  fullyUnset: number;
  mismatch: number;
  bacModules: number;
  withTraffic: number;
}

export function computeStats(cells: AccessCell[]): AccessStats {
  const roles = new Set(cells.map((c) => c.role_id));
  const modules = new Set(cells.map((c) => c.module_id));
  let clientSet = 0;
  let serverSet = 0;
  let bothSet = 0;
  let fullyUnset = 0;
  let mismatch = 0;
  let withTraffic = 0;

  for (const cell of cells) {
    const c = isSet(cell.client_allowed);
    const s = isSet(cell.server_expected);
    if (c) clientSet++;
    if (s) serverSet++;
    if (c && s) {
      bothSet++;
      if (cell.client_allowed !== cell.server_expected) mismatch++;
    }
    if (!c && !s) fullyUnset++;
    if ((cell.flow_count ?? 0) > 0) withTraffic++;
  }

  return {
    roleCount: roles.size,
    moduleCount: modules.size,
    cellCount: cells.length,
    clientSet,
    serverSet,
    bothSet,
    fullyUnset,
    mismatch,
    bacModules: bacReadyModuleIds(cells).size,
    withTraffic,
  };
}

export type CoverageStatus =
  | "observed"
  | "gap"
  | "unexpected"
  | "boundary"
  | "empty";

export function coverageStatus(row: AccessCoverageRow): CoverageStatus {
  const flows = row.flow_count ?? 0;
  if (row.server_expected === "DENY" && flows > 0) return "boundary";
  if (row.client_allowed === "DENY" && flows > 0) return "unexpected";
  if (row.client_allowed === "ALLOW" && flows === 0) return "gap";
  if (flows > 0) return "observed";
  return "empty";
}

export function coverageStatusLabel(s: CoverageStatus): string {
  switch (s) {
    case "observed":
      return "observed";
    case "gap":
      return "coverage gap";
    case "unexpected":
      return "client DENY + traffic";
    case "boundary":
      return "server DENY + traffic";
    default:
      return "no traffic";
  }
}

export function coverageStatusClass(s: CoverageStatus): string {
  switch (s) {
    case "observed":
      return "badge-success badge-outline";
    case "gap":
      return "badge-warning badge-outline";
    case "unexpected":
      return "badge-error badge-outline";
    case "boundary":
      return "badge-error";
    default:
      return "badge-ghost";
  }
}

export function uniqueRoles(cells: AccessCell[]): { id: string; name: string }[] {
  const map = new Map<string, string>();
  for (const c of cells) map.set(c.role_id, c.role_name);
  return [...map.entries()]
    .map(([id, name]) => ({ id, name }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function uniqueModules(
  cells: AccessCell[]
): { id: string; name: string }[] {
  const map = new Map<string, string>();
  for (const c of cells) map.set(c.module_id, c.module_name);
  return [...map.entries()]
    .map(([id, name]) => ({ id, name }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
