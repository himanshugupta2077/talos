/** Query keys shared by the Findings list and Finding detail adjacent nav. */
export const FINDING_NAV_KEYS = [
  "view",
  "status",
  "attack_type",
  "verdict",
  "role",
  "module",
] as const;

export type FindingNavKey = (typeof FINDING_NAV_KEYS)[number];

export function findingNavFromSearch(
  sp: URLSearchParams
): Record<string, string> {
  const q: Record<string, string> = {};
  for (const k of FINDING_NAV_KEYS) {
    const v = sp.get(k);
    if (v) q[k] = v;
  }
  return q;
}

/** Build `?view=…` for list → detail so adjacent stays in the filtered set. */
export function findingNavSearch(
  filters: Partial<Record<FindingNavKey, string | undefined>>
): string {
  const p = new URLSearchParams();
  for (const k of FINDING_NAV_KEYS) {
    const v = filters[k];
    if (!v) continue;
    if (k === "view" && v === "primary") continue;
    p.set(k, v);
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function preserveSearch(sp: URLSearchParams): string {
  const s = sp.toString();
  return s ? `?${s}` : "";
}
