/** Shared types and constants for the BAC (Broken Access Control) workspace. */

export type BacTab = "overview" | "run" | "results" | "config";

export const BAC_TABS: { id: BacTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
  { id: "config", label: "Filter" },
];

export function isBacTab(v: string | null): v is BacTab {
  return v === "overview" || v === "run" || v === "results" || v === "config";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["POSSIBLE_BAC", "SECURE", "UNKNOWN"] as const;

export const DEFAULT_TECHNIQUES = [
  "session-swap",
  "method-fuzz",
  "content-type",
  "url-fuzz",
  "header-inject",
  "host-fuzz",
  "role-inject",
  "parser-confuse",
] as const;

export interface BacVariant {
  name: string;
  description: string;
  mutation?: string;
}

export interface BacTechnique {
  name: string;
  description: string;
  attack_type: string;
  variant_count: number;
  variants?: BacVariant[];
}

export interface BacResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  attack_type?: string;
  variant?: string;
  mutation_family?: string | null;
  mutation?: string | null;
  attacker_role_id?: string;
  target_role_id?: string;
  module_id?: string;
  attacker_role_name?: string | null;
  target_role_name?: string | null;
  module_name?: string | null;
  verdict?: string;
  matched_section?: string | null;
  matched_group?: string | null;
  matched_rules?: string | null;
  method?: string;
  path?: string;
  host?: string;
  status_code?: number;
  captured_at?: string;
}

export interface BacAuthRole {
  role_id: string;
  role_name: string;
  passed: boolean;
  errors: string[];
}

export interface BacOverview {
  counts: Record<string, number>;
  candidates: {
    candidate_count: number;
    flow_count: number;
    attacker_roles: string[];
    target_roles: string[];
    modules: string[];
  };
  total_variants: number;
  estimated_jobs_all: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  auth: {
    roles: BacAuthRole[];
    passed_count: number;
    failed_count: number;
    all_passed: boolean;
  };
  techniques: BacTechnique[];
  recent_possible: BacResultRow[];
  empty_state: {
    no_candidates?: boolean;
    no_results?: boolean;
    jobs_in_flight?: boolean;
    auth_failed?: boolean;
  };
  auth_model?: {
    mode: string;
    label: string;
    identity: string;
  };
}

export type BacScopeMode = "project" | "module" | "endpoint";

/** Upper-bound job estimate: candidate flows × selected variants. */
export function estimateJobs(flowCount: number, variantCount: number): number {
  return Math.max(0, flowCount) * Math.max(0, variantCount);
}

export function variantCountForTechniques(
  techniques: BacTechnique[],
  selected: string[] | null | undefined,
  totalVariants: number
): number {
  if (!selected || selected.length === 0) return totalVariants;
  const set = new Set(selected);
  return techniques
    .filter((t) => set.has(t.name))
    .reduce((sum, t) => sum + (t.variant_count || 0), 0);
}

/** Map job type or CLI name to a short display label. */
export function techniqueLabel(attackType?: string | null): string {
  if (!attackType) return "—";
  if (attackType.startsWith("bac_")) {
    return attackType.replace(/^bac_/, "").replace(/_/g, "-");
  }
  return attackType;
}

export function buildCliPreview(opts: {
  techniques: string[];
  role?: string;
  module?: string;
  endpoint?: string;
  autoGenerate?: boolean;
}): string[] {
  const techs =
    opts.techniques.length > 0 ? opts.techniques : [...DEFAULT_TECHNIQUES];
  return techs.map((tech) => {
    const parts = ["talos", "attack", "bac", tech];
    if (opts.role) parts.push("--role", opts.role);
    if (opts.module) parts.push("--module", opts.module);
    if (opts.endpoint) parts.push("--endpoint", opts.endpoint);
    if (opts.autoGenerate) parts.push("--auto-generate");
    return parts.join(" ");
  });
}
