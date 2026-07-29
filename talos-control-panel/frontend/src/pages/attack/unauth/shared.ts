/** Shared types and constants for Unauthenticated Execution workspace. */

export type UnauthTab = "overview" | "run" | "results" | "config";

export const UNAUTH_TABS: { id: UnauthTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
  { id: "config", label: "Filter & Config" },
];

export function isUnauthTab(v: string | null): v is UnauthTab {
  return v === "overview" || v === "run" || v === "results" || v === "config";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["BYPASS", "SECURE", "UNKNOWN"] as const;

export interface UnauthTechnique {
  name: string;
  description: string;
  mutation_family: string;
  recipe_count: number;
}

export interface UnauthResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  auth_mutation_family?: string;
  auth_mutation?: string;
  request_mutation_family?: string | null;
  request_mutation?: string | null;
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

export interface UnauthOverview {
  counts: Record<string, number>;
  testable_endpoints: number;
  total_recipes: number;
  estimated_jobs_all: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  auto_run: { enabled: boolean; source: string };
  techniques: UnauthTechnique[];
  recent_bypass: UnauthResultRow[];
  empty_state: {
    no_testable?: boolean;
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}

/** Upper-bound job estimate for a technique (or all). */
export function estimateJobs(
  testable: number,
  recipeCount: number
): number {
  return Math.max(0, testable) * Math.max(0, recipeCount);
}

export function recipeCountForTechnique(
  techniques: UnauthTechnique[],
  technique: string | null | undefined,
  totalRecipes: number
): number {
  if (!technique) return totalRecipes;
  const t = techniques.find((x) => x.name === technique);
  return t?.recipe_count ?? 0;
}
