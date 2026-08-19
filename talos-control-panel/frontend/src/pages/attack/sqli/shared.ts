/** Shared types for the SQL injection workspace. */

export type SqliTab = "overview" | "run" | "results";

export const SQLI_TABS: { id: SqliTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
];

export function isSqliTab(v: string | null): v is SqliTab {
  return v === "overview" || v === "run" || v === "results";
}

export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export const VERDICTS = ["SQLI", "SECURE", "UNKNOWN"] as const;
export const FAMILIES = ["error", "union", "boolean", "time"] as const;

export interface SqliDbType {
  name: string;
  label: string;
  description: string;
  payload_count?: number;
}

export interface SqliTechnique {
  name: string;
  family: string;
  description: string;
  dbms?: string;
  encodeable?: boolean | string;
}

export const DB_TYPES: SqliDbType[] = [
  {
    name: "unknown",
    label: "Unknown",
    description:
      "DBMS not known. Multi-vendor payloads plus URL / double-URL / IIS unicode encodings.",
  },
  {
    name: "mssql",
    label: "Microsoft SQL Server",
    description: "T-SQL / SQL Server CONVERT, WAITFOR, stacked comments.",
  },
];

export function techniqueMatchesDb(tech: SqliTechnique, db: string): boolean {
  if (!db || db === "unknown") return true;
  const vendor = (tech.dbms || "generic").toLowerCase();
  return vendor === "generic" || vendor === "mssql";
}

export interface SqliResultRow {
  replay_flow_id: string;
  original_flow_id?: string;
  endpoint_id?: string | null;
  host?: string;
  technique?: string;
  technique_family?: string;
  location?: string;
  param_name?: string;
  payload_sent?: string;
  dbms?: string | null;
  evidence?: string;
  verdict?: string;
  risk_hint?: string;
  method?: string;
  path?: string;
  replay_status?: number | null;
  elapsed_ms?: number | null;
  captured_at?: string;
}

export interface SqliOverview {
  counts: Record<string, number>;
  total_techniques: number;
  jobs: Record<string, number>;
  jobs_pending: number;
  jobs_running: number;
  techniques: SqliTechnique[];
  families: string[];
  db_types?: SqliDbType[];
  payload_counts?: Record<string, number>;
  recent_issues: SqliResultRow[];
  empty_state: {
    no_results?: boolean;
    jobs_in_flight?: boolean;
  };
}
