const COLOR_MAP: Record<string, string> = {
  // verdicts
  SECURE: "badge-success",
  SAME: "badge-success",
  POSSIBLE_BAC: "badge-error",
  BYPASS: "badge-error",
  WEAK_VALIDATION: "badge-error",
  CORS_MISCONFIG: "badge-error",
  SQLI: "badge-error",
  DIFFERENT: "badge-warning",
  UNKNOWN: "badge-ghost",
  ERROR: "badge-error",
  // finding status
  TRIAGING: "badge-warning",
  CONFIRMED: "badge-error",
  REJECTED: "badge-ghost",
  DUPLICATE: "badge-ghost",
  // scheduler / job / candidate status
  pending: "badge-warning",
  approved: "badge-info",
  rejected: "badge-ghost",
  running: "badge-info",
  done: "badge-success",
  failed: "badge-error",
  skipped: "badge-ghost",
  paused: "badge-warning",
  waiting_for_session: "badge-warning",
  // priority
  LOW: "badge-ghost",
  NORMAL: "badge-info",
  HIGH: "badge-warning",
  CRITICAL: "badge-error",
  // qualification / booleans / policy decisions
  qualified: "badge-success",
  excluded: "badge-ghost",
  TESTABLE: "badge-success",
  SKIPPED: "badge-ghost",
  INCLUDED: "badge-outline",
  EXCLUDED: "badge-ghost",
  SAFE: "badge-success",
  DANGEROUS: "badge-error",
  LOGOUT: "badge-error",
  UNQUALIFIED: "badge-warning",
  // auth session / health
  READY: "badge-success",
  EXPIRING: "badge-warning",
  EXPIRED: "badge-error",
  FAILED: "badge-error",
  WAITING_FOR_USER: "badge-warning",
  HEALTHY: "badge-success",
  DEGRADED: "badge-error",
  WATCHING: "badge-warning",
  PASS: "badge-success",
};

export default function StatusBadge({ value }: { value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === "") {
    return <span className="badge badge-ghost badge-sm">—</span>;
  }
  const key = String(value);
  const cls = COLOR_MAP[key] || "badge-neutral";
  return <span className={`badge badge-sm ${cls}`}>{key}</span>;
}
