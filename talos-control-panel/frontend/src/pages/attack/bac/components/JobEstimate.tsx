/**
 * Honest upper-bound job estimate for BAC enqueue.
 * CLI also skips auth-failed roles and pending/running duplicates.
 */
export default function JobEstimate({
  flowCount,
  variantCount,
  candidateCount,
  techniqueLabel,
  authFailed,
  excludedEndpointCount = 0,
}: {
  flowCount: number;
  variantCount: number;
  candidateCount: number;
  /** Empty string means all techniques. */
  techniqueLabel: string;
  authFailed?: boolean;
  excludedEndpointCount?: number;
}) {
  const estimate = Math.max(0, flowCount) * Math.max(0, variantCount);

  if (candidateCount === 0 || flowCount === 0) {
    return (
      <div className="text-xs text-warning">
        No BAC candidates. Configure the access matrix (ALLOW target vs
        DENY/UNKNOWN attacker per module), capture 2xx role-tagged flows, and
        keep endpoints qualified (not excluded / logout / dangerous).
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        <span className="font-medium text-base-content/80">
          Up to ~{estimate.toLocaleString()} jobs
        </span>
        {" · "}
        {flowCount.toLocaleString()} candidate flow
        {flowCount === 1 ? "" : "s"}
        {excludedEndpointCount > 0
          ? ` (excluding ${excludedEndpointCount.toLocaleString()} endpoint${excludedEndpointCount === 1 ? "" : "s"} this run)`
          : ""}
        {" × "}
        {variantCount} variant{variantCount === 1 ? "" : "s"}
        {techniqueLabel ? (
          <>
            {" "}
            for <span className="mono">{techniqueLabel}</span>
          </>
        ) : (
          " (all techniques)"
        )}
        .
      </div>
      <p className="text-[10px] text-base-content/40 leading-snug">
        Upper bound. Auth prerequisite failures and pending/running duplicates
        are skipped by the CLI.
        {authFailed
          ? " Some attacker roles currently fail auth checks — enable auto-generate or fix Auth Config."
          : ""}
      </p>
    </div>
  );
}
