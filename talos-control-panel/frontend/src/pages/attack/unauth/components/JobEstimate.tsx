/**
 * Honest upper-bound job estimate for unauth enqueue.
 * CLI also deduplicates pending/running identical jobs.
 */
export default function JobEstimate({
  testable,
  recipes,
  techniqueLabel,
}: {
  testable: number;
  recipes: number;
  techniqueLabel: string;
}) {
  const estimate = Math.max(0, testable) * Math.max(0, recipes);

  if (testable === 0) {
    return (
      <div className="text-xs text-warning">
        No testable endpoints. Qualify endpoints with a 2xx baseline flow and
        ensure they are not excluded (logout / dangerous / policy).
      </div>
    );
  }

  return (
    <div className="text-xs text-base-content/60">
      <span className="font-medium text-base-content/80">
        Up to ~{estimate.toLocaleString()} jobs
      </span>
      {" · "}
      {testable.toLocaleString()} testable endpoint
      {testable === 1 ? "" : "s"}
      {" × "}
      {recipes} recipe{recipes === 1 ? "" : "s"}
      {techniqueLabel ? (
        <>
          {" "}
          for <span className="mono">{techniqueLabel}</span>
        </>
      ) : (
        " (all recipes)"
      )}
      . Pending/running duplicates are skipped by the CLI.
    </div>
  );
}
