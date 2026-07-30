/** Active-risk blurb for Intruder. */

export default function IntruderDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-3">
      <div className="space-y-1">
        <div>
          <span className="font-medium">Active high-volume attack.</span>{" "}
          Sessions enqueue scheduler jobs (time-sliced ~100 attempts / 60s).
          Defaults: 2 RPS, concurrency 1, metrics_only storage, max 10k
          attempts. Cluster bomb / multi-set products can grow quickly — check
          the estimate before Run.
        </div>
        <div className="text-base-content/70">
          Authorization headers and session cookies{" "}
          <strong>can be mutated</strong> (unlike Input Validation).
          Logout-annotated endpoints are hard-blocked. Global Scheduler resume
          does not resume Intruder — use Resume on the Run tab.
        </div>
      </div>
    </div>
  );
}
