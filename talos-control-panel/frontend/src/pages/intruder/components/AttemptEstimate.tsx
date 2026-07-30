import {
  CONFIRM_THRESHOLD,
  DEFAULT_MAX_ATTEMPTS,
  roughDurationLabel,
} from "../shared";

export default function AttemptEstimate({
  attempts,
  rps = 2,
  concurrency = 1,
  maxAttempts = DEFAULT_MAX_ATTEMPTS,
  authoritative = false,
}: {
  attempts: number | null | undefined;
  rps?: number;
  concurrency?: number;
  maxAttempts?: number;
  /** True when from validate/configure response */
  authoritative?: boolean;
}) {
  if (attempts == null) {
    return (
      <div className="rounded-md border border-base-300 bg-base-200/40 px-3 py-2 text-xs text-base-content/60">
        Estimated attempts: —{" "}
        <span className="text-base-content/50">
          (add payloads, or Save / Validate for path-backed wordlists)
        </span>
      </div>
    );
  }
  const overConfirm = attempts > CONFIRM_THRESHOLD;
  const overCap = attempts > maxAttempts;
  return (
    <div
      className={`rounded-md border px-3 py-2 text-xs space-y-0.5 ${
        overCap
          ? "border-error/40 bg-error/10"
          : overConfirm
            ? "border-warning/40 bg-warning/10"
            : "border-base-300 bg-base-200/40"
      }`}
    >
      <div className="font-medium text-sm">
        Estimated attempts: {attempts.toLocaleString()}
        {!authoritative && (
          <span className="font-normal text-base-content/50 ml-1">
            (preview)
          </span>
        )}
      </div>
      <div className="text-base-content/70">
        {roughDurationLabel(attempts, rps, concurrency)} · concurrency{" "}
        {concurrency}
      </div>
      <div className="text-base-content/50">
        Max cap: {maxAttempts.toLocaleString()} attempts (engine default)
      </div>
      {overConfirm && !overCap && (
        <div className="text-warning-content/80">
          Above {CONFIRM_THRESHOLD.toLocaleString()} — confirmation required to
          run.
        </div>
      )}
      {overCap && (
        <div className="text-error">
          Exceeds engine max_attempts — reduce payloads or raise cap via CLI.
        </div>
      )}
    </div>
  );
}
