import type { IntruderProgress } from "../types";

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return `${m}m ${s}s`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function ProgressStrip({
  status,
  progress,
}: {
  status: string;
  progress: IntruderProgress;
}) {
  const sent = Number(progress.sent ?? 0);
  const estimate = progress.estimate_total != null
    ? Number(progress.estimate_total)
    : null;
  const matched = Number(progress.matched ?? 0);
  const interesting = Number(progress.interesting ?? 0);
  const pct =
    estimate && estimate > 0
      ? Math.min(100, Math.round((sent / estimate) * 100))
      : null;

  return (
    <div className="rounded-md border border-base-300 bg-base-200/40 px-3 py-2 space-y-1.5">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="font-medium capitalize">{status}</span>
        <span>
          Sent:{" "}
          <span className="mono font-medium">
            {sent.toLocaleString()}
            {estimate != null ? ` / ${estimate.toLocaleString()}` : ""}
          </span>
          {pct != null && (
            <span className="text-base-content/40 ml-1">({pct}%)</span>
          )}
        </span>
        <span>Matched: {matched.toLocaleString()}</span>
        <span className={interesting > 0 ? "text-warning font-medium" : ""}>
          Interesting: {interesting.toLocaleString()}
        </span>
        {progress.active_duration_s != null && (
          <span className="text-base-content/50">
            Active: {formatDuration(Number(progress.active_duration_s))}
          </span>
        )}
        {progress.stopped_reason && (
          <span className="text-base-content/50">
            Reason: {String(progress.stopped_reason)}
          </span>
        )}
      </div>
      {pct != null && (
        <progress
          className="progress progress-primary w-full h-2"
          value={pct}
          max={100}
        />
      )}
    </div>
  );
}
