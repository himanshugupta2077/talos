import { scoreBand } from "../shared";

export default function CandidateScore({
  score,
  confidence,
  showLabel = true,
}: {
  score?: number;
  confidence?: number;
  showLabel?: boolean;
}) {
  const s = Math.max(0, Math.min(100, Number(score ?? 0)));
  const band = scoreBand(s);
  const barClass =
    band === "high"
      ? "bg-info"
      : band === "mid"
        ? "bg-warning"
        : "bg-base-content/30";

  return (
    <div className="min-w-[5.5rem]">
      {showLabel && (
        <div className="flex justify-between text-xs mb-0.5">
          <span className="font-medium">{s}</span>
          {confidence != null && (
            <span className="text-base-content/50">c{confidence}</span>
          )}
        </div>
      )}
      <div className="h-1.5 w-full rounded bg-base-content/10 overflow-hidden">
        <div className={`h-full ${barClass}`} style={{ width: `${s}%` }} />
      </div>
    </div>
  );
}
