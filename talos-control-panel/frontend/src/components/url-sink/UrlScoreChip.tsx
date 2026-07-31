/**
 * Prioritization score chip for URL Sink Discovery.
 * Warn at ≥70, mid outline at ≥40, ghost otherwise. Never badge-error (K18).
 */
export function scoreTone(score: number | null | undefined): "warn" | "mid" | "ghost" {
  const n = Number(score) || 0;
  if (n >= 70) return "warn";
  if (n >= 40) return "mid";
  return "ghost";
}

export default function UrlScoreChip({
  score,
  className = "",
  title,
}: {
  score?: number | null;
  className?: string;
  title?: string;
}) {
  if (score == null || Number.isNaN(Number(score))) {
    return <span className="text-base-content/40 text-xs">—</span>;
  }
  const n = Math.max(0, Math.min(100, Math.round(Number(score))));
  const tone = scoreTone(n);
  const cls =
    tone === "warn"
      ? "badge badge-warning badge-xs"
      : tone === "mid"
        ? "badge badge-outline badge-warning badge-xs"
        : "badge badge-ghost badge-xs";
  return (
    <span
      className={`${cls} mono tabular-nums ${className}`}
      title={
        title ||
        `URL sink score ${n}/100 — prioritization only, not a confirmed vulnerability`
      }
    >
      {n}
    </span>
  );
}
