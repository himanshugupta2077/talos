import { confidenceChipClass } from "../shared";

export default function ConfidenceChip({
  level,
  score,
}: {
  level: string;
  score?: number | null;
}) {
  return (
    <span className={`badge badge-sm ${confidenceChipClass(level)}`} title={level}>
      {level || "—"}
      {score != null ? ` · ${score}` : ""}
    </span>
  );
}
