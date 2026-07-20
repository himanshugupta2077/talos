const REFLECTION_CLASS: Record<string, string> = {
  reflected: "badge-info",
  not_reflected: "badge-ghost",
  unknown: "badge-ghost",
  conflicting: "badge-warning",
};

const OUTCOME_CLASS: Record<string, string> = {
  accepted: "badge-success",
  rejected: "badge-ghost",
  modified: "badge-info",
  encoded: "badge-info",
  normalized: "badge-info",
  truncated: "badge-warning",
  ignored: "badge-ghost",
  unknown: "badge-ghost",
};

export default function StateChip({
  state,
  kind = "generic",
}: {
  state?: string | null;
  kind?: "reflection" | "outcome" | "generic";
}) {
  const s = (state || "unknown").toLowerCase();
  let cls = "badge-ghost";
  if (kind === "reflection") cls = REFLECTION_CLASS[s] || "badge-ghost";
  else if (kind === "outcome") cls = OUTCOME_CLASS[s] || "badge-ghost";
  return <span className={`badge badge-xs ${cls}`}>{s}</span>;
}
