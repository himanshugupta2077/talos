import { buildHealthChips, FlowFlagSources, HealthChip } from "../../lib/flowFlags";

const TONE: Record<HealthChip["tone"], string> = {
  neutral: "badge-ghost",
  success: "badge-success",
  warning: "badge-warning",
  info: "badge-info",
  error: "badge-error",
};

export default function FlowHealthChips({ source }: { source: FlowFlagSources }) {
  const chips = buildHealthChips(source);
  if (!chips.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5 mt-2">
      {chips.map((c) => (
        <span key={c.kind} className={`badge badge-sm ${TONE[c.tone]}`}>
          {c.label}
        </span>
      ))}
    </div>
  );
}
