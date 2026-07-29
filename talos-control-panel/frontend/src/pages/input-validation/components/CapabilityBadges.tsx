/** Emphasize reflection-related capabilities for stored/same-request surfaces. */
function badgeClass(cap: string): string {
  if (cap === "stored_reflection") {
    return "badge badge-warning badge-outline badge-xs mono";
  }
  if (cap === "reflective_input") {
    return "badge badge-info badge-outline badge-xs mono";
  }
  if (cap.endsWith("_context")) {
    return "badge badge-accent badge-outline badge-xs mono";
  }
  return "badge badge-ghost badge-xs mono";
}

export default function CapabilityBadges({
  caps,
  limit = 12,
}: {
  caps?: string[] | null;
  limit?: number;
}) {
  const list = caps || [];
  if (!list.length) {
    return <span className="text-base-content/40 text-xs">—</span>;
  }
  const shown = list.slice(0, limit);
  const extra = list.length - shown.length;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {shown.map((c) => (
        <span
          key={c}
          className={badgeClass(c)}
          title={
            c === "stored_reflection"
              ? "Value observed on another page/flow (data-flow evidence, not XSS)"
              : c === "reflective_input"
                ? "Input reflects in a response (same-request and/or stored)"
                : undefined
          }
        >
          {c}
        </span>
      ))}
      {extra > 0 && <span className="badge badge-ghost badge-xs">+{extra}</span>}
    </span>
  );
}
