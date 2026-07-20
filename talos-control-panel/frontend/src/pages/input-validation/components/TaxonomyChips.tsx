import StateChip from "./StateChip";

export default function TaxonomyChips({
  classes,
}: {
  classes?: Record<string, any> | null;
}) {
  if (!classes || !Object.keys(classes).length) {
    return <span className="text-xs text-base-content/40">No class outcomes yet.</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {Object.entries(classes).map(([name, entry]) => {
        const outcome =
          typeof entry === "object" && entry
            ? entry.outcome || entry.state || "unknown"
            : String(entry);
        const conf =
          typeof entry === "object" && entry && entry.confidence != null
            ? ` ${entry.confidence}`
            : "";
        return (
          <span
            key={name}
            className="inline-flex items-center gap-1 text-xs border border-base-content/10 rounded px-1.5 py-0.5"
          >
            <span className="mono">{name}</span>
            <StateChip state={outcome} kind="outcome" />
            {conf && <span className="text-base-content/40">{conf}</span>}
          </span>
        );
      })}
    </div>
  );
}
