/**
 * Name-category chip for URL Sink Discovery (redirect, webhook, …).
 * Outline accents only — never implies confirmed vulnerability.
 */
const ACCENT: Record<string, string> = {
  redirect: "badge-info",
  oauth: "badge-info",
  webhook: "badge-secondary",
  remote_fetch: "badge-accent",
  remote_asset: "badge-accent",
  infrastructure: "badge-warning",
  network_probe: "badge-warning",
  import_metadata: "badge-ghost",
  path_like: "badge-ghost",
};

export default function SinkCategoryBadge({
  category,
  className = "",
}: {
  category?: string | null;
  className?: string;
}) {
  if (!category) {
    return <span className="text-base-content/40 text-xs">—</span>;
  }
  const accent = ACCENT[category] || "badge-ghost";
  return (
    <span
      className={`badge badge-outline badge-xs mono ${accent} ${className}`}
      title={`Name category: ${category} (catalog hint, prioritization only)`}
    >
      {category}
    </span>
  );
}
