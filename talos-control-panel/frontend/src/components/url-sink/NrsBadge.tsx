/**
 * Possible network-resource flag from passive url_features.
 * Prioritization signal only — not a confirmed SSRF / open-redirect Finding.
 */
export default function NrsBadge({
  nrs,
  className = "",
}: {
  nrs?: boolean | null;
  className?: string;
}) {
  if (!nrs) {
    return <span className={`text-base-content/30 text-xs ${className}`}>—</span>;
  }
  return (
    <span
      className={`badge badge-warning badge-outline badge-xs ${className}`}
      title="possible_network_resource — prioritization signal, not a confirmed vulnerability"
    >
      NRS
    </span>
  );
}
