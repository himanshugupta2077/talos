export default function StaleVersionBadge({
  version,
  current,
  stale,
}: {
  version: string | null | undefined;
  current?: string | null;
  stale?: boolean;
}) {
  const isStale =
    stale ?? (version == null || (current != null && version !== current));
  if (!isStale) {
    return (
      <span className="badge badge-ghost badge-xs mono" title="Up to date">
        {version || "—"}
      </span>
    );
  }
  return (
    <span
      className="badge badge-warning badge-xs mono"
      title={
        current
          ? `Scanned with ${version || "unknown"}; current is ${current}`
          : "Needs rescan"
      }
    >
      {version || "none"} · stale
    </span>
  );
}
