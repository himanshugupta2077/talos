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
        <span key={c} className="badge badge-ghost badge-xs mono">
          {c}
        </span>
      ))}
      {extra > 0 && <span className="badge badge-ghost badge-xs">+{extra}</span>}
    </span>
  );
}
