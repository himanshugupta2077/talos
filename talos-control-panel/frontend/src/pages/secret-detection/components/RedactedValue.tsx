/** Monospace redacted secret display — never shows raw material. */

export default function RedactedValue({
  value,
  className = "",
}: {
  value: string | null | undefined;
  className?: string;
}) {
  if (!value) {
    return <span className="text-base-content/30 mono text-xs">—</span>;
  }
  return (
    <span
      className={`mono text-xs break-all ${className}`}
      title="Redacted value (raw secret not stored on detection rows)"
    >
      {value}
    </span>
  );
}
