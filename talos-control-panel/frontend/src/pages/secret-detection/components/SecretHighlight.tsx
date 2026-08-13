/** Highlight the redacted leak inside its stored source context. */
export default function SecretHighlight({
  contextBefore,
  redactedValue,
  contextAfter,
}: {
  contextBefore?: string | null;
  redactedValue?: string | null;
  contextAfter?: string | null;
}) {
  const before = contextBefore || "";
  const value = redactedValue || "";
  const after = contextAfter || "";
  if (!before && !after && !value) {
    return <p className="text-sm text-base-content/40">No source context stored.</p>;
  }
  return (
    <pre className="panel p-3 mono text-xs whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
      <span className="text-base-content/50">{before}</span>
      <mark className="bg-warning/40 text-base-content px-0.5 rounded-sm font-semibold">
        {value || "????"}
      </mark>
      <span className="text-base-content/50">{after}</span>
    </pre>
  );
}
