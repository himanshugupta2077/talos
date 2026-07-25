interface Props {
  flowMeta: Record<string, unknown> | null | undefined;
}

/** Structured flow_meta as printed by `talos flow show`. */
export default function FlowMetaCard({ flowMeta }: Props) {
  const meta = flowMeta && typeof flowMeta === "object" ? flowMeta : {};
  const keys = Object.keys(meta);
  if (!keys.length) {
    return (
      <div className="panel p-4">
        <h3 className="font-semibold text-sm mb-2">flow_meta</h3>
        <p className="text-xs text-base-content/50">
          No structured metadata on this flow. Replay / IV / BAC generated flows
          often carry multiprobe plans and analysis here.
        </p>
      </div>
    );
  }
  return (
    <div className="panel p-4">
      <h3 className="font-semibold text-sm mb-2">flow_meta</h3>
      <p className="text-[11px] text-base-content/50 mb-2">
        Core-owned JSON metadata (generated_by, multiprobe plans, analysis, …).
      </p>
      <pre className="mono text-xs bg-base-300/40 rounded p-3 max-h-96 overflow-auto whitespace-pre-wrap break-all">
        {JSON.stringify(meta, null, 2)}
      </pre>
    </div>
  );
}
