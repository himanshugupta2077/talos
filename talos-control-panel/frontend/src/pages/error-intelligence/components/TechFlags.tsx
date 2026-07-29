import type { ErrorClusterRow } from "../shared";

/** Compact chips for stack / path / host / version disclosure flags. */
export default function TechFlags({
  cluster,
  compact = false,
}: {
  cluster: Pick<
    ErrorClusterRow,
    | "has_stack_trace"
    | "has_path_leak"
    | "has_internal_host"
    | "has_version_leak"
    | "language"
    | "framework"
    | "database"
    | "server"
  >;
  compact?: boolean;
}) {
  const flags: { key: string; label: string; on: boolean; tone: string }[] = [
    {
      key: "stack",
      label: "stack",
      on: cluster.has_stack_trace,
      tone: "badge-error badge-outline",
    },
    {
      key: "path",
      label: "path leak",
      on: cluster.has_path_leak,
      tone: "badge-warning badge-outline",
    },
    {
      key: "host",
      label: "internal host",
      on: cluster.has_internal_host,
      tone: "badge-warning badge-outline",
    },
    {
      key: "ver",
      label: "version",
      on: cluster.has_version_leak,
      tone: "badge-info badge-outline",
    },
  ];

  const meta = [
    cluster.language,
    cluster.framework,
    cluster.database,
    cluster.server,
  ].filter(Boolean) as string[];

  return (
    <div className="flex flex-wrap gap-1 items-center">
      {!compact &&
        meta.map((m) => (
          <span key={m} className="badge badge-ghost badge-xs mono">
            {m}
          </span>
        ))}
      {flags
        .filter((f) => f.on)
        .map((f) => (
          <span key={f.key} className={`badge badge-xs ${f.tone}`}>
            {f.label}
          </span>
        ))}
      {flags.every((f) => !f.on) && compact && (
        <span className="text-base-content/30 text-xs">—</span>
      )}
    </div>
  );
}
