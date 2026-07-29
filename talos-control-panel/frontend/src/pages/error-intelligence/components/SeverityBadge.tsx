import { severityBadgeClass } from "../shared";

export default function SeverityBadge({
  severity,
  className = "",
}: {
  severity: string;
  className?: string;
}) {
  return (
    <span
      className={`badge badge-sm uppercase ${severityBadgeClass(severity)} ${className}`}
    >
      {severity || "—"}
    </span>
  );
}
