import StatusBadge from "../../../components/StatusBadge";
import { statusTone } from "../shared";
import type { IntruderSessionStatus } from "../types";

const EXTRA: Record<string, string> = {
  draft: "badge-warning",
  configured: "badge-success",
  queued: "badge-info",
  running: "badge-info",
  paused: "badge-warning",
  completed: "badge-success",
  failed: "badge-error",
  cancelled: "badge-error",
};

export default function SessionStatusBadge({
  status,
}: {
  status: IntruderSessionStatus | string;
}) {
  const cls = EXTRA[status] || "badge-ghost";
  // Prefer dedicated classes; fall back to StatusBadge map
  if (EXTRA[status]) {
    return <span className={`badge badge-sm ${cls}`}>{status}</span>;
  }
  void statusTone(status);
  return <StatusBadge value={status} />;
}
