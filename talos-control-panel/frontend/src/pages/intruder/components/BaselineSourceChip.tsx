import { Link } from "react-router-dom";
import { shortId } from "../shared";
import type { BaselineSource } from "../types";

const LABELS: Record<BaselineSource, string> = {
  last_send: "Baseline: last send",
  capture: "Baseline: capture",
  flow: "Baseline: flow",
};

export default function BaselineSourceChip({
  flowId,
  source,
}: {
  flowId: string | null | undefined;
  source: BaselineSource;
}) {
  if (!flowId) {
    return (
      <span className="badge badge-ghost badge-sm">No baseline flow</span>
    );
  }
  return (
    <Link
      to={`/flows/${flowId}`}
      className="badge badge-outline badge-sm gap-1 hover:badge-primary font-normal"
      title={flowId}
    >
      {LABELS[source]} · {shortId(flowId)}
    </Link>
  );
}
