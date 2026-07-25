import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { UuidChip } from "../../components/Common";
import { formatIST } from "../../lib/time";
import { formatDurationMs } from "../../lib/flowFlags";
import { FlowDetail } from "../../types";

interface Derived {
  duration_ms?: number | null;
  request_body_size?: number;
  response_body_size?: number;
  request_body_truncated?: boolean;
  response_body_truncated?: boolean;
}

export default function FlowSummaryCard({
  flow,
  derived,
}: {
  flow: FlowDetail & {
    role_id?: string;
    module_id?: string;
    request_body_truncated?: boolean;
    response_body_truncated?: boolean;
  };
  derived?: Derived | null;
}) {
  const rows: { label: string; node: ReactNode }[] = [
    { label: "URL", node: <span className="mono break-all">{flow.url}</span> },
    { label: "Method", node: flow.method },
    { label: "Status", node: flow.status_code ?? "—" },
    {
      label: "Duration",
      node: formatDurationMs(derived?.duration_ms) ?? "—",
    },
    {
      label: "Response size",
      node:
        derived?.response_body_size != null
          ? `${derived.response_body_size} bytes`
          : "—",
    },
    {
      label: "Request size",
      node:
        derived?.request_body_size != null
          ? `${derived.request_body_size} bytes`
          : "—",
    },
    { label: "Role", node: flow.role_name },
    { label: "Module", node: flow.module_name },
    {
      label: "Endpoint",
      node: flow.endpoint_id ? (
        <Link to={`/endpoints/${flow.endpoint_id}`} className="link">
          <UuidChip value={flow.endpoint_id} />
        </Link>
      ) : (
        "—"
      ),
    },
    { label: "Host", node: <span className="mono">{flow.host}</span> },
    { label: "Captured", node: formatIST(flow.captured_at) },
    { label: "Source", node: flow.source },
    {
      label: "Flow ID",
      node: <UuidChip value={flow.id} />,
    },
    {
      label: "Original flow",
      node: flow.original_flow_id ? (
        <Link to={`/flows/${flow.original_flow_id}`} className="link">
          <UuidChip value={flow.original_flow_id} />
        </Link>
      ) : (
        "—"
      ),
    },
    { label: "Replay reason", node: flow.replay_reason || "—" },
    {
      label: "Replay error",
      node: flow.replay_error ? (
        <span className="text-error">{flow.replay_error}</span>
      ) : (
        "—"
      ),
    },
    {
      label: "Tags",
      node:
        flow.tags?.length > 0 ? (
          <span className="flex flex-wrap gap-1">
            {flow.tags.map((t) => (
              <span key={t} className="badge badge-sm badge-ghost">
                {t}
              </span>
            ))}
          </span>
        ) : (
          "—"
        ),
    },
    { label: "Content-Type", node: flow.content_type || "—" },
    {
      label: "Truncated",
      node: (
        <span>
          req: {derived?.request_body_truncated || flow.request_body_truncated ? "yes" : "no"}
          {" · "}
          resp:{" "}
          {derived?.response_body_truncated || flow.response_body_truncated ? "yes" : "no"}
        </span>
      ),
    },
    { label: "Session ID", node: flow.session_id ? <UuidChip value={flow.session_id} /> : "—" },
  ];

  return (
    <div className="panel p-4">
      <h3 className="font-semibold text-sm mb-3">Flow summary</h3>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
        {rows.map((r) => (
          <div key={r.label} className="flex gap-2 min-w-0">
            <dt className="text-base-content/50 w-28 shrink-0 text-xs uppercase tracking-wide pt-0.5">
              {r.label}
            </dt>
            <dd className="min-w-0 text-xs">{r.node}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
