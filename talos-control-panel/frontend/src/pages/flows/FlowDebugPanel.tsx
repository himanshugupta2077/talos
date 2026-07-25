import { FlowDetail } from "../../types";

interface Derived {
  duration_ms?: number | null;
  request_body_size?: number;
  response_body_size?: number;
  has_auth_material?: boolean;
  request_body_truncated?: boolean;
  response_body_truncated?: boolean;
}

export default function FlowDebugPanel({
  flow,
  derived,
}: {
  flow: FlowDetail & {
    request_body_encoding?: string;
    response_body_encoding?: string;
    request_body_truncated?: boolean;
    response_body_truncated?: boolean;
    role_id?: string;
    module_id?: string;
  };
  derived?: Derived | null;
}) {
  const lines: [string, string][] = [
    ["flow.id", flow.id],
    ["project_id", flow.project_id || "—"],
    ["role_id", (flow as any).role_id || "—"],
    ["module_id", (flow as any).module_id || "—"],
    ["session_id", flow.session_id || "—"],
    ["endpoint_id", flow.endpoint_id || "—"],
    ["request_body_encoding", flow.request_body_encoding || "utf-8"],
    ["response_body_encoding", flow.response_body_encoding || "utf-8"],
    ["request_body_size", String(derived?.request_body_size ?? "—")],
    ["response_body_size", String(derived?.response_body_size ?? "—")],
    ["request_body_truncated", String(!!(derived?.request_body_truncated || flow.request_body_truncated))],
    ["response_body_truncated", String(!!(derived?.response_body_truncated || flow.response_body_truncated))],
    ["has_auth_material", String(!!derived?.has_auth_material)],
    ["duration_ms", String(derived?.duration_ms ?? "—")],
    ["header_count_req", String(Object.keys(flow.request_headers || {}).length)],
    ["header_count_resp", String(Object.keys(flow.response_headers || {}).length)],
    ["cookie_map_count", String(Object.keys(flow.request_cookies || {}).length)],
  ];

  return (
    <div className="space-y-3">
      <p className="text-[11px] text-base-content/50">
        Storage diagnostics for Talos developers. Cookie dual-storage
        (headers.Cookie + request_cookies) is intentional at capture time.
      </p>
      <dl className="mono text-[11px] grid grid-cols-1 gap-1">
        {lines.map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <dt className="text-base-content/50 w-48 shrink-0">{k}</dt>
            <dd className="break-all">{v}</dd>
          </div>
        ))}
      </dl>
      <div>
        <div className="text-[10px] uppercase text-base-content/50 mb-1">Raw flow_meta</div>
        <pre className="mono text-[10px] bg-base-300/40 rounded p-2 max-h-64 overflow-auto whitespace-pre-wrap break-all">
          {JSON.stringify(flow.flow_meta || {}, null, 2)}
        </pre>
      </div>
    </div>
  );
}
