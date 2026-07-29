/**
 * Lightweight request/response diff display for Repeater compare mode.
 */

interface RequestDiff {
  method_changed?: boolean;
  method_a?: string;
  method_b?: string;
  url_changed?: boolean;
  path_changed?: boolean;
  path_a?: string;
  path_b?: string;
  query_changed?: boolean;
  headers?: { added?: string[]; removed?: string[]; changed?: string[] };
  cookies?: { added?: string[]; removed?: string[]; changed?: string[] };
  body_equal?: boolean;
  body_len_a?: number;
  body_len_b?: number;
  body_len_delta?: number;
  changed?: boolean;
  body_text_diff?: string[] | null;
}

interface ResponseDiff {
  verdict?: string;
  status_changed?: boolean;
  status_diff?: string;
  length_diff?: number;
}

interface Props {
  request?: RequestDiff | null;
  response?: ResponseDiff | null;
}

function ChipList({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="text-xs">
      <span className="text-base-content/50">{label}: </span>
      {items.map((x) => (
        <span key={x} className="badge badge-ghost badge-xs mono mr-1">
          {x}
        </span>
      ))}
    </div>
  );
}

export default function HttpDiffView({ request, response }: Props) {
  if (!request && !response) {
    return (
      <div className="text-xs text-base-content/50 p-2">
        Select two history rows (or parent vs last) to compare.
      </div>
    );
  }

  return (
    <div className="space-y-3 p-2 text-xs">
      {response && (
        <div className="panel p-2 space-y-1">
          <div className="text-[10px] uppercase text-base-content/50">Response</div>
          {response.verdict && (
            <span className="badge badge-sm">{response.verdict}</span>
          )}
          {response.status_diff && (
            <div className="mono">{response.status_diff}</div>
          )}
          {response.length_diff != null && (
            <div>length Δ {response.length_diff}</div>
          )}
        </div>
      )}
      {request && (
        <div className="panel p-2 space-y-1">
          <div className="text-[10px] uppercase text-base-content/50">Request</div>
          <div>
            {request.changed ? (
              <span className="badge badge-warning badge-sm">changed</span>
            ) : (
              <span className="badge badge-success badge-sm">identical</span>
            )}
          </div>
          {request.method_changed && (
            <div className="mono">
              method {request.method_a} → {request.method_b}
            </div>
          )}
          {request.path_changed && (
            <div className="mono">
              path {request.path_a} → {request.path_b}
            </div>
          )}
          {request.query_changed && <div>query changed</div>}
          <ChipList label="headers+" items={request.headers?.added} />
          <ChipList label="headers−" items={request.headers?.removed} />
          <ChipList label="headers~" items={request.headers?.changed} />
          <ChipList label="cookies+" items={request.cookies?.added} />
          <ChipList label="cookies−" items={request.cookies?.removed} />
          {request.body_equal === false && (
            <div>
              body len {request.body_len_a} → {request.body_len_b} (Δ{" "}
              {request.body_len_delta})
            </div>
          )}
          {request.body_text_diff && request.body_text_diff.length > 0 && (
            <pre className="mono text-[10px] max-h-40 overflow-auto bg-base-200 p-2 rounded">
              {request.body_text_diff.join("\n")}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
