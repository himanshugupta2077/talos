import { Link } from "react-router-dom";
import SideDrawer from "../../../components/SideDrawer";
import type { IntruderResultRow } from "../types";

export default function ResultDetailDrawer({
  row,
  onClose,
}: {
  row: IntruderResultRow | null;
  onClose: () => void;
}) {
  return (
    <SideDrawer
      open={!!row}
      onClose={onClose}
      title={
        row
          ? `Attempt #${row.attempt_index}${row.interesting ? " ★" : ""}`
          : "Result"
      }
      wide
    >
      {row && (
        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-base-content/50">Status</span>
              <div className="font-medium">
                {row.status_code ?? "—"}{" "}
                <span className="text-base-content/50">
                  ({row.success ? "success" : "fail"})
                </span>
              </div>
            </div>
            <div>
              <span className="text-base-content/50">Duration</span>
              <div className="font-medium">
                {row.duration_ms != null ? `${row.duration_ms} ms` : "—"}
              </div>
            </div>
            <div>
              <span className="text-base-content/50">Body length</span>
              <div className="font-medium">
                {row.body_length != null
                  ? row.body_length.toLocaleString()
                  : "—"}
              </div>
            </div>
            <div>
              <span className="text-base-content/50">Interesting</span>
              <div className="font-medium">{row.interesting ? "yes" : "no"}</div>
            </div>
          </div>

          <div>
            <div className="text-xs text-base-content/50 mb-1">Payloads</div>
            <pre className="text-xs mono bg-base-200 rounded p-2 overflow-auto max-h-40">
              {JSON.stringify(row.variables || {}, null, 2)}
            </pre>
          </div>

          {(row.match_tags?.length ?? 0) > 0 && (
            <div>
              <div className="text-xs text-base-content/50 mb-1">Match tags</div>
              <div className="flex flex-wrap gap-1">
                {row.match_tags.map((t) => (
                  <span key={t} className="badge badge-sm badge-outline">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {row.grepped && Object.keys(row.grepped).length > 0 && (
            <div>
              <div className="text-xs text-base-content/50 mb-1">Grep</div>
              <pre className="text-xs mono bg-base-200 rounded p-2 overflow-auto max-h-32">
                {JSON.stringify(row.grepped, null, 2)}
              </pre>
            </div>
          )}

          {row.fingerprint && Object.keys(row.fingerprint).length > 0 && (
            <div>
              <div className="text-xs text-base-content/50 mb-1">
                Fingerprint
              </div>
              <pre className="text-xs mono bg-base-200 rounded p-2 overflow-auto max-h-32">
                {JSON.stringify(row.fingerprint, null, 2)}
              </pre>
            </div>
          )}

          {row.failure_reason && (
            <div className="alert alert-error text-xs py-2">
              {row.failure_reason}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            {row.flow_id && (
              <>
                <Link
                  to={`/flows/${row.flow_id}`}
                  className="btn btn-sm btn-outline"
                >
                  Open flow
                </Link>
                <Link
                  to={`/repeater?flow=${row.flow_id}`}
                  className="btn btn-sm btn-ghost"
                >
                  Send to Repeater
                </Link>
              </>
            )}
            {row.finding_id && (
              <Link
                to={`/findings/${row.finding_id}`}
                className="btn btn-sm btn-ghost"
              >
                Open finding
              </Link>
            )}
          </div>
        </div>
      )}
    </SideDrawer>
  );
}
