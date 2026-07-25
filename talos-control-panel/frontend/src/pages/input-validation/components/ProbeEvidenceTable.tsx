import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import { selectClass } from "../shared";

export default function ProbeEvidenceTable({ probes }: { probes: any[] }) {
  const [analysis, setAnalysis] = useState("");
  const [status, setStatus] = useState("");

  const analyses = useMemo(
    () => [...new Set(probes.map((p) => p.analysis).filter(Boolean))],
    [probes],
  );
  const statuses = useMemo(
    () => [...new Set(probes.map((p) => p.status).filter(Boolean))],
    [probes],
  );

  const filtered = probes.filter(
    (p) =>
      (!analysis || p.analysis === analysis) &&
      (!status || p.status === status),
  );

  return (
    <div>
      <div className="flex gap-2 mb-2 flex-wrap">
        <select className={selectClass} value={analysis} onChange={(e) => setAnalysis(e.target.value)}>
          <option value="">analysis: any</option>
          {analyses.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <select className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">status: any</option>
          {statuses.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="text-xs text-base-content/50 self-center">
          {filtered.length} / {probes.length} probes
        </span>
      </div>
      <div className="overflow-x-auto panel">
        <table className="table table-tight table-xs table-boxed w-full">
          <thead>
            <tr>
              <th>Analysis</th>
              <th>Payload type</th>
              <th>Payload</th>
              <th>Status</th>
              <th>Flow</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr key={p.id || `${p.analysis}-${p.payload_index}-${p.payload}`}>
                <td>{p.analysis}</td>
                <td className="mono text-xs">{p.payload_type}</td>
                <td className="mono max-w-xs truncate text-xs">{p.payload}</td>
                <td>{p.status}</td>
                <td>
                  {p.flow_id ? (
                    <Link className="link mono text-xs" to={`/flows/${p.flow_id}`}>
                      {String(p.flow_id).slice(0, 8)}
                    </Link>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center text-base-content/40 py-4">
                  No probe evidence.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
