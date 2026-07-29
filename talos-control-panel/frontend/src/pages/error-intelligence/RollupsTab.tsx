import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import SeverityBadge from "./components/SeverityBadge";
import CategoryBadge from "./components/CategoryBadge";
import {
  ERRORS_BASE,
  EndpointRollupRow,
  ParameterRollupRow,
  shortId,
} from "./shared";
import { IV_BASE } from "../attack/registry";

export default function RollupsTab({ projectId }: { projectId: string }) {
  const [paramRows, setParamRows] = useState<ParameterRollupRow[]>([]);
  const [epRows, setEpRows] = useState<EndpointRollupRow[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      api
        .get<{ rollup: ParameterRollupRow[] }>(
          "/api/error-intel/rollups/parameter",
          { project_id: projectId, limit: 50 },
        )
        .then((r) => setParamRows(r.rollup || []))
        .catch(() => setParamRows([])),
      api
        .get<{ rollup: EndpointRollupRow[] }>(
          "/api/error-intel/rollups/endpoint",
          { project_id: projectId, limit: 50 },
        )
        .then((r) => setEpRows(r.rollup || []))
        .catch(() => setEpRows([])),
    ]).finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <button className="btn btn-xs" onClick={load} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <Section title="By parameter">
        {paramRows.length === 0 ? (
          <p className="text-sm text-base-content/50">
            No parameter-linked errors yet — run IV/attacks or wait for proxy
            capture with param context.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Parameter</th>
                  <th>Error</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Obs</th>
                  <th>Attack types</th>
                </tr>
              </thead>
              <tbody>
                {paramRows.map((r, i) => (
                  <tr key={`${r.parameter_uuid}-${r.error_id}-${i}`} className="hover">
                    <td>
                      {r.parameter_uuid ? (
                        <Link
                          to={`${IV_BASE}/params/${r.parameter_uuid}`}
                          className="link mono text-xs"
                        >
                          {r.parameter_name || shortId(r.parameter_uuid)}
                        </Link>
                      ) : (
                        <span className="text-base-content/40">—</span>
                      )}
                    </td>
                    <td>
                      {r.error_id ? (
                        <Link
                          to={`${ERRORS_BASE}/${r.error_id}`}
                          className="link text-sm"
                        >
                          {r.exception_type || shortId(r.error_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.severity ? (
                        <SeverityBadge severity={String(r.severity)} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.category ? (
                        <CategoryBadge category={String(r.category)} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="mono">{r.observation_count ?? "—"}</td>
                    <td className="text-xs">
                      {Array.isArray(r.attack_types)
                        ? r.attack_types.join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="By endpoint">
        {epRows.length === 0 ? (
          <p className="text-sm text-base-content/50">
            No endpoint-linked error rollups yet.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Error</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Obs</th>
                  <th>Attack types</th>
                </tr>
              </thead>
              <tbody>
                {epRows.map((r, i) => (
                  <tr key={`${r.endpoint_id}-${r.error_id}-${i}`} className="hover">
                    <td>
                      {r.endpoint_id ? (
                        <Link
                          to={`/endpoints/${r.endpoint_id}`}
                          className="link mono text-xs"
                        >
                          {shortId(r.endpoint_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.error_id ? (
                        <Link
                          to={`${ERRORS_BASE}/${r.error_id}`}
                          className="link text-sm"
                        >
                          {r.exception_type || shortId(r.error_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.severity ? (
                        <SeverityBadge severity={String(r.severity)} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.category ? (
                        <CategoryBadge category={String(r.category)} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="mono">{r.observation_count ?? "—"}</td>
                    <td className="text-xs">
                      {Array.isArray(r.attack_types)
                        ? r.attack_types.join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
