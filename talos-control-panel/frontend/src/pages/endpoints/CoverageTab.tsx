import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import { EndpointCoverage } from "../../types";
import { CardStat, FilterState } from "./shared";

export default function CoverageTab({
  projectId,
  onJumpInventory,
}: {
  projectId: string;
  onJumpInventory: (filters: Partial<FilterState>) => void;
}) {
  const navigate = useNavigate();
  const [data, setData] = useState<EndpointCoverage | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get<EndpointCoverage>("/api/endpoints/coverage", { project_id: projectId })
      .then(setData)
      .finally(() => setLoading(false));
  }, [projectId]);

  if (loading && !data) {
    return (
      <div className="py-12 text-center">
        <span className="loading loading-spinner" />
      </div>
    );
  }
  if (!data) {
    return (
      <div className="text-sm text-base-content/50 py-8 text-center">
        No coverage data yet.
      </div>
    );
  }

  const c = data.cards;
  const q = data.qualification;

  return (
    <div className="space-y-6">
      <div>
        <div className="text-sm text-base-content/60 mb-2">
          Read-only quality view over Talos state. This is{" "}
          <strong>not</strong> the Access Model — role rows show traffic Talos has
          actually observed.
        </div>
        <div className="text-2xl font-semibold tabular-nums mb-3">
          {data.total} endpoints
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          <CardStat
            label="% qualified"
            value={`${c.qualified_pct}%`}
            onClick={() => onJumpInventory({ qualified: "1" })}
          />
          <CardStat
            label="% have baseline"
            value={`${c.baseline_pct}%`}
            onClick={() => onJumpInventory({ has_baseline: "1" })}
          />
          <CardStat
            label="% under 2+ roles"
            value={`${c.multi_role_pct}%`}
          />
          <CardStat
            label="% have parameters"
            value={`${c.parameters_pct}%`}
            onClick={() => onJumpInventory({ has_parameters: "1" })}
          />
          <CardStat
            label="% excluded"
            value={`${c.excluded_pct}%`}
            onClick={() => onJumpInventory({ excluded: "1" })}
          />
        </div>
      </div>

      <section>
        <h3 className="font-semibold mb-2">Qualification breakdown</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          <CardStat
            label="Qualified"
            value={q.qualified ?? 0}
            onClick={() => onJumpInventory({ qualified: "1" })}
          />
          <CardStat
            label="No flows"
            value={q.no_flows ?? 0}
            onClick={() => onJumpInventory({ qualification_reason: "no_flows" })}
          />
          <CardStat
            label="No 2xx response"
            value={q.no_2xx_response ?? 0}
            onClick={() => onJumpInventory({ qualification_reason: "no_2xx_response" })}
          />
          <CardStat
            label="Only redirects"
            value={q.only_redirects ?? 0}
            onClick={() => onJumpInventory({ qualification_reason: "only_redirects" })}
          />
          <CardStat
            label="Dangerous"
            value={q.is_dangerous ?? 0}
            onClick={() => onJumpInventory({ dangerous: "1" })}
          />
          <CardStat
            label="Logout"
            value={q.is_logout ?? 0}
            onClick={() => onJumpInventory({ logout: "1" })}
          />
        </div>
      </section>

      <section>
        <h3 className="font-semibold mb-2">Baseline readiness</h3>
        <div className="grid grid-cols-2 gap-2 mb-2">
          <CardStat
            label="Baseline ready"
            value={data.baseline.ready}
            onClick={() => onJumpInventory({ has_baseline: "1" })}
          />
          <CardStat
            label="Missing baseline"
            value={data.baseline.missing}
            onClick={() => onJumpInventory({ has_baseline: "0" })}
          />
        </div>
        {Object.keys(data.baseline.missing_by_reason || {}).length > 0 && (
          <div className="panel p-3 text-sm">
            <div className="text-xs text-base-content/50 mb-2">Missing baseline by reason</div>
            <div className="flex flex-wrap gap-3">
              {Object.entries(data.baseline.missing_by_reason).map(([reason, n]) => (
                <button
                  key={reason}
                  className="btn btn-xs btn-ghost"
                  onClick={() => onJumpInventory({ qualification_reason: reason, has_baseline: "0" })}
                >
                  <span className="mono">{reason}</span>
                  <span className="tabular-nums font-semibold">{n}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </section>

      <section>
        <h3 className="font-semibold mb-1">Role observation coverage</h3>
        <p className="text-xs text-base-content/50 mb-2">
          Observed under roles from captured traffic — not intended authorization
          (see Access Model for that).
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
          {data.roles.by_role.map((r) => (
            <CardStat
              key={r.name}
              label={r.name}
              value={r.endpoints}
              onClick={() => onJumpInventory({ role: r.name })}
            />
          ))}
        </div>
        <div className="flex flex-wrap gap-3 text-sm mb-3">
          <span>
            1 role: <strong>{data.roles.coverage_buckets["1"] ?? 0}</strong>
          </span>
          <span>
            2 roles: <strong>{data.roles.coverage_buckets["2"] ?? 0}</strong>
          </span>
          <span>
            3+ roles: <strong>{data.roles.coverage_buckets["3+"] ?? 0}</strong>
          </span>
        </div>
        {data.roles.role_names.length > 0 && (
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  {data.roles.role_names.map((n) => (
                    <th key={n}>{n}</th>
                  ))}
                  <th>Coverage</th>
                </tr>
              </thead>
              <tbody>
                {data.roles.table.slice(0, 40).map((row) => (
                  <tr
                    key={row.id}
                    className="hover cursor-pointer"
                    onClick={() => navigate(`/endpoints/${row.id}`)}
                  >
                    <td className="mono text-xs">
                      <span className="badge badge-ghost badge-xs mr-1">{row.method}</span>
                      {row.path}
                    </td>
                    {data.roles.role_names.map((n) => (
                      <td key={n} className="text-center">
                        {row.roles[n] ? "✓" : "—"}
                      </td>
                    ))}
                    <td className="tabular-nums">{row.coverage}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h3 className="font-semibold mb-2">Parameter coverage</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mb-3">
          <CardStat
            label="Endpoints with parameters"
            value={data.parameters.endpoints_with_parameters}
            onClick={() => onJumpInventory({ has_parameters: "1" })}
          />
          {Object.entries(data.parameters.by_location || {}).map(([loc, n]) => (
            <CardStat key={loc} label={`${loc} parameters`} value={n} />
          ))}
        </div>
        {(data.parameters.heavy || []).length > 0 && (
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Params</th>
                </tr>
              </thead>
              <tbody>
                {data.parameters.heavy.map((row: any) => (
                  <tr
                    key={row.id}
                    className="hover cursor-pointer"
                    onClick={() => navigate(`/endpoints/${row.id}`)}
                  >
                    <td className="mono">{row.method}</td>
                    <td className="mono text-xs">{row.normalized_path}</td>
                    <td className="tabular-nums">{row.parameter_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
