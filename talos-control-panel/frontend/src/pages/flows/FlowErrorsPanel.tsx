import { Link } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { formatIST } from "../../lib/time";
import SeverityBadge from "../error-intelligence/components/SeverityBadge";
import CategoryBadge from "../error-intelligence/components/CategoryBadge";
import AttackTypeChip from "../error-intelligence/components/AttackTypeChip";
import type {
  ErrorByFlowResponse,
  ErrorClusterRow,
} from "../error-intelligence/shared";
import { ERRORS_BASE, clusterTitle, shortId } from "../error-intelligence/shared";

export default function FlowErrorsPanel({
  projectId,
  flowId,
  data,
  loadError,
  onRefresh,
}: {
  projectId: string;
  flowId: string;
  data: ErrorByFlowResponse | null;
  loadError?: boolean;
  onRefresh: () => void;
}) {
  const rescan = useAction("Rescan flow errors", () =>
    api.post(
      "/api/error-intel/rescan",
      { mode: "flow", id: flowId, force: false },
      { project_id: projectId },
    ),
  );

  if (loadError && !data) {
    return (
      <div className="panel p-4 text-sm text-base-content/60">
        Could not load error intelligence for this flow.
      </div>
    );
  }

  if (!data) {
    return <div className="loading loading-spinner loading-sm" />;
  }

  const { observations, clusters, observation_count, scanner_enabled } = data;
  const clusterById = new Map<string, ErrorClusterRow>(
    (clusters || []).map((c) => [c.id, c]),
  );

  if (observation_count === 0) {
    return (
      <div className="panel p-4 space-y-3 text-sm">
        {scanner_enabled ? (
          <>
            <p className="text-base-content/70">
              No error intelligence for this flow.
            </p>
            <button
              type="button"
              className="btn btn-xs"
              disabled={rescan.running}
              onClick={async () => {
                await rescan.run();
                onRefresh();
              }}
            >
              Rescan this flow
            </button>
          </>
        ) : (
          <>
            <p className="text-base-content/70">
              Scanner disabled — enable in Error Intelligence Settings to analyze
              new captures. Historical intelligence still appears when present.
            </p>
            <Link
              to={`${ERRORS_BASE}?tab=settings`}
              className="btn btn-xs btn-primary"
            >
              Open Settings
            </Link>
          </>
        )}
        <Link to={ERRORS_BASE} className="link text-xs block">
          Open Error Intelligence
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="badge badge-outline">
          {observation_count} observation{observation_count === 1 ? "" : "s"}
        </span>
        <span className="badge badge-ghost">
          {clusters.length} cluster{clusters.length === 1 ? "" : "s"}
        </span>
        {!scanner_enabled && (
          <span className="badge badge-warning badge-outline">
            scanner disabled (historical)
          </span>
        )}
        <button
          type="button"
          className="btn btn-xs btn-outline"
          disabled={rescan.running}
          onClick={async () => {
            await rescan.run();
            onRefresh();
          }}
        >
          Rescan this flow
        </button>
        <Link to={ERRORS_BASE} className="btn btn-xs btn-ghost">
          Open Error Intelligence
        </Link>
      </div>

      {clusters.length > 0 && (
        <div className="panel p-3">
          <h3 className="font-semibold text-sm mb-2">Clusters</h3>
          <ul className="space-y-2">
            {clusters.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center gap-2 text-sm">
                <SeverityBadge severity={c.severity} />
                <CategoryBadge category={c.category} />
                <Link to={`${ERRORS_BASE}/${c.id}`} className="link">
                  {clusterTitle(c)}
                </Link>
                <span className="text-xs text-base-content/40 mono">
                  {shortId(c.id)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="panel p-3 overflow-x-auto">
        <h3 className="font-semibold text-sm mb-2">Observations</h3>
        <table className="table table-xs">
          <thead>
            <tr>
              <th>When</th>
              <th>Attack</th>
              <th>Status</th>
              <th>Cluster</th>
              <th>Detectors</th>
            </tr>
          </thead>
          <tbody>
            {observations.map((o) => {
              const cluster = clusterById.get(o.error_id);
              return (
                <tr key={o.id}>
                  <td className="text-xs whitespace-nowrap">
                    {o.observed_at ? formatIST(o.observed_at) : "—"}
                  </td>
                  <td>
                    <AttackTypeChip attackType={o.attack_type} />
                  </td>
                  <td className="mono">{o.response_status ?? "—"}</td>
                  <td>
                    {cluster ? (
                      <Link
                        to={`${ERRORS_BASE}/${cluster.id}`}
                        className="link text-sm"
                      >
                        {clusterTitle(cluster)}
                      </Link>
                    ) : o.error_id ? (
                      <span className="text-xs text-base-content/50">
                        cluster missing{" "}
                        <Link
                          to={`${ERRORS_BASE}/${o.error_id}`}
                          className="link mono"
                        >
                          {shortId(o.error_id)}
                        </Link>
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="text-xs max-w-[12rem] truncate">
                    {o.detectors?.join(", ") || "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
