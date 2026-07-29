import { Link } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { ConfirmButton, Section } from "../../components/Common";
import { formatIST } from "../../lib/time";
import ErrorDisclaimer from "./components/ErrorDisclaimer";
import SeverityBadge from "./components/SeverityBadge";
import CategoryBadge from "./components/CategoryBadge";
import TechFlags from "./components/TechFlags";
import type {
  ErrorClusterRow,
  ErrorIntelConfig,
  ErrorIntelEmptyState,
  ErrorIntelStatus,
} from "./shared";
import { ERRORS_BASE, clusterTitle, shortId } from "./shared";

export default function OverviewTab({
  projectId,
  config,
  status,
  topClusters,
  emptyState,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  config: ErrorIntelConfig | null;
  status: ErrorIntelStatus | null;
  topClusters: ErrorClusterRow[];
  emptyState: ErrorIntelEmptyState;
  onRefresh: () => void;
  onGoTab: (tab: string) => void;
}) {
  const enable = useAction("Enable error intelligence", () =>
    api.post(
      "/api/error-intel/config",
      { key: "enabled", value: true },
      { project_id: projectId },
    ),
  );
  const disable = useAction("Disable error intelligence", () =>
    api.post(
      "/api/error-intel/config",
      { key: "enabled", value: false },
      { project_id: projectId },
    ),
  );
  const rescanOutdated = useAction("Rescan outdated", () =>
    api.post(
      "/api/error-intel/rescan",
      { mode: "all", outdated: true, force: false, limit: 200 },
      { project_id: projectId },
    ),
  );
  const rescanForce = useAction("Force full rescan", () =>
    api.post(
      "/api/error-intel/rescan",
      { mode: "all", force: true, limit: 200 },
      { project_id: projectId },
    ),
  );

  const enabled = status?.enabled ?? config?.enabled ?? false;
  const bySev = status?.by_severity || {};
  const byCat = status?.by_category || {};
  const lowCount = bySev.low ?? 0;
  const totalClusters = status?.clusters ?? 0;
  const infraHttp =
    (byCat.infrastructure ?? 0) + (byCat.http ?? 0);
  const showFloodBanner =
    totalClusters > 0 &&
    (lowCount > totalClusters * 0.5 || infraHttp > totalClusters * 0.4);

  const sevOrder = ["critical", "high", "medium", "low"] as const;

  return (
    <div>
      <ErrorDisclaimer />

      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span className={`badge ${enabled ? "badge-success" : "badge-ghost"}`}>
          {enabled ? "enabled" : "disabled"}
        </span>
        <span className="badge badge-outline">
          store_generic:{" "}
          {status?.store_generic_http_errors ??
          config?.store_generic_http_errors
            ? "on"
            : "off"}
        </span>
        <span className="badge badge-ghost mono">
          scanner {status?.scanner_version || "—"}
        </span>
        <span className="badge badge-ghost">
          queue max {status?.queue_maxsize ?? config?.queue_maxsize ?? "—"}
        </span>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        {enabled ? (
          <button
            className="btn btn-xs"
            disabled={disable.running}
            onClick={async () => {
              await disable.run();
              onRefresh();
            }}
          >
            Disable
          </button>
        ) : (
          <button
            className="btn btn-xs btn-primary"
            disabled={enable.running}
            onClick={async () => {
              await enable.run();
              onRefresh();
            }}
          >
            Enable
          </button>
        )}
        <button
          className="btn btn-xs btn-outline"
          disabled={rescanOutdated.running}
          onClick={async () => {
            await rescanOutdated.run();
            onRefresh();
          }}
        >
          Rescan outdated
        </button>
        <ConfirmButton
          className="btn btn-xs btn-warning"
          confirmText="Force rescan all recent error-like flows? Can take a while."
          onConfirm={async () => {
            await rescanForce.run();
            onRefresh();
          }}
        >
          Force full rescan
        </ConfirmButton>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("errors")}>
          All errors
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("settings")}>
          Settings
        </button>
      </div>

      {!enabled && (
        <div className="alert alert-warning text-xs py-2 mb-4">
          <span>
            Scanner disabled — enable to analyze new captures. Historical
            clusters remain available.
          </span>
        </div>
      )}

      {emptyState.no_clusters && enabled && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No error clusters yet. Browse in-scope apps with the proxy running, or
          wait for active tests that produce error-like responses.{" "}
          <Link to="/proxy" className="link">
            Open Proxy
          </Link>
          {" · "}
          <Link to="/scheduler" className="link">
            Scheduler
          </Link>
        </div>
      )}

      {showFloodBanner && (
        <div className="alert alert-warning text-xs py-2 mb-4">
          <span>
            Many low infrastructure/http clusters detected (default pages may be
            stored — see known noise). Errors tab defaults to{" "}
            <strong>medium+</strong>; use the hide-noise chip when including low,
            or tighten Settings (<span className="mono">store_generic_http_errors</span>
            ).
          </span>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3">
          <div className="font-medium mb-1">Clusters</div>
          <div className="text-lg font-semibold">{status?.clusters ?? "—"}</div>
          <div>Observations: {status?.observations ?? "—"}</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">By severity</div>
          {sevOrder.every((k) => !bySev[k]) && (
            <div className="text-base-content/40">—</div>
          )}
          {sevOrder.map((k) =>
            bySev[k] != null ? (
              <div key={k} className="flex justify-between gap-2">
                <span className="truncate capitalize">{k}</span>
                <span className="mono">{bySev[k]}</span>
              </div>
            ) : null,
          )}
        </div>
        <div className="panel p-3 md:col-span-2">
          <div className="font-medium mb-1">By category</div>
          {Object.keys(byCat).length === 0 && (
            <div className="text-base-content/40">—</div>
          )}
          {Object.entries(byCat).map(([k, n]) => (
            <div key={k} className="flex justify-between gap-2">
              <span className="truncate">{k}</span>
              <span className="mono">{n}</span>
            </div>
          ))}
        </div>
      </div>

      <Section
        title="Top clusters"
        action={
          <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("errors")}>
            View all
          </button>
        }
      >
        {topClusters.length === 0 ? (
          <p className="text-sm text-base-content/50">No clusters yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Exception / message</th>
                  <th>Category</th>
                  <th>Flags</th>
                  <th>Obs</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {topClusters.map((c) => (
                  <tr key={c.id} className="hover">
                    <td>
                      <SeverityBadge severity={c.severity} />
                    </td>
                    <td>
                      <Link
                        to={`${ERRORS_BASE}/${c.id}`}
                        className="link link-hover text-sm"
                      >
                        {clusterTitle(c)}
                      </Link>
                      <div className="text-[10px] text-base-content/40 mono">
                        {shortId(c.id)}
                      </div>
                    </td>
                    <td>
                      <CategoryBadge category={c.category} />
                    </td>
                    <td>
                      <TechFlags cluster={c} compact />
                    </td>
                    <td className="mono">{c.observation_count}</td>
                    <td className="text-xs text-base-content/50">
                      {c.last_seen ? formatIST(c.last_seen) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <p className="text-xs text-base-content/40 mt-2">
        Findings bridge later — intelligence only. No auto Findings in v1.
      </p>
    </div>
  );
}
