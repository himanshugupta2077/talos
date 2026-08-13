import { Link } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { ConfirmButton, Section } from "../../components/Common";
import { formatIST } from "../../lib/time";
import PassiveDisclaimer from "./components/PassiveDisclaimer";
import ConfidenceChip from "./components/ConfidenceChip";
import CategoryBadge from "./components/CategoryBadge";
import RedactedValue from "./components/RedactedValue";
import type { DetectionRow, PassiveConfig, PassiveStatus } from "./shared";
import { SECRETS_BASE, shortId } from "./shared";

export default function OverviewTab({
  projectId,
  config,
  status,
  topDetections,
  emptyState,
  onRefresh,
  onGoTab,
}: {
  projectId: string;
  config: PassiveConfig | null;
  status: PassiveStatus | null;
  topDetections: DetectionRow[];
  emptyState: {
    no_documents?: boolean;
    no_detections?: boolean;
    disabled?: boolean;
    has_stale?: boolean;
  };
  onRefresh: () => void;
  onGoTab: (tab: string) => void;
}) {
  const enable = useAction("Enable passive scan", () =>
    api.post("/api/passive/config", { key: "enabled", value: true }, { project_id: projectId }),
  );
  const disable = useAction("Disable passive scan", () =>
    api.post("/api/passive/config", { key: "enabled", value: false }, { project_id: projectId }),
  );
  const rescanAll = useAction("Rescan outdated", () =>
    api.post("/api/passive/rescan", { mode: "all", force: false }, { project_id: projectId }),
  );
  const rescanForce = useAction("Force full rescan", () =>
    api.post("/api/passive/rescan", { mode: "all", force: true }, { project_id: projectId }),
  );

  const enabled = status?.enabled ?? config?.enabled ?? true;
  const byConf = status?.by_confidence || {};
  const byCat = status?.by_category || {};

  return (
    <div>
      <PassiveDisclaimer />

      <div className="panel p-3 mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium mb-1">Secret detection</div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`badge ${enabled ? "badge-success" : "badge-warning"}`}>
              {enabled ? "ON" : "OFF"}
            </span>
            <span className="text-base-content/60">
              {enabled
                ? "Scanning in-scope HTML/JS/JSON/… responses for secrets"
                : "Not scanning — turn on to enqueue and detect secrets"}
            </span>
            <span className="badge badge-outline">
              threshold: {status?.auto_finding_threshold || config?.auto_finding_threshold || "HIGH"}
            </span>
            <span className="badge badge-ghost mono">
              scanner {status?.scanner_version || "—"}
            </span>
            <span className="badge badge-ghost">
              queue max {status?.queue_maxsize ?? config?.queue_maxsize ?? "—"}
            </span>
            {(status?.stale_documents ?? 0) > 0 && (
              <span className="badge badge-warning badge-outline">
                {status!.stale_documents} doc(s) need rescan
              </span>
            )}
          </div>
        </div>
        <div className="flex gap-2 shrink-0">
          {enabled ? (
            <button
              className="btn btn-sm btn-warning"
              disabled={disable.running}
              onClick={async () => {
                await disable.run();
                onRefresh();
              }}
            >
              Turn off
            </button>
          ) : (
            <button
              className="btn btn-sm btn-success"
              disabled={enable.running}
              onClick={async () => {
                await enable.run();
                onRefresh();
              }}
            >
              Turn on
            </button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <button
          className="btn btn-xs btn-outline"
          disabled={rescanAll.running}
          onClick={async () => {
            await rescanAll.run();
            onRefresh();
          }}
        >
          Rescan outdated
        </button>
        <ConfirmButton
          className="btn btn-xs btn-warning"
          confirmText="Force rescan all documents? Can take a while."
          onConfirm={async () => {
            await rescanForce.run();
            onRefresh();
          }}
        >
          Force full rescan
        </ConfirmButton>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("detections")}>
          All detections
        </button>
        <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("settings")}>
          Settings
        </button>
        <Link to="/findings" className="btn btn-xs btn-ghost">
          Findings
        </Link>
      </div>

      {emptyState.disabled && (
        <div className="panel p-4 mb-4 text-sm border border-warning/40 bg-warning/5">
          <strong>Secret detection is off.</strong> Capture continues, but responses
          are not scanned for secrets. Use <strong>Turn on</strong> above or{" "}
          <span className="mono">talos passive config set enabled true</span>.
        </div>
      )}

      {emptyState.no_documents && !emptyState.disabled && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          No source documents yet. Browse in-scope apps with the proxy running —
          HTML, JS, JSON, CSS, and source maps are scanned automatically when
          secret detection is on.
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3">
          <div className="font-medium mb-1">Documents</div>
          <div className="text-lg font-semibold">{status?.documents ?? "—"}</div>
          <div>Scanned: {status?.documents_scanned ?? "—"}</div>
          <div>Pending: {status?.documents_pending ?? "—"}</div>
          <div>Error: {status?.documents_error ?? "—"}</div>
          <div>Too large: {status?.documents_too_large ?? "—"}</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Detections</div>
          <div className="text-lg font-semibold">{status?.detections ?? "—"}</div>
          <div>With finding: {status?.detections_with_finding ?? "—"}</div>
          <div>Stale docs: {status?.stale_documents ?? "—"}</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">By confidence</div>
          {Object.keys(byConf).length === 0 && <div className="text-base-content/40">—</div>}
          {Object.entries(byConf).map(([k, n]) => (
            <div key={k} className="flex justify-between gap-2">
              <span className="truncate">{k}</span>
              <span className="mono">{n}</span>
            </div>
          ))}
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">By category</div>
          {Object.keys(byCat).length === 0 && <div className="text-base-content/40">—</div>}
          {Object.entries(byCat).map(([k, n]) => (
            <div key={k} className="flex justify-between gap-2">
              <span className="truncate">{k}</span>
              <span className="mono">{n}</span>
            </div>
          ))}
        </div>
      </div>

      <Section
        title="Recent detections"
        action={
          <button className="btn btn-xs btn-ghost" onClick={() => onGoTab("detections")}>
            View all
          </button>
        }
      >
        {topDetections.length === 0 ? (
          <p className="text-sm text-base-content/50">No detections yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Detector</th>
                  <th>Category</th>
                  <th>Confidence</th>
                  <th>Finding</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {topDetections.map((d) => (
                  <tr key={d.id} className="hover">
                    <td>
                      <Link
                        to={`${SECRETS_BASE}/detections/${d.id}`}
                        className="link link-hover"
                      >
                        <RedactedValue value={d.redacted_value} />
                      </Link>
                    </td>
                    <td className="mono text-xs">{d.detector_id}</td>
                    <td>
                      <CategoryBadge category={d.category} />
                    </td>
                    <td>
                      <ConfidenceChip level={d.confidence_level} score={d.confidence_score} />
                    </td>
                    <td>
                      {d.finding_id ? (
                        <Link to={`/findings/${d.finding_id}`} className="link mono text-xs">
                          {shortId(d.finding_id)}
                        </Link>
                      ) : (
                        <span className="text-base-content/30">—</span>
                      )}
                    </td>
                    <td className="text-xs text-base-content/50">
                      {d.created_at ? formatIST(d.created_at) : "—"}
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
