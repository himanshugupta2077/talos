/**
 * URL Sink Discovery — Overview tab (PR4).
 *
 * Status strip, distributions, top sinks, empty states, quick actions.
 * Top URL-family candidates: server-side capability filter (K19).
 */

import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import {
  InventoryOnlyBadge,
  NrsBadge,
  SinkCategoryBadge,
  UrlScoreChip,
} from "../../components/url-sink";
import CandidateScore from "../input-validation/components/CandidateScore";
import UrlSinkDisclaimer from "./components/UrlSinkDisclaimer";
import type {
  SinkRow,
  UrlFamilyCandidate,
  UrlSinkEmptyState,
  UrlSinkStatus,
} from "./shared";
import {
  IV_BASE,
  TALOS_CONFIG_URL_SINK,
  URL_SINKS_BASE,
  endpointLabel,
  inventoryHref,
  shortId,
  sortedCounts,
} from "./shared";

export default function OverviewTab({
  projectId,
  status,
  topSinks,
  emptyState,
  onRefresh,
  onGoInventory,
}: {
  projectId: string;
  status: UrlSinkStatus | null;
  topSinks: SinkRow[];
  emptyState: UrlSinkEmptyState;
  onRefresh: () => void;
  onGoInventory: (opts?: {
    nrs_only?: boolean;
    min_score?: number;
  }) => void;
}) {
  const navigate = useNavigate();
  const [candidates, setCandidates] = useState<UrlFamilyCandidate[] | null>(
    null,
  );
  const [candidatesError, setCandidatesError] = useState(false);

  useEffect(() => {
    setCandidatesError(false);
    api
      .get<{ candidates: UrlFamilyCandidate[]; count: number }>(
        "/api/input-validation/candidates",
        {
          project_id: projectId,
          capability: "network_resource_sink",
          min_score: 60,
          limit: 20,
        },
      )
      .then((r) => setCandidates(r.candidates || []))
      .catch(() => {
        setCandidates(null);
        setCandidatesError(true);
      });
  }, [projectId]);

  const thr = status?.score_threshold ?? 45;
  const passiveOn = status?.enabled_passive !== false;
  const byCat = sortedCounts(status?.by_category);
  const byLooks = sortedCounts(status?.by_looks_like);
  const byLoc = sortedCounts(status?.by_location);

  const openDossier = (row: SinkRow) => {
    if (row.param_uuid) {
      navigate(`${IV_BASE}/params/${row.param_uuid}`);
    }
  };

  return (
    <div>
      <UrlSinkDisclaimer />

      {/* Config strip (from per-project status — K20; no mutations here) */}
      <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
        <span
          className={`badge ${passiveOn ? "badge-success" : "badge-ghost"}`}
        >
          passive {passiveOn ? "on" : "off"}
        </span>
        <span className="badge badge-outline">threshold: {thr}</span>
        <span className="badge badge-ghost">
          html/js: {status?.enabled_html_js === false ? "off" : "on"}
        </span>
        <span className="badge badge-ghost">
          iv_probes: {status?.enabled_iv_probes === false ? "off" : "on"}
        </span>
        <Link
          to={TALOS_CONFIG_URL_SINK}
          className="link link-hover text-base-content/50"
        >
          Talos Config → url_sink
        </Link>
        <Link
          to={`${URL_SINKS_BASE}?tab=settings`}
          className="link link-hover text-base-content/50"
        >
          Module Settings
        </Link>
      </div>

      {/* Quick actions */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          type="button"
          className="btn btn-xs btn-primary"
          onClick={() => onGoInventory({ nrs_only: true, min_score: thr })}
        >
          Open inventory (NRS)
        </button>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => onGoInventory({ nrs_only: false, min_score: 0 })}
        >
          Inventory (all scores)
        </button>
        <Link
          to={`${IV_BASE}?tab=candidates&capability=network_resource_sink&min_score=60`}
          className="btn btn-xs btn-ghost"
        >
          IV candidates (NRS)
        </Link>
        <Link
          to={`${URL_SINKS_BASE}?tab=rollups`}
          className="btn btn-xs btn-ghost"
        >
          Rollups
        </Link>
        <button type="button" className="btn btn-xs btn-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {/* Empty / guidance states (FE + API empty_state) */}
      {!passiveOn && (
        <div className="alert alert-warning text-xs py-2 mb-4">
          <span>
            Passive URL sink analysis is disabled for this project. Enable{" "}
            <span className="mono">url_sink.passive.enabled</span> via{" "}
            <Link to={TALOS_CONFIG_URL_SINK} className="link">
              Talos Config
            </Link>
            {" or "}
            <Link to={`${URL_SINKS_BASE}?tab=settings`} className="link">
              Settings
            </Link>
            . Historical parameters remain visible if already captured.
          </span>
        </div>
      )}

      {emptyState.no_params && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          <div className="font-medium mb-1">No parameters yet</div>
          <p className="mb-2">
            Capture traffic with the proxy so Endpoint Intelligence can extract
            parameters and attach <span className="mono">url_features</span>.
          </p>
          <div className="flex flex-wrap gap-2">
            <Link to="/proxy" className="btn btn-xs btn-primary">
              Open Proxy
            </Link>
            <Link to="/flows" className="btn btn-xs btn-ghost">
              Flows
            </Link>
          </div>
        </div>
      )}

      {!emptyState.no_params && emptyState.no_nrs && (
        <div className="panel p-4 mb-4 text-sm text-base-content/70">
          <div className="font-medium mb-1">No network-resource sinks yet</div>
          <p className="mb-2">
            No parameters currently match{" "}
            <span className="mono">possible_network_resource</span> at the
            project threshold. Inventory still lists lower-score or name-only
            hits when filters are relaxed.
          </p>
          <button
            type="button"
            className="btn btn-xs btn-outline"
            onClick={() => onGoInventory({ nrs_only: false, min_score: 0 })}
          >
            Open inventory (all scores)
          </button>
        </div>
      )}

      {/* KPI strip — parameters-only (K14); no default IV-characterized chip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
        <div className="panel p-3">
          <div className="font-medium mb-1">NRS params</div>
          <div className="text-lg font-semibold tabular-nums">
            {status?.nrs_count ?? "—"}
          </div>
          <div className="text-base-content/50">
            possible_network_resource
          </div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Score ≥ {thr}</div>
          <div className="text-lg font-semibold tabular-nums">
            {status?.score_ge_threshold ?? "—"}
          </div>
          <div className="text-base-content/50">project threshold</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">Score ≥ 70</div>
          <div className="text-lg font-semibold tabular-nums">
            {status?.score_ge_70 ?? "—"}
          </div>
          <div className="text-base-content/50">hot prioritization</div>
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">With url_features</div>
          <div className="text-lg font-semibold tabular-nums">
            {status?.with_url_features ?? "—"}
          </div>
          <div className="text-base-content/50">
            of {status?.total_params ?? "—"} params
          </div>
        </div>
      </div>

      {/* Distributions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mb-4">
        <div className="panel p-3">
          <div className="font-medium mb-1">By category</div>
          {byCat.length === 0 ? (
            <div className="text-base-content/40">—</div>
          ) : (
            byCat.slice(0, 10).map(([k, n]) => (
              <div key={k} className="flex justify-between gap-2">
                <span className="truncate mono">{k}</span>
                <span className="mono tabular-nums">{n}</span>
              </div>
            ))
          )}
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">By looks_like</div>
          {byLooks.length === 0 ? (
            <div className="text-base-content/40">—</div>
          ) : (
            byLooks.slice(0, 10).map(([k, n]) => (
              <div key={k} className="flex justify-between gap-2">
                <span className="truncate mono">{k}</span>
                <span className="mono tabular-nums">{n}</span>
              </div>
            ))
          )}
        </div>
        <div className="panel p-3">
          <div className="font-medium mb-1">By location</div>
          {byLoc.length === 0 ? (
            <div className="text-base-content/40">—</div>
          ) : (
            byLoc.map(([k, n]) => (
              <div key={k} className="flex justify-between gap-2">
                <span className="truncate mono">{k}</span>
                <span className="mono tabular-nums">{n}</span>
              </div>
            ))
          )}
        </div>
      </div>

      <Section
        title="Top sinks"
        action={
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            onClick={() => onGoInventory({ nrs_only: true, min_score: thr })}
          >
            View inventory
          </button>
        }
      >
        {topSinks.length === 0 ? (
          <p className="text-sm text-base-content/50">
            No high-priority sinks yet. Capture traffic or relax inventory
            filters.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Score</th>
                  <th>NRS</th>
                  <th>Name</th>
                  <th>Loc</th>
                  <th>Host</th>
                  <th>Endpoint</th>
                  <th>Category</th>
                  <th>Flags</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {topSinks.map((row) => (
                  <tr
                    key={row.parameter_id || row.param_uuid || row.name}
                    className="hover cursor-pointer"
                    onClick={() => openDossier(row)}
                  >
                    <td>
                      <UrlScoreChip score={row.url_score} />
                    </td>
                    <td>
                      <NrsBadge nrs={row.possible_network_resource} />
                    </td>
                    <td className="mono text-xs max-w-[8rem] truncate">
                      {row.name || "—"}
                    </td>
                    <td className="mono text-xs">{row.location || "—"}</td>
                    <td className="mono text-xs max-w-[10rem] truncate">
                      {row.host || "—"}
                    </td>
                    <td className="text-xs max-w-[12rem] truncate">
                      {endpointLabel(row)}
                    </td>
                    <td>
                      <SinkCategoryBadge category={row.name_category} />
                    </td>
                    <td>
                      {row.inventory_only ? <InventoryOnlyBadge /> : null}
                    </td>
                    <td>
                      {row.param_uuid && (
                        <Link
                          to={`${IV_BASE}/params/${row.param_uuid}`}
                          className="link text-xs"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Dossier
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* Top URL-family candidates — K19 server-side filter; hide on empty/error */}
      {!candidatesError && candidates && candidates.length > 0 && (
        <Section
          title="Top URL-family candidates"
          action={
            <Link
              to={`${IV_BASE}?tab=candidates&capability=network_resource_sink&min_score=60`}
              className="btn btn-xs btn-ghost"
            >
              Open IV Candidates
            </Link>
          }
        >
          <p className="text-[10px] text-base-content/45 mb-2">
            Server-filtered by capability{" "}
            <span className="mono">network_resource_sink</span>, min_score 60 —
            prioritization only.
          </p>
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Score</th>
                  <th>Attack</th>
                  <th>Parameter</th>
                  <th>Host</th>
                </tr>
              </thead>
              <tbody>
                {candidates.slice(0, 20).map((c, i) => (
                  <tr
                    key={`${c.param_uuid || c.parameter_name}-${c.attack}-${i}`}
                    className="hover cursor-pointer"
                    onClick={() => {
                      if (c.param_uuid) {
                        navigate(`${IV_BASE}/params/${c.param_uuid}`);
                      }
                    }}
                  >
                    <td>
                      <CandidateScore
                        score={c.score}
                        confidence={c.confidence}
                        showLabel
                      />
                    </td>
                    <td className="mono text-xs">{c.attack || "—"}</td>
                    <td className="mono text-xs">
                      {c.parameter_name || shortId(c.param_uuid)}
                    </td>
                    <td className="mono text-xs max-w-[10rem] truncate">
                      {c.host || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {!candidatesError && candidates && candidates.length === 0 && (
        <div className="panel p-3 mb-4 text-xs text-base-content/60">
          No network-resource candidates yet — passive inventory is still
          useful.{" "}
          <Link to={inventoryHref({ nrs_only: true })} className="link">
            Inventory
          </Link>
          {" · "}
          <Link
            to={`${IV_BASE}?tab=candidates&capability=network_resource_sink&min_score=60`}
            className="link"
          >
            IV Candidates
          </Link>
        </div>
      )}

      <p className="text-[10px] text-base-content/40 mt-2">
        Workspace: <span className="mono">{URL_SINKS_BASE}</span> · Config:{" "}
        <span className="mono">talos config set url_sink.*</span> /{" "}
        <Link to={TALOS_CONFIG_URL_SINK} className="link">
          Talos Config
        </Link>
        {" · "}
        <Link to={`${URL_SINKS_BASE}?tab=settings`} className="link">
          Settings
        </Link>
        {" · "}
        <Link to={`${URL_SINKS_BASE}?tab=rollups`} className="link">
          Rollups
        </Link>
        .
      </p>
    </div>
  );
}
