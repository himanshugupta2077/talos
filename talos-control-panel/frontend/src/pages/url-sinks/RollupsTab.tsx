/**
 * URL Sink Discovery — Rollups tab (PR5).
 *
 * By host / endpoint / category aggregates. Click row → Inventory with filter.
 */

import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import { UrlScoreChip } from "../../components/url-sink";
import UrlSinkDisclaimer from "./components/UrlSinkDisclaimer";
import type {
  CategoryRollupRow,
  EndpointRollupRow,
  HostRollupRow,
  RollupKind,
} from "./shared";
import {
  DEFAULT_MIN_SCORE,
  DEFAULT_NRS_ONLY,
  endpointLabel,
  inventoryHref,
} from "./shared";

export default function RollupsTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [kind, setKind] = useState<RollupKind>("host");
  const [minScore, setMinScore] = useState(DEFAULT_MIN_SCORE);
  const [nrsOnly, setNrsOnly] = useState(DEFAULT_NRS_ONLY);
  const [hostRows, setHostRows] = useState<HostRollupRow[]>([]);
  const [epRows, setEpRows] = useState<EndpointRollupRow[]>([]);
  const [catRows, setCatRows] = useState<CategoryRollupRow[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    const q = {
      project_id: projectId,
      min_score: minScore,
      nrs_only: nrsOnly,
      limit: 50,
    };
    Promise.all([
      api
        .get<{ rollup: HostRollupRow[] }>("/api/url-sink/rollups/host", q)
        .then((r) => setHostRows(r.rollup || []))
        .catch(() => setHostRows([])),
      api
        .get<{ rollup: EndpointRollupRow[] }>(
          "/api/url-sink/rollups/endpoint",
          q,
        )
        .then((r) => setEpRows(r.rollup || []))
        .catch(() => setEpRows([])),
      api
        .get<{ rollup: CategoryRollupRow[] }>(
          "/api/url-sink/rollups/category",
          q,
        )
        .then((r) => setCatRows(r.rollup || []))
        .catch(() => setCatRows([])),
    ]).finally(() => setLoading(false));
  }, [projectId, minScore, nrsOnly]);

  useEffect(() => {
    load();
  }, [load]);

  const goInventory = (overrides: {
    host?: string;
    endpoint_id?: string;
    category?: string;
  }) => {
    navigate(
      inventoryHref({
        min_score: minScore,
        nrs_only: nrsOnly,
        host: overrides.host || "",
        endpoint_id: overrides.endpoint_id || "",
        category: overrides.category || "",
        offset: 0,
      }),
    );
  };

  return (
    <div className="space-y-4">
      <UrlSinkDisclaimer />

      <p className="text-xs text-base-content/55">
        Aggregates use the same score / NRS gates as Inventory (defaults{" "}
        <span className="mono">min_score={DEFAULT_MIN_SCORE}</span>,{" "}
        <span className="mono">nrs_only</span>). Click a row to open Inventory
        with that filter. Prioritization only — not Findings.
      </p>

      <div className="flex flex-wrap gap-2 items-center">
        <div role="tablist" className="tabs tabs-boxed tabs-sm">
          {(
            [
              ["host", "By host"],
              ["endpoint", "By endpoint"],
              ["category", "By category"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              className={`tab ${kind === id ? "tab-active" : ""}`}
              onClick={() => setKind(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1 text-xs">
          <span className="text-base-content/50">min_score</span>
          <input
            type="number"
            min={0}
            max={100}
            className="input input-xs input-bordered w-16"
            value={minScore}
            onChange={(e) =>
              setMinScore(
                Math.max(0, Math.min(100, Number(e.target.value) || 0)),
              )
            }
            aria-label="Rollup minimum score"
          />
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={nrsOnly}
            onChange={(e) => setNrsOnly(e.target.checked)}
          />
          <span className="label-text text-xs">nrs_only</span>
        </label>
        <button
          type="button"
          className="btn btn-xs"
          onClick={load}
          disabled={loading}
        >
          {loading ? "Loading…" : "Refresh"}
        </button>
        <Link
          to={inventoryHref({ min_score: minScore, nrs_only: nrsOnly })}
          className="btn btn-xs btn-ghost"
        >
          Open inventory
        </Link>
      </div>

      {kind === "host" && (
        <Section title="By host">
          {hostRows.length === 0 ? (
            <p className="text-sm text-base-content/50">
              No host rollups for current filters.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="table table-xs">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Count</th>
                    <th>NRS</th>
                    <th>Max score</th>
                    <th>Top categories</th>
                  </tr>
                </thead>
                <tbody>
                  {hostRows.map((r) => (
                    <tr
                      key={r.key || "empty"}
                      className="hover cursor-pointer"
                      onClick={() => goInventory({ host: r.key || "" })}
                    >
                      <td className="mono text-xs max-w-[16rem] truncate">
                        {r.key || "(empty)"}
                      </td>
                      <td className="mono tabular-nums">{r.count ?? 0}</td>
                      <td className="mono tabular-nums">{r.nrs_count ?? 0}</td>
                      <td>
                        <UrlScoreChip score={r.max_score} />
                      </td>
                      <td className="text-xs mono">
                        {(r.top_categories || Object.keys(r.categories || {}))
                          .slice(0, 4)
                          .join(", ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {kind === "endpoint" && (
        <Section title="By endpoint">
          {epRows.length === 0 ? (
            <p className="text-sm text-base-content/50">
              No endpoint rollups for current filters.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="table table-xs">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Host</th>
                    <th>Count</th>
                    <th>NRS</th>
                    <th>Max score</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {epRows.map((r) => (
                    <tr
                      key={r.endpoint_id || r.key}
                      className="hover cursor-pointer"
                      onClick={() =>
                        goInventory({ endpoint_id: r.endpoint_id || "" })
                      }
                    >
                      <td className="text-xs max-w-[14rem] truncate">
                        {endpointLabel(r)}
                      </td>
                      <td className="mono text-xs max-w-[10rem] truncate">
                        {r.host || "—"}
                      </td>
                      <td className="mono tabular-nums">{r.count ?? 0}</td>
                      <td className="mono tabular-nums">{r.nrs_count ?? 0}</td>
                      <td>
                        <UrlScoreChip score={r.max_score} />
                      </td>
                      <td>
                        {r.endpoint_id && (
                          <Link
                            to={`/endpoints/${r.endpoint_id}`}
                            className="link text-xs"
                            onClick={(e) => e.stopPropagation()}
                          >
                            Detail
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
      )}

      {kind === "category" && (
        <Section title="By category">
          {catRows.length === 0 ? (
            <p className="text-sm text-base-content/50">
              No category rollups for current filters.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="table table-xs">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Count</th>
                    <th>Max score</th>
                    <th>Median</th>
                  </tr>
                </thead>
                <tbody>
                  {catRows.map((r) => {
                    const cat =
                      r.key && r.key !== "(none)" ? r.key : undefined;
                    return (
                      <tr
                        key={r.key || "none"}
                        className="hover cursor-pointer"
                        onClick={() =>
                          cat
                            ? goInventory({ category: cat })
                            : navigate(
                                inventoryHref({
                                  min_score: minScore,
                                  nrs_only: nrsOnly,
                                }),
                              )
                        }
                      >
                        <td className="mono text-xs">{r.key || "(none)"}</td>
                        <td className="mono tabular-nums">{r.count ?? 0}</td>
                        <td>
                          <UrlScoreChip score={r.max_score} />
                        </td>
                        <td className="mono tabular-nums">
                          {r.median_score ?? "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

    </div>
  );
}
