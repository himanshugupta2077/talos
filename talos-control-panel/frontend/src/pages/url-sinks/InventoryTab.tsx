/**
 * URL Sink Discovery — Inventory tab (PR4).
 *
 * Primary filterable table. Query keys = API K13 canon.
 * Row click → SideDrawer; primary handoff = IV dossier (never bulk Run IV).
 */

import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import SideDrawer from "../../components/SideDrawer";
import {
  InventoryOnlyBadge,
  NrsBadge,
  SinkCategoryBadge,
  UrlScoreChip,
} from "../../components/url-sink";
import UrlFeaturesPanel from "./components/UrlFeaturesPanel";
import UrlSinkDisclaimer from "./components/UrlSinkDisclaimer";
import type { InventoryFilters, SinkRow, TriBool } from "./shared";
import {
  DEFAULT_LIMIT,
  DEFAULT_MIN_SCORE,
  DEFAULT_NRS_ONLY,
  DEFAULT_SORT,
  IV_BASE,
  LOCATION_OPTIONS,
  LOOKS_LIKE_OPTIONS,
  SINK_CATEGORIES,
  SORT_OPTIONS,
  applyFiltersToSearchParams,
  defaultInventoryFilters,
  downloadJson,
  endpointLabel,
  filtersFromSearchParams,
  inputClass,
  inventoryApiParams,
  selectClass,
  shortId,
  truncateValue,
} from "./shared";

export default function InventoryTab({ projectId }: { projectId: string }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<InventoryFilters>(() =>
    filtersFromSearchParams(searchParams),
  );
  // Draft fields for Apply pattern (host/search/min_score)
  const [draftMinScore, setDraftMinScore] = useState(String(filters.min_score));
  const [draftHost, setDraftHost] = useState(filters.host);
  const [draftSearch, setDraftSearch] = useState(filters.search);
  const [draftNrsOnly, setDraftNrsOnly] = useState(filters.nrs_only);
  const [draftCategory, setDraftCategory] = useState(filters.category);
  const [draftLooksLike, setDraftLooksLike] = useState(filters.looks_like);
  const [draftLocation, setDraftLocation] = useState(filters.location);
  const [draftSort, setDraftSort] = useState(filters.sort);
  const [draftLimit, setDraftLimit] = useState(filters.limit);
  const [draftHasIv, setDraftHasIv] = useState<TriBool>(filters.has_iv_profile);
  const [draftHasObs, setDraftHasObs] = useState<TriBool>(
    filters.has_url_sink_obs,
  );

  const [rows, setRows] = useState<SinkRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<SinkRow | null>(null);
  const [detail, setDetail] = useState<SinkRow | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Sync from URL when deep-link params change externally
  useEffect(() => {
    const next = filtersFromSearchParams(searchParams);
    setFilters(next);
    setDraftMinScore(String(next.min_score));
    setDraftHost(next.host);
    setDraftSearch(next.search);
    setDraftNrsOnly(next.nrs_only);
    setDraftCategory(next.category);
    setDraftLooksLike(next.looks_like);
    setDraftLocation(next.location);
    setDraftSort(next.sort);
    setDraftLimit(next.limit);
    setDraftHasIv(next.has_iv_profile);
    setDraftHasObs(next.has_url_sink_obs);
  }, [searchParams]);

  const load = useCallback(() => {
    setLoading(true);
    const params = inventoryApiParams(projectId, filters);
    api
      .get<{ items: SinkRow[]; total_matched: number; count: number }>(
        "/api/url-sink/inventory",
        params,
      )
      .then((r) => {
        setRows(r.items || []);
        setTotal(r.total_matched ?? (r.items || []).length);
      })
      .catch(() => {
        setRows([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  }, [projectId, filters]);

  useEffect(() => {
    load();
  }, [load]);

  const applyDraft = () => {
    const next = defaultInventoryFilters({
      min_score: Math.max(
        0,
        Math.min(100, Number(draftMinScore) || DEFAULT_MIN_SCORE),
      ),
      nrs_only: draftNrsOnly,
      category: draftCategory,
      looks_like: draftLooksLike,
      location: draftLocation,
      host: draftHost.trim(),
      endpoint_id: filters.endpoint_id,
      has_iv_profile: draftHasIv,
      has_url_sink_obs: draftHasObs,
      search: draftSearch.trim(),
      sort: draftSort,
      limit: draftLimit,
      offset: 0,
      include_iv: filters.include_iv,
    });
    setFilters(next);
    setSearchParams(
      applyFiltersToSearchParams(searchParams, next, { tab: "inventory" }),
      { replace: true },
    );
  };

  const resetFilters = () => {
    const next = defaultInventoryFilters();
    setFilters(next);
    setDraftMinScore(String(DEFAULT_MIN_SCORE));
    setDraftHost("");
    setDraftSearch("");
    setDraftNrsOnly(DEFAULT_NRS_ONLY);
    setDraftCategory("");
    setDraftLooksLike("");
    setDraftLocation("");
    setDraftSort(DEFAULT_SORT);
    setDraftLimit(DEFAULT_LIMIT);
    setDraftHasIv(null);
    setDraftHasObs(null);
    setSearchParams(
      applyFiltersToSearchParams(new URLSearchParams(), next, {
        tab: "inventory",
      }),
      { replace: true },
    );
  };

  const page = (delta: number) => {
    const nextOffset = Math.max(0, filters.offset + delta * filters.limit);
    if (nextOffset === filters.offset) return;
    if (delta > 0 && filters.offset + rows.length >= total) return;
    const next = { ...filters, offset: nextOffset };
    setFilters(next);
    setSearchParams(
      applyFiltersToSearchParams(searchParams, next, { tab: "inventory" }),
      { replace: true },
    );
  };

  const openRow = (row: SinkRow) => {
    setSelected(row);
    setDetail(row);
    setDetailLoading(true);
    const q: Record<string, string> = { project_id: projectId };
    const path = row.parameter_id
      ? `/api/url-sink/params/${row.parameter_id}`
      : "/api/url-sink/params";
    if (!row.parameter_id && row.param_uuid) {
      q.param_uuid = row.param_uuid;
    }
    api
      .get<{ item: SinkRow }>(path, q)
      .then((r) => setDetail(r.item || row))
      .catch(() => setDetail(row))
      .finally(() => setDetailLoading(false));
  };

  const columns: Column<SinkRow>[] = [
    {
      key: "url_score",
      header: "Score",
      sortValue: (r) => r.url_score ?? 0,
      render: (r) => <UrlScoreChip score={r.url_score} />,
    },
    {
      key: "possible_network_resource",
      header: "NRS",
      render: (r) => <NrsBadge nrs={r.possible_network_resource} />,
    },
    {
      key: "name",
      header: "Name",
      render: (r) => (
        <div>
          <span className="mono text-xs">{r.name || "—"}</span>
          {r.inventory_only && (
            <InventoryOnlyBadge className="ml-1" />
          )}
        </div>
      ),
    },
    {
      key: "location",
      header: "Loc",
      className: "mono text-xs",
      render: (r) => r.location || "—",
    },
    {
      key: "host",
      header: "Host",
      className: "mono text-xs max-w-[10rem] truncate",
      render: (r) => (
        <span title={r.host || undefined}>{r.host || "—"}</span>
      ),
    },
    {
      key: "endpoint",
      header: "Endpoint",
      className: "text-xs max-w-[12rem] truncate",
      render: (r) => (
        <span title={endpointLabel(r)}>{endpointLabel(r)}</span>
      ),
    },
    {
      key: "name_category",
      header: "Category",
      render: (r) => <SinkCategoryBadge category={r.name_category} />,
    },
    {
      key: "looks_like",
      header: "Looks",
      render: (r) =>
        r.looks_like?.length ? (
          <span className="mono text-[10px] text-base-content/70">
            {r.looks_like.slice(0, 3).join(", ")}
            {r.looks_like.length > 3 ? "…" : ""}
          </span>
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "example_values",
      header: "Sample",
      className: "mono text-[10px] max-w-[8rem] truncate",
      render: (r) => {
        const v = r.example_values?.[0];
        if (v == null) return <span className="text-base-content/30">—</span>;
        return <span title={String(v)}>{truncateValue(v, 36)}</span>;
      },
    },
  ];

  const pageStart = total === 0 ? 0 : filters.offset + 1;
  const pageEnd = Math.min(filters.offset + rows.length, total);

  return (
    <div>
      <UrlSinkDisclaimer />

      <p className="text-xs text-base-content/55 mb-3">
        Default filters:{" "}
        <span className="mono">min_score=45</span>,{" "}
        <span className="mono">nrs_only=true</span>. Optional{" "}
        <span className="mono">has_iv_profile</span> /{" "}
        <span className="mono">has_url_sink_obs</span> load a capped IV uuid
        index (not used unless set). Scores are prioritization only. Open a row
        for evidence; primary handoff is the IV parameter dossier
        (characterization), not a bulk Run from this list.
      </p>

      {/* Filters — K13 keys */}
      <div className="flex flex-wrap gap-2 mb-3 items-center">
        <label className="flex items-center gap-1 text-xs">
          <span className="text-base-content/50">min_score</span>
          <input
            type="number"
            min={0}
            max={100}
            className={`${inputClass} w-16`}
            value={draftMinScore}
            onChange={(e) => setDraftMinScore(e.target.value)}
            aria-label="Minimum URL sink score"
          />
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={draftNrsOnly}
            onChange={(e) => setDraftNrsOnly(e.target.checked)}
          />
          <span className="label-text text-xs">nrs_only</span>
        </label>
        <select
          className={selectClass}
          value={draftCategory}
          onChange={(e) => setDraftCategory(e.target.value)}
          aria-label="Name category"
        >
          <option value="">category: any</option>
          {SINK_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={draftLooksLike}
          onChange={(e) => setDraftLooksLike(e.target.value)}
          aria-label="Looks like"
        >
          <option value="">looks_like: any</option>
          {LOOKS_LIKE_OPTIONS.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={draftLocation}
          onChange={(e) => setDraftLocation(e.target.value)}
          aria-label="Location"
        >
          <option value="">location: any</option>
          {LOCATION_OPTIONS.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          className={`${inputClass} w-36`}
          placeholder="host (contains)"
          value={draftHost}
          onChange={(e) => setDraftHost(e.target.value)}
          aria-label="Host substring filter"
        />
        <input
          className={`${inputClass} w-44`}
          placeholder="search name/path/host"
          value={draftSearch}
          onChange={(e) => setDraftSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyDraft();
          }}
          aria-label="Search name path host"
        />
        <select
          className={selectClass}
          value={
            draftHasIv == null ? "" : draftHasIv ? "true" : "false"
          }
          onChange={(e) => {
            const v = e.target.value;
            setDraftHasIv(v === "" ? null : v === "true");
          }}
          aria-label="Has IV profile"
          title="Requires a capped IV profile index (not on hot path)"
        >
          <option value="">has_iv_profile: any</option>
          <option value="true">has IV profile</option>
          <option value="false">no IV profile</option>
        </select>
        <select
          className={selectClass}
          value={
            draftHasObs == null ? "" : draftHasObs ? "true" : "false"
          }
          onChange={(e) => {
            const v = e.target.value;
            setDraftHasObs(v === "" ? null : v === "true");
          }}
          aria-label="Has URL sink observation"
          title="observed.url_sink.confidence > 0 (capped profile index)"
        >
          <option value="">has_url_sink_obs: any</option>
          <option value="true">has url_sink obs</option>
          <option value="false">no url_sink obs</option>
        </select>
        <select
          className={selectClass}
          value={draftSort}
          onChange={(e) =>
            setDraftSort(e.target.value as InventoryFilters["sort"])
          }
          aria-label="Sort"
        >
          {SORT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              sort: {o.label}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={draftLimit}
          onChange={(e) => setDraftLimit(Number(e.target.value))}
          aria-label="Page size"
        >
          {[50, 100, 200, 500].map((n) => (
            <option key={n} value={n}>
              limit {n}
            </option>
          ))}
        </select>
        <button type="button" className="btn btn-xs btn-primary" onClick={applyDraft}>
          Apply
        </button>
        <button type="button" className="btn btn-xs btn-ghost" onClick={resetFilters}>
          Reset
        </button>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={load}
          disabled={loading}
        >
          Refresh
        </button>
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={() =>
            downloadJson(`url-sinks-inventory-${projectId}.json`, {
              filters,
              total_matched: total,
              items: rows,
            })
          }
          disabled={rows.length === 0}
        >
          Download JSON
        </button>
        <span className="text-xs text-base-content/50">
          {loading
            ? "Loading…"
            : `${pageStart}–${pageEnd} of ${total} matched`}
        </span>
      </div>

      {filters.endpoint_id && (
        <div className="alert alert-ghost border border-base-300 text-xs py-1.5 mb-3">
          <span>
            Filtered to endpoint{" "}
            <span className="mono">{shortId(filters.endpoint_id, 12)}</span>
            .{" "}
            <button
              type="button"
              className="link"
              onClick={() => {
                const next = { ...filters, endpoint_id: "", offset: 0 };
                setFilters(next);
                setSearchParams(
                  applyFiltersToSearchParams(searchParams, next, {
                    tab: "inventory",
                  }),
                  { replace: true },
                );
              }}
            >
              Clear endpoint filter
            </button>
          </span>
        </div>
      )}

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) =>
          String(r.parameter_id || r.param_uuid || `${r.host}:${r.name}`)
        }
        onRowClick={openRow}
        emptyLabel="No sinks match filters. Try lowering min_score or clearing nrs_only."
        storageKey="url-sink-inventory"
      />

      <div className="flex items-center gap-2 mt-3">
        <button
          type="button"
          className="btn btn-xs"
          disabled={filters.offset <= 0 || loading}
          onClick={() => page(-1)}
        >
          Prev
        </button>
        <button
          type="button"
          className="btn btn-xs"
          disabled={filters.offset + rows.length >= total || loading}
          onClick={() => page(1)}
        >
          Next
        </button>
      </div>

      <SideDrawer
        open={!!selected}
        onClose={() => {
          setSelected(null);
          setDetail(null);
        }}
        title={
          selected
            ? `${selected.name || "parameter"} · ${selected.location || "?"}`
            : "Sink detail"
        }
        wide
      >
        {selected && (
          <div className="space-y-4 text-sm">
            {detailLoading && (
              <p className="text-xs text-base-content/50">Loading detail…</p>
            )}
            <div className="text-xs space-y-1">
              <div>
                <span className="text-base-content/50">Host </span>
                <span className="mono">{detail?.host || selected.host || "—"}</span>
              </div>
              <div>
                <span className="text-base-content/50">Endpoint </span>
                <span className="mono">
                  {endpointLabel(detail || selected)}
                </span>
              </div>
              <div>
                <span className="text-base-content/50">param_uuid </span>
                <span className="mono text-[10px] break-all">
                  {detail?.param_uuid || selected.param_uuid || "—"}
                </span>
              </div>
            </div>

            <UrlFeaturesPanel
              urlFeatures={
                (detail?.url_features || selected.url_features) as Record<
                  string,
                  unknown
                >
              }
              urlScore={detail?.url_score ?? selected.url_score}
              nrs={
                detail?.possible_network_resource ??
                selected.possible_network_resource
              }
              nameCategory={detail?.name_category ?? selected.name_category}
              looksLike={detail?.looks_like ?? selected.looks_like}
              location={detail?.location ?? selected.location}
              name={detail?.name ?? selected.name}
              exampleValues={
                detail?.example_values ?? selected.example_values
              }
            />

            {detail?.iv?.has_profile && (
              <div className="panel p-3 text-xs">
                <div className="font-medium mb-1">IV slice (if profiled)</div>
                {detail.iv.url_sink_confidence != null && (
                  <div>
                    url_sink confidence:{" "}
                    <span className="mono">{detail.iv.url_sink_confidence}</span>
                  </div>
                )}
                {detail.iv.top_url_candidate && (
                  <div>
                    top candidate:{" "}
                    <span className="mono">
                      {detail.iv.top_url_candidate.attack} @{" "}
                      {detail.iv.top_url_candidate.score}
                    </span>
                  </div>
                )}
                {detail.iv.capabilities && detail.iv.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {detail.iv.capabilities.map((c) => (
                      <span key={c} className="badge badge-ghost badge-xs mono">
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-2 border-t border-base-300">
              {(detail?.param_uuid || selected.param_uuid) && (
                <Link
                  className="btn btn-xs btn-primary"
                  to={`${IV_BASE}/params/${detail?.param_uuid || selected.param_uuid}`}
                >
                  IV dossier
                </Link>
              )}
              <Link
                className="btn btn-xs btn-outline"
                to={`${IV_BASE}?tab=candidates&capability=network_resource_sink&min_score=60`}
              >
                IV candidates
              </Link>
              {(detail?.endpoint_id || selected.endpoint_id) && (
                <>
                  <Link
                    className="btn btn-xs btn-ghost"
                    to={`/endpoints/${detail?.endpoint_id || selected.endpoint_id}`}
                  >
                    Endpoint
                  </Link>
                  <Link
                    className="btn btn-xs btn-ghost"
                    to={`/flows?endpoint=${detail?.endpoint_id || selected.endpoint_id}`}
                  >
                    Flows
                  </Link>
                </>
              )}
            </div>
            <p className="text-[10px] text-base-content/45">
              Inventory does not bulk-run IV. Characterize from the parameter
              dossier (name scope). Inventory-only surfaces (response / jwt.*)
              are not normal injectables.
            </p>
          </div>
        )}
      </SideDrawer>
    </div>
  );
}
