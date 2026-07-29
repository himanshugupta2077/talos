import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  VERDICTS,
  inputClass,
  selectClass,
  type UnauthResultRow,
} from "./shared";

export default function ResultsTab({
  projectId,
  jobsInFlight,
}: {
  projectId: string;
  jobsInFlight?: boolean;
}) {
  const navigate = useNavigate();
  const [results, setResults] = useState<UnauthResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [authMutation, setAuthMutation] = useState("");
  const [requestMutation, setRequestMutation] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ results: UnauthResultRow[] }>("/api/attack/unauth/results", {
        project_id: projectId,
        verdict: verdict || undefined,
        auth_mutation: authMutation || undefined,
        request_mutation: requestMutation || undefined,
        search: search || undefined,
        limit: 300,
      })
      .then((r) => setResults(r.results || []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false));
  }, [projectId, verdict, authMutation, requestMutation, search]);

  useEffect(() => {
    load();
  }, [load]);

  // Light poll while jobs are in flight
  useEffect(() => {
    if (!jobsInFlight) return;
    const id = window.setInterval(load, 8000);
    return () => window.clearInterval(id);
  }, [jobsInFlight, load]);

  const authOptions = useMemo(
    () =>
      [...new Set(results.map((r) => r.auth_mutation).filter(Boolean))].sort() as string[],
    [results]
  );
  const reqOptions = useMemo(
    () =>
      [
        ...new Set(
          results
            .map((r) => r.request_mutation)
            .filter((v): v is string => Boolean(v))
        ),
      ].sort(),
    [results]
  );

  const columns: Column<UnauthResultRow>[] = [
    {
      key: "captured_at",
      header: "Time",
      className: "text-xs whitespace-nowrap",
      sortValue: (r) => r.captured_at || "",
      render: (r) => formatIST(r.captured_at),
      defaultWidth: 130,
    },
    {
      key: "method",
      header: "Method",
      className: "mono",
      defaultWidth: 70,
    },
    {
      key: "path",
      header: "Path",
      className: "mono text-xs",
      render: (r) => (
        <span title={r.host ? `${r.host}${r.path || ""}` : r.path}>
          {r.path}
        </span>
      ),
      defaultWidth: 200,
    },
    {
      key: "status_code",
      header: "Status",
      defaultWidth: 64,
    },
    {
      key: "auth_mutation",
      header: "Auth mutation",
      className: "text-xs",
      render: (r) => r.auth_mutation || "—",
      defaultWidth: 140,
    },
    {
      key: "request_mutation",
      header: "Request mutation",
      className: "text-xs",
      render: (r) => r.request_mutation || "—",
      defaultWidth: 140,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (r) => <StatusBadge value={r.verdict} />,
      defaultWidth: 100,
    },
    {
      key: "matched_section",
      header: "Evidence",
      className: "text-xs text-base-content/60",
      sortable: false,
      render: (r) => {
        if (!r.matched_section && !r.matched_group) return "—";
        const parts = [r.matched_section, r.matched_group].filter(Boolean);
        return <span title={r.matched_rules || undefined}>{parts.join(" · ")}</span>;
      },
      defaultWidth: 140,
    },
  ];

  return (
    <div>
      <div className="flex flex-wrap items-end gap-2 mb-3">
        <label className="form-control">
          <span className="label-text text-xs">Verdict</span>
          <select
            className={selectClass}
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
          >
            <option value="">any</option>
            {VERDICTS.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Auth mutation</span>
          <select
            className={selectClass}
            value={authMutation}
            onChange={(e) => setAuthMutation(e.target.value)}
          >
            <option value="">any</option>
            {authOptions.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Request mutation</span>
          <select
            className={selectClass}
            value={requestMutation}
            onChange={(e) => setRequestMutation(e.target.value)}
          >
            <option value="">any</option>
            <option value="__none__">none (core only)</option>
            {reqOptions.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Search path / host</span>
          <div className="flex gap-1">
            <input
              className={`${inputClass} w-44`}
              value={searchInput}
              placeholder="/api, host…"
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") setSearch(searchInput.trim());
              }}
            />
            <button
              className="btn btn-xs"
              onClick={() => setSearch(searchInput.trim())}
            >
              Go
            </button>
          </div>
        </label>
        <button className="btn btn-xs btn-ghost" onClick={load}>
          Refresh
        </button>
        <Link to="/findings" className="btn btn-xs btn-ghost">
          Findings
        </Link>
      </div>

      {jobsInFlight && (
        <p className="text-xs text-warning mb-2">
          Jobs still running — table refreshes automatically every few seconds.
        </p>
      )}

      <Section title={`Results (${results.length})`}>
        <DataTable
          columns={columns}
          rows={results}
          rowKey={(r) => r.replay_flow_id}
          storageKey="unauth-results"
          loading={loading}
          emptyLabel="No unauth results yet."
          onRowClick={(r) => navigate(`/flows/${r.replay_flow_id}`)}
        />
      </Section>
    </div>
  );
}
