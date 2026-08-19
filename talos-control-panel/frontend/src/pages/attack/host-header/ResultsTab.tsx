import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  FAMILIES,
  VERDICTS,
  inputClass,
  selectClass,
  type HostHeaderResultRow,
} from "./shared";

export default function ResultsTab({
  projectId,
  jobsInFlight,
}: {
  projectId: string;
  jobsInFlight?: boolean;
}) {
  const navigate = useNavigate();
  const [results, setResults] = useState<HostHeaderResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [family, setFamily] = useState("");
  const [technique, setTechnique] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ results: HostHeaderResultRow[] }>("/api/attack/host-header/results", {
        project_id: projectId,
        verdict: verdict || undefined,
        family: family || undefined,
        technique: technique || undefined,
        host: search || undefined,
        limit: 300,
      })
      .then((r) => setResults(r.results || []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false));
  }, [projectId, verdict, family, technique, search]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!jobsInFlight) return;
    const id = window.setInterval(load, 8000);
    return () => window.clearInterval(id);
  }, [jobsInFlight, load]);

  const techOptions = useMemo(
    () =>
      [...new Set(results.map((r) => r.technique).filter(Boolean))].sort() as string[],
    [results]
  );

  const columns: Column<HostHeaderResultRow>[] = [
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
      defaultWidth: 160,
    },
    {
      key: "param_name",
      header: "Header",
      className: "mono text-xs",
      defaultWidth: 160,
    },
    {
      key: "technique",
      header: "Technique",
      className: "mono text-xs",
      defaultWidth: 140,
    },
    {
      key: "risk_hint",
      header: "Sink",
      className: "mono text-xs",
      render: (r) => r.risk_hint || "—",
      defaultWidth: 90,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (r) => <StatusBadge value={r.verdict} />,
      defaultWidth: 130,
    },
    {
      key: "evidence",
      header: "Evidence",
      className: "text-xs",
      sortable: false,
      render: (r) => (
        <span className="break-all" title={r.evidence || r.reflected_url || ""}>
          {(r.evidence || r.reflected_url || r.risk_hint || "—").slice(0, 48)}
        </span>
      ),
      defaultWidth: 180,
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
          <span className="label-text text-xs">Family</span>
          <select
            className={selectClass}
            value={family}
            onChange={(e) => setFamily(e.target.value)}
          >
            <option value="">any</option>
            {FAMILIES.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Technique</span>
          <select
            className={selectClass}
            value={technique}
            onChange={(e) => setTechnique(e.target.value)}
          >
            <option value="">any</option>
            {techOptions.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Host</span>
          <input
            className={inputClass}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setSearch(searchInput.trim());
            }}
            placeholder="filter host"
          />
        </label>
        <button
          className="btn btn-xs"
          onClick={() => setSearch(searchInput.trim())}
        >
          Filter
        </button>
      </div>

      <Section title={loading ? "Results (loading…)" : `Results (${results.length})`}>
        <DataTable
          rows={results}
          columns={columns}
          rowKey={(r) => r.replay_flow_id}
          onRowClick={(r) => navigate(`/flows/${r.replay_flow_id}`)}
          emptyLabel="No host-header probe results yet. Pick a flow and enqueue a scan."
        />
      </Section>
    </div>
  );
}
