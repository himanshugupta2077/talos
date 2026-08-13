import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  VERDICTS,
  inputClass,
  selectClass,
  type CorsResultRow,
} from "./shared";

export default function ResultsTab({
  projectId,
  jobsInFlight,
}: {
  projectId: string;
  jobsInFlight?: boolean;
}) {
  const navigate = useNavigate();
  const [results, setResults] = useState<CorsResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [technique, setTechnique] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ results: CorsResultRow[] }>("/api/attack/cors/results", {
        project_id: projectId,
        verdict: verdict || undefined,
        technique: technique || undefined,
        host: search || undefined,
        limit: 300,
      })
      .then((r) => setResults(r.results || []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false));
  }, [projectId, verdict, technique, search]);

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

  const columns: Column<CorsResultRow>[] = [
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
      defaultWidth: 180,
    },
    {
      key: "technique",
      header: "Technique",
      className: "mono text-xs",
      defaultWidth: 150,
    },
    {
      key: "origin_sent",
      header: "Origin sent",
      className: "mono text-xs",
      render: (r) => (
        <span className="break-all" title={r.origin_sent}>
          {(r.origin_sent || "").slice(0, 40)}
        </span>
      ),
      defaultWidth: 180,
    },
    {
      key: "acao",
      header: "ACAO",
      className: "mono text-xs",
      render: (r) => r.acao || "—",
      defaultWidth: 140,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (r) => <StatusBadge value={r.verdict} />,
      defaultWidth: 130,
    },
    {
      key: "reflected",
      header: "Flags",
      className: "text-xs",
      sortable: false,
      render: (r) => {
        const bits = [];
        if (r.reflected) bits.push("reflected");
        if (r.credentials) bits.push("creds");
        if (r.wildcard) bits.push("*");
        return bits.join(" · ") || "—";
      },
      defaultWidth: 110,
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
          emptyLabel="No CORS probe results yet. Enqueue a run and wait for the scheduler."
        />
      </Section>
    </div>
  );
}
