import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  DEFAULT_TECHNIQUES,
  VERDICTS,
  inputClass,
  selectClass,
  techniqueLabel,
  type BacResultRow,
  type BacTechnique,
} from "./shared";

export default function ResultsTab({
  projectId,
  techniques,
  jobsInFlight,
}: {
  projectId: string;
  techniques: BacTechnique[];
  jobsInFlight?: boolean;
}) {
  const navigate = useNavigate();
  const [results, setResults] = useState<BacResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [attackType, setAttackType] = useState("");
  const [moduleName, setModuleName] = useState("");
  const [attackerRole, setAttackerRole] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ results: BacResultRow[] }>("/api/attack/bac/results", {
        project_id: projectId,
        verdict: verdict || undefined,
        attack_type: attackType || undefined,
        module_name: moduleName || undefined,
        attacker_role: attackerRole || undefined,
        search: search || undefined,
        limit: 300,
      })
      .then((r) => setResults(r.results || []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false));
  }, [projectId, verdict, attackType, moduleName, attackerRole, search]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!jobsInFlight) return;
    const id = window.setInterval(load, 8000);
    return () => window.clearInterval(id);
  }, [jobsInFlight, load]);

  const moduleOptions = useMemo(
    () =>
      [
        ...new Set(
          results.map((r) => r.module_name).filter((v): v is string => Boolean(v))
        ),
      ].sort(),
    [results]
  );
  const roleOptions = useMemo(
    () =>
      [
        ...new Set(
          results
            .map((r) => r.attacker_role_name)
            .filter((v): v is string => Boolean(v))
        ),
      ].sort(),
    [results]
  );

  const techOptions =
    techniques.length > 0
      ? techniques.map((t) => t.name)
      : [...DEFAULT_TECHNIQUES];

  const columns: Column<BacResultRow>[] = [
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
      key: "attacker_role_name",
      header: "Attacker",
      className: "text-xs",
      render: (r) => r.attacker_role_name || "—",
      defaultWidth: 100,
    },
    {
      key: "target_role_name",
      header: "Target",
      className: "text-xs",
      render: (r) => r.target_role_name || "—",
      defaultWidth: 100,
    },
    {
      key: "module_name",
      header: "Module",
      className: "text-xs",
      render: (r) => r.module_name || "—",
      defaultWidth: 100,
    },
    {
      key: "attack_type",
      header: "Technique",
      className: "mono text-xs",
      render: (r) => techniqueLabel(r.attack_type),
      defaultWidth: 110,
    },
    {
      key: "variant",
      header: "Variant",
      className: "text-xs",
      render: (r) => r.variant || r.mutation || "—",
      defaultWidth: 120,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (r) => <StatusBadge value={r.verdict} />,
      defaultWidth: 110,
    },
    {
      key: "matched_section",
      header: "Evidence",
      className: "text-xs text-base-content/60",
      sortable: false,
      render: (r) => {
        if (!r.matched_section && !r.matched_group) return "—";
        const parts = [r.matched_section, r.matched_group].filter(Boolean);
        return (
          <span title={r.matched_rules || undefined}>{parts.join(" · ")}</span>
        );
      },
      defaultWidth: 130,
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
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
          >
            <option value="">any</option>
            {techOptions.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Module</span>
          <select
            className={selectClass}
            value={moduleName}
            onChange={(e) => setModuleName(e.target.value)}
          >
            <option value="">any</option>
            {moduleOptions.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Attacker role</span>
          <select
            className={selectClass}
            value={attackerRole}
            onChange={(e) => setAttackerRole(e.target.value)}
          >
            <option value="">any</option>
            {roleOptions.map((v) => (
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
          storageKey="bac-results"
          loading={loading}
          emptyLabel="No BAC results yet."
          onRowClick={(r) => navigate(`/flows/${r.replay_flow_id}`)}
        />
      </Section>
    </div>
  );
}
