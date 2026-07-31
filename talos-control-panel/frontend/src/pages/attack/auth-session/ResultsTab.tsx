import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../../api/client";
import { Modal, Section, UuidChip } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  KNOWN_FAMILIES,
  VERDICTS,
  inputClass,
  selectClass,
  type AuthSessionBinding,
  type AuthSessionResultRow,
} from "./shared";

type ResultsResponse = {
  items: AuthSessionResultRow[];
  count: number;
};

type ResultDetail = {
  item: AuthSessionResultRow & Record<string, unknown>;
  finding: {
    finding_id: string;
    title?: string;
    status?: string;
    verdict?: string;
  } | null;
};

export default function ResultsTab({
  projectId,
  jobsInFlight,
}: {
  projectId: string;
  jobsInFlight?: boolean;
}) {
  const [items, setItems] = useState<AuthSessionResultRow[]>([]);
  const [bindings, setBindings] = useState<AuthSessionBinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [bindingId, setBindingId] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [family, setFamily] = useState("");
  const [testId, setTestId] = useState("");
  const [limit, setLimit] = useState(200);
  const [detail, setDetail] = useState<ResultDetail | null>(null);

  useEffect(() => {
    api
      .get<{ items: AuthSessionBinding[] }>("/api/attack/auth-session/bindings", {
        project_id: projectId,
      })
      .then((r) => setBindings(r.items || []))
      .catch(() => setBindings([]));
  }, [projectId]);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string | number | undefined> = {
      project_id: projectId,
      limit,
    };
    if (verdict) params.verdict = verdict;
    if (bindingId) params.binding_id = bindingId;
    if (endpointId.trim()) params.endpoint_id = endpointId.trim();
    if (family) params.family = family;
    if (testId.trim()) params.test_id = testId.trim();

    api
      .get<ResultsResponse>("/api/attack/auth-session/results", params)
      .then((r) => setItems(r.items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [projectId, verdict, bindingId, endpointId, family, testId, limit]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!jobsInFlight) return;
    const id = window.setInterval(load, 8000);
    return () => window.clearInterval(id);
  }, [jobsInFlight, load]);

  const openDetail = (row: AuthSessionResultRow) => {
    api
      .get<ResultDetail>(
        `/api/attack/auth-session/results/${row.replay_flow_id}`,
        { project_id: projectId }
      )
      .then(setDetail)
      .catch(() =>
        setDetail({
          item: row as AuthSessionResultRow & Record<string, unknown>,
          finding: null,
        })
      );
  };

  const tallies = items.reduce(
    (acc, r) => {
      const v = r.verdict || "UNKNOWN";
      acc[v] = (acc[v] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const columns: Column<AuthSessionResultRow>[] = [
    {
      key: "created_at",
      header: "Time",
      className: "text-xs whitespace-nowrap",
      sortValue: (r) => r.captured_at || r.created_at || "",
      render: (r) => formatIST(r.captured_at || r.created_at),
      defaultWidth: 130,
    },
    {
      key: "method",
      header: "Method",
      className: "mono",
      defaultWidth: 70,
      render: (r) => r.method || "—",
    },
    {
      key: "path",
      header: "Path",
      className: "mono text-xs",
      defaultWidth: 180,
      render: (r) => (
        <span title={r.host ? `${r.host}${r.path || ""}` : r.path}>
          {r.path || "—"}
        </span>
      ),
    },
    {
      key: "test_id",
      header: "test_id",
      className: "mono text-xs",
      defaultWidth: 130,
    },
    {
      key: "test_family",
      header: "Family",
      className: "mono text-xs",
      defaultWidth: 100,
    },
    {
      key: "verdict",
      header: "Verdict",
      defaultWidth: 120,
      render: (r) => <StatusBadge value={r.verdict} />,
    },
    {
      key: "statuses",
      header: "orig→replay",
      className: "text-xs mono",
      sortable: false,
      defaultWidth: 90,
      render: (r) =>
        `${r.original_status ?? "—"}→${r.replay_status ?? r.status_code ?? "—"}`,
    },
    {
      key: "matched_section",
      header: "Match",
      className: "text-xs text-base-content/60",
      sortable: false,
      defaultWidth: 120,
      render: (r) => {
        if (!r.matched_section && !r.matched_group) return "—";
        const parts = [r.matched_section, r.matched_group].filter(Boolean);
        return (
          <span title={r.matched_rules || undefined}>{parts.join(" · ")}</span>
        );
      },
    },
    {
      key: "failure_reason",
      header: "Failure",
      className: "text-xs",
      defaultWidth: 120,
      render: (r) => r.failure_reason || "—",
    },
  ];

  return (
    <div>
      <div className="alert text-xs py-2 mb-3 bg-base-200 border border-base-300">
        <span>
          <strong>WEAK_VALIDATION</strong> means the target accepted a mutated
          token (weak validation evidence)—not a freeform exploit.{" "}
          <Link
            className="link"
            to="/findings?attack_type=auth_session&verdict=WEAK_VALIDATION"
          >
            Open WEAK_VALIDATION findings
          </Link>
        </span>
      </div>

      <div className="flex flex-wrap gap-2 mb-3 text-xs">
        {VERDICTS.map((v) => (
          <span
            key={v}
            className={`badge badge-outline ${
              v === "WEAK_VALIDATION" && (tallies[v] || 0) > 0
                ? "badge-error"
                : ""
            }`}
          >
            {v}: {tallies[v] || 0}
          </span>
        ))}
        {jobsInFlight && (
          <span className="badge badge-warning badge-outline">jobs in flight</span>
        )}
      </div>

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
          <span className="label-text text-xs">Binding</span>
          <select
            className={selectClass}
            value={bindingId}
            onChange={(e) => setBindingId(e.target.value)}
          >
            <option value="">All</option>
            {bindings.map((b) => (
              <option key={b.id} value={b.id}>
                {b.location}:{b.name}
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
            <option value="">All</option>
            {KNOWN_FAMILIES.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control min-w-[10rem]">
          <span className="label-text text-xs">Endpoint UUID</span>
          <input
            className={`${inputClass} mono`}
            value={endpointId}
            onChange={(e) => setEndpointId(e.target.value)}
            placeholder="optional"
          />
        </label>
        <label className="form-control min-w-[8rem]">
          <span className="label-text text-xs">test_id</span>
          <input
            className={`${inputClass} mono`}
            value={testId}
            onChange={(e) => setTestId(e.target.value)}
            placeholder="optional"
          />
        </label>
        <label className="form-control w-24">
          <span className="label-text text-xs">Limit</span>
          <select
            className={selectClass}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={50}>50</option>
            <option value={200}>200</option>
            <option value={500}>500</option>
            <option value={1000}>1000</option>
          </select>
        </label>
        <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
          Refresh
        </button>
      </div>

      {loading && items.length === 0 ? (
        <div className="text-sm text-base-content/50">Loading…</div>
      ) : (
        <DataTable
          columns={columns}
          rows={items}
          rowKey={(r) => r.replay_flow_id}
          emptyLabel="No results yet. Approve candidates and run an attack."
          onRowClick={openDetail}
        />
      )}

      {detail && (
        <Modal
          open
          title={`Result · ${detail.item.test_id || detail.item.replay_flow_id}`}
          onClose={() => setDetail(null)}
          wide
        >
          <div className="space-y-2 text-sm">
            <div className="flex flex-wrap gap-2 items-center">
              <StatusBadge value={detail.item.verdict as string} />
              {detail.item.test_family && (
                <span className="badge badge-xs badge-ghost mono">
                  {String(detail.item.test_family)}
                </span>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <div className="text-base-content/50">Replay flow</div>
                <Link
                  className="link link-primary"
                  to={`/flows/${detail.item.replay_flow_id}`}
                >
                  <UuidChip value={String(detail.item.replay_flow_id)} />
                </Link>
              </div>
              <div>
                <div className="text-base-content/50">Original flow</div>
                {detail.item.original_flow_id ? (
                  <Link
                    className="link link-primary"
                    to={`/flows/${detail.item.original_flow_id}`}
                  >
                    <UuidChip value={String(detail.item.original_flow_id)} />
                  </Link>
                ) : (
                  "—"
                )}
              </div>
              <div>
                <div className="text-base-content/50">Candidate</div>
                {detail.item.candidate_id ? (
                  <UuidChip value={String(detail.item.candidate_id)} />
                ) : (
                  "—"
                )}
              </div>
              <div>
                <div className="text-base-content/50">Endpoint</div>
                {detail.item.endpoint_id ? (
                  <Link
                    className="link link-primary mono"
                    to={`/endpoints/${detail.item.endpoint_id}`}
                  >
                    {String(detail.item.method || "")}{" "}
                    {String(detail.item.path || detail.item.endpoint_id)}
                  </Link>
                ) : (
                  "—"
                )}
              </div>
              <div>
                <div className="text-base-content/50">Mutation</div>
                <span className="text-xs">
                  {String(detail.item.mutation_summary || "—")}
                </span>
              </div>
              <div>
                <div className="text-base-content/50">Failure</div>
                {String(detail.item.failure_reason || "—")}
              </div>
            </div>

            {detail.finding ? (
              <div className="alert alert-warning text-xs py-2">
                Finding:{" "}
                <Link
                  className="link link-primary font-medium"
                  to={`/findings/${detail.finding.finding_id}`}
                >
                  {detail.finding.title || detail.finding.finding_id}
                </Link>{" "}
                <StatusBadge value={detail.finding.status} />
              </div>
            ) : (
              <p className="text-xs text-base-content/50">
                No finding linked yet. WEAK_VALIDATION rows create findings after
                scheduler settle.{" "}
                <Link
                  className="link"
                  to="/findings?attack_type=auth_session"
                >
                  Open Findings
                </Link>
              </p>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
