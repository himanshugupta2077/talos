import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import StatusBadge from "../../../components/StatusBadge";
import { formatIST } from "../../../lib/time";
import {
  CANDIDATE_STATUSES,
  KNOWN_FAMILIES,
  inputClass,
  selectClass,
  type AuthSessionBinding,
  type AuthSessionCandidate,
} from "./shared";
import GenerateScopeForm from "./components/GenerateScopeForm";
import CandidateDetailDrawer from "./components/CandidateDetailDrawer";

type CandidatesResponse = {
  items: AuthSessionCandidate[];
  count: number;
};

export default function CandidatesTab({
  projectId,
  onChanged,
}: {
  projectId: string;
  onChanged?: () => void;
}) {
  const [items, setItems] = useState<AuthSessionCandidate[]>([]);
  const [bindings, setBindings] = useState<AuthSessionBinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [bindingId, setBindingId] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [family, setFamily] = useState("");
  const [testId, setTestId] = useState("");
  const [limit, setLimit] = useState(200);
  const [selected, setSelected] = useState<AuthSessionCandidate | null>(null);

  const loadBindings = useCallback(() => {
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
    if (status) params.status = status;
    if (bindingId) params.binding_id = bindingId;
    if (endpointId.trim()) params.endpoint_id = endpointId.trim();
    if (family) params.family = family;
    if (testId.trim()) params.test_id = testId.trim();

    api
      .get<CandidatesResponse>("/api/attack/auth-session/candidates", params)
      .then((r) => setItems(r.items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [projectId, status, bindingId, endpointId, family, testId, limit]);

  useEffect(() => {
    loadBindings();
  }, [loadBindings]);

  useEffect(() => {
    load();
  }, [load]);

  const onGenerated = () => {
    load();
    loadBindings();
    onChanged?.();
  };

  const columns: Column<AuthSessionCandidate>[] = [
    {
      key: "status",
      header: "Status",
      defaultWidth: 90,
      render: (r) => <StatusBadge value={r.status} />,
    },
    {
      key: "test_id",
      header: "test_id",
      className: "mono text-xs",
      defaultWidth: 140,
    },
    {
      key: "test_family",
      header: "Family",
      className: "mono text-xs",
      defaultWidth: 100,
    },
    {
      key: "title",
      header: "Title",
      className: "text-xs",
      defaultWidth: 160,
      render: (r) => r.title || "—",
    },
    {
      key: "endpoint_path",
      header: "Endpoint",
      className: "mono text-xs",
      defaultWidth: 160,
      render: (r) =>
        r.endpoint_id ? (
          <Link
            className="link link-hover"
            to={`/endpoints/${r.endpoint_id}`}
            onClick={(e) => e.stopPropagation()}
          >
            {r.endpoint_method || ""} {r.endpoint_path || r.endpoint_id.slice(0, 8)}
          </Link>
        ) : (
          "—"
        ),
    },
    {
      key: "risk_hint",
      header: "Risk",
      className: "text-xs",
      defaultWidth: 70,
      render: (r) => r.risk_hint || "—",
    },
    {
      key: "token_fingerprint",
      header: "Fingerprint",
      className: "mono text-[11px]",
      defaultWidth: 140,
      render: (r) => r.token_fingerprint || "—",
    },
    {
      key: "updated_at",
      header: "Updated",
      className: "text-xs whitespace-nowrap",
      defaultWidth: 120,
      render: (r) => formatIST(r.updated_at),
    },
  ];

  return (
    <div>
      <GenerateScopeForm
        projectId={projectId}
        bindings={bindings}
        onDone={onGenerated}
      />

      <Section
        title="Candidate inventory"
        action={
          <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
            Refresh
          </button>
        }
      >
        <div className="alert text-xs py-2 mb-3 bg-base-200 border border-base-300">
          <span>
            <strong>Approve lifecycle (Phase 3).</strong> Bulk approve / reject /
            unapprove is not enabled in the UI yet. Use CLI:{" "}
            <span className="mono">
              talos attack auth-session approve --all-pending
            </span>
            . Selecting rows here is for review only.
          </span>
        </div>

        <div className="flex flex-wrap items-end gap-2 mb-3">
          <label className="form-control">
            <span className="label-text text-xs">Status</span>
            <select
              className={selectClass}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All</option>
              {CANDIDATE_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
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
        </div>

        {loading && items.length === 0 ? (
          <div className="text-sm text-base-content/50">Loading…</div>
        ) : (
          <DataTable
            columns={columns}
            rows={items}
            rowKey={(r) => r.id}
            emptyLabel="No candidates match filters. Generate above or widen filters."
            onRowClick={(r) => setSelected(r)}
          />
        )}
        <p className="text-[11px] text-base-content/45 mt-2">
          Showing up to {limit} rows (no offset pagination in v1). Full token
          values are never stored — fingerprint only.
        </p>
      </Section>

      <CandidateDetailDrawer
        candidate={selected}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
