import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
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
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [rejectReason, setRejectReason] = useState("");

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

  // Clear selection when filters change
  useEffect(() => {
    setChecked(new Set());
  }, [status, bindingId, endpointId, family, testId, limit]);

  const onGenerated = () => {
    load();
    loadBindings();
    onChanged?.();
  };

  const afterLifecycle = () => {
    setChecked(new Set());
    setSelected(null);
    load();
    onChanged?.();
  };

  const scopeBody = useMemo(
    () => ({
      endpoint_id: endpointId.trim() || undefined,
      test_ids: testId.trim() ? [testId.trim()] : undefined,
      families: family ? [family] : undefined,
      binding_id: bindingId || undefined,
    }),
    [endpointId, testId, family, bindingId]
  );

  const approve = useAction(
    "Approve auth-session candidates",
    (body: Record<string, unknown>) =>
      api.post("/api/attack/auth-session/approve", body, {
        project_id: projectId,
      })
  );
  const reject = useAction(
    "Reject auth-session candidates",
    (body: Record<string, unknown>) =>
      api.post("/api/attack/auth-session/reject", body, {
        project_id: projectId,
      })
  );
  const unapprove = useAction(
    "Unapprove auth-session candidates",
    (body: Record<string, unknown>) =>
      api.post("/api/attack/auth-session/unapprove", body, {
        project_id: projectId,
      })
  );

  const busy = approve.running || reject.running || unapprove.running;

  const runLifecycle = async (
    action: typeof approve,
    body: Record<string, unknown>
  ) => {
    try {
      await action.run(body);
      afterLifecycle();
    } catch {
      /* logged by useAction */
    }
  };

  const selectedIds = useMemo(() => Array.from(checked), [checked]);
  const allVisibleChecked =
    items.length > 0 && items.every((r) => checked.has(r.id));

  const toggleAll = () => {
    if (allVisibleChecked) {
      setChecked(new Set());
    } else {
      setChecked(new Set(items.map((r) => r.id)));
    }
  };

  const toggleOne = (id: string) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const columns: Column<AuthSessionCandidate>[] = [
    {
      key: "_sel",
      header: (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={allVisibleChecked}
          onChange={toggleAll}
          aria-label="Select all visible"
          onClick={(e) => e.stopPropagation()}
        />
      ),
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 36,
      render: (r) => (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={checked.has(r.id)}
          onChange={() => toggleOne(r.id)}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${r.test_id}`}
        />
      ),
    },
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
            <strong>Approve-first gate.</strong> Only{" "}
            <span className="mono">approved</span> candidates enqueue on Run.
            Pending never auto-fires. Select rows for subset actions, or use bulk
            scope (respects table filters). Binding-scoped bulk expands fully on
            the server (not just the visible page).
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

      {/* Sticky bulk bar */}
      <div className="sticky bottom-3 z-20 mt-4">
        <div className="panel border border-primary/30 shadow-lg px-3 py-2 flex flex-wrap items-center gap-2 bg-base-100">
          <span className="text-xs font-medium shrink-0">
            {selectedIds.length > 0
              ? `${selectedIds.length} selected`
              : "Bulk lifecycle"}
          </span>

          <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
            <button
              type="button"
              className="btn btn-xs btn-primary"
              disabled={busy || selectedIds.length === 0}
              onClick={() =>
                runLifecycle(approve, { candidate_ids: selectedIds })
              }
            >
              Approve selected
            </button>
            {!busy && (
              <ConfirmButton
                className="btn btn-xs btn-outline"
                confirmText="Approve all pending in current filter scope?"
                onConfirm={() =>
                  runLifecycle(approve, {
                    all_pending: true,
                    ...scopeBody,
                  })
                }
              >
                Approve all pending
              </ConfirmButton>
            )}
            <button
              type="button"
              className="btn btn-xs"
              disabled={busy}
              onClick={() =>
                runLifecycle(approve, {
                  retry_failed: true,
                  ...scopeBody,
                })
              }
            >
              Retry failed
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
            <input
              className={`${inputClass} w-36`}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="reject reason"
              title="Optional --reason for reject"
            />
            <button
              type="button"
              className="btn btn-xs btn-outline"
              disabled={busy || selectedIds.length === 0}
              onClick={() =>
                runLifecycle(reject, {
                  candidate_ids: selectedIds,
                  reason: rejectReason.trim() || undefined,
                })
              }
            >
              Reject selected
            </button>
            {!busy && (
              <ConfirmButton
                className="btn btn-xs btn-ghost"
                confirmText="Reject all pending in current filter scope?"
                onConfirm={() =>
                  runLifecycle(reject, {
                    all_pending: true,
                    reason: rejectReason.trim() || undefined,
                    ...scopeBody,
                  })
                }
              >
                Reject all pending
              </ConfirmButton>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
            <button
              type="button"
              className="btn btn-xs"
              disabled={busy || selectedIds.length === 0}
              onClick={() =>
                runLifecycle(unapprove, { candidate_ids: selectedIds })
              }
            >
              Unapprove selected
            </button>
            {!busy && (
              <ConfirmButton
                className="btn btn-xs btn-ghost"
                confirmText="Unapprove all approved in current filter scope?"
                onConfirm={() =>
                  runLifecycle(unapprove, {
                    all_approved: true,
                    ...scopeBody,
                  })
                }
              >
                Unapprove all approved
              </ConfirmButton>
            )}
          </div>

          {selectedIds.length > 0 && (
            <button
              type="button"
              className="btn btn-xs btn-ghost ml-auto"
              onClick={() => setChecked(new Set())}
            >
              Clear selection
            </button>
          )}
        </div>
      </div>

      <CandidateDetailDrawer
        candidate={selected}
        onClose={() => setSelected(null)}
        busy={busy}
        onApprove={(id) =>
          runLifecycle(approve, { candidate_ids: [id] }) as unknown as void
        }
        onReject={(id) =>
          runLifecycle(reject, {
            candidate_ids: [id],
            reason: rejectReason.trim() || undefined,
          }) as unknown as void
        }
      />
    </div>
  );
}
