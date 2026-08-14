import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import {
  inputClass,
  selectClass,
  type AuthSessionBinding,
  type AuthSessionTarget,
} from "./shared";

type TargetsResponse = {
  items: AuthSessionTarget[];
  count: number;
};

export default function CandidatesTab({
  projectId,
  onChanged,
}: {
  projectId: string;
  onChanged?: () => void;
}) {
  const [items, setItems] = useState<AuthSessionTarget[]>([]);
  const [bindings, setBindings] = useState<AuthSessionBinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [bindingId, setBindingId] = useState("");
  const [flowId, setFlowId] = useState("");

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
    const params: Record<string, string | undefined> = {
      project_id: projectId,
    };
    if (bindingId) params.binding_id = bindingId;
    api
      .get<TargetsResponse>("/api/attack/auth-session/targets", params)
      .then((r) => setItems(r.items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [projectId, bindingId]);

  useEffect(() => {
    loadBindings();
  }, [loadBindings]);

  useEffect(() => {
    load();
  }, [load]);

  const refresh = () => {
    load();
    loadBindings();
    onChanged?.();
  };

  const addFlow = useAction("Add JWT target flow", () =>
    api.post(
      "/api/attack/auth-session/targets/add",
      {
        flow_id: flowId.trim(),
        binding_id: bindingId || undefined,
      },
      { project_id: projectId }
    )
  );

  const removeFlow = useAction(
    "Remove JWT target flow",
    (target: AuthSessionTarget) =>
      api.post(
        "/api/attack/auth-session/targets/remove",
        {
          flow_id: target.flow_id,
          binding_id: target.binding_id,
        },
        { project_id: projectId }
      )
  );

  const columns: Column<AuthSessionTarget>[] = [
    {
      key: "method",
      header: "Method",
      className: "mono text-xs font-medium",
      defaultWidth: 70,
      render: (r) => r.method || "—",
    },
    {
      key: "path",
      header: "Path",
      className: "mono text-xs",
      defaultWidth: 220,
      render: (r) =>
        r.endpoint_id ? (
          <Link
            className="link link-hover"
            to={`/endpoints/${r.endpoint_id}`}
          >
            {r.path || r.url || r.endpoint_id.slice(0, 8)}
          </Link>
        ) : (
          r.path || r.url || "—"
        ),
    },
    {
      key: "test_count",
      header: "JWT tests",
      className: "text-xs tabular-nums",
      defaultWidth: 80,
    },
    {
      key: "runnable_count",
      header: "Ready",
      className: "text-xs tabular-nums",
      defaultWidth: 70,
    },
    {
      key: "flow_id",
      header: "Flow",
      className: "mono text-[11px]",
      defaultWidth: 140,
      render: (r) => (
        <Link className="link link-hover" to={`/flows/${r.flow_id}`}>
          {r.flow_id.slice(0, 8)}…
        </Link>
      ),
    },
    {
      key: "running_count",
      header: "",
      sortable: false,
      defaultWidth: 90,
      render: (r) =>
        r.running_count > 0 ? (
          <span className="text-[11px] text-base-content/50">running</span>
        ) : (
          <ConfirmButton
            className="btn btn-xs btn-ghost text-error"
            confirmText={`Remove ${r.method || "this"} ${r.path || "flow"} from JWT testing?`}
            onConfirm={async () => {
              try {
                await removeFlow.run(r);
                refresh();
              } catch {
                /* logged */
              }
            }}
          >
            Remove
          </ConfirmButton>
        ),
    },
  ];

  return (
    <div>
      <Section title="Add a target flow">
        <p className="text-xs text-base-content/60 mb-3">
          Binding already picks up to five method-diverse flows (one GET, one
          POST, one PATCH or PUT). Add another captured flow if you want more
          coverage.
        </p>
        <div className="flex flex-wrap items-end gap-2">
          {bindings.length > 1 && (
            <label className="form-control">
              <span className="label-text text-xs">Binding</span>
              <select
                className={selectClass}
                value={bindingId}
                onChange={(e) => setBindingId(e.target.value)}
              >
                <option value="">All / default</option>
                {bindings.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.location}:{b.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="form-control min-w-[16rem] flex-1">
            <span className="label-text text-xs">Flow UUID</span>
            <input
              className={`${inputClass} mono w-full`}
              value={flowId}
              onChange={(e) => setFlowId(e.target.value)}
              placeholder="captured flow to test"
            />
          </label>
          <button
            type="button"
            className="btn btn-xs btn-primary"
            disabled={!flowId.trim() || addFlow.running}
            onClick={async () => {
              try {
                await addFlow.run();
                setFlowId("");
                refresh();
              } catch {
                /* logged */
              }
            }}
          >
            {addFlow.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Add flow"
            )}
          </button>
        </div>
      </Section>

      <Section
        title="Target flows"
        action={
          <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
            Refresh
          </button>
        }
      >
        {loading && items.length === 0 ? (
          <div className="text-sm text-base-content/50">Loading…</div>
        ) : (
          <DataTable
            columns={columns}
            rows={items}
            rowKey={(r) => `${r.binding_id}:${r.flow_id}`}
            emptyLabel="No target flows yet. Bind a JWT field or add a flow UUID above."
          />
        )}
        <p className="text-[11px] text-base-content/45 mt-2">
          Each flow is replayed with the JWT suite (alg, signature, claims,
          structure). Run uses the latest captured JWT unless you paste a
          custom token on the Run tab.
        </p>
      </Section>
    </div>
  );
}
