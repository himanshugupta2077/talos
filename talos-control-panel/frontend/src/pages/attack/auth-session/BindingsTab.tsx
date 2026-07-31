import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section, UuidChip } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import { formatIST } from "../../../lib/time";
import type { AuthSessionBinding } from "./shared";
import BindingForm from "./components/BindingForm";

type BindingsResponse = {
  items: AuthSessionBinding[];
  count: number;
  auth_config_ready: boolean;
  auth_artifacts: { type: string; name: string }[];
};

export default function BindingsTab({
  projectId,
  onChanged,
}: {
  projectId: string;
  onChanged?: () => void;
}) {
  const [items, setItems] = useState<AuthSessionBinding[]>([]);
  const [artifacts, setArtifacts] = useState<{ type: string; name: string }[]>(
    []
  );
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<BindingsResponse>("/api/attack/auth-session/bindings", {
        project_id: projectId,
      })
      .then((r) => {
        setItems(r.items || []);
        setArtifacts(r.auth_artifacts || []);
      })
      .catch(() => {
        setItems([]);
        setArtifacts([]);
      })
      .finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  const refresh = () => {
    load();
    onChanged?.();
  };

  const unbind = useAction(
    "Unbind auth-session field",
    (bindingId: string, force: boolean) =>
      api.post(
        "/api/attack/auth-session/unbind",
        { binding_id: bindingId, force },
        { project_id: projectId }
      )
  );

  const columns: Column<AuthSessionBinding>[] = [
    {
      key: "location",
      header: "Location",
      className: "mono text-xs",
      defaultWidth: 80,
    },
    {
      key: "name",
      header: "Name",
      className: "mono text-xs font-medium",
      defaultWidth: 140,
    },
    {
      key: "auth_type",
      header: "Type",
      className: "mono text-xs",
      defaultWidth: 60,
    },
    {
      key: "in_auth_config",
      header: "In auth_config",
      defaultWidth: 100,
      render: (r) =>
        r.in_auth_config ? (
          <span className="text-success text-xs">yes</span>
        ) : (
          <span className="text-warning text-xs">missing</span>
        ),
    },
    {
      key: "candidate_counts",
      header: "Candidates",
      defaultWidth: 120,
      render: (r) => {
        const c = r.candidate_counts || {};
        const total = c.total ?? 0;
        if (!total) return <span className="text-xs text-base-content/40">0</span>;
        return (
          <span className="text-xs">
            {total}
            {c.pending ? ` · ${c.pending}p` : ""}
            {c.approved ? ` · ${c.approved}a` : ""}
          </span>
        );
      },
    },
    {
      key: "role_id",
      header: "Role",
      className: "mono text-xs",
      defaultWidth: 90,
      render: (r) =>
        r.role_id ? <UuidChip value={r.role_id} /> : <span className="opacity-40">—</span>,
    },
    {
      key: "created_at",
      header: "Created",
      className: "text-xs whitespace-nowrap",
      defaultWidth: 120,
      render: (r) => formatIST(r.created_at),
    },
    {
      key: "id",
      header: "Actions",
      defaultWidth: 160,
      render: (r) => {
        const counts = r.candidate_counts || {};
        const soft =
          (counts.pending || 0) + (counts.rejected || 0) > 0 &&
          !(counts.approved || counts.running || counts.done || counts.failed);
        const protectedCount =
          (counts.approved || 0) +
          (counts.running || 0) +
          (counts.done || 0) +
          (counts.failed || 0);

        if (protectedCount > 0) {
          return (
            <span
              className="text-[11px] text-base-content/50"
              title="CLI refuses unbind when approved/running/done/failed or results exist"
            >
              protected
            </span>
          );
        }

        if (soft) {
          return (
            <ConfirmButton
              className="btn btn-xs btn-error btn-outline"
              confirmText="Force-unbind and cascade-delete pending/rejected?"
              onConfirm={async () => {
                try {
                  await unbind.run(r.id, true);
                  refresh();
                } catch {
                  /* logged */
                }
              }}
            >
              Unbind --force
            </ConfirmButton>
          );
        }

        return (
          <button
            type="button"
            className="btn btn-xs btn-ghost text-error"
            disabled={unbind.running}
            onClick={async () => {
              try {
                await unbind.run(r.id, false);
                refresh();
              } catch {
                /* logged */
              }
            }}
          >
            Unbind
          </button>
        );
      },
    },
  ];

  return (
    <div>
      <BindingForm
        projectId={projectId}
        artifacts={artifacts}
        onDone={refresh}
      />

      <Section
        title="Current bindings"
        action={
          <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
            Refresh
          </button>
        }
      >
        <p className="text-xs text-base-content/60 mb-2">
          Each binding maps one auth_config field to the JWT mutator. Prerequisite:{" "}
          <Link className="link link-primary" to="/auth">
            Auth page
          </Link>
          .
        </p>
        {loading && items.length === 0 ? (
          <div className="text-sm text-base-content/50">Loading…</div>
        ) : (
          <DataTable
            columns={columns}
            rows={items}
            rowKey={(r) => r.id}
            emptyLabel="No bindings yet — use the form above."
          />
        )}
      </Section>
    </div>
  );
}
