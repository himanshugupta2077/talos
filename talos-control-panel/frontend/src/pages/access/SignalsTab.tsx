/**
 * Structured BAC/IDOR signals from access map + observed traffic.
 */

import { type ReactNode, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { AccessSignals } from "../../types";
import type { MatrixFilter } from "./shared";
import { valueBadgeClass } from "./shared";

export default function SignalsTab({
  projectId,
  onJumpMatrix,
}: {
  projectId: string;
  onJumpMatrix?: (filter: MatrixFilter) => void;
}) {
  const [data, setData] = useState<AccessSignals | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    api
      .get<AccessSignals>("/api/access/signals", { project_id: projectId })
      .then(setData)
      .catch((e) => setError(e?.message || "Failed to load signals"))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, [projectId]);

  if (loading && !data) {
    return (
      <div className="py-12 text-center">
        <span className="loading loading-spinner" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel p-4 text-sm text-error">
        {error}{" "}
        <button type="button" className="btn btn-xs ml-2" onClick={load}>
          Retry
        </button>
      </div>
    );
  }

  const d = data || {
    multi_role: [],
    server_deny_endpoints: [],
    deny_with_flows: [],
    allow_without_flows: [],
  };

  const total =
    d.multi_role.length +
    d.server_deny_endpoints.length +
    d.deny_with_flows.length +
    d.allow_without_flows.length;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-base-content/50 flex-1">
          Immediate BAC/IDOR signals without replay (same data as{" "}
          <span className="mono">talos access signals</span>). Not findings —
          investigation starting points.
        </p>
        <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
          Refresh
        </button>
        <Link to="/testing/bac" className="btn btn-xs btn-outline">
          Open BAC
        </Link>
        <Link to="/endpoints" className="btn btn-xs btn-ghost">
          Endpoints
        </Link>
      </div>

      <div className="flex flex-wrap gap-2 text-xs">
        <span className="badge badge-outline">{total} signal rows</span>
        <span className="badge badge-ghost">{d.multi_role.length} multi-role</span>
        <span className="badge badge-ghost">
          {d.server_deny_endpoints.length} boundary
        </span>
        <span className="badge badge-ghost">
          {d.deny_with_flows.length} client DENY+flows
        </span>
        <span className="badge badge-ghost">
          {d.allow_without_flows.length} ALLOW gaps
        </span>
      </div>

      <SignalSection
        title="Cross-role endpoint exposure"
        subtitle="IDOR / privilege confusion — endpoints seen under more than one role"
        count={d.multi_role.length}
      >
        {d.multi_role.length === 0 ? (
          <Empty />
        ) : (
          <ul className="divide-y divide-base-300">
            {d.multi_role.map((row) => (
              <li
                key={row.endpoint_id}
                className="py-2 px-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm"
              >
                <Link
                  className="link link-hover mono text-xs"
                  to={`/endpoints/${row.endpoint_id}`}
                >
                  {row.method} {row.host}
                  {row.normalized_path}
                </Link>
                <span className="badge badge-sm badge-outline">
                  {row.role_count} roles
                </span>
                <span className="text-xs text-base-content/50">
                  {row.role_names}
                </span>
              </li>
            ))}
          </ul>
        )}
      </SignalSection>

      <SignalSection
        title="Module boundary violation"
        subtitle="server_expected=DENY but an endpoint was still reached under that pair"
        count={d.server_deny_endpoints.length}
        action={
          onJumpMatrix ? (
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              onClick={() => onJumpMatrix("server_deny")}
            >
              Filter matrix
            </button>
          ) : undefined
        }
      >
        {d.server_deny_endpoints.length === 0 ? (
          <Empty />
        ) : (
          <ul className="divide-y divide-base-300">
            {d.server_deny_endpoints.map((row, i) => (
              <li
                key={`${row.endpoint_id}-${row.role_name}-${row.module_name}-${i}`}
                className="py-2 px-1 text-sm space-y-0.5"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium">
                    {row.role_name} → {row.module_name}
                  </span>
                  <span className={`badge badge-xs ${valueBadgeClass(row.client_allowed)}`}>
                    C {row.client_allowed || "—"}
                  </span>
                  <span className={`badge badge-xs ${valueBadgeClass(row.server_expected)}`}>
                    S {row.server_expected}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2 items-baseline">
                  <Link
                    className="link link-hover mono text-xs"
                    to={`/endpoints/${row.endpoint_id}`}
                  >
                    {row.method} {row.host}
                    {row.normalized_path}
                  </Link>
                  <span className="text-[11px] text-base-content/45">
                    {row.flow_count} flow{row.flow_count === 1 ? "" : "s"}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </SignalSection>

      <SignalSection
        title="client=DENY with observed flows"
        subtitle="Potential client-side bypass or mis-tagged capture"
        count={d.deny_with_flows.length}
        action={
          onJumpMatrix ? (
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              onClick={() => onJumpMatrix("client_deny")}
            >
              Filter matrix
            </button>
          ) : undefined
        }
      >
        {d.deny_with_flows.length === 0 ? (
          <Empty />
        ) : (
          <ul className="divide-y divide-base-300">
            {d.deny_with_flows.map((row) => (
              <li
                key={`${row.role_name}::${row.module_name}`}
                className="py-2 px-1 flex flex-wrap items-center gap-2 text-sm"
              >
                <span className="font-medium">
                  {row.role_name} → {row.module_name}
                </span>
                <span className={`badge badge-xs ${valueBadgeClass(row.client_allowed)}`}>
                  C {row.client_allowed}
                </span>
                <span className="text-xs text-base-content/50 tabular-nums">
                  {row.flow_count ?? 0} flows
                </span>
              </li>
            ))}
          </ul>
        )}
      </SignalSection>

      <SignalSection
        title="client=ALLOW with no observed flows"
        subtitle="Coverage gap — matrix claims access but no traffic tagged for the pair"
        count={d.allow_without_flows.length}
        action={
          onJumpMatrix ? (
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              onClick={() => onJumpMatrix("unset")}
            >
              Open matrix
            </button>
          ) : undefined
        }
      >
        {d.allow_without_flows.length === 0 ? (
          <Empty />
        ) : (
          <ul className="divide-y divide-base-300">
            {d.allow_without_flows.map((row) => (
              <li
                key={`${row.role_name}::${row.module_name}`}
                className="py-2 px-1 flex flex-wrap items-center gap-2 text-sm"
              >
                <span className="font-medium">
                  {row.role_name} → {row.module_name}
                </span>
                <span className={`badge badge-xs ${valueBadgeClass(row.client_allowed)}`}>
                  C {row.client_allowed}
                </span>
              </li>
            ))}
          </ul>
        )}
      </SignalSection>
    </div>
  );
}

function SignalSection({
  title,
  subtitle,
  count,
  children,
  action,
}: {
  title: string;
  subtitle: string;
  count: number;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="flex flex-wrap items-start justify-between gap-2 px-3 py-2 border-b border-base-300">
        <div>
          <h3 className="font-semibold text-sm flex items-center gap-2">
            {title}
            <span className="badge badge-sm badge-ghost">{count}</span>
          </h3>
          <p className="text-[11px] text-base-content/45 mt-0.5">{subtitle}</p>
        </div>
        {action}
      </div>
      <div className="px-3 py-1">{children}</div>
    </section>
  );
}

function Empty() {
  return (
    <div className="py-3 text-xs text-base-content/40 text-center">(none)</div>
  );
}
