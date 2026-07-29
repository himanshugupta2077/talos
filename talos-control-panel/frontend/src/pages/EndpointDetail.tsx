/**
 * Endpoint inspector — Overview | Policy | Parameters | Flows | Activity
 *
 * Policy tab reuses PolicyExplain (same component as workspace Policy drawer).
 * Activity is only shown when core exposes audit history (never faked).
 */

import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { Section, UuidChip } from "../components/Common";
import PolicyExplain from "../components/PolicyExplain";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import {
  BulkMutationResult,
  EndpointPolicyExplanation,
  Parameter,
} from "../types";
import { DecisionBadge, formatRelativeAge, PRIORITIES } from "./endpoints/shared";
import { IV_BASE } from "./attack/registry";
import RelatedErrorsStrip from "./error-intelligence/components/RelatedErrorsStrip";
import type { EndpointRollupRow } from "./error-intelligence/shared";

interface EndpointDetailResponse {
  endpoint: any;
  policy: any;
  policy_explanation: EndpointPolicyExplanation | null;
  annotations: { tag: string; created_at: string }[];
  tags: string[];
  parameters: Parameter[];
  roles: { id: string; name: string; first_seen: string; last_seen: string }[];
  modules: { id: string; name: string }[];
  flows: any[];
  activity_available: boolean;
}

type DetailTab = "overview" | "policy" | "parameters" | "flows" | "activity";

export default function EndpointDetail() {
  const { endpointId } = useParams();
  const { selected } = useProject();
  const [data, setData] = useState<EndpointDetailResponse | null>(null);
  const [adjacent, setAdjacent] = useState<{ prev_id: string | null; next_id: string | null }>({
    prev_id: null,
    next_id: null,
  });
  const [tab, setTab] = useState<DetailTab>("overview");
  const [tagInput, setTagInput] = useState("");
  const [errorRollup, setErrorRollup] = useState<EndpointRollupRow[] | null>([]);
  const [errorRollupLoading, setErrorRollupLoading] = useState(false);
  const navigate = useNavigate();

  const load = () => {
    if (!selected || !endpointId) return;
    api
      .get<EndpointDetailResponse>(`/api/endpoints/${endpointId}`, {
        project_id: selected.id,
      })
      .then(setData);
    api
      .get(`/api/endpoints/${endpointId}/adjacent`, { project_id: selected.id })
      .then(setAdjacent as any);
    setErrorRollupLoading(true);
    api
      .get<{ rollup: EndpointRollupRow[] }>(
        "/api/error-intel/rollups/endpoint",
        {
          project_id: selected.id,
          endpoint_id: endpointId,
          limit: 8,
        },
      )
      .then((r) => setErrorRollup(r.rollup || []))
      .catch(() => setErrorRollup(null))
      .finally(() => setErrorRollupLoading(false));
  };

  useEffect(load, [selected, endpointId]);

  const act = useAction("Endpoint action", (path: string, body?: object) =>
    api.post<BulkMutationResult>(path, body ?? {}, { project_id: selected!.id })
  );

  if (!data) return <div className="loading loading-spinner" />;
  const {
    endpoint,
    policy,
    policy_explanation,
    annotations,
    tags: policyTags,
    parameters,
    roles,
    modules,
    flows,
    activity_available,
  } = data;

  const tags = policyTags?.length
    ? policyTags
    : annotations.map((a) => a.tag);
  const explanation = policy_explanation;
  const decision =
    explanation?.decision ||
    (policy?.qualified && !policy?.excluded ? "TESTABLE" : "SKIPPED");
  const prioSource = explanation?.priority?.source || explanation?.source || "auto";
  const effective =
    explanation?.priority?.effective ||
    explanation?.effective_level ||
    policy?.manual_priority ||
    policy?.auto_priority;
  const origin = endpoint.origin || endpoint.host;
  const hostDisplay = endpoint.host_display || endpoint.host;

  const safetyLabel = policy?.logout
    ? "LOGOUT"
    : policy?.dangerous
      ? "DANGEROUS"
      : "SAFE";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <button
            className="btn btn-xs"
            disabled={!adjacent.prev_id}
            onClick={() => navigate(`/endpoints/${adjacent.prev_id}`)}
          >
            ← prev
          </button>
          <button
            className="btn btn-xs"
            disabled={!adjacent.next_id}
            onClick={() => navigate(`/endpoints/${adjacent.next_id}`)}
          >
            next →
          </button>
        </div>
        <Link to="/endpoints" className="link link-sm">
          back to workspace
        </Link>
      </div>

      {/* Header */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="badge badge-outline mono">{endpoint.method}</span>
          <span className="font-mono text-lg break-all">{endpoint.normalized_path}</span>
        </div>
        <div className="text-sm text-base-content/60 mono">{origin || hostDisplay}</div>
        <div className="text-xs text-base-content/50 mt-1 flex items-center gap-2">
          Endpoint ID <UuidChip value={endpoint.id} />
        </div>

        <div className="flex flex-wrap gap-2 mt-3 items-center">
          <StatusBadge value={effective} />
          <span className="badge badge-ghost badge-sm uppercase">
            {(prioSource || "auto").replace("path_rule", "rule")}
          </span>
          <DecisionBadge decision={decision} />
          <span className={`badge badge-sm ${policy?.excluded ? "badge-ghost" : "badge-outline"}`}>
            {policy?.excluded ? "EXCLUDED" : "INCLUDED"}
          </span>
          <span
            className={`badge badge-sm ${
              safetyLabel === "SAFE" ? "badge-success" : "badge-error"
            }`}
          >
            {safetyLabel}
          </span>
          {tags.map((t) => (
            <span key={t} className="badge badge-warning badge-sm">
              {t}
            </span>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-2 mb-6">
        {(() => {
          const preferredFlowId =
            (policy?.baseline_flow_id &&
              flows.some((f: any) => f.id === policy.baseline_flow_id) &&
              policy.baseline_flow_id) ||
            flows[0]?.id ||
            null;
          return preferredFlowId ? (
            <Link
              to={`/repeater?flow=${preferredFlowId}`}
              className="btn btn-xs btn-primary"
              title="Open preferred flow in Repeater (Mode 2)"
            >
              Send to Repeater
            </Link>
          ) : (
            <button
              type="button"
              className="btn btn-xs btn-disabled"
              title="No flows for this endpoint"
            >
              Send to Repeater
            </button>
          );
        })()}
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Replay ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-40 border border-base-300 z-20">
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/replay/endpoint/${endpointId}`, { right_now: true });
                  load();
                }}
              >
                Replay now
              </button>
            </li>
          </ul>
        </div>
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Enqueue ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-20">
            <li>
              <button
                onClick={async () => {
                  await act.run("/api/scheduler/enqueue/endpoint", {
                    endpoint_id: endpointId,
                  });
                  load();
                }}
              >
                Enqueue replay
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run("/api/scheduler/enqueue/endpoint", {
                    endpoint_id: endpointId,
                    type: "auth-test",
                  });
                  load();
                }}
              >
                Enqueue auth test
              </button>
            </li>
          </ul>
        </div>
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Mark ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-20">
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/mark`, { tag: "dangerous" });
                  load();
                }}
              >
                Dangerous
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/mark`, { tag: "logout" });
                  load();
                }}
              >
                Logout
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/mark`, { tag: "safe" });
                  load();
                }}
              >
                Safe (clear annotations)
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/unmark`, { tag: "dangerous" });
                  load();
                }}
              >
                Unmark dangerous
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/unmark`, { tag: "logout" });
                  load();
                }}
              >
                Unmark logout
              </button>
            </li>
          </ul>
        </div>
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Priority ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-20">
            {PRIORITIES.map((p) => (
              <li key={p}>
                <button
                  onClick={async () => {
                    await act.run(`/api/endpoints/${endpointId}/priority`, { priority: p });
                    load();
                  }}
                >
                  {p}
                </button>
              </li>
            ))}
            <li>
              <button
                onClick={async () => {
                  await api.del(`/api/endpoints/${endpointId}/priority`, {
                    project_id: selected!.id,
                  });
                  load();
                }}
              >
                Clear manual priority
              </button>
            </li>
          </ul>
        </div>
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Exclusion ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-36 border border-base-300 z-20">
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/exclude`);
                  load();
                }}
              >
                Exclude
              </button>
            </li>
            <li>
              <button
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/include`);
                  load();
                }}
              >
                Include
              </button>
            </li>
          </ul>
        </div>
        <div className="dropdown">
          <button tabIndex={0} className="btn btn-xs">
            Tags ▾
          </button>
          <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-52 border border-base-300 z-20">
            <li className="p-2">
              <input
                className="input input-xs input-bordered w-full"
                placeholder="tag"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onClick={(e) => e.stopPropagation()}
              />
            </li>
            <li>
              <button
                disabled={!tagInput.trim()}
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/tags`, {
                    action: "add",
                    tags: [tagInput.trim()],
                  });
                  setTagInput("");
                  load();
                }}
              >
                Add tag
              </button>
            </li>
            <li>
              <button
                disabled={!tagInput.trim()}
                onClick={async () => {
                  await act.run(`/api/endpoints/${endpointId}/tags`, {
                    action: "remove",
                    tags: [tagInput.trim()],
                  });
                  setTagInput("");
                  load();
                }}
              >
                Remove tag
              </button>
            </li>
          </ul>
        </div>
      </div>

      {/* Tabs */}
      <div role="tablist" className="tabs tabs-boxed w-fit mb-4 flex-wrap">
        {(
          [
            ["overview", "Overview"],
            ["policy", "Policy"],
            ["parameters", "Parameters"],
            ["flows", "Flows"],
            ["activity", "Activity"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            type="button"
            className={`tab ${tab === id ? "tab-active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <Section title="Identity">
              <dl className="text-sm space-y-1">
                <Row label="Method" value={endpoint.method} mono />
                <Row label="Canonical origin" value={origin} mono />
                <Row label="Host" value={hostDisplay} mono />
                <Row label="Normalized path" value={endpoint.normalized_path} mono />
                <Row label="Endpoint ID" value={endpoint.id} mono />
              </dl>
            </Section>
            <Section title="Observation">
              <dl className="text-sm space-y-1">
                <Row label="First seen" value={formatIST(endpoint.first_seen)} />
                <Row label="Last seen" value={`${formatRelativeAge(endpoint.last_seen)} (${formatIST(endpoint.last_seen)})`} />
                <Row label="Hit count" value={String(endpoint.hit_count ?? "—")} />
                <Row
                  label="Observed roles"
                  value={roles.map((r) => r.name).join(", ") || "—"}
                />
                <Row
                  label="Observed modules"
                  value={modules.map((m) => m.name).join(", ") || "—"}
                />
              </dl>
            </Section>
            <Section title="Qualification & baseline">
              <dl className="text-sm space-y-1">
                <Row
                  label="Qualified"
                  value={
                    policy?.qualified
                      ? `yes · ${policy?.qualification_reason || "flow_2xx"}`
                      : `no · ${policy?.qualification_reason || "—"}`
                  }
                />
                <div className="flex gap-2 items-center">
                  <span className="text-base-content/50 w-36">Baseline flow</span>
                  <UuidChip value={policy?.baseline_flow_id} />
                  {policy?.baseline_status != null && (
                    <StatusBadge value={policy.baseline_status} />
                  )}
                </div>
              </dl>
            </Section>
          </div>
          <RelatedErrorsStrip
            title="Top errors"
            rows={errorRollup}
            loading={errorRollupLoading}
            emptyLabel="No error clusters linked to this endpoint yet."
            limit={8}
          />
        </div>
      )}

      {tab === "policy" && (
        <div className="max-w-2xl">
          <PolicyExplain data={explanation} />
        </div>
      )}

      {tab === "parameters" && (
        <Section title={`Parameters (${parameters.length})`}>
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Name</th>
                  <th>Type / Shape</th>
                  <th>Observed values</th>
                  <th>IV state</th>
                </tr>
              </thead>
              <tbody>
                {parameters.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="badge badge-ghost badge-xs">{p.location}</span>
                    </td>
                    <td className="mono">{p.name}</td>
                    <td className="text-xs">
                      {p.param_type}
                      {p.semantic_type ? ` · ${p.semantic_type}` : ""}
                    </td>
                    <td className="mono max-w-xs truncate text-xs">
                      {(p.example_values || []).join(", ") || "—"}
                    </td>
                    <td className="text-xs">
                      {p.is_reflected ? (
                        <span className="badge badge-warning badge-xs">
                          reflected ({p.reflection_count})
                        </span>
                      ) : (
                        <Link
                          className="link link-hover"
                          to={`${IV_BASE}?tab=parameters`}
                        >
                          open IV
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
                {parameters.length === 0 && (
                  <tr>
                    <td colSpan={5} className="text-center text-base-content/40 py-4">
                      No parameters observed.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {tab === "flows" && (
        <Section
          title="Recent flows"
          action={
            <Link
              className="btn btn-xs"
              to={`/flows?endpoint=${endpointId}`}
            >
              View all flows for endpoint
            </Link>
          }
        >
          <div className="overflow-x-auto panel">
            <table className="table table-tight table-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Status</th>
                  <th>Role</th>
                  <th>Module</th>
                  <th>Source</th>
                  <th>Flow</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f) => (
                  <tr
                    key={f.id}
                    className="hover cursor-pointer"
                    onClick={() => navigate(`/flows/${f.id}`)}
                  >
                    <td className="text-xs whitespace-nowrap">{formatIST(f.captured_at)}</td>
                    <td className="mono">{f.method}</td>
                    <td>
                      <StatusBadge value={f.status_code} />
                    </td>
                    <td>{f.role_name}</td>
                    <td>{f.module_name}</td>
                    <td>{f.source}</td>
                    <td>
                      <UuidChip value={f.id} />
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <Link
                        to={`/repeater?flow=${f.id}`}
                        className="btn btn-ghost btn-xs"
                      >
                        Repeater
                      </Link>
                    </td>
                  </tr>
                ))}
                {flows.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center text-base-content/40 py-4">
                      No flows yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {tab === "activity" && (
        <Section title="Activity">
          {activity_available ? (
            <div className="text-sm text-base-content/60">Activity timeline would appear here.</div>
          ) : (
            <div className="panel p-6 text-sm text-base-content/60">
              <p className="font-medium text-base-content mb-1">Not available yet</p>
              <p>
                Endpoint policy audit history is not persisted by Talos core. This tab will
                show priority changes, tags, exclusions, and discovery events when that audit
                stream exists. The Control Panel will not invent a timeline from{" "}
                <span className="mono">updated_at</span>.
              </p>
            </div>
          )}
        </Section>
      )}
    </div>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-2">
      <dt className="text-base-content/50 w-36 shrink-0">{label}</dt>
      <dd className={`break-all ${mono ? "mono text-xs" : ""}`}>{value || "—"}</dd>
    </div>
  );
}
