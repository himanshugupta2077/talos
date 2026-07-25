/**
 * Flow inspection workspace — primary UI for one HTTP transaction.
 *
 * Layout: header + health chips | tabs (Overview/HTTP/Replay/Timeline/Debug)
 * | operator panels below (Actions / Session / Attack / Related).
 * Thin surface over Core data — no re-derived verdicts or session scores.
 */

import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { ModuleHelp, UuidChip } from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import HttpInspector from "../components/http/HttpInspector";
import { formatIST } from "../lib/time";
import { formatDurationMs, methodBadgeClass } from "../lib/flowFlags";
import { FlowDetail as FlowDetailT, Role } from "../types";
import FlowActions from "./flows/FlowActions";
import FlowHealthChips from "./flows/FlowHealthChips";
import FlowSummaryCard from "./flows/FlowSummaryCard";
import FlowMetaCard from "./flows/FlowMetaCard";
import FlowAttackResults from "./flows/FlowAttackResults";
import FlowReplayPanel from "./flows/FlowReplayPanel";
import FlowSessionPanel, { SessionIntel } from "./flows/FlowSessionPanel";
import FlowRelatedPanel from "./flows/FlowRelatedPanel";
import FlowTimeline, { buildTimelineEvents } from "./flows/FlowTimeline";
import FlowDebugPanel from "./flows/FlowDebugPanel";

interface Derived {
  duration_ms?: number | null;
  request_body_size?: number;
  response_body_size?: number;
  has_auth_material?: boolean;
  request_body_truncated?: boolean;
  response_body_truncated?: boolean;
  is_replay?: boolean;
  has_request_body?: boolean;
  has_response_body?: boolean;
}

interface Results {
  diff?: any;
  bac?: any;
  unauth?: any;
  auth_test?: any;
}

interface Bundle {
  flow: FlowDetailT & {
    role_id?: string;
    module_id?: string;
    request_body_truncated?: boolean;
    response_body_truncated?: boolean;
  };
  derived?: Derived;
  results?: Results;
  endpoint_policy?: any;
  diff?: any;
  bac_result?: any;
  unauth_result?: any;
  auth_test_result?: any;
}

interface Related {
  original: any;
  children: any[];
  findings: any[];
  jobs: any[];
  param_count: number;
}

interface Intelligence {
  endpoint: any;
  session: SessionIntel | null;
}

type LeftTab = "overview" | "http" | "replay" | "timeline" | "debug";

export default function FlowDetail() {
  const { flowId } = useParams();
  const { selected } = useProject();
  const [searchParams] = useSearchParams();
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [related, setRelated] = useState<Related | null>(null);
  const [intel, setIntel] = useState<Intelligence | null>(null);
  const [adjacent, setAdjacent] = useState<{ prev_id: string | null; next_id: string | null }>({
    prev_id: null,
    next_id: null,
  });
  const [roles, setRoles] = useState<Role[]>([]);
  const [tab, setTab] = useState<LeftTab>("http");
  const navigate = useNavigate();

  // Optional filter-aware adjacent (from list query string)
  const filterQs = useMemo(() => {
    const keys = [
      "source",
      "method",
      "host",
      "status_code",
      "role",
      "module",
      "search",
      "endpoint",
    ];
    const q: Record<string, string> = {};
    for (const k of keys) {
      const v = searchParams.get(k);
      if (v) q[k] = v;
    }
    return q;
  }, [searchParams]);

  const load = () => {
    if (!selected || !flowId) return;
    api.get<Bundle>(`/api/flows/${flowId}`, { project_id: selected.id }).then(setBundle);
    api
      .get(`/api/flows/${flowId}/adjacent`, { project_id: selected.id, ...filterQs })
      .then(setAdjacent as any);
    api
      .get<Related>(`/api/flows/${flowId}/related`, { project_id: selected.id })
      .then(setRelated)
      .catch(() => setRelated(null));
    api
      .get<Intelligence>(`/api/flows/${flowId}/intelligence`, { project_id: selected.id })
      .then(setIntel)
      .catch(() => setIntel(null));
  };

  useEffect(load, [selected, flowId, filterQs]);

  useEffect(() => {
    if (!selected) return;
    api.get<{ roles: Role[] }>("/api/roles", { project_id: selected.id }).then((r) => setRoles(r.roles));
  }, [selected]);

  // Keyboard: ← / → prev/next, Esc → list (when not in input)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.tagName === "SELECT" ||
          t.isContentEditable)
      ) {
        return;
      }
      if (e.key === "Escape") {
        navigate("/flows");
        return;
      }
      if (e.key === "ArrowLeft" && adjacent.prev_id) {
        e.preventDefault();
        navigate(`/flows/${adjacent.prev_id}${locationSearchPreserve(searchParams)}`);
      }
      if (e.key === "ArrowRight" && adjacent.next_id) {
        e.preventDefault();
        navigate(`/flows/${adjacent.next_id}${locationSearchPreserve(searchParams)}`);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [adjacent, navigate, searchParams]);

  // Hash section deep-links
  useEffect(() => {
    const hash = window.location.hash.replace("#", "");
    if (hash.startsWith("section=")) {
      const s = hash.slice("section=".length) as LeftTab;
      if (["overview", "http", "replay", "timeline", "debug"].includes(s)) setTab(s);
    }
  }, [flowId]);

  if (!selected) {
    return (
      <div className="text-base-content/60 text-sm">
        Select a project to inspect flows.
      </div>
    );
  }

  if (!bundle) return <div className="loading loading-spinner" />;

  const { flow, derived, results, endpoint_policy } = bundle;
  const diff = results?.diff ?? bundle.diff;
  const bac = results?.bac ?? bundle.bac_result;
  const unauth = results?.unauth ?? bundle.unauth_result;
  const authTest = results?.auth_test ?? bundle.auth_test_result;

  const pathDisplay = `${flow.path}${flow.query ? `?${flow.query}` : ""}`;
  const duration = formatDurationMs(derived?.duration_ms);
  const fromEndpoint = searchParams.get("from") === "endpoint" || !!flow.endpoint_id;

  const timeline = buildTimelineEvents({
    capturedAt: flow.captured_at,
    endpointId: flow.endpoint_id,
    jobs: related?.jobs,
    children: related?.children,
    diff,
    bac,
    unauth,
    authTest,
    findings: related?.findings,
  });

  const tabs: { id: LeftTab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "http", label: "HTTP" },
    { id: "replay", label: "Replay" },
    { id: "timeline", label: "Timeline" },
    { id: "debug", label: "Debug" },
  ];

  return (
    <div className="pb-16">
      {/* Breadcrumb + nav */}
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="text-xs text-base-content/50 flex items-center gap-1 flex-wrap">
          <Link to="/flows" className="link link-hover">
            Flows
          </Link>
          <span>›</span>
          <span className="mono">Flow {flow.id.slice(0, 8)}</span>
          {fromEndpoint && flow.endpoint_id && (
            <>
              <span className="mx-1">·</span>
              <Link to={`/endpoints/${flow.endpoint_id}`} className="link link-hover">
                Back to endpoint
              </Link>
            </>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn btn-xs"
            disabled={!adjacent.prev_id}
            onClick={() =>
              navigate(`/flows/${adjacent.prev_id}${locationSearchPreserve(searchParams)}`)
            }
            title="Newer (←)"
          >
            ← newer
          </button>
          <button
            type="button"
            className="btn btn-xs"
            disabled={!adjacent.next_id}
            onClick={() =>
              navigate(`/flows/${adjacent.next_id}${locationSearchPreserve(searchParams)}`)
            }
            title="Older (→)"
          >
            older →
          </button>
          <Link to="/flows" className="link link-sm">
            Esc → list
          </Link>
        </div>
      </div>

      <ModuleHelp title="How Flow inspection works">
        <p>
          Each flow is one stored HTTP transaction. Request/response bodies and headers
          come from the project database; attack/diff chips are Core result rows — the UI
          does not re-score BAC or session health.
        </p>
        <p>
          <strong>HTTP</strong> shows Request and Response side by side. Each side defaults
          to Burp-style <strong>Pretty</strong>: full message (start-line, all headers, body)
          with syntax colors, line numbers, wrap always on, and indented
          JSON/XML/HTML/CSS/JS. Switch to Raw for the untransformed dump; request also has
          Params and JWT.
        </p>
        <p>
          <strong>Replay now</strong> re-sends the stored request via Core; modified or
          different-role replay is not a first-class CLI action yet — use Attack for
          BAC/unauth. Operator panels (Actions, Session, Attack results, Related) sit below
          the main workspace.
        </p>
        <p>
          Keyboard: <span className="mono">←</span> / <span className="mono">→</span>{" "}
          adjacent flows, <span className="mono">Esc</span> back to the list.
        </p>
      </ModuleHelp>

      {/* Header */}
      <div className="mb-4 mt-3">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className={`badge badge-outline mono ${methodBadgeClass(flow.method)}`}>
            {flow.method}
          </span>
          <span className="mono text-base break-all">
            <span className="text-base-content/50 text-sm">{flow.host}</span>
            <span className="font-medium">{pathDisplay}</span>
          </span>
          <StatusBadge value={flow.status_code} />
          <span className="badge badge-ghost badge-sm">{flow.source}</span>
          {duration && <span className="badge badge-ghost badge-sm">{duration}</span>}
        </div>
        <div className="text-xs text-base-content/50 flex gap-3 flex-wrap items-center">
          <span>{formatIST(flow.captured_at)}</span>
          <span>role: {flow.role_name}</span>
          <span>module: {flow.module_name}</span>
          <span className="flex items-center gap-1">
            id <UuidChip value={flow.id} />
          </span>
          {flow.endpoint_id && (
            <Link to={`/endpoints/${flow.endpoint_id}`} className="link">
              endpoint
            </Link>
          )}
          {flow.original_flow_id && (
            <Link to={`/flows/${flow.original_flow_id}`} className="link">
              original
            </Link>
          )}
          {(related?.findings?.length ?? 0) > 0 && (
            <Link to={`/findings/${related!.findings[0].finding_id}`} className="link">
              finding
            </Link>
          )}
        </div>
        <FlowHealthChips
          source={{
            ...flow,
            derived,
            results: { diff, bac, unauth, auth_test: authTest },
            endpoint_policy: endpoint_policy || intel?.endpoint,
            has_auth_material: derived?.has_auth_material,
          }}
        />
      </div>

      {/* Full-width workspace tabs */}
      <div className="min-w-0">
        <div className="tabs tabs-boxed tabs-sm mb-4 flex-wrap bg-base-200/50 p-1 w-fit max-w-full">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              className={`tab ${tab === t.id ? "tab-active" : ""}`}
              onClick={() => {
                setTab(t.id);
                window.location.hash = `section=${t.id}`;
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <div className="space-y-4">
            <FlowSummaryCard flow={flow} derived={derived} />
            <FlowMetaCard flowMeta={flow.flow_meta} />
          </div>
        )}

        {tab === "http" && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="panel p-3 min-w-0">
              <h3 className="font-semibold text-sm mb-2">Request</h3>
              <HttpInspector
                side="request"
                startLine={`${flow.method} ${flow.path}${flow.query ? `?${flow.query}` : ""} HTTP/1.1`}
                headers={flow.request_headers || {}}
                cookies={flow.request_cookies || {}}
                body={flow.request_body}
                bodyEncoding={flow.request_body_encoding}
                contentType={flow.content_type}
                query={flow.query}
              />
            </div>
            <div className="panel p-3 min-w-0">
              <h3 className="font-semibold text-sm mb-2">Response</h3>
              <HttpInspector
                side="response"
                startLine={`HTTP/1.1 ${flow.status_code ?? ""}`}
                headers={flow.response_headers || {}}
                body={flow.response_body}
                bodyEncoding={flow.response_body_encoding}
                contentType={
                  (flow.response_headers &&
                    (flow.response_headers["Content-Type"] ||
                      flow.response_headers["content-type"])) ||
                  flow.content_type
                }
              />
            </div>
          </div>
        )}

        {tab === "replay" && (
          <FlowReplayPanel
            originalFlowId={flow.original_flow_id}
            original={related?.original}
            children={related?.children || []}
            diff={diff}
          />
        )}

        {tab === "timeline" && <FlowTimeline events={timeline} />}

        {tab === "debug" && <FlowDebugPanel flow={flow} derived={derived} />}
      </div>

      {/* Operator panels below request/response (and other tabs) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mt-6">
        <div className="panel p-3">
          <h3 className="font-semibold text-sm mb-2">Actions</h3>
          <FlowActions
            variant="panel"
            projectId={selected.id}
            roles={roles}
            flow={{
              id: flow.id,
              method: flow.method,
              host: flow.host,
              path: flow.path,
              query: flow.query,
              url: flow.url,
              endpoint_id: flow.endpoint_id,
              request_headers: flow.request_headers,
              request_cookies: flow.request_cookies,
              request_body: flow.request_body,
              request_body_encoding: flow.request_body_encoding,
            }}
          />
        </div>

        <div className="panel p-3">
          <h3 className="font-semibold text-sm mb-2">Session</h3>
          <FlowSessionPanel session={intel?.session ?? null} />
        </div>

        <div className="panel p-3">
          <h3 className="font-semibold text-sm mb-2">Attack results</h3>
          <FlowAttackResults
            results={{ diff, bac, unauth, auth_test: authTest }}
          />
        </div>

        <div className="panel p-3">
          <h3 className="font-semibold text-sm mb-2">Related</h3>
          <FlowRelatedPanel
            roleName={flow.role_name}
            moduleName={flow.module_name}
            endpointId={flow.endpoint_id}
            originalFlowId={flow.original_flow_id}
            childrenCount={related?.children?.length ?? 0}
            findings={related?.findings || []}
            jobs={related?.jobs || []}
            paramCount={related?.param_count}
          />
        </div>

        {flow.tags && flow.tags.length > 0 && (
          <div className="panel p-3 sm:col-span-2 xl:col-span-4">
            <h3 className="font-semibold text-sm mb-2">Tags</h3>
            <div className="flex flex-wrap gap-1">
              {flow.tags.map((t) => (
                <span key={t} className="badge badge-sm badge-warning">
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer nav */}
      <div className="fixed bottom-0 left-0 right-0 border-t border-base-300 bg-base-100/95 backdrop-blur px-6 py-2 flex justify-between text-sm z-20 lg:left-56">
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={!adjacent.prev_id}
          onClick={() =>
            navigate(`/flows/${adjacent.prev_id}${locationSearchPreserve(searchParams)}`)
          }
        >
          ← Previous flow
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={!adjacent.next_id}
          onClick={() =>
            navigate(`/flows/${adjacent.next_id}${locationSearchPreserve(searchParams)}`)
          }
        >
          Next flow →
        </button>
      </div>
    </div>
  );
}

function locationSearchPreserve(sp: URLSearchParams): string {
  const s = sp.toString();
  return s ? `?${s}` : "";
}
