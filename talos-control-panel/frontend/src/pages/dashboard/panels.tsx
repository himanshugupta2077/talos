import { Link } from "react-router-dom";
import {
  formatProxyStateLabel,
  formatSchedulerStateLabel,
} from "../../api/client";
import {
  formatBytes,
  formatDurationSeconds,
  formatRelativeAge,
  formatUptime,
} from "./format";
import type { ProjectDashboard } from "./types";
import {
  CoverageMeter,
  MiniBars,
  MiniDonut,
  PanelShell,
  QueueFillBar,
  SegmentLegend,
  Stat,
  StatusDot,
} from "./widgets";

const SOURCE_LABELS: Record<string, string> = {
  proxy_capture: "capture",
  manual_replay: "manual",
  auto_replay: "auto",
  iv_scan: "iv",
};

export function HeroStrip({ data }: { data: ProjectDashboard }) {
  const { project, readiness, proxy, scheduler, findings } = data;
  const chips: {
    key: string;
    label: string;
    tone: "ok" | "warn" | "bad" | "idle";
    pulse?: boolean;
  }[] = [
    {
      key: "active",
      label: readiness.active ? "Active" : "Inactive",
      tone: readiness.active ? "ok" : "warn",
    },
    {
      key: "db",
      label: readiness.db ? "DB ready" : "No DB",
      tone: readiness.db ? "ok" : "bad",
    },
    {
      key: "scope",
      label: readiness.scope
        ? `Scope ${project.scope_count}`
        : "Empty scope",
      tone: readiness.scope ? "ok" : "warn",
    },
    {
      key: "proxy",
      label: readiness.proxy ? "Proxy live" : "Proxy stopped",
      tone: readiness.proxy ? "ok" : readiness.active ? "warn" : "idle",
      pulse: readiness.proxy,
    },
    {
      key: "session",
      label:
        readiness.session === "ok"
          ? "Session OK"
          : readiness.session === "degraded"
            ? "Session degraded"
            : "Session unset",
      tone:
        readiness.session === "ok"
          ? "ok"
          : readiness.session === "degraded"
            ? "bad"
            : "idle",
    },
    {
      key: "queue",
      label: readiness.queue_pressure
        ? "Queue pressure"
        : `Queue ${scheduler.active_queue}`,
      tone: readiness.queue_pressure ? "warn" : "idle",
    },
    {
      key: "triage",
      label: `${findings.by_status.TRIAGING || 0} triaging`,
      tone: (findings.by_status.TRIAGING || 0) > 0 ? "warn" : "idle",
    },
  ];

  const needOnboarding =
    !project.db_exists || project.scope_count === 0 || data.flows.total === 0;

  return (
    <div className="panel p-4 md:p-5 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold truncate">{project.name}</h1>
            {project.active ? (
              <span className="badge badge-success gap-1">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-success-content" />
                Activated
              </span>
            ) : (
              <span className="badge badge-ghost gap-1">Not activated</span>
            )}
            {proxy.running && (
              <span className="badge badge-outline badge-sm mono">
                {proxy.listen_host || "127.0.0.1"}:{proxy.listen_port || "—"}
              </span>
            )}
          </div>
          <p className="text-sm text-base-content/60 max-w-2xl">
            {project.description || "No description"}
          </p>
          {!project.active && (
            <p className="text-xs text-warning">
              This project isn&apos;t the active one in Talos — open it from the{" "}
              <Link to="/projects" className="link">
                Projects page
              </Link>{" "}
              to capture traffic against it.
            </p>
          )}
        </div>
        <div className="flex flex-wrap gap-2 text-xs text-base-content/60">
          <span className="badge badge-ghost badge-sm">
            {project.roles} roles · {project.modules} modules
          </span>
          <span className="badge badge-ghost badge-sm">
            bodies {project.constraints.store_bodies ? "on" : "off"} ·{" "}
            {formatBytes(project.constraints.max_body_size)}
          </span>
          {project.outscope_count > 0 && (
            <span className="badge badge-outline badge-sm">
              {project.outscope_count} out of scope
            </span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        {chips.map((c) => (
          <span
            key={c.key}
            className="inline-flex items-center gap-1.5 rounded-full border border-base-300 bg-base-200/40 px-2.5 py-1"
          >
            <StatusDot tone={c.tone} pulse={c.pulse} />
            <span className="text-xs font-medium">{c.label}</span>
          </span>
        ))}
      </div>

      {project.scope.length > 0 && (
        <div className="flex gap-1 flex-wrap">
          {project.scope.slice(0, 8).map((s) => (
            <span key={s} className="badge badge-outline badge-sm mono">
              {s}
            </span>
          ))}
          {project.scope.length > 8 && (
            <span className="badge badge-ghost badge-sm">
              +{project.scope.length - 8}
            </span>
          )}
        </div>
      )}

      {needOnboarding && (
        <div className="rounded-lg border border-warning/30 bg-warning/5 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-warning mb-2">
            Getting started
          </div>
          <ol className="grid sm:grid-cols-2 gap-1.5 text-sm text-base-content/70 list-decimal list-inside">
            <li className={project.active ? "opacity-50 line-through" : ""}>
              Open / activate project
            </li>
            <li className={project.scope_count > 0 ? "opacity-50 line-through" : ""}>
              Set Basic Scope
            </li>
            <li className={proxy.running ? "opacity-50 line-through" : ""}>
              Start proxy &amp; point browser
            </li>
            <li className={data.flows.total > 0 ? "opacity-50 line-through" : ""}>
              Browse app → watch flows climb
            </li>
          </ol>
        </div>
      )}
    </div>
  );
}

export function FindingsPanel({ data }: { data: ProjectDashboard }) {
  const f = data.findings;
  const by = f.by_status;
  const statusData = [
    { name: "Triaging", value: by.TRIAGING || 0, fill: "#f59e0b" },
    { name: "Confirmed", value: by.CONFIRMED || 0, fill: "#ef4444" },
    { name: "Rejected", value: by.REJECTED || 0, fill: "#94a3b8" },
    { name: "Duplicate", value: by.DUPLICATE || 0, fill: "#64748b" },
  ];
  const attackData = f.by_attack_type.map((a) => ({
    name: a.type,
    value: a.n,
  }));

  return (
    <PanelShell
      title="Findings"
      to="/findings"
      badge={
        <StatusDot
          tone={(by.TRIAGING || 0) > 0 ? "warn" : "ok"}
          label={(by.TRIAGING || 0) > 0 ? "action needed" : "clear"}
        />
      }
    >
      <div className="grid grid-cols-4 gap-2">
        <Stat value={by.TRIAGING || 0} label="Triaging" accent="warning" size="lg" />
        <Stat value={by.CONFIRMED || 0} label="Confirmed" accent="error" />
        <Stat value={by.REJECTED || 0} label="Rejected" size="sm" />
        <Stat value={by.DUPLICATE || 0} label="Duplicate" size="sm" />
      </div>
      <div className="grid grid-cols-2 gap-2 items-center">
        <MiniDonut data={statusData} height={100} />
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1">
            By attack type
          </div>
          <MiniBars data={attackData} height={90} layout="vertical" />
        </div>
      </div>
      <SegmentLegend items={statusData} />
      <div className="text-[11px] text-base-content/50">
        Groups: <span className="mono text-base-content/80">{f.groups_open}</span>
      </div>
      {f.recent_triaging.length > 0 && (
        <ul className="space-y-1.5 border-t border-base-300 pt-2">
          {f.recent_triaging.map((row) => (
            <li key={row.id}>
              <Link
                to={`/findings/${row.id}`}
                className="flex items-start justify-between gap-2 text-sm hover:text-primary"
              >
                <span className="truncate">
                  {row.title || row.id.slice(0, 8)}
                </span>
                <span className="badge badge-ghost badge-xs shrink-0">
                  {row.attack_type || "—"}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </PanelShell>
  );
}

export function SchedulerPanel({ data }: { data: ProjectDashboard }) {
  const s = data.scheduler;
  const stateLabel = formatSchedulerStateLabel(s.state?.state);
  const counts = s.counts || {};
  const statusData = [
    { name: "pend", value: counts.pending || 0, fill: "#6366f1" },
    { name: "run", value: counts.running || 0, fill: "#22c55e" },
    { name: "done", value: counts.done || 0, fill: "#94a3b8" },
    { name: "fail", value: counts.failed || 0, fill: "#ef4444" },
    { name: "skip", value: counts.skipped || 0, fill: "#64748b" },
    { name: "pause", value: counts.paused || 0, fill: "#f59e0b" },
  ];
  const maxQ = s.config?.max_queue_size || 200;
  const tone =
    (s.state?.state || "").toLowerCase() === "running"
      ? "ok"
      : (s.state?.state || "").toLowerCase().includes("wait")
        ? "warn"
        : (s.state?.state || "").toLowerCase() === "paused"
          ? "warn"
          : "idle";

  return (
    <PanelShell
      title="Scheduler"
      to="/scheduler"
      badge={<StatusDot tone={tone} pulse={tone === "ok"} label={stateLabel} />}
    >
      <div className="grid grid-cols-3 gap-2">
        <Stat value={s.active_queue} label="Active queue" accent="info" />
        <Stat value={counts.failed || 0} label="Failed" accent="error" size="sm" />
        <Stat value={counts.done || 0} label="Done" size="sm" />
      </div>
      <QueueFillBar pct={s.queue_fill_pct} active={s.active_queue} max={maxQ} />
      <MiniBars data={statusData} height={96} />
      <div className="text-[11px] text-base-content/50 flex flex-wrap gap-2">
        <span>
          delay{" "}
          <span className="mono text-base-content/80">
            {s.config?.min_delay ?? "—"}–{s.config?.max_delay ?? "—"}s
          </span>
        </span>
        {s.by_job_type_active.length > 0 && (
          <span>
            active types:{" "}
            {s.by_job_type_active
              .slice(0, 3)
              .map((j) => `${j.job_type}(${j.n})`)
              .join(" · ")}
          </span>
        )}
      </div>
      {s.recent_failed.length > 0 && (
        <ul className="space-y-1 border-t border-base-300 pt-2">
          {s.recent_failed.slice(0, 3).map((j) => (
            <li
              key={j.id}
              className="text-xs flex justify-between gap-2 text-error/90"
            >
              <span className="truncate mono">{j.job_type || j.id.slice(0, 8)}</span>
              <span className="truncate opacity-70">
                {j.failure_reason || "failed"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </PanelShell>
  );
}

export function ProxyPanel({ data }: { data: ProjectDashboard }) {
  const p = data.proxy;
  const label = formatProxyStateLabel(p);
  const tone =
    p.running ? "ok" : p.last_error ? "bad" : p.transitional ? "warn" : "idle";

  return (
    <PanelShell
      title="Proxy"
      to="/proxy"
      badge={<StatusDot tone={tone} pulse={p.running} label={label} />}
    >
      <div className="space-y-2">
        <div className="flex items-baseline justify-between gap-2">
          <Stat
            value={
              p.listen_port
                ? `${p.listen_host || "127.0.0.1"}:${p.listen_port}`
                : "—"
            }
            label="Listen"
            size="sm"
          />
          <div className="text-right">
            <div className="text-lg font-semibold mono tabular-nums">
              {formatUptime(p.startup_time)}
            </div>
            <div className="text-[11px] uppercase text-base-content/50">
              Uptime
            </div>
          </div>
        </div>
        <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
          <div>
            <dt className="text-base-content/50">Mode</dt>
            <dd className="mono">
              {p.upstream_url ? `upstream · ${p.upstream_url}` : "direct"}
            </dd>
          </div>
          <div>
            <dt className="text-base-content/50">PID</dt>
            <dd className="mono">{p.pid ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-base-content/50">Project</dt>
            <dd className="mono truncate">
              {p.project_id || "—"}
            </dd>
          </div>
          <div>
            <dt className="text-base-content/50">Role / module</dt>
            <dd className="mono truncate">
              {(p.role_id || "—").slice(0, 8)} / {(p.module_id || "—").slice(0, 8)}
            </dd>
          </div>
        </dl>
        {p.restart_pending && (
          <div className="text-xs text-warning">Restart pending…</div>
        )}
        {p.last_error && (
          <div className="text-xs text-error bg-error/10 rounded px-2 py-1.5 line-clamp-3">
            {p.last_error}
          </div>
        )}
      </div>
    </PanelShell>
  );
}

export function SessionHealthPanel({ data }: { data: ProjectDashboard }) {
  const roles = data.session_health;
  const degraded = roles.filter((r) => r.health_degraded).length;
  const configured = roles.filter((r) => r.configured).length;

  return (
    <PanelShell
      title="Session health"
      to="/auth"
      badge={
        <StatusDot
          tone={degraded > 0 ? "bad" : configured > 0 ? "ok" : "idle"}
          label={
            degraded > 0
              ? `${degraded} degraded`
              : configured > 0
                ? `${configured} ready`
                : "unset"
          }
        />
      }
    >
      {roles.length === 0 ? (
        <p className="text-sm text-base-content/50">No roles yet.</p>
      ) : (
        <ul className="space-y-2 max-h-56 overflow-y-auto pr-1">
          {roles.map((r) => {
            const tone = r.health_degraded
              ? "bad"
              : r.configured
                ? "ok"
                : "idle";
            return (
              <li
                key={r.role_id}
                className={`rounded-md border border-base-300 px-2.5 py-2 ${
                  r.is_active ? "bg-primary/5 border-primary/30" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <StatusDot tone={tone} />
                    <span className="font-medium text-sm truncate">
                      {r.role_name}
                    </span>
                    {r.is_active && (
                      <span className="badge badge-primary badge-xs">capture</span>
                    )}
                  </div>
                  <span className="badge badge-ghost badge-xs uppercase">
                    {r.provider || "none"}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-base-content/55">
                  <span>
                    age{" "}
                    <span className="mono text-base-content/80">
                      {formatDurationSeconds(r.session_age_seconds)}
                    </span>
                  </span>
                  <span>
                    expires{" "}
                    <span className="mono text-base-content/80">
                      {r.expires_in_seconds == null
                        ? "—"
                        : formatDurationSeconds(r.expires_in_seconds)}
                    </span>
                  </span>
                  <span>
                    suspicion{" "}
                    <span className="mono text-base-content/80">
                      {r.suspicion_count}/{r.suspicion_threshold}
                    </span>
                  </span>
                  <span>
                    ctl{" "}
                    <span className="mono text-base-content/80">
                      {r.control_flow_count}
                    </span>
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </PanelShell>
  );
}

export function EndpointsPanel({ data }: { data: ProjectDashboard }) {
  const inv = data.endpoints.inventory;
  const pol = data.endpoints.policy;
  const cov = data.endpoints.coverage;
  const decisionData = [
    { name: "Testable", value: inv.testable, fill: "#22c55e" },
    { name: "Excluded", value: inv.excluded, fill: "#94a3b8" },
    { name: "Unqual.", value: inv.unqualified, fill: "#f59e0b" },
  ];
  const prioData = ["CRITICAL", "HIGH", "NORMAL", "LOW"].map((k, i) => ({
    name: k.slice(0, 4),
    value: pol.by_priority?.[k] || 0,
    fill: ["#ef4444", "#f59e0b", "#6366f1", "#94a3b8"][i],
  }));

  return (
    <PanelShell title="Endpoints" to="/endpoints">
      <div className="grid grid-cols-4 gap-2">
        <Stat value={inv.total} label="Total" />
        <Stat value={inv.testable} label="Testable" accent="success" />
        <Stat value={inv.dangerous} label="Dangerous" accent="error" size="sm" />
        <Stat value={inv.logout} label="Logout" size="sm" />
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1">
            Decision mix
          </div>
          <MiniDonut data={decisionData} height={110} />
          <SegmentLegend items={decisionData} />
        </div>
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1">
            Priority
          </div>
          <MiniBars data={prioData} height={110} />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <CoverageMeter label="Qualified" pct={cov.qualified_pct} />
        <CoverageMeter label="Baseline" pct={cov.baseline_pct} />
        <CoverageMeter label="Multi-role" pct={cov.multi_role_pct} />
        <CoverageMeter label="Params" pct={cov.params_pct} />
      </div>
      <div className="text-[11px] text-base-content/50">
        Policy sources: manual {pol.manual_overrides} · rule {pol.rule_controlled}{" "}
        · auto {pol.auto_controlled}
      </div>
    </PanelShell>
  );
}

export function FlowsPanel({ data }: { data: ProjectDashboard }) {
  const f = data.flows;
  const sourceData = Object.entries(f.by_source || {}).map(([k, v]) => ({
    name: SOURCE_LABELS[k] || k,
    value: v,
  }));
  const statusData = ["2xx", "3xx", "4xx", "5xx", "other"].map((k, i) => ({
    name: k,
    value: f.by_status_class?.[k] || 0,
    fill: ["#22c55e", "#6366f1", "#f59e0b", "#ef4444", "#94a3b8"][i],
  }));
  const lastAge = formatRelativeAge(f.last_captured_at);
  const stale =
    f.last_captured_at &&
    Date.now() - new Date(f.last_captured_at).getTime() > 30 * 60 * 1000;

  return (
    <PanelShell
      title="Flows"
      to="/flows"
      badge={
        <StatusDot
          tone={f.total === 0 ? "idle" : stale ? "warn" : "ok"}
          label={f.total === 0 ? "empty" : `last ${lastAge}`}
        />
      }
    >
      <div className="grid grid-cols-4 gap-2">
        <Stat value={f.total} label="Total" size="lg" />
        <Stat value={f.distinct_hosts} label="Hosts" size="sm" />
        <Stat value={f.distinct_methods} label="Methods" size="sm" />
        <Stat
          value={lastAge}
          label="Last capture"
          size="sm"
          accent={stale ? "warning" : "default"}
        />
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1">
            Source mix
          </div>
          <MiniDonut data={sourceData} height={110} />
          <SegmentLegend items={sourceData} />
        </div>
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1">
            Status classes
          </div>
          <MiniBars data={statusData} height={110} />
        </div>
      </div>
    </PanelShell>
  );
}

export function HttpRulesPanel({ data }: { data: ProjectDashboard }) {
  const h = data.http_rules;
  const s = h.summary;
  return (
    <PanelShell
      title="HTTP rules"
      to="/mutations"
      badge={
        <StatusDot
          tone={h.enabled ? "ok" : "warn"}
          label={h.enabled ? "engine on" : "engine off"}
        />
      }
    >
      <div className="grid grid-cols-4 gap-2">
        <Stat value={s.active} label="Active" accent="success" />
        <Stat value={s.request} label="Request" size="sm" />
        <Stat value={s.response} label="Response" size="sm" />
        <Stat value={s.disabled} label="Disabled" size="sm" />
      </div>
      <div className="text-xs text-base-content/60">
        {s.total} total rules · manipulation engine{" "}
        <span className={h.enabled ? "text-success" : "text-warning"}>
          {h.enabled ? "enabled" : "disabled"}
        </span>
      </div>
    </PanelShell>
  );
}

export function TalosConfigPanel({ data }: { data: ProjectDashboard }) {
  const c = data.talos_config;
  const flags = c.key_flags || {};
  const sources = Object.entries(c.source_counts || {}).filter(([, n]) => n > 0);

  return (
    <PanelShell title="Talos config" to="/talos-config?tab=overview">
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {(c.sections || []).map((sec) => (
          <div
            key={sec.section}
            className="rounded-md border border-base-300 bg-base-200/30 px-2.5 py-2"
          >
            <div className="flex items-center justify-between gap-1">
              <span className="text-xs font-semibold uppercase tracking-wide">
                {sec.label}
              </span>
              <span className="badge badge-ghost badge-xs">{sec.source}</span>
            </div>
            <div className="text-xs text-base-content/70 mt-0.5 mono">
              {sec.summary}
            </div>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-2 text-[11px]">
        <span className="badge badge-outline badge-sm">
          upstream {flags.upstream_enabled ? "on" : "off"}
        </span>
        <span className="badge badge-outline badge-sm">
          bodies {flags.store_bodies === false ? "off" : "on"}
        </span>
        <span className="badge badge-outline badge-sm">
          unauth auto {flags.unauth_auto_run ? "on" : "off"}
        </span>
        <span className="badge badge-outline badge-sm">
          http {flags.http_enabled === false ? "off" : "on"}
        </span>
      </div>
      {sources.length > 0 && (
        <div className="text-[11px] text-base-content/50">
          Leaf sources:{" "}
          {sources.map(([k, n]) => `${k}=${n}`).join(" · ")}
        </div>
      )}
    </PanelShell>
  );
}

export function ActivityRail({ data }: { data: ProjectDashboard }) {
  const findings = data.findings.recent_triaging;
  const failed = data.scheduler.recent_failed;
  if (!findings.length && !failed.length) return null;

  return (
    <div className="panel p-4">
      <div className="text-sm font-semibold tracking-wide uppercase text-base-content/80 mb-3">
        Activity
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1.5">
            Recent triaging
          </div>
          {findings.length === 0 ? (
            <p className="text-xs text-base-content/40">None</p>
          ) : (
            <ul className="space-y-1">
              {findings.map((f) => (
                <li key={f.id}>
                  <Link
                    to={`/findings/${f.id}`}
                    className="text-sm hover:text-primary flex justify-between gap-2"
                  >
                    <span className="truncate">{f.title || f.id.slice(0, 8)}</span>
                    <span className="text-[11px] text-base-content/50 mono shrink-0">
                      {formatRelativeAge(f.created_at)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <div className="text-[11px] uppercase text-base-content/50 mb-1.5">
            Recent failed jobs
          </div>
          {failed.length === 0 ? (
            <p className="text-xs text-base-content/40">None</p>
          ) : (
            <ul className="space-y-1">
              {failed.map((j) => (
                <li key={j.id} className="text-sm flex justify-between gap-2">
                  <Link
                    to={`/scheduler?tab=history&status=failed&job=${encodeURIComponent(j.id)}`}
                    className="truncate hover:text-primary mono"
                  >
                    {j.job_type || j.id.slice(0, 8)}
                  </Link>
                  <span className="text-[11px] text-error/80 truncate max-w-[50%]">
                    {j.failure_reason || "failed"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
