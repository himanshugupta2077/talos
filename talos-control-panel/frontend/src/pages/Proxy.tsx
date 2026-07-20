import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  api,
  formatProxyStateLabel,
  ProxyRuntimeStatus,
} from "../api/client";
import { useAction } from "../hooks/useAction";
import { useProject } from "../state/ProjectContext";
import { useStatus } from "../state/StatusContext";

interface ProxyConfig {
  project_id?: string;
  mode: "direct" | "upstream" | string;
  upstream_url: string | null;
}

interface LayeredProxy {
  mode: string;
  upstream_url: unknown;
  source: string;
}

interface HttpRulesSummary {
  enabled: boolean | null;
  active: number;
  request: number;
  response: number;
  total: number;
}

const emptyStatus: ProxyRuntimeStatus = {
  state: "stopped",
  running: false,
  transitional: false,
};

export default function Proxy() {
  const { selected } = useProject();
  const { refreshStatus } = useStatus();
  const [status, setStatus] = useState<ProxyRuntimeStatus>(emptyStatus);
  const [logs, setLogs] = useState<string[]>([]);
  const [logPath, setLogPath] = useState<string | null>(null);
  const [listenHost, setListenHost] = useState("127.0.0.1");
  const [port, setPort] = useState(8080);
  const [upstreamInput, setUpstreamInput] = useState("");
  const [config, setConfig] = useState<ProxyConfig | null>(null);
  const [layered, setLayered] = useState<LayeredProxy | null>(null);
  const [httpRules, setHttpRules] = useState<HttpRulesSummary | null>(null);
  const [copied, setCopied] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const loadConfig = useCallback(async () => {
    try {
      const c = await api.get<ProxyConfig>("/api/proxy/config");
      setConfig(c);
      setUpstreamInput(c.upstream_url || "");
    } catch {
      setConfig(null);
    }
    try {
      const params = selected?.id ? { project_id: selected.id } : undefined;
      const eff = await api.get<{
        values: Record<string, unknown>;
        sources: Record<string, string>;
      }>("/api/configuration/effective", params);
      const enabled = Boolean(eff.values?.["proxy.upstream.enabled"]);
      const url = eff.values?.["proxy.upstream.url"];
      const src =
        (eff.sources?.["proxy.upstream.enabled"] ||
          eff.sources?.["proxy.upstream.url"] ||
          "default"
        ).toLowerCase();
      setLayered({
        mode: enabled ? "upstream" : "direct",
        upstream_url: url,
        source: src,
      });
    } catch {
      setLayered(null);
    }
    // Compact HTTP Manipulation status — pipeline stage before capture.
    if (selected?.id) {
      try {
        const r = await api.get<{
          enabled: boolean;
          summary?: {
            active: number;
            request: number;
            response: number;
            total: number;
          };
          count?: number;
        }>("/api/mutations", { project_id: selected.id });
        setHttpRules({
          enabled: r.enabled !== false,
          active: r.summary?.active ?? r.count ?? 0,
          request: r.summary?.request ?? 0,
          response: r.summary?.response ?? 0,
          total: r.summary?.total ?? r.count ?? 0,
        });
      } catch {
        setHttpRules(null);
      }
    } else {
      setHttpRules(null);
    }
  }, [selected?.id]);

  const poll = useCallback(async () => {
    try {
      const s = await api.get<ProxyRuntimeStatus>("/api/proxy/status");
      setStatus({
        ...emptyStatus,
        ...s,
        state: (s.state || "stopped").toLowerCase(),
        running: !!s.running || (s.state || "").toLowerCase() === "running",
      });
      // Prefill listen fields from last known runtime when idle.
      if (s.listen_host && !s.running && (s.state || "") === "stopped") {
        setListenHost(s.listen_host);
      }
      if (s.listen_port != null && !s.running && (s.state || "") === "stopped") {
        setPort(s.listen_port);
      }
      if (s.running && s.listen_host) setListenHost(s.listen_host);
      if (s.running && s.listen_port != null) setPort(s.listen_port);
    } catch {
      setStatus(emptyStatus);
    }
    try {
      const l = await api.get<{ lines: string[]; path?: string }>("/api/proxy/logs", {
        tail: 500,
      });
      setLogs(l.lines);
      setLogPath(l.path || null);
    } catch {
      setLogs([]);
    }
  }, []);

  const start = useAction("Start proxy", () =>
    api.post("/api/proxy/start", { listen_host: listenHost, port })
  );
  const stop = useAction("Stop proxy", () => api.post("/api/proxy/stop", {}));
  const restart = useAction("Restart proxy", () =>
    api.post("/api/proxy/restart", { listen_host: listenHost, port })
  );
  const kill = useAction("Kill proxy / free port", () =>
    api.post("/api/proxy/kill", { listen_host: listenHost, port, force: false })
  );
  const forceKill = useAction("Force kill proxy port", () =>
    api.post("/api/proxy/kill", { listen_host: listenHost, port, force: true })
  );
  const setUpstream = useAction("Set upstream proxy", () =>
    api.post("/api/proxy/config", { upstream_url: upstreamInput.trim() })
  );
  const setDirect = useAction("Set direct mode", () =>
    api.post("/api/proxy/config", { direct: true })
  );

  useEffect(() => {
    poll();
    loadConfig();
    const id = setInterval(poll, status.transitional ? 1000 : 2000);
    return () => clearInterval(id);
  }, [poll, loadConfig, status.transitional]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [logs]);

  const label = formatProxyStateLabel(status);
  const busy =
    start.running ||
    stop.running ||
    restart.running ||
    kill.running ||
    forceKill.running ||
    status.transitional;
  const state = (status.state || "stopped").toLowerCase();
  // Match header smart rules: only valid lifecycle actions per runtime state.
  const canStart = !status.running && !status.transitional && state === "stopped";
  const canStop = status.running || state === "starting" || state === "running";
  const canRestart = status.running && !status.transitional && state === "running";

  const afterLifecycle = async (action: () => Promise<unknown>) => {
    await action();
    await poll();
    await refreshStatus();
  };

  const afterConfig = async (action: () => Promise<unknown>) => {
    await action();
    await loadConfig();
    // Core may auto-restart; refresh runtime so the header catches it.
    await poll();
    await refreshStatus();
  };

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Proxy</h1>

      <p className="text-xs text-base-content/50 mb-4 max-w-3xl">
        Lifecycle and configuration are owned by Talos core. This page requests
        start / stop / restart / kill and observes runtime state (including
        automatic restarts after proxy-relevant config changes). Use{" "}
        <span className="mono">Kill</span> when the listen port is stuck after a
        bad stop; <span className="mono">Force kill</span> if a non-mitmdump
        process holds the port. The Control Panel does not decide when a restart
        is required.
      </p>

      {selected && !selected.active && (
        <div className="alert alert-warning mb-4 text-sm">
          <span>
            This project isn't the active one in Talos. Open it from the Projects
            page (or the header's project pill) before starting the proxy.
          </span>
        </div>
      )}

      {status.last_error && (
        <div className="alert alert-error mb-4 text-sm">
          <span className="mono">{status.last_error}</span>
        </div>
      )}

      <div className="panel p-4 mb-4 flex items-end gap-4 flex-wrap">
        <label className="form-control">
          <span className="label-text text-xs">Listen host</span>
          <input
            className="input input-sm input-bordered mono"
            value={listenHost}
            onChange={(e) => setListenHost(e.target.value)}
            disabled={!canStart || busy}
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Port</span>
          <input
            type="number"
            className="input input-sm input-bordered mono w-28"
            value={port}
            onChange={(e) => setPort(Number(e.target.value))}
            disabled={!canStart || busy}
          />
        </label>

        <button
          className="btn btn-sm btn-primary"
          disabled={!canStart || busy || start.running}
          onClick={() => afterLifecycle(() => start.run())}
        >
          {start.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Start"
          )}
        </button>
        <button
          className="btn btn-sm btn-error"
          disabled={!canStop || stop.running}
          onClick={() => afterLifecycle(() => stop.run())}
        >
          {stop.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Stop"
          )}
        </button>
        <button
          className="btn btn-sm"
          disabled={!canRestart || busy || restart.running}
          onClick={() => afterLifecycle(() => restart.run())}
        >
          {restart.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Restart"
          )}
        </button>
        <button
          className="btn btn-sm btn-outline"
          disabled={busy || kill.running}
          onClick={() => afterLifecycle(() => kill.run())}
        >
          {kill.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Kill"
          )}
        </button>
        <button
          className="btn btn-sm btn-outline btn-error"
          disabled={busy || forceKill.running}
          onClick={() => {
            const ok = window.confirm(
              `Force-kill any process on ${listenHost}:${port}?\n\nThis kills non-mitmdump listeners too.`
            );
            if (!ok) return;
            void afterLifecycle(() => forceKill.run());
          }}
        >
          {forceKill.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Force kill"
          )}
        </button>

        <div className="ml-auto flex flex-col items-end gap-1">
          <div className="flex items-center gap-2">
            <span
              className={`badge ${
                status.running
                  ? "badge-success"
                  : status.transitional
                    ? "badge-warning"
                    : status.last_error
                      ? "badge-error"
                      : "badge-ghost"
              }`}
            >
              {label}
            </span>
            {status.pid != null && (
              <span className="text-xs text-base-content/50 mono">pid {status.pid}</span>
            )}
          </div>
          {status.restart_pending && (
            <span className="badge badge-warning badge-xs">restart pending</span>
          )}
        </div>
      </div>

      {selected && (
        <div className="panel p-4 mb-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-xs uppercase tracking-wide text-base-content/50 mb-1">
                HTTP Manipulation
              </div>
              <p className="text-xs text-base-content/50 max-w-xl mb-3">
                Every proxied request and response passes through the HTTP
                Manipulation Engine before capture. Rules live under Capture →
                HTTP Rules.
              </p>
              <dl className="grid grid-cols-[5.5rem_1fr] gap-y-1 text-sm">
                <dt className="text-base-content/50">Engine</dt>
                <dd>
                  <span
                    className={`badge badge-sm ${
                      httpRules == null
                        ? "badge-ghost"
                        : httpRules.enabled
                          ? "badge-success"
                          : "badge-error"
                    }`}
                  >
                    {httpRules == null
                      ? "…"
                      : httpRules.enabled
                        ? "Enabled"
                        : "Disabled"}
                  </span>
                </dd>
                <dt className="text-base-content/50">Rules</dt>
                <dd className="mono">{httpRules?.active ?? "—"}</dd>
                <dt className="text-base-content/50">Request</dt>
                <dd className="mono text-info">{httpRules?.request ?? "—"}</dd>
                <dt className="text-base-content/50">Response</dt>
                <dd className="mono text-success">{httpRules?.response ?? "—"}</dd>
              </dl>
            </div>
            <Link className="btn btn-sm btn-outline" to="/mutations">
              Open HTTP Rules
            </Link>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="panel p-4">
          <div className="text-xs uppercase tracking-wide text-base-content/50 mb-3">
            Runtime
          </div>
          <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5 text-sm">
            <dt className="text-base-content/50">State</dt>
            <dd className="mono">{status.state}</dd>
            <dt className="text-base-content/50">Project</dt>
            <dd className="mono truncate">{status.project_id || "—"}</dd>
            <dt className="text-base-content/50">Role / module</dt>
            <dd className="mono truncate">
              {status.role_id || "—"} / {status.module_id || "—"}
            </dd>
            <dt className="text-base-content/50">Listen</dt>
            <dd className="mono">
              {status.listen_host != null && status.listen_port != null
                ? `${status.listen_host}:${status.listen_port}`
                : "—"}
            </dd>
            <dt className="text-base-content/50">Upstream</dt>
            <dd className="mono truncate">{status.upstream_url || "direct"}</dd>
            <dt className="text-base-content/50">Started</dt>
            <dd className="mono">{status.startup_time || "—"}</dd>
            <dt className="text-base-content/50">Applied gen</dt>
            <dd className="mono">
              {status.applied_generation != null ? status.applied_generation : "—"}
              {status.applied_project_id ? ` (${status.applied_project_id})` : ""}
            </dd>
            {status.validation_deferred && (
              <>
                <dt className="text-base-content/50">Validation</dt>
                <dd className="text-warning text-xs">deferred (lifecycle lock busy)</dd>
              </>
            )}
          </dl>
        </div>

        <div className="panel p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs uppercase tracking-wide text-base-content/50">
              Configuration (Talos)
            </div>
            <Link
              className="link link-primary text-xs"
              to="/talos-config?tab=settings&section=proxy"
            >
              Full config →
            </Link>
          </div>
          <p className="text-xs text-base-content/50 mb-3">
            Layered effective proxy mode (<span className="mono">proxy.upstream.*</span>).
            Contextual editor below dual-writes via Talos CLI. Changes may trigger an automatic
            restart when the proxy is running.
          </p>
          <dl className="grid grid-cols-[7rem_1fr] gap-y-1.5 text-sm mb-3">
            <dt className="text-base-content/50">Mode</dt>
            <dd className="font-medium">
              {layered
                ? layered.mode === "upstream"
                  ? "Upstream"
                  : "Direct"
                : config
                  ? config.mode === "upstream"
                    ? "Upstream"
                    : "Direct"
                  : "—"}
            </dd>
            <dt className="text-base-content/50">Upstream URL</dt>
            <dd className="mono truncate">
              {layered?.upstream_url != null
                ? String(layered.upstream_url)
                : config?.upstream_url || "null"}
            </dd>
            <dt className="text-base-content/50">Source</dt>
            <dd>
              <span className="badge badge-sm badge-ghost uppercase">
                {layered?.source || "—"}
              </span>
            </dd>
          </dl>
          <label className="form-control mb-2">
            <span className="label-text text-xs">Upstream URL</span>
            <input
              className="input input-sm input-bordered mono"
              value={upstreamInput}
              onChange={(e) => setUpstreamInput(e.target.value)}
              placeholder="http://127.0.0.1:8081"
              disabled={setUpstream.running || setDirect.running}
            />
          </label>
          <div className="flex gap-2 flex-wrap">
            <button
              className="btn btn-sm btn-primary"
              disabled={!upstreamInput.trim() || setUpstream.running}
              onClick={() => afterConfig(() => setUpstream.run())}
            >
              {setUpstream.running ? (
                <span className="loading loading-spinner loading-xs" />
              ) : (
                "Set upstream"
              )}
            </button>
            <button
              className="btn btn-sm"
              disabled={setDirect.running}
              onClick={() => afterConfig(() => setDirect.run())}
            >
              {setDirect.running ? (
                <span className="loading loading-spinner loading-xs" />
              ) : (
                "Use direct"
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="panel p-3">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs uppercase tracking-wide text-base-content/50">
            Live log
            {logPath && (
              <span className="ml-2 normal-case tracking-normal mono text-base-content/40">
                {logPath}
              </span>
            )}
          </div>
          <button
            className="btn btn-xs"
            disabled={logs.length === 0}
            onClick={() => {
              navigator.clipboard.writeText(logs.join("\n"));
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? "Copied!" : "Copy log"}
          </button>
        </div>
        <div
          ref={logRef}
          className="mono text-xs h-96 overflow-y-auto whitespace-pre-wrap bg-base-300/40 rounded p-3"
        >
          {logs.length === 0 ? (
            <span className="text-base-content/40">No output yet.</span>
          ) : (
            logs.join("\n")
          )}
        </div>
      </div>
    </div>
  );
}
