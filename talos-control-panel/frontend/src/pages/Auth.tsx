/**
 * Auth workspace — capability parity with Talos auth + auth-config CLI.
 *
 * Model (not a setup wizard):
 *   Artifact definition → provider → credential acquisition → active auth
 *   state → session health → validation → recovery.
 *
 * Sections:
 *   1. Authentication Artifacts (project-wide names)
 *   2. Role Authentication (AUTO login flows / MANUAL session UI)
 *   3. Session Health (TTL for AUTO, refresh-before, signals, suspicion)
 *   4. Validation Flows (control flows + per-flow validate)
 *   5. Runtime and Recovery
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import {
  ConfirmButton,
  FieldHint,
  Modal,
  ModuleHelp,
  NoProjectNotice,
  Section,
  UuidChip,
} from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import { Role, StepsResponse } from "../types";

// ── Types ────────────────────────────────────────────────────────────

interface AuthArtifact {
  type: string;
  name: string;
}

interface LoginFlow {
  id: string;
  flow_id: string;
  has_extractor: number;
  sort_order: number;
  method?: string | null;
  path?: string | null;
  host?: string | null;
  status_code?: number | null;
  url?: string | null;
}

interface ControlFlow {
  flow_id: string;
  method?: string | null;
  path?: string | null;
  host?: string | null;
  status_code?: number | null;
  url?: string | null;
}

interface HealthConfig {
  ttl_seconds: number;
  refresh_before_seconds: number;
  expiry_body_signals: string[];
  expiry_status_codes: number[];
  expiry_header_signals: Record<string, string[]>;
  has_row?: boolean;
}

interface ManualSession {
  headers: Record<string, string>;
  cookies: Record<string, string>;
  expires_at: string | null;
  ttl_seconds: number | null;
  created_at?: string | null;
  updated_at?: string | null;
  expires_in_seconds?: number | null;
  expiry_iso?: string | null;
}

interface RoleAuthState {
  provider: { provider: string; updated_at: string } | null;
  artifacts: { key: string; value: string; collected_at: string }[];
  manual_session: ManualSession | null;
  flows: LoginFlow[];
  health: HealthConfig;
  control_flows: ControlFlow[];
  suspicion: { suspicion_count: number; last_checked_at: string | null } | null;
  session_state: string;
  session_age_seconds: number | null;
  expires_in_seconds: number | null;
  collected_at: string | null;
  suspicion_threshold: number;
  health_degraded: boolean;
}

interface KvRow {
  id: string;
  name: string;
  value: string;
}

interface ExtractorPayload {
  flow_id: string;
  role_id: string;
  code: string;
  configured: boolean;
}

const EXTRACTOR_TEMPLATE = `def extract(response):
    """Return artifact name → value from the login response.

    response.status   — HTTP status (int)
    response.headers  — dict (lowercase keys)
    response.body     — decoded body text
    response.cookies  — cookie dict
    """
    # Example: cookie session token
    # return {"sessionid": response.cookies.get("sessionid", "")}
    return {}
`;

function newRow(name = "", value = ""): KvRow {
  return { id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, name, value };
}

function dictToRows(d: Record<string, string> | null | undefined): KvRow[] {
  const entries = Object.entries(d || {});
  if (!entries.length) return [newRow()];
  return entries.map(([name, value]) => newRow(name, value));
}

function rowsToDict(rows: KvRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const k = r.name.trim();
    if (!k) continue;
    out[k] = r.value;
  }
  return out;
}

// ── Small presentational helpers ─────────────────────────────────────

function StatePill({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string;
  tone?: "neutral" | "ok" | "warn" | "bad" | "info";
}) {
  const toneCls =
    tone === "ok"
      ? "badge-success"
      : tone === "warn"
        ? "badge-warning"
        : tone === "bad"
          ? "badge-error"
          : tone === "info"
            ? "badge-info"
            : "badge-ghost";
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span className="text-base-content/45 uppercase tracking-wide">{label}</span>
      <span className={`badge badge-sm ${toneCls}`}>{value}</span>
    </div>
  );
}

function sessionTone(state: string | undefined): "ok" | "warn" | "bad" | "neutral" {
  if (!state) return "neutral";
  if (state === "READY") return "ok";
  if (state === "EXPIRING") return "warn";
  if (state === "EXPIRED" || state === "FAILED") return "bad";
  return "neutral";
}

function formatSeconds(sec: number | null | undefined): string {
  if (sec == null || Number.isNaN(sec)) return "—";
  const abs = Math.abs(sec);
  if (abs < 60) return `${sec}s`;
  if (abs < 3600) {
    const m = Math.trunc(sec / 60);
    const s = Math.abs(sec % 60);
    return `${m}m ${s}s`;
  }
  const h = Math.trunc(sec / 3600);
  const m = Math.floor((Math.abs(sec) % 3600) / 60);
  return `${sec < 0 ? "-" : ""}${Math.abs(h)}h ${m}m`;
}

function flowLabel(f: { method?: string | null; path?: string | null; flow_id: string }) {
  if (f.method && f.path) return `${f.method} ${f.path}`;
  return f.flow_id.slice(0, 8) + "…";
}

function parseTestArtifacts(steps: StepsResponse["steps"] | undefined): Record<string, string> | null {
  if (!steps?.length) return null;
  for (let i = steps.length - 1; i >= 0; i--) {
    const s = steps[i];
    if (!s.ok || !s.stdout?.trim()) continue;
    try {
      const data = JSON.parse(s.stdout);
      if (data && typeof data === "object" && data.artifacts && typeof data.artifacts === "object") {
        return data.artifacts as Record<string, string>;
      }
    } catch {
      /* table stdout */
    }
  }
  return null;
}

function ArtifactValue({ value }: { value: string }) {
  const [open, setOpen] = useState(false);
  const long = value.length > 48;
  return (
    <div className="flex items-start gap-2 min-w-0">
      <code className="mono text-xs break-all whitespace-pre-wrap flex-1">
        {open || !long ? value : `${value.slice(0, 48)}…`}
      </code>
      <div className="flex gap-1 shrink-0">
        {long && (
          <button type="button" className="btn btn-ghost btn-xs" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide" : "Full"}
          </button>
        )}
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => navigator.clipboard.writeText(value)}
        >
          Copy
        </button>
      </div>
    </div>
  );
}

function KvEditor({
  title,
  rows,
  onChange,
  namePlaceholder,
  valuePlaceholder,
}: {
  title: string;
  rows: KvRow[];
  onChange: (rows: KvRow[]) => void;
  namePlaceholder: string;
  valuePlaceholder: string;
}) {
  return (
    <div className="panel p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[11px] uppercase tracking-wide text-base-content/45">{title}</div>
        <button type="button" className="btn btn-ghost btn-xs" onClick={() => onChange([...rows, newRow()])}>
          + Add
        </button>
      </div>
      <div className="space-y-2">
        {rows.map((row, idx) => (
          <div key={row.id} className="flex gap-2 items-start">
            <input
              className="input input-xs input-bordered mono w-36 shrink-0"
              placeholder={namePlaceholder}
              value={row.name}
              onChange={(e) => {
                const next = [...rows];
                next[idx] = { ...row, name: e.target.value };
                onChange(next);
              }}
            />
            <input
              className="input input-xs input-bordered mono flex-1 min-w-0"
              placeholder={valuePlaceholder}
              value={row.value}
              onChange={(e) => {
                const next = [...rows];
                next[idx] = { ...row, value: e.target.value };
                onChange(next);
              }}
            />
            <button
              type="button"
              className="btn btn-ghost btn-xs text-error shrink-0"
              disabled={rows.length <= 1}
              onClick={() => onChange(rows.filter((r) => r.id !== row.id))}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────

export default function Auth() {
  const { selected } = useProject();

  const [artifacts, setArtifacts] = useState<AuthArtifact[]>([]);
  const [cookieInput, setCookieInput] = useState("");
  const [headerInput, setHeaderInput] = useState("");

  const [roles, setRoles] = useState<Role[]>([]);
  const [roleId, setRoleId] = useState("");
  const [roleState, setRoleState] = useState<RoleAuthState | null>(null);
  const [stateLoading, setStateLoading] = useState(false);

  const [loginFlowId, setLoginFlowId] = useState("");

  // MANUAL structured session (primary)
  const [headerRows, setHeaderRows] = useState<KvRow[]>([newRow()]);
  const [cookieRows, setCookieRows] = useState<KvRow[]>([newRow()]);
  const [expiryMode, setExpiryMode] = useState<"absolute" | "ttl">("ttl");
  const [expiresAtInput, setExpiresAtInput] = useState("");
  const [sessionTtlInput, setSessionTtlInput] = useState("3600");
  const [sessionPath, setSessionPath] = useState("");
  const [sessionContent, setSessionContent] = useState("");
  const [showRawFile, setShowRawFile] = useState(false);
  const [sessionHydrated, setSessionHydrated] = useState(false);

  const [ttlInput, setTtlInput] = useState("1200");
  const [refreshBeforeInput, setRefreshBeforeInput] = useState("120");
  const [signalKind, setSignalKind] = useState<"status" | "body" | "header">("status");
  const [signalStatus, setSignalStatus] = useState("401");
  const [signalBody, setSignalBody] = useState("");
  const [signalHeaderName, setSignalHeaderName] = useState("");
  const [signalHeaderValue, setSignalHeaderValue] = useState("");

  const [controlFlowId, setControlFlowId] = useState("");

  const [extractorOpen, setExtractorOpen] = useState(false);
  const [extractorFlowId, setExtractorFlowId] = useState("");
  const [extractorCode, setExtractorCode] = useState("");
  const [extractorConfigured, setExtractorConfigured] = useState(false);
  const [testArtifacts, setTestArtifacts] = useState<Record<string, string> | null>(null);
  const [testStdout, setTestStdout] = useState("");

  const projectId = selected?.id;

  const hydrateManualForm = useCallback((session: ManualSession | null | undefined, path?: string) => {
    if (path) setSessionPath(path);
    if (!session) {
      setHeaderRows([newRow()]);
      setCookieRows([newRow()]);
      setExpiryMode("ttl");
      setExpiresAtInput("");
      setSessionTtlInput("3600");
      setSessionHydrated(true);
      return;
    }
    setHeaderRows(dictToRows(session.headers));
    setCookieRows(dictToRows(session.cookies));
    if (session.expires_at) {
      setExpiryMode("absolute");
      setExpiresAtInput(session.expires_at);
      setSessionTtlInput(session.ttl_seconds != null ? String(session.ttl_seconds) : "3600");
    } else {
      setExpiryMode("ttl");
      setExpiresAtInput("");
      setSessionTtlInput(session.ttl_seconds != null ? String(session.ttl_seconds) : "3600");
    }
    setSessionHydrated(true);
  }, []);

  const loadArtifacts = useCallback(() => {
    if (!projectId) return;
    return api
      .get<{ artifacts: AuthArtifact[] }>("/api/auth", { project_id: projectId })
      .then((r) => setArtifacts(r.artifacts));
  }, [projectId]);

  const loadRoles = useCallback(() => {
    if (!projectId) return;
    return api.get<{ roles: Role[] }>("/api/roles", { project_id: projectId }).then((r) => {
      setRoles(r.roles);
      setRoleId((prev) => {
        if (prev && r.roles.some((x) => x.id === prev)) return prev;
        return r.roles[0]?.id || "";
      });
    });
  }, [projectId]);

  const loadRoleState = useCallback(async () => {
    if (!projectId || !roleId) {
      setRoleState(null);
      return;
    }
    setStateLoading(true);
    try {
      const s = await api.get<RoleAuthState>(`/api/auth-config/${roleId}/state`, {
        project_id: projectId,
      });
      setRoleState(s);
      if (s.health) {
        setTtlInput(String(s.health.ttl_seconds ?? 1200));
        setRefreshBeforeInput(String(s.health.refresh_before_seconds ?? 120));
      }
      // Keep form in sync when state already has applied manual session.
      if (s.provider?.provider === "manual" && s.manual_session) {
        hydrateManualForm(s.manual_session);
      }
    } finally {
      setStateLoading(false);
    }
  }, [projectId, roleId, hydrateManualForm]);

  const loadStructuredSession = useCallback(async () => {
    if (!projectId || !roleId) return;
    const r = await api.get<{
      path: string;
      content: string;
      session: ManualSession;
      steps: StepsResponse["steps"];
    }>(`/api/auth-config/${roleId}/session`, { project_id: projectId });
    setSessionPath(r.path);
    setSessionContent(r.content);
    hydrateManualForm(r.session, r.path);
    return { steps: r.steps };
  }, [projectId, roleId, hydrateManualForm]);

  useEffect(() => {
    loadArtifacts();
    loadRoles();
  }, [loadArtifacts, loadRoles]);

  useEffect(() => {
    loadRoleState();
    setSessionHydrated(false);
    setShowRawFile(false);
    setSessionContent("");
    setSessionPath("");
    setTestArtifacts(null);
    setTestStdout("");
  }, [loadRoleState]);

  // Auto-load structured manual session when provider is MANUAL.
  useEffect(() => {
    if (!projectId || !roleId) return;
    if (roleState?.provider?.provider !== "manual") return;
    if (sessionHydrated) return;
    loadStructuredSession().catch(() => {
      /* path create may fail if role missing; form stays empty */
    });
  }, [projectId, roleId, roleState?.provider?.provider, sessionHydrated, loadStructuredSession]);

  // ── Mutations ──────────────────────────────────────────────────────

  const setAuth = useAction("Set auth artifacts", () =>
    api.post(
      "/api/auth/set",
      {
        cookies: cookieInput.trim() ? [cookieInput.trim()] : [],
        headers: headerInput.trim() ? [headerInput.trim()] : [],
      },
      { project_id: projectId! }
    )
  );
  const unsetAuth = useAction(
    "Remove auth artifact",
    (body: { cookies: string[]; headers: string[] }) =>
      api.post("/api/auth/unset", body, { project_id: projectId! })
  );
  const clearAuth = useAction("Clear auth artifacts", () =>
    api.post("/api/auth/clear", {}, { project_id: projectId! })
  );

  const setProvider = useAction("Set auth provider", (p: string) =>
    api.post(`/api/auth-config/${roleId}/provider`, { provider: p }, { project_id: projectId! })
  );
  const addFlow = useAction("Attach login flow", (fid: string) =>
    api.post(`/api/auth-config/${roleId}/flows/${fid}`, {}, { project_id: projectId! })
  );
  const removeFlow = useAction("Remove login flow", (fid: string) =>
    api.del(`/api/auth-config/${roleId}/flows/${fid}`, { project_id: projectId! })
  );
  const saveExtractor = useAction("Save extractor", (fid: string, code: string) =>
    api.post(
      `/api/auth-config/${roleId}/flows/${fid}/extractor`,
      { code },
      { project_id: projectId! }
    )
  );
  const removeExtractor = useAction("Remove extractor", (fid: string) =>
    api.del(`/api/auth-config/${roleId}/flows/${fid}/extractor`, { project_id: projectId! })
  );
  const testFlow = useAction("Test flow + extractor", (fid: string) =>
    api.post(`/api/auth-config/${roleId}/test/${fid}`, {}, { project_id: projectId! })
  );
  const validateAuth = useAction("Validate session", (flowId?: string) =>
    api.post(
      `/api/auth-config/${roleId}/validate`,
      flowId ? { flow_id: flowId } : {},
      { project_id: projectId! }
    )
  );
  const refreshAuth = useAction("Refresh auth state", () =>
    api.post(`/api/auth-config/${roleId}/refresh`, {}, { project_id: projectId! })
  );
  const resetHealth = useAction("Reset health suspicion", () =>
    api.post(`/api/auth-config/${roleId}/reset-health`, {}, { project_id: projectId! })
  );
  const clearSession = useAction("Clear manual session", () =>
    api.post(`/api/auth-config/${roleId}/session/clear`, {}, { project_id: projectId! })
  );
  const setTtl = useAction("Save TTL policy", (ttl: number, refresh_before: number) =>
    api.post(
      `/api/auth-config/${roleId}/ttl`,
      { ttl, refresh_before },
      { project_id: projectId! }
    )
  );
  const setRefreshBeforeOnly = useAction("Save refresh-before", (refresh_before: number) =>
    // Core set-ttl requires --ttl; keep existing AUTO TTL when only adjusting warn window.
    api.post(
      `/api/auth-config/${roleId}/ttl`,
      {
        ttl: Number(roleState?.health?.ttl_seconds ?? ttlInput) || 1200,
        refresh_before,
      },
      { project_id: projectId! }
    )
  );
  const addExpirySignal = useAction(
    "Add expiry signal",
    (body: {
      body_signals: string[];
      status_codes: number[];
      header_signals: { name: string; value: string }[];
    }) => api.post(`/api/auth-config/${roleId}/expiry-signals`, body, { project_id: projectId! })
  );
  const clearExpirySignals = useAction("Clear expiry signals", () =>
    api.del(`/api/auth-config/${roleId}/expiry-signals`, { project_id: projectId! })
  );
  const addControlFlow = useAction("Add validation flow", (fid: string) =>
    api.post(`/api/auth-config/${roleId}/control-flows/${fid}`, {}, { project_id: projectId! })
  );
  const removeControlFlow = useAction("Remove validation flow", (fid: string) =>
    api.del(`/api/auth-config/${roleId}/control-flows/${fid}`, { project_id: projectId! })
  );

  const saveStructuredSession = useAction(
    "Save manual session",
    (payload: {
      headers: Record<string, string>;
      cookies: Record<string, string>;
      expires_at: string | null;
      ttl_seconds: number | null;
      apply: boolean;
    }) => api.post(`/api/auth-config/${roleId}/session`, payload, { project_id: projectId! })
  );
  const saveSessionFile = useAction("Save session file", (content: string) =>
    api.post(
      `/api/auth-config/${roleId}/session/file`,
      { content },
      { project_id: projectId! }
    )
  );
  const applySession = useAction("Apply manual session", () =>
    api.post(`/api/auth-config/${roleId}/session/apply`, {}, { project_id: projectId! })
  );
  const loadSessionAction = useAction("Load session", async () => {
    const r = await loadStructuredSession();
    return { steps: r?.steps || [] };
  });

  const role = roles.find((r) => r.id === roleId);
  const provider = roleState?.provider?.provider || null;
  const sessionState = roleState?.session_state || "—";
  const suspicionCount = roleState?.suspicion?.suspicion_count ?? 0;
  const suspicionThreshold = roleState?.suspicion_threshold ?? 3;

  const cookies = useMemo(
    () => artifacts.filter((a) => a.type === "cookie"),
    [artifacts]
  );
  const headers = useMemo(
    () => artifacts.filter((a) => a.type === "header"),
    [artifacts]
  );

  const expiryRows = useMemo(() => {
    const health = roleState?.health;
    if (!health) return [] as { kind: string; label: string }[];
    const rows: { kind: string; label: string }[] = [];
    for (const code of health.expiry_status_codes || []) {
      rows.push({ kind: "STATUS", label: `STATUS ${code}` });
    }
    for (const body of health.expiry_body_signals || []) {
      rows.push({ kind: "BODY", label: `BODY ${JSON.stringify(body)}` });
    }
    for (const [name, values] of Object.entries(health.expiry_header_signals || {})) {
      for (const v of values || []) {
        rows.push({ kind: "HEADER", label: `HEADER ${name} → ${v}` });
      }
    }
    return rows;
  }, [roleState?.health]);

  function buildSessionPayload(apply: boolean) {
    const h = rowsToDict(headerRows);
    const c = rowsToDict(cookieRows);
    const expires_at =
      expiryMode === "absolute" && expiresAtInput.trim() ? expiresAtInput.trim() : null;
    let ttl_seconds: number | null = null;
    if (expiryMode === "ttl") {
      const n = Number(sessionTtlInput);
      ttl_seconds = Number.isFinite(n) && n > 0 ? n : null;
    }
    return { headers: h, cookies: c, expires_at, ttl_seconds, apply };
  }

  async function openExtractor(flowId: string) {
    if (!projectId || !roleId) return;
    setExtractorFlowId(flowId);
    setTestArtifacts(null);
    setTestStdout("");
    setExtractorOpen(true);
    const data = await api.get<ExtractorPayload>(
      `/api/auth-config/${roleId}/flows/${flowId}/extractor`,
      { project_id: projectId }
    );
    setExtractorCode(data.code || EXTRACTOR_TEMPLATE);
    setExtractorConfigured(data.configured);
  }

  async function runExtractorTest() {
    if (!extractorFlowId) return;
    const result = await testFlow.run(extractorFlowId);
    setTestArtifacts(parseTestArtifacts(result?.steps));
    const last = [...(result?.steps || [])].reverse().find((s) => s.stdout?.trim());
    setTestStdout(last?.stdout || "");
    await loadRoleState();
  }

  if (!selected) return <NoProjectNotice />;

  return (
    <div className="pb-10">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
        <div>
          <h1 className="text-xl font-semibold">Auth</h1>
          <p className="text-xs text-base-content/50 mt-0.5 max-w-2xl">
            Configure what authentication means for this project, how each role acquires
            credentials, and how Talos keeps sessions healthy and validated.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="form-control">
            <span className="label-text text-[10px] text-base-content/45">Role</span>
            <select
              className="select select-sm select-bordered min-w-[10rem]"
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              disabled={roles.length === 0}
            >
              {roles.length === 0 && <option value="">No roles</option>}
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="btn btn-sm btn-ghost mt-4"
            disabled={!roleId || stateLoading}
            onClick={() => loadRoleState()}
          >
            {stateLoading ? <span className="loading loading-spinner loading-xs" /> : "Reload"}
          </button>
        </div>
      </div>

      <div className="mb-4">
        <ModuleHelp title="How Auth works">
          <p>
            Talos models authentication as a pipeline: declare artifact{" "}
            <strong className="text-base-content/70">names</strong>, choose a per-role{" "}
            <strong className="text-base-content/70">provider</strong> (AUTO or MANUAL), acquire
            credentials, then keep the session healthy through TTL (AUTO), session expiry (MANUAL),
            expiry signals, and validation control flows.
          </p>
          <p>
            <strong className="text-base-content/70">AUTO</strong> replays login flows and runs a
            Python extractor. <strong className="text-base-content/70">MANUAL</strong> uses a
            structured session (headers/cookies + expiry) that Talos stores in the role session
            file — UI is preferred; raw file edit remains available.
          </p>
          <p>
            Session Health <span className="mono">TTL</span> applies to{" "}
            <strong className="text-base-content/70">AUTO</strong> credential lifetime. MANUAL
            lifetime comes from the session&apos;s <span className="mono">expires_at</span> or{" "}
            <span className="mono">ttl_seconds</span>.{" "}
            <span className="mono">refresh_before</span> still applies to both (when to treat the
            session as needing refresh).
          </p>
          <p>
            Runtime actions stay separate: <span className="mono">test</span> (login
            flow+extractor), <span className="mono">validate</span> (control flow baseline),{" "}
            <span className="mono">refresh</span> (re-acquire / re-apply credentials).
          </p>
          <p>
            <strong className="text-base-content/70">NTLM / IIS Persistent-Auth</strong> is
            not a cookie or Authorization header. After the handshake, captures look
            unauthenticated. Configure platform authentication on the Proxy page
            instead — IV uses that session; Unauth and auth-test send without it.
          </p>
        </ModuleHelp>
      </div>

      {roles.length === 0 ? (
        <div className="panel p-6 text-sm text-base-content/60">
          Create a role on the Roles &amp; Modules page before configuring per-role auth.
        </div>
      ) : (
        <div className="panel px-4 py-3 mb-5 sticky top-0 z-10 bg-base-100/95 backdrop-blur border-base-300">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <span className="text-sm font-medium">{role?.name || "Role"}</span>
            <StatePill
              label="Provider"
              value={(provider || "unset").toUpperCase()}
              tone={provider ? "info" : "neutral"}
            />
            <StatePill label="Session" value={sessionState} tone={sessionTone(sessionState)} />
            <StatePill
              label="Artifacts"
              value={String(roleState?.artifacts?.length ?? 0)}
              tone={(roleState?.artifacts?.length ?? 0) > 0 ? "ok" : "neutral"}
            />
            <StatePill
              label="Validation flows"
              value={String(roleState?.control_flows?.length ?? 0)}
              tone={(roleState?.control_flows?.length ?? 0) > 0 ? "ok" : "warn"}
            />
            <StatePill
              label="Health"
              value={
                roleState?.health_degraded
                  ? "DEGRADED"
                  : suspicionCount > 0
                    ? `SUSPICION ${suspicionCount}/${suspicionThreshold}`
                    : "HEALTHY"
              }
              tone={
                roleState?.health_degraded ? "bad" : suspicionCount > 0 ? "warn" : "ok"
              }
            />
            <span className="text-[11px] text-base-content/40 mono ml-auto">
              age {formatSeconds(roleState?.session_age_seconds)} · expires{" "}
              {roleState?.expires_in_seconds != null
                ? roleState.expires_in_seconds < 0
                  ? `${formatSeconds(roleState.expires_in_seconds)} ago`
                  : `in ${formatSeconds(roleState.expires_in_seconds)}`
                : "—"}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_22rem] gap-5 items-start">
        <div className="flex flex-col gap-6 min-w-0">
          {/* ═══ 1. Artifacts ═══ */}
          <Section title="1. Authentication Artifacts">
            <p className="text-xs text-base-content/55 mb-3">
              Artifact names tell Talos which headers and cookies represent authentication.
              Values are acquired per role through AUTO or MANUAL — only{" "}
              <strong className="font-medium text-base-content/70">names</strong> are stored here.
              Skip this section for NTLM / Windows Integrated Auth: there is no header
              to name. Use Proxy → platform authentication, then run IV or Unauth.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
              <div className="panel p-3">
                <div className="text-[11px] uppercase tracking-wide text-base-content/45 mb-2">
                  Cookies
                </div>
                {cookies.length === 0 ? (
                  <div className="text-sm text-base-content/40">None</div>
                ) : (
                  <ul className="space-y-1">
                    {cookies.map((a) => (
                      <li key={`c-${a.name}`} className="flex items-center justify-between gap-2">
                        <span className="mono text-sm">{a.name}</span>
                        <button
                          type="button"
                          className="btn btn-ghost btn-xs text-error"
                          onClick={async () => {
                            await unsetAuth.run({ cookies: [a.name], headers: [] });
                            await loadArtifacts();
                          }}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="panel p-3">
                <div className="text-[11px] uppercase tracking-wide text-base-content/45 mb-2">
                  Headers
                </div>
                {headers.length === 0 ? (
                  <div className="text-sm text-base-content/40">None</div>
                ) : (
                  <ul className="space-y-1">
                    {headers.map((a) => (
                      <li key={`h-${a.name}`} className="flex items-center justify-between gap-2">
                        <span className="mono text-sm">{a.name}</span>
                        <button
                          type="button"
                          className="btn btn-ghost btn-xs text-error"
                          onClick={async () => {
                            await unsetAuth.run({ cookies: [], headers: [a.name] });
                            await loadArtifacts();
                          }}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
            <div className="flex flex-wrap gap-2 items-end">
              <label className="form-control">
                <span className="label-text text-xs">Cookie name</span>
                <input
                  className="input input-sm input-bordered mono"
                  value={cookieInput}
                  onChange={(e) => setCookieInput(e.target.value)}
                  placeholder="sessionid"
                />
              </label>
              <label className="form-control">
                <span className="label-text text-xs">Header name</span>
                <input
                  className="input input-sm input-bordered mono"
                  value={headerInput}
                  onChange={(e) => setHeaderInput(e.target.value)}
                  placeholder="Authorization"
                />
              </label>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={(!cookieInput.trim() && !headerInput.trim()) || setAuth.running}
                onClick={async () => {
                  await setAuth.run();
                  setCookieInput("");
                  setHeaderInput("");
                  await loadArtifacts();
                }}
              >
                Add
              </button>
              <ConfirmButton
                className="btn btn-sm btn-ghost text-error"
                confirmText="Clear all artifact names?"
                onConfirm={async () => {
                  await clearAuth.run();
                  await loadArtifacts();
                }}
              >
                Clear all
              </ConfirmButton>
            </div>
          </Section>

          {/* ═══ 2. Role Authentication ═══ */}
          <Section title="2. Role Authentication">
            {!roleId ? (
              <p className="text-sm text-base-content/50">Select a role above.</p>
            ) : (
              <>
                <p className="text-xs text-base-content/55 mb-3">
                  <span className="font-medium text-base-content/70">AUTO</span> — replay login
                  flows and extract credentials.{" "}
                  <span className="font-medium text-base-content/70">MANUAL</span> — supply session
                  headers/cookies and expiry (any auth stack, including MFA/OAuth/SSO).
                </p>
                <div className="flex gap-2 mb-4">
                  <button
                    type="button"
                    className={`btn btn-sm ${provider === "auto" ? "btn-primary" : "btn-outline"}`}
                    disabled={setProvider.running}
                    onClick={async () => {
                      await setProvider.run("auto");
                      await loadRoleState();
                    }}
                  >
                    AUTO
                  </button>
                  <button
                    type="button"
                    className={`btn btn-sm ${provider === "manual" ? "btn-primary" : "btn-outline"}`}
                    disabled={setProvider.running}
                    onClick={async () => {
                      await setProvider.run("manual");
                      await loadRoleState();
                      await loadSessionAction.run();
                    }}
                  >
                    MANUAL
                  </button>
                  {!provider && (
                    <span className="text-xs text-warning self-center">Provider not set</span>
                  )}
                </div>

                {provider === "auto" && (
                  <div className="space-y-3">
                    <div className="text-sm font-medium">Login flows</div>
                    <p className="text-xs text-base-content/50">
                      Managed login requests for this role. Each needs an extractor that returns
                      artifact name → value.
                    </p>
                    {(roleState?.flows?.length || 0) === 0 ? (
                      <div className="text-sm text-base-content/40 panel p-3">
                        No login flows attached.
                      </div>
                    ) : (
                      <div className="panel overflow-x-auto">
                        <table className="table table-tight table-sm">
                          <thead>
                            <tr>
                              <th>Request</th>
                              <th>Flow</th>
                              <th>Extractor</th>
                              <th className="text-right">Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {roleState!.flows.map((f) => (
                              <tr key={f.id}>
                                <td className="mono text-xs">
                                  {f.method || "?"} {f.path || "(unknown path)"}
                                  {f.status_code != null && (
                                    <span className="text-base-content/40 ml-1">
                                      → {f.status_code}
                                    </span>
                                  )}
                                </td>
                                <td>
                                  <UuidChip value={f.flow_id} />
                                </td>
                                <td>
                                  <span
                                    className={`badge badge-xs ${
                                      f.has_extractor ? "badge-success" : "badge-warning"
                                    }`}
                                  >
                                    {f.has_extractor ? "CONFIGURED" : "MISSING"}
                                  </span>
                                </td>
                                <td className="text-right">
                                  <div className="flex flex-wrap gap-1 justify-end">
                                    <button
                                      type="button"
                                      className="btn btn-xs"
                                      onClick={() => openExtractor(f.flow_id)}
                                    >
                                      {f.has_extractor ? "Edit extractor" : "Set extractor"}
                                    </button>
                                    <button
                                      type="button"
                                      className="btn btn-xs"
                                      disabled={!f.has_extractor || testFlow.running}
                                      onClick={async () => {
                                        await openExtractor(f.flow_id);
                                        try {
                                          const result = await testFlow.run(f.flow_id);
                                          setTestArtifacts(parseTestArtifacts(result?.steps));
                                          const last = [...(result?.steps || [])]
                                            .reverse()
                                            .find((s) => s.stdout?.trim());
                                          setTestStdout(last?.stdout || "");
                                        } catch {
                                          /* logged */
                                        }
                                      }}
                                    >
                                      Test
                                    </button>
                                    <ConfirmButton
                                      className="btn btn-xs btn-ghost text-error"
                                      confirmText="Detach this login flow?"
                                      onConfirm={async () => {
                                        await removeFlow.run(f.flow_id);
                                        await loadRoleState();
                                      }}
                                    >
                                      Remove
                                    </ConfirmButton>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-2 items-end">
                      <label className="form-control flex-1 min-w-[14rem]">
                        <span className="label-text text-xs">Flow UUID</span>
                        <input
                          className="input input-sm input-bordered mono w-full"
                          value={loginFlowId}
                          onChange={(e) => setLoginFlowId(e.target.value.trim())}
                          placeholder="login flow uuid"
                        />
                      </label>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        disabled={!loginFlowId || addFlow.running}
                        onClick={async () => {
                          await addFlow.run(loginFlowId);
                          setLoginFlowId("");
                          await loadRoleState();
                        }}
                      >
                        Add login flow
                      </button>
                    </div>
                  </div>
                )}

                {provider === "manual" && (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-sm font-medium">Manual session</div>
                        <p className="text-xs text-base-content/50 mt-0.5 max-w-xl">
                          Prefer the structured editor. Values are written to the Talos session
                          file, then applied into <span className="mono">role_auth_state</span>{" "}
                          (requires project artifact names + validation flow). Raw file edit is
                          optional.
                        </p>
                      </div>
                      <div className="flex gap-2">
                        {!sessionHydrated && (
                          <button
                            type="button"
                            className="btn btn-sm"
                            disabled={loadSessionAction.running}
                            onClick={async () => {
                              await loadSessionAction.run();
                            }}
                          >
                            Load session
                          </button>
                        )}
                        <button
                          type="button"
                          className={`btn btn-sm ${showRawFile ? "btn-active" : "btn-ghost"}`}
                          onClick={async () => {
                            if (!sessionHydrated) await loadSessionAction.run();
                            setShowRawFile((v) => !v);
                          }}
                        >
                          {showRawFile ? "Hide raw file" : "Edit raw file"}
                        </button>
                      </div>
                    </div>

                    {roleState?.manual_session && (
                      <div className="flex flex-wrap gap-3 text-xs text-base-content/60 panel p-3">
                        <span>
                          Updated:{" "}
                          <span className="mono">
                            {roleState.manual_session.updated_at
                              ? formatIST(roleState.manual_session.updated_at)
                              : "—"}
                          </span>
                        </span>
                        <span>
                          Expires in:{" "}
                          <span className="mono">
                            {formatSeconds(
                              roleState.manual_session.expires_in_seconds ??
                                roleState.expires_in_seconds
                            )}
                          </span>
                        </span>
                        <span>
                          Session TTL:{" "}
                          <span className="mono">
                            {roleState.manual_session.ttl_seconds != null
                              ? `${roleState.manual_session.ttl_seconds}s`
                              : roleState.manual_session.expires_at || "—"}
                          </span>
                        </span>
                      </div>
                    )}

                    {sessionHydrated && (
                      <>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <KvEditor
                            title="Headers"
                            rows={headerRows}
                            onChange={setHeaderRows}
                            namePlaceholder="Authorization"
                            valuePlaceholder="Bearer …"
                          />
                          <KvEditor
                            title="Cookies"
                            rows={cookieRows}
                            onChange={setCookieRows}
                            namePlaceholder="sessionid"
                            valuePlaceholder="value"
                          />
                        </div>

                        <div className="panel p-3 space-y-3">
                          <div className="text-[11px] uppercase tracking-wide text-base-content/45">
                            Expiry
                            <FieldHint text="Required: absolute expires_at OR relative ttl_seconds from apply time" />
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <button
                              type="button"
                              className={`btn btn-xs ${
                                expiryMode === "ttl" ? "btn-primary" : "btn-outline"
                              }`}
                              onClick={() => setExpiryMode("ttl")}
                            >
                              TTL (seconds)
                            </button>
                            <button
                              type="button"
                              className={`btn btn-xs ${
                                expiryMode === "absolute" ? "btn-primary" : "btn-outline"
                              }`}
                              onClick={() => setExpiryMode("absolute")}
                            >
                              Absolute time
                            </button>
                          </div>
                          {expiryMode === "ttl" ? (
                            <label className="form-control max-w-xs">
                              <span className="label-text text-xs">
                                ttl_seconds — lifetime from apply
                              </span>
                              <input
                                className="input input-sm input-bordered mono"
                                type="number"
                                min={1}
                                value={sessionTtlInput}
                                onChange={(e) => setSessionTtlInput(e.target.value)}
                                placeholder="3600"
                              />
                            </label>
                          ) : (
                            <label className="form-control max-w-md">
                              <span className="label-text text-xs">
                                expires_at — UTC, e.g. <span className="mono">2026-07-15 18:00 UTC</span>
                              </span>
                              <input
                                className="input input-sm input-bordered mono"
                                value={expiresAtInput}
                                onChange={(e) => setExpiresAtInput(e.target.value)}
                                placeholder="2026-07-15 18:00 UTC"
                              />
                            </label>
                          )}
                        </div>

                        {sessionPath && (
                          <div className="text-[11px] mono text-base-content/40 break-all">
                            Session file: {sessionPath}
                          </div>
                        )}

                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            className="btn btn-sm"
                            disabled={saveStructuredSession.running}
                            onClick={async () => {
                              await saveStructuredSession.run(buildSessionPayload(false));
                              await loadStructuredSession();
                            }}
                          >
                            Save
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            disabled={saveStructuredSession.running}
                            onClick={async () => {
                              await saveStructuredSession.run(buildSessionPayload(true));
                              await loadRoleState();
                              await loadStructuredSession();
                            }}
                          >
                            Save &amp; Apply
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-outline"
                            disabled={applySession.running}
                            onClick={async () => {
                              await applySession.run();
                              await loadRoleState();
                            }}
                          >
                            Apply only
                          </button>
                          <ConfirmButton
                            className="btn btn-sm btn-ghost text-error"
                            confirmText="Clear manual session config?"
                            onConfirm={async () => {
                              await clearSession.run();
                              setSessionHydrated(false);
                              hydrateManualForm(null);
                              await loadRoleState();
                            }}
                          >
                            Clear session
                          </ConfirmButton>
                        </div>

                        {showRawFile && (
                          <div className="space-y-2 border-t border-base-300 pt-3">
                            <p className="text-xs text-base-content/50">
                              Advanced: edit the same file Talos CLI uses. Saving here overwrites
                              structured form content until you reload.
                            </p>
                            <textarea
                              className="textarea textarea-sm textarea-bordered w-full mono text-xs"
                              rows={12}
                              value={sessionContent}
                              onChange={(e) => setSessionContent(e.target.value)}
                              spellCheck={false}
                            />
                            <div className="flex gap-2">
                              <button
                                type="button"
                                className="btn btn-sm"
                                disabled={saveSessionFile.running}
                                onClick={async () => {
                                  await saveSessionFile.run(sessionContent);
                                }}
                              >
                                Save raw file
                              </button>
                              <button
                                type="button"
                                className="btn btn-sm btn-primary"
                                disabled={applySession.running}
                                onClick={async () => {
                                  await saveSessionFile.run(sessionContent);
                                  await applySession.run();
                                  await loadRoleState();
                                  await loadStructuredSession();
                                }}
                              >
                                Save raw &amp; Apply
                              </button>
                              <button
                                type="button"
                                className="btn btn-sm btn-ghost"
                                onClick={() => loadSessionAction.run()}
                              >
                                Reload
                              </button>
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </Section>

          {/* ═══ 3. Session Health ═══ */}
          <Section title="3. Session Health">
            {!roleId ? (
              <p className="text-sm text-base-content/50">Select a role above.</p>
            ) : (
              <div className="space-y-5">
                <p className="text-xs text-base-content/55">
                  Three layers: proactive refresh, expiry signals + suspicion, and validation
                  flows (section 4). Display uses Talos-backed state.
                </p>

                {/* TTL — AUTO full policy; MANUAL only refresh_before */}
                <div className="panel p-4">
                  <div className="text-sm font-medium mb-2">
                    {provider === "manual" ? "Refresh window" : "TTL policy"}
                  </div>
                  {provider === "manual" ? (
                    <>
                      <p className="text-xs text-base-content/50 mb-3">
                        MANUAL session lifetime comes from the session&apos;s{" "}
                        <span className="mono">expires_at</span> /{" "}
                        <span className="mono">ttl_seconds</span> (section 2), not from Session
                        Health TTL. <span className="mono">refresh_before</span> still applies:
                        when remaining time falls below this window, Talos treats the session as
                        needing refresh (operator must re-apply credentials).
                      </p>
                      <div className="flex flex-wrap gap-3 items-end">
                        <label className="form-control">
                          <span className="label-text text-xs">Refresh before expiry (seconds)</span>
                          <input
                            className="input input-sm input-bordered w-32 mono"
                            type="number"
                            min={0}
                            value={refreshBeforeInput}
                            onChange={(e) => setRefreshBeforeInput(e.target.value)}
                          />
                        </label>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          disabled={setRefreshBeforeOnly.running}
                          onClick={async () => {
                            const rb = Number(refreshBeforeInput);
                            if (!Number.isFinite(rb) || rb < 0) return;
                            await setRefreshBeforeOnly.run(rb);
                            await loadRoleState();
                          }}
                        >
                          Save refresh window
                        </button>
                      </div>
                      <div className="text-[11px] text-base-content/40 mt-2 mono">
                        Effective refresh_before:{" "}
                        {roleState?.health?.refresh_before_seconds ?? "—"}s · manual expires in{" "}
                        {formatSeconds(roleState?.expires_in_seconds)}
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-base-content/50 mb-3">
                        AUTO credential lifetime and how early Talos should re-run login flows
                        before expiry. Values in seconds.
                      </p>
                      <div className="flex flex-wrap gap-3 items-end">
                        <label className="form-control">
                          <span className="label-text text-xs">Session TTL (seconds)</span>
                          <input
                            className="input input-sm input-bordered w-32 mono"
                            type="number"
                            min={1}
                            value={ttlInput}
                            onChange={(e) => setTtlInput(e.target.value)}
                          />
                        </label>
                        <label className="form-control">
                          <span className="label-text text-xs">Refresh before expiry (seconds)</span>
                          <input
                            className="input input-sm input-bordered w-32 mono"
                            type="number"
                            min={0}
                            value={refreshBeforeInput}
                            onChange={(e) => setRefreshBeforeInput(e.target.value)}
                          />
                        </label>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          disabled={setTtl.running || !ttlInput}
                          onClick={async () => {
                            const ttl = Number(ttlInput);
                            const rb = Number(refreshBeforeInput);
                            if (!Number.isFinite(ttl) || ttl < 1) return;
                            await setTtl.run(ttl, Number.isFinite(rb) ? rb : 120);
                            await loadRoleState();
                          }}
                        >
                          Save TTL policy
                        </button>
                      </div>
                      <div className="text-[11px] text-base-content/40 mt-2 mono">
                        Effective: TTL {roleState?.health?.ttl_seconds ?? "—"}s · refresh before{" "}
                        {roleState?.health?.refresh_before_seconds ?? "—"}s
                      </div>
                    </>
                  )}
                </div>

                {/* Expiry signals */}
                <div className="panel p-4">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="text-sm font-medium">Expiry signals</div>
                    <ConfirmButton
                      className="btn btn-xs btn-ghost text-error"
                      confirmText="Remove all expiry signals for this role?"
                      onConfirm={async () => {
                        await clearExpirySignals.run();
                        await loadRoleState();
                      }}
                    >
                      Remove all signals
                    </ConfirmButton>
                  </div>
                  <p className="text-xs text-base-content/50 mb-3">
                    Response patterns that suggest the session expired. Core supports clear-all
                    only — not per-signal deletion.
                  </p>
                  {expiryRows.length === 0 ? (
                    <div className="text-sm text-base-content/40 mb-3">No signals configured.</div>
                  ) : (
                    <ul className="space-y-1 mb-3">
                      {expiryRows.map((r, i) => (
                        <li key={`${r.kind}-${i}`} className="mono text-xs panel px-2 py-1">
                          {r.label}
                        </li>
                      ))}
                    </ul>
                  )}
                  <div className="flex flex-wrap gap-2 items-end">
                    <label className="form-control">
                      <span className="label-text text-xs">Signal type</span>
                      <select
                        className="select select-sm select-bordered"
                        value={signalKind}
                        onChange={(e) =>
                          setSignalKind(e.target.value as "status" | "body" | "header")
                        }
                      >
                        <option value="status">HTTP status</option>
                        <option value="body">Response body contains</option>
                        <option value="header">Response header</option>
                      </select>
                    </label>
                    {signalKind === "status" && (
                      <label className="form-control">
                        <span className="label-text text-xs">Status code</span>
                        <input
                          className="input input-sm input-bordered w-28 mono"
                          value={signalStatus}
                          onChange={(e) => setSignalStatus(e.target.value)}
                        />
                      </label>
                    )}
                    {signalKind === "body" && (
                      <label className="form-control flex-1 min-w-[12rem]">
                        <span className="label-text text-xs">Body substring</span>
                        <input
                          className="input input-sm input-bordered mono w-full"
                          value={signalBody}
                          onChange={(e) => setSignalBody(e.target.value)}
                        />
                      </label>
                    )}
                    {signalKind === "header" && (
                      <>
                        <label className="form-control">
                          <span className="label-text text-xs">Header name</span>
                          <input
                            className="input input-sm input-bordered mono w-36"
                            value={signalHeaderName}
                            onChange={(e) => setSignalHeaderName(e.target.value)}
                          />
                        </label>
                        <label className="form-control flex-1 min-w-[10rem]">
                          <span className="label-text text-xs">Value substring</span>
                          <input
                            className="input input-sm input-bordered mono w-full"
                            value={signalHeaderValue}
                            onChange={(e) => setSignalHeaderValue(e.target.value)}
                          />
                        </label>
                      </>
                    )}
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={addExpirySignal.running}
                      onClick={async () => {
                        const body: {
                          body_signals: string[];
                          status_codes: number[];
                          header_signals: { name: string; value: string }[];
                        } = { body_signals: [], status_codes: [], header_signals: [] };
                        if (signalKind === "status") {
                          const n = Number(signalStatus);
                          if (!Number.isFinite(n)) return;
                          body.status_codes = [n];
                        } else if (signalKind === "body") {
                          if (!signalBody.trim()) return;
                          body.body_signals = [signalBody.trim()];
                        } else {
                          if (!signalHeaderName.trim() || !signalHeaderValue.trim()) return;
                          body.header_signals = [
                            {
                              name: signalHeaderName.trim(),
                              value: signalHeaderValue.trim(),
                            },
                          ];
                        }
                        await addExpirySignal.run(body);
                        setSignalBody("");
                        setSignalHeaderName("");
                        setSignalHeaderValue("");
                        await loadRoleState();
                      }}
                    >
                      Add signal
                    </button>
                  </div>
                </div>

                {/* Suspicion */}
                <div className="panel p-4">
                  <div className="text-sm font-medium mb-2">Suspicion state</div>
                  <div className="flex flex-wrap gap-4 text-sm mb-2">
                    <span>
                      Count: <span className="mono font-medium">{suspicionCount}</span>
                    </span>
                    <span>
                      Threshold:{" "}
                      <span className="mono font-medium">{suspicionThreshold}</span>
                    </span>
                    <span>
                      State:{" "}
                      <StatusBadge
                        value={
                          roleState?.health_degraded
                            ? "DEGRADED"
                            : suspicionCount > 0
                              ? "WATCHING"
                              : "HEALTHY"
                        }
                      />
                    </span>
                  </div>
                  {suspicionCount > 0 && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={resetHealth.running}
                      onClick={async () => {
                        await resetHealth.run();
                        await loadRoleState();
                      }}
                    >
                      Reset health suspicion
                    </button>
                  )}
                </div>
              </div>
            )}
          </Section>

          {/* ═══ 4. Validation Flows ═══ */}
          <Section title="4. Validation Flows">
            {!roleId ? (
              <p className="text-sm text-base-content/50">Select a role above.</p>
            ) : (
              <>
                <p className="text-xs text-base-content/55 mb-3">
                  Talos validates the current session by replaying a captured validation flow with
                  the latest role authentication state. The replay response status must match the
                  captured baseline status. Use <strong className="text-base-content/70">Validate</strong>{" "}
                  on a row to probe that flow.
                </p>

                {(roleState?.control_flows?.length || 0) === 0 ? (
                  <div className="panel p-3 text-sm text-warning/80 mb-3">
                    No validation flows configured. Validation is mandatory for a healthy session.
                  </div>
                ) : (
                  <div className="panel overflow-x-auto mb-3">
                    <table className="table table-tight table-sm">
                      <thead>
                        <tr>
                          <th>Request</th>
                          <th>Baseline</th>
                          <th>Flow</th>
                          <th className="text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {roleState!.control_flows.map((cf) => (
                          <tr key={cf.flow_id}>
                            <td className="mono text-xs">
                              {cf.method || "?"} {cf.path || "(unknown)"}
                            </td>
                            <td className="mono text-xs">
                              {cf.status_code != null ? cf.status_code : "—"}
                            </td>
                            <td>
                              <UuidChip value={cf.flow_id} />
                            </td>
                            <td className="text-right">
                              <div className="flex flex-wrap gap-1 justify-end">
                                <button
                                  type="button"
                                  className="btn btn-xs btn-primary"
                                  disabled={validateAuth.running}
                                  onClick={async () => {
                                    await validateAuth.run(cf.flow_id);
                                    await loadRoleState();
                                  }}
                                >
                                  Validate
                                </button>
                                <ConfirmButton
                                  className="btn btn-xs btn-ghost text-error"
                                  confirmText="Remove this validation flow?"
                                  onConfirm={async () => {
                                    await removeControlFlow.run(cf.flow_id);
                                    await loadRoleState();
                                  }}
                                >
                                  Remove
                                </ConfirmButton>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 items-end">
                  <label className="form-control flex-1 min-w-[14rem]">
                    <span className="label-text text-xs">
                      Validation flow UUID
                      <FieldHint text="Captured authenticated request used as baseline, e.g. GET /api/me" />
                    </span>
                    <input
                      className="input input-sm input-bordered mono w-full"
                      value={controlFlowId}
                      onChange={(e) => setControlFlowId(e.target.value.trim())}
                      placeholder="control flow uuid"
                    />
                  </label>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={!controlFlowId || addControlFlow.running}
                    onClick={async () => {
                      await addControlFlow.run(controlFlowId);
                      setControlFlowId("");
                      await loadRoleState();
                    }}
                  >
                    Add validation flow
                  </button>
                </div>
              </>
            )}
          </Section>

          {/* ═══ 5. Runtime ═══ */}
          <Section title="5. Runtime and Recovery">
            {!roleId ? (
              <p className="text-sm text-base-content/50">Select a role above.</p>
            ) : (
              <>
                <p className="text-xs text-base-content/55 mb-3">
                  {provider === "manual" ? (
                    <>
                      MANUAL runtime state uses the applied session config for Session / Expires.
                      Active values appear when apply (or validate) has written{" "}
                      <span className="mono">role_auth_state</span>.{" "}
                      <span className="mono">refresh</span> re-applies the stored manual session
                      (no login HTTP).
                    </>
                  ) : (
                    <>
                      <span className="mono">validate</span> checks the session;{" "}
                      <span className="mono">refresh</span> re-runs login flows;{" "}
                      <span className="mono">auth-config test</span> only tests extractors without
                      storing state.
                    </>
                  )}
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs mb-4 panel p-3">
                  <div>
                    <div className="text-base-content/40">Provider</div>
                    <div className="font-medium">{(provider || "unset").toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="text-base-content/40">Auth state</div>
                    <div className="font-medium">{sessionState}</div>
                  </div>
                  <div>
                    <div className="text-base-content/40">Session age</div>
                    <div className="font-medium mono">
                      {formatSeconds(roleState?.session_age_seconds)}
                    </div>
                  </div>
                  <div>
                    <div className="text-base-content/40">Expires</div>
                    <div className="font-medium mono">
                      {formatSeconds(roleState?.expires_in_seconds)}
                    </div>
                  </div>
                  <div>
                    <div className="text-base-content/40">
                      {provider === "manual" ? "Session TTL / expiry" : "Health TTL"}
                    </div>
                    <div className="font-medium mono">
                      {provider === "manual"
                        ? roleState?.manual_session?.ttl_seconds != null
                          ? `${roleState.manual_session.ttl_seconds}s`
                          : roleState?.manual_session?.expires_at || "—"
                        : `${roleState?.health?.ttl_seconds ?? "—"}s`}
                    </div>
                  </div>
                  <div>
                    <div className="text-base-content/40">Suspicion</div>
                    <div className="font-medium mono">
                      {suspicionCount}/{suspicionThreshold}
                    </div>
                  </div>
                  <div>
                    <div className="text-base-content/40">Configured artifacts</div>
                    <div className="font-medium">
                      {artifacts.length} names · {roleState?.artifacts?.length ?? 0} values
                    </div>
                  </div>
                  <div className="col-span-2">
                    <div className="text-base-content/40">Last collected</div>
                    <div className="font-medium mono text-[11px]">
                      {roleState?.collected_at ? formatIST(roleState.collected_at) : "—"}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={validateAuth.running}
                    onClick={async () => {
                      await validateAuth.run();
                      await loadRoleState();
                    }}
                  >
                    Validate all
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={refreshAuth.running}
                    onClick={async () => {
                      await refreshAuth.run();
                      await loadRoleState();
                    }}
                  >
                    Refresh now
                  </button>
                  {provider === "manual" && (
                    <ConfirmButton
                      className="btn btn-sm btn-outline"
                      confirmText="Clear manual session?"
                      onConfirm={async () => {
                        await clearSession.run();
                        setSessionHydrated(false);
                        await loadRoleState();
                      }}
                    >
                      Clear manual session
                    </ConfirmButton>
                  )}
                  {suspicionCount > 0 && (
                    <button
                      type="button"
                      className="btn btn-sm btn-outline"
                      disabled={resetHealth.running}
                      onClick={async () => {
                        await resetHealth.run();
                        await loadRoleState();
                      }}
                    >
                      Reset health suspicion
                    </button>
                  )}
                </div>
              </>
            )}
          </Section>
        </div>

        {/* Right rail */}
        <aside className="panel p-4 sticky top-[4.5rem] space-y-4">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-base-content/45 mb-2">
              Active session values
            </div>
            <p className="text-[11px] text-base-content/45 mb-2">
              Collected <span className="mono">role_auth_state</span> for the selected role.
            </p>
            {(roleState?.artifacts?.length || 0) === 0 ? (
              <div className="text-sm text-base-content/40">
                None collected yet.
                {provider === "manual" && (
                  <span className="block mt-1 text-[11px]">
                    Save &amp; Apply the manual session (and ensure validation passes) to populate
                    values.
                  </span>
                )}
              </div>
            ) : (
              <ul className="space-y-3">
                {roleState!.artifacts.map((a) => (
                  <li key={a.key} className="border-b border-base-300/50 pb-2 last:border-0">
                    <div className="mono text-xs font-medium mb-0.5">{a.key}</div>
                    <ArtifactValue value={a.value} />
                    <div className="text-[10px] text-base-content/35 mt-1">
                      {formatIST(a.collected_at)}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {provider === "auto" && (roleState?.flows?.length || 0) > 0 && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-base-content/45 mb-2">
                Login flow extractors
              </div>
              <ul className="space-y-1">
                {roleState!.flows.map((f) => (
                  <li key={f.flow_id} className="flex items-center justify-between gap-1 text-xs">
                    <span className="truncate mono">
                      {flowLabel(f)}
                    </span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs shrink-0"
                      onClick={() => openExtractor(f.flow_id)}
                    >
                      {f.has_extractor ? "Open" : "Set"}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </aside>
      </div>

      <Modal
        open={extractorOpen}
        onClose={() => setExtractorOpen(false)}
        title="Login flow extractor"
        wide
      >
        <div className="space-y-3">
          <p className="text-xs text-base-content/55">
            Python function <span className="mono">extract(response)</span> must return artifact
            name → value. Test does not store state.
          </p>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-base-content/45">Flow</span>
            <UuidChip value={extractorFlowId} />
            <span
              className={`badge badge-xs ${extractorConfigured ? "badge-success" : "badge-warning"}`}
            >
              {extractorConfigured ? "configured" : "empty / template"}
            </span>
          </div>
          <textarea
            className="textarea textarea-bordered w-full mono text-xs min-h-[16rem]"
            value={extractorCode}
            onChange={(e) => setExtractorCode(e.target.value)}
            spellCheck={false}
          />
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={!extractorCode.trim() || saveExtractor.running}
              onClick={async () => {
                await saveExtractor.run(extractorFlowId, extractorCode);
                setExtractorConfigured(true);
                await loadRoleState();
              }}
            >
              Save extractor
            </button>
            <button
              type="button"
              className="btn btn-sm"
              disabled={!extractorConfigured || testFlow.running}
              onClick={() => runExtractorTest()}
            >
              {testFlow.running ? (
                <span className="loading loading-spinner loading-xs" />
              ) : (
                "Run extractor test"
              )}
            </button>
            <ConfirmButton
              className="btn btn-sm btn-ghost text-error"
              confirmText="Remove extractor from this flow?"
              onConfirm={async () => {
                await removeExtractor.run(extractorFlowId);
                setExtractorCode(EXTRACTOR_TEMPLATE);
                setExtractorConfigured(false);
                setTestArtifacts(null);
                await loadRoleState();
              }}
            >
              Remove extractor
            </ConfirmButton>
          </div>

          {(testArtifacts || testStdout) && (
            <div className="panel p-3 bg-base-200/40">
              <div className="text-xs font-medium mb-2">Extracted tokens (full values)</div>
              {testArtifacts && Object.keys(testArtifacts).length > 0 ? (
                <ul className="space-y-2">
                  {Object.entries(testArtifacts).map(([k, v]) => (
                    <li key={k}>
                      <div className="mono text-xs font-medium text-base-content/70">{k}</div>
                      <ArtifactValue value={v} />
                    </li>
                  ))}
                </ul>
              ) : testArtifacts ? (
                <div className="text-sm text-base-content/50">Empty dict returned.</div>
              ) : (
                <pre className="mono text-[11px] whitespace-pre-wrap break-all max-h-48 overflow-auto">
                  {testStdout}
                </pre>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
