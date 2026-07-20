import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { NoProjectNotice, Section } from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";

const BAC_TECHNIQUES = [
  "session-swap", "method-fuzz", "content-type", "url-fuzz",
  "header-inject", "host-fuzz", "role-inject", "parser-confuse",
];

function UnauthTab({ projectId }: { projectId: string }) {
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [results, setResults] = useState<any[]>([]);
  const [maxPriority, setMaxPriority] = useState("");
  const [authMutation, setAuthMutation] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [autoRun, setAutoRun] = useState<{ enabled: boolean; source: string } | null>(null);

  const load = () => {
    api.get<{ counts: Record<string, number> }>("/api/attack/unauth/summary", { project_id: projectId }).then((r) => setSummary(r.counts));
    api.get<{ results: any[] }>("/api/attack/unauth/results", { project_id: projectId, limit: 100 }).then((r) => setResults(r.results));
    api
      .get<{ key: string; value: unknown; source: string }>("/api/configuration/get", {
        project_id: projectId,
        key: "attack.unauth_auto_run",
      })
      .then((r) =>
        setAutoRun({
          enabled: Boolean(r.value),
          source: (r.source || "default").toLowerCase(),
        })
      )
      .catch(() => setAutoRun(null));
  };
  useEffect(load, [projectId]);

  const run = useAction("Run unauth attack", () =>
    api.post("/api/attack/unauth/run", {
      max_priority: maxPriority ? Number(maxPriority) : undefined,
      auth_mutation: authMutation || undefined,
    }, { project_id: projectId })
  );
  const filterInit = useAction("Init unauth filter", () => api.post("/api/attack/unauth/filter/init", {}, { project_id: projectId }));
  const filterShow = useAction("Show unauth filter", () => api.post("/api/attack/unauth/filter/show", {}, { project_id: projectId }));
  const filterValidate = useAction("Validate unauth filter", () => api.post("/api/attack/unauth/filter/validate", {}, { project_id: projectId }));

  return (
    <div>
      <div className="panel p-3 mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-wide text-base-content/50 mb-0.5">
            Automatic unauth testing
          </div>
          <div className="flex items-center gap-2 text-sm">
            <span className={`badge badge-sm ${autoRun?.enabled ? "badge-success" : "badge-ghost"}`}>
              {autoRun == null ? "…" : autoRun.enabled ? "Enabled" : "Disabled"}
            </span>
            {autoRun && (
              <span className="text-xs text-base-content/50">
                Inherited from: <span className="uppercase font-medium">{autoRun.source}</span>
              </span>
            )}
          </div>
          <p className="text-xs text-base-content/50 mt-1 max-w-xl">
            When enabled, Talos automatically enqueues unauth/auth-test work for eligible untested
            endpoints. Owned by layered configuration — not a separate attack toggle.
          </p>
        </div>
        <Link
          className="link link-primary text-xs shrink-0"
          to="/talos-config?tab=settings&section=attack"
        >
          Configure attack.unauth_auto_run →
        </Link>
      </div>

      <Section title="Run">
        <div className="flex gap-2 items-end flex-wrap">
          <label className="form-control">
            <span className="label-text text-xs">Max priority</span>
            <input className="input input-xs input-bordered w-24" value={maxPriority} onChange={(e) => setMaxPriority(e.target.value)} placeholder="2" />
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Auth mutation (optional)</span>
            <input className="input input-xs input-bordered w-56 mono" value={authMutation} onChange={(e) => setAuthMutation(e.target.value)} placeholder="remove_authorization_header" />
          </label>
          <button className="btn btn-sm btn-primary" disabled={run.running} onClick={async () => { await run.run(); load(); }}>
            {run.running ? <span className="loading loading-spinner loading-xs" /> : "Run unauth attack"}
          </button>
        </div>
      </Section>

      <Section title="Decision filter" action={
        <div className="flex gap-2">
          <button className="btn btn-xs" onClick={() => filterInit.run()}>Init</button>
          <button className="btn btn-xs" onClick={() => filterShow.run()}>Show</button>
          <button className="btn btn-xs" onClick={() => filterValidate.run()}>Validate</button>
        </div>
      }>
        <p className="text-xs text-base-content/50">
          Output of init/show/validate appears in the Console drawer at the bottom.
        </p>
      </Section>

      <Section title="Summary">
        <div className="flex gap-3">
          {["BYPASS", "SECURE", "UNKNOWN"].map((v) => (
            <div key={v} className="panel p-3 text-center">
              <div className="text-xl font-semibold">{summary[v] ?? 0}</div>
              <StatusBadge value={v} />
            </div>
          ))}
        </div>
      </Section>

      <Section title="Recent results" action={
        <select className="select select-xs select-bordered" value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value)}>
          <option value="">verdict: any</option>
          {["BYPASS", "SECURE", "UNKNOWN"].map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
      }>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Auth mutation</th><th>Request mutation</th><th>Verdict</th></tr></thead>
            <tbody>
              {results.filter((r) => !verdictFilter || r.verdict === verdictFilter).map((r) => (
                <tr key={r.replay_flow_id}>
                  <td className="text-xs whitespace-nowrap">{formatIST(r.captured_at)}</td>
                  <td className="mono">{r.method}</td>
                  <td className="mono">{r.path}</td>
                  <td>{r.status_code}</td>
                  <td>{r.auth_mutation}</td>
                  <td>{r.request_mutation || "—"}</td>
                  <td><StatusBadge value={r.verdict} /></td>
                </tr>
              ))}
              {results.length === 0 && <tr><td colSpan={7} className="text-center text-base-content/40 py-4">No results yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}

function BacTab({ projectId }: { projectId: string }) {
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [results, setResults] = useState<any[]>([]);
  const [role, setRole] = useState("");
  const [autoGenerate, setAutoGenerate] = useState(false);
  const [verdictFilter, setVerdictFilter] = useState("");
  const [moduleFilter, setModuleFilter] = useState("");

  const load = () => {
    api.get<{ counts: Record<string, number> }>("/api/attack/bac/summary", { project_id: projectId }).then((r) => setSummary(r.counts));
    api.get<{ results: any[] }>("/api/attack/bac/results", { project_id: projectId, limit: 100 }).then((r) => setResults(r.results));
  };
  useEffect(load, [projectId]);

  const run = useAction("Run BAC technique", (technique: string) =>
    api.post(`/api/attack/bac/${technique}`, { role: role || undefined, auto_generate: autoGenerate }, { project_id: projectId })
  );
  const filterInit = useAction("Init BAC filter", () => api.post("/api/attack/bac/filter/init", {}, { project_id: projectId }));
  const filterShow = useAction("Show BAC filter", () => api.post("/api/attack/bac/filter/show", {}, { project_id: projectId }));
  const filterValidate = useAction("Validate BAC filter", () => api.post("/api/attack/bac/filter/validate", {}, { project_id: projectId }));

  return (
    <div>
      <Section title="Run a technique">
        <div className="flex gap-2 items-end flex-wrap mb-3">
          <label className="form-control">
            <span className="label-text text-xs">Attacker role (optional)</span>
            <input className="input input-xs input-bordered w-40" value={role} onChange={(e) => setRole(e.target.value)} placeholder="customer" />
          </label>
          <label className="label cursor-pointer gap-2">
            <span className="label-text text-xs">--auto-generate</span>
            <input type="checkbox" className="checkbox checkbox-xs" checked={autoGenerate} onChange={(e) => setAutoGenerate(e.target.checked)} />
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          {BAC_TECHNIQUES.map((t) => (
            <button key={t} className="btn btn-xs btn-primary" disabled={run.running} onClick={async () => { await run.run(t); load(); }}>
              {t}
            </button>
          ))}
        </div>
      </Section>

      <Section title="Decision filter" action={
        <div className="flex gap-2">
          <button className="btn btn-xs" onClick={() => filterInit.run()}>Init</button>
          <button className="btn btn-xs" onClick={() => filterShow.run()}>Show</button>
          <button className="btn btn-xs" onClick={() => filterValidate.run()}>Validate</button>
        </div>
      }>
        <p className="text-xs text-base-content/50">
          Output of init/show/validate appears in the Console drawer at the bottom.
        </p>
      </Section>

      <Section title="Summary">
        <div className="flex gap-3">
          {["POSSIBLE_BAC", "SECURE", "UNKNOWN"].map((v) => (
            <div key={v} className="panel p-3 text-center">
              <div className="text-xl font-semibold">{summary[v] ?? 0}</div>
              <StatusBadge value={v} />
            </div>
          ))}
        </div>
      </Section>

      <Section title="Recent results" action={
        <div className="flex gap-2">
          <select className="select select-xs select-bordered" value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value)}>
            <option value="">verdict: any</option>
            {["POSSIBLE_BAC", "SECURE", "UNKNOWN"].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <select className="select select-xs select-bordered" value={moduleFilter} onChange={(e) => setModuleFilter(e.target.value)}>
            <option value="">module: any</option>
            {[...new Set(results.map((r) => r.module_name).filter(Boolean))].map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
      }>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Attacker</th><th>Target</th><th>Module</th><th>Variant</th><th>Verdict</th></tr></thead>
            <tbody>
              {results
                .filter((r) => (!verdictFilter || r.verdict === verdictFilter) && (!moduleFilter || r.module_name === moduleFilter))
                .map((r) => (
                <tr key={r.replay_flow_id}>
                  <td className="text-xs whitespace-nowrap">{formatIST(r.captured_at)}</td>
                  <td className="mono">{r.method}</td>
                  <td className="mono">{r.path}</td>
                  <td>{r.attacker_role_name}</td>
                  <td>{r.target_role_name}</td>
                  <td>{r.module_name}</td>
                  <td>{r.variant}</td>
                  <td><StatusBadge value={r.verdict} /></td>
                </tr>
              ))}
              {results.length === 0 && <tr><td colSpan={8} className="text-center text-base-content/40 py-4">No results yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}

export default function Attack() {
  const { selected } = useProject();
  const [tab, setTab] = useState<"unauth" | "bac">("bac");

  if (!selected) return <NoProjectNotice />;

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Attack Modules</h1>
      <div role="tablist" className="tabs tabs-boxed w-fit mb-6">
        <a role="tab" className={`tab ${tab === "bac" ? "tab-active" : ""}`} onClick={() => setTab("bac")}>BAC</a>
        <a role="tab" className={`tab ${tab === "unauth" ? "tab-active" : ""}`} onClick={() => setTab("unauth")}>Unauth</a>
      </div>
      {tab === "bac" ? <BacTab projectId={selected.id} /> : <UnauthTab projectId={selected.id} />}
    </div>
  );
}
