import { useEffect, useState } from "react";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import { BUDGETS, PHASES, IvConfig, inputClass, selectClass } from "./shared";

const PHASE_KEYS: { phase: string; field: keyof IvConfig }[] = [
  { phase: "baseline", field: "analyses_baseline" },
  { phase: "multiprobe", field: "analyses_multiprobe" },
  { phase: "identifier", field: "analyses_identifier" },
  { phase: "characters", field: "analyses_characters" },
  { phase: "length", field: "analyses_length" },
  { phase: "types", field: "analyses_types" },
  { phase: "transformations", field: "analyses_transformations" },
  { phase: "reflection", field: "analyses_reflection" },
  { phase: "validation", field: "analyses_validation" },
];

export default function SettingsTab({
  projectId,
  config,
  onRefresh,
}: {
  projectId: string;
  config: IvConfig | null;
  onRefresh: () => void;
}) {
  const [workers, setWorkers] = useState("2");
  const [budget, setBudget] = useState("standard");
  const [maxReq, setMaxReq] = useState("0");
  const [excludeHost, setExcludeHost] = useState("");
  const [excludeEndpoint, setExcludeEndpoint] = useState("");

  useEffect(() => {
    if (!config) return;
    setWorkers(String(config.workers ?? 2));
    setBudget(config.probe_strategy || "standard");
    setMaxReq(String(config.max_requests_per_param ?? 0));
  }, [config]);

  const enable = useAction("Enable IV", () =>
    api.post("/api/input-validation/config", { enable: true }, { project_id: projectId }),
  );
  const disable = useAction("Disable IV", () =>
    api.post("/api/input-validation/config", { disable: true }, { project_id: projectId }),
  );
  const applyWorkers = useAction("Set workers", () =>
    api.post(
      "/api/input-validation/config",
      { workers: Number(workers) },
      { project_id: projectId },
    ),
  );
  const applyBudget = useAction("Set budget", () =>
    api.post(
      "/api/input-validation/config",
      {
        probe_strategy: budget,
        max_requests_per_param: Number(maxReq) || 0,
      },
      { project_id: projectId },
    ),
  );
  const setAuth = useAction("Set auth artifacts policy", (include: boolean) =>
    api.post(
      "/api/input-validation/config",
      include
        ? { include_auth_artifacts: true }
        : { skip_auth_artifacts: true },
      { project_id: projectId },
    ),
  );
  const togglePhase = useAction("Toggle IV phase", (phase: string, on: boolean) =>
    api.post(
      "/api/input-validation/config",
      on ? { analysis_on: phase } : { analysis_off: phase },
      { project_id: projectId },
    ),
  );
  const excludeH = useAction("Exclude host", () =>
    api.post(`/api/input-validation/exclude/host/${encodeURIComponent(excludeHost)}`, {}, {
      project_id: projectId,
    }),
  );
  const includeH = useAction("Include host", () =>
    api.post(`/api/input-validation/include/host/${encodeURIComponent(excludeHost)}`, {}, {
      project_id: projectId,
    }),
  );
  const excludeE = useAction("Exclude endpoint", () =>
    api.post(
      `/api/input-validation/exclude/endpoint/${encodeURIComponent(excludeEndpoint)}`,
      {},
      { project_id: projectId },
    ),
  );
  const includeE = useAction("Include endpoint", () =>
    api.post(
      `/api/input-validation/include/endpoint/${encodeURIComponent(excludeEndpoint)}`,
      {},
      { project_id: projectId },
    ),
  );

  return (
    <div className="space-y-4">
      <Section title="Engine">
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <span className={`badge ${config?.enabled ? "badge-success" : "badge-ghost"}`}>
            {config?.enabled ? "enabled" : "disabled"}
          </span>
          {!config?.enabled ? (
            <button
              className="btn btn-xs btn-primary"
              onClick={async () => {
                await enable.run();
                onRefresh();
              }}
            >
              Enable
            </button>
          ) : (
            <button
              className="btn btn-xs"
              onClick={async () => {
                await disable.run();
                onRefresh();
              }}
            >
              Disable
            </button>
          )}
        </div>
        <div className="flex flex-wrap gap-2 items-end">
          <div>
            <div className="text-xs text-base-content/50 mb-1">Workers</div>
            <input
              className={`${inputClass} w-20`}
              value={workers}
              onChange={(e) => setWorkers(e.target.value)}
            />
          </div>
          <button
            className="btn btn-xs"
            onClick={async () => {
              await applyWorkers.run();
              onRefresh();
            }}
          >
            Apply workers
          </button>
        </div>
      </Section>

      <Section title="Budget & limits">
        <div className="flex flex-wrap gap-3 items-end">
          <div>
            <div className="text-xs text-base-content/50 mb-1">Budget tier</div>
            <select
              className={selectClass}
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
            >
              {BUDGETS.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          </div>
          <div>
            <div className="text-xs text-base-content/50 mb-1">
              Max requests / param (0 = tier default)
            </div>
            <input
              className={`${inputClass} w-24`}
              value={maxReq}
              onChange={(e) => setMaxReq(e.target.value)}
            />
          </div>
          <button
            className="btn btn-xs btn-primary"
            onClick={async () => {
              await applyBudget.run();
              onRefresh();
            }}
          >
            Apply budget
          </button>
        </div>
        <p className="text-xs text-base-content/50 mt-2">
          standard uses multiprobe-first adaptive planning; exhaustive approximates the legacy
          full matrix.
        </p>
      </Section>

      <Section title="Auth artifacts">
        <p className="text-xs text-base-content/60 mb-2">
          Session cookies and Authorization headers are skipped by default.
        </p>
        <div className="flex gap-2">
          <button
            className={`btn btn-xs ${config?.include_auth_artifacts ? "btn-primary" : ""}`}
            onClick={async () => {
              await setAuth.run(true);
              onRefresh();
            }}
          >
            Include auth artifacts
          </button>
          <button
            className={`btn btn-xs ${!config?.include_auth_artifacts ? "btn-primary" : ""}`}
            onClick={async () => {
              await setAuth.run(false);
              onRefresh();
            }}
          >
            Skip auth artifacts (default)
          </button>
        </div>
      </Section>

      <Section title="Analysis phases">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {PHASE_KEYS.map(({ phase, field }) => {
            const raw = config ? (config as any)[field] : undefined;
            // Default on when column missing (older DBs).
            const on = raw === undefined || raw === null ? true : Boolean(Number(raw));
            return (
              <label key={phase} className="flex items-center gap-2 text-xs panel p-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs"
                  checked={on}
                  onChange={async (e) => {
                    await togglePhase.run(phase, e.target.checked);
                    onRefresh();
                  }}
                />
                <span className="mono">{phase}</span>
              </label>
            );
          })}
        </div>
        <p className="text-xs text-base-content/40 mt-2">
          Phases: {PHASES.join(", ")}
        </p>
      </Section>

      <Section title="Exclusions">
        <div className="text-xs mb-2">
          <div className="font-medium mb-1">Excluded hosts</div>
          <div className="mono">
            {(config?.excluded_hosts || []).length
              ? (config?.excluded_hosts || []).join(", ")
              : "—"}
          </div>
          <div className="font-medium mt-2 mb-1">Excluded endpoints</div>
          <div className="mono break-all">
            {(config?.excluded_endpoints || []).length
              ? (config?.excluded_endpoints || []).join(", ")
              : "—"}
          </div>
        </div>
        <div className="flex flex-wrap gap-2 items-end mb-2">
          <input
            className={`${inputClass} mono w-56`}
            value={excludeHost}
            onChange={(e) => setExcludeHost(e.target.value)}
            placeholder="host"
          />
          <button
            className="btn btn-xs"
            disabled={!excludeHost}
            onClick={async () => {
              await excludeH.run();
              onRefresh();
            }}
          >
            Exclude host
          </button>
          <button
            className="btn btn-xs"
            disabled={!excludeHost}
            onClick={async () => {
              await includeH.run();
              onRefresh();
            }}
          >
            Include host
          </button>
        </div>
        <div className="flex flex-wrap gap-2 items-end">
          <input
            className={`${inputClass} mono w-72`}
            value={excludeEndpoint}
            onChange={(e) => setExcludeEndpoint(e.target.value)}
            placeholder="endpoint_id"
          />
          <button
            className="btn btn-xs"
            disabled={!excludeEndpoint}
            onClick={async () => {
              await excludeE.run();
              onRefresh();
            }}
          >
            Exclude endpoint
          </button>
          <button
            className="btn btn-xs"
            disabled={!excludeEndpoint}
            onClick={async () => {
              await includeE.run();
              onRefresh();
            }}
          >
            Include endpoint
          </button>
        </div>
      </Section>
    </div>
  );
}
