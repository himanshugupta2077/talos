import { useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { ConfirmButton, Section } from "../../components/Common";
import ScopeBar, { ScopeType, scopeBody } from "./components/ScopeBar";
import { OPERATOR_SCAN, PHASES } from "./shared";
import type { IvConfig, IvStatus } from "./shared";

export default function RunTab({
  projectId,
  config,
  status,
  onRefresh,
}: {
  projectId: string;
  config: IvConfig | null;
  status: IvStatus | null;
  onRefresh: () => void;
}) {
  const [scopeType, setScopeType] = useState<ScopeType>("none");
  const [scopeValue, setScopeValue] = useState("");
  const [ignoreCache, setIgnoreCache] = useState(false);
  const [includeAuth, setIncludeAuth] = useState(false);
  const [advanced, setAdvanced] = useState(false);

  const autoRunOn = Boolean(Number(config?.auto_run ?? 0)) || Boolean(status?.auto_run);

  const body = () => ({
    ...scopeBody(scopeType, scopeValue),
    ignore_cache: ignoreCache,
    include_auth_artifacts: includeAuth,
  });

  const run = useAction("Run IV", () =>
    api.post("/api/input-validation/run", body(), { project_id: projectId }),
  );
  const resume = useAction("Resume IV", () =>
    api.post("/api/input-validation/resume", scopeBody(scopeType, scopeValue), {
      project_id: projectId,
    }),
  );
  const setAutoRun = useAction("Set IV auto-run", (value: boolean) =>
    api.post(
      "/api/input-validation/config",
      { auto_run: value },
      { project_id: projectId },
    ),
  );
  const clearCache = useAction("Reset IV scan", () =>
    api.post("/api/input-validation/clear-cache", scopeBody(scopeType, scopeValue), {
      project_id: projectId,
    }),
  );
  const exportCsv = useAction("Export IV CSV", () =>
    api.post("/api/input-validation/export/csv", {}, { project_id: projectId }),
  );
  const runPhase = useAction("Run IV phase", (phase: string) =>
    api.post(
      `/api/input-validation/phase/${phase}`,
      {
        ...scopeBody(scopeType, scopeValue),
        ignore_cache: ignoreCache,
      },
      { project_id: projectId },
    ),
  );

  const jobs =
    (status?.running ?? 0) + (status?.queued ?? 0) > 0;

  return (
    <div className="space-y-4">
      {jobs && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            Jobs in flight (running {status?.running ?? 0}, queued {status?.queued ?? 0}).
            {" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Auto-run">
        <div className="panel p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="max-w-xl">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`badge badge-sm ${autoRunOn ? "badge-success" : "badge-ghost"}`}
                >
                  {autoRunOn ? "Enabled" : "Disabled"}
                </span>
                <span className="badge badge-outline badge-sm">
                  scan: {OPERATOR_SCAN}
                </span>
              </div>
              <p className="text-xs text-base-content/60 leading-relaxed">
                When enabled, the scheduler characterizes every unique in-scope
                parameter as traffic arrives. Duplicate browser captures of the
                same request collapse to one unique endpoint and one parameter
                plan. Profiles and candidates are produced automatically after
                probes — no separate synthesize step.
              </p>
            </div>
            <div className="shrink-0">
              {autoRunOn ? (
                <button
                  className="btn btn-sm"
                  disabled={setAutoRun.running}
                  onClick={async () => {
                    await setAutoRun.run(false);
                    onRefresh();
                  }}
                >
                  Disable auto-run
                </button>
              ) : (
                <button
                  className="btn btn-sm btn-primary"
                  disabled={setAutoRun.running}
                  onClick={async () => {
                    await setAutoRun.run(true);
                    onRefresh();
                  }}
                >
                  Enable auto-run
                </button>
              )}
            </div>
          </div>
        </div>
      </Section>

      <Section title="Scope">
        <ScopeBar
          projectId={projectId}
          scopeType={scopeType}
          scopeValue={scopeValue}
          onTypeChange={setScopeType}
          onValueChange={setScopeValue}
        />
      </Section>

      <Section title="Run">
        <p className="text-xs text-base-content/50 mb-3">
          Runs the unified IV scan (standard characterization plus adaptive
          deep follow-ups) for every unique in-scope parameter. Not an
          exhaustive brute-force matrix. ignore-cache and Clear cache wipe
          probe results and profiles for this scope so the planner starts at
          baseline again. Candidates appear on the Candidates tab after
          analysis finishes.
        </p>
        <div className="flex flex-wrap gap-3 items-center mb-3">
          <label className="label cursor-pointer gap-2 py-0">
            <input
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={ignoreCache}
              onChange={(e) => setIgnoreCache(e.target.checked)}
            />
            <span className="label-text text-xs">ignore-cache (re-run from baseline)</span>
          </label>
          <label className="label cursor-pointer gap-2 py-0">
            <input
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={includeAuth}
              onChange={(e) => setIncludeAuth(e.target.checked)}
            />
            <span className="label-text text-xs">include auth artifacts</span>
          </label>
        </div>

        <div className="flex flex-wrap gap-2 mb-3">
          <button
            className="btn btn-sm btn-primary"
            disabled={run.running}
            onClick={async () => {
              await run.run();
              onRefresh();
            }}
          >
            Run
          </button>
          <button
            className="btn btn-sm"
            disabled={resume.running}
            onClick={async () => {
              await resume.run();
              onRefresh();
            }}
          >
            Resume
          </button>
          <ConfirmButton
            className="btn btn-sm btn-ghost"
            confirmText="Reset IV probes, profiles, and cache for this scope? Next Run starts at baseline."
            onConfirm={async () => {
              await clearCache.run();
              onRefresh();
            }}
          >
            Clear cache
          </ConfirmButton>
          <button className="btn btn-sm" onClick={() => exportCsv.run()}>
            Export CSV
          </button>
        </div>

        <button
          type="button"
          className="btn btn-ghost btn-xs mb-2"
          onClick={() => setAdvanced((v) => !v)}
        >
          {advanced ? "Hide" : "Show"} advanced phase shortcuts
        </button>

        {advanced && (
          <div>
            <p className="text-xs text-base-content/50 mb-2">
              Prefer adaptive planner via Run or auto-run. Phase shortcuts
              enqueue one phase only (bypass full plan).
            </p>
            <div className="flex flex-wrap gap-2">
              {PHASES.map((p) => (
                <button
                  key={p}
                  className="btn btn-xs"
                  onClick={async () => {
                    await runPhase.run(p);
                    onRefresh();
                  }}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </Section>
    </div>
  );
}
