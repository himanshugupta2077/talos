import { useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { ConfirmButton, Section } from "../../components/Common";
import ScopeBar, { ScopeType, scopeBody } from "./components/ScopeBar";
import { BUDGETS, PHASES, selectClass } from "./shared";
import type { IvStatus } from "./shared";

export default function RunTab({
  projectId,
  budget,
  setBudget,
  status,
  onRefresh,
}: {
  projectId: string;
  budget: string;
  setBudget: (b: string) => void;
  status: IvStatus | null;
  onRefresh: () => void;
}) {
  const [scopeType, setScopeType] = useState<ScopeType>("none");
  const [scopeValue, setScopeValue] = useState("");
  const [ignoreCache, setIgnoreCache] = useState(false);
  const [includeAuth, setIncludeAuth] = useState(false);
  const [advanced, setAdvanced] = useState(false);

  const body = () => ({
    ...scopeBody(scopeType, scopeValue),
    ignore_cache: ignoreCache,
    include_auth_artifacts: includeAuth,
    budget,
  });

  const run = useAction("Run IV", () =>
    api.post("/api/input-validation/run", body(), { project_id: projectId }),
  );
  const resume = useAction("Resume IV", () =>
    api.post("/api/input-validation/resume", scopeBody(scopeType, scopeValue), {
      project_id: projectId,
    }),
  );
  const synthesize = useAction("Synthesize", () =>
    api.post(
      "/api/input-validation/synthesize",
      {
        host: scopeType === "host" ? scopeValue : undefined,
      },
      { project_id: projectId },
    ),
  );
  const clearCache = useAction("Clear IV cache", () =>
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
        <div className="flex flex-wrap gap-3 items-center mb-3">
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
          <label className="label cursor-pointer gap-2 py-0">
            <input
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={ignoreCache}
              onChange={(e) => setIgnoreCache(e.target.checked)}
            />
            <span className="label-text text-xs">ignore-cache</span>
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
            Run ({budget})
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
          <button
            className="btn btn-sm"
            disabled={synthesize.running}
            onClick={async () => {
              await synthesize.run();
              onRefresh();
            }}
          >
            Synthesize
          </button>
          <ConfirmButton
            className="btn btn-sm btn-ghost"
            confirmText="Clear IV cache for this scope?"
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
              Prefer adaptive planner via Run. Phase shortcuts enqueue one phase only
              (bypass full plan).
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
