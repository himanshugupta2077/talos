import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { Module, Role, StepsResponse } from "../../../types";
import type { BacOverview, BacScopeMode, BacTechnique } from "./shared";
import {
  buildCliPreview,
  estimateJobs,
  parseUuidList,
  variantCountForTechniques,
} from "./shared";
import BacDisclaimer from "./components/BacDisclaimer";
import TechniqueCards from "./components/TechniqueCards";
import JobEstimate from "./components/JobEstimate";
import ScopeControls from "./components/ScopeControls";

export default function RunTab({
  projectId,
  overview,
  techniques,
  totalVariants,
  onRefresh,
}: {
  projectId: string;
  overview: BacOverview | null;
  techniques: BacTechnique[];
  totalVariants: number;
  onRefresh: () => void;
}) {
  // Empty selected = all techniques (default product behaviour)
  const [selected, setSelected] = useState<string[]>([]);
  const [searchParams] = useSearchParams();
  const [role, setRole] = useState(searchParams.get("role") || "");
  const [scopeMode, setScopeMode] = useState<BacScopeMode>("project");
  const [moduleName, setModuleName] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [autoGenerate, setAutoGenerate] = useState(false);
  const [excludeEndpointText, setExcludeEndpointText] = useState("");
  const [roles, setRoles] = useState<Role[]>([]);
  const [modules, setModules] = useState<Module[]>([]);
  const [lastStdout, setLastStdout] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<{ roles: Role[] }>("/api/roles", { project_id: projectId })
      .then((r) => setRoles(r.roles || []))
      .catch(() => setRoles([]));
    api
      .get<{ modules: Module[] }>("/api/modules", { project_id: projectId })
      .then((r) => setModules(r.modules || []))
      .catch(() => setModules([]));
  }, [projectId]);

  const flowCount = overview?.candidates?.flow_count ?? 0;
  const candidateCount = overview?.candidates?.candidate_count ?? 0;
  const variants = variantCountForTechniques(
    techniques,
    selected,
    totalVariants || overview?.total_variants || 0
  );
  const estimate = estimateJobs(flowCount, variants);
  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;
  const authFailed = (overview?.auth?.failed_count ?? 0) > 0;

  const moduleArg = scopeMode === "module" ? moduleName || undefined : undefined;
  const endpointArg =
    scopeMode === "endpoint" ? endpointId || undefined : undefined;
  const excludeEndpoints = useMemo(
    () => parseUuidList(excludeEndpointText),
    [excludeEndpointText]
  );

  const scopeReady =
    scopeMode === "project" ||
    (scopeMode === "module" && !!moduleName) ||
    (scopeMode === "endpoint" && !!endpointId);

  const run = useAction("Run BAC attack", () =>
    api.post(
      "/api/attack/bac/run",
      {
        techniques: selected.length > 0 ? selected : undefined,
        role: role || undefined,
        module: moduleArg,
        endpoint: endpointArg,
        exclude_endpoints: excludeEndpoints.length > 0 ? excludeEndpoints : undefined,
        auto_generate: autoGenerate,
      },
      { project_id: projectId }
    )
  );

  const cliPreviews = useMemo(
    () =>
      buildCliPreview({
        techniques: selected,
        role: role || undefined,
        module: moduleArg,
        endpoint: endpointArg,
        excludeEndpoints,
        autoGenerate,
      }),
    [selected, role, moduleArg, endpointArg, excludeEndpoints, autoGenerate]
  );

  const techniqueLabel =
    selected.length === 0
      ? ""
      : selected.length === 1
        ? selected[0]
        : `${selected.length} techniques`;

  const doRun = async () => {
    try {
      const res = (await run.run()) as StepsResponse | undefined;
      const steps = res?.steps || [];
      // Concatenate stdout from multi-technique steps for inline review
      const chunks = steps
        .map((s) => (s.stdout || s.stderr || "").trim())
        .filter(Boolean);
      setLastStdout(chunks.length ? chunks.join("\n---\n") : null);
      onRefresh();
    } catch {
      /* failure already logged by useAction */
    }
  };

  return (
    <div className="space-y-4">
      <BacDisclaimer authMode={overview?.auth_model?.mode} />

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            BAC jobs already in flight (
            {overview?.jobs_running ?? 0} running,{" "}
            {overview?.jobs_pending ?? 0} pending). New enqueues skip exact
            duplicates.{" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Techniques">
        <TechniqueCards
          techniques={techniques}
          totalVariants={totalVariants || overview?.total_variants || 0}
          selected={selected}
          onChange={setSelected}
          disabled={run.running}
        />
      </Section>

      <Section title="Scope & auth">
        <div className="panel p-4">
          <ScopeControls
            roles={roles}
            modules={modules}
            role={role}
            scopeMode={scopeMode}
            moduleName={moduleName}
            endpointId={endpointId}
            autoGenerate={autoGenerate}
            onRole={setRole}
            onScopeMode={(m) => {
              setScopeMode(m);
              if (m !== "module") setModuleName("");
              if (m !== "endpoint") setEndpointId("");
            }}
            onModule={setModuleName}
            onEndpoint={setEndpointId}
            onAutoGenerate={setAutoGenerate}
            disabled={run.running}
          />

          <div className="mt-4 pt-3 border-t border-base-300">
            <label className="form-control w-full">
              <span className="label-text text-xs">
                Exclude endpoints{" "}
                <span className="text-base-content/40">
                  (this run only · --exclude-endpoint)
                </span>
              </span>
              <textarea
                className="textarea textarea-bordered textarea-xs w-full font-mono mt-1 min-h-20"
                value={excludeEndpointText}
                disabled={run.running}
                placeholder="endpoint UUID, one per line or comma-separated"
                onChange={(e) => setExcludeEndpointText(e.target.value)}
              />
            </label>
            <p className="text-[10px] text-base-content/40 leading-snug mt-1 max-w-2xl">
              Skip these endpoints for this enqueue only. Does not change
              endpoint policy. Copy UUIDs from{" "}
              <Link className="link" to="/endpoints">
                Endpoints
              </Link>
              {excludeEndpoints.length > 0
                ? `. ${excludeEndpoints.length} endpoint${excludeEndpoints.length === 1 ? "" : "s"} excluded.`
                : "."}
            </p>
          </div>
        </div>
      </Section>

      <Section title="Enqueue">
        <div className="panel p-4 space-y-3">
          <JobEstimate
            flowCount={flowCount}
            variantCount={variants}
            candidateCount={candidateCount}
            techniqueLabel={techniqueLabel}
            authFailed={authFailed}
            excludedEndpointCount={excludeEndpoints.length}
          />

          <div className="space-y-1">
            {cliPreviews.slice(0, 4).map((line) => (
              <div
                key={line}
                className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit max-w-full overflow-x-auto"
              >
                {line}
              </div>
            ))}
            {cliPreviews.length > 4 && (
              <div className="text-[10px] text-base-content/40">
                +{cliPreviews.length - 4} more technique
                {cliPreviews.length - 4 === 1 ? "" : "s"}…
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {estimate > 50 ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={`Enqueue up to ~${estimate} BAC jobs?`}
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : selected.length === 0 ? (
                  "Enqueue all techniques"
                ) : (
                  `Enqueue ${selected.length} technique${selected.length === 1 ? "" : "s"}`
                )}
              </ConfirmButton>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                disabled={
                  run.running ||
                  candidateCount === 0 ||
                  variants === 0 ||
                  !scopeReady
                }
                onClick={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : selected.length === 0 ? (
                  "Enqueue all techniques"
                ) : (
                  `Enqueue ${selected.length} technique${selected.length === 1 ? "" : "s"}`
                )}
              </button>
            )}
            <Link to="/scheduler" className="btn btn-sm btn-ghost">
              Scheduler
            </Link>
            <Link to="/access" className="btn btn-sm btn-ghost">
              Access
            </Link>
            <Link to="/auth" className="btn btn-sm btn-ghost">
              Auth
            </Link>
          </div>

          {!scopeReady && (
            <p className="text-xs text-warning">
              {scopeMode === "module"
                ? "Select a module for --module scope."
                : "Enter an endpoint UUID for --endpoint scope."}
            </p>
          )}

          <p className="text-xs text-base-content/50">
            Enqueue is usually quick; execution happens on the scheduler. Results
            appear under the Results tab as jobs complete.{" "}
            <span className="mono">POSSIBLE_BAC</span> also creates findings.
          </p>
        </div>
      </Section>

      {lastStdout && (
        <Section title="Last run output">
          <pre className="panel p-3 text-xs mono whitespace-pre-wrap max-h-64 overflow-auto">
            {lastStdout}
          </pre>
          <p className="text-xs text-base-content/50 mt-2">
            Full steps also appear in the Console drawer.{" "}
            <Link className="link" to="/scheduler">
              Monitor jobs →
            </Link>
          </p>
        </Section>
      )}
    </div>
  );
}
