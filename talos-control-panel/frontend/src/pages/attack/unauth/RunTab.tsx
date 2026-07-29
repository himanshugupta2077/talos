import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import type { UnauthOverview, UnauthTechnique } from "./shared";
import {
  estimateJobs,
  recipeCountForTechnique,
} from "./shared";
import UnauthDisclaimer from "./components/UnauthDisclaimer";
import TechniqueCards from "./components/TechniqueCards";
import JobEstimate from "./components/JobEstimate";

export default function RunTab({
  projectId,
  overview,
  techniques,
  totalRecipes,
  onRefresh,
}: {
  projectId: string;
  overview: UnauthOverview | null;
  techniques: UnauthTechnique[];
  totalRecipes: number;
  onRefresh: () => void;
}) {
  const [technique, setTechnique] = useState("");
  const [lastStdout, setLastStdout] = useState<string | null>(null);

  const testable = overview?.testable_endpoints ?? 0;
  const recipes = recipeCountForTechnique(techniques, technique, totalRecipes);
  const estimate = estimateJobs(testable, recipes);
  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;

  const run = useAction("Run unauth attack", () =>
    api.post(
      "/api/attack/unauth/run",
      { technique: technique || undefined },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    if (technique) {
      return `talos attack unauth run --technique ${technique}`;
    }
    return "talos attack unauth run";
  }, [technique]);

  const doRun = async () => {
    try {
      const res = (await run.run()) as StepsResponse | undefined;
      const steps = res?.steps || [];
      const last = steps[steps.length - 1];
      setLastStdout(last?.stdout?.trim() || last?.stderr?.trim() || null);
      onRefresh();
    } catch {
      /* failure already logged by useAction */
    }
  };

  return (
    <div className="space-y-4">
      <UnauthDisclaimer />

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            Unauth jobs already in flight (
            {overview?.jobs_running ?? 0} running,{" "}
            {overview?.jobs_pending ?? 0} pending). New enqueues skip exact
            duplicates.{" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Technique">
        <TechniqueCards
          techniques={techniques}
          totalRecipes={totalRecipes}
          selected={technique}
          onSelect={setTechnique}
          disabled={run.running}
        />
      </Section>

      <Section title="Enqueue">
        <div className="panel p-4 space-y-3">
          <JobEstimate
            testable={testable}
            recipes={recipes}
            techniqueLabel={technique}
          />

          <div className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit">
            {cliPreview}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {estimate > 50 ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={`Enqueue up to ~${estimate} unauth jobs?`}
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue unauth attack"
                )}
              </ConfirmButton>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                disabled={run.running || testable === 0 || recipes === 0}
                onClick={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue unauth attack"
                )}
              </button>
            )}
            <Link to="/scheduler" className="btn btn-sm btn-ghost">
              Scheduler
            </Link>
            <Link to="/endpoints" className="btn btn-sm btn-ghost">
              Endpoints
            </Link>
          </div>

          <p className="text-xs text-base-content/50">
            Enqueue is usually quick; execution happens on the scheduler. Results
            appear under the Results tab as jobs complete.
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
