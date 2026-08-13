import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import type { CorsOverview, CorsTechnique } from "./shared";
import { estimateJobs } from "./shared";
import CorsDisclaimer from "./components/CorsDisclaimer";

export default function RunTab({
  projectId,
  overview,
  techniques,
  onRefresh,
}: {
  projectId: string;
  overview: CorsOverview | null;
  techniques: CorsTechnique[];
  onRefresh: () => void;
}) {
  const [technique, setTechnique] = useState("");
  const [lastStdout, setLastStdout] = useState<string | null>(null);

  const candidates = overview?.candidates ?? 0;
  const techCount = technique ? 1 : techniques.length || overview?.total_techniques || 0;
  const estimate = estimateJobs(candidates, techCount);
  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;

  const run = useAction("Run CORS attack", () =>
    api.post(
      "/api/attack/cors/run",
      { technique: technique || undefined },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    if (technique) return `talos attack cors run --technique ${technique}`;
    return "talos attack cors run";
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
      <CorsDisclaimer />

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            CORS jobs already in flight ({overview?.jobs_running ?? 0} running,{" "}
            {overview?.jobs_pending ?? 0} pending). Duplicates are skipped.{" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Technique">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <button
            type="button"
            className={`panel p-3 text-left text-xs ${
              technique === "" ? "ring-1 ring-primary" : ""
            }`}
            onClick={() => setTechnique("")}
            disabled={run.running}
          >
            <div className="font-medium">All techniques</div>
            <div className="text-base-content/50">
              {techniques.length || overview?.total_techniques || 0} Origin
              payloads · one unique flow each
            </div>
          </button>
          {techniques.map((t) => (
            <button
              key={t.name}
              type="button"
              className={`panel p-3 text-left text-xs ${
                technique === t.name ? "ring-1 ring-primary" : ""
              }`}
              onClick={() => setTechnique(t.name)}
              disabled={run.running}
            >
              <div className="font-medium mono">{t.name}</div>
              <div className="text-base-content/50">{t.description}</div>
              <div className="text-base-content/40 mt-1">{t.family}</div>
            </button>
          ))}
        </div>
      </Section>

      <Section title="Enqueue">
        <div className="panel p-4 space-y-3">
          <p className="text-sm">
            ~{estimate} job{estimate === 1 ? "" : "s"} from {candidates}{" "}
            in-scope 200 OK candidate{candidates === 1 ? "" : "s"} × {techCount}{" "}
            technique{techCount === 1 ? "" : "s"}.
          </p>
          <div className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit">
            {cliPreview}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {estimate > 50 ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={`Enqueue up to ~${estimate} CORS jobs?`}
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue CORS attack"
                )}
              </ConfirmButton>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                disabled={run.running || candidates === 0 || techCount === 0}
                onClick={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue CORS attack"
                )}
              </button>
            )}
            <Link to="/scheduler" className="btn btn-sm btn-ghost">
              Scheduler
            </Link>
            <Link to="/flows" className="btn btn-sm btn-ghost">
              Flows
            </Link>
          </div>
          <p className="text-xs text-base-content/50">
            Same flow as other attack modules: enqueue{" "}
            <span className="mono">cors_attack</span> jobs. The scheduler
            executes each probe as a unique replay flow. Results appear as jobs
            complete.
          </p>
        </div>
      </Section>

      {lastStdout && (
        <Section title="Last run output">
          <pre className="panel p-3 text-xs mono whitespace-pre-wrap max-h-64 overflow-auto">
            {lastStdout}
          </pre>
        </Section>
      )}
    </div>
  );
}
