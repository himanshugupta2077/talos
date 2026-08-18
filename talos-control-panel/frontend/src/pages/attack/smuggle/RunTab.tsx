import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import type { SmuggleOverview, SmuggleTechnique } from "./shared";
import SmuggleDisclaimer from "./components/SmuggleDisclaimer";

function parseFlowIds(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(/[\s,]+/)) {
    const id = part.trim();
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

export default function RunTab({
  projectId,
  overview,
  techniques,
  onRefresh,
}: {
  projectId: string;
  overview: SmuggleOverview | null;
  techniques: SmuggleTechnique[];
  onRefresh: () => void;
}) {
  const [flowText, setFlowText] = useState("");
  const [technique, setTechnique] = useState("");
  const [lastStdout, setLastStdout] = useState<string | null>(null);

  const flowIds = useMemo(() => parseFlowIds(flowText), [flowText]);
  const techCount = technique
    ? 1
    : techniques.length || overview?.total_techniques || 0;
  const estimate = flowIds.length * techCount;
  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;

  const run = useAction("Run HTTP request smuggling", () =>
    api.post(
      "/api/attack/smuggle/run",
      {
        flows: flowIds,
        technique: technique || undefined,
      },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    const parts = ["talos attack smuggle run"];
    for (const id of flowIds) parts.push(`--flow ${id}`);
    if (technique) parts.push(`--technique ${technique}`);
    return parts.join(" ");
  }, [flowIds, technique]);

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
      <SmuggleDisclaimer />

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            Smuggle jobs already in flight ({overview?.jobs_running ?? 0} running,{" "}
            {overview?.jobs_pending ?? 0} pending). Duplicates are skipped.{" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Flows">
        <p className="text-xs text-base-content/60 mb-2">
          Paste one or more captured flow UUIDs. Or select rows on{" "}
          <Link className="link" to="/flows">
            Flows
          </Link>{" "}
          and run HTTP Request Smuggling from the attack bar.
        </p>
        <textarea
          className="textarea textarea-bordered textarea-sm w-full font-mono text-xs min-h-24"
          placeholder="flow UUID, one per line"
          value={flowText}
          onChange={(e) => setFlowText(e.target.value)}
          disabled={run.running}
        />
        <p className="text-xs text-base-content/50 mt-1">
          {flowIds.length} flow{flowIds.length === 1 ? "" : "s"} · ~{techCount}{" "}
          technique{techCount === 1 ? "" : "s"} each
        </p>
      </Section>

      <Section title="Techniques">
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
              {techniques.length || overview?.total_techniques || 0} CL/TE
              probes · one unique flow each
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
            ~{estimate} job{estimate === 1 ? "" : "s"} from {flowIds.length}{" "}
            flow{flowIds.length === 1 ? "" : "s"} × {techCount} technique
            {techCount === 1 ? "" : "s"}.
          </p>
          <div className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit max-w-full break-all">
            {cliPreview}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {estimate > 50 ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={`Enqueue smuggle jobs for ${flowIds.length} flow(s)?`}
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue smuggle scan"
                )}
              </ConfirmButton>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                disabled={run.running || flowIds.length === 0 || techCount === 0}
                onClick={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue smuggle scan"
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
