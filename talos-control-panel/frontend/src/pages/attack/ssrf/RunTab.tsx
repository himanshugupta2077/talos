import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import {
  FAMILIES,
  type SsrfOverview,
  type SsrfTechnique,
} from "./shared";
import SsrfDisclaimer from "./components/SsrfDisclaimer";

interface SsrfPoint {
  flow_id?: string;
  location: string;
  name: string;
  original?: string;
  surface_kind?: string;
}

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
  overview: SsrfOverview | null;
  techniques: SsrfTechnique[];
  onRefresh: () => void;
}) {
  const [flowText, setFlowText] = useState("");
  const [paramName, setParamName] = useState("");
  const [family, setFamily] = useState("");
  const [technique, setTechnique] = useState("");
  const [highPriority, setHighPriority] = useState(true);
  const [collaborator, setCollaborator] = useState("");
  const [lastStdout, setLastStdout] = useState<string | null>(null);
  const [points, setPoints] = useState<SsrfPoint[]>([]);

  const flowIds = useMemo(() => parseFlowIds(flowText), [flowText]);
  const collabHost = collaborator.trim();
  const visibleTechniques = techniques.filter((t) => {
    if (family && t.family !== family) return false;
    if (!collabHost && (t.requires_collaborator || t.family === "oast")) return false;
    return true;
  });
  const techCount = technique ? 1 : visibleTechniques.length;
  const estimate = flowIds.length * techCount;
  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;

  useEffect(() => {
    if (!projectId || flowIds.length === 0) {
      setPoints([]);
      return;
    }
    let cancelled = false;
    api
      .get<{ points?: SsrfPoint[] }>("/api/attack/ssrf/points", {
        project_id: projectId,
        flow: flowIds.join(","),
      })
      .then((r) => {
        if (!cancelled) setPoints(r.points || []);
      })
      .catch(() => {
        if (!cancelled) setPoints([]);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, flowIds]);

  const uniqueParams = useMemo(() => {
    const seen = new Set<string>();
    const out: SsrfPoint[] = [];
    for (const point of points) {
      const key = `${point.location}:${point.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(point);
    }
    return out;
  }, [points]);

  const run = useAction("Run ssrf attack", () =>
    api.post(
      "/api/attack/ssrf/run",
      {
        flows: flowIds,
        param: paramName.trim() || undefined,
        technique: technique || undefined,
        family: family || undefined,
        collaborator: collaborator.trim() || undefined,
        high_priority: highPriority,
      },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    const parts = ["talos attack ssrf run"];
    for (const id of flowIds) parts.push(`--flow ${id}`);
    if (paramName.trim()) parts.push(`--param ${paramName.trim()}`);
    if (technique) parts.push(`--technique ${technique}`);
    else if (family) parts.push(`--family ${family}`);
    if (collaborator.trim()) parts.push(`--collaborator ${collaborator.trim()}`);
    parts.push(highPriority ? "--high-priority" : "--no-high-priority");
    return parts.join(" ");
  }, [flowIds, paramName, technique, family, collaborator, highPriority]);

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
      <SsrfDisclaimer />

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            Path-traversal jobs already in flight ({overview?.jobs_running ?? 0}{" "}
            running, {overview?.jobs_pending ?? 0} pending). Duplicates are skipped.{" "}
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
          and run SSRF from the attack bar.
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
          payload{techCount === 1 ? "" : "s"} each
          {paramName.trim()
            ? ` on ${paramName.trim()}`
            : " (times every entry point on the request)"}
        </p>
      </Section>

      <Section title="Parameter">
        <p className="text-xs text-base-content/60 mb-2">
          Optional. Leave as all entry points, or scan one query key, JSON path,
          form field, path parameter, or multipart filename on the selected flow.
        </p>
        <div className="flex flex-wrap gap-2 items-center">
          <select
            className="select select-sm select-bordered"
            value={
              uniqueParams.some(
                (p) => p.name === paramName || `${p.location}:${p.name}` === paramName
              )
                ? paramName
                : paramName
                  ? "__custom"
                  : ""
            }
            onChange={(e) => {
              const next = e.target.value;
              if (next === "__custom") return;
              setParamName(next);
            }}
            disabled={run.running}
          >
            <option value="">All entry points</option>
            {paramName &&
              !uniqueParams.some(
                (p) =>
                  p.name === paramName ||
                  `${p.location}:${p.name}` === paramName
              ) && <option value="__custom">Custom: {paramName}</option>}
            {uniqueParams.map((point) => {
              const value = `${point.location}:${point.name}`;
              return (
                <option key={value} value={value}>
                  {value}
                  {point.original ? ` = ${point.original.slice(0, 40)}` : ""}
                </option>
              );
            })}
          </select>
          <input
            className="input input-sm input-bordered font-mono text-xs min-w-48"
            placeholder="or type name / location:name"
            value={paramName}
            onChange={(e) => setParamName(e.target.value)}
            disabled={run.running}
          />
        </div>
        {flowIds.length > 0 && uniqueParams.length === 0 && (
          <p className="text-xs text-base-content/40 mt-1">
            No entry points loaded yet for the pasted flow(s).
          </p>
        )}
      </Section>

      <Section title="Burp Collaborator">
        <p className="text-xs text-base-content/60 mb-2">
          Optional. Paste a Burp Collaborator payload URL or host
          (<span className="mono">abc.oastify.com</span>). OAST payloads get a
          unique subdomain per probe. Talos does not poll Collaborator — check
          Burp for DNS/HTTP hits. In-band confirmation still uses the target
          HTTP response.
        </p>
        <input
          className="input input-sm input-bordered font-mono text-xs w-full max-w-xl"
          placeholder="abc.oastify.com or https://abc.oastify.com"
          value={collaborator}
          onChange={(e) => setCollaborator(e.target.value)}
          disabled={run.running}
        />
      </Section>

      <Section title="Payloads">
        <div className="flex flex-wrap gap-2 mb-3">
          <button
            type="button"
            className={`btn btn-xs ${family === "" && technique === "" ? "btn-primary" : ""}`}
            onClick={() => {
              setFamily("");
              setTechnique("");
            }}
            disabled={run.running}
          >
            All families
          </button>
          {FAMILIES.map((name) => (
            <button
              key={name}
              type="button"
              className={`btn btn-xs ${family === name && !technique ? "btn-primary" : ""}`}
              onClick={() => {
                setFamily(name);
                setTechnique("");
              }}
              disabled={run.running || (name === "oast" && !collabHost)}
              title={
                name === "oast" && !collabHost
                  ? "Paste a Collaborator URL first"
                  : undefined
              }
            >
              {name}
            </button>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {visibleTechniques.map((t) => (
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
              <div className="text-base-content/40 mt-1">
                {t.family}
                {t.sink && t.sink !== "generic" ? ` · ${t.sink}` : ""}
                {t.inject_mode && t.inject_mode !== "replace"
                  ? ` · ${t.inject_mode}`
                  : ""}
              </div>
            </button>
          ))}
        </div>
      </Section>

      <Section title="Enqueue">
        <div className="panel p-4 space-y-3">
          <p className="text-sm">
            ~{estimate}+ job{estimate === 1 ? "" : "s"} (one per entry point ×
            payload on each selected flow).
          </p>
          <div className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit max-w-full break-all">
            {cliPreview}
          </div>
          <label className="label cursor-pointer justify-start gap-2 py-0">
            <input
              type="checkbox"
              className="checkbox checkbox-xs checkbox-primary"
              checked={highPriority}
              onChange={(e) => setHighPriority(e.target.checked)}
              disabled={run.running}
            />
            <span className="label-text text-xs">
              High priority — run these jobs before other pending work
            </span>
          </label>
          <div className="flex flex-wrap items-center gap-2">
            {estimate > 50 ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={`Enqueue ssrf jobs for ${flowIds.length} flow(s)?`}
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  "Enqueue ssrf scan"
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
                  "Enqueue ssrf scan"
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
