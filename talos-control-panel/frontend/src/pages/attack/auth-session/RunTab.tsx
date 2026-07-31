import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import {
  CONFIRM_ESTIMATE_THRESHOLD,
  KNOWN_FAMILIES,
  RIGHT_NOW_MAX,
  inputClass,
  selectClass,
  type AuthSessionBinding,
  type AuthSessionOverview,
} from "./shared";
import AuthSessionDisclaimer from "./components/AuthSessionDisclaimer";

export default function RunTab({
  projectId,
  overview,
  onRefresh,
}: {
  projectId: string;
  overview: AuthSessionOverview | null;
  onRefresh: () => void;
}) {
  const [bindings, setBindings] = useState<AuthSessionBinding[]>([]);
  const [endpointId, setEndpointId] = useState("");
  const [bindingId, setBindingId] = useState("");
  const [family, setFamily] = useState("");
  const [testId, setTestId] = useState("");
  const [candidateIds, setCandidateIds] = useState("");
  const [rightNow, setRightNow] = useState(false);
  const [estimate, setEstimate] = useState<number | null>(null);
  const [estimateLoading, setEstimateLoading] = useState(false);
  const [lastStdout, setLastStdout] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<{ items: AuthSessionBinding[] }>("/api/attack/auth-session/bindings", {
        project_id: projectId,
      })
      .then((r) => setBindings(r.items || []))
      .catch(() => setBindings([]));
  }, [projectId]);

  const parseCandidateIds = useCallback(() => {
    return candidateIds
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }, [candidateIds]);

  const loadEstimate = useCallback(() => {
    setEstimateLoading(true);
    const params: Record<string, string | undefined> = {
      project_id: projectId,
    };
    if (endpointId.trim()) params.endpoint_id = endpointId.trim();
    if (bindingId) params.binding_id = bindingId;
    if (family) params.family = family;
    if (testId.trim()) params.test_id = testId.trim();
    const cids = parseCandidateIds();
    // API accepts repeated candidate; send comma-joined (backend parses CSV)
    if (cids.length) params.candidate = cids.join(",");

    api
      .get<{ approved_matching: number }>(
        "/api/attack/auth-session/run-estimate",
        params
      )
      .then((r) => setEstimate(r.approved_matching ?? 0))
      .catch(() => setEstimate(null))
      .finally(() => setEstimateLoading(false));
  }, [projectId, endpointId, bindingId, family, testId, parseCandidateIds]);

  useEffect(() => {
    loadEstimate();
  }, [loadEstimate]);

  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;
  const e = estimate ?? overview?.estimated_jobs_approved ?? 0;
  const rightNowDisabled = rightNow && e > RIGHT_NOW_MAX;
  const needsConfirm = e > CONFIRM_ESTIMATE_THRESHOLD || rightNow;

  const run = useAction("Run auth-session attack", () =>
    api.post(
      "/api/attack/auth-session/run",
      {
        endpoint_id: endpointId.trim() || undefined,
        binding_id: bindingId || undefined,
        families: family ? [family] : undefined,
        test_ids: testId.trim() ? [testId.trim()] : undefined,
        candidate_ids: parseCandidateIds().length
          ? parseCandidateIds()
          : undefined,
        right_now: rightNow,
      },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    const parts = ["talos attack auth-session run"];
    for (const id of parseCandidateIds()) {
      parts.push(`--candidate ${id}`);
    }
    if (endpointId.trim()) parts.push(`--endpoint ${endpointId.trim()}`);
    if (testId.trim()) parts.push(`--test-id ${testId.trim()}`);
    if (family) parts.push(`--family ${family}`);
    if (bindingId) parts.push(`--binding ${bindingId}`);
    if (rightNow) parts.push("--right-now");
    return parts.join(" ");
  }, [endpointId, bindingId, family, testId, rightNow, parseCandidateIds]);

  const doRun = async () => {
    try {
      const res = (await run.run()) as StepsResponse & {
        estimate?: number;
        timeout_seconds?: number;
      };
      const steps = res?.steps || [];
      const last = steps[steps.length - 1];
      setLastStdout(last?.stdout?.trim() || last?.stderr?.trim() || null);
      onRefresh();
      loadEstimate();
    } catch {
      /* logged by useAction */
    }
  };

  return (
    <div className="space-y-4">
      <AuthSessionDisclaimer />

      <div className="alert text-xs py-2 bg-base-200 border border-base-300">
        <span>
          <strong>Only approved candidates enqueue.</strong> Pending must be
          approved on the Candidates tab first. Each approved test is one{" "}
          <span className="mono">auth_session_attack</span> job and one outbound
          HTTP request.
        </span>
      </div>

      {jobsInFlight && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            Auth-session jobs already in flight (
            {overview?.jobs_running ?? 0} running,{" "}
            {overview?.jobs_pending ?? 0} pending).{" "}
            <Link className="link" to="/scheduler">
              Open Scheduler
            </Link>
          </span>
        </div>
      )}

      <Section title="Scope filters">
        <div className="panel p-4 space-y-3">
          <p className="text-xs text-base-content/60">
            Filters narrow which <strong>approved</strong> candidates run.
            Leave empty to run all approved in the project.
          </p>
          <div className="flex flex-wrap items-end gap-2">
            <label className="form-control">
              <span className="label-text text-xs">Binding</span>
              <select
                className={selectClass}
                value={bindingId}
                onChange={(e) => setBindingId(e.target.value)}
              >
                <option value="">All</option>
                {bindings.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.location}:{b.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="form-control">
              <span className="label-text text-xs">Family</span>
              <select
                className={selectClass}
                value={family}
                onChange={(e) => setFamily(e.target.value)}
              >
                <option value="">All</option>
                {KNOWN_FAMILIES.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </label>
            <label className="form-control min-w-[10rem]">
              <span className="label-text text-xs">Endpoint UUID</span>
              <input
                className={`${inputClass} mono`}
                value={endpointId}
                onChange={(e) => setEndpointId(e.target.value)}
                placeholder="optional"
              />
            </label>
            <label className="form-control min-w-[8rem]">
              <span className="label-text text-xs">test_id</span>
              <input
                className={`${inputClass} mono`}
                value={testId}
                onChange={(e) => setTestId(e.target.value)}
                placeholder="optional"
              />
            </label>
            <label className="form-control min-w-[14rem] flex-1">
              <span className="label-text text-xs">
                Candidate UUIDs (space/comma separated)
              </span>
              <input
                className={`${inputClass} mono w-full`}
                value={candidateIds}
                onChange={(e) => setCandidateIds(e.target.value)}
                placeholder="optional subset"
              />
            </label>
          </div>
        </div>
      </Section>

      <Section title="Enqueue / right-now">
        <div className="panel p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="text-sm">
              <span className="text-base-content/50 text-xs block mb-0.5">
                Approved matching scope
              </span>
              <span className="font-semibold tabular-nums text-lg">
                {estimateLoading ? "…" : e}
              </span>
              <button
                type="button"
                className="btn btn-ghost btn-xs ml-2"
                onClick={loadEstimate}
              >
                refresh
              </button>
            </div>
            <label className="label cursor-pointer gap-2">
              <input
                type="checkbox"
                className="checkbox checkbox-sm"
                checked={rightNow}
                onChange={(e) => setRightNow(e.target.checked)}
              />
              <span className="label-text text-xs">
                Right now (bypass scheduler; sequential HTTP)
              </span>
            </label>
          </div>

          {rightNow && (
            <div className="alert alert-warning text-xs py-2">
              <span>
                <strong>Elevated outbound risk.</strong> Right-now executes
                immediately in-process. Max {RIGHT_NOW_MAX} approved in scope —
                larger batches must enqueue without right-now.
              </span>
            </div>
          )}

          {rightNowDisabled && (
            <div className="alert alert-error text-xs py-2">
              Right-now refused: {e} approved (limit {RIGHT_NOW_MAX}). Uncheck
              right-now to enqueue via the scheduler.
            </div>
          )}

          <div className="text-xs mono text-base-content/50 bg-base-200/50 rounded px-2 py-1.5 w-fit max-w-full break-all">
            {cliPreview}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {needsConfirm && !rightNowDisabled ? (
              <ConfirmButton
                className="btn btn-sm btn-primary"
                confirmText={
                  rightNow
                    ? `Execute ${e} approved candidate(s) right now against the live target?`
                    : `Enqueue ~${e} auth-session job(s)?`
                }
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : rightNow ? (
                  "Run right now"
                ) : (
                  "Enqueue attack"
                )}
              </ConfirmButton>
            ) : (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={run.running || e === 0 || rightNowDisabled}
                onClick={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : rightNow ? (
                  "Run right now"
                ) : (
                  "Enqueue attack"
                )}
              </button>
            )}
            <Link to="/scheduler" className="btn btn-sm btn-ghost">
              Scheduler
            </Link>
            <Link
              to="/testing/auth-session?tab=results"
              className="btn btn-sm btn-ghost"
            >
              Results
            </Link>
            <Link
              to="/testing/auth-session?tab=candidates"
              className="btn btn-sm btn-ghost"
            >
              Candidates
            </Link>
          </div>

          <p className="text-xs text-base-content/50">
            Default enqueue is usually quick; execution happens on the
            scheduler. Results appear under the Results tab as jobs complete.
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
