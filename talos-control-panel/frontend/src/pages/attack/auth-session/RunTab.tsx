import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { ConfirmButton, Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";
import {
  CONFIRM_ESTIMATE_THRESHOLD,
  RIGHT_NOW_MAX,
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
  const [bindingId, setBindingId] = useState("");
  const [customJwt, setCustomJwt] = useState("");
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

  const loadEstimate = useCallback(() => {
    setEstimateLoading(true);
    const params: Record<string, string | undefined> = {
      project_id: projectId,
    };
    if (bindingId) params.binding_id = bindingId;
    api
      .get<{ approved_matching: number; runnable_matching?: number }>(
        "/api/attack/auth-session/run-estimate",
        params
      )
      .then((r) => setEstimate(r.runnable_matching ?? r.approved_matching ?? 0))
      .catch(() => setEstimate(null))
      .finally(() => setEstimateLoading(false));
  }, [projectId, bindingId]);

  useEffect(() => {
    loadEstimate();
  }, [loadEstimate]);

  const jobsInFlight =
    (overview?.jobs_pending ?? 0) + (overview?.jobs_running ?? 0) > 0;
  const e =
    estimate ??
    overview?.estimated_jobs ??
    overview?.estimated_jobs_approved ??
    0;
  const rightNowDisabled = rightNow && e > RIGHT_NOW_MAX;
  const needsConfirm = e > CONFIRM_ESTIMATE_THRESHOLD || rightNow;
  const jwtTrimmed = customJwt.trim();

  const run = useAction("Run auth-session attack", () =>
    api.post(
      "/api/attack/auth-session/run",
      {
        binding_id: bindingId || undefined,
        jwt: jwtTrimmed || undefined,
        right_now: rightNow,
      },
      { project_id: projectId }
    )
  );

  const cliPreview = useMemo(() => {
    const parts = ["talos attack auth-session run"];
    if (bindingId) parts.push(`--binding ${bindingId}`);
    if (jwtTrimmed) parts.push("--jwt <custom>");
    if (rightNow) parts.push("--right-now");
    return parts.join(" ");
  }, [bindingId, jwtTrimmed, rightNow]);

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
          Tests the selected target flows with the{" "}
          <strong>latest captured JWT</strong> for the bound field, unless you
          paste a custom token below. First WEAK_VALIDATION finding is primary;
          later JWT findings are linked under it.
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

      <Section title="Token">
        <div className="panel p-4 space-y-3">
          <p className="text-xs text-base-content/60">
            Leave empty to use whatever JWT was captured most recently. Paste a
            compact JWT (or <span className="mono">Bearer …</span>) to test that
            token on every selected flow.
          </p>
          <textarea
            className="textarea textarea-bordered textarea-xs w-full font-mono"
            rows={3}
            value={customJwt}
            onChange={(e) => setCustomJwt(e.target.value)}
            placeholder="optional custom JWT"
          />
        </div>
      </Section>

      <Section title="Run">
        <div className="panel p-4 space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            {bindings.length > 1 && (
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
            )}
            <div className="text-sm">
              <span className="text-base-content/50 text-xs block mb-0.5">
                Tests ready
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
                Right now (bypass scheduler)
              </span>
            </label>
          </div>

          {rightNow && (
            <div className="alert alert-warning text-xs py-2">
              Right-now executes immediately in-process. Max {RIGHT_NOW_MAX}{" "}
              tests — larger batches must enqueue.
            </div>
          )}

          {rightNowDisabled && (
            <div className="alert alert-error text-xs py-2">
              Right-now refused: {e} tests (limit {RIGHT_NOW_MAX}). Uncheck
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
                    ? `Execute ${e} JWT test(s) right now against the live target?`
                    : `Enqueue ~${e} JWT test(s)?`
                }
                onConfirm={doRun}
              >
                {run.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : rightNow ? (
                  "Run right now"
                ) : (
                  "Run JWT tests"
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
                  "Run JWT tests"
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
              Target flows
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
