import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import type { StepsResponse } from "../../../types";

export default function ConfigTab({
  projectId,
  autoRunEnabled,
  autoRunSource,
  onRefresh,
}: {
  projectId: string;
  autoRunEnabled: boolean;
  autoRunSource?: string;
  onRefresh: () => void;
}) {
  const [filterText, setFilterText] = useState<string | null>(null);
  const [validateMsg, setValidateMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);
  const [applyPreview, setApplyPreview] = useState<{
    dry_run: boolean;
    results_total: number;
    results_unchanged: number;
    results_updated: number;
    findings_rejected: number;
    findings_skipped_confirmed: number;
    findings_skipped_other: number;
    would_create_finding: number;
    incomplete: number;
    rows?: Array<{
      replay_flow_id: string;
      old_verdict: string;
      new_verdict: string;
      finding_id: string | null;
      finding_status: string | null;
      action: string;
      reason: string;
    }>;
  } | null>(null);
  const [includeConfirmed, setIncludeConfirmed] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [source, setSource] = useState(autoRunSource || "default");
  const [enabled, setEnabled] = useState(autoRunEnabled);

  useEffect(() => {
    setEnabled(autoRunEnabled);
    setSource(autoRunSource || "default");
  }, [autoRunEnabled, autoRunSource]);

  // Prefer layered config source badge when available
  useEffect(() => {
    api
      .get<{ key: string; value: unknown; source: string }>(
        "/api/configuration/get",
        { project_id: projectId, key: "attack.unauth_auto_run" }
      )
      .then((r) => {
        setEnabled(Boolean(r.value));
        setSource((r.source || "default").toLowerCase());
      })
      .catch(() => undefined);
  }, [projectId]);

  const setAutoRun = useAction("Set unauth auto-run", (value: boolean) =>
    api.post(
      "/api/configuration/value",
      { key: "attack.unauth_auto_run", value, scope: "project" },
      { project_id: projectId }
    )
  );

  const filterInit = useAction("Init unauth filter", () =>
    api.post("/api/attack/unauth/filter/init", {}, { project_id: projectId })
  );
  const filterShow = useAction("Show unauth filter", () =>
    api.post("/api/attack/unauth/filter/show", {}, { project_id: projectId })
  );
  const filterValidate = useAction("Validate unauth filter", () =>
    api.post(
      "/api/attack/unauth/filter/validate",
      {},
      { project_id: projectId }
    )
  );

  const filterApply = useAction(
    "Apply unauth filter",
    (opts: { dry_run: boolean; force: boolean }) =>
      api.post(
        "/api/attack/unauth/filter/apply",
        { dry_run: opts.dry_run, force: opts.force },
        { project_id: projectId }
      )
  );

  const extractStdout = (res: StepsResponse | undefined) => {
    const steps = res?.steps || [];
    const last = steps[steps.length - 1];
    return {
      ok: last?.ok !== false && (last?.exit_code ?? 0) === 0,
      text: (last?.stdout || last?.stderr || "").trim(),
    };
  };

  return (
    <div className="space-y-6">
      <Section title="Auto-run (classic auth_test)">
        <div className="panel p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="max-w-xl">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`badge badge-sm ${enabled ? "badge-success" : "badge-ghost"}`}
                >
                  {enabled ? "Enabled" : "Disabled"}
                </span>
                <span className="text-xs text-base-content/50 uppercase">
                  source: {source}
                </span>
              </div>
              <p className="text-xs text-base-content/60 leading-relaxed">
                When enabled, the scheduler automatically enqueues classic{" "}
                <span className="mono">auth_test</span> (Authentication Bypass)
                jobs for qualified endpoints that have no result yet. This is{" "}
                <strong>distinct</strong> from{" "}
                <span className="mono">talos attack unauth run</span>, which
                enqueues recipe-based <span className="mono">unauth_attack</span>{" "}
                jobs.
              </p>
              <p className="text-xs text-base-content/40 mt-1 mono">
                attack.unauth_auto_run · talos attack unauth config --auto-run
                on|off
              </p>
            </div>
            <div className="flex flex-col gap-2 shrink-0">
              {enabled ? (
                <button
                  className="btn btn-sm"
                  disabled={setAutoRun.running}
                  onClick={async () => {
                    try {
                      await setAutoRun.run(false);
                      setEnabled(false);
                      onRefresh();
                    } catch {
                      /* logged by useAction */
                    }
                  }}
                >
                  Disable auto-run
                </button>
              ) : (
                <button
                  className="btn btn-sm btn-primary"
                  disabled={setAutoRun.running}
                  onClick={async () => {
                    try {
                      await setAutoRun.run(true);
                      setEnabled(true);
                      onRefresh();
                    } catch {
                      /* logged by useAction */
                    }
                  }}
                >
                  Enable auto-run
                </button>
              )}
              <Link
                className="link link-primary text-xs text-center"
                to="/talos-config?tab=settings&section=attack"
              >
                Open in Talos Config →
              </Link>
            </div>
          </div>
        </div>
      </Section>

      <Section
        title="Decision filter"
        action={
          <div className="flex gap-2">
            <button
              className="btn btn-xs"
              disabled={filterInit.running}
              onClick={async () => {
                try {
                  const res = (await filterInit.run()) as StepsResponse | undefined;
                  const { text } = extractStdout(res);
                  if (text) setFilterText(text);
                  setValidateMsg(null);
                } catch {
                  /* logged by useAction */
                }
              }}
            >
              Init
            </button>
            <button
              className="btn btn-xs"
              disabled={filterShow.running}
              onClick={async () => {
                try {
                  const res = (await filterShow.run()) as StepsResponse | undefined;
                  const { ok, text } = extractStdout(res);
                  setFilterText(text || (ok ? "(empty)" : "Failed to load filter"));
                  setValidateMsg(null);
                } catch {
                  setFilterText("Failed to load filter (see Console drawer).");
                }
              }}
            >
              Show
            </button>
            <button
              className="btn btn-xs"
              disabled={filterValidate.running}
              onClick={async () => {
                try {
                  const res = (await filterValidate.run()) as
                    | StepsResponse
                    | undefined;
                  const { ok, text } = extractStdout(res);
                  setValidateMsg({
                    ok,
                    text: text || (ok ? "Valid" : "Validation failed"),
                  });
                } catch {
                  setValidateMsg({
                    ok: false,
                    text: "Validation failed (see Console drawer).",
                  });
                }
              }}
            >
              Validate
            </button>
          </div>
        }
      >
        <p className="text-xs text-base-content/50 mb-2">
          File:{" "}
          <span className="mono">unauth-decision-filter.yaml</span> in the
          project data directory. Edit on disk to customise BYPASS/SECURE
          detection patterns. Maps to{" "}
          <span className="mono">talos attack unauth filter …</span>.
        </p>

        {validateMsg && (
          <div
            className={`alert text-xs py-2 mb-2 ${
              validateMsg.ok ? "alert-success" : "alert-error"
            }`}
          >
            <span className="whitespace-pre-wrap">{validateMsg.text}</span>
          </div>
        )}

        {filterText != null ? (
          <pre className="panel p-3 text-xs mono whitespace-pre-wrap max-h-96 overflow-auto">
            {filterText}
          </pre>
        ) : (
          <p className="text-xs text-base-content/40">
            Click <strong>Show</strong> to preview the filter YAML inline.
            Output also lands in the Console drawer.
          </p>
        )}
      </Section>

      <Section title="Apply filter to existing results">
        <div className="panel p-4 space-y-3">
          <p className="text-xs text-base-content/60 leading-relaxed">
            After editing{" "}
            <span className="mono">unauth-decision-filter.yaml</span>, re-evaluate
            stored unauth results offline. Responses that now match{" "}
            <strong>passed_detection</strong> (SECURE) flip from BYPASS and linked{" "}
            <strong>TRIAGING</strong> findings are auto-rejected as false
            positives with a system timeline reason. Reverse BYPASS is reported
            only (no new findings in v1). Maps to{" "}
            <span className="mono">talos attack unauth filter apply</span>.
          </p>

          <label className="flex items-center gap-2 text-xs cursor-pointer">
            <input
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={includeConfirmed}
              onChange={(e) => setIncludeConfirmed(e.target.checked)}
            />
            Also reject <strong>CONFIRMED</strong> findings (maps to{" "}
            <span className="mono">--force</span>)
          </label>

          <div className="flex flex-wrap gap-2">
            <button
              className="btn btn-sm"
              disabled={filterApply.running}
              onClick={async () => {
                setApplyError(null);
                try {
                  const res = (await filterApply.run({
                    dry_run: true,
                    force: includeConfirmed,
                  })) as unknown as typeof applyPreview;
                  setApplyPreview(res);
                } catch (e) {
                  setApplyPreview(null);
                  setApplyError(
                    e instanceof Error ? e.message : "Dry-run failed"
                  );
                }
              }}
            >
              Preview (dry-run)
            </button>
            <button
              className="btn btn-sm btn-primary"
              disabled={filterApply.running || !applyPreview}
              onClick={async () => {
                if (
                  !window.confirm(
                    `Apply filter? This will update ${applyPreview?.results_updated ?? 0} result(s) and reject ${applyPreview?.findings_rejected ?? 0} finding(s).`
                  )
                ) {
                  return;
                }
                setApplyError(null);
                try {
                  const res = (await filterApply.run({
                    dry_run: false,
                    force: includeConfirmed,
                  })) as unknown as typeof applyPreview;
                  setApplyPreview(res);
                  onRefresh();
                } catch (e) {
                  setApplyError(
                    e instanceof Error ? e.message : "Apply failed"
                  );
                }
              }}
            >
              Apply
            </button>
          </div>

          {applyError && (
            <div className="alert alert-error text-xs py-2">
              <span className="whitespace-pre-wrap">{applyError}</span>
            </div>
          )}

          {applyPreview && (
            <div className="space-y-2">
              <div
                className={`alert text-xs py-2 ${
                  applyPreview.dry_run ? "alert-info" : "alert-success"
                }`}
              >
                <span>
                  {applyPreview.dry_run ? "Dry-run preview" : "Applied"}:{" "}
                  {applyPreview.results_updated} result(s) updated,{" "}
                  {applyPreview.findings_rejected} finding(s) rejected
                  {applyPreview.findings_skipped_confirmed
                    ? `, ${applyPreview.findings_skipped_confirmed} CONFIRMED skipped`
                    : ""}
                  {applyPreview.would_create_finding
                    ? `, ${applyPreview.would_create_finding} would create finding`
                    : ""}
                  {applyPreview.incomplete
                    ? `, ${applyPreview.incomplete} incomplete`
                    : ""}
                </span>
              </div>
              {applyPreview.rows && applyPreview.rows.length > 0 && (
                <div className="overflow-x-auto max-h-64 overflow-y-auto">
                  <table className="table table-xs">
                    <thead>
                      <tr>
                        <th>Replay</th>
                        <th>Verdict</th>
                        <th>Finding</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {applyPreview.rows
                        .filter((r) => r.action !== "unchanged")
                        .slice(0, 40)
                        .map((r) => (
                          <tr key={r.replay_flow_id}>
                            <td className="mono">
                              {r.replay_flow_id.slice(0, 8)}
                            </td>
                            <td className="mono">
                              {r.old_verdict}→{r.new_verdict}
                            </td>
                            <td className="mono">
                              {r.finding_id
                                ? `${r.finding_id.slice(0, 8)} (${r.finding_status})`
                                : "—"}
                            </td>
                            <td>
                              <span className="badge badge-ghost badge-sm">
                                {r.action}
                              </span>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}
