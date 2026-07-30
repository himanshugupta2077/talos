/**
 * Advanced Intruder controls: match/grep, safety, findings, timing modes,
 * pools, suggest, raw config JSON — all via draft Save (except pools lifecycle
 * and suggest/findings promote which CLI-wrap).
 */

import { useCallback, useEffect, useState } from "react";
import { ConfirmButton, FieldHint } from "../../components/Common";
import { api, ApiError } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import TimingPanel from "./components/TimingPanel";
import type { SessionDraftApi } from "./hooks/useSessionDraft";
import { DEFAULT_MAX_ATTEMPTS, formatRelative } from "./shared";
import type {
  GrepRule,
  IntruderSessionDetail,
  MatchRule,
  PoolDetail,
  PoolSummary,
} from "./types";

const LOCKED = new Set(["queued", "running"]);

export default function AdvancedTab({
  projectId,
  session,
  draft,
  onSessionUpdated,
}: {
  projectId: string;
  session: IntruderSessionDetail;
  draft: SessionDraftApi;
  onSessionUpdated: (s: IntruderSessionDetail) => void;
}) {
  const { config, dirty, saving, saveError } = draft;
  const locked = LOCKED.has(session.status);
  const match = (config.match || []) as MatchRule[];
  const grep = (config.grep || []) as GrepRule[];
  const safety = config.safety || {};
  const findings = config.findings || {};

  const [rawOpen, setRawOpen] = useState(false);
  const [rawText, setRawText] = useState("");
  const [rawError, setRawError] = useState<string | null>(null);
  const [suggestPreview, setSuggestPreview] = useState<unknown>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // ---- Match form ----
  const [mTag, setMTag] = useState("");
  const [mStatus, setMStatus] = useState("");
  const [mBody, setMBody] = useState("");
  const [mRegex, setMRegex] = useState("");
  const [mLen, setMLen] = useState("");
  const [mTime, setMTime] = useState("");

  const addMatch = () => {
    if (locked) return;
    const rule: MatchRule = {};
    if (mTag.trim()) rule.tag = mTag.trim();
    if (mStatus.trim()) rule.status = Number(mStatus);
    if (mBody.trim()) rule.body_contains = mBody;
    if (mRegex.trim()) rule.regex = mRegex;
    if (mLen.trim()) rule.length_delta_gt = Number(mLen);
    if (mTime.trim()) rule.time_gt_ms = Number(mTime);
    if (
      rule.status == null &&
      !rule.body_contains &&
      !rule.regex &&
      rule.length_delta_gt == null &&
      rule.time_gt_ms == null
    ) {
      setActionError("Match rule needs at least one criterion.");
      return;
    }
    draft.setConfig((c) => {
      c.match = [...(c.match || []), rule];
      return c;
    });
    setMTag("");
    setMStatus("");
    setMBody("");
    setMRegex("");
    setMLen("");
    setMTime("");
    setActionError(null);
  };

  // ---- Grep form ----
  const [gName, setGName] = useState("");
  const [gRegex, setGRegex] = useState("");
  const [gGroup, setGGroup] = useState(1);
  const [gSource, setGSource] = useState("body");
  const [gIgnoreCase, setGIgnoreCase] = useState(false);
  const [gToPool, setGToPool] = useState(true);
  const [gInteresting, setGInteresting] = useState(false);

  const addGrep = () => {
    if (locked) return;
    if (!gName.trim() || !gRegex.trim()) {
      setActionError("Grep requires name and regex.");
      return;
    }
    const rule: GrepRule = {
      name: gName.trim(),
      regex: gRegex,
      group: gGroup,
      source: gSource || "body",
      max_matches: 50,
      to_pool: gToPool,
      tag_interesting: gInteresting,
    };
    if (gIgnoreCase) rule.ignore_case = true;
    draft.setConfig((c) => {
      c.grep = [...(c.grep || []), rule];
      return c;
    });
    setGName("");
    setGRegex("");
    setActionError(null);
  };

  // ---- Pools ----
  const [pools, setPools] = useState<PoolSummary[]>([]);
  const [poolDetail, setPoolDetail] = useState<PoolDetail | null>(null);
  const [poolsLoading, setPoolsLoading] = useState(false);

  const loadPools = useCallback(() => {
    setPoolsLoading(true);
    api
      .get<{ pools: PoolSummary[] }>("/api/intruder/pools", {
        project_id: projectId,
      })
      .then((r) => setPools(r.pools || []))
      .catch(() => setPools([]))
      .finally(() => setPoolsLoading(false));
  }, [projectId]);

  useEffect(() => {
    loadPools();
  }, [loadPools]);

  const openPool = async (name: string) => {
    try {
      const d = await api.get<PoolDetail>(`/api/intruder/pools/${encodeURIComponent(name)}`, {
        project_id: projectId,
        limit: 200,
      });
      setPoolDetail(d);
    } catch (e) {
      setActionError(formatErr(e));
    }
  };

  // ---- Suggest ----
  const suggestMut = useAction("Intruder suggest", async (apply: boolean) => {
    const res = await api.post<{
      session: IntruderSessionDetail;
      suggestions: unknown;
      steps: any[];
    }>(
      `/api/intruder/sessions/${session.id}/suggest`,
      { apply, replace_payloads: false },
      { project_id: projectId }
    );
    setSuggestPreview(res.suggestions);
    if (apply) {
      onSessionUpdated(res.session);
      draft.hydrateFromSession(res.session);
    }
    return { steps: res.steps || [] };
  });

  const promoteMut = useAction("Findings promote", async () => {
    const res = await api.post<{
      session: IntruderSessionDetail;
      result: unknown;
      steps: any[];
    }>(
      `/api/intruder/sessions/${session.id}/findings/promote`,
      { enable: true },
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    return { steps: res.steps || [] };
  });

  const applyRaw = () => {
    try {
      const parsed = JSON.parse(rawText);
      if (!parsed || typeof parsed !== "object") {
        setRawError("Config must be a JSON object.");
        return;
      }
      draft.setConfig(() => parsed);
      setRawError(null);
      setRawOpen(false);
    } catch (e) {
      setRawError(e instanceof Error ? e.message : "Invalid JSON");
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {locked && (
        <div className="alert alert-info text-xs py-2">
          Session is running/queued — advanced config is read-only.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 justify-between sticky top-0 z-10 bg-base-100/95 backdrop-blur py-2 border-b border-base-300/60">
        <div className="text-xs text-base-content/50">
          {dirty ? (
            <span className="text-warning font-medium">Unsaved changes</span>
          ) : (
            <span>Last saved: {formatRelative(draft.serverUpdatedAt)}</span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            disabled={!dirty || saving || locked}
            onClick={() => draft.discard()}
          >
            Discard
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={!dirty || saving || locked}
            onClick={() => void draft.save()}
          >
            {saving ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Save"
            )}
          </button>
        </div>
      </div>

      {(saveError || actionError) && (
        <div className="alert alert-error text-xs py-2">
          {saveError || actionError}
        </div>
      )}

      {/* Match rules */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Match rules</h3>
        <p className="text-xs text-base-content/60">
          Tag attempts as interesting when criteria match. Empty list = engine
          default interesting heuristics only.
        </p>
        {match.length === 0 ? (
          <div className="text-xs text-base-content/40">No match rules.</div>
        ) : (
          <ul className="space-y-1">
            {match.map((r, i) => (
              <li
                key={i}
                className="flex items-start justify-between gap-2 rounded border border-base-300 px-2 py-1.5 text-xs mono"
              >
                <span className="break-all">{JSON.stringify(r)}</span>
                {!locked && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs text-error"
                    onClick={() =>
                      draft.setConfig((c) => {
                        c.match = (c.match || []).filter((_, j) => j !== i);
                        return c;
                      })
                    }
                  >
                    ×
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {!locked && (
          <div className="rounded-md border border-base-300 p-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
            <Field
              label="Tag"
              value={mTag}
              onChange={setMTag}
              placeholder="diff"
            />
            <Field
              label="Status code"
              value={mStatus}
              onChange={setMStatus}
              placeholder="403"
            />
            <Field
              label="Body contains"
              value={mBody}
              onChange={setMBody}
              placeholder="error"
            />
            <Field
              label="Regex"
              value={mRegex}
              onChange={setMRegex}
              placeholder="admin"
            />
            <Field
              label="Length delta >"
              value={mLen}
              onChange={setMLen}
              placeholder="100"
            />
            <Field
              label="Time > ms"
              value={mTime}
              onChange={setMTime}
              placeholder="2000"
            />
            <div className="sm:col-span-2 flex gap-2">
              <button
                type="button"
                className="btn btn-xs btn-outline"
                onClick={addMatch}
              >
                Add match rule
              </button>
              {match.length > 0 && (
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() =>
                    draft.setConfig((c) => {
                      c.match = [];
                      return c;
                    })
                  }
                >
                  Clear all
                </button>
              )}
            </div>
          </div>
        )}
      </section>

      {/* Grep rules */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Grep / extract rules</h3>
        <p className="text-xs text-base-content/60">
          Python/re extracts fill project pools (and can mark interesting).
          Regex needs a capture group for pool values.
        </p>
        {grep.length === 0 ? (
          <div className="text-xs text-base-content/40">No grep rules.</div>
        ) : (
          <ul className="space-y-1">
            {grep.map((r, i) => (
              <li
                key={i}
                className="flex items-start justify-between gap-2 rounded border border-base-300 px-2 py-1.5 text-xs"
              >
                <span>
                  <span className="mono font-medium">{r.name}</span>{" "}
                  <span className="mono text-base-content/50">{r.regex}</span>
                  <span className="text-base-content/40 ml-1">
                    src={r.source || "body"}
                    {r.to_pool !== false ? " · pool" : ""}
                    {r.tag_interesting ? " · ★" : ""}
                  </span>
                </span>
                {!locked && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs text-error"
                    onClick={() =>
                      draft.setConfig((c) => {
                        c.grep = (c.grep || []).filter((_, j) => j !== i);
                        return c;
                      })
                    }
                  >
                    ×
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {!locked && (
          <div className="rounded-md border border-base-300 p-3 space-y-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field
                label="Name / pool"
                value={gName}
                onChange={setGName}
                placeholder="tokens"
              />
              <Field
                label="Regex"
                value={gRegex}
                onChange={setGRegex}
                placeholder={"token=([a-z0-9]+)"}
              />
              <label className="form-control">
                <span className="label-text text-xs">Group</span>
                <input
                  type="number"
                  className="input input-bordered input-sm"
                  value={gGroup}
                  onChange={(e) => setGGroup(Number(e.target.value) || 0)}
                />
              </label>
              <label className="form-control">
                <span className="label-text text-xs">Source</span>
                <input
                  className="input input-bordered input-sm mono"
                  value={gSource}
                  onChange={(e) => setGSource(e.target.value)}
                  placeholder="body | headers | header:Name"
                />
              </label>
            </div>
            <div className="flex flex-wrap gap-3 text-xs">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs"
                  checked={gIgnoreCase}
                  onChange={(e) => setGIgnoreCase(e.target.checked)}
                />
                Ignore case
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs"
                  checked={gToPool}
                  onChange={(e) => setGToPool(e.target.checked)}
                />
                Accumulate to pool
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs"
                  checked={gInteresting}
                  onChange={(e) => setGInteresting(e.target.checked)}
                />
                Tag interesting on match
              </label>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                className="btn btn-xs btn-outline"
                onClick={addGrep}
              >
                Add grep rule
              </button>
              {grep.length > 0 && (
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() =>
                    draft.setConfig((c) => {
                      c.grep = [];
                      return c;
                    })
                  }
                >
                  Clear all
                </button>
              )}
            </div>
          </div>
        )}
      </section>

      {/* Timing advanced */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Timing (advanced)</h3>
        <fieldset disabled={locked} className="border-0 p-0 m-0">
          <TimingPanel
            value={{
              mode: (config.timing?.mode as string) || "fixed",
              rps: Number(config.timing?.rps ?? 2),
              max_concurrency: Number(config.timing?.max_concurrency ?? 1),
              jitter_ms: Number(config.timing?.jitter_ms ?? 0),
              timeout_s: Number(config.timing?.timeout_s ?? 30),
              burst_size: Number(config.timing?.burst_size ?? 1),
              min_rps: Number(config.timing?.min_rps ?? 0.25),
              max_rps: Number(config.timing?.max_rps ?? 10),
              slow_ms: Number(config.timing?.slow_ms ?? 2000),
            }}
            onChange={(p) =>
              draft.setConfig((c) => {
                c.timing = {
                  ...(c.timing || {}),
                  mode: p.mode,
                  rps: p.rps,
                  max_concurrency: p.max_concurrency,
                  jitter_ms: p.jitter_ms,
                  timeout_s: p.timeout_s,
                  burst_size: p.burst_size,
                  min_rps: p.min_rps,
                  max_rps: p.max_rps,
                  slow_ms: p.slow_ms,
                };
                return c;
              })
            }
          />
        </fieldset>
      </section>

      {/* Safety */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Safety</h3>
        <p className="text-xs text-base-content/60">
          Logout endpoints stay hard-blocked (
          <code className="mono">respect_logout</code> cannot be turned off in
          the UI).
        </p>
        <fieldset
          disabled={locked}
          className="rounded-md border border-base-300 p-3 space-y-2 text-xs"
        >
          <Toggle
            label="Require in scope"
            checked={safety.require_in_scope !== false}
            onChange={(v) =>
              draft.setConfig((c) => {
                c.safety = { ...(c.safety || {}), require_in_scope: v };
                return c;
              })
            }
          />
          <Toggle
            label="Respect dangerous annotations"
            checked={safety.respect_dangerous !== false}
            onChange={(v) =>
              draft.setConfig((c) => {
                c.safety = { ...(c.safety || {}), respect_dangerous: v };
                return c;
              })
            }
          />
          <Toggle
            label="Skip auth artifacts (Authorization / session cookies)"
            checked={safety.skip_auth_artifacts === true}
            onChange={(v) =>
              draft.setConfig((c) => {
                c.safety = { ...(c.safety || {}), skip_auth_artifacts: v };
                return c;
              })
            }
          />
          {!safety.skip_auth_artifacts && (
            <div className="text-warning">
              Auth headers/cookies can be mutated (engine default). Unlike Input
              Validation.
            </div>
          )}
          <div className="grid grid-cols-2 gap-2 max-w-md pt-1">
            <label className="form-control">
              <span className="label-text text-xs">
                Max attempts
                <FieldHint text="Engine hard cap (default 10,000)." />
              </span>
              <input
                type="number"
                className="input input-bordered input-sm"
                value={Number(safety.max_attempts ?? DEFAULT_MAX_ATTEMPTS)}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.safety = {
                      ...(c.safety || {}),
                      max_attempts: Math.max(
                        1,
                        Math.floor(Number(e.target.value) || DEFAULT_MAX_ATTEMPTS)
                      ),
                    };
                    return c;
                  })
                }
              />
            </label>
            <label className="form-control">
              <span className="label-text text-xs">Max duration (s)</span>
              <input
                type="number"
                className="input input-bordered input-sm"
                value={Number(safety.max_duration_s ?? 3600)}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.safety = {
                      ...(c.safety || {}),
                      max_duration_s: Math.max(
                        1,
                        Math.floor(Number(e.target.value) || 3600)
                      ),
                    };
                    return c;
                  })
                }
              />
            </label>
          </div>
        </fieldset>
      </section>

      {/* Findings */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Findings promote</h3>
        <p className="text-xs text-base-content/60">
          Off by default. When on, interesting results can become findings
          (capped).
        </p>
        <fieldset
          disabled={locked}
          className="rounded-md border border-base-300 p-3 space-y-2 text-xs"
        >
          <Toggle
            label="Promote findings"
            checked={findings.promote === true}
            onChange={(v) =>
              draft.setConfig((c) => {
                c.findings = { ...(c.findings || {}), promote: v };
                return c;
              })
            }
          />
          <div className="grid grid-cols-2 gap-2 max-w-md">
            <label className="form-control">
              <span className="label-text text-xs">On</span>
              <select
                className="select select-bordered select-sm"
                value={String(findings.on || "interesting")}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.findings = { ...(c.findings || {}), on: e.target.value };
                    return c;
                  })
                }
              >
                <option value="interesting">interesting</option>
                <option value="matched">matched</option>
              </select>
            </label>
            <label className="form-control">
              <span className="label-text text-xs">Cluster by</span>
              <select
                className="select select-bordered select-sm"
                value={String(findings.cluster_by || "session")}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.findings = {
                      ...(c.findings || {}),
                      cluster_by: e.target.value,
                    };
                    return c;
                  })
                }
              >
                <option value="session">session</option>
                <option value="endpoint">endpoint</option>
              </select>
            </label>
            <label className="form-control">
              <span className="label-text text-xs">Max findings</span>
              <input
                type="number"
                className="input input-bordered input-sm"
                value={Number(findings.max_findings ?? 25)}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.findings = {
                      ...(c.findings || {}),
                      max_findings: Math.max(
                        1,
                        Math.floor(Number(e.target.value) || 25)
                      ),
                    };
                    return c;
                  })
                }
              />
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer mt-5">
              <input
                type="checkbox"
                className="checkbox checkbox-xs"
                checked={findings.only_success !== false}
                onChange={(e) =>
                  draft.setConfig((c) => {
                    c.findings = {
                      ...(c.findings || {}),
                      only_success: e.target.checked,
                    };
                    return c;
                  })
                }
              />
              Only successful HTTP
            </label>
          </div>
          <button
            type="button"
            className="btn btn-xs btn-outline"
            disabled={promoteMut.running || dirty}
            onClick={() =>
              void promoteMut
                .run()
                .catch((e) => setActionError(formatErr(e)))
            }
            title={
              dirty
                ? "Save configuration first"
                : "Offline promote interesting rows without finding_id"
            }
          >
            {promoteMut.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Run offline promote"
            )}
          </button>
        </fieldset>
      </section>

      {/* Pools */}
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">Project pools</h3>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={loadPools}
          >
            Refresh
          </button>
        </div>
        <p className="text-xs text-base-content/60">
          Values extracted by grep rules accumulate here. Use as a{" "}
          <code className="mono">pool</code> generator on Configure.
        </p>
        {poolsLoading && (
          <div className="text-xs text-base-content/40">Loading…</div>
        )}
        {!poolsLoading && pools.length === 0 && (
          <div className="text-xs text-base-content/40">No pools yet.</div>
        )}
        <ul className="space-y-1">
          {pools.map((p) => (
            <li
              key={p.name}
              className="flex items-center justify-between gap-2 rounded border border-base-300 px-2 py-1.5 text-xs"
            >
              <button
                type="button"
                className="link link-hover mono text-left"
                onClick={() => void openPool(p.name)}
              >
                {p.name}{" "}
                <span className="text-base-content/40">({p.count})</span>
              </button>
              <div className="flex gap-1">
                <ConfirmButton
                  className="btn btn-ghost btn-xs"
                  confirmText={`Clear pool ${p.name}?`}
                  onConfirm={() => {
                    void api
                      .post(
                        `/api/intruder/pools/${encodeURIComponent(p.name)}/clear`,
                        {},
                        { project_id: projectId }
                      )
                      .then(loadPools)
                      .catch((e) => setActionError(formatErr(e)));
                  }}
                >
                  Clear
                </ConfirmButton>
                <ConfirmButton
                  className="btn btn-ghost btn-xs text-error"
                  confirmText={`Delete pool ${p.name}?`}
                  onConfirm={() => {
                    void api
                      .del(
                        `/api/intruder/pools/${encodeURIComponent(p.name)}`,
                        { project_id: projectId }
                      )
                      .then(() => {
                        if (poolDetail?.name === p.name) setPoolDetail(null);
                        loadPools();
                      })
                      .catch((e) => setActionError(formatErr(e)));
                  }}
                >
                  Delete
                </ConfirmButton>
              </div>
            </li>
          ))}
        </ul>
        {poolDetail && (
          <div className="rounded-md border border-base-300 p-3 space-y-1">
            <div className="flex justify-between text-xs font-medium">
              <span className="mono">{poolDetail.name}</span>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                onClick={() => setPoolDetail(null)}
              >
                Close
              </button>
            </div>
            <pre className="text-[11px] mono max-h-40 overflow-auto bg-base-200 rounded p-2">
              {(poolDetail.values || []).join("\n") || "(empty)"}
            </pre>
            {poolDetail.truncated && (
              <div className="text-[10px] text-base-content/40">
                Truncated preview
              </div>
            )}
          </div>
        )}
      </section>

      {/* Suggest */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Suggest</h3>
        <p className="text-xs text-base-content/60">
          Heuristic offline suggestions for payloads / match / grep based on
          the baseline. Apply writes to the saved session (not the dirty draft).
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn btn-sm btn-outline"
            disabled={suggestMut.running || dirty}
            onClick={() =>
              void suggestMut
                .run(false)
                .catch((e) => setActionError(formatErr(e)))
            }
          >
            Preview suggestions
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={suggestMut.running || dirty || locked}
            onClick={() =>
              void suggestMut
                .run(true)
                .catch((e) => setActionError(formatErr(e)))
            }
          >
            Apply suggestions
          </button>
        </div>
        {dirty && (
          <div className="text-xs text-warning">
            Save or discard Configure/Advanced draft before suggest.
          </div>
        )}
        {suggestPreview != null && (
          <pre className="text-[11px] mono max-h-64 overflow-auto bg-base-200 rounded p-2">
            {JSON.stringify(suggestPreview, null, 2)}
          </pre>
        )}
      </section>

      {/* Raw JSON */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Raw config JSON</h3>
        <p className="text-xs text-base-content/60">
          Power-user escape hatch. Applies to the local draft — still needs{" "}
          <strong>Save</strong>.
        </p>
        {!rawOpen ? (
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            disabled={locked}
            onClick={() => {
              setRawText(JSON.stringify(config, null, 2));
              setRawError(null);
              setRawOpen(true);
            }}
          >
            Edit raw JSON
          </button>
        ) : (
          <div className="space-y-2">
            <textarea
              className="textarea textarea-bordered w-full font-mono text-xs min-h-[240px]"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
            {rawError && (
              <div className="text-xs text-error">{rawError}</div>
            )}
            <div className="flex gap-2">
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={applyRaw}
              >
                Apply to draft
              </button>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => setRawOpen(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="form-control">
      <span className="label-text text-xs">{label}</span>
      <input
        className="input input-bordered input-sm mono"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </label>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 cursor-pointer">
      <input
        type="checkbox"
        className="toggle toggle-sm"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof ApiError) {
    const d = e.body?.detail;
    if (typeof d === "string") return d;
    if (d?.message) return d.message;
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return String(e);
}
