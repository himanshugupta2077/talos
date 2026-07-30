import { useEffect, useMemo, useRef, useState } from "react";
import { useAction } from "../../hooks/useAction";
import { api, ApiError } from "../../api/client";
import AttemptEstimate from "./components/AttemptEstimate";
import DiscoverSuggestions from "./components/DiscoverSuggestions";
import PayloadSetForm from "./components/PayloadSetForm";
import StorageModeSelect from "./components/StorageModeSelect";
import StrategyPicker from "./components/StrategyPicker";
import TemplatePreview from "./components/TemplatePreview";
import TimingPanel from "./components/TimingPanel";
import VariableAddForm from "./components/VariableAddForm";
import VariableChips from "./components/VariableChips";
import VariableEditPanel from "./components/VariableEditPanel";
import type { SessionDraftApi } from "./hooks/useSessionDraft";
import {
  attackVariables,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_RPS,
  estimateAttemptsFromDraft,
  formatRelative,
  pathInjectWarning,
} from "./shared";
import type {
  IntruderSessionDetail,
  IntruderStorageMode,
  IntruderStrategy,
  TemplateVariable,
} from "./types";

const LOCKED_STATUSES = new Set(["queued", "running"]);

export default function ConfigureTab({
  projectId,
  session,
  draft,
  isEmptyDraft,
  onSessionUpdated,
}: {
  projectId: string;
  session: IntruderSessionDetail;
  draft: SessionDraftApi;
  isEmptyDraft: boolean;
  onSessionUpdated?: (s: IntruderSessionDetail) => void;
}) {
  const { config, artifacts, dirty, saving, saveError, serverUpdatedAt } = draft;
  const vars = config.template?.variables || [];
  const attack = attackVariables(config);
  const [selectedVar, setSelectedVar] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const payloadRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const locked = LOCKED_STATUSES.has(session.status);
  const selected = vars.find((v) => v.name === selectedVar) || null;
  const hasEndpoint = !!(session.endpoint_id || config.session?.endpoint_id);

  const estimate = useMemo(
    () => estimateAttemptsFromDraft(config, artifacts),
    [config, artifacts]
  );

  const pathWarnings = useMemo(() => {
    return vars
      .filter((v) => v.location === "path")
      .map((v) =>
        pathInjectWarning(
          v.location,
          v.path || v.name,
          config.template?.normalized_path
        )
      )
      .filter(Boolean) as string[];
  }, [vars, config.template?.normalized_path]);

  const rps = Number(config.timing?.rps ?? DEFAULT_RPS);
  const concurrency = Number(
    config.timing?.max_concurrency ?? DEFAULT_MAX_CONCURRENCY
  );

  useEffect(() => {
    if (!selectedVar) return;
    const el = payloadRefs.current[selectedVar];
    el?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [selectedVar]);

  const onAddVar = (v: TemplateVariable) => {
    if (locked) return;
    const next = [...vars, v];
    draft.setVariables(next);
    if (v.fixed_value == null) {
      if (!config.payload_sets?.[v.name]) {
        draft.setPayloadSet(v.name, {
          generator: "wordlist",
          options: {},
          processors: [],
        });
      }
    }
    setSelectedVar(v.name);
    setAddOpen(false);
  };

  const onAddMany = (added: TemplateVariable[]) => {
    if (locked || !added.length) return;
    const next = [...vars, ...added];
    draft.setVariables(next);
    for (const v of added) {
      if (v.fixed_value == null && !config.payload_sets?.[v.name]) {
        draft.setPayloadSet(v.name, {
          generator: "wordlist",
          options: {},
          processors: [],
        });
      }
    }
    setSelectedVar(added[0].name);
  };

  const onRemoveVar = (name: string) => {
    if (locked) return;
    draft.setVariables(vars.filter((v) => v.name !== name));
    draft.setPayloadSet(name, null);
    draft.clearArtifact(name);
    if (selectedVar === name) setSelectedVar(null);
  };

  const onUpdateVar = (updated: TemplateVariable) => {
    if (locked) return;
    const prev = vars.find((v) => v.name === updated.name);
    draft.setVariables(
      vars.map((v) => (v.name === updated.name ? updated : v))
    );
    if (updated.fixed_value != null) {
      draft.setPayloadSet(updated.name, null);
      draft.clearArtifact(updated.name);
    } else if (
      prev?.fixed_value != null &&
      !config.payload_sets?.[updated.name]
    ) {
      draft.setPayloadSet(updated.name, {
        generator: "wordlist",
        options: {},
        processors: [],
      });
    }
  };

  const fromParams = useAction("From parameters", async () => {
    if (dirty) {
      const ok = window.confirm(
        "From parameters reloads the session from the server and will discard unsaved draft changes. Continue?"
      );
      if (!ok) return { steps: [] };
    }
    const res = await api.post<{
      session: IntruderSessionDetail;
      added?: number;
      steps: any[];
    }>(
      `/api/intruder/sessions/${session.id}/from-params`,
      { set_payloads: true, replace: false },
      { project_id: projectId }
    );
    onSessionUpdated?.(res.session);
    draft.hydrateFromSession(res.session);
    return { steps: res.steps || [] };
  });

  const [fromParamsErr, setFromParamsErr] = useState<string | null>(null);

  return (
    <div className="space-y-4 pb-16">
      {locked && (
        <div className="alert alert-info text-xs py-2">
          Session is <strong>{session.status}</strong> — configuration is
          read-only until Pause/Stop (or completion). Changes would race the
          running job.
        </div>
      )}

      {isEmptyDraft && !locked && (
        <div className="rounded-md border border-dashed border-primary/40 bg-primary/5 px-4 py-3 text-sm">
          <div className="font-medium mb-1">Draft session ready</div>
          <p className="text-xs text-base-content/70 mb-3">
            Baseline{" "}
            <span className="mono">
              {config.template?.method}{" "}
              {config.template?.url || session.base_flow_id}
            </span>
            . Add attack variables, attach payloads, choose strategy, then{" "}
            <strong>Save</strong>. Use Run when ready.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setAddOpen(true)}
            >
              + Add variable
            </button>
            <button
              type="button"
              className="btn btn-sm btn-outline"
              disabled={!dirty || saving}
              onClick={() => void draft.save()}
            >
              Save
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 justify-between sticky top-0 z-10 bg-base-100/95 backdrop-blur py-2 -mt-1 border-b border-base-300/60">
        <div className="text-xs text-base-content/50">
          {dirty ? (
            <span className="text-warning font-medium">Unsaved changes</span>
          ) : (
            <span>Last saved: {formatRelative(serverUpdatedAt)}</span>
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

      {saveError && (
        <div className="alert alert-error text-xs py-2">{saveError}</div>
      )}
      {fromParamsErr && (
        <div className="alert alert-error text-xs py-2">{fromParamsErr}</div>
      )}

      <TemplatePreview template={config.template} />

      <div className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium">Variables</div>
          {!locked && hasEndpoint && (
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              disabled={fromParams.running}
              onClick={() => {
                setFromParamsErr(null);
                void fromParams.run().catch((e) => {
                  setFromParamsErr(
                    e instanceof ApiError
                      ? typeof e.body?.detail === "string"
                        ? e.body.detail
                        : e.message
                      : String(e)
                  );
                });
              }}
              title="Import variables from Parameter Intelligence for the linked endpoint"
            >
              {fromParams.running ? (
                <span className="loading loading-spinner loading-xs" />
              ) : (
                "From parameters"
              )}
            </button>
          )}
        </div>
        <VariableChips
          variables={vars}
          selected={selectedVar}
          onSelect={setSelectedVar}
          onRemove={locked ? undefined : onRemoveVar}
        />
        {selected && !locked && (
          <VariableEditPanel
            variable={selected}
            normalizedPath={config.template?.normalized_path}
            onChange={onUpdateVar}
            onClose={() => setSelectedVar(null)}
          />
        )}
        {!locked && (
          <div className="flex flex-wrap gap-2 items-start">
            <VariableAddForm
              existing={vars}
              normalizedPath={config.template?.normalized_path}
              onAdd={onAddVar}
              forceOpen={addOpen}
              onOpenChange={setAddOpen}
            />
            <DiscoverSuggestions
              template={config.template}
              existing={vars}
              onAdd={onAddMany}
            />
          </div>
        )}
        {pathWarnings.map((w, i) => (
          <div key={i} className="alert alert-warning text-xs py-2">
            {w}
          </div>
        ))}
      </div>

      {attack.length > 0 && (
        <div className="space-y-2">
          <div className="text-sm font-medium">Payload sets</div>
          <p className="text-xs text-base-content/50">
            One generator per attack variable. Wordlist/CSV/JSON files are
            stored under the project data directory on Save.
          </p>
          <div className="space-y-3">
            {attack.map((v) => (
              <div
                key={v.name}
                ref={(el) => {
                  payloadRefs.current[v.name] = el;
                }}
                className={
                  selectedVar === v.name
                    ? "ring-1 ring-primary/40 rounded-md"
                    : undefined
                }
              >
                <PayloadSetForm
                  varName={v.name}
                  projectId={projectId}
                  payload={config.payload_sets?.[v.name]}
                  artifactText={artifacts[v.name]?.text}
                  disabled={locked}
                  onChangePayload={(ps) => {
                    if (!locked) draft.setPayloadSet(v.name, ps);
                  }}
                  onChangeArtifact={(text, kind) => {
                    if (!locked)
                      draft.setArtifactText(v.name, text, kind || "wordlist");
                  }}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      <fieldset
        disabled={locked}
        className="space-y-4 border-0 p-0 m-0 min-w-0"
      >
        <StrategyPicker
          value={config.strategy?.type || "single"}
          attackVarCount={attack.length}
          onChange={(s: IntruderStrategy) =>
            draft.setConfig((c) => {
              c.strategy = {
                type: s,
                options: c.strategy?.options || {},
                sets: attack.map((v) => v.name),
              };
              return c;
            })
          }
        />

        <AttemptEstimate
          attempts={estimate}
          rps={rps}
          concurrency={concurrency}
          maxAttempts={Number(
            config.safety?.max_attempts ?? DEFAULT_MAX_ATTEMPTS
          )}
        />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <TimingPanel
            compact
            value={{
              mode: (config.timing?.mode as string) || "fixed",
              rps,
              max_concurrency: concurrency,
              jitter_ms: Number(config.timing?.jitter_ms ?? 0),
              timeout_s: Number(config.timing?.timeout_s ?? 30),
            }}
            onChange={(p) =>
              draft.setConfig((c) => {
                c.timing = {
                  ...(c.timing || {}),
                  mode: "fixed",
                  rps: p.rps,
                  max_concurrency: p.max_concurrency,
                };
                return c;
              })
            }
          />
          <StorageModeSelect
            value={(config.storage?.mode as string) || "metrics_only"}
            onChange={(m: IntruderStorageMode) =>
              draft.setConfig((c) => {
                c.storage = { ...(c.storage || {}), mode: m };
                return c;
              })
            }
          />
        </div>
      </fieldset>

      <div className="alert alert-info text-xs py-2">
        Authorization and session cookies can be mutated by default (unlike
        Input Validation). Adjust on the Advanced tab (
        <code className="mono">skip_auth_artifacts</code>) if needed. Match,
        grep, findings, and pools live under Advanced.
      </div>
    </div>
  );
}
