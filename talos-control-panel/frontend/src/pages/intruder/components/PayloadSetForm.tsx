import { useEffect, useState } from "react";
import { FieldHint } from "../../../components/Common";
import { api } from "../../../api/client";
import { KNOWN_PROCESSORS, PATH_BACKED_GENERATORS } from "../shared";
import type {
  ArtifactDrafts,
  GeneratorType,
  PayloadSetConfig,
  PoolSummary,
} from "../types";
import {
  BruteforceForm,
  CsvJsonFileForm,
  DatesForm,
  ExampleValuesForm,
  GeneratorTypeSelect,
  NumbersForm,
  PatternForm,
  PoolForm,
  RandomForm,
  StaticForm,
  UuidForm,
  WordlistForm,
  preferStaticHeuristic,
} from "./GeneratorForms";

function valuesToText(opts: Record<string, unknown>): string {
  const v = opts.values;
  if (Array.isArray(v)) return v.map(String).join("\n");
  if (typeof v === "string") return v;
  return "";
}

function defaultOptions(g: GeneratorType): Record<string, unknown> {
  switch (g) {
    case "numbers":
      return { start: 1, end: 100, step: 1 };
    case "static":
      return { values: [] };
    case "uuid":
      return { count: 10 };
    case "csv":
      return { path: "", column: "0", delimiter: "," };
    case "json":
      return { path: "", json_path: "" };
    case "example_values":
      return { param_id: "" };
    case "pool":
      return { pool: "" };
    case "dates": {
      const today = new Date().toISOString().slice(0, 10);
      return {
        start_date: today,
        end_date: today,
        step_days: 1,
        date_format: "%Y-%m-%d",
      };
    }
    case "bruteforce":
      return {
        charset: "abcdefghijklmnopqrstuvwxyz0123456789",
        min_len: 1,
        max_len: 3,
      };
    case "random":
      return {
        count: 100,
        length: 8,
        charset:
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      };
    case "pattern":
      return { pattern: "user{n}", start: 0, end: 99 };
    case "wordlist":
    default:
      return {};
  }
}

export default function PayloadSetForm({
  varName,
  payload,
  artifactText,
  projectId,
  onChangePayload,
  onChangeArtifact,
  disabled = false,
}: {
  varName: string;
  payload: PayloadSetConfig | undefined;
  artifactText?: string;
  projectId?: string;
  onChangePayload: (ps: PayloadSetConfig) => void;
  onChangeArtifact: (text: string, kind?: "wordlist" | "csv" | "json") => void;
  disabled?: boolean;
}) {
  const gen = ((payload?.generator as GeneratorType) || "wordlist") as GeneratorType;
  const opts = (payload?.options || {}) as Record<string, unknown>;
  const pathHint =
    typeof opts.path === "string" ? (opts.path as string) : null;
  const processors = (payload?.processors || []) as string[];
  const [pools, setPools] = useState<string[]>([]);

  useEffect(() => {
    if (!projectId || gen !== "pool") return;
    api
      .get<{ pools: PoolSummary[] }>("/api/intruder/pools", {
        project_id: projectId,
      })
      .then((r) => setPools((r.pools || []).map((p) => p.name)))
      .catch(() => setPools([]));
  }, [projectId, gen]);

  const setGen = (g: GeneratorType) => {
    const base = defaultOptions(g);
    // Preserve path when switching between path-backed kinds if present
    if (PATH_BACKED_GENERATORS.has(g) && pathHint) {
      base.path = pathHint;
    }
    onChangePayload({
      generator: g,
      options: base,
      processors,
    });
  };

  const setOpts = (next: Record<string, unknown>) => {
    onChangePayload({
      generator: gen,
      options: next,
      processors,
    });
  };

  const setProcessors = (next: string[]) => {
    onChangePayload({
      generator: gen,
      options: opts,
      processors: next,
    });
  };

  return (
    <fieldset
      disabled={disabled}
      className="rounded-md border border-base-300 p-3 space-y-2 min-w-0"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium mono">{varName}</div>
        <GeneratorTypeSelect value={gen} onChange={setGen} />
      </div>

      {gen === "wordlist" && (
        <>
          <WordlistForm
            text={artifactText ?? ""}
            onChange={(t) => {
              onChangeArtifact(t, "wordlist");
              onChangePayload({
                generator: "wordlist",
                options: pathHint ? { path: pathHint } : {},
                processors,
              });
            }}
            pathHint={pathHint}
          />
          {preferStaticHeuristic(artifactText || "") && !disabled && (
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => {
                const text = artifactText || "";
                onChangePayload({
                  generator: "static",
                  options: {
                    values: text
                      .split("\n")
                      .map((l) => l.trimEnd())
                      .filter((l) => l.length > 0),
                  },
                  processors: [],
                });
              }}
            >
              Use static values instead (small paste)
            </button>
          )}
        </>
      )}

      {gen === "numbers" && (
        <NumbersForm
          start={Number(opts.start ?? 1)}
          end={Number(opts.end ?? 100)}
          step={Number(opts.step ?? 1)}
          onChange={(p) => setOpts(p)}
        />
      )}

      {gen === "static" && (
        <StaticForm
          text={valuesToText(opts)}
          onChange={(t) =>
            setOpts({
              values: t
                .split("\n")
                .map((l) => l.trimEnd())
                .filter((l) => l.length > 0),
            })
          }
        />
      )}

      {gen === "uuid" && (
        <UuidForm
          count={Number(opts.count ?? 10)}
          onChange={(count) => setOpts({ count })}
        />
      )}

      {gen === "csv" && (
        <CsvJsonFileForm
          kind="csv"
          text={artifactText ?? ""}
          pathHint={pathHint}
          onChange={(t) => onChangeArtifact(t, "csv")}
          extra={
            <div className="grid grid-cols-2 gap-2">
              <label className="form-control">
                <span className="label-text text-xs">Column</span>
                <input
                  className="input input-bordered input-sm mono"
                  value={String(opts.column ?? "0")}
                  onChange={(e) =>
                    setOpts({
                      ...opts,
                      column: e.target.value,
                      path: pathHint || opts.path,
                    })
                  }
                  placeholder="name or 0-based index"
                />
              </label>
              <label className="form-control">
                <span className="label-text text-xs">Delimiter</span>
                <input
                  className="input input-bordered input-sm mono"
                  value={String(opts.delimiter ?? ",")}
                  onChange={(e) =>
                    setOpts({
                      ...opts,
                      delimiter: e.target.value,
                      path: pathHint || opts.path,
                    })
                  }
                />
              </label>
            </div>
          }
        />
      )}

      {gen === "json" && (
        <CsvJsonFileForm
          kind="json"
          text={artifactText ?? ""}
          pathHint={pathHint}
          onChange={(t) => onChangeArtifact(t, "json")}
          extra={
            <label className="form-control">
              <span className="label-text text-xs">
                JSON path
                <FieldHint text="e.g. ids or users[].id" />
              </span>
              <input
                className="input input-bordered input-sm mono"
                value={String(opts.json_path ?? "")}
                onChange={(e) =>
                  setOpts({
                    ...opts,
                    json_path: e.target.value,
                    path: pathHint || opts.path,
                  })
                }
                placeholder="ids"
              />
            </label>
          }
        />
      )}

      {gen === "example_values" && (
        <ExampleValuesForm
          paramId={String(opts.param_id ?? "")}
          onChange={(param_id) => setOpts({ param_id })}
        />
      )}

      {gen === "pool" && (
        <PoolForm
          poolName={String(opts.pool ?? opts.pool_name ?? "")}
          knownPools={pools}
          onChange={(pool) => setOpts({ pool })}
        />
      )}

      {gen === "dates" && (
        <DatesForm
          startDate={String(opts.start_date ?? opts.start ?? "")}
          endDate={String(opts.end_date ?? opts.end ?? "")}
          stepDays={Number(opts.step_days ?? 1)}
          dateFormat={String(opts.date_format ?? "%Y-%m-%d")}
          onChange={setOpts}
        />
      )}

      {gen === "bruteforce" && (
        <BruteforceForm
          charset={String(
            opts.charset ?? "abcdefghijklmnopqrstuvwxyz0123456789"
          )}
          minLen={Number(opts.min_len ?? opts.min ?? 1)}
          maxLen={Number(opts.max_len ?? opts.max ?? 3)}
          onChange={setOpts}
        />
      )}

      {gen === "random" && (
        <RandomForm
          count={Number(opts.count ?? 100)}
          length={Number(opts.length ?? 8)}
          charset={String(
            opts.charset ??
              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
          )}
          seed={String(opts.seed ?? "")}
          onChange={(p) =>
            setOpts({
              count: p.count,
              length: p.length,
              charset: p.charset,
              ...(p.seed ? { seed: p.seed } : {}),
            })
          }
        />
      )}

      {gen === "pattern" && (
        <PatternForm
          pattern={String(opts.pattern ?? "user{n}")}
          start={Number(opts.start ?? 0)}
          end={Number(opts.end ?? 99)}
          seed={String(opts.seed ?? "")}
          onChange={(p) =>
            setOpts({
              pattern: p.pattern,
              start: p.start,
              end: p.end,
              ...(p.seed ? { seed: p.seed } : {}),
            })
          }
        />
      )}

      {/* Processors chain */}
      <div className="pt-2 border-t border-base-300 space-y-1">
        <div className="text-xs font-medium text-base-content/70">
          Processors
          <FieldHint text="Applied in order to each payload value before inject. Also: prefix:<text>, suffix:<text>." />
        </div>
        <div className="flex flex-wrap gap-1">
          {processors.map((p, i) => (
            <span
              key={`${p}-${i}`}
              className="badge badge-sm badge-outline gap-1 mono"
            >
              {p}
              <button
                type="button"
                className="hover:text-error"
                onClick={() =>
                  setProcessors(processors.filter((_, j) => j !== i))
                }
              >
                ×
              </button>
            </span>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5 items-center">
          <select
            className="select select-bordered select-xs"
            defaultValue=""
            onChange={(e) => {
              const v = e.target.value;
              if (!v) return;
              setProcessors([...processors, v]);
              e.target.value = "";
            }}
          >
            <option value="">+ built-in…</option>
            {KNOWN_PROCESSORS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => {
              const t = window.prompt("Custom processor (e.g. prefix:admin_)");
              if (t?.trim()) setProcessors([...processors, t.trim()]);
            }}
          >
            + custom
          </button>
          {processors.length > 0 && (
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => setProcessors([])}
            >
              Clear
            </button>
          )}
        </div>
      </div>
    </fieldset>
  );
}

export type { ArtifactDrafts };
