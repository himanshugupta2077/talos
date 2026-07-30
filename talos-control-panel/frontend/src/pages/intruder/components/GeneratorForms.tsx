import { useRef, type ReactNode } from "react";
import { FieldHint } from "../../../components/Common";
import {
  ALL_GENERATORS,
  GENERATOR_LABELS,
  STATIC_HEURISTIC_BYTES,
  STATIC_HEURISTIC_LINES,
} from "../shared";
import type { GeneratorType } from "../types";

export function WordlistForm({
  text,
  onChange,
  pathHint,
}: {
  text: string;
  onChange: (t: string) => void;
  pathHint?: string | null;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const hasLocalText = text.trim().length > 0;
  const hasSavedPath = !!pathHint && !hasLocalText;
  const lines = text
    ? text.split("\n").filter((l) => l.trim().length > 0).length
    : 0;

  const onFile = async (file: File | null) => {
    if (!file) return;
    try {
      const content = await file.text();
      onChange(content);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        One value per line. Saved under project data (not a temp file).
        <FieldHint text="Engine re-opens the file on validate/run. Max ~1M lines / 64 MiB." />
      </div>

      {hasSavedPath && (
        <div className="rounded-md border border-success/30 bg-success/5 px-3 py-2 text-xs space-y-1">
          <div className="font-medium text-success">
            Using saved wordlist on disk
          </div>
          <div
            className="mono text-base-content/50 truncate"
            title={pathHint || ""}
          >
            {pathHint}
          </div>
          <div className="text-base-content/60">
            Paste or upload below to replace on next Save.
          </div>
        </div>
      )}

      <textarea
        className="textarea textarea-bordered textarea-sm w-full font-mono min-h-[120px]"
        placeholder={
          hasSavedPath
            ? "Replace wordlist: paste new values (one per line)…"
            : "admin\nuser\nguest"
        }
        value={text}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-base-content/40">
        <span>
          {hasLocalText
            ? `${lines} value${lines === 1 ? "" : "s"} (unsaved paste)`
            : hasSavedPath
              ? "saved file · no local paste"
              : "0 values"}
        </span>
        <div className="flex items-center gap-2">
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.lst,.wordlist,text/plain"
            className="hidden"
            onChange={(e) => {
              void onFile(e.target.files?.[0] ?? null);
              e.target.value = "";
            }}
          />
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => fileRef.current?.click()}
          >
            Upload file
          </button>
          {hasLocalText && pathHint && (
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => onChange("")}
            >
              Clear paste
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function NumbersForm({
  start,
  end,
  step,
  onChange,
}: {
  start: number;
  end: number;
  step: number;
  onChange: (p: { start: number; end: number; step: number }) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Inclusive start/end; step ≠ 0.
      </div>
      <div className="grid grid-cols-3 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Start</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={start}
            onChange={(e) =>
              onChange({ start: Number(e.target.value), end, step })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">End</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={end}
            onChange={(e) =>
              onChange({ start, end: Number(e.target.value), step })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Step</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={step}
            onChange={(e) =>
              onChange({ start, end, step: Number(e.target.value) || 1 })
            }
          />
        </label>
      </div>
    </div>
  );
}

export function StaticForm({
  text,
  onChange,
}: {
  text: string;
  onChange: (t: string) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        One value per line — stored in session config (not a file).
      </div>
      <textarea
        className="textarea textarea-bordered textarea-sm w-full font-mono min-h-[80px]"
        value={text}
        onChange={(e) => onChange(e.target.value)}
        placeholder={"true\nfalse"}
      />
    </div>
  );
}

export function UuidForm({
  count,
  onChange,
}: {
  count: number;
  onChange: (count: number) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Generate N random UUIDs (v4).
      </div>
      <label className="form-control max-w-[10rem]">
        <span className="label-text text-xs">Count</span>
        <input
          type="number"
          min={1}
          className="input input-bordered input-sm"
          value={count}
          onChange={(e) => onChange(Math.max(1, Math.floor(Number(e.target.value) || 1)))}
        />
      </label>
    </div>
  );
}

export function CsvJsonFileForm({
  kind,
  text,
  onChange,
  pathHint,
  extra,
}: {
  kind: "csv" | "json";
  text: string;
  onChange: (t: string) => void;
  pathHint?: string | null;
  extra?: ReactNode;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const hasLocal = text.trim().length > 0;
  const hasPath = !!pathHint && !hasLocal;

  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        {kind === "csv"
          ? "Paste CSV content or upload. Saved under project data."
          : "Paste JSON array / object content or upload. Saved under project data."}
      </div>
      {hasPath && (
        <div className="text-xs mono text-success/80 truncate" title={pathHint || ""}>
          Saved: {pathHint}
        </div>
      )}
      {extra}
      <textarea
        className="textarea textarea-bordered textarea-sm w-full font-mono min-h-[100px]"
        value={text}
        onChange={(e) => onChange(e.target.value)}
        placeholder={
          kind === "csv" ? "id,name\n1,alice\n2,bob" : '["a","b"] or {"ids":[1,2]}'
        }
      />
      <div className="flex gap-2">
        <input
          ref={fileRef}
          type="file"
          accept={kind === "csv" ? ".csv,text/csv,text/plain" : ".json,application/json,text/plain"}
          className="hidden"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f) onChange(await f.text());
            e.target.value = "";
          }}
        />
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => fileRef.current?.click()}
        >
          Upload
        </button>
      </div>
    </div>
  );
}

export function ExampleValuesForm({
  paramId,
  onChange,
}: {
  paramId: string;
  onChange: (paramId: string) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Uses example values from Parameter Intelligence for this{" "}
        <code className="mono">param_id</code>. Prefer{" "}
        <strong>From parameters</strong> to wire automatically.
      </div>
      <label className="form-control">
        <span className="label-text text-xs">param_id</span>
        <input
          className="input input-bordered input-sm mono"
          value={paramId}
          onChange={(e) => onChange(e.target.value)}
          placeholder="UUID from parameters table"
        />
      </label>
    </div>
  );
}

export function PoolForm({
  poolName,
  onChange,
  knownPools,
}: {
  poolName: string;
  onChange: (name: string) => void;
  knownPools?: string[];
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Payloads from a project pool (filled by grep extracts). Manage pools on
        the Advanced tab.
      </div>
      {knownPools && knownPools.length > 0 ? (
        <label className="form-control max-w-xs">
          <span className="label-text text-xs">Pool</span>
          <select
            className="select select-bordered select-sm"
            value={poolName}
            onChange={(e) => onChange(e.target.value)}
          >
            <option value="">Select…</option>
            {knownPools.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <label className="form-control max-w-xs">
          <span className="label-text text-xs">Pool name</span>
          <input
            className="input input-bordered input-sm mono"
            value={poolName}
            onChange={(e) => onChange(e.target.value)}
            placeholder="extracted_tokens"
          />
        </label>
      )}
    </div>
  );
}

export function DatesForm({
  startDate,
  endDate,
  stepDays,
  dateFormat,
  onChange,
}: {
  startDate: string;
  endDate: string;
  stepDays: number;
  dateFormat: string;
  onChange: (p: {
    start_date: string;
    end_date: string;
    step_days: number;
    date_format: string;
  }) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Inclusive calendar range. Format uses Python strftime (default %Y-%m-%d).
      </div>
      <div className="grid grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Start (YYYY-MM-DD)</span>
          <input
            type="date"
            className="input input-bordered input-sm"
            value={startDate}
            onChange={(e) =>
              onChange({
                start_date: e.target.value,
                end_date: endDate,
                step_days: stepDays,
                date_format: dateFormat,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">End (YYYY-MM-DD)</span>
          <input
            type="date"
            className="input input-bordered input-sm"
            value={endDate}
            onChange={(e) =>
              onChange({
                start_date: startDate,
                end_date: e.target.value,
                step_days: stepDays,
                date_format: dateFormat,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Step days</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={stepDays}
            onChange={(e) =>
              onChange({
                start_date: startDate,
                end_date: endDate,
                step_days: Number(e.target.value) || 1,
                date_format: dateFormat,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Format</span>
          <input
            className="input input-bordered input-sm mono"
            value={dateFormat}
            onChange={(e) =>
              onChange({
                start_date: startDate,
                end_date: endDate,
                step_days: stepDays,
                date_format: e.target.value,
              })
            }
            placeholder="%Y-%m-%d"
          />
        </label>
      </div>
    </div>
  );
}

export function BruteforceForm({
  charset,
  minLen,
  maxLen,
  onChange,
}: {
  charset: string;
  minLen: number;
  maxLen: number;
  onChange: (p: { charset: string; min_len: number; max_len: number }) => void;
}) {
  const chars = [...new Set(charset.split(""))];
  let combos = 0;
  for (let len = minLen; len <= maxLen; len++) {
    combos += Math.pow(chars.length || 0, len);
  }
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        All strings of length min…max over charset. Large products need force /
        are capped (~100k default).
      </div>
      <label className="form-control">
        <span className="label-text text-xs">Charset</span>
        <input
          className="input input-bordered input-sm mono"
          value={charset}
          onChange={(e) =>
            onChange({ charset: e.target.value, min_len: minLen, max_len: maxLen })
          }
        />
      </label>
      <div className="grid grid-cols-2 gap-2 max-w-sm">
        <label className="form-control">
          <span className="label-text text-xs">Min len</span>
          <input
            type="number"
            min={0}
            className="input input-bordered input-sm"
            value={minLen}
            onChange={(e) =>
              onChange({
                charset,
                min_len: Math.max(0, Math.floor(Number(e.target.value) || 0)),
                max_len: maxLen,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Max len</span>
          <input
            type="number"
            min={0}
            className="input input-bordered input-sm"
            value={maxLen}
            onChange={(e) =>
              onChange({
                charset,
                min_len: minLen,
                max_len: Math.max(0, Math.floor(Number(e.target.value) || 0)),
              })
            }
          />
        </label>
      </div>
      <div
        className={`text-xs ${combos > 100_000 ? "text-error" : "text-base-content/50"}`}
      >
        ≈ {combos.toLocaleString()} combinations
        {combos > 100_000 ? " — may require --force on validate" : ""}
      </div>
    </div>
  );
}

export function RandomForm({
  count,
  length,
  charset,
  seed,
  onChange,
}: {
  count: number;
  length: number;
  charset: string;
  seed: string;
  onChange: (p: {
    count: number;
    length: number;
    charset: string;
    seed?: string;
  }) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Random strings. Seed makes the sequence deterministic for resume.
      </div>
      <div className="grid grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Count</span>
          <input
            type="number"
            min={1}
            className="input input-bordered input-sm"
            value={count}
            onChange={(e) =>
              onChange({
                count: Math.max(1, Math.floor(Number(e.target.value) || 1)),
                length,
                charset,
                seed,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Length</span>
          <input
            type="number"
            min={1}
            className="input input-bordered input-sm"
            value={length}
            onChange={(e) =>
              onChange({
                count,
                length: Math.max(1, Math.floor(Number(e.target.value) || 1)),
                charset,
                seed,
              })
            }
          />
        </label>
        <label className="form-control col-span-2">
          <span className="label-text text-xs">Charset</span>
          <input
            className="input input-bordered input-sm mono"
            value={charset}
            onChange={(e) =>
              onChange({ count, length, charset: e.target.value, seed })
            }
          />
        </label>
        <label className="form-control col-span-2">
          <span className="label-text text-xs">Seed (optional)</span>
          <input
            className="input input-bordered input-sm mono"
            value={seed}
            onChange={(e) =>
              onChange({ count, length, charset, seed: e.target.value })
            }
            placeholder="optional"
          />
        </label>
      </div>
    </div>
  );
}

export function PatternForm({
  pattern,
  start,
  end,
  seed,
  onChange,
}: {
  pattern: string;
  start: number;
  end: number;
  seed: string;
  onChange: (p: {
    pattern: string;
    start: number;
    end: number;
    seed?: string;
  }) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-base-content/60">
        Template with placeholders:{" "}
        <code className="mono">{"{n}"}</code>,{" "}
        <code className="mono">{"{n:04d}"}</code>,{" "}
        <code className="mono">{"{hex}"}</code>,{" "}
        <code className="mono">{"{a}"}</code>,{" "}
        <code className="mono">{"{rand:N}"}</code>.
      </div>
      <label className="form-control">
        <span className="label-text text-xs">Pattern</span>
        <input
          className="input input-bordered input-sm mono"
          value={pattern}
          onChange={(e) =>
            onChange({ pattern: e.target.value, start, end, seed })
          }
          placeholder="user{n:03d}"
        />
      </label>
      <div className="grid grid-cols-3 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Start</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={start}
            onChange={(e) =>
              onChange({
                pattern,
                start: Number(e.target.value),
                end,
                seed,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">End</span>
          <input
            type="number"
            className="input input-bordered input-sm"
            value={end}
            onChange={(e) =>
              onChange({
                pattern,
                start,
                end: Number(e.target.value),
                seed,
              })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Seed</span>
          <input
            className="input input-bordered input-sm mono"
            value={seed}
            onChange={(e) =>
              onChange({ pattern, start, end, seed: e.target.value })
            }
          />
        </label>
      </div>
    </div>
  );
}

export function GeneratorTypeSelect({
  value,
  onChange,
}: {
  value: GeneratorType | string;
  onChange: (g: GeneratorType) => void;
}) {
  const current = (value || "wordlist") as GeneratorType;
  return (
    <select
      className="select select-bordered select-sm"
      value={current}
      onChange={(e) => onChange(e.target.value as GeneratorType)}
    >
      {ALL_GENERATORS.map((g) => (
        <option key={g} value={g}>
          {GENERATOR_LABELS[g]}
        </option>
      ))}
    </select>
  );
}

/** Suggest static for small pastes. */
export function preferStaticHeuristic(text: string): boolean {
  const lines = text.split("\n").filter((l) => l.trim()).length;
  const bytes = new TextEncoder().encode(text).length;
  return (
    lines > 0 &&
    lines <= STATIC_HEURISTIC_LINES &&
    bytes <= STATIC_HEURISTIC_BYTES
  );
}
