import { useEffect, useMemo, useState } from "react";
import { useProject } from "../state/ProjectContext";
import { useCommandLog } from "../state/CommandLogContext";
import { api } from "../api/client";
import { CommandArgSpec, CommandGroup, CommandSpec } from "../types";

type Values = Record<string, any>;

function defaultsFor(command: CommandSpec): Values {
  const values: Values = {};
  for (const spec of command.args) {
    if (spec.kind === "boolean") values[spec.name] = spec.default === true || spec.default === "true";
    else if (spec.kind === "multi") values[spec.name] = spec.default ? [spec.default] : [];
    else values[spec.name] = spec.default ?? "";
  }
  return values;
}

// Mirrors backend build_argv() exactly, for a live "what will run" preview.
// The server rebuilds this itself from the same spec — this is display-only.
function previewArgv(command: CommandSpec, values: Values): string[] {
  const positionals: string[] = [];
  const flagged: string[] = [];
  for (const spec of command.args) {
    const val = values[spec.name];
    if (val === undefined || val === null || val === "" || (Array.isArray(val) && val.length === 0)) continue;
    if (spec.kind === "boolean") {
      if (spec.flag && (val === true || String(val).toLowerCase() === "true")) flagged.push(spec.flag);
      continue;
    }
    if (spec.kind === "multi") {
      const items = Array.isArray(val) ? val : [val];
      for (const item of items) {
        const s = String(item);
        if (!s) continue;
        if (spec.flag) {
          flagged.push(spec.flag, s);
        } else {
          positionals.push(s);
        }
      }
      continue;
    }
    const s = String(val);
    if (spec.flag) flagged.push(spec.flag, s);
    else positionals.push(s);
  }
  return ["talos", ...command.path, ...positionals, ...flagged];
}

function Field({
  spec, value, onChange,
}: {
  spec: CommandArgSpec;
  value: any;
  onChange: (v: any) => void;
}) {
  if (spec.kind === "boolean") {
    return (
      <label className="label cursor-pointer justify-start gap-2">
        <input
          type="checkbox"
          className="checkbox checkbox-sm"
          checked={!!value}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className="label-text text-sm">
          {spec.label} {spec.required && <span className="text-error">*</span>}
        </span>
      </label>
    );
  }

  if (spec.kind === "select") {
    return (
      <label className="form-control">
        <span className="label-text text-xs">
          {spec.label} {spec.required && <span className="text-error">*</span>}
        </span>
        <select
          className="select select-sm select-bordered mono"
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">—</option>
          {spec.options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (spec.kind === "multi") {
    const text = Array.isArray(value) ? value.join("\n") : "";
    return (
      <label className="form-control">
        <span className="label-text text-xs">
          {spec.label} {spec.required && <span className="text-error">*</span>}{" "}
          <span className="text-base-content/40">(one per line)</span>
        </span>
        <textarea
          className="textarea textarea-sm textarea-bordered mono"
          rows={3}
          value={text}
          onChange={(e) =>
            onChange(e.target.value.split("\n").map((s) => s.trim()).filter(Boolean))
          }
        />
      </label>
    );
  }

  return (
    <label className="form-control">
      <span className="label-text text-xs">
        {spec.label} {spec.required && <span className="text-error">*</span>}
      </span>
      <input
        type={spec.kind === "number" ? "number" : "text"}
        className="input input-sm input-bordered mono"
        value={value ?? ""}
        placeholder={spec.help}
        onChange={(e) => onChange(e.target.value)}
      />
      {spec.help && <span className="text-[11px] text-base-content/40 mt-0.5">{spec.help}</span>}
    </label>
  );
}

export default function Console() {
  const { selected } = useProject();
  const { log } = useCommandLog();

  const [groups, setGroups] = useState<CommandGroup[]>([]);
  const [groupId, setGroupId] = useState<string | null>(null);
  const [command, setCommand] = useState<CommandSpec | null>(null);
  const [values, setValues] = useState<Values>({});
  const [scoped, setScoped] = useState(true);
  const [running, setRunning] = useState(false);
  const [bgResult, setBgResult] = useState<any | null>(null);
  const [mode, setMode] = useState<"modeled" | "raw">("modeled");
  const [rawArgs, setRawArgs] = useState("");

  useEffect(() => {
    api.get<{ groups: CommandGroup[] }>("/api/console/tree").then((r) => {
      setGroups(r.groups);
      setGroupId(r.groups[0]?.group ?? null);
    });
  }, []);

  const activeGroup = groups.find((g) => g.group === groupId) ?? null;

  const missingRequired = useMemo(() => {
    if (!command) return [];
    return command.args.filter((spec) => {
      if (!spec.required) return false;
      const v = values[spec.name];
      return v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0);
    });
  }, [command, values]);

  const selectCommand = (c: CommandSpec) => {
    setCommand(c);
    setValues(defaultsFor(c));
    setBgResult(null);
  };

  const runModeled = async () => {
    if (!command) return;
    setRunning(true);
    setBgResult(null);
    try {
      const res = await api.post<any>("/api/console/run", {
        command_id: command.id,
        values,
        project_id: scoped && selected ? selected.id : undefined,
      });
      if (res.background) {
        setBgResult(res);
      } else if (res.steps) {
        log(`Console: ${command.summary}`, res.steps);
      } else if (res.error) {
        log(`Console: ${command.summary}`, [
          {
            cmd: [], cmd_str: "", stdout: "", stderr: res.error,
            exit_code: -1, duration_ms: 0, ok: false,
          },
        ]);
      }
    } finally {
      setRunning(false);
    }
  };

  const runRaw = async () => {
    const args = rawArgs.split(/\s+/).filter(Boolean);
    if (args.length === 0) return;
    setRunning(true);
    try {
      const res = await api.post<any>("/api/console/raw", {
        args,
        project_id: scoped && selected ? selected.id : undefined,
      });
      log(`Console: raw — talos ${args.join(" ")}`, res.steps || []);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <h1 className="text-xl font-semibold">Console</h1>
        <div className="tabs tabs-boxed tabs-sm">
          <button
            className={`tab ${mode === "modeled" ? "tab-active" : ""}`}
            onClick={() => setMode("modeled")}
          >
            Modeled commands
          </button>
          <button className={`tab ${mode === "raw" ? "tab-active" : ""}`} onClick={() => setMode("raw")}>
            Raw
          </button>
        </div>
      </div>
      <p className="text-sm text-base-content/60 mb-4">
        Full-coverage fallback for any <span className="mono">talos</span> command — including ones
        that don't have a dedicated page yet. Every action here still runs through the CLI, exactly
        like everywhere else in the panel.
      </p>

      <div className="flex items-center gap-3 mb-4 panel px-3 py-2">
        <label className="label cursor-pointer gap-2 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-sm"
            checked={scoped}
            onChange={(e) => setScoped(e.target.checked)}
          />
          <span className="label-text text-sm">Scope to active project</span>
        </label>
        {scoped && (
          selected ? (
            <span className="badge badge-sm badge-outline mono">{selected.name}</span>
          ) : (
            <span className="text-xs text-warning">
              No project selected — scoped commands will fail until one is chosen above.
            </span>
          )
        )}
        {scoped && (
          <span className="text-[11px] text-base-content/40">
            (runs <span className="mono">talos project open &lt;id&gt;</span> first, then the command)
          </span>
        )}
      </div>

      {mode === "raw" ? (
        <div className="panel p-4">
          <label className="form-control mb-3">
            <span className="label-text text-xs">Arguments (space-separated, no shell quoting)</span>
            <input
              className="input input-sm input-bordered mono"
              value={rawArgs}
              onChange={(e) => setRawArgs(e.target.value)}
              placeholder="finding list --status CONFIRMED"
            />
          </label>
          <div className="mono text-xs text-base-content/50 mb-3">
            $ talos {rawArgs || "…"}
          </div>
          <button className="btn btn-sm btn-primary" disabled={running || !rawArgs.trim()} onClick={runRaw}>
            {running ? <span className="loading loading-spinner loading-xs" /> : "Run"}
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-3 panel p-2 h-fit">
            {groups.map((g) => (
              <button
                key={g.group}
                className={`block w-full text-left px-2 py-1.5 rounded text-sm ${
                  g.group === groupId ? "bg-primary/10 text-primary font-medium" : "hover:bg-base-200"
                }`}
                onClick={() => {
                  setGroupId(g.group);
                  setCommand(null);
                  setBgResult(null);
                }}
              >
                {g.label}
              </button>
            ))}
          </div>

          <div className="col-span-4 panel p-2 h-fit max-h-[70vh] overflow-y-auto">
            {activeGroup?.commands.map((c) => (
              <button
                key={c.id}
                className={`block w-full text-left px-2 py-1.5 rounded text-sm ${
                  command?.id === c.id ? "bg-primary/10 text-primary" : "hover:bg-base-200"
                }`}
                onClick={() => selectCommand(c)}
              >
                <div className="flex items-center gap-2">
                  <span className="mono text-xs text-base-content/50">
                    {c.path.join(" ")}
                  </span>
                  {c.background && <span className="badge badge-xs badge-info">background</span>}
                </div>
                <div className="text-xs text-base-content/60">{c.summary}</div>
              </button>
            ))}
          </div>

          <div className="col-span-5 panel p-4">
            {!command && (
              <div className="text-sm text-base-content/50 text-center py-8">
                Choose a command from the list.
              </div>
            )}
            {command && (
              <>
                <div className="mb-3">
                  <div className="font-medium text-sm">{command.summary}</div>
                  <div className="mono text-xs text-base-content/40">talos {command.path.join(" ")}</div>
                </div>

                <div className="space-y-3 mb-4">
                  {command.args.length === 0 && (
                    <div className="text-xs text-base-content/40">No arguments.</div>
                  )}
                  {command.args.map((spec) => (
                    <Field
                      key={spec.name}
                      spec={spec}
                      value={values[spec.name]}
                      onChange={(v) => setValues((prev) => ({ ...prev, [spec.name]: v }))}
                    />
                  ))}
                </div>

                <div className="mono text-xs text-base-content/50 mb-3 break-all">
                  $ {previewArgv(command, values).join(" ")}
                </div>

                <button
                  className="btn btn-sm btn-primary"
                  disabled={running || missingRequired.length > 0}
                  onClick={runModeled}
                >
                  {running ? <span className="loading loading-spinner loading-xs" /> : "Run"}
                </button>

                {bgResult && (
                  <div className="mt-4 panel p-3 mono text-xs">
                    {bgResult.error ? (
                      <div className="text-error">{bgResult.error}</div>
                    ) : (
                      <>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={bgResult.running ? "text-success" : "text-error"}>
                            {bgResult.running ? "●" : "○"}
                          </span>
                          <span>{bgResult.already_running ? "already running" : "started"}</span>
                          <span className="text-base-content/40 ml-auto">pid {bgResult.pid}</span>
                        </div>
                        <div className="text-base-content/60">{bgResult.cmd_str}</div>
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
