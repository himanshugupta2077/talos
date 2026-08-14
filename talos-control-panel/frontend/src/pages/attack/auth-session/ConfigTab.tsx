import { useCallback, useEffect, useState } from "react";
import { useAction } from "../../../hooks/useAction";
import { api } from "../../../api/client";
import { Section } from "../../../components/Common";
import DataTable, { Column } from "../../../components/DataTable";
import type { StepsResponse } from "../../../types";
import {
  KNOWN_FAMILIES,
  inputClass,
  selectClass,
  type AuthSessionOverview,
  type AuthSessionSuiteCase,
} from "./shared";

export default function ConfigTab({
  projectId,
  overview,
  onRefresh,
}: {
  projectId: string;
  overview: AuthSessionOverview | null;
  onRefresh: () => void;
}) {
  const [filterText, setFilterText] = useState<string | null>(null);
  const [validateMsg, setValidateMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);
  const [openDirMsg, setOpenDirMsg] = useState<string | null>(null);
  const [suite, setSuite] = useState<AuthSessionSuiteCase[]>([]);
  const [suiteLoading, setSuiteLoading] = useState(false);
  const [alg, setAlg] = useState("");
  const [family, setFamily] = useState("");

  const filterPath =
    overview?.filter_path ||
    "…/auth-session-decision-filter.yaml";
  const filterExists = overview?.filter_exists;
  const filterFilename =
    overview?.filter_filename || "auth-session-decision-filter.yaml";

  const extractStdout = (res: StepsResponse | undefined) => {
    const steps = res?.steps || [];
    const last = steps[steps.length - 1];
    return {
      ok: last?.ok !== false && (last?.exit_code ?? 0) === 0,
      text: (last?.stdout || last?.stderr || "").trim(),
    };
  };

  const filterInit = useAction("Init auth-session filter", () =>
    api.post(
      "/api/attack/auth-session/filter/init",
      {},
      { project_id: projectId }
    )
  );
  const filterShow = useAction("Show auth-session filter", () =>
    api.post(
      "/api/attack/auth-session/filter/show",
      {},
      { project_id: projectId }
    )
  );
  const filterValidate = useAction("Validate auth-session filter", () =>
    api.post(
      "/api/attack/auth-session/filter/validate",
      {},
      { project_id: projectId }
    )
  );
  const openDataDir = useAction("Open project data dir", async () => {
    const result = await api.post<{
      ok?: boolean;
      message?: string;
      path?: string;
      target?: string;
    }>(`/api/projects/${projectId}/open-directory`, { target: "data_dir" });
    const ok = result.ok !== false;
    const detail =
      result.message ||
      (ok
        ? `Directory open requested${result.path ? `: ${result.path}` : ""}`
        : "Directory open failed");
    return {
      steps: [
        {
          cmd: ["open-directory", result.target || "data_dir"],
          cmd_str: `open-directory target=${result.target || "data_dir"}`,
          stdout: ok ? detail : "",
          stderr: ok ? "" : detail,
          exit_code: ok ? 0 : 1,
          duration_ms: 0,
          ok,
        },
      ],
    };
  });

  const loadSuite = useCallback(() => {
    setSuiteLoading(true);
    const params: Record<string, string | undefined> = {
      auth_type: "jwt",
    };
    if (alg.trim()) params.alg = alg.trim();
    if (family) params.family = family;
    api
      .get<{ items: AuthSessionSuiteCase[] }>(
        "/api/attack/auth-session/suite",
        params
      )
      .then((r) => setSuite(r.items || []))
      .catch(() => setSuite([]))
      .finally(() => setSuiteLoading(false));
  }, [alg, family]);

  useEffect(() => {
    loadSuite();
  }, [loadSuite]);

  const suiteColumns: Column<AuthSessionSuiteCase>[] = [
    {
      key: "test_id",
      header: "test_id",
      className: "mono text-xs",
      defaultWidth: 160,
    },
    {
      key: "family",
      header: "Family",
      className: "mono text-xs",
      defaultWidth: 110,
    },
    {
      key: "title",
      header: "Title",
      className: "text-xs",
      defaultWidth: 180,
    },
    {
      key: "risk_hint",
      header: "Risk",
      className: "text-xs",
      defaultWidth: 70,
      render: (r) => r.risk_hint || "—",
    },
    {
      key: "source",
      header: "Source",
      className: "text-xs",
      defaultWidth: 120,
    },
  ];

  return (
    <div className="space-y-6">
      <Section title="Decision filter">
        <div className="panel p-4 space-y-3">
          <div className="alert text-xs py-2 bg-base-200 border border-base-300">
            <span>
              <strong>No reclassify/apply in v1.</strong> Edit{" "}
              <span className="mono">{filterFilename}</span> on disk, then{" "}
              <strong>re-run</strong> the JWT tests to rescore. Historical
              result rows are not rewritten.
            </span>
          </div>

          <div className="text-xs space-y-1">
            <div>
              <span className="text-base-content/50">Filename: </span>
              <span className="mono">{filterFilename}</span>
            </div>
            <div>
              <span className="text-base-content/50">Path: </span>
              <span className="mono break-all">{filterPath}</span>
              {filterExists === true && (
                <span className="badge badge-success badge-xs ml-2">exists</span>
              )}
              {filterExists === false && (
                <span className="badge badge-ghost badge-xs ml-2">missing</span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn btn-xs"
              disabled={filterInit.running}
              onClick={async () => {
                try {
                  const res = (await filterInit.run()) as StepsResponse | undefined;
                  const { text } = extractStdout(res);
                  if (text) setFilterText(text);
                  setValidateMsg(null);
                  onRefresh();
                } catch {
                  /* logged */
                }
              }}
            >
              Init
            </button>
            <button
              type="button"
              className="btn btn-xs"
              disabled={filterShow.running}
              onClick={async () => {
                try {
                  const res = (await filterShow.run()) as StepsResponse & {
                    stdout?: string;
                  };
                  const fromField = res?.stdout?.trim();
                  const { text } = extractStdout(res);
                  setFilterText(fromField || text || "(empty)");
                  setValidateMsg(null);
                } catch {
                  /* logged */
                }
              }}
            >
              Show
            </button>
            <button
              type="button"
              className="btn btn-xs"
              disabled={filterValidate.running}
              onClick={async () => {
                try {
                  const res = (await filterValidate.run()) as StepsResponse | undefined;
                  const { ok, text } = extractStdout(res);
                  setValidateMsg({ ok, text: text || (ok ? "valid" : "invalid") });
                } catch {
                  /* logged */
                }
              }}
            >
              Validate
            </button>
            <button
              type="button"
              className="btn btn-xs btn-outline"
              disabled={openDataDir.running}
              onClick={async () => {
                try {
                  await openDataDir.run();
                  setOpenDirMsg("Opened project data directory in the file manager.");
                } catch (err) {
                  setOpenDirMsg(
                    `Could not open directory (headless?). Path: ${filterPath}`
                  );
                }
              }}
            >
              Open data dir
            </button>
          </div>

          {openDirMsg && (
            <p className="text-xs text-base-content/60 mono">{openDirMsg}</p>
          )}

          {validateMsg && (
            <div
              className={`alert text-xs py-2 ${
                validateMsg.ok ? "alert-success" : "alert-error"
              }`}
            >
              <pre className="whitespace-pre-wrap mono text-xs">
                {validateMsg.text}
              </pre>
            </div>
          )}

          {filterText && (
            <div>
              <div className="text-xs text-base-content/50 mb-1">Filter YAML</div>
              <pre className="panel p-3 text-xs mono whitespace-pre-wrap max-h-80 overflow-auto">
                {filterText}
              </pre>
            </div>
          )}

          <p className="text-[11px] text-base-content/45">
            CLI:{" "}
            <span className="mono">
              talos attack auth-session filter init|show|validate
            </span>
            . Console group:{" "}
            <span className="mono">attack.auth-session.filter.*</span>
          </p>
        </div>
      </Section>

      <Section
        title="Suite catalog (JWT)"
        action={
          <button type="button" className="btn btn-xs btn-ghost" onClick={loadSuite}>
            Refresh
          </button>
        }
      >
        <div className="panel p-4 space-y-3">
          <p className="text-xs text-base-content/60">
            Read-only catalog of mutation <span className="mono">test_id</span>s
            used by generate. Enter an observed <span className="mono">alg</span>{" "}
            (e.g. RS256) to expand the algorithm-degradation matrix.
          </p>
          <div className="flex flex-wrap items-end gap-2">
            <label className="form-control w-32">
              <span className="label-text text-xs">Observed alg</span>
              <input
                className={`${inputClass} mono`}
                value={alg}
                onChange={(e) => setAlg(e.target.value)}
                placeholder="RS256"
              />
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
          </div>

          {suiteLoading && suite.length === 0 ? (
            <div className="text-sm text-base-content/50">Loading suite…</div>
          ) : (
            <DataTable
              columns={suiteColumns}
              rows={suite}
              rowKey={(r) => `${r.source}:${r.test_id}`}
              emptyLabel="No suite rows (unexpected)."
            />
          )}
          <p className="text-[11px] text-base-content/45">
            {suite.length} case{suite.length === 1 ? "" : "s"}
            {alg.trim() ? ` (core + degrade for alg=${alg.trim()})` : " (core only)"}
            . CLI:{" "}
            <span className="mono">
              talos attack auth-session suite list --type jwt
              {alg.trim() ? ` --alg ${alg.trim()}` : ""}
            </span>
          </p>
        </div>
      </Section>
    </div>
  );
}
