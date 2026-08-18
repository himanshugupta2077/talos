/**
 * Access Model workspace — matrix editor, coverage, BAC/IDOR signals.
 * Full parity with `talos access client|server|delete|show|coverage|signals`.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { ModuleHelp, NoProjectNotice } from "../components/Common";
import AuthModeBadge from "../components/AuthModeBadge";
import type { AccessCell } from "../types";
import CoverageTab from "./access/CoverageTab";
import MatrixTab from "./access/MatrixTab";
import PrivilegeDiffTab from "./access/PrivilegeDiffTab";
import SignalsTab from "./access/SignalsTab";
import {
  AccessStats,
  AccessTab,
  computeStats,
  MatrixFilter,
} from "./access/shared";

export default function Access() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = (searchParams.get("tab") as AccessTab) || "matrix";
  const tab: AccessTab = ["matrix", "coverage", "signals", "privilege"].includes(
    tabParam
  )
    ? tabParam
    : "matrix";

  const [cells, setCells] = useState<AccessCell[]>([]);
  const [loading, setLoading] = useState(false);
  const [jumpFilter, setJumpFilter] = useState<MatrixFilter | null>(null);

  const load = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const r = await api.get<{ cells: AccessCell[] }>("/api/access/matrix", {
        project_id: selected.id,
      });
      setCells(r.cells || []);
    } finally {
      setLoading(false);
    }
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  const stats: AccessStats = useMemo(() => computeStats(cells), [cells]);

  const setTab = (t: AccessTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  };

  const jumpMatrix = (filter: MatrixFilter) => {
    setJumpFilter(filter);
    setTab("matrix");
  };

  if (!selected) return <NoProjectNotice />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            Access Model
            <AuthModeBadge mode={selected.auth_mode} size="sm" />
          </h1>
          <p className="text-sm text-base-content/60 mt-0.5">
            Two-layer role × module map — client exposure vs server enforcement.
            Manual ALLOW/DENY feeds BAC; privilege-diff finds the rest
            automatically from captured endpoints.
          </p>
          {selected.auth_mode === "platform_ntlm" && (
            <p className="text-xs text-warning mt-2 max-w-2xl">
              NTLM project: ALLOW / DENY is which Windows account may use a
              module. BAC replays ALLOW flows as the DENY role’s bound NTLM
              profile — not by swapping headers.
            </p>
          )}
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <Link to="/roles-modules" className="btn btn-xs btn-ghost">
            Roles &amp; Modules
          </Link>
          <Link to="/auth" className="btn btn-xs btn-ghost">
            Auth
          </Link>
          <Link to="/testing/bac" className="btn btn-xs btn-outline">
            BAC
          </Link>
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            disabled={loading}
            onClick={() => load()}
          >
            {loading ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Refresh"
            )}
          </button>
          <ModuleHelp title="How the Access Model works">
            <p>
              <strong className="text-base-content/70">Client allowed</strong> is
              what the product UI exposes for a role in a feature area (buttons,
              menus).{" "}
              <strong className="text-base-content/70">Server expected</strong> is
              your assertion of what the backend should enforce. Values: ALLOW,
              DENY, UNKNOWN — never auto-inferred.
            </p>
            <p>
              CLI:{" "}
              <span className="mono">
                talos access client|server set|unset
              </span>
              , <span className="mono">delete</span>,{" "}
              <span className="mono">coverage</span>,{" "}
              <span className="mono">signals</span>. Create roles and modules on{" "}
              <Link className="link" to="/roles-modules">
                Roles &amp; Modules
              </Link>
              , capture with the active pair, then fill this matrix.
            </p>
            <p>
              <strong className="text-base-content/70">BAC surface:</strong> a
              module where one role is ALLOW and another is DENY/UNKNOWN becomes
              candidate material for{" "}
              <Link className="link" to="/testing/bac">
                Broken Access Control
              </Link>{" "}
              testing (plus qualified 2xx proxy flows). Give roles a privilege
              rank (0 = highest) and capture the app as each identity — endpoints
              only the higher role saw are automatic candidates for the lower
              one. Same rank means peer accounts, not a privilege pair.
            </p>
            <p>
              <strong className="text-base-content/70">Example:</strong> admin /
              user × orders — client+server ALLOW for admin, DENY for user. Capture
              admin traffic on orders, then run BAC.
            </p>
          </ModuleHelp>
        </div>
      </div>

      {/* Stats strip */}
      {cells.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="badge badge-outline">
            {stats.roleCount}×{stats.moduleCount} grid
          </span>
          <span className="badge badge-ghost">
            client set {stats.clientSet}/{stats.cellCount}
          </span>
          <span className="badge badge-ghost">
            server set {stats.serverSet}/{stats.cellCount}
          </span>
          {stats.mismatch > 0 && (
            <button
              type="button"
              className="badge badge-warning badge-outline cursor-pointer"
              onClick={() => jumpMatrix("mismatch")}
              title="Show cells where client ≠ server"
            >
              {stats.mismatch} mismatch
            </button>
          )}
          {stats.fullyUnset > 0 && (
            <button
              type="button"
              className="badge badge-ghost cursor-pointer"
              onClick={() => jumpMatrix("unset")}
            >
              {stats.fullyUnset} fully unset
            </button>
          )}
          {stats.bacModules > 0 ? (
            <button
              type="button"
              className="badge badge-primary badge-outline cursor-pointer"
              onClick={() => jumpMatrix("bac_ready")}
            >
              {stats.bacModules} BAC-ready module
              {stats.bacModules === 1 ? "" : "s"}
            </button>
          ) : (
            <span className="badge badge-ghost opacity-70">
              no BAC surface yet
            </span>
          )}
          {stats.withTraffic > 0 && (
            <span className="badge badge-ghost">
              {stats.withTraffic} with traffic
            </span>
          )}
        </div>
      )}

      <div role="tablist" className="tabs tabs-boxed w-fit mb-2 flex-wrap">
        {(
          [
            ["matrix", "Matrix"],
            ["coverage", "Coverage"],
            ["signals", "Signals"],
            ["privilege", "Privilege diff"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            type="button"
            className={`tab ${tab === id ? "tab-active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "matrix" && (
        <MatrixTab
          projectId={selected.id}
          cells={cells}
          onReload={load}
          jumpFilter={jumpFilter}
          onJumpFilterConsumed={() => setJumpFilter(null)}
        />
      )}
      {tab === "coverage" && <CoverageTab projectId={selected.id} />}
      {tab === "signals" && (
        <SignalsTab projectId={selected.id} onJumpMatrix={jumpMatrix} />
      )}
      {tab === "privilege" && <PrivilegeDiffTab projectId={selected.id} />}
    </div>
  );
}
