/**
 * Privilege-diff BAC surface — endpoints seen under a higher-privilege role
 * and never mapped under a lower-privilege role.
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { PrivilegeDiffResponse, PrivilegeGap } from "../../types";

export default function PrivilegeDiffTab({ projectId }: { projectId: string }) {
  const [data, setData] = useState<PrivilegeDiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attacker, setAttacker] = useState<string>("all");
  const [openKey, setOpenKey] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    const params: Record<string, string> = { project_id: projectId };
    if (attacker !== "all") params.attacker = attacker;
    api
      .get<PrivilegeDiffResponse>("/api/access/privilege-diff", params)
      .then((r) => setData(r))
      .catch((e) => setError(e?.message || "Failed to load privilege diff"))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, [projectId, attacker]);

  const roles = data?.roles || [];
  const gaps = data?.gaps || [];
  const ranked = useMemo(
    () => [...roles].sort((a, b) => a.privilege - b.privilege || a.name.localeCompare(b.name)),
    [roles]
  );
  const distinctRanks = new Set(ranked.map((r) => r.privilege)).size;

  if (loading && !data) {
    return (
      <div className="py-12 text-center">
        <span className="loading loading-spinner" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel p-4 text-sm text-error">
        {error}{" "}
        <button type="button" className="btn btn-xs ml-2" onClick={load}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-base-content/50">
        Automatic BAC surface. Privilege <span className="mono">0</span> is
        highest. Same number = peer accounts (different people, same access).
        Capture the app as each role; endpoints only the higher role saw are
        tested with the lower role&apos;s identity (cookie session or bound
        NTLM profile). Same data as{" "}
        <span className="mono">talos access privilege-diff</span>.
      </p>

      {ranked.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center text-xs">
          {ranked.map((r) => (
            <span key={r.id} className="badge badge-outline gap-1">
              <span className="font-medium">{r.name}</span>
              <span className="opacity-60">priv {r.privilege}</span>
            </span>
          ))}
          <Link to="/roles-modules" className="btn btn-xs btn-ghost">
            Edit privileges
          </Link>
        </div>
      )}

      <div className="flex flex-wrap gap-2 items-center">
        <label className="text-xs text-base-content/60">Attacker</label>
        <select
          className="select select-xs select-bordered"
          value={attacker}
          onChange={(e) => setAttacker(e.target.value)}
        >
          <option value="all">All lower-privilege roles</option>
          {ranked.map((r) => (
            <option key={r.id} value={r.name}>
              {r.name} (priv {r.privilege})
            </option>
          ))}
        </select>
        <button type="button" className="btn btn-xs" onClick={load} disabled={loading}>
          {loading ? <span className="loading loading-spinner loading-xs" /> : "Refresh"}
        </button>
        <span className="badge badge-outline">{gaps.length} pair{gaps.length === 1 ? "" : "s"}</span>
      </div>

      {ranked.length < 2 && (
        <div className="panel p-6 text-sm text-base-content/60">
          Create at least two roles on{" "}
          <Link className="link" to="/roles-modules">
            Roles &amp; Modules
          </Link>
          , give them different privilege ranks, then capture the application
          as each identity.
        </div>
      )}

      {ranked.length >= 2 && distinctRanks < 2 && (
        <div className="panel p-6 text-sm text-base-content/60">
          All operator roles share privilege 0 (or the same rank). Same rank
          means peer accounts — no automatic candidates. Set one role to a
          higher number (weaker) on{" "}
          <Link className="link" to="/roles-modules">
            Roles &amp; Modules
          </Link>
          .
        </div>
      )}

      {ranked.length >= 2 && distinctRanks >= 2 && !gaps.length && (
        <div className="panel p-6 text-sm text-base-content/60">
          No endpoint gaps yet. Use each role for capture and browse the
          application. Endpoints that return 2xx only under the higher
          privilege role will appear here.
        </div>
      )}

      {gaps.map((gap) => (
        <GapCard
          key={`${gap.target_role_id}:${gap.attacker_role_id}`}
          gap={gap}
          open={
            openKey === `${gap.target_role_id}:${gap.attacker_role_id}`
          }
          onToggle={() => {
            const key = `${gap.target_role_id}:${gap.attacker_role_id}`;
            setOpenKey((cur) => (cur === key ? null : key));
          }}
        />
      ))}
    </div>
  );
}

function GapCard({
  gap,
  open,
  onToggle,
}: {
  gap: PrivilegeGap;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="panel border-t-2 border-t-warning">
      <button
        type="button"
        className="w-full text-left p-3 flex flex-wrap items-start justify-between gap-2"
        onClick={onToggle}
      >
        <div>
          <div className="text-sm font-medium">
            {gap.target_role_name}{" "}
            <span className="text-base-content/50 font-normal">
              (priv {gap.target_privilege})
            </span>
            <span className="mx-1 text-base-content/30">→</span>
            {gap.attacker_role_name}{" "}
            <span className="text-base-content/50 font-normal">
              (priv {gap.attacker_privilege})
            </span>
          </div>
          <p className="text-[11px] text-base-content/50 mt-0.5">
            {gap.endpoint_count} endpoint
            {gap.endpoint_count === 1 ? "" : "s"} present for{" "}
            {gap.target_role_name} and absent for {gap.attacker_role_name}.
            Test with {gap.attacker_role_name}&apos;s identity.
          </p>
        </div>
        <span className="badge badge-warning badge-outline badge-sm">
          {gap.endpoint_count}
        </span>
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-2">
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Module</th>
                  <th>Flows</th>
                </tr>
              </thead>
              <tbody>
                {gap.endpoints.map((ep) => (
                  <tr key={ep.endpoint_id}>
                    <td className="mono">
                      {ep.method} {ep.host}
                      {ep.path}
                    </td>
                    <td>{ep.module_name}</td>
                    <td>{ep.flow_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Link
            to={`/testing/bac?tab=run&role=${encodeURIComponent(gap.attacker_role_name)}`}
            className="btn btn-xs btn-primary"
          >
            Run BAC as {gap.attacker_role_name}
          </Link>
        </div>
      )}
    </div>
  );
}
