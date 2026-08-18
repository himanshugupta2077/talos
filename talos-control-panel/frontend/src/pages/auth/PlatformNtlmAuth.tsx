/**
 * Auth workspace for platform_ntlm projects.
 * Identity is a named NTLM profile per role — not cookies or headers.
 */
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { ConfirmButton, Section } from "../../components/Common";
import type { Role } from "../../types";

interface AuthInfo {
  mode: string;
  stored_mode: string;
  inferred?: boolean;
  label: string;
  ntlm_only?: boolean;
  has_artifacts?: boolean;
  has_platform_ntlm?: boolean;
  profiles: {
    id: string;
    name: string;
    host: string;
    username: string;
    enabled: boolean;
  }[];
}

interface Binding {
  role_id: string;
  role_name: string;
  profile_id: string;
  profile_name: string;
  host: string;
  username: string;
  enabled: boolean;
  profile_missing: boolean;
}

export default function PlatformNtlmAuth({
  projectId,
  onSwitchToArtifacts,
}: {
  projectId: string;
  onSwitchToArtifacts: () => Promise<void>;
}) {
  const [auth, setAuth] = useState<AuthInfo | null>(null);
  const [bindings, setBindings] = useState<Binding[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [roleId, setRoleId] = useState("");
  const [profileKey, setProfileKey] = useState("");

  const load = useCallback(async () => {
    const [ntlm, roleResp] = await Promise.all([
      api.get<{ auth: AuthInfo; bindings: Binding[] }>("/api/auth-config/ntlm", {
        project_id: projectId,
      }),
      api.get<{ roles: Role[] }>("/api/roles", { project_id: projectId }),
    ]);
    setAuth(ntlm.auth);
    setBindings(ntlm.bindings || []);
    setRoles(roleResp.roles || []);
    setRoleId((prev) => {
      if (prev && roleResp.roles.some((r) => r.id === prev)) return prev;
      return roleResp.roles[0]?.id || "";
    });
    const first = ntlm.auth?.profiles?.[0];
    setProfileKey((prev) => prev || first?.id || "");
  }, [projectId]);

  useEffect(() => {
    load().catch(() => {
      setAuth(null);
      setBindings([]);
    });
  }, [load]);

  const bind = useAction("Bind NTLM profile", () =>
    api.post(`/api/auth-config/${roleId}/ntlm`, { profile: profileKey }, { project_id: projectId })
  );
  const unbind = useAction("Unbind NTLM profile", (rid: string) =>
    api.del(`/api/auth-config/${rid}/ntlm`, { project_id: projectId })
  );

  const after = async () => {
    await load();
  };

  const profiles = auth?.profiles || [];
  const boundForRole = bindings.find((b) => b.role_id === roleId);

  return (
    <div className="space-y-4">
      <div className="alert alert-info text-xs py-3">
        <div>
          <div className="font-semibold mb-1">Windows / NTLM platform auth</div>
          <p>
            This project does <strong>not</strong> swap cookies or{" "}
            <span className="mono">Authorization</span> headers. Identity is a
            named NTLM profile bound to each role. BAC replays the privileged
            request as the other account’s profile (fresh handshake, HTTP/1.1
            keep-alive).
          </p>
        </div>
      </div>

      <Section title="How to test BAC">
        <ol className="list-decimal pl-5 text-sm space-y-1.5 text-base-content/80">
          <li>
            Add one NTLM profile per account on{" "}
            <Link to="/proxy" className="link">
              Proxy → platform auth
            </Link>
            .
          </li>
          <li>Bind the privileged account to the ALLOW role, the other to the DENY role.</li>
          <li>
            On{" "}
            <Link to="/access" className="link">
              Access
            </Link>
            , set server expected ALLOW / DENY per module.
          </li>
          <li>
            Run{" "}
            <Link to="/testing/bac" className="link">
              BAC
            </Link>{" "}
            recipes as the DENY role. Requests land in the Burp extension JSONL.
          </li>
        </ol>
      </Section>

      <Section title="NTLM profiles">
        {profiles.length === 0 ? (
          <p className="text-sm text-base-content/60">
            No credentialed profiles yet.{" "}
            <Link to="/proxy" className="link">
              Add them on the Proxy page
            </Link>{" "}
            (<span className="mono">talos proxy auth add</span>).
          </p>
        ) : (
          <ul className="text-sm space-y-1">
            {profiles.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{p.name || p.id}</span>
                <span className="mono text-xs text-base-content/50">{p.id}</span>
                <span className="text-xs text-base-content/50">
                  {p.host} · {p.username}
                </span>
                {!p.enabled && <span className="badge badge-ghost badge-xs">disabled</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Role → profile bindings">
        <p className="text-xs text-base-content/55">
          BAC session-swap uses the attacker role’s bound profile. Two
          accounts on the same host must be two profiles, each bound to a role.
        </p>
        {bindings.length === 0 ? (
          <p className="text-sm text-base-content/50 mt-2">No bindings yet.</p>
        ) : (
          <table className="table table-xs mt-2">
            <thead>
              <tr>
                <th>Role</th>
                <th>Profile</th>
                <th>Host</th>
                <th>User</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {bindings.map((b) => (
                <tr key={b.role_id}>
                  <td>{b.role_name}</td>
                  <td>
                    {b.profile_name}
                    {b.profile_missing && (
                      <span className="badge badge-error badge-xs ml-1">missing</span>
                    )}
                  </td>
                  <td className="mono">{b.host}</td>
                  <td className="mono">{b.username}</td>
                  <td>
                    <ConfirmButton
                      className="btn btn-ghost btn-xs text-error"
                      confirmText={`Unbind NTLM from ${b.role_name}?`}
                      onConfirm={async () => {
                        await unbind.run(b.role_id);
                        await after();
                      }}
                    >
                      Unbind
                    </ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="flex flex-wrap gap-2 items-end mt-3">
          <label className="form-control">
            <span className="label-text text-xs">Role</span>
            <select
              className="select select-xs select-bordered"
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
            >
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} (priv {r.privilege ?? 0})
                </option>
              ))}
            </select>
          </label>
          <label className="form-control">
            <span className="label-text text-xs">NTLM profile</span>
            <select
              className="select select-xs select-bordered min-w-[12rem]"
              value={profileKey}
              onChange={(e) => setProfileKey(e.target.value)}
            >
              <option value="">Select profile…</option>
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id} ({p.username}@{p.host})
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="btn btn-xs btn-primary"
            disabled={!roleId || !profileKey || bind.running}
            onClick={async () => {
              await bind.run();
              await after();
            }}
          >
            {boundForRole ? "Replace binding" : "Bind"}
          </button>
        </div>
      </Section>

      <p className="text-[11px] text-base-content/40">
        Cookie/header session instead?{" "}
        <button type="button" className="link" onClick={() => onSwitchToArtifacts()}>
          Switch this project to artifacts mode
        </button>
        . That does not delete NTLM profiles.
      </p>
    </div>
  );
}
