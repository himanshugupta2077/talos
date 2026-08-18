/**
 * Roles & Modules — create and manage identity types (roles) and feature
 * areas (modules); switch capture context via talos role|module set/unset.
 *
 * All writes go through Control Panel APIs that call Talos CLI (create, set,
 * unset, rename, delete). List reads use the project DB.
 */

import { useEffect, useState } from "react";
import { useProject } from "../state/ProjectContext";
import { useStatus } from "../state/StatusContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import {
  ConfirmButton,
  FieldHint,
  ModuleHelp,
  NoProjectNotice,
  UuidChip,
} from "../components/Common";
import { Role, Module } from "../types";

const GLOBAL_NAME = "global";

export default function RolesModules() {
  const { selected } = useProject();
  const { refreshStatus } = useStatus();
  const [roles, setRoles] = useState<Role[]>([]);
  const [modules, setModules] = useState<Module[]>([]);
  const [roleName, setRoleName] = useState("");
  const [rolePrivilege, setRolePrivilege] = useState("0");
  const [editingPrivilege, setEditingPrivilege] = useState<string | null>(null);
  const [privilegeValue, setPrivilegeValue] = useState("0");
  const [moduleName, setModuleName] = useState("");
  const [moduleDesc, setModuleDesc] = useState("");
  const [renamingRole, setRenamingRole] = useState<string | null>(null);
  const [renamingModule, setRenamingModule] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const loadRoles = () =>
    selected &&
    api
      .get<{ roles: Role[] }>("/api/roles", { project_id: selected.id })
      .then((r) => setRoles(r.roles));
  const loadModules = () =>
    selected &&
    api
      .get<{ modules: Module[] }>("/api/modules", { project_id: selected.id })
      .then((r) => setModules(r.modules));

  const reload = async () => {
    await Promise.all([loadRoles(), loadModules()]);
    await refreshStatus();
  };

  useEffect(() => {
    loadRoles();
    loadModules();
  }, [selected]);

  const createRole = useAction("Create role", () =>
    api.post(
      "/api/roles",
      { name: roleName, privilege: Number(rolePrivilege) || 0 },
      { project_id: selected!.id }
    )
  );
  const setRole = useAction("Use role for capture", (name: string) =>
    api.post("/api/roles/set", { name }, { project_id: selected!.id })
  );
  const unsetRole = useAction("Reset role to global", () =>
    api.post("/api/roles/unset", {}, { project_id: selected!.id })
  );
  const renameRole = useAction("Rename role", (name: string, newName: string) =>
    api.post(
      "/api/roles/rename",
      { name, new_name: newName },
      { project_id: selected!.id }
    )
  );
  const deleteRole = useAction("Delete role", (name: string) =>
    api.post("/api/roles/delete", { name }, { project_id: selected!.id })
  );
  const setPrivilege = useAction(
    "Set role privilege",
    (name: string, privilege: number) =>
      api.post(
        "/api/roles/privilege",
        { name, privilege },
        { project_id: selected!.id }
      )
  );

  const createModule = useAction("Create module", () =>
    api.post(
      "/api/modules",
      { name: moduleName, description: moduleDesc },
      { project_id: selected!.id }
    )
  );
  const setModule = useAction("Use module for capture", (name: string) =>
    api.post("/api/modules/set", { name }, { project_id: selected!.id })
  );
  const unsetModule = useAction("Reset module to global", () =>
    api.post("/api/modules/unset", {}, { project_id: selected!.id })
  );
  const renameModule = useAction(
    "Rename module",
    (name: string, newName: string) =>
      api.post(
        "/api/modules/rename",
        { name, new_name: newName },
        { project_id: selected!.id }
      )
  );
  const deleteModule = useAction("Delete module", (name: string) =>
    api.post("/api/modules/delete", { name }, { project_id: selected!.id })
  );

  if (!selected) return <NoProjectNotice />;

  const activeRole = roles.find((r) => !!r.is_active) || null;
  const activeModule = modules.find((m) => !!m.is_active) || null;
  const busy =
    createRole.running ||
    setRole.running ||
    unsetRole.running ||
    renameRole.running ||
    deleteRole.running ||
    setPrivilege.running ||
    createModule.running ||
    setModule.running ||
    unsetModule.running ||
    renameModule.running ||
    deleteModule.running;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Roles &amp; Modules</h1>
        <p className="text-xs text-base-content/50 mt-0.5">
          Identity types and feature areas for tagging capture and modeling access.
          Active pair stamps new proxy traffic; switching may restart a running proxy.
        </p>
      </div>

      <ModuleHelp title="How roles and modules work">
        <p>
          <strong className="text-base-content/70">Roles</strong> are who is
          testing (e.g. admin, user).{" "}
          <strong className="text-base-content/70">Modules</strong> are what is
          being tested (e.g. orders, billing). Together they label traffic and
          drive the access matrix used by BAC-style checks. Privilege{" "}
          <span className="mono">0</span> is highest; the same number on two
          roles means peer accounts. A higher number is weaker and is the
          attacker for automatic privilege-diff BAC.
        </p>
        <p>
          <strong className="text-base-content/70">Use for capture</strong> runs{" "}
          <span className="mono">talos role|module set</span> so new flows are
          stamped with that name.{" "}
          <strong className="text-base-content/70">Reset to global</strong> runs{" "}
          <span className="mono">talos role|module unset</span>, which does not
          clear the context — it switches the active value back to the built-in{" "}
          <span className="mono">global</span> role/module. The header chips
          offer the same switch/reset controls.
        </p>
        <p>
          <strong className="text-base-content/70">Rename</strong> only changes
          the display name (UUID stays stable).{" "}
          <strong className="text-base-content/70">Delete</strong> cascades access
          and related config and reassigns tagged flows to{" "}
          <span className="mono">global</span>. Built-in{" "}
          <span className="mono">global</span> cannot be renamed or deleted.
        </p>
        <p>
          <strong className="text-base-content/70">Example:</strong> create role{" "}
          <span className="mono">admin</span> and module{" "}
          <span className="mono">orders</span>, use both for capture, browse the
          app as admin on order pages, then set the access matrix for that pair.
        </p>
      </ModuleHelp>

      {/* Capture context — what set/unset actually control */}
      <div className="panel p-3 flex flex-wrap items-center gap-3 border-t-2 border-t-accent">
        <div className="text-xs font-medium text-base-content/60 shrink-0">
          Capture tags new flows as
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="badge badge-primary badge-sm gap-1">
            role
            <span className="font-semibold">{activeRole?.name || "—"}</span>
          </span>
          <span className="text-base-content/30">×</span>
          <span className="badge badge-secondary badge-sm gap-1">
            module
            <span className="font-semibold">{activeModule?.name || "—"}</span>
          </span>
        </div>
        <p className="text-[11px] text-base-content/45 w-full sm:w-auto sm:ml-auto">
          Only one role and one module are active. Unset resets to{" "}
          <span className="mono">global</span>, not to empty.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* ── Roles ───────────────────────────────────────────── */}
        <div className="panel p-4 border-t-2 border-t-primary">
          <h2 className="font-semibold mb-1 flex items-center gap-2">
            <span className="badge badge-primary badge-sm">Roles</span>
            <span className="text-xs font-normal text-base-content/50">
              Identity types (who is testing)
            </span>
          </h2>
          <p className="text-[11px] text-base-content/45 mb-3">
            Create a short name, then use it for capture while you browse as that
            identity. Prefer names you will also use on Access and Auth.
          </p>
          <div className="flex gap-2 mb-3">
            <input
              className="input input-sm input-bordered flex-1"
              placeholder="admin"
              value={roleName}
              onChange={(e) => setRoleName(e.target.value)}
              disabled={busy}
            />
            <input
              className="input input-sm input-bordered w-20"
              type="number"
              min={0}
              step={1}
              title="Privilege (0 = highest)"
              value={rolePrivilege}
              onChange={(e) => setRolePrivilege(e.target.value)}
              disabled={busy}
            />
            <button
              className="btn btn-sm btn-primary"
              disabled={!roleName.trim() || createRole.running}
              onClick={async () => {
                await createRole.run();
                setRoleName("");
                setRolePrivilege("0");
                await reload();
              }}
            >
              Create
            </button>
          </div>
          <p className="text-[11px] text-base-content/45 -mt-2 mb-3">
            Privilege number: 0 is highest. Same number = same access, different
            account.
          </p>
          <div className="divide-y divide-base-300 rounded border border-base-300">
            {roles.length === 0 && (
              <div className="p-4 text-sm text-base-content/50">No roles yet.</div>
            )}
            {roles.map((r) => {
              const isActive = !!r.is_active;
              const isGlobal = r.name === GLOBAL_NAME;
              const isRenaming = renamingRole === r.name;
              return (
                <div
                  key={r.id}
                  className={`p-3 space-y-2 ${isActive ? "bg-success/10" : ""}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-sm">{r.name}</span>
                        {isActive && (
                          <span className="badge badge-success badge-xs">
                            capturing
                          </span>
                        )}
                        {isGlobal && (
                          <span className="badge badge-ghost badge-xs">built-in</span>
                        )}
                        <span
                          className="badge badge-ghost badge-xs"
                          title="0 = highest privilege"
                        >
                          priv {r.privilege ?? 0}
                        </span>
                      </div>
                      <div className="mt-0.5">
                        <UuidChip value={r.id} />
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1 justify-end shrink-0">
                      {!isActive ? (
                        <button
                          className="btn btn-xs btn-primary btn-outline"
                          disabled={busy}
                          onClick={async () => {
                            await setRole.run(r.name);
                            await reload();
                          }}
                        >
                          Use for capture
                        </button>
                      ) : (
                        !isGlobal && (
                          <button
                            className="btn btn-xs"
                            disabled={busy}
                            onClick={async () => {
                              await unsetRole.run();
                              await reload();
                            }}
                          >
                            Reset to global
                          </button>
                        )
                      )}
                      {!isGlobal && (
                        <>
                          <button
                            className="btn btn-xs btn-ghost"
                            disabled={busy}
                            onClick={() => {
                              setRenamingRole(isRenaming ? null : r.name);
                              setRenameValue(r.name);
                              setRenamingModule(null);
                              setEditingPrivilege(null);
                            }}
                          >
                            Rename
                          </button>
                          <button
                            className="btn btn-xs btn-ghost"
                            disabled={busy}
                            onClick={() => {
                              const next =
                                editingPrivilege === r.name ? null : r.name;
                              setEditingPrivilege(next);
                              setPrivilegeValue(String(r.privilege ?? 0));
                              setRenamingRole(null);
                            }}
                          >
                            Privilege
                          </button>
                          <ConfirmButton
                            className="btn btn-xs btn-ghost text-error"
                            confirmText="Delete role? Flows → global"
                            onConfirm={async () => {
                              await deleteRole.run(r.name);
                              setRenamingRole(null);
                              setEditingPrivilege(null);
                              await reload();
                            }}
                          >
                            Delete
                          </ConfirmButton>
                        </>
                      )}
                      {isGlobal && (
                        <button
                          className="btn btn-xs btn-ghost"
                          disabled={busy}
                          onClick={() => {
                            const next =
                              editingPrivilege === r.name ? null : r.name;
                            setEditingPrivilege(next);
                            setPrivilegeValue(String(r.privilege ?? 0));
                            setRenamingRole(null);
                          }}
                        >
                          Privilege
                        </button>
                      )}
                    </div>
                  </div>
                  {editingPrivilege === r.name && (
                    <div className="flex gap-2 items-center">
                      <input
                        className="input input-xs input-bordered w-24"
                        type="number"
                        min={0}
                        step={1}
                        value={privilegeValue}
                        onChange={(e) => setPrivilegeValue(e.target.value)}
                        title="0 = highest"
                        autoFocus
                      />
                      <span className="text-[11px] text-base-content/50">
                        0 = highest
                      </span>
                      <button
                        className="btn btn-xs btn-primary"
                        disabled={busy || privilegeValue === ""}
                        onClick={async () => {
                          const n = Number(privilegeValue);
                          if (!Number.isInteger(n) || n < 0) return;
                          await setPrivilege.run(r.name, n);
                          setEditingPrivilege(null);
                          await reload();
                        }}
                      >
                        Save
                      </button>
                      <button
                        className="btn btn-xs btn-ghost"
                        onClick={() => setEditingPrivilege(null)}
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                  {isRenaming && (
                    <div className="flex gap-2 items-center">
                      <input
                        className="input input-xs input-bordered flex-1"
                        value={renameValue}
                        onChange={(e) => setRenameValue(e.target.value)}
                        placeholder="New role name"
                        autoFocus
                      />
                      <button
                        className="btn btn-xs btn-primary"
                        disabled={!renameValue.trim() || renameValue.trim() === r.name || busy}
                        onClick={async () => {
                          await renameRole.run(r.name, renameValue.trim());
                          setRenamingRole(null);
                          await reload();
                        }}
                      >
                        Save
                      </button>
                      <button
                        className="btn btn-xs btn-ghost"
                        onClick={() => setRenamingRole(null)}
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Modules ─────────────────────────────────────────── */}
        <div className="panel p-4 border-t-2 border-t-secondary">
          <h2 className="font-semibold mb-1 flex items-center gap-2">
            <span className="badge badge-secondary badge-sm">Modules</span>
            <span className="text-xs font-normal text-base-content/50">
              Feature areas (what is being tested)
            </span>
          </h2>
          <p className="text-[11px] text-base-content/45 mb-3">
            Name the product area you are exercising. Description is optional and
            shown only here for your notes.
            <FieldHint text="Description is stored with the module; it does not affect capture or access logic." />
          </p>
          <div className="flex flex-wrap gap-2 mb-3">
            <input
              className="input input-sm input-bordered flex-1 min-w-[6rem]"
              placeholder="orders"
              value={moduleName}
              onChange={(e) => setModuleName(e.target.value)}
              disabled={busy}
            />
            <input
              className="input input-sm input-bordered flex-1 min-w-[6rem]"
              placeholder="Description (optional)"
              value={moduleDesc}
              onChange={(e) => setModuleDesc(e.target.value)}
              disabled={busy}
            />
            <button
              className="btn btn-sm btn-primary"
              disabled={!moduleName.trim() || createModule.running}
              onClick={async () => {
                await createModule.run();
                setModuleName("");
                setModuleDesc("");
                await reload();
              }}
            >
              Create
            </button>
          </div>
          <div className="divide-y divide-base-300 rounded border border-base-300">
            {modules.length === 0 && (
              <div className="p-4 text-sm text-base-content/50">No modules yet.</div>
            )}
            {modules.map((m) => {
              const isActive = !!m.is_active;
              const isGlobal = m.name === GLOBAL_NAME;
              const isRenaming = renamingModule === m.name;
              return (
                <div
                  key={m.id}
                  className={`p-3 space-y-2 ${isActive ? "bg-success/10" : ""}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-sm">{m.name}</span>
                        {isActive && (
                          <span className="badge badge-success badge-xs">
                            capturing
                          </span>
                        )}
                        {isGlobal && (
                          <span className="badge badge-ghost badge-xs">built-in</span>
                        )}
                      </div>
                      {m.description ? (
                        <div className="text-xs text-base-content/50 mt-0.5">
                          {m.description}
                        </div>
                      ) : null}
                      <div className="mt-0.5">
                        <UuidChip value={m.id} />
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1 justify-end shrink-0">
                      {!isActive ? (
                        <button
                          className="btn btn-xs btn-secondary btn-outline"
                          disabled={busy}
                          onClick={async () => {
                            await setModule.run(m.name);
                            await reload();
                          }}
                        >
                          Use for capture
                        </button>
                      ) : (
                        !isGlobal && (
                          <button
                            className="btn btn-xs"
                            disabled={busy}
                            onClick={async () => {
                              await unsetModule.run();
                              await reload();
                            }}
                          >
                            Reset to global
                          </button>
                        )
                      )}
                      {!isGlobal && (
                        <>
                          <button
                            className="btn btn-xs btn-ghost"
                            disabled={busy}
                            onClick={() => {
                              setRenamingModule(isRenaming ? null : m.name);
                              setRenameValue(m.name);
                              setRenamingRole(null);
                            }}
                          >
                            Rename
                          </button>
                          <ConfirmButton
                            className="btn btn-xs btn-ghost text-error"
                            confirmText="Delete module? Flows → global"
                            onConfirm={async () => {
                              await deleteModule.run(m.name);
                              setRenamingModule(null);
                              await reload();
                            }}
                          >
                            Delete
                          </ConfirmButton>
                        </>
                      )}
                    </div>
                  </div>
                  {isRenaming && (
                    <div className="flex gap-2 items-center">
                      <input
                        className="input input-xs input-bordered flex-1"
                        value={renameValue}
                        onChange={(e) => setRenameValue(e.target.value)}
                        placeholder="New module name"
                        autoFocus
                      />
                      <button
                        className="btn btn-xs btn-primary"
                        disabled={
                          !renameValue.trim() ||
                          renameValue.trim() === m.name ||
                          busy
                        }
                        onClick={async () => {
                          await renameModule.run(m.name, renameValue.trim());
                          setRenamingModule(null);
                          await reload();
                        }}
                      >
                        Save
                      </button>
                      <button
                        className="btn btn-xs btn-ghost"
                        onClick={() => setRenamingModule(null)}
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
