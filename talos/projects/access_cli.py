"""
Module: talos.projects.access_cli

Purpose:
    Command-line interface for roles, modules, and access map management.
    Entry points for:
        talos role   create | add | list | show | rename | delete | set | unset
                     | privilege
        talos module create | add | list | show | rename | delete | set | unset
        talos access client set | unset
                     server set | unset
                     delete
                     show
                     coverage
                     signals
                     privilege-diff

    All commands require a bound project (registry ACTIVE, --project, or
    TALOS_PROJECT) — they operate on that project's
    SQLite database.

    Role and module list/show expose UUIDs so BAC --module, auth-config, and
    other UUID consumers remain discoverable after create. Role and module
    references accept name or UUID where noted (CLI-001 / CLI-004).

    Rename keeps the UUID stable (no FK rewrite). Delete cascades config rows,
    reassigns flows to global, and refuses the built-in global role/module
    (CLI-006).

Dependencies: argparse, sys, talos.projects.manager, talos.projects.access
Data flow:
    CLI args → bound project DB path → access functions → stdout
Side effects:
    - Write commands mutate the project SQLite database.
    - Prints human-readable output to stdout.
    - Exits with code 1 on error.
"""
from talos.cli_output import (
    EXIT_USAGE,
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    add_force_argument,
    confirm_or_exit,
    wants_json,
)

import argparse
import sys

from talos.projects.manager import ProjectManager, NoActiveProject
from talos.projects.access import (
    create_role,
    list_roles,
    resolve_role,
    set_active_role,
    set_role_privilege,
    rename_role,
    delete_role,
    role_dependency_counts,
    create_module,
    list_modules,
    resolve_module,
    set_active_module,
    rename_module,
    delete_module,
    module_dependency_counts,
    set_client_access,
    set_server_access,
    unset_client_access,
    unset_server_access,
    delete_access,
    list_access_map,
    detect_allow_without_flows,
    detect_deny_with_flows,
    detect_server_deny_endpoints,
    get_access_coverage,
    list_endpoints_multi_role,
)


# ------------------------------------------------------------------ #
# Role command handlers                                               #
# ------------------------------------------------------------------ #

def _require_active_project(manager: ProjectManager):
    """
    Purpose:
        Fetch the active project, exiting with a clear error if none is set.
    Input:   manager — ProjectManager instance.
    Output:  Active Project instance.
    Side effects: Exits 1 if no active project.
    """
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def cmd_role_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Create a new role in the active project.
    Input:   args.name — role label; args.privilege — rank (0 = highest).
    Side effects: Inserts role into DB; prints confirmation.
    """
    project = _require_active_project(manager)
    privilege = getattr(args, "privilege", 0)
    try:
        role_id = create_role(project.db_path, args.name, privilege=privilege)
        print(
            f"Role created: {args.name}  (id: {role_id}, privilege: {int(privilege or 0)})"
        )
    except Exception as exc:
        # sqlite3.IntegrityError surfaces as a duplicate name violation.
        cli_error(str(exc))


def cmd_role_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all roles in the active project with UUID, name, and active marker.
        UUID is always shown so auth-config and other consumers remain
        discoverable after create (CLI-001).
    Side effects: Prints role table or JSON to stdout.
    """
    project = _require_active_project(manager)
    roles = list_roles(project.db_path)
    if wants_json(args):
        cli_json([
            {
                "id": r["id"],
                "name": r["name"],
                "is_active": bool(r.get("is_active")),
                "privilege": int(r.get("privilege") or 0),
            }
            for r in roles
        ])
        return

    if not roles:
        print("No roles defined.")
        return

    uuid_w = max(len("UUID"), max(len(r["id"]) for r in roles))
    name_w = max(len("Name"), max(len(r["name"]) for r in roles))
    priv_w = max(len("Privilege"), 9)
    active_w = len("Active")

    header = (
        f"{'UUID':<{uuid_w}}  {'Name':<{name_w}}  "
        f"{'Privilege':<{priv_w}}  {'Active':<{active_w}}"
    )
    print(header)
    print("-" * len(header))
    for r in roles:
        active_mark = "*" if r.get("is_active") else ""
        priv = int(r.get("privilege") or 0)
        print(
            f"{r['id']:<{uuid_w}}  {r['name']:<{name_w}}  "
            f"{priv:<{priv_w}}  {active_mark:<{active_w}}"
        )


def cmd_role_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show detailed information for one role (name or UUID).
        Includes access-map modules, auth provider, and auth-flow count so
        operators can continue workflows without inspecting SQLite.
    Input:
        args.name_or_id — role name or full UUID.
    Side effects: Prints role dossier to stdout; exits 1 if not found.
    """
    project = _require_active_project(manager)
    role = resolve_role(project.db_path, args.name_or_id)
    if role is None:
        cli_error(f"Role '{args.name_or_id}' not found.")

    role_id = role["id"]
    role_name = role["name"]
    status = "active" if role.get("is_active") else "inactive"

    # Modules that appear in the access map for this role.
    modules = sorted(
        {
            e["module"]
            for e in list_access_map(project.db_path)
            if e["role"] == role_name
        }
    )
    modules_display = ", ".join(modules) if modules else "(none in access map)"

    # Auth provider + flow count (lazy imports keep access_cli free of auth
    # circular import risk at module load).
    from talos.projects.auth import list_auth_flow_configs
    from talos.projects.auth_provider import get_provider

    provider = get_provider(project.db_path, role_id)
    flow_configs = list_auth_flow_configs(project.db_path, role_id)
    flow_count = len(flow_configs)
    extractors_set = sum(1 for c in flow_configs if c.get("extractor_code"))

    privilege = int(role.get("privilege") or 0)
    if wants_json(args):
        cli_json({
            "id": role_id,
            "name": role_name,
            "status": status,
            "is_active": bool(role.get("is_active")),
            "privilege": privilege,
            "modules": modules,
            "provider": provider,
            "flow_count": flow_count,
            "extractors_set": extractors_set,
        })
        return

    print(f"Name            : {role_name}")
    print(f"UUID            : {role_id}")
    print(f"Status          : {status}")
    print(f"Privilege       : {privilege}  (0 = highest)")
    print(f"Modules         : {modules_display}")
    print(f"Configured auth : {provider}")
    print(f"Flow count      : {flow_count}")
    if flow_count:
        print(f"Extractors set  : {extractors_set}/{flow_count}")


def cmd_role_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the active role for the current project.
        Capture stamps role_id once at proxy start — a running proxy is
        restarted (via notify) so new flows use the new active role.
    Input:   args.name — role to activate.
    Side effects: Updates DB; may restart managed proxy; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_active_role(project.db_path, args.name)
        print(f"Active role set to: {args.name}")
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(project.id, f"role set {args.name}")
        print("Proxy will restart if running so capture uses the new role.")
    except ValueError as exc:
        cli_error(str(exc))


def cmd_role_unset(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Revert the active role back to "global".
        Running proxy is restarted so capture reloads the active role stamp.
    Side effects: Updates DB; may restart managed proxy; prints confirmation.
    """
    project = _require_active_project(manager)
    set_active_role(project.db_path, "global")
    print("Active role reset to: global")
    from talos.proxy.runtime.events import notify_proxy_config_changed

    notify_proxy_config_changed(project.id, "role unset → global")
    print("Proxy will restart if running so capture uses the new role.")


def cmd_role_privilege(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set a role's privilege rank. 0 is highest; the same number on two
        roles means peer accounts (no automatic BAC between them).
    Input:
        args.name_or_id — role name or UUID.
        args.privilege  — non-negative integer.
    Side effects: Updates roles.privilege; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        result = set_role_privilege(
            project.db_path, args.name_or_id, args.privilege
        )
    except ValueError as exc:
        cli_error(str(exc))
    print(
        f"Role '{result['name']}' privilege set to {result['privilege']} "
        "(0 = highest)."
    )


# Human labels for role_dependency_counts keys (CLI-006 delete safety).
_ROLE_DEP_LABELS = {
    "access_map": "Access matrix",
    "flows": "Flows (will reassign to global)",
    "endpoint_roles": "Endpoint role observations",
    "auth_flows": "Auth flows",
    "auth_provider": "Auth provider config",
    "manual_session": "Manual session config",
    "session_health": "Session health / auth state",
    "bac_results": "BAC results",
    "findings_evidence": "Findings evidence",
}

_MODULE_DEP_LABELS = {
    "access_map": "Access matrix",
    "flows": "Flows (will reassign to global)",
    "bac_results": "BAC results",
    "findings_evidence": "Findings evidence",
}


def _print_dependency_summary(kind: str, name: str, counts: dict[str, int], labels: dict) -> None:
    """Print a bullet list of non-zero dependency counts for delete confirm."""
    print(f"{kind} '{name}' is referenced by:")
    for key, count in counts.items():
        label = labels.get(key, key)
        print(f"  • {label}: {count}")
    print()


def cmd_role_rename(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Rename a role (name or UUID → new name). UUID stays stable.
    Input:
        args.name_or_id — existing role name or UUID.
        args.new_name   — new unique role name.
    Side effects: Updates roles.name; prints confirmation; exits 1 on error.
    """
    project = _require_active_project(manager)
    try:
        result = rename_role(project.db_path, args.name_or_id, args.new_name)
        print(
            f"Role renamed: {result['old_name']} → {result['new_name']}"
            f"  (id: {result['id']})"
        )
    except ValueError as exc:
        cli_error(str(exc))


def cmd_role_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Delete a role by name or UUID with dependency summary and confirm.
        Cascades access/auth/BAC rows; reassigns flows to global. Refuses
        the built-in global role. --force skips the confirmation prompt.
    Input:
        args.name_or_id — role name or UUID.
        args.force      — skip interactive confirmation when True.
    Side effects:
        Mutates DB; may remove auth session file; prints result; may exit.
    """
    project = _require_active_project(manager)
    role = resolve_role(project.db_path, args.name_or_id)
    if role is None:
        cli_error(f"Role '{args.name_or_id}' not found.")
    if role["name"] == "global":
        cli_error("The built-in 'global' role cannot be deleted.")

    deps = role_dependency_counts(project.db_path, role["id"])
    if not args.force and deps:
        _print_dependency_summary("Role", role["name"], deps, _ROLE_DEP_LABELS)
    prompt = (
        "Delete anyway?"
        if deps
        else f"Delete role '{role['name']}' ({role['id']})?"
    )
    confirm_or_exit(prompt, force=args.force)

    try:
        result = delete_role(project.db_path, role["id"])
    except (ValueError, RuntimeError) as exc:
        cli_error(str(exc))

    # Best-effort cleanup of the manual session file (not in SQLite).
    session_path = project.auth_session_path(result["id"])
    if session_path.exists():
        try:
            session_path.unlink()
        except OSError:
            pass

    print(f"Role deleted: {result['name']}  (id: {result['id']})")
    if result["reassigned_flows"]:
        print(f"  Flows reassigned to global: {result['reassigned_flows']}")
    if result["deleted_access_map"]:
        print(f"  Access map rows removed: {result['deleted_access_map']}")
    if result["was_active"]:
        print("  Active role reset to: global")


def cmd_module_rename(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Rename a module (name or UUID → new name). UUID stays stable.
    Input:
        args.name_or_id — existing module name or UUID.
        args.new_name   — new unique module name.
    Side effects: Updates modules.name; prints confirmation; exits 1 on error.
    """
    project = _require_active_project(manager)
    try:
        result = rename_module(project.db_path, args.name_or_id, args.new_name)
        print(
            f"Module renamed: {result['old_name']} → {result['new_name']}"
            f"  (id: {result['id']})"
        )
    except ValueError as exc:
        cli_error(str(exc))


def cmd_module_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Delete a module by name or UUID with dependency summary and confirm.
        Cascades access/BAC rows; reassigns flows to global. Refuses the
        built-in global module. --force skips the confirmation prompt.
    Input:
        args.name_or_id — module name or UUID.
        args.force      — skip interactive confirmation when True.
    Side effects: Mutates DB; prints result; may exit.
    """
    project = _require_active_project(manager)
    module = resolve_module(project.db_path, args.name_or_id)
    if module is None:
        cli_error(f"Module '{args.name_or_id}' not found.")
    if module["name"] == "global":
        cli_error("The built-in 'global' module cannot be deleted.")

    deps = module_dependency_counts(project.db_path, module["id"])
    if not args.force and deps:
        _print_dependency_summary(
            "Module", module["name"], deps, _MODULE_DEP_LABELS
        )
    prompt = (
        "Delete anyway?"
        if deps
        else f"Delete module '{module['name']}' ({module['id']})?"
    )
    confirm_or_exit(prompt, force=args.force)

    try:
        result = delete_module(project.db_path, module["id"])
    except (ValueError, RuntimeError) as exc:
        cli_error(str(exc))

    print(f"Module deleted: {result['name']}  (id: {result['id']})")
    if result["reassigned_flows"]:
        print(f"  Flows reassigned to global: {result['reassigned_flows']}")
    if result["deleted_access_map"]:
        print(f"  Access map rows removed: {result['deleted_access_map']}")
    if result["was_active"]:
        print("  Active module reset to: global")


# ------------------------------------------------------------------ #
# Module command handlers                                             #
# ------------------------------------------------------------------ #

def cmd_module_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Create a new module in the active project.
    Input:   args.name, args.description (optional).
    Side effects: Inserts module into DB; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        module_id = create_module(project.db_path, args.name, args.description or "")
        print(f"Module created: {args.name}  (id: {module_id})")
    except Exception as exc:
        cli_error(str(exc))


def cmd_module_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all modules in the active project with UUID, name, and active marker.
        UUID is always shown so BAC --module and other consumers remain
        discoverable after create (CLI-004).
    Side effects: Prints module table or JSON to stdout.
    """
    project = _require_active_project(manager)
    modules = list_modules(project.db_path)
    if wants_json(args):
        cli_json([
            {
                "id": m["id"],
                "name": m["name"],
                "description": m.get("description") or "",
                "is_active": bool(m.get("is_active")),
            }
            for m in modules
        ])
        return

    if not modules:
        print("No modules defined.")
        return

    uuid_w = max(len("UUID"), max(len(m["id"]) for m in modules))
    name_w = max(len("Name"), max(len(m["name"]) for m in modules))
    active_w = len("Active")

    header = f"{'UUID':<{uuid_w}}  {'Name':<{name_w}}  {'Active':<{active_w}}"
    print(header)
    print("-" * len(header))
    for m in modules:
        active_mark = "*" if m.get("is_active") else ""
        print(
            f"{m['id']:<{uuid_w}}  {m['name']:<{name_w}}  {active_mark:<{active_w}}"
        )


def cmd_module_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show detailed information for one module (name or UUID).
        Includes description and access-map roles so operators can continue
        BAC scoping without inspecting SQLite.
    Input:
        args.name_or_id — module name or full UUID.
    Side effects: Prints module dossier to stdout; exits 1 if not found.
    """
    project = _require_active_project(manager)
    module = resolve_module(project.db_path, args.name_or_id)
    if module is None:
        cli_error(f"Module '{args.name_or_id}' not found.")

    module_id = module["id"]
    module_name = module["name"]
    status = "active" if module.get("is_active") else "inactive"
    description = (module.get("description") or "").strip() or "(none)"

    roles = sorted(
        {
            e["role"]
            for e in list_access_map(project.db_path)
            if e["module"] == module_name
        }
    )
    roles_display = ", ".join(roles) if roles else "(none in access map)"

    if wants_json(args):
        cli_json({
            "id": module_id,
            "name": module_name,
            "status": status,
            "is_active": bool(module.get("is_active")),
            "description": (module.get("description") or "").strip(),
            "roles": roles,
        })
        return

    print(f"Name            : {module_name}")
    print(f"UUID            : {module_id}")
    print(f"Status          : {status}")
    print(f"Description     : {description}")
    print(f"Roles           : {roles_display}")


def cmd_module_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the active module for the current project.
        Capture stamps module_id once at proxy start — running proxy restarts.
    Input:   args.name — module to activate.
    Side effects: Updates DB; may restart managed proxy; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_active_module(project.db_path, args.name)
        print(f"Active module set to: {args.name}")
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(project.id, f"module set {args.name}")
        print("Proxy will restart if running so capture uses the new module.")
    except ValueError as exc:
        cli_error(str(exc))


def cmd_module_unset(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Revert the active module back to "global".
        Running proxy restarts so capture reloads the module stamp.
    Side effects: Updates DB; may restart managed proxy; prints confirmation.
    """
    project = _require_active_project(manager)
    set_active_module(project.db_path, "global")
    print("Active module reset to: global")
    from talos.proxy.runtime.events import notify_proxy_config_changed

    notify_proxy_config_changed(project.id, "module unset → global")
    print("Proxy will restart if running so capture uses the new module.")


# ------------------------------------------------------------------ #
# Access map command handlers                                         #
# ------------------------------------------------------------------ #

def cmd_access_client_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the client_allowed state for a (role, module) pair.
        Represents what the client exposes — manually observed from navigation/buttons.
    Input:
        args.role   — role name.
        args.module — module name.
        args.state  — 'allow', 'deny', or 'unknown'.
    Side effects: Upserts client_allowed in access_map; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_client_access(project.db_path, args.role, args.module, args.state)
        print(
            f"client_allowed set: {args.role} → {args.module} = {args.state.upper()}"
        )
    except ValueError as exc:
        cli_error(str(exc))


def cmd_access_server_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the server_expected state for a (role, module) pair.
        Represents your assertion of what the backend SHOULD enforce.
    Input:
        args.role   — role name.
        args.module — module name.
        args.state  — 'allow', 'deny', or 'unknown'.
    Side effects: Upserts server_expected in access_map; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_server_access(project.db_path, args.role, args.module, args.state)
        print(
            f"server_expected set: {args.role} → {args.module} = {args.state.upper()}"
        )
    except ValueError as exc:
        cli_error(str(exc))


def cmd_access_client_unset(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear client_allowed (set to NULL) for a (role, module) pair.
        Row is kept; server_expected is unaffected.
    Input:
        args.role   — role name.
        args.module — module name.
    Side effects: Sets client_allowed = NULL; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        unset_client_access(project.db_path, args.role, args.module)
        print(f"client_allowed cleared: {args.role} → {args.module}")
    except ValueError as exc:
        cli_error(str(exc))


def cmd_access_server_unset(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear server_expected (set to NULL) for a (role, module) pair.
        Row is kept; client_allowed is unaffected.
    Input:
        args.role   — role name.
        args.module — module name.
    Side effects: Sets server_expected = NULL; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        unset_server_access(project.db_path, args.role, args.module)
        print(f"server_expected cleared: {args.role} → {args.module}")
    except ValueError as exc:
        cli_error(str(exc))


def cmd_access_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove the entire (role, module) row from access_map.
        Use only when the mapping is invalid (wrong role or module assigned).
        Confirms interactively unless --force; non-interactive requires --force.
    Input:
        args.role   — role name.
        args.module — module name.
        args.force  — skip confirmation when True.
    Side effects: May prompt; deletes row from access_map; prints result; may exit.
    """
    project = _require_active_project(manager)
    confirm_or_exit(
        f"Delete access mapping '{args.role}' → '{args.module}'?",
        force=bool(getattr(args, "force", False)),
    )
    try:
        delete_access(project.db_path, args.role, args.module)
        print(f"Access mapping deleted: {args.role} → {args.module}")
    except ValueError as exc:
        cli_error(str(exc))


def cmd_access_show(manager: ProjectManager, args: object) -> None:
    """
    Purpose:
        Display the full access map matrix for the active project.
        Columns: Role, Module, Client, Server.
        NULL values shown as '-' (not yet set) in table mode.
    Side effects: Prints access map table or JSON to stdout.
    """
    project = _require_active_project(manager)
    entries = list_access_map(project.db_path)
    if wants_json(args if isinstance(args, argparse.Namespace) else None):
        cli_json(entries)
        return

    if not entries:
        print(
            "Access map is empty.\n"
            "Use 'talos access client set <role> <module> <allow|deny|unknown>'\n"
            "and 'talos access server set <role> <module> <allow|deny|unknown>'."
        )
        return

    def _fmt(val: str | None) -> str:
        return val if val is not None else "-"

    # Compute column widths for alignment.
    role_w   = max(len("Role"),   max(len(e["role"])   for e in entries))
    module_w = max(len("Module"), max(len(e["module"]) for e in entries))
    client_w = max(len("Client"), max(len(_fmt(e["client_allowed"]))  for e in entries))
    server_w = max(len("Server"), max(len(_fmt(e["server_expected"])) for e in entries))

    header = (
        f"{'Role':<{role_w}}  {'Module':<{module_w}}  "
        f"{'Client':<{client_w}}  {'Server':<{server_w}}"
    )
    separator = "-" * len(header)
    print(header)
    print(separator)
    for e in entries:
        print(
            f"{e['role']:<{role_w}}  {e['module']:<{module_w}}  "
            f"{_fmt(e['client_allowed']):<{client_w}}  "
            f"{_fmt(e['server_expected']):<{server_w}}"
        )


def cmd_access_coverage(manager: ProjectManager, _args: object) -> None:
    """
    Purpose:
        Display expected-vs-observed coverage for each access_map row.
        Combines access_map with observed flow and endpoint counts.
    Side effects: Prints a coverage table to stdout.
    """
    project = _require_active_project(manager)
    rows = get_access_coverage(project.db_path)
    if not rows:
        print(
            "No access coverage data available.\n"
            "Define access_map entries first with 'talos access client/server set ...'."
        )
        return

    def _fmt(val: str | None) -> str:
        return val if val is not None else "-"

    role_w = max(len("Role"), max(len(r["role_name"]) for r in rows))
    module_w = max(len("Module"), max(len(r["module_name"]) for r in rows))
    client_w = max(len("Client"), max(len(_fmt(r["client_allowed"])) for r in rows))
    server_w = max(len("Server"), max(len(_fmt(r["server_expected"])) for r in rows))
    flow_w = max(len("Flows"), max(len(str(r["flow_count"])) for r in rows))
    endpoint_w = max(
        len("Endpoints"),
        max(len(str(r["endpoint_count"])) for r in rows),
    )

    header = (
        f"{'Role':<{role_w}}  {'Module':<{module_w}}  "
        f"{'Client':<{client_w}}  {'Server':<{server_w}}  "
        f"{'Flows':>{flow_w}}  {'Endpoints':>{endpoint_w}}"
    )
    separator = "-" * len(header)
    print(header)
    print(separator)
    for row in rows:
        print(
            f"{row['role_name']:<{role_w}}  {row['module_name']:<{module_w}}  "
            f"{_fmt(row['client_allowed']):<{client_w}}  "
            f"{_fmt(row['server_expected']):<{server_w}}  "
            f"{row['flow_count']:>{flow_w}}  {row['endpoint_count']:>{endpoint_w}}"
        )


def cmd_access_signals(manager: ProjectManager, _args: object) -> None:
    """
    Purpose:
        Display immediate BAC/IDOR signals without replay:
        1. Cross-role exposure  — endpoints accessed by more than one role
                                   (candidates for IDOR / privilege confusion).
        2. Module boundary      — endpoints reached under (role, module) pairs
                                   where server_expected = DENY
                                   (missing server-side enforcement).
        3. DENY with flows      — (role, module) pair marked DENY but traffic exists.
        4. ALLOW without flows  — (role, module) pair marked ALLOW but no traffic seen.
    Side effects: Prints signal sections to stdout.
    """
    project = _require_active_project(manager)

    multi_role    = list_endpoints_multi_role(project.db_path)
    deny_endpoint = detect_server_deny_endpoints(project.db_path)
    deny_rows     = detect_deny_with_flows(project.db_path)
    allow_rows    = detect_allow_without_flows(project.db_path)

    # ------------------------------------------------------------------ #
    # Section 1 — Cross-role endpoint exposure                            #
    # ------------------------------------------------------------------ #
    print("Cross-role endpoint exposure  [IDOR / privilege confusion]")
    print("-" * 60)
    if not multi_role:
        print("(none)")
    else:
        for row in multi_role:
            print(
                f"  [{row['role_count']} roles]  "
                f"{row['method']} {row['host']}{row['normalized_path']}"
            )
            print(f"    roles: {row['role_names']}")

    print()

    # ------------------------------------------------------------------ #
    # Section 2 — Module boundary violation (server DENY, traffic seen)   #
    # ------------------------------------------------------------------ #
    print("Module boundary violation  [server_expected=DENY, endpoint reached]")
    print("-" * 60)
    if not deny_endpoint:
        print("(none)")
    else:
        current_combo = None
        for row in deny_endpoint:
            combo = (row["role_name"], row["module_name"])
            if combo != current_combo:
                current_combo = combo
                print(
                    f"  {row['role_name']} → {row['module_name']}"
                    f"  client={row['client_allowed'] or '-'}"
                    f"  server={row['server_expected']}"
                )
            print(
                f"    {row['method']} {row['host']}{row['normalized_path']}"
                f"  ({row['flow_count']} flow{'s' if row['flow_count'] != 1 else ''})"
            )

    print()

    # ------------------------------------------------------------------ #
    # Section 3 — client=DENY, flows observed (flow-level summary)        #
    # ------------------------------------------------------------------ #
    print("client=DENY with observed flows  [potential client-side bypass]")
    print("-" * 60)
    if not deny_rows:
        print("(none)")
    else:
        for row in deny_rows:
            print(
                f"  {row['role_name']} → {row['module_name']}"
                f"  client={row['client_allowed']}"
                f"  flows={row['flow_count']}"
            )

    print()

    # ------------------------------------------------------------------ #
    # Section 4 — client=ALLOW, no flows (coverage gap)                  #
    # ------------------------------------------------------------------ #
    print("client=ALLOW with no observed flows  [coverage gap]")
    print("-" * 60)
    if not allow_rows:
        print("(none)")
    else:
        for row in allow_rows:
            print(
                f"  {row['role_name']} → {row['module_name']}"
                f"  client={row['client_allowed']}"
            )


def cmd_access_privilege_diff(
    manager: ProjectManager, args: argparse.Namespace
) -> None:
    """
    Purpose:
        Show endpoints seen under a higher-privilege role and absent from a
        lower-privilege role. Those gaps are automatic BAC candidates.
    Input:
        args.attacker — optional lower-privilege role name/UUID filter.
        args.format   — optional json.
    Side effects: Prints privilege-diff report or JSON.
    """
    project = _require_active_project(manager)
    from talos.projects.bac.candidates import list_privilege_gaps

    attacker_id = None
    attacker_filter = getattr(args, "attacker", None)
    if attacker_filter:
        role = resolve_role(project.db_path, attacker_filter)
        if role is None:
            cli_error(f"Role '{attacker_filter}' not found.")
        attacker_id = role["id"]

    gaps = list_privilege_gaps(
        project.db_path,
        project.id,
        attacker_role_id=attacker_id,
    )
    payload = [g.to_dict() for g in gaps]
    if wants_json(args):
        cli_json({"gaps": payload, "count": len(payload)})
        return

    if not gaps:
        print(
            "No privilege-diff candidates.\n"
            "Create two roles with different privilege ranks (0 = highest),\n"
            "capture the app as each role, then re-run this command.\n"
            "Same privilege = peer accounts and is not a candidate pair."
        )
        return

    print("Privilege-diff BAC surface  [higher-privilege endpoints missing on lower]")
    print("-" * 70)
    for gap in gaps:
        print(
            f"\n{gap.target_role_name} (priv {gap.target_privilege}) → "
            f"{gap.attacker_role_name} (priv {gap.attacker_privilege})  "
            f"[{len(gap.endpoints)} endpoint"
            f"{'' if len(gap.endpoints) == 1 else 's'}]"
        )
        print(
            "  Test with "
            f"{gap.attacker_role_name}'s identity "
            "(NTLM profile or session)."
        )
        for ep in gap.endpoints:
            print(
                f"  {ep.method} {ep.host}{ep.path}  "
                f"module={ep.module_name}  flows={len(ep.flow_ids)}"
            )


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_role_parser() -> argparse.ArgumentParser:
    """
    Purpose: Construct the argument parser for 'talos role' subcommands.
    Output:  Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos role",
        description="Manage roles (identity types for access-control modeling).",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # create / add (aliases)
    p_create = sub.add_parser("create", help="Create a new role.")
    p_create.add_argument("name", help="Role name (e.g. user, admin, support).")
    p_create.add_argument(
        "--privilege",
        type=int,
        default=0,
        metavar="N",
        help="Privilege rank (0 = highest). Same rank = peer accounts.",
    )
    p_add = sub.add_parser("add", help="Create a new role (alias for create).")
    p_add.add_argument("name", help="Role name (e.g. user, admin, support).")
    p_add.add_argument(
        "--privilege",
        type=int,
        default=0,
        metavar="N",
        help="Privilege rank (0 = highest). Same rank = peer accounts.",
    )

    # list
    p_list = sub.add_parser(
        "list",
        help="List all roles (UUID, name, privilege, active marker).",
    )
    add_format_argument(p_list)

    # show
    p_show = sub.add_parser(
        "show",
        help="Show details for a role (name or UUID): status, modules, auth.",
    )
    p_show.add_argument(
        "name_or_id",
        help="Role name or UUID.",
    )
    add_format_argument(p_show)

    # rename
    p_rename = sub.add_parser(
        "rename",
        help="Rename a role (UUID stays the same).",
    )
    p_rename.add_argument(
        "name_or_id",
        help="Current role name or UUID.",
    )
    p_rename.add_argument(
        "new_name",
        help="New unique role name.",
    )

    # delete
    p_delete = sub.add_parser(
        "delete",
        help="Delete a role (cascades config; reassigns flows to global).",
    )
    p_delete.add_argument(
        "name_or_id",
        help="Role name or UUID to delete.",
    )
    add_force_argument(p_delete)

    # set
    p_set = sub.add_parser("set", help="Set the active role (tags future captured flows).")
    p_set.add_argument("name", help="Role name to activate.")

    # unset
    sub.add_parser("unset", help="Reset the active role back to 'global'.")

    # privilege
    p_priv = sub.add_parser(
        "privilege",
        help="Set a role's privilege rank (0 = highest).",
    )
    p_priv.add_argument("name_or_id", help="Role name or UUID.")
    p_priv.add_argument(
        "privilege",
        type=int,
        help="Privilege rank (0 = highest; same rank = peer accounts).",
    )

    return parser


def build_module_parser() -> argparse.ArgumentParser:
    """
    Purpose: Construct the argument parser for 'talos module' subcommands.
    Output:  Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos module",
        description="Manage modules (logical application feature areas).",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # create / add (aliases)
    p_create = sub.add_parser("create", help="Create a new module.")
    p_create.add_argument("name", help="Module name (e.g. billing, auth, orders).")
    p_create.add_argument("-d", "--description", default="", help="Optional description.")
    p_add = sub.add_parser("add", help="Create a new module (alias for create).")
    p_add.add_argument("name", help="Module name (e.g. billing, auth, orders).")
    p_add.add_argument("-d", "--description", default="", help="Optional description.")

    # list
    p_list = sub.add_parser(
        "list",
        help="List all modules (UUID, name, active marker).",
    )
    add_format_argument(p_list)

    # show
    p_show = sub.add_parser(
        "show",
        help="Show details for a module (name or UUID): status, description, roles.",
    )
    p_show.add_argument(
        "name_or_id",
        help="Module name or UUID.",
    )
    add_format_argument(p_show)

    # rename
    p_rename = sub.add_parser(
        "rename",
        help="Rename a module (UUID stays the same).",
    )
    p_rename.add_argument(
        "name_or_id",
        help="Current module name or UUID.",
    )
    p_rename.add_argument(
        "new_name",
        help="New unique module name.",
    )

    # delete
    p_delete = sub.add_parser(
        "delete",
        help="Delete a module (cascades config; reassigns flows to global).",
    )
    p_delete.add_argument(
        "name_or_id",
        help="Module name or UUID to delete.",
    )
    add_force_argument(p_delete)

    # set
    p_set = sub.add_parser("set", help="Set the active module (tags future captured flows).")
    p_set.add_argument("name", help="Module name to activate.")

    # unset
    sub.add_parser("unset", help="Reset the active module back to 'global'.")

    return parser


# ------------------------------------------------------------------ #
# Dispatch entry points                                               #
# ------------------------------------------------------------------ #

_ROLE_COMMAND_MAP = {
    "create": cmd_role_create,
    "add":    cmd_role_create,   # alias
    "list":   cmd_role_list,
    "show":   cmd_role_show,
    "rename": cmd_role_rename,
    "delete": cmd_role_delete,
    "set":    cmd_role_set,
    "unset":  cmd_role_unset,
    "privilege": cmd_role_privilege,
}

_MODULE_COMMAND_MAP = {
    "create": cmd_module_create,
    "add":    cmd_module_create,  # alias
    "list":   cmd_module_list,
    "show":   cmd_module_show,
    "rename": cmd_module_rename,
    "delete": cmd_module_delete,
    "set":    cmd_module_set,
    "unset":  cmd_module_unset,
}


def run_role_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate role command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding 'talos role').
    Side effects: Delegates to handlers; may exit.
    """
    parser = build_role_parser()
    args = parser.parse_args(argv)
    handler = _ROLE_COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(manager, args)


def run_module_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate module command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding 'talos module').
    Side effects: Delegates to handlers; may exit.
    """
    parser = build_module_parser()
    args = parser.parse_args(argv)
    handler = _MODULE_COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(manager, args)


def run_access_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Dispatch 'talos access ...' to the appropriate handler.
        Command structure:
            access client set   <role> <module> <allow|deny|unknown>
            access client unset <role> <module>
            access server set   <role> <module> <allow|deny|unknown>
            access server unset <role> <module>
            access delete       <role> <module>
            access show
            access coverage
            access signals
            access privilege-diff [--attacker NAME|UUID]
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding 'talos access').
    Side effects: Delegates to handlers; may exit.
    """
    if not argv or argv[0] in ("-h", "--help"):
        _print_access_usage()
        sys.exit(0)

    subcmd = argv[0]
    rest = argv[1:]

    if subcmd in ("client", "server"):
        _run_access_side(manager, side=subcmd, argv=rest)
    elif subcmd == "delete":
        _run_access_delete(manager, rest)
    elif subcmd == "show":
        parser = argparse.ArgumentParser(prog="talos access show")
        add_format_argument(parser)
        cmd_access_show(manager, parser.parse_args(rest))
    elif subcmd == "coverage":
        cmd_access_coverage(manager, None)
    elif subcmd == "signals":
        cmd_access_signals(manager, None)
    elif subcmd in ("privilege-diff", "privilege_diff"):
        parser = argparse.ArgumentParser(prog="talos access privilege-diff")
        parser.add_argument(
            "--attacker",
            metavar="NAME|UUID",
            default=None,
            help="Only show gaps where this lower-privilege role is the attacker.",
        )
        add_format_argument(parser)
        cmd_access_privilege_diff(manager, parser.parse_args(rest))
    else:
        cli_error(f"Unknown access subcommand: '{subcmd}'.", exit_code=None)
        _print_access_usage()
        sys.exit(EXIT_USAGE)


def _run_access_side(manager: ProjectManager, side: str, argv: list[str]) -> None:
    """
    Purpose:
        Handle 'talos access client ...' and 'talos access server ...' subcommands.
    Input:
        manager — ProjectManager instance.
        side    — 'client' or 'server'.
        argv    — remaining args after 'client'/'server'.
    Side effects: Delegates to set/unset handlers; may exit.
    """
    if not argv or argv[0] in ("-h", "--help"):
        _print_access_side_usage(side)
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]

    if action == "set":
        # Accept the state argument case-insensitively (e.g. "UNKNOWN",
        # "Allow") so callers don't have to know the exact casing
        # argparse's `choices` enforces.
        if len(rest) >= 3:
            rest[2] = rest[2].lower()
        parser = argparse.ArgumentParser(prog=f"talos access {side} set")
        parser.add_argument("role",   help="Role name.")
        parser.add_argument("module", help="Module name.")
        parser.add_argument(
            "state",
            choices=["allow", "deny", "unknown"],
            help="Access state: allow, deny, or unknown.",
        )
        args = parser.parse_args(rest)
        if side == "client":
            cmd_access_client_set(manager, args)
        else:
            cmd_access_server_set(manager, args)

    elif action == "unset":
        parser = argparse.ArgumentParser(prog=f"talos access {side} unset")
        parser.add_argument("role",   help="Role name.")
        parser.add_argument("module", help="Module name.")
        args = parser.parse_args(rest)
        if side == "client":
            cmd_access_client_unset(manager, args)
        else:
            cmd_access_server_unset(manager, args)

    else:
        cli_error(f"Unknown '{side}' action: '{action}'.", exit_code=None)
        _print_access_side_usage(side)
        sys.exit(EXIT_USAGE)


def _run_access_delete(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Handle 'talos access delete <role> <module> [--force]'.
    Input:
        manager — ProjectManager instance.
        argv    — remaining args after 'delete'.
    Side effects: Delegates to cmd_access_delete; may exit.
    """
    parser = argparse.ArgumentParser(prog="talos access delete")
    parser.add_argument("role",   help="Role name.")
    parser.add_argument("module", help="Module name.")
    add_force_argument(parser)
    args = parser.parse_args(argv)
    cmd_access_delete(manager, args)


def _print_access_usage() -> None:
    """Print top-level access subcommand usage."""
    print(
        "Usage: talos access <subcommand> [args]\n\n"
        "Subcommands:\n"
        "  client set   <role> <module> <allow|deny|unknown>  Set client-observed access\n"
        "  client unset <role> <module>                       Clear client-observed access\n"
        "  server set   <role> <module> <allow|deny|unknown>  Set expected enforcement\n"
        "  server unset <role> <module>                       Clear expected enforcement\n"
        "  delete       <role> <module> [--force]             Remove entire mapping\n"
        "  show                                               Display access matrix\n"
        "  coverage                                           Compare expected vs observed traffic\n"
        "  signals                                            Show immediate BAC signal candidates\n"
        "  privilege-diff [--attacker NAME]                   Endpoints on a higher-privilege role\n"
        "                                                     missing from a lower-privilege role\n"
    )


def _print_access_side_usage(side: str) -> None:
    """Print usage for 'talos access client/server'."""
    print(
        f"Usage: talos access {side} <action> [args]\n\n"
        f"Actions:\n"
        f"  set   <role> <module> <allow|deny|unknown>\n"
        f"  unset <role> <module>\n"
    )

