"""
Module: talos.projects.access_cli

Purpose:
    Command-line interface for roles, modules, and access map management.
    Entry points for:
        talos role   create | add | list | set | unset
        talos module create | add | list | set | unset
        talos access client set | unset
                     server set | unset
                     delete
                     show
                     coverage
                     signals

    All commands require an active project — they operate on that project's
    SQLite database.

Dependencies: argparse, sys, talos.projects.manager, talos.projects.access
Data flow:
    CLI args → active project DB path → access functions → stdout
Side effects:
    - Write commands mutate the project SQLite database.
    - Prints human-readable output to stdout.
    - Exits with code 1 on error.
"""

import argparse
import sys

from talos.ui.db import (
    detect_allow_without_flows,
    detect_deny_with_flows,
    detect_server_deny_endpoints,
    get_access_coverage,
    list_endpoints_multi_role,
)
from talos.projects.manager import ProjectManager, NoActiveProject
from talos.projects.access import (
    create_role,
    list_roles,
    get_active_role,
    set_active_role,
    create_module,
    list_modules,
    get_active_module,
    set_active_module,
    set_client_access,
    set_server_access,
    unset_client_access,
    unset_server_access,
    delete_access,
    list_access_map,
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
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return project


def cmd_role_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Create a new role in the active project.
    Input:   args.name — role label.
    Side effects: Inserts role into DB; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        role_id = create_role(project.db_path, args.name)
        print(f"Role created: {args.name}  (id: {role_id})")
    except Exception as exc:
        # sqlite3.IntegrityError surfaces as a duplicate name violation.
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_role_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: List all roles in the active project.
    Side effects: Prints role table to stdout.
    """
    project = _require_active_project(manager)
    roles = list_roles(project.db_path)
    if not roles:
        print("No roles defined.")
        return
    active_name = get_active_role(project.db_path)
    print(f"Roles ({len(roles)}):\n")
    for r in roles:
        marker = " [active]" if r["name"] == active_name else ""
        print(f"  {r['name']}{marker}")


def cmd_role_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the active role for the current project.
        All flows captured after this point will be tagged with this role.
    Input:   args.name — role to activate.
    Side effects: Updates DB; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_active_role(project.db_path, args.name)
        print(f"Active role set to: {args.name}")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_role_unset(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Revert the active role back to "global".
        Flows captured after this point will be tagged with role="global".
    Side effects: Updates DB; prints confirmation.
    """
    project = _require_active_project(manager)
    set_active_role(project.db_path, "global")
    print("Active role reset to: global")


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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_module_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: List all modules in the active project.
    Side effects: Prints module table to stdout.
    """
    project = _require_active_project(manager)
    modules = list_modules(project.db_path)
    if not modules:
        print("No modules defined.")
        return
    active_name = get_active_module(project.db_path)
    print(f"Modules ({len(modules)}):\n")
    for m in modules:
        marker = " [active]" if m["name"] == active_name else ""
        desc = f"  — {m['description']}" if m["description"] else ""
        print(f"  {m['name']}{marker}{desc}")


def cmd_module_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the active module for the current project.
        All flows captured after this point will be tagged with this module.
    Input:   args.name — module to activate.
    Side effects: Updates DB; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        set_active_module(project.db_path, args.name)
        print(f"Active module set to: {args.name}")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_module_unset(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Revert the active module back to "global".
        Flows captured after this point will be tagged with module="global".
    Side effects: Updates DB; prints confirmation.
    """
    project = _require_active_project(manager)
    set_active_module(project.db_path, "global")
    print("Active module reset to: global")


# ------------------------------------------------------------------ #
# Access map command handlers                                         #
# ------------------------------------------------------------------ #

def cmd_access_client_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the client_allowed state for a (role, module) pair.
        Represents what the UI exposes — manually observed from navigation/buttons.
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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_access_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove the entire (role, module) row from access_map.
        Use only when the mapping is invalid (wrong role or module assigned).
    Input:
        args.role   — role name.
        args.module — module name.
    Side effects: Deletes row from access_map; prints confirmation.
    """
    project = _require_active_project(manager)
    try:
        delete_access(project.db_path, args.role, args.module)
        print(f"Access mapping deleted: {args.role} → {args.module}")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_access_show(manager: ProjectManager, _args: object) -> None:
    """
    Purpose:
        Display the full access map matrix for the active project.
        Columns: Role, Module, Client, Server.
        NULL values shown as '-' (not yet set).
    Side effects: Prints access map table to stdout.
    """
    project = _require_active_project(manager)
    entries = list_access_map(project.db_path)
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
    print("client=DENY with observed flows  [potential UI bypass]")
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
    p_add = sub.add_parser("add", help="Create a new role (alias for create).")
    p_add.add_argument("name", help="Role name (e.g. user, admin, support).")

    # list
    sub.add_parser("list", help="List all roles.")

    # set
    p_set = sub.add_parser("set", help="Set the active role (tags future captured flows).")
    p_set.add_argument("name", help="Role name to activate.")

    # unset
    sub.add_parser("unset", help="Reset the active role back to 'global'.")

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
    sub.add_parser("list", help="List all modules.")

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
    "set":    cmd_role_set,
    "unset":  cmd_role_unset,
}

_MODULE_COMMAND_MAP = {
    "create": cmd_module_create,
    "add":    cmd_module_create,  # alias
    "list":   cmd_module_list,
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
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding 'talos access').
    Side effects: Delegates to handlers; may exit.
    """
    if not argv:
        _print_access_usage()
        sys.exit(0)

    subcmd = argv[0]
    rest = argv[1:]

    if subcmd in ("client", "server"):
        _run_access_side(manager, side=subcmd, argv=rest)
    elif subcmd == "delete":
        _run_access_delete(manager, rest)
    elif subcmd == "show":
        cmd_access_show(manager, None)
    elif subcmd == "coverage":
        cmd_access_coverage(manager, None)
    elif subcmd == "signals":
        cmd_access_signals(manager, None)
    else:
        print(f"Unknown access subcommand: '{subcmd}'", file=sys.stderr)
        _print_access_usage()
        sys.exit(1)


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
    if not argv:
        _print_access_side_usage(side)
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]

    if action == "set":
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
        print(f"Unknown '{side}' action: '{action}'", file=sys.stderr)
        _print_access_side_usage(side)
        sys.exit(1)


def _run_access_delete(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Handle 'talos access delete <role> <module>'.
    Input:
        manager — ProjectManager instance.
        argv    — remaining args after 'delete'.
    Side effects: Delegates to cmd_access_delete; may exit.
    """
    parser = argparse.ArgumentParser(prog="talos access delete")
    parser.add_argument("role",   help="Role name.")
    parser.add_argument("module", help="Module name.")
    args = parser.parse_args(argv)
    cmd_access_delete(manager, args)


def _print_access_usage() -> None:
    """Print top-level access subcommand usage."""
    print(
        "Usage: talos access <subcommand> [args]\n\n"
        "Subcommands:\n"
        "  client set   <role> <module> <allow|deny|unknown>  Set UI-observed access\n"
        "  client unset <role> <module>                       Clear UI-observed access\n"
        "  server set   <role> <module> <allow|deny|unknown>  Set expected enforcement\n"
        "  server unset <role> <module>                       Clear expected enforcement\n"
        "  delete       <role> <module>                       Remove entire mapping\n"
        "  show                                               Display access matrix\n"
        "  coverage                                           Compare expected vs observed traffic\n"
        "  signals                                            Show immediate BAC signal candidates\n"
    )


def _print_access_side_usage(side: str) -> None:
    """Print usage for 'talos access client/server'."""
    print(
        f"Usage: talos access {side} <action> [args]\n\n"
        f"Actions:\n"
        f"  set   <role> <module> <allow|deny|unknown>\n"
        f"  unset <role> <module>\n"
    )

