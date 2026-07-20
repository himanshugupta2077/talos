"""
Module: talos.projects.cli

Purpose:
    Command-line interface for project management operations.
    Entry point for: create, open, close, delete, rename, description,
    list, scope, constraints, status, outscope commands.

Dependencies: argparse, talos.projects.manager, talos.config
Data flow:
    CLI args → ProjectManager → stdout (human-readable output)
Side effects:
    - All state changes are delegated to ProjectManager.
    - Prints structured output to stdout.
    - Exits with code 1 on error.
"""
from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_json,
    confirm_or_exit,
    wants_json,
)

import argparse
import sys
from pathlib import Path

from talos.projects.manager import (
    ProjectManager,
    ProjectError,
    ProjectNotFound,
    ProjectAlreadyExists,
    NoActiveProject,
)
from talos.projects.model import Project, ProjectStatus, ScopeConstraints
from talos.projects.outscope_cli import run_outscope_cli
from talos.projects.scope_cli import run_scope_cli
from talos.proxy.scope import ScopeParseError


# ------------------------------------------------------------------ #
# Formatting helpers                                                   #
# ------------------------------------------------------------------ #

def _fmt_project(project: Project, label: str = "") -> str:
    """
    Purpose: Render a single project as a human-readable block.
    Input:   project — Project instance; label — optional prefix tag.
    Output:  Multi-line string.
    Side effects: None.
    """
    status_tag = "[ACTIVE]" if project.status == ProjectStatus.ACTIVE else "[inactive]"
    prefix = f"  {label}" if label else ""
    scope_display = ", ".join(project.scope) if project.scope else "(none)"
    c = project.constraints
    return (
        f"{prefix}{status_tag} {project.name} ({project.id})\n"
        f"    Created         : {project.created_at}\n"
        f"    Scope           : {scope_display}\n"
        f"    Store bodies    : {c.store_bodies}\n"
        f"    Max body size   : {c.max_body_size:,} bytes\n"
        f"    DB              : {project.db_path}\n"
        f"    Note            : {project.description or '—'}"
    )


def _project_as_dict(
    project: Project,
    *,
    process_override: str | None = None,
) -> dict:
    """
    Purpose:
        Stable JSON shape for project list/status (CLI-014).
    Input:
        project          — Project instance.
        process_override — When set, include as process_override field.
    Output: JSON-ready dict.
    Side effects: None.
    """
    payload = {
        "id": project.id,
        "name": project.name,
        "description": project.description or "",
        "created_at": project.created_at,
        "status": project.status.value,
        "scope": list(project.scope),
        "constraints": project.constraints.to_dict(),
        "data_dir": project.data_dir,
        "db_path": str(project.db_path),
    }
    if process_override is not None:
        payload["process_override"] = process_override
    return payload


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Create a new project.
    Input:   manager, args with: name, description, scope (optional list).
    Side effects: Prints confirmation; exits 1 on failure.
    """
    scope = args.scope or []
    try:
        project = manager.create(
            name=args.name,
            description=args.description or "",
            scope=scope,
        )
        print(f"Project created.\n{_fmt_project(project)}")
    except ProjectAlreadyExists as exc:
        cli_error(str(exc))
    except ValueError as exc:
        cli_error(str(exc))


def cmd_open(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Open (activate) a project.
    Input:   manager, args with: id.
    Side effects: Prints confirmation; reconciles proxy runtime; exits 1 on failure.
    """
    try:
        project = manager.open(args.id)
        print(f"Project opened.\n{_fmt_project(project)}")
        from talos.config import TalosConfig
        from talos.proxy.runtime.generation import get_generation
        from talos.proxy.runtime.manager import ProxyRuntimeManager
        from talos.scheduler.runtime import SchedulerRuntimeManager

        config = TalosConfig.from_env()
        gen = get_generation(config.projects_dir, project.id)
        ProxyRuntimeManager(data_dir=config.data_dir).reconcile(
            active_project=project,
            spawn_generation=gen,
            generation_reader=lambda pid: get_generation(config.projects_dir, pid),
        )
        SchedulerRuntimeManager(
            data_dir=config.data_dir
        ).reconcile_active_project(active_project=project)
    except ProjectNotFound as exc:
        cli_error(str(exc))


def cmd_close(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: Close the active project.
    Side effects: Prints confirmation; stops managed proxy and scheduler if running.
    """
    closed = manager.close()
    if closed:
        print(f"Project closed: {closed.name} ({closed.id})")
    else:
        print("No active project to close.")
    from talos.config import TalosConfig
    from talos.proxy.runtime.manager import ProxyRuntimeManager
    from talos.scheduler.runtime import SchedulerRuntimeManager

    config = TalosConfig.from_env()
    ProxyRuntimeManager(data_dir=config.data_dir).reconcile(active_project=None)
    SchedulerRuntimeManager(data_dir=config.data_dir).reconcile_active_project(
        active_project=None
    )


def cmd_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a project from the registry.
        Without --purge: data on disk is preserved.
        With --purge: permanently deletes the project directory (DB, archive,
        reports, sessions — everything). Interactive purge requires a second
        confirmation unless --force is set (CLI-015 / CLI-017).
    Input:
        manager — ProjectManager instance.
        args    — id, force (bool), purge (bool).
    Side effects:
        Prompts unless --force; may rmtree project data_dir; exits on abort/error.
    """
    purge = bool(getattr(args, "purge", False))

    if purge:
        confirm_or_exit(
            f"PERMANENTLY delete project '{args.id}' and ALL data on disk "
            f"(registry, database, archive, reports, sessions)? "
            f"This cannot be undone.",
            force=args.force,
        )
        # Double confirmation for purge when not using --force (CLI-017).
        if not args.force:
            confirm_or_exit(
                f"Second confirmation: permanently erase all data for "
                f"'{args.id}'?",
                force=False,
            )
    else:
        confirm_or_exit(
            f"Remove project '{args.id}' from registry? "
            "Data on disk will NOT be deleted.",
            force=args.force,
        )

    try:
        project = manager.delete(args.id, purge=purge)
        if purge:
            print(
                f"Purged: {project.name} ({project.id})\n"
                f"Registry entry and data directory removed: {project.data_dir}"
            )
        else:
            print(
                f"Removed: {project.name} ({project.id})\n"
                f"Data preserved at: {project.data_dir}\n"
                f"Tip: use 'talos project delete {project.id} --purge --force' "
                f"to also delete data on disk."
            )
    except ProjectNotFound as exc:
        cli_error(str(exc))


def cmd_rename(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Rename a project (display name and, when the slug changes, id +
        on-disk directory).
    Input:
        manager — ProjectManager instance.
        args    — id (current slug), new_name.
    Side effects: Prints confirmation; exits 1 on failure.
    """
    try:
        project = manager.rename(args.id, args.new_name)
        print(f"Project renamed.\n{_fmt_project(project)}")
    except ProjectNotFound as exc:
        cli_error(str(exc))
    except ProjectAlreadyExists as exc:
        cli_error(str(exc))
    except ValueError as exc:
        cli_error(str(exc))
    except ProjectError as exc:
        cli_error(str(exc))


def cmd_description(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show or update a project's free-text description.
        If text is provided: sets description.
        If omitted: prints the current description.
    Input:
        manager — ProjectManager instance.
        args    — id, text (optional list of words or None).
    Side effects: May write registry; prints to stdout; exits 1 on missing project.
    """
    try:
        project = manager.get(args.id)
    except ProjectNotFound as exc:
        cli_error(str(exc))
        return

    # text is nargs='*' — empty list means display-only.
    if args.text:
        new_description = " ".join(args.text)
        try:
            project = manager.set_description(args.id, new_description)
        except ProjectNotFound as exc:
            cli_error(str(exc))
            return
        print(f"Description updated for '{project.id}':")
        print(f"  {project.description or '—'}")
    else:
        print(f"Description for '{project.id}':")
        print(f"  {project.description or '—'}")
        print(
            f"\nUpdate with: talos project description {project.id} "
            f"\"Your note here\""
        )


def cmd_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: List all registered projects.
    Side effects: Prints project list to stdout (table or JSON).
    """
    projects = manager.list_all()
    if wants_json(args):
        cli_json([_project_as_dict(p) for p in projects])
        return

    if not projects:
        print("No projects registered. Use 'talos project create <name>'.")
        return

    print(f"{len(projects)} project(s):\n")
    for project in projects:
        print(_fmt_project(project))
        print()


def cmd_scope_legacy(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Compatibility surface: get or replace scope by explicit project id.

            talos project scope <id>              # list
            talos project scope <id> P1 [P2 ...]  # replace entire list

        Prefer the resource API for day-to-day use:

            talos project scope add|remove|list|clear|import

        Both paths use the same ProjectManager Basic Scope validation.
    """
    try:
        project = manager.get(args.id)
    except ProjectNotFound as exc:
        cli_error(str(exc))

    if args.patterns:
        try:
            project = manager.set_scope(args.id, args.patterns)
        except ScopeParseError as exc:
            cli_error(str(exc))
        print(f"Scope updated for '{project.id}':")
        for pattern in project.scope:
            print(f"  {pattern}")
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(project.id, "project scope updated")
    else:
        if project.scope:
            print(f"Scope for '{project.id}':")
            for pattern in project.scope:
                print(f"  {pattern}")
        else:
            print(
                f"No scope set for '{project.id}'. "
                f"Use: talos project scope add <prefix> "
                f"(with project open / --project), or "
                f"talos project scope {project.id} <prefix> [<prefix>...]"
            )


def cmd_constraints(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Get or set capture constraints for a project.
        If options provided: applies changes and prints updated constraints.
        If no options: prints current constraints.
    Input:
        manager — ProjectManager instance.
        args    — parsed args: id, store_bodies (bool|None), max_body_size (int|None).
    Side effects:
        - Writes registry if any change is requested.
        - Prints result to stdout.
    """
    try:
        project = manager.get(args.id)
    except ProjectNotFound as exc:
        cli_error(str(exc))

    # Determine whether any change was requested.
    changing = (args.store_bodies is not None) or (args.max_body_size is not None)

    if changing:
        current = project.constraints
        new_constraints = ScopeConstraints(
            capture_in_scope_only=True,  # always enforced; not user-configurable
            store_bodies=args.store_bodies if args.store_bodies is not None else current.store_bodies,
            max_body_size=args.max_body_size if args.max_body_size is not None else current.max_body_size,
        )
        project = manager.set_constraints(args.id, new_constraints)
        print(f"Constraints updated for '{project.id}':")
    else:
        print(f"Constraints for '{project.id}':")

    c = project.constraints
    print(f"  capture_in_scope_only : {c.capture_in_scope_only}")
    print(f"  store_bodies          : {c.store_bodies}")
    print(f"  max_body_size         : {c.max_body_size:,} bytes")


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show the effective project for this process (quick status check).
        When a process override is set (--project / TALOS_PROJECT), reports
        that bind without implying the registry ACTIVE flag changed.
    Side effects: Prints effective project or guidance when none is bound
        (table or JSON).
    """
    try:
        active = manager.active()
    except ProjectNotFound as exc:
        cli_error(str(exc))
        return

    if wants_json(args):
        if active:
            cli_json(
                _project_as_dict(
                    active,
                    process_override=manager.project_override,
                )
            )
        else:
            cli_json(None)
        return

    if active:
        if manager.project_override:
            print(
                "Effective project "
                f"(process override '{manager.project_override}'; "
                "registry ACTIVE unchanged):\n"
                f"{_fmt_project(active)}"
            )
        else:
            print(f"Active project:\n{_fmt_project(active)}")
    else:
        print(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    """
    Purpose: Construct the full argument parser for 'talos project' subcommands.
    Output:  Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos project",
        description="Manage Talos projects. A project is the root isolation unit.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new project.")
    p_create.add_argument("name", help="Human-readable project name.")
    p_create.add_argument("-d", "--description", default="", help="Optional description.")
    p_create.add_argument(
        "-s", "--scope", nargs="*", metavar="PREFIX",
        help=(
            "Initial Basic Scope prefixes (one complete host/URL prefix each). "
            "Can be set later with 'project scope add'."
        ),
    )

    # open
    p_open = sub.add_parser("open", help="Open (activate) a project.")
    p_open.add_argument("id", help="Project id (slug).")

    # close
    sub.add_parser("close", help="Close the currently active project.")

    # delete
    p_delete = sub.add_parser(
        "delete",
        help=(
            "Remove a project from the registry "
            "(data preserved unless --purge)."
        ),
    )
    p_delete.add_argument("id", help="Project id (slug).")
    p_delete.add_argument(
        "--purge",
        action="store_true",
        help=(
            "Also permanently delete the project directory on disk "
            "(database, archive, reports, sessions). Irreversible. "
            "Interactive mode requires a second confirmation; non-interactive "
            "requires --force."
        ),
    )
    add_force_argument(p_delete)

    # rename
    p_rename = sub.add_parser(
        "rename",
        help=(
            "Rename a project (updates display name and id slug; "
            "moves the data directory when the slug changes)."
        ),
    )
    p_rename.add_argument("id", help="Current project id (slug).")
    p_rename.add_argument(
        "new_name",
        help="New human-readable name (slug is derived from this name).",
    )

    # description
    p_description = sub.add_parser(
        "description",
        help="Show or set the project description note.",
    )
    p_description.add_argument("id", help="Project id (slug).")
    p_description.add_argument(
        "text",
        nargs="*",
        metavar="TEXT",
        help=(
            "New description text. Omit to display the current description. "
            'Example: talos project description myapp "Production July Assessment"'
        ),
    )

    # list
    p_list = sub.add_parser("list", help="List all projects.")
    add_format_argument(p_list)

    # scope — resource subcommands (add/list/...) OR legacy `scope <id> [PREFIX...]`
    # Dispatched in run_project_cli; parser entry is a stub for help text only.
    sub.add_parser(
        "scope",
        help=(
            "Manage Basic Scope allow list "
            "(add|remove|list|clear|import; or legacy: scope <id> [PREFIX...])."
        ),
        add_help=False,
    )

    # constraints
    p_constraints = sub.add_parser(
        "constraints",
        help="Get or set capture constraints for a project.",
    )
    p_constraints.add_argument("id", help="Project id (slug).")
    p_constraints.add_argument(
        "--store-bodies",
        dest="store_bodies",
        type=lambda v: v.lower() in ("1", "true", "yes"),
        default=None,
        metavar="BOOL",
        help="Store request/response bodies (true|false).",
    )
    p_constraints.add_argument(
        "--max-body-size",
        dest="max_body_size",
        type=int,
        default=None,
        metavar="BYTES",
        help="Maximum body size in bytes before truncation.",
    )

    # status
    p_status = sub.add_parser(
        "status",
        help="Show the effective project (registry ACTIVE or --project / TALOS_PROJECT).",
    )
    add_format_argument(p_status)

    # outscope — delegates to its own sub-parser via run_outscope_cli
    sub.add_parser(
        "outscope",
        help="Manage out-of-scope URL-prefix exclusions (Basic Scope model).",
        add_help=False,
    )

    return parser


_COMMAND_MAP = {
    "create": cmd_create,
    "open": cmd_open,
    "close": cmd_close,
    "delete": cmd_delete,
    "rename": cmd_rename,
    "description": cmd_description,
    "list": cmd_list,
    "constraints": cmd_constraints,
    "status": cmd_status,
}

# Resource subcommands for `talos project scope add|remove|list|clear|import`.
_SCOPE_RESOURCE_COMMANDS = frozenset({"add", "remove", "list", "clear", "import"})


def run_project_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate project command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding the top-level 'talos' token).
    Side effects:
        Delegates to command handlers; may exit with sys.exit().
    """
    # Delegate outscope subcommand directly — it has its own sub-parser.
    if argv and argv[0] == "outscope":
        run_outscope_cli(manager, argv[1:])
        return

    # Scope resource API vs legacy `scope <project-id> [PREFIX...]`.
    if argv and argv[0] == "scope":
        rest = argv[1:]
        if rest and rest[0] in _SCOPE_RESOURCE_COMMANDS:
            run_scope_cli(manager, rest)
            return
        # Legacy compatibility: scope <id> [PREFIX ...]
        legacy = argparse.Namespace(
            id=rest[0] if rest else None,
            patterns=rest[1:] if len(rest) > 1 else [],
        )
        if not legacy.id:
            # No args → show resource help.
            run_scope_cli(manager, ["--help"])
            return
        # If first token looks like a resource command typo, resource parser
        # already handled known commands. Treat as project id.
        cmd_scope_legacy(manager, legacy)
        return

    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(manager, args)
