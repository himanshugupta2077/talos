"""
Module: talos.__main__

Purpose:
    Top-level CLI entry point for the Talos tool.
    Routes top-level subcommands (project, proxy) to their handlers.

Dependencies: sys, talos.config, talos.projects, talos.proxy
Data flow:
    sys.argv → top-level dispatcher → subcommand handler
Side effects:
    - Initializes config from environment.
    - Creates ProjectManager with configured path.
    - May exit with sys.exit() on argument errors.
"""

import logging
import sys

from talos.config import TalosConfig
from talos.projects.manager import ProjectManager
from talos.projects.cli import run_project_cli
from talos.projects.access_cli import run_role_cli, run_module_cli, run_access_cli
from talos.projects.endpoint_cli import run_endpoint_cli
from talos.proxy.cli import run_proxy_cli
from talos.ui.cli import run_inspect_cli
from talos.replay.cli import run_replay_cli
from talos.projects.auth_cli import run_auth_cli
from talos.projects.mutation_cli import run_mutation_cli
from talos.projects.attack_cli import run_attack_cli
from talos.scheduler.cli import run_scheduler_cli

# Structured logging to stderr; keeps stdout clean for parseable output.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)


def main(argv: list[str] | None = None) -> None:
    """
    Purpose:
        Parse the top-level subcommand and dispatch to the appropriate handler.
    Input:
        argv — argument list; defaults to sys.argv[1:] if None.
    Side effects:
        - Reads environment for config.
        - Delegates to subcommand CLI modules.
    """
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        _print_usage()
        sys.exit(0)

    config = TalosConfig.from_env()
    subcommand = argv[0]
    rest = argv[1:]

    if subcommand == "project":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_project_cli(manager, rest)
    elif subcommand == "proxy":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_proxy_cli(manager, rest)
    elif subcommand == "ui":
        run_inspect_cli(projects_root=config.projects_dir, argv=rest)
    elif subcommand == "role":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_role_cli(manager, rest)
    elif subcommand == "module":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_module_cli(manager, rest)
    elif subcommand == "access":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_access_cli(manager, rest)
    elif subcommand == "replay":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_replay_cli(manager, rest)
    elif subcommand == "auth":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_auth_cli(manager, rest)
    elif subcommand == "endpoint":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_endpoint_cli(manager, rest)
    elif subcommand == "scheduler":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_scheduler_cli(manager, rest)
    elif subcommand == "mutation":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_mutation_cli(manager, rest)
    elif subcommand == "attack":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_attack_cli(manager, rest)
    else:
        print(f"Unknown command: '{subcommand}'", file=sys.stderr)
        _print_usage()
        sys.exit(1)


def _print_usage() -> None:
    print(
        "Usage: talos <command> [args]\n\n"
        "Commands:\n"
        "  project   Manage projects (create, open, close, list, scope, constraints, delete, status, outscope)\n"
        "  proxy     Control the capture proxy (start)\n"
        "  ui        Start the Talos web UI (default: http://127.0.0.1:8000/)\n"
        "  role      Manage roles (create/add, list, set, unset)\n"
        "  module    Manage modules (create/add, list, set, unset)\n"
        "  access    Manage access map (client set/unset, server set/unset, delete, show)\n"
        "  replay     Replay captured flows (flow <id>, endpoint <id>)\n"
        "  auth       Manage auth config and run auth-bypass tests (set, show, clear, test <id>)\n"
        "  endpoint   Manage endpoint annotations (mark, unmark, show)\n"
        "  scheduler  Control the replay scheduler (status, config, enqueue, clear)\n"
        "  mutation   Manage request mutations (add, list, delete)\n"
        "  attack     Manage attack module config (unauth exclude add|remove|list)\n"
    )


if __name__ == "__main__":
    main()
