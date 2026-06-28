"""
Module: talos.__main__

Purpose:
    Top-level CLI entry point for the Talos tool.
    Routes top-level subcommands to their handlers.
    Running 'talos --help' or 'talos -h' prints a full command tree
    including all subcommands without needing to run each individually.

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
from talos.projects.auth_config_cli import run_auth_config_cli
from talos.projects.mutation_cli import run_mutation_cli
from talos.projects.attack_cli import run_attack_cli
from talos.projects.flow_cli import run_flow_cli
from talos.scheduler.cli import run_scheduler_cli
from talos.input_validation.cli import run_input_validation_cli

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

    if not argv or argv[0] in ("--help", "-h"):
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
    elif subcommand == "auth-config":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_auth_config_cli(manager, rest)
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
    elif subcommand == "input-validation":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_input_validation_cli(manager, rest)
    elif subcommand == "flow":
        manager = ProjectManager(projects_root=config.projects_dir)
        run_flow_cli(manager, rest)
    else:
        print(f"Unknown command: '{subcommand}'", file=sys.stderr)
        _print_usage()
        sys.exit(1)


def _print_usage() -> None:
    print(
        "Talos — MITM-based web application security testing tool\n\n"
        "Usage: talos <command> [subcommand] [args]\n\n"
        "Commands and subcommands:\n\n"
        "  project\n"
        "    create          Create a new project\n"
        "    open            Open (activate) a project\n"
        "    close           Close the active project\n"
        "    delete          Delete a project\n"
        "    list            List all projects\n"
        "    scope           Show or replace project scope\n"
        "    constraints     Show or update body storage constraints\n"
        "    status          Show the active project\n"
        "    outscope\n"
        "      add domain    Add a domain to the out-of-scope block list\n"
        "      list          List out-of-scope domains\n"
        "      remove domain Remove a domain from the block list\n\n"
        "  proxy\n"
        "    start           Start the capture proxy\n\n"
        "  ui                Start the Talos web UI (http://127.0.0.1:8000/)\n\n"
        "  role\n"
        "    create          Create a new role\n"
        "    add             Alias for create\n"
        "    list            List roles\n"
        "    set             Set the active role\n"
        "    unset           Clear the active role\n\n"
        "  module\n"
        "    create          Create a new module\n"
        "    add             Alias for create\n"
        "    list            List modules\n"
        "    set             Set the active module\n"
        "    unset           Clear the active module\n\n"
        "  access\n"
        "    client set      Set client-side access (ALLOW/DENY) for role+module\n"
        "    client unset    Remove client-side access entry\n"
        "    server set      Set server-expected access assertion\n"
        "    server unset    Remove server-expected access assertion\n"
        "    delete          Remove an entire access row\n"
        "    show            Display the full access matrix\n"
        "    coverage        Show expected vs observed endpoint counts\n"
        "    signals         Show BAC/IDOR signal report\n\n"
        "  auth\n"
        "    set             Define a required auth artifact (cookie/header)\n"
        "    unset           Remove an auth artifact\n"
        "    show            Show configured auth artifacts\n"
        "    clear           Remove all auth artifacts\n"
        "    test            Run auth-bypass tests for an endpoint\n\n"
        "  auth-config\n"
        "    add-flow        Add an auth flow for a role\n"
        "    remove-flow     Remove an auth flow\n"
        "    list-flows      List auth flows for a role\n"
        "    set-extractor   Assign a Python extractor to a flow\n"
        "    show-extractor  Show the extractor for a flow\n"
        "    edit-extractor  Open extractor in $EDITOR\n"
        "    remove-extractor Remove extractor from a flow\n"
        "    test            Test extractor against a live response\n"
        "    validate        Validate extractor outputs match auth-config artifacts\n"
        "    refresh         Run extractors and update role auth state\n"
        "    status          Show auth state and health for all roles\n"
        "    show            Show auth state for a specific role\n"
        "    set-ttl         Configure session TTL and refresh window\n"
        "    add-expiry-signal   Add a body/header expiry detection signal\n"
        "    clear-expiry-signals  Remove all expiry signals\n"
        "    set-validation  Configure Layer 3 session validation URL\n"
        "    clear-validation  Remove Layer 3 validation config\n"
        "    add-control-flow    Add a Layer 4 control flow\n"
        "    remove-control-flow Remove a Layer 4 control flow\n"
        "    list-control-flows  List Layer 4 control flows\n\n"
        "  endpoint\n"
        "    mark            Add a safety annotation (--logout | --dangerous)\n"
        "    unmark          Remove a safety annotation\n"
        "    show            Display endpoint policy, annotations, and score\n"
        "    export <id>     Export complete endpoint dossier (Markdown)\n"
        "    priority set endpoint   Set manual priority for an endpoint\n"
        "    priority set path       Set manual priority via path pattern\n"
        "    priority clear endpoint  Remove manual priority override\n"
        "    priority clear path     Remove path-based priority rule\n"
        "    exclude endpoint  Exclude an endpoint from attack candidate gen\n"
        "    exclude path      Exclude endpoints matching a path pattern\n"
        "    include endpoint  Remove endpoint exclusion\n"
        "    include path      Remove path exclusion\n"
        "    rules list        List all path-based policy rules\n\n"
        "  replay\n"
        "    flow            Replay a specific captured flow\n"
        "    endpoint        Replay the best flow for an endpoint\n\n"
        "  scheduler\n"
        "    status          Show scheduler queue status\n"
        "    config          Show or update scheduler rate-limit config\n"
        "    enqueue flow    Manually enqueue a flow replay job\n"
        "    enqueue endpoint  Manually enqueue an endpoint replay job\n"
        "    clear           Clear pending or all scheduler jobs\n\n"
        "  mutation\n"
        "    add             Add a request header mutation\n"
        "    list            List all request mutations\n"
        "    delete          Remove a request mutation\n\n"
        "  attack\n"
        "    unauth\n"
        "      exclude add   Exclude a host/path from unauth testing\n"
        "      exclude remove  Remove a host/path exclusion\n"
        "      exclude list  List unauth exclusions\n"
        "    bac session-swap    Direct session swap BAC test\n"
        "    bac method-fuzz     HTTP Method Manipulation\n"
        "    bac content-type    Content-Type Confusion\n"
        "    bac url-fuzz        URL Manipulation\n"
        "    bac header-inject   Header Manipulation\n"
        "    bac host-fuzz       Host Header Changes\n"
        "    bac role-inject     Role Parameter Injection\n"
        "    bac filter init     Create BAC decision filter config\n"
        "    bac filter show     Show current filter config\n"
        "    bac filter validate Validate the filter config\n\n"
        "  input-validation\n"
        "    run             Schedule IV jobs for the entire project\n"
        "    run --host H    Scope to a single host\n"
        "    run --endpoint  Scope to a single endpoint\n"
        "    run --parameter Scope to a single parameter\n"
        "    run --ignore-cache  Force re-run (ignore cached results)\n"
        "    config          Show or update IV configuration\n"
        "      --enable / --disable\n"
        "      --workers N\n"
        "      --analysis-on / --analysis-off <phase>\n"
        "    status          Show IV progress summary\n"
        "    resume          Continue from unfinished analyses\n"
        "    clear-cache                     Delete all cached IV results\n"
        "    clear-cache --host H            Delete cache for one host\n"
        "    clear-cache --endpoint ID       Delete cache for one endpoint\n"
        "    clear-cache --parameter NAME    Delete cache for one parameter name\n"
        "    exclude endpoint <id>   Exclude an endpoint\n"
        "    exclude host <host>     Exclude a host\n"
        "    include endpoint <id>   Remove endpoint exclusion\n"
        "    include host <host>     Remove host exclusion\n"
        "    show <param_uuid>  Display complete profile for a parameter (by UUID)\n"
        "    export csv                  Export per-probe data as CSV\n"
        "    export parameter <uuid>     Export parameter dossier (Markdown)\n"
        "    export host <host>          Export host IV summary (Markdown)\n"
        "    [Phase shortcuts — each supports --host/--endpoint/--parameter/--force]\n"
        "    baseline        Run Phase 1 (baseline response capture)\n"
        "    identifier      Run Phase 2 (identifier injection, 9 probes)\n"
        "    characters      Run Phase 3 (character acceptance, 30 probes)\n"
        "    length          Run Phase 4 (length behaviour, 10 probes)\n"
        "    types           Run Phase 5 (type characterization, 12 probes)\n"
        "    transformations Run Phase 6 (transformation analysis — 0 HTTP)\n"
        "    reflection      Run Phase 7 (reflection analysis — 0 HTTP)\n"
        "    validation      Run Phase 8 (validation behaviour, 8 probes)\n\n"
        "  flow\n"
        "    show <flow_id>             Display a replay flow (request + response + meta)\n"
        "    export <flow_id>           Export a flow to Markdown\n"
        "    export --module <module>   Export all flows from a module\n"
        "    export --parameter <uuid>  Export all IV flows for a parameter UUID\n"
        "    export --endpoint <id>     Export all flows for an endpoint\n"
        "    export --flows <id>...     Export a list of specific flows\n"
    )


if __name__ == "__main__":
    main()
