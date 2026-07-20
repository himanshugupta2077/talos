"""
Module: talos.__main__

Purpose:
    Top-level CLI entry point for the Talos tool.
    Routes top-level subcommands to their handlers.
    Running 'talos --help' or 'talos -h' prints a full command tree
    including all subcommands without needing to run each individually.

    Global options (CLI-013) may appear before the subcommand:
        talos --project <id> <command> …
    Equivalent environment variable: TALOS_PROJECT=<id>

Dependencies: os, sys, talos.config, talos.cli_output, talos.projects, talos.proxy
Data flow:
    sys.argv → global options → top-level dispatcher → subcommand handler
Side effects:
    - Initializes config from environment.
    - Creates ProjectManager with configured path and optional project override.
    - May set TALOS_PROJECT in the process environment when --project is given
      so child processes (e.g. mitmdump / addon) inherit the same bind.
    - May exit with sys.exit() on argument errors.
    - Root help documents shared CLI output conventions, exit codes,
      machine-readable --format json (CLI-011/012/014), and project context
      (CLI-013).
"""

import logging
import os
import sys

from talos.cli_output import EXIT_USAGE, cli_error, cli_usage_error
from talos.config import TalosConfig
from talos.projects.manager import (
    ProjectManager,
    ProjectNotFound,
    TALOS_PROJECT_ENV,
)
from talos.projects.cli import run_project_cli
from talos.projects.access_cli import run_role_cli, run_module_cli, run_access_cli
from talos.projects.endpoint_cli import run_endpoint_cli
from talos.proxy.cli import run_proxy_cli
from talos.replay.cli import run_replay_cli
from talos.projects.auth_cli import run_auth_cli
from talos.projects.auth_config_cli import run_auth_config_cli
from talos.projects.attack_cli import run_attack_cli
from talos.projects.flow_cli import run_flow_cli
from talos.scheduler.cli import run_scheduler_cli
from talos.input_validation.cli import run_input_validation_cli
from talos.findings.cli import run_finding_cli
from talos.configuration.cli import run_config_cli

# Structured logging to stderr; keeps stdout clean for parseable output.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)


def _split_global_args(argv: list[str]) -> tuple[str | None, list[str]]:
    """
    Purpose:
        Consume root-level global flags that appear before the subcommand.
        Supported: --project <id>, --project=<id>
    Input:
        argv — full argument list after the program name.
    Output:
        (project_id_or_None, remaining_argv starting at subcommand / help)
    Side effects:
        Exits with EXIT_USAGE if --project is present without a value.
    """
    project_id: str | None = None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--project":
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                cli_usage_error("--project requires a project id.")
            project_id = argv[index + 1]
            index += 2
            continue
        if token.startswith("--project="):
            project_id = token[len("--project="):]
            if not project_id.strip():
                cli_usage_error("--project requires a project id.")
            index += 1
            continue
        # First non-global token is the subcommand (or -h / --help).
        break
    return project_id, argv[index:]


def _make_manager(config: TalosConfig, project_override: str | None) -> ProjectManager:
    """
    Purpose:
        Build ProjectManager and fail early if an override id is unknown.
    Input:
        config           — resolved TalosConfig.
        project_override — id from --project, or None (env still applied inside manager).
    Output:
        ProjectManager instance.
    Side effects:
        When project_override is set, exports TALOS_PROJECT into os.environ so
        child processes (proxy addon) share the same process-scoped bind.
        Exits 1 if the override project does not exist in the registry.
    """
    if project_override is not None:
        cleaned = project_override.strip()
        if not cleaned:
            cli_usage_error("--project requires a project id.")
        # Inherit into mitmdump / addon without mutating registry ACTIVE.
        os.environ[TALOS_PROJECT_ENV] = cleaned
        project_override = cleaned

    manager = ProjectManager(
        projects_root=config.projects_dir,
        project_override=project_override,
    )
    if manager.project_override:
        try:
            manager.get(manager.project_override)
        except ProjectNotFound as exc:
            cli_error(str(exc))
    return manager


def main(argv: list[str] | None = None) -> None:
    """
    Purpose:
        Parse global options and the top-level subcommand, then dispatch.
    Input:
        argv — argument list; defaults to sys.argv[1:] if None.
    Side effects:
        - Reads environment for config and optional TALOS_PROJECT.
        - May set TALOS_PROJECT when --project is given.
        - Delegates to subcommand CLI modules.
    """
    if argv is None:
        argv = sys.argv[1:]

    project_override, argv = _split_global_args(argv)

    if not argv or argv[0] in ("--help", "-h"):
        _print_usage()
        sys.exit(0)

    config = TalosConfig.from_env()
    manager = _make_manager(config, project_override)
    subcommand = argv[0]
    rest = argv[1:]

    if subcommand == "project":
        run_project_cli(manager, rest)
    elif subcommand == "config":
        run_config_cli(manager, rest)
    elif subcommand == "proxy":
        run_proxy_cli(manager, rest)
    elif subcommand == "role":
        run_role_cli(manager, rest)
    elif subcommand == "module":
        run_module_cli(manager, rest)
    elif subcommand == "access":
        run_access_cli(manager, rest)
    elif subcommand == "replay":
        run_replay_cli(manager, rest)
    elif subcommand == "auth":
        run_auth_cli(manager, rest)
    elif subcommand == "auth-config":
        run_auth_config_cli(manager, rest)
    elif subcommand == "endpoint":
        run_endpoint_cli(manager, rest)
    elif subcommand == "scheduler":
        run_scheduler_cli(manager, rest)
    elif subcommand == "attack":
        run_attack_cli(manager, rest)
    elif subcommand == "input-validation":
        run_input_validation_cli(manager, rest)
    elif subcommand == "flow":
        run_flow_cli(manager, rest)
    elif subcommand == "finding":
        run_finding_cli(manager, rest)
    else:
        cli_error(f"Unknown command: '{subcommand}'.", exit_code=None)
        _print_usage()
        sys.exit(EXIT_USAGE)


def _print_usage() -> None:
    print(
        "Talos — MITM-based web application security testing tool\n\n"
        "Usage: talos [--project ID] <command> [subcommand] [args]\n\n"
        "Project context (most commands need a project):\n"
        "  talos project open <id>           Interactive: set registry ACTIVE\n"
        "  talos --project <id> <command>    Per-invocation (does not rewrite registry)\n"
        "  TALOS_PROJECT=<id> talos <cmd>    Same as --project for this process\n"
        "  talos project status              Show effective project for this process\n\n"
        "Role and module arguments accept a name or UUID "
        "(see: talos role list / talos module list).\n\n"
        "Output (shared style):\n"
        "  Errors    → stderr  'Error:' then blank line then message\n"
        "  Warnings  → stderr  'Warning:' then blank line then message\n"
        "  Cancel    → stdout  'Cancelled.' when a confirmation is declined\n"
        "  Confirm   → Interactive TTY: [y/N] on destructive ops\n"
        "              Non-interactive (CI/pipes): require --force or exit 2\n"
        "              --force always skips the prompt\n"
        "  --format  → table (default) | json on list / show / status commands\n"
        "              Example: talos endpoint list --format json | jq .\n\n"
        "Exit codes:\n"
        "  0   Success (including intentional no-ops)\n"
        "  1   General failure (not found, operation failed)\n"
        "  2   Invalid arguments / unknown command / missing --force (non-interactive)\n"
        "  3   Preconditions failed (no project, auth/policy gate)\n"
        "  130 User cancelled a confirmation prompt\n\n"
        "Commands and subcommands:\n\n"
        "  project\n"
        "    create          Create a new project\n"
        "    open            Open (activate) a project\n"
        "    close           Close the active project\n"
        "    delete          Remove from registry [--force]; add --purge to erase disk data\n"
        "    rename          Rename project (name + id slug; moves data directory)\n"
        "    description     Show or set project description note\n"
        "    list            List all projects\n"
        "    scope           Show or replace project scope\n"
        "    constraints     Show or update body storage constraints\n"
        "    status          Show effective project (ACTIVE or process override)\n"
        "    outscope\n"
        "      add domain    Add a domain to the out-of-scope block list\n"
        "      list          List out-of-scope domains\n"
        "      remove domain Remove a domain from the block list\n\n"
        "  config            Layered configuration (defaults → global → project → CLI)\n"
        "    show            Config file paths and layer summary\n"
        "    effective       Fully merged config with value sources\n"
        "    get <key>       Get one value + inheritance source\n"
        "    set <key> <val> Set project override (or --global)\n"
        "    unset <key>     Remove override (inherit lower layer)\n"
        "    edit            Open project.yaml (or --global) in $EDITOR\n"
        "    schema          Machine-readable types/defaults (UI / automation)\n"
        "    proxy|capture|scheduler|attack|http\n"
        "                    Section resources: show | set | unset | edit\n"
        "    http            HTTP Manipulation Engine (request + response rules)\n"
        "      list          List effective rules (all layers)\n"
        "      show <id>     Show one rule\n"
        "      create        Create a rule (--name, --direction, --action, …)\n"
        "      delete        Delete a rule [--force]\n"
        "      enable|disable  Toggle a rule\n"
        "      set-priority  Change rule priority (lower runs first)\n"
        "      set-match|clear-match  Scope a rule (host/path/method/endpoint…)\n"
        "      add-action|remove-action  Append or drop an action\n"
        "      reorder       Renumber priorities 100,200,300…\n"
        "      export|import YAML/JSON rule sets\n"
        "      enable-engine|disable-engine  Master switch (http.enabled)\n"
        "      actions       List supported action opcodes\n\n"
        "  proxy\n"
        "    start           Start managed proxy (background; --foreground to block)\n"
        "                    [--upstream URL | --no-upstream] [--port] [--listen-host]\n"
        "    stop            Gracefully stop the managed capture proxy\n"
        "    kill            Stop managed proxy + free port (orphan mitmdump)\n"
        "    restart         Gracefully restart the managed capture proxy\n"
        "    status          Show managed proxy runtime status [--format json]\n"
        "    config          Show or set Direct vs Upstream Proxy mode\n"
        "                    (also: talos config proxy / config set proxy.*)\n\n"
        "  role\n"
        "    create          Create a new role\n"
        "    add             Alias for create\n"
        "    list            List roles (UUID, name, active)\n"
        "    show            Show role details (name or UUID)\n"
        "    rename          Rename a role (UUID unchanged)\n"
        "    delete          Delete a role [--force]\n"
        "    set             Set the active role\n"
        "    unset           Clear the active role\n\n"
        "  module\n"
        "    create          Create a new module\n"
        "    add             Alias for create\n"
        "    list            List modules (UUID, name, active)\n"
        "    show            Show module details (name or UUID)\n"
        "    rename          Rename a module (UUID unchanged)\n"
        "    delete          Delete a module [--force]\n"
        "    set             Set the active module\n"
        "    unset           Clear the active module\n\n"
        "  access\n"
        "    client set      Set client-side access (allow|deny|unknown)\n"
        "    client unset    Remove client-side access entry\n"
        "    server set      Set server-expected access assertion\n"
        "    server unset    Remove server-expected access assertion\n"
        "    delete          Remove an entire access row [--force]\n"
        "    show            Display the full access matrix\n"
        "    coverage        Show expected vs observed endpoint counts\n"
        "    signals         Show privilege-confusion / BAC signal report\n\n"
        "  auth\n"
        "    set             Define required auth artifact names (cookie/header)\n"
        "    unset           Remove an auth artifact name\n"
        "    show            Show configured auth artifacts\n"
        "    clear           Remove all auth artifacts [--force]\n"
        "    test            Run Authentication Bypass test for an endpoint\n\n"
        "  auth-config   (role: name or UUID)\n"
        "    set-provider    Set provider for a role (auto|manual)\n"
        "    show-provider   Show configured provider\n"
        "    set-session     Manual session file: 'path' prints path; no arg applies\n"
        "    clear-session   Clear manual session config (session recovery)\n"
        "    add-flow        Add an auth flow (auto provider)\n"
        "    remove-flow     Remove an auth flow\n"
        "    list-flows      List auth flows for a role\n"
        "    set-extractor   Assign a Python extractor to a flow\n"
        "    show-extractor  Show the extractor for a flow\n"
        "    edit-extractor  Open extractor in $EDITOR\n"
        "    remove-extractor Remove extractor from a flow\n"
        "    test            Test one flow+extractor (no state stored)\n"
        "    validate        Validate session (auto and manual)\n"
        "    refresh         Refresh auth state\n"
        "    status          Show provider, session state, and artifacts\n"
        "    show            Show complete auth config for a role\n"
        "    set-ttl         Layer 1: session TTL and refresh window\n"
        "    add-expiry-signal   Layer 2: body/header/status expiry signals\n"
        "    clear-expiry-signals  Remove all Layer 2 expiry signals [--force]\n"
        "    reset-health    Reset Layer 2 suspicion counter (health recovery)\n"
        "    add-control-flow    Layer 3: add session validation flow\n"
        "    remove-control-flow Remove a validation flow\n"
        "    list-control-flows  List validation flows\n\n"
        "  endpoint\n"
        "    list            List endpoints (UUID, method, host, path, policy)\n"
        "                    [--method] [--host] [--qualified] [--excluded]\n"
        "                    [--search] [--role] [--priority] [--format table|json]\n"
        "    mark            Safety annotation on one or more IDs\n"
        "                    <id> [<id> ...] --logout|--dangerous|--safe\n"
        "    unmark          Remove annotation from one or more IDs\n"
        "                    <id> [<id> ...] --logout|--dangerous\n"
        "    show            Display endpoint policy, annotations, and score\n"
        "                    [--format table|json]\n"
        "    policy <id>     Explain effective policy (why final state exists)\n"
        "                    [--format table|json]\n"
        "    export          Export dossier(s): <id> or --endpoints <id>...\n"
        "    notes set|clear <id>           Free-form analyst notes (set via stdin)\n"
        "    tags add|remove|set|clear      Labels on one or more IDs\n"
        "                    <id> [<id> ...] [--tag T ...]  (or legacy tags after one id)\n"
        "    priority set endpoint <id> [<id> ...] LEVEL\n"
        "    priority clear endpoint <id> [<id> ...]\n"
        "    priority set|clear path \"pattern\" ...\n"
        "    exclude|include endpoint <id> [<id> ...]\n"
        "    exclude|include path \"pattern\"\n"
        "    rule add|update|delete|list|show|preview   Path policy-rule resource\n"
        "    rules                          List path rules (alias for rule list)\n\n"
        "  replay\n"
        "    flow            Replay a specific captured flow\n"
        "    endpoint        Replay the best flow for an endpoint\n\n"
        "  flow\n"
        "    list                       List flows (UUID, endpoint, method, status,\n"
        "                               role, source, created)\n"
        "                               [--endpoint] [--status-code] [--role]\n"
        "                               [--source] [--limit]\n"
        "    show <flow_id>             Display a flow (request + response + meta)\n"
        "    export <flow_id>           Export a flow to Markdown\n"
        "    export --module <name>     Export flows by generated_by module\n"
        "    export --parameter <uuid>  Export IV flows for a parameter UUID\n"
        "    export --endpoint <id>     Export all flows for an endpoint\n"
        "    export --flows <id>...     Export a list of specific flows\n\n"
        "  scheduler\n"
        "    start           Start managed scheduler process for bound project\n"
        "    stop            Gracefully stop managed scheduler process\n"
        "    status          Process runtime + queue depth / metrics\n"
        "    config          Show or update rate-limit config\n"
        "    enqueue flow    Manually enqueue a flow replay job\n"
        "    enqueue endpoint  Manually enqueue endpoint replay or auth-test\n"
        "    jobs list       List jobs [--status] [--type] [--limit] [--format]\n"
        "    jobs show       Inspect one job by UUID or unique prefix\n"
        "    cancel          Cancel one pending/paused job by UUID\n"
        "    prune           Delete terminal history (--status done|failed|…)\n"
        "                    [--force]\n"
        "    clear           Remove all pending jobs [--force]\n"
        "    pause           Pause execution (pending → paused)\n"
        "    resume          Validate sessions as needed; resume paused jobs\n\n"
        "  attack\n"
        "    unauth run      Enqueue Unauthenticated Execution jobs\n"
        "                    [--technique NAME]\n"
        "    unauth config   Show or set auto-run (auth_test auto-enqueue)\n"
        "                    [show] [--auto-run on|off]\n"
        "    unauth filter   init | show | validate\n"
        "    bac session-swap|method-fuzz|content-type|url-fuzz|\n"
        "        header-inject|host-fuzz|role-inject|parser-confuse\n"
        "                    [--role NAME|UUID] [--endpoint UUID]\n"
        "                    [--module NAME|UUID] [--auto-generate]\n"
        "    bac filter      init | show | validate\n\n"
        "  input-validation\n"
        "    run             Schedule IV jobs (adaptive planner)\n"
        "                    [--budget quick|standard|deep|exhaustive]\n"
        "                    [--host / --endpoint / --parameter NAME]\n"
        "                    [--ignore-cache] [--include-auth-artifacts]\n"
        "    config          Show or update IV config\n"
        "                    (--enable|--disable|--workers N|\n"
        "                     --probe-strategy|--budget TIER|\n"
        "                     --max-requests-per-param N|\n"
        "                     --analysis-on|--analysis-off PHASE)\n"
        "    status          Progress, budget, requests_used, confidence, plan\n"
        "    resume          Continue unfinished analyses\n"
        "    synthesize      Offline profiles from existing probes (zero HTTP)\n"
        "    candidates      List attack candidates (prioritization only)\n"
        "                    [--attack|--min-score|--host|--capability]\n"
        "    clear-cache     Delete IV cache [--force] (optional host/endpoint/parameter)\n"
        "    exclude|include endpoint|host\n"
        "    show <param_uuid>   Parameter profile + candidates\n"
        "    show --endpoint|--host   Multi-level intelligence (M10)\n"
        "    export parameter|host [--format markdown|json]\n"
        "    export csv\n"
        "    baseline|multiprobe|identifier|characters|length|types|\n"
        "    transformations|reflection|validation\n"
        "                    Phase shortcuts (--host/--endpoint/--parameter/\n"
        "                    --ignore-cache)\n\n"
        "  finding\n"
        "    list                       List PRIMARY findings (default)\n"
        "    list --linked              List LINKED findings only\n"
        "    list --all                 List PRIMARY and LINKED findings\n"
        "    list [--status STATUS]     Filter by lifecycle status\n"
        "    show <uuid>                Show finding detail, evidence, timeline\n"
        "    confirm <uuid>             Mark finding as CONFIRMED\n"
        "    reject <uuid>              Mark finding as REJECTED\n"
        "    reopen <uuid>              Revert to TRIAGING\n"
        "    confirm|reject|reopen <uuid> --linked [--force]\n"
        "    duplicate <uuid> --of <uuid>\n"
        "    note set|clear <uuid>      Free-form analyst notes (set via stdin)\n"
        "    group create|add|remove|list\n"
        "    report <uuid> | report --group <group>\n"
    )


if __name__ == "__main__":
    main()
