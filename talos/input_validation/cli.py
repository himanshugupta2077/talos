"""
Module: talos.input_validation.cli

Purpose:
    Command-line interface for the Input Validation Engine.
    Entry point: talos input-validation <subcommand>

    Module 12 (operator experience) wires M1–M11 into usable CLI:
    budget config, status with confidence, candidates list/filter,
    export JSON+Markdown with version fields, synthesize, show profile.

    Main execution commands:
        talos input-validation run               — schedule jobs for the entire project
        talos input-validation run --budget standard — set planner tier then schedule
        talos input-validation run --host H      — single host
        talos input-validation run --endpoint ID — single endpoint
        talos input-validation run --parameter P — single parameter everywhere it appears
        talos input-validation run --ignore-cache — force re-run

    Phase-level commands (shorthand for --phase X):
        talos input-validation baseline
        talos input-validation multiprobe
        talos input-validation identifier
        talos input-validation characters
        talos input-validation length
        talos input-validation types
        talos input-validation transformations
        talos input-validation reflection
        talos input-validation validation

    Probe volume: config --probe-strategy / --budget quick|standard|deep|exhaustive
    (Module 5 planner schedules adaptively; multiprobe first under standard).
    Optional hard cap: config --max-requests-per-param N.

    Surfaces (Module 9): path, query, body (JSON/form/multipart/XML/GraphQL),
    header, cookie.  Auth artifacts (session cookies, Authorization) are
    skipped by default; opt in with --include-auth-artifacts.

    Multi-level learning (Module 10): endpoint and application/host profiles
    aggregate shared middleware defaults; new parameters inherit tested
    negatives and parser expectations at reduced confidence.

    Capabilities & candidates (Module 11): show/export/candidates list;
    scores are prioritization only, not confirmed vulnerabilities.

    Each phase command supports: --host, --endpoint, --parameter, --ignore-cache
    (--force is a deprecated alias for --ignore-cache on phase shortcuts only;
    reserved elsewhere for confirmation bypass — CLI-019).

    Configuration:
        talos input-validation config            — show current config
        talos input-validation config --enable
        talos input-validation config --disable
        talos input-validation config --workers N
        talos input-validation config --probe-strategy standard
        talos input-validation config --budget standard   # alias for probe-strategy
        talos input-validation config --include-auth-artifacts
        talos input-validation config --analysis-on  <phase>
        talos input-validation config --analysis-off <phase>

    Status:
        talos input-validation status            — progress, budget, confidence, plan

    Resume:
        talos input-validation resume            — continue from unfinished analyses

    Cache:
        talos input-validation clear-cache                         — delete all IV cache data
        talos input-validation clear-cache --host api.example.com  — scoped to one host
        talos input-validation clear-cache --endpoint <id>         — scoped to one endpoint
        talos input-validation clear-cache --parameter <name>      — scoped to one parameter name

    Exclusions:
        talos input-validation exclude endpoint <id>
        talos input-validation exclude host <host>
        talos input-validation include endpoint <id>
        talos input-validation include host <host>

    Results:
        talos input-validation show <parameter_uuid> — parameter profile + candidates
        talos input-validation show --endpoint <id>  — endpoint intelligence (M10)
        talos input-validation show --host <host>    — application/host intelligence (M10)
        talos input-validation candidates            — list/filter attack candidates
        talos input-validation reflections           — raw cross-flow / stored reflection links
        talos input-validation export parameter|host — Markdown or JSON export
        talos input-validation export csv            — per-probe CSV
        talos input-validation synthesize            — offline profiles from existing probes

Dependencies: argparse, sys
              talos.projects.manager, talos.input_validation.config,
              talos.input_validation.db, talos.input_validation.engine,
              talos.input_validation.synthesize, talos.input_validation.candidates,
              talos.scheduler.job
Data flow:
    CLI args -> bound project lookup -> engine / config / db / synthesize -> stdout
Side effects:
    - Reads/writes project DB.
    - Inserts scheduler jobs.
    - Prints to stdout/stderr.
    - Exits 1 on error.
"""
from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_json,
    cli_usage_error,
    cli_precondition_error,
    confirm_or_exit,
    wants_json,
)

import argparse
import csv
import io
import json
import sys

from talos.projects.manager import ProjectManager
from talos.input_validation.config import (
    IVConfig, IVAnalysesConfig, load_config, save_config, format_config
)
from talos.input_validation import db as iv_db
from talos.input_validation import engine as iv_engine
from talos.scheduler.job import (
    IV_BASELINE, IV_MULTIPROBE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
    IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION,
)


# Valid phase names for validation.
_PHASE_NAMES = {
    "baseline": IV_BASELINE,
    "multiprobe": IV_MULTIPROBE,
    "identifier": IV_IDENTIFIER,
    "characters": IV_CHARACTERS,
    "length": IV_LENGTH,
    "types": IV_TYPES,
    "transformations": IV_TRANSFORMATIONS,
    "reflection": IV_REFLECTION,
    "validation": IV_VALIDATION,
}


def _require_active(manager: ProjectManager):
    """Return the active project or exit with an error message."""
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_input_validation_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse input-validation subcommand arguments and dispatch to handler.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'input-validation'.
    Side effects:
        Dispatches to command handlers.
        Prints usage and exits 0 for --help.
        Exits 1 for errors.
    """
    parser = argparse.ArgumentParser(
        prog="talos input-validation",
        description=(
            "Input Validation Engine — actively characterize every input accepted "
            "by the application. Disabled by default; enable with "
            "'talos input-validation config --enable'."
        ),
    )
    sub = parser.add_subparsers(dest="iv_cmd", metavar="<command>")
    sub.required = True

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    p_run = sub.add_parser(
        "run",
        help="Schedule Input Validation jobs for the project (or a scoped subset).",
    )
    _add_scope_args(p_run)
    p_run.add_argument(
        "--ignore-cache",
        action="store_true",
        help="Ignore cached analyses and re-run everything.",
    )
    p_run.add_argument(
        "--include-auth-artifacts",
        action="store_true",
        help=(
            "Probe session cookies and Authorization-like headers "
            "(Module 9; default skips them). One-shot override for this run."
        ),
    )
    p_run.add_argument(
        "--budget",
        "--probe-strategy",
        dest="budget",
        metavar="TIER",
        choices=("quick", "standard", "deep", "exhaustive"),
        help=(
            "Set planner budget tier (persists as probe_strategy) then schedule: "
            "quick|standard|deep|exhaustive. Same as "
            "'config --probe-strategy TIER' before run."
        ),
    )

    # ------------------------------------------------------------------
    # Phase shorthand commands
    # ------------------------------------------------------------------
    for phase_name in _PHASE_NAMES:
        p_phase = sub.add_parser(
            phase_name,
            help=f"Run only the {phase_name} analysis phase.",
        )
        _add_scope_args(p_phase)
        # CLI-019: re-analysis uses --ignore-cache; --force remains a
        # backwards-compatible alias. Elsewhere --force is only for
        # confirmation bypass (e.g. clear-cache).
        p_phase.add_argument(
            "--ignore-cache",
            "--force",
            dest="ignore_cache",
            action="store_true",
            help=(
                "Ignore cached result for this phase and re-run. "
                "(--force is a deprecated alias for --ignore-cache.)"
            ),
        )

    # ------------------------------------------------------------------
    # config
    # ------------------------------------------------------------------
    p_config = sub.add_parser(
        "config",
        help="Show or update Input Validation configuration.",
    )
    p_config.add_argument("--enable", action="store_true", help="Enable the engine.")
    p_config.add_argument("--disable", action="store_true", help="Disable the engine.")
    p_config.add_argument(
        "--workers",
        type=int,
        metavar="N",
        help="Number of concurrent analysis workers.",
    )
    p_config.add_argument(
        "--analysis-on",
        metavar="PHASE",
        help=f"Enable a specific analysis phase ({', '.join(_PHASE_NAMES)}).",
    )
    p_config.add_argument(
        "--analysis-off",
        metavar="PHASE",
        help="Disable a specific analysis phase.",
    )
    p_config.add_argument(
        "--probe-strategy",
        "--budget",
        dest="probe_strategy",
        metavar="TIER",
        choices=("quick", "standard", "deep", "exhaustive"),
        help=(
            "Planner budget tier (Module 5): quick|standard|deep|exhaustive. "
            "--budget is an alias. standard uses multiprobe-first adaptive "
            "planning; exhaustive approximates the legacy full matrix."
        ),
    )
    p_config.add_argument(
        "--max-requests-per-param",
        type=int,
        metavar="N",
        help=(
            "Hard HTTP request cap per parameter (Module 5). "
            "0 or omit to use the tier default (quick=8, standard=18, "
            "deep=40, exhaustive=80)."
        ),
    )
    p_config.add_argument(
        "--include-auth-artifacts",
        action="store_true",
        help=(
            "Persist opt-in: probe session cookies / Authorization-like "
            "headers (Module 9). Default is skip."
        ),
    )
    p_config.add_argument(
        "--skip-auth-artifacts",
        action="store_true",
        help="Persist default: skip session cookies / Authorization (Module 9).",
    )

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    p_status = sub.add_parser("status", help="Show Input Validation progress summary.")
    add_format_argument(p_status)

    # ------------------------------------------------------------------
    # resume
    # ------------------------------------------------------------------
    p_resume = sub.add_parser(
        "resume",
        help="Continue from unfinished analyses (alias for 'run' with no --ignore-cache).",
    )
    _add_scope_args(p_resume)

    # ------------------------------------------------------------------
    # clear-cache
    # ------------------------------------------------------------------
    p_clear = sub.add_parser(
        "clear-cache",
        help="Delete cached Input Validation results (all, or scoped to host/endpoint/parameter).",
    )
    _add_scope_args(p_clear)
    add_force_argument(p_clear)

    # ------------------------------------------------------------------
    # exclude / include
    # ------------------------------------------------------------------
    p_exclude = sub.add_parser(
        "exclude",
        help="Exclude an endpoint or host from Input Validation.",
    )
    _add_include_exclude_args(p_exclude)

    p_include = sub.add_parser(
        "include",
        help="Remove an Input Validation exclusion.",
    )
    _add_include_exclude_args(p_include)

    # ------------------------------------------------------------------
    # show (parameter | endpoint | host — Module 10 multi-level)
    # ------------------------------------------------------------------
    p_show = sub.add_parser(
        "show",
        help=(
            "Display IV intelligence: parameter profile (default), "
            "or --endpoint / --host multi-level summary (Module 10)."
        ),
    )
    p_show.add_argument(
        "param_id",
        nargs="?",
        default=None,
        help="UUID of the parameter row (from the parameters table) to display.",
    )
    show_scope = p_show.add_mutually_exclusive_group()
    show_scope.add_argument(
        "--endpoint",
        metavar="ENDPOINT_ID",
        help="Show endpoint-level intelligence profile (Module 10).",
    )
    show_scope.add_argument(
        "--host",
        metavar="HOST",
        help="Show application/host-level intelligence profile (Module 10).",
    )
    add_format_argument(p_show)

    # ------------------------------------------------------------------
    # synthesize (Module 3 — offline from existing probes)
    # ------------------------------------------------------------------
    p_synth = sub.add_parser(
        "synthesize",
        help=(
            "Build intelligence profiles from existing iv_probe_results "
            "(zero new HTTP). Scope: project (default), --host, or --param-uuid."
        ),
    )
    synth_scope = p_synth.add_mutually_exclusive_group()
    synth_scope.add_argument(
        "--host",
        metavar="HOST",
        help="Synthesize only parameters observed on this host.",
    )
    synth_scope.add_argument(
        "--param-uuid",
        metavar="PARAM_UUID",
        help="Synthesize a single parameter by deterministic param_uuid.",
    )
    p_synth.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute profiles but do not write iv_param_profiles.",
    )
    add_format_argument(p_synth)

    # ------------------------------------------------------------------
    # reflections (cross-flow / stored reflection raw links — FP validation)
    # ------------------------------------------------------------------
    p_refl = sub.add_parser(
        "reflections",
        help=(
            "List raw cross-flow / stored reflection links "
            "(data-flow prioritization evidence; not confirmed XSS). "
            "Values are redacted by default."
        ),
    )
    p_refl.add_argument(
        "--param-uuid",
        metavar="UUID",
        help="Filter by source parameter UUID (sha256 host|location|name).",
    )
    p_refl.add_argument(
        "--host",
        metavar="HOST",
        help="Filter by canonical host/origin (endpoints.host).",
    )
    p_refl.add_argument(
        "--source-endpoint",
        metavar="ID",
        help="Filter by source endpoint id.",
    )
    p_refl.add_argument(
        "--sink-endpoint",
        metavar="ID",
        help="Filter by sink endpoint id.",
    )
    p_refl.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Max rows to return (default 50).",
    )
    p_refl.add_argument(
        "--include-values",
        action="store_true",
        help=(
            "Include value hash prefix detail only (links never store full secrets; "
            "this flag is reserved for future value_index debug)."
        ),
    )
    p_refl.add_argument(
        "--cross-flow",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,  # design alias; always cross-flow for this command
    )
    add_format_argument(p_refl)

    # candidates (Module 11/12 — prioritization list, not findings)
    # ------------------------------------------------------------------
    p_cands = sub.add_parser(
        "candidates",
        help=(
            "List attack candidates (prioritization only — not confirmed vulns). "
            "Filter by --attack, --min-score, --host, --capability."
        ),
    )
    p_cands.add_argument(
        "--attack",
        metavar="NAME",
        help=(
            "Filter by attack name: xss, sqli, open_redirect, ssrf, hpp, "
            "header_injection, path_traversal, mass_assignment."
        ),
    )
    p_cands.add_argument(
        "--min-score",
        type=int,
        default=0,
        metavar="N",
        help="Minimum candidate score 0–100 (default 0).",
    )
    p_cands.add_argument(
        "--min-confidence",
        type=int,
        default=0,
        metavar="N",
        help="Minimum candidate confidence 0–100 (default 0).",
    )
    p_cands.add_argument(
        "--host",
        metavar="HOST",
        help="Filter to parameters on this host.",
    )
    p_cands.add_argument(
        "--capability",
        metavar="FLAG",
        help=(
            "Require capability flag (e.g. reflective_input, "
            "stored_reflection, html_context)."
        ),
    )
    p_cands.add_argument(
        "--limit",
        type=int,
        default=100,
        metavar="N",
        help="Max rows (default 100).",
    )
    p_cands.add_argument(
        "--recompute",
        action="store_true",
        help="Re-score from profiles in memory (does not persist).",
    )
    add_format_argument(p_cands)

    # ------------------------------------------------------------------
    # export (with subcommands: host, endpoint, parameter, or csv)
    # ------------------------------------------------------------------
    p_export = sub.add_parser(
        "export",
        help="Export Input Validation data as Markdown, JSON, or CSV.",
    )
    export_sub = p_export.add_subparsers(dest="export_target", metavar="<target>")

    p_export_param = export_sub.add_parser(
        "parameter",
        help="Export full IV profile for a parameter UUID (Markdown or JSON).",
    )
    p_export_param.add_argument(
        "param_uuid",
        help="Parameter UUID (from iv_probe_results or parameters table).",
    )
    p_export_param.add_argument(
        "--format",
        choices=("markdown", "json", "md"),
        default="markdown",
        help="Output format (default: markdown). json includes schema_version.",
    )
    p_export_param.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write to file (default: project exports/ directory).",
    )

    p_export_host = export_sub.add_parser(
        "host",
        help="Export IV summary for all parameters on a host (Markdown or JSON).",
    )
    p_export_host.add_argument("host", help="Hostname (e.g. api.example.com).")
    p_export_host.add_argument(
        "--format",
        choices=("markdown", "json", "md"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    p_export_host.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write to file (default: project exports/ directory).",
    )

    p_export_csv = export_sub.add_parser(
        "csv",
        help="Export all IV data as CSV (per-probe rows).",
    )
    p_export_csv.add_argument(
        "--output", "-o", metavar="FILE", help="Output file path (default: stdout).",
    )

    args = parser.parse_args(argv)

    # Dispatch.
    if args.iv_cmd == "run":
        _cmd_run(manager, args, phase_filter=None)
    elif args.iv_cmd in _PHASE_NAMES:
        _cmd_run(manager, args, phase_filter=_PHASE_NAMES[args.iv_cmd])
    elif args.iv_cmd == "config":
        _cmd_config(manager, args)
    elif args.iv_cmd == "status":
        _cmd_status(manager, args)
    elif args.iv_cmd == "resume":
        _cmd_run(manager, args, phase_filter=None)
    elif args.iv_cmd == "clear-cache":
        _cmd_clear_cache(manager, args)
    elif args.iv_cmd == "exclude":
        _cmd_exclude(manager, args, adding=True)
    elif args.iv_cmd == "include":
        _cmd_exclude(manager, args, adding=False)
    elif args.iv_cmd == "show":
        _cmd_show(manager, args)
    elif args.iv_cmd == "synthesize":
        _cmd_synthesize(manager, args)
    elif args.iv_cmd == "candidates":
        _cmd_candidates(manager, args)
    elif args.iv_cmd == "reflections":
        _cmd_reflections(manager, args)
    elif args.iv_cmd == "export":
        if not hasattr(args, "export_target") or args.export_target is None:
            p_export.print_help()
            sys.exit(1)
        elif args.export_target == "parameter":
            _cmd_export_parameter(manager, args)
        elif args.export_target == "host":
            _cmd_export_host(manager, args)
        elif args.export_target == "csv":
            _cmd_export_csv(manager, args)
        else:
            p_export.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    """Add --host, --endpoint, --parameter scope arguments to a subparser."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--host",
        metavar="HOST",
        help="Scope analysis to a single host (e.g. api.example.com).",
    )
    group.add_argument(
        "--endpoint",
        metavar="ENDPOINT_ID",
        help="Scope analysis to a single endpoint UUID.",
    )
    group.add_argument(
        "--parameter",
        metavar="PARAM",
        help="Scope analysis to a single parameter name.",
    )


def _add_include_exclude_args(parser: argparse.ArgumentParser) -> None:
    """Add target type (endpoint/host) and value arguments."""
    parser.add_argument(
        "target_type",
        choices=["endpoint", "host"],
        help="Target type to exclude/include.",
    )
    parser.add_argument("target_value", help="Endpoint UUID or host string.")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _cmd_run(
    manager: ProjectManager,
    args: argparse.Namespace,
    phase_filter: str | None,
) -> None:
    """
    Purpose:
        Schedule Input Validation jobs.
        Respects --host, --endpoint, --parameter scope arguments.
        Phase-level commands pass a phase_filter; 'run' passes None.

        Before scheduling, verifies that every role required by the selected
        endpoints has a complete, valid, and healthy authentication
        configuration.  If any role fails the check, the scan does not start.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    config = load_config(db_path)
    if not config.enabled:
        cli_error(
            "Input Validation is disabled. "
            "Enable it with: talos input-validation config --enable"
        )

    # Module 12: run --budget TIER persists probe_strategy then schedules.
    budget = getattr(args, "budget", None)
    if budget:
        config.probe_strategy = str(budget).lower()
        save_config(db_path, config)
        print(f"Budget tier set to '{config.probe_strategy}'.")

    # Phase shortcuts accept --ignore-cache (primary) or deprecated --force
    # alias (both dest=ignore_cache). run uses --ignore-cache only. clear-cache
    # keeps --force for confirmation bypass (CLI-015 / CLI-019).
    ignore_cache = bool(getattr(args, "ignore_cache", False))
    # Module 9: one-shot auth-artifact probe override (does not persist).
    include_auth: bool | None = None
    # run subcommand only; phase shortcuts omit the flag → None (use config).
    if getattr(args, "include_auth_artifacts", False):
        include_auth = True

    # Determine scope.
    host = getattr(args, "host", None)
    endpoint_id = getattr(args, "endpoint", None)
    param_name = getattr(args, "parameter", None)

    # Auth pre-check: verify every role that would be used by this scan.
    print("Checking authentication readiness ...")
    auth_errors = iv_engine.verify_auth_for_iv_scan(
        db_path, project_id, host=host, endpoint_id=endpoint_id, param_name=param_name
    )
    if auth_errors:
        print("Authentication pre-check failed. Fix the following before starting:", file=sys.stderr)
        for err in auth_errors:
            print(f"  - {err}", file=sys.stderr)
        cli_error(
            "\nEnsure every required role has:\n"
            "  1. Auth artifacts:   talos auth set --cookie <name>\n"
            "  2. Provider:         talos auth-config set-provider <role> manual|auto\n"
            "  3. Session/flows:    talos auth-config set-session <role>  (manual)\n"
            "                       talos auth-config add-flow <role> <flow_id>  (auto)\n"
            "  4. Validation:       talos auth-config add-control-flow <role> <flow_id>\n"
            "  5. Validate:         talos auth-config validate <role>\n"
            "  (<role> = role name or UUID; see talos role list)"
        )

    if host:
        enqueued = iv_engine.schedule_host(
            db_path, project_id, host,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
            include_auth_artifacts=include_auth,
        )
        scope_desc = f"host '{host}'"
    elif endpoint_id:
        enqueued = iv_engine.schedule_endpoint(
            db_path, project_id, endpoint_id,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
            include_auth_artifacts=include_auth,
        )
        scope_desc = f"endpoint {endpoint_id}"
    elif param_name:
        enqueued = iv_engine.schedule_parameter(
            db_path, project_id, param_name,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
            include_auth_artifacts=include_auth,
        )
        scope_desc = f"parameter '{param_name}'"
    else:
        enqueued = iv_engine.schedule_project(
            db_path, project_id,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
            include_auth_artifacts=include_auth,
        )
        scope_desc = "entire project"

    phase_desc = f" [{phase_filter}]" if phase_filter else ""
    if enqueued == 0:
        print(
            f"No new jobs enqueued for {scope_desc}{phase_desc}. "
            "All analyses may already be complete. "
            "Use --ignore-cache to re-run.",
        )
    else:
        print(
            f"Enqueued {enqueued} Input Validation job(s) for {scope_desc}{phase_desc}. "
            "Jobs will run when the scheduler is active."
        )


def _cmd_config(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Show or update the IV configuration."""
    project = _require_active(manager)
    db_path = project.db_path
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)

    config = load_config(db_path)
    changed = False

    if args.enable and args.disable:
        cli_usage_error("Cannot use --enable and --disable together.")

    if args.enable:
        config.enabled = True
        changed = True
    if args.disable:
        config.enabled = False
        changed = True
    if getattr(args, "include_auth_artifacts", False) and getattr(
        args, "skip_auth_artifacts", False
    ):
        cli_usage_error(
            "Cannot use --include-auth-artifacts and --skip-auth-artifacts together."
        )
    if getattr(args, "include_auth_artifacts", False):
        config.include_auth_artifacts = True
        changed = True
    if getattr(args, "skip_auth_artifacts", False):
        config.include_auth_artifacts = False
        changed = True
    if args.workers is not None:
        if args.workers < 1:
            cli_usage_error("--workers must be >= 1.")
        config.workers = args.workers
        changed = True
    if args.analysis_on:
        phase = args.analysis_on.lower()
        if phase not in _PHASE_NAMES:
            cli_usage_error(f"Unknown phase '{phase}'. Valid: {', '.join(_PHASE_NAMES)}")
        setattr(config.analyses, phase, True)
        changed = True
    if args.analysis_off:
        phase = args.analysis_off.lower()
        if phase not in _PHASE_NAMES:
            cli_usage_error(f"Unknown phase '{phase}'. Valid: {', '.join(_PHASE_NAMES)}")
        setattr(config.analyses, phase, False)
        changed = True
    if getattr(args, "probe_strategy", None):
        config.probe_strategy = args.probe_strategy.lower()
        changed = True
    if getattr(args, "max_requests_per_param", None) is not None:
        n = int(args.max_requests_per_param)
        if n < 0:
            cli_usage_error("--max-requests-per-param must be >= 0.")
        config.max_requests_per_param = n
        changed = True

    if changed:
        save_config(db_path, config)
        print("Configuration updated.")

    print(format_config(config))


def _cmd_status(manager: ProjectManager, args: argparse.Namespace | None = None) -> None:
    """
    Purpose:
        Show Input Validation progress: cache counts, budget, requests_used,
        pending plan actions, and Module 12 confidence / candidate summary.
    """
    project = _require_active(manager)
    status = iv_db.get_iv_status(project.db_path)
    if wants_json(args):
        cli_json(status)
        return
    plan_actions = status.get("pending_plan_actions") or {}
    if plan_actions:
        plan_str = ", ".join(f"{k}={v}" for k, v in sorted(plan_actions.items()))
    else:
        plan_str = "(none)"
    override = int(status.get("max_requests_override") or 0)
    cap_note = f" (override {override})" if override > 0 else ""
    conf = status.get("confidence") or {}
    buckets = conf.get("buckets") or {}
    avg_refl = conf.get("avg_reflection_confidence")
    avg_type = conf.get("avg_type_confidence")
    avg_len = conf.get("avg_length_confidence")

    def _avg_label(v) -> str:
        return "—" if v is None else str(v)

    print(
        f"Input Validation Status\n"
        f"  Parameters       : {status['total_params']}\n"
        f"  Completed        : {status['completed']}\n"
        f"  Running          : {status['running']}\n"
        f"  Queued           : {status['queued']}\n"
        f"  Failed           : {status['failed']}\n"
        f"  Skipped          : {status.get('skipped', 0)} "
        f"(auth artifacts / hop-by-hop; see phase=surface)\n"
        f"  Budget tier      : {status.get('budget_tier', 'standard')}\n"
        f"  Max req/param    : {status.get('max_requests_per_param', '—')}{cap_note}\n"
        f"  Requests used    : {status.get('requests_used', 0)}\n"
        f"  Params probed    : {status.get('params_probed', 0)}\n"
        f"  Profiles         : {status.get('profiles', 0)} param / "
        f"{status.get('endpoint_profiles', 0)} endpoint / "
        f"{status.get('app_profiles', 0)} app\n"
        f"  With capabilities: {conf.get('profiles_with_capabilities', 0)}\n"
        f"  With candidates  : {conf.get('profiles_with_candidates', 0)} "
        f"({conf.get('candidates_total', 0)} total; "
        f"{conf.get('candidates_score_ge_60', 0)} score≥60)\n"
        f"  Confidence avg   : reflection={_avg_label(avg_refl)}  "
        f"type={_avg_label(avg_type)}  length={_avg_label(avg_len)}\n"
        f"  Confidence buckets: trust≥90={buckets.get('trust', 0)}  "
        f"verify 60–89={buckets.get('verify', 0)}  "
        f"reprobe<60={buckets.get('reprobe', 0)}  "
        f"unknown={buckets.get('unknown', 0)}\n"
        f"  Pending plan     : {status.get('pending_plan_params', 0)} param(s)\n"
        f"  Plan actions     : {plan_str}\n"
        f"\n"
        f"  Note: candidate scores are prioritization only, not confirmed vulns.\n"
    )


def _cmd_clear_cache(
    manager: ProjectManager,
    args: argparse.Namespace,
) -> None:
    """
    Purpose:
        Delete IV cache data.  Scope is controlled by --host, --endpoint,
        or --parameter; without any flag the entire cache is cleared.
        Confirms interactively unless --force; non-interactive requires --force.
    """
    project = _require_active(manager)
    db_path = project.db_path

    host = getattr(args, "host", None)
    endpoint_id = getattr(args, "endpoint", None)
    param_name = getattr(args, "parameter", None)

    if host:
        scope = f"host '{host}'"
    elif endpoint_id:
        scope = f"endpoint {endpoint_id}"
    elif param_name:
        scope = f"parameter '{param_name}'"
    else:
        scope = "entire project"

    confirm_or_exit(
        f"Clear IV cache for {scope}?",
        force=bool(getattr(args, "force", False)),
    )

    if host:
        param_n = iv_db.clear_param_cache(db_path, host=host)
        refl_n = iv_db.clear_reflection_cache(db_path, host=host)
    elif endpoint_id:
        param_n = iv_db.clear_param_cache_for_endpoint(db_path, endpoint_id)
        refl_n = iv_db.clear_reflection_cache(db_path, endpoint_id=endpoint_id)
    elif param_name:
        param_n = iv_db.clear_param_cache(db_path, param_name=param_name)
        refl_n = iv_db.clear_reflection_cache(db_path, param_name=param_name)
    else:
        param_n, refl_n = iv_db.clear_all_iv_cache(db_path)

    print(
        f"Cache cleared for {scope}: "
        f"{param_n} parameter analysis entries, "
        f"{refl_n} reflection entries deleted."
    )


def _cmd_exclude(
    manager: ProjectManager,
    args: argparse.Namespace,
    adding: bool,
) -> None:
    """Add or remove an exclusion from the IV config."""
    project = _require_active(manager)
    db_path = project.db_path
    config = load_config(db_path)

    action = "exclude" if adding else "include"
    target_type = args.target_type
    target_value = args.target_value.strip()

    if target_type == "host":
        if adding:
            if target_value not in config.excluded_hosts:
                config.excluded_hosts.append(target_value)
                save_config(db_path, config)
                print(f"Host '{target_value}' excluded from Input Validation.")
            else:
                print(f"Host '{target_value}' is already excluded.")
        else:
            if target_value in config.excluded_hosts:
                config.excluded_hosts.remove(target_value)
                save_config(db_path, config)
                print(f"Host '{target_value}' inclusion restored.")
            else:
                print(f"Host '{target_value}' was not excluded.")

    elif target_type == "endpoint":
        if adding:
            if target_value not in config.excluded_endpoints:
                config.excluded_endpoints.append(target_value)
                save_config(db_path, config)
                print(f"Endpoint {target_value} excluded from Input Validation.")
            else:
                print(f"Endpoint {target_value} is already excluded.")
        else:
            if target_value in config.excluded_endpoints:
                config.excluded_endpoints.remove(target_value)
                save_config(db_path, config)
                print(f"Endpoint {target_value} inclusion restored.")
            else:
                print(f"Endpoint {target_value} was not excluded.")


def _cmd_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Display IV intelligence for a parameter (default), endpoint, or host.

        Parameter mode: passive + active profile, synthesized intelligence,
        per-probe results, analysis cache summaries.

        Module 10: ``--endpoint`` / ``--host`` show aggregated multi-level
        profiles (tested defaults, rejected classes, parser, capabilities).
        Module 11: parameter show includes attack candidates (prioritization
        only — not confirmed vulnerabilities).
    """
    from talos.input_validation.learning import (
        format_app_intel_lines,
        format_endpoint_intel_lines,
        load_inheritance_priors,
    )
    from talos.input_validation.synthesize import format_profile_summary_lines

    project = _require_active(manager)
    db_path = project.db_path

    endpoint_id = getattr(args, "endpoint", None)
    host_key = getattr(args, "host", None)

    # ── Endpoint intelligence (Module 10) ─────────────────────────────────
    if endpoint_id:
        ep = iv_db.get_endpoint_profile(db_path, endpoint_id)
        meta = iv_db.get_endpoint_meta(db_path, endpoint_id)
        if wants_json(args):
            cli_json({
                "level": "endpoint",
                "endpoint_id": endpoint_id,
                "meta": meta,
                "profile": ep,
            })
            return
        print(f"\nEndpoint Intelligence: {endpoint_id}")
        print("=" * 70)
        if meta:
            print(
                f"  Host   : {meta.get('host')}\n"
                f"  Method : {meta.get('method')}\n"
                f"  Path   : {meta.get('path')}"
            )
            print()
        for line in format_endpoint_intel_lines(ep):
            print(f"  {line}")
        if not ep:
            print(
                "  (none — run input-validation synthesize after probing "
                "parameters on this endpoint)"
            )
        print()
        return

    # ── Application / host intelligence (Module 10) ───────────────────────
    if host_key:
        app = iv_db.get_app_profile(db_path, host_key)
        endpoints = iv_db.list_endpoint_profiles(db_path, host=host_key, limit=50)
        if wants_json(args):
            cli_json({
                "level": "application",
                "host": host_key,
                "profile": app,
                "endpoint_profiles": endpoints,
            })
            return
        print(f"\nApplication Intelligence: {host_key}")
        print("=" * 70)
        for line in format_app_intel_lines(app):
            print(f"  {line}")
        if endpoints:
            print(f"  Endpoint profiles: {len(endpoints)}")
            for ep in endpoints[:15]:
                print(
                    f"    - {ep.get('endpoint_id', '?')[:12]}…  "
                    f"{ep.get('method') or ''} {ep.get('path') or ''}"
                )
        if not app:
            print(
                "  (none — run input-validation synthesize after probing "
                "parameters on this host)"
            )
        print()
        return

    # ── Parameter mode (legacy + inheritance summary) ─────────────────────
    if not args.param_id:
        cli_usage_error(
            "show requires a parameter UUID, or --endpoint / --host "
            "(Module 10 multi-level)."
        )

    profile = iv_db.get_parameter_profile(db_path, args.param_id)

    if profile is None:
        cli_error(f"No parameter found with UUID '{args.param_id}'.")

    param_uuid = profile.get("param_uuid", "")
    probe_records = iv_db.get_probe_results_for_param(db_path, param_uuid)
    intel = profile.get("intelligence_profile")

    # Resolve endpoint for inheritance display.
    ep_id = ""
    for rec in probe_records:
        if rec.get("endpoint_id"):
            ep_id = str(rec["endpoint_id"])
            break
    if not ep_id and profile.get("endpoint_id"):
        ep_id = str(profile["endpoint_id"])

    priors = load_inheritance_priors(
        db_path,
        host=str(profile.get("host") or ""),
        endpoint_id=ep_id,
        local_profile=intel,
        budget_tier="standard",
    )

    # Module 11: consumer-facing candidates (recompute in-memory if missing).
    from talos.input_validation.candidates import get_param_intelligence

    consumer = get_param_intelligence(db_path, args.param_id, recompute=False)
    if consumer and intel and (
        not intel.get("candidates") or not intel.get("capabilities")
    ):
        # Fill candidates for display without requiring re-synthesize.
        consumer = get_param_intelligence(db_path, args.param_id, recompute=True)
        if consumer and consumer.get("profile"):
            intel = consumer["profile"]
            profile["intelligence_profile"] = intel

    if wants_json(args):
        cli_json({
            "parameter": profile,
            "probes": probe_records,
            "intelligence_profile": intel,
            "capabilities": (consumer or {}).get("capabilities") if consumer else (
                (intel or {}).get("capabilities") if intel else []
            ),
            "candidates": (consumer or {}).get("candidates") if consumer else (
                (intel or {}).get("candidates") if intel else []
            ),
            "inheritance": priors.to_inferred_block() if priors.is_active() else None,
            "endpoint_profile": (
                iv_db.get_endpoint_profile(db_path, ep_id) if ep_id else None
            ),
            "app_profile": iv_db.get_app_profile(
                db_path, str(profile.get("host") or "")
            ),
        })
        return

    # Header
    print(f"\nParameter: {profile['name']}  [{profile['id']}]")
    print("=" * 70)
    print(
        f"  Host       : {profile['host']}\n"
        f"  Endpoint   : {profile['method']} {profile['path']}\n"
        f"  Location   : {profile['location']}\n"
        f"  Type       : {profile['param_type']} / {profile['semantic_type']}\n"
        f"  Seen       : {profile['seen_count']} flows\n"
        f"  Roles      : {', '.join(profile['appears_in_roles']) or '(none)'}\n"
        f"  Modules    : {', '.join(profile['appears_in_modules']) or '(none)'}\n"
        f"  Same-req   : {'Yes' if profile['is_reflected'] else 'No'} "
        f"({profile['reflection_count']}x)  [same-flow reflection]"
    )
    if profile["reflection_locations"]:
        print(
            f"  Refl. loc  : {', '.join(profile['reflection_locations'])}\n"
            f"  Refl. enc  : {', '.join(profile['reflection_encoding'])}"
        )
    cf_yes = bool(profile.get("cross_flow_reflected"))
    cf_count = int(profile.get("cross_flow_reflection_count") or 0)
    print(
        f"  Cross-flow : {'Yes' if cf_yes else 'No'} "
        f"({cf_count}x)  [stored / other-page reflection]"
    )
    cf_sinks = profile.get("cross_flow_sink_endpoints") or []
    if isinstance(cf_sinks, list) and cf_sinks:
        sink_bits: list[str] = []
        for s in cf_sinks[:6]:
            if isinstance(s, dict):
                sink_bits.append(
                    f"{s.get('method', '')} {s.get('path', '')}".strip()
                    or str(s.get("endpoint_id") or "")[:12]
                )
            else:
                sink_bits.append(str(s)[:40])
        print(f"  CF sinks   : {', '.join(sink_bits)}")
        if len(cf_sinks) > 6:
            print(f"               … +{len(cf_sinks) - 6} more")
    print(
        f"  Examples   : {', '.join(str(e) for e in profile['examples']) or '(none)'}"
    )
    print()

    # Synthesized intelligence profile (Module 3+11) — preferred summary view.
    if intel:
        print("  Intelligence Profile:")
        for line in format_profile_summary_lines(intel):
            print(f"    {line}")
        print()
        # Surface stored sinks from live consumer candidates when present.
        consumer_cands = (consumer or {}).get("candidates") if consumer else None
        if not consumer_cands and intel:
            consumer_cands = intel.get("candidates")
        stored_any = False
        for cand in consumer_cands or []:
            if not isinstance(cand, dict):
                continue
            stored = cand.get("stored_reflection")
            if isinstance(stored, dict) and (stored.get("sinks") or stored.get("link_count")):
                stored_any = True
                break
        if stored_any or cf_yes:
            print(
                "  Note: stored/cross-page reflection is data-flow "
                "prioritization evidence — not confirmed XSS."
            )
            print()
    elif probe_records:
        print(
            "  Intelligence Profile: (none — run "
            "'talos input-validation synthesize')"
        )
        print()
    elif cf_yes:
        print(
            "  Cross-flow links present on parameters table, but no "
            "iv_param_profiles document yet.\n"
            "  XSS candidates from stored reflection require synthesize "
            "(or an existing profile + recompute).\n"
            "  Raw links: talos input-validation reflections "
            f"--param-uuid {param_uuid or profile.get('param_uuid') or ''}"
        )
        print()

    # Module 10: inheritance priors (inferred only — not local observed).
    if priors.is_active():
        print("  Inheritance (endpoint/app priors, confidence capped):")
        block = priors.to_inferred_block()
        print(
            f"    sources={','.join(block.get('source_levels') or []) or '(none)'}  "
            f"~{block.get('reduced_request_estimate', 0)} req saved (est.)"
        )
        if block.get("suppress_control_probes"):
            print("    suppress_control_probes=yes (host/endpoint rejects control/null)")
        if block.get("suppress_parser_probes"):
            print("    suppress_parser_probes=yes (parent parser known)")
        tested = block.get("tested") or {}
        if tested:
            keys = sorted(tested.keys())[:15]
            print(f"    inherited tested: {', '.join(keys)}")
        rej = block.get("rejected_classes") or []
        if rej:
            print(f"    inherited rejected classes: {', '.join(rej[:15])}")
        print()

    # Per-probe results from iv_probe_results (the canonical scan evidence).
    if probe_records:
        print("  Input Validation Probes:")
        print(
            f"  {'#':<4} {'Analysis':<16} {'Payload':<30} {'Status':<12} "
            f"{'HTTP':<6} {'Flow ID'}"
        )
        print("  " + "-" * 90)
        for i, rec in enumerate(probe_records, 1):
            analysis = rec.get("analysis", "")
            payload = rec.get("payload")
            payload_display = repr(payload) if payload is not None else "(none)"
            if len(payload_display) > 28:
                payload_display = payload_display[:25] + "..."
            status = rec.get("status", "")
            # status_code comes from flows JOIN (get_probe_results_for_param)
            http_status = rec.get("status_code")
            http_str = str(http_status) if http_status is not None else "—"
            flow_id = rec.get("flow_id") or ""
            flow_short = flow_id[:8] + "..." if flow_id else "—"
            print(
                f"  {i:<4} {analysis:<16} {payload_display:<30} "
                f"{status:<12} {http_str:<6} {flow_short}"
            )
    else:
        print("  Input Validation: not yet run (no probe results found)")

    # Analysis summaries (transformations, reflection) from iv_param_cache / iv_reflection_cache.
    if profile["iv_phases"]:
        print()
        print("  Analysis Summaries:")
        for phase, data in sorted(profile["iv_phases"].items()):
            status_label = data.get("status", "not_started")
            if status_label == "completed" and data.get("result"):
                print(f"  [{phase}]  {status_label}")
                for line in _format_phase_result(phase, data["result"]):
                    print(f"      {line}")

    if profile["iv_reflection"] is not None:
        refl_data = profile["iv_reflection"]
        refl_status = refl_data.get("status", "not_started")
        if refl_status == "completed" and refl_data.get("result"):
            print(f"  [reflection]  {refl_status}")
            for line in _format_phase_result("reflection", refl_data["result"]):
                print(f"      {line}")

    print()


def _cmd_reflections(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        List raw cross-flow reflection links for operator FP validation.
        Values are never stored on the link table; reasons use param/endpoint
        identity only. Not confirmed XSS — data-flow prioritization evidence.
    Side effects: Read-only DB.
    """
    from talos.projects.value_reflection import (
        format_cross_flow_reason,
        list_cross_flow_reflections,
    )

    project = _require_active(manager)
    db_path = project.db_path
    limit = int(getattr(args, "limit", 50) or 50)
    limit = max(1, min(limit, 10_000))

    rows = list_cross_flow_reflections(
        db_path,
        param_uuid=(getattr(args, "param_uuid", None) or None),
        host=(getattr(args, "host", None) or None),
        source_endpoint_id=(getattr(args, "source_endpoint", None) or None),
        sink_endpoint_id=(getattr(args, "sink_endpoint", None) or None),
        limit=limit,
    )

    # Attach operator-facing reason strings (no secret values).
    for row in rows:
        row["reason"] = format_cross_flow_reason(row)
        # Redact hash to prefix by default for display hygiene.
        vh = row.get("value_hash") or ""
        if vh and not getattr(args, "include_values", False):
            row["value_hash_prefix"] = vh[:8]
            row.pop("value_hash", None)
        else:
            row["value_hash_prefix"] = (vh[:8] if vh else "")

    if wants_json(args):
        cli_json({
            "kind": "cross_flow_reflections",
            "count": len(rows),
            "disclaimer": (
                "Data-flow prioritization evidence only — not confirmed XSS. "
                "Full secret values are not stored on reflection links."
            ),
            "reflections": rows,
        })
        return

    print(
        "Cross-flow reflections "
        "(data-flow prioritization evidence — not confirmed XSS)"
    )
    print(f"Count: {len(rows)}")
    if not rows:
        print(
            "No cross-flow links yet. Enable with:\n"
            "  talos config set parameter_intel.cross_flow.enabled true --project\n"
            "then capture traffic (or IV multiprobe) and re-check."
        )
        return

    print()
    for i, row in enumerate(rows, 1):
        reason = row.get("reason") or format_cross_flow_reason(row)
        conf = row.get("confidence", "")
        mode = row.get("detection_mode") or "passive"
        vlen = row.get("value_len") or 0
        vpref = row.get("value_hash_prefix") or (str(row.get("value_hash") or "")[:8])
        print(f"{i}. {reason}")
        print(
            f"   conf={conf}  mode={mode}  value_len={vlen}  "
            f"hash={vpref}…  obs={row.get('observation_count', 1)}"
        )
        print(
            f"   source_param_uuid={row.get('source_param_uuid', '')}  "
            f"sink_flow={str(row.get('sink_flow_id') or '')[:8]}…"
        )
    print()
    print(
        "Tip: filter with --param-uuid / --host / --source-endpoint / --sink-endpoint"
    )


def _cmd_candidates(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        List attack candidates across the project (Module 11/12).
        Scores are prioritization only — not confirmed vulnerabilities.
    Side effects: Read-only DB; optional in-memory recompute.
    """
    from talos.input_validation.candidates import (
        KNOWN_ATTACKS,
        list_candidates,
    )

    project = _require_active(manager)
    db_path = project.db_path

    attack = (getattr(args, "attack", None) or "").strip().lower() or None
    if attack and attack not in KNOWN_ATTACKS:
        cli_usage_error(
            f"Unknown attack '{attack}'. Valid: {', '.join(sorted(KNOWN_ATTACKS))}"
        )

    min_score = int(getattr(args, "min_score", 0) or 0)
    min_conf = int(getattr(args, "min_confidence", 0) or 0)
    if min_score < 0 or min_score > 100:
        cli_usage_error("--min-score must be 0–100.")
    if min_conf < 0 or min_conf > 100:
        cli_usage_error("--min-confidence must be 0–100.")

    rows = list_candidates(
        db_path,
        attack=attack,
        min_score=min_score,
        min_confidence=min_conf,
        host=getattr(args, "host", None) or None,
        capability=getattr(args, "capability", None) or None,
        limit=max(1, int(getattr(args, "limit", 100) or 100)),
        recompute=bool(getattr(args, "recompute", False)),
    )

    if wants_json(args):
        cli_json({
            "candidates": rows,
            "count": len(rows),
            "filters": {
                "attack": attack,
                "min_score": min_score,
                "min_confidence": min_conf,
                "host": getattr(args, "host", None),
                "capability": getattr(args, "capability", None),
            },
            "note": (
                "Candidate scores are prioritization only, not confirmed "
                "vulnerabilities. Stored/cross-page reflection is data-flow "
                "evidence, not XSS confirmation."
            ),
        })
        return

    print(
        "Attack candidates (prioritization only — not confirmed vulnerabilities)"
    )
    print(
        "Stored/cross-page reflection = data-flow evidence, not XSS confirmation."
    )
    if not rows:
        print("  (none — run synthesize after probing, or lower --min-score)")
        print(
            "  Tip: filter stored surfaces with "
            "--capability stored_reflection"
        )
        print()
        return

    print(
        f"  {'Host':<24} {'Name':<16} {'Loc':<8} "
        f"{'Attack':<16} {'Score':>5} {'Conf':>5}"
    )
    print("  " + "-" * 90)
    for r in rows:
        host = str(r.get("host") or "")[:22]
        name = str(r.get("name") or "")[:14]
        loc = str(r.get("location") or "")[:6]
        atk = str(r.get("attack") or "")[:14]
        print(
            f"  {host:<24} {name:<16} {loc:<8} "
            f"{atk:<16} {int(r.get('score') or 0):>5} "
            f"{int(r.get('confidence') or 0):>5}"
        )
        modes = r.get("reflection_modes") or []
        if modes:
            print(f"      modes: {', '.join(str(m) for m in modes)}")
        reasons = r.get("reasons") or []
        if reasons:
            # Indent first reason for operators scanning the table.
            print(f"      → {reasons[0]}")
        stored = r.get("stored_reflection")
        if isinstance(stored, dict):
            sinks = stored.get("sinks") or []
            if isinstance(sinks, list):
                for sink in sinks[:2]:
                    if not isinstance(sink, dict):
                        continue
                    rsn = sink.get("reason")
                    if rsn:
                        print(f"      stored: {rsn}")
                    else:
                        method = sink.get("method") or ""
                        path = sink.get("path") or ""
                        print(f"      stored sink: {method} {path}".strip())
    print()
    print(
        f"  {len(rows)} candidate row(s). Use --format json for full reasons. "
        "Filter: --capability stored_reflection"
    )
    print()


def _cmd_synthesize(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Offline synthesis of intelligence profiles from existing probes.
        Zero new HTTP. Scope: whole project, --host, or --param-uuid.
    Side effects:
        Writes iv_param_profiles unless --dry-run.
    """
    from talos.cli_output import cli_info, cli_success
    from talos.input_validation.synthesize import synthesize_many

    project = _require_active(manager)
    db_path = project.db_path
    persist = not bool(getattr(args, "dry_run", False))
    host = getattr(args, "host", None)
    param_uuid = getattr(args, "param_uuid", None)

    summary = synthesize_many(
        db_path,
        host=host,
        param_uuid=param_uuid,
        persist=persist,
        bump_version=True,
    )

    if wants_json(args):
        cli_json({
            "persist": persist,
            "host": host,
            "param_uuid": param_uuid,
            **summary,
        })
        return

    scope = (
        f"param_uuid={param_uuid}"
        if param_uuid
        else (f"host={host}" if host else "project")
    )
    mode = "dry-run" if not persist else "written"
    cli_info(
        f"Synthesize ({mode}, scope={scope}): "
        f"requested={summary['requested']}  "
        f"ok={summary['synthesized']}  "
        f"partial={summary['partial']}  "
        f"empty={summary['empty']}  "
        f"errors={len(summary['errors'])}"
    )
    if summary["errors"]:
        for err in summary["errors"][:10]:
            print(f"  ! {err.get('param_uuid', '?')}: {err.get('error')}")
    if persist and summary["synthesized"]:
        cli_success(
            f"Stored {summary['synthesized']} parameter profile(s) in iv_param_profiles."
        )
    elif not persist:
        cli_info("Dry-run only — no profiles written.")
    elif summary["requested"] == 0:
        cli_info("No probe rows found to synthesize.")


def _format_phase_result(phase: str, result: dict) -> list[str]:
    """
    Purpose:
        Format a phase result dict into a list of human-readable detail lines
        to print under the phase status in _cmd_show.
    Input:
        phase  — phase name string (e.g. 'baseline', 'characters').
        result — dict loaded from iv_param_cache.result JSON.
    Output:
        List of strings (each becomes one indented detail line).
    """
    lines: list[str] = []
    if not result:
        return lines

    error = result.get("error")
    if error:
        lines.append(f"! Error: {error}")
        return lines

    phase_short = phase.replace("iv_", "")

    if phase_short == "baseline":
        sc = result.get("status_code", "?")
        bl = result.get("body_length", "?")
        ct = result.get("content_type", "")
        redir = result.get("redirect", "")
        lines.append(f"Status: {sc}  Body: {bl} bytes  Content-Type: {ct or '(none)'}")
        if redir:
            lines.append(f"Redirect: {redir}")

    elif phase_short == "identifier":
        probe = result.get("identifier", "")
        reflected = result.get("reflected", False)
        loc = result.get("reflection_location", "")
        sc = result.get("status_code", "?")
        lines.append(f"Probe: {probe}")
        if reflected:
            lines.append(f"Reflected: YES  Location: {loc}  Status: {sc}")
        else:
            lines.append(f"Reflected: NO  Status: {sc}")

    elif phase_short == "characters":
        chars: dict = result.get("characters", {})
        if chars:
            by_outcome: dict[str, list[str]] = {}
            for ch, outcome in chars.items():
                by_outcome.setdefault(outcome, []).append(repr(ch) if ch == " " else ch)
            for outcome, char_list in sorted(by_outcome.items()):
                label = outcome.replace("_", " ").title()
                lines.append(f"{label}: {' '.join(char_list)}")

    elif phase_short == "length":
        max_acc = result.get("observed_max_accepted", 0)
        lengths: dict = result.get("lengths", {})
        lines.append(f"Max accepted: {max_acc} bytes")
        if lengths:
            summary = "  ".join(f"{n}={v}" for n, v in sorted(lengths.items(), key=lambda x: int(x[0])))
            lines.append(f"Results: {summary}")

    elif phase_short == "types":
        types: dict = result.get("types", {})
        if types:
            by_outcome: dict[str, list[str]] = {}
            for t, outcome in types.items():
                by_outcome.setdefault(outcome, []).append(t)
            for outcome, type_list in sorted(by_outcome.items()):
                label = outcome.replace("_", " ").title()
                lines.append(f"{label}: {', '.join(type_list)}")

    elif phase_short == "transformations":
        transforms = result.get("transformations", [])
        probe = result.get("probe", "")
        reflected_form = result.get("reflected_form", "")
        sc = result.get("status_code", "?")
        if transforms:
            lines.append(f"Detected transforms: {', '.join(transforms)}")
        else:
            lines.append("No transforms detected")
        if reflected_form:
            lines.append(f"Reflected as: {repr(reflected_form)}")
        else:
            lines.append("Not reflected (transformation analysis inconclusive)")
        lines.append(f"Status: {sc}")

    elif phase_short == "reflection":
        reflected = result.get("reflected", False)
        if reflected:
            enc = result.get("encoding", "")
            loc = result.get("reflection_location", "")
            count = result.get("reflection_count", 0)
            snippet = result.get("context_snippet", "")
            lines.append(f"Reflected: YES  Encoding: {enc}  Location: {loc}  Count: {count}")
            if snippet:
                lines.append(f"Snippet: {snippet!r}")
        else:
            sc = result.get("status_code", "?")
            lines.append(f"Reflected: NO  Status: {sc}")

    elif phase_short == "validation":
        probes: dict = result.get("probes", {})
        if probes:
            for probe_name, pdata in probes.items():
                sc = pdata.get("status_code", "?")
                et = pdata.get("error_type", "?")
                perr = pdata.get("error")
                suffix = f"  (net error: {perr})" if perr else ""
                lines.append(f"{probe_name:<18} {et} (HTTP {sc}){suffix}")

    return lines


def _cmd_export_csv(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Export per-probe IV data as CSV.  One row per HTTP request sent.
        Each row contains the exact payload, HTTP status code, flow_id, and
        timing — not summaries.
    """
    project = _require_active(manager)
    db_path = project.db_path

    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        param_rows = conn.execute(
            """
            SELECT DISTINCT
                p.id        AS param_id,
                p.name      AS param_name,
                e.host,
                e.id        AS endpoint_id,
                e.method,
                e.normalized_path,
                p.location,
                p.param_type,
                p.semantic_type,
                p.seen_count,
                p.is_reflected,
                p.reflection_count,
                p.example_values
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.project_id = ?
            ORDER BY e.host, p.name, p.location
            """,
            (project.id,),
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "param_uuid", "param_id", "param_name", "host",
        "endpoint_id", "endpoint_method", "endpoint_path",
        "location", "param_type", "semantic_type",
        "seen_count", "is_reflected", "reflection_count", "example_values",
        "analysis", "payload", "payload_class", "payload_index",
        "probe_status", "flow_id", "http_status", "content_type",
        "body_length", "error", "created_at", "completed_at",
    ])

    from talos.input_validation.db import make_param_uuid

    for pr in param_rows:
        host = pr["host"]
        location = pr["location"]
        name = pr["param_name"]
        p_uuid = make_param_uuid(host, location, name)

        probe_records = iv_db.get_probe_results_for_param(db_path, p_uuid)

        if not probe_records:
            writer.writerow([
                p_uuid, pr["param_id"], name, host,
                pr["endpoint_id"], pr["method"], pr["normalized_path"],
                location, pr["param_type"], pr["semantic_type"],
                pr["seen_count"], pr["is_reflected"], pr["reflection_count"],
                pr["example_values"] or "[]",
                "", "", "", "", "", "", "", "", "", "", "", "",
            ])
            continue

        for rec in probe_records:
            writer.writerow([
                p_uuid, pr["param_id"], name, host,
                pr["endpoint_id"], pr["method"], pr["normalized_path"],
                location, pr["param_type"], pr["semantic_type"],
                pr["seen_count"], pr["is_reflected"], pr["reflection_count"],
                pr["example_values"] or "[]",
                rec.get("analysis", ""),
                rec.get("payload", ""),
                rec.get("payload_class", ""),
                rec.get("payload_index", ""),
                rec.get("status", ""),
                rec.get("flow_id") or "",
                rec.get("status_code") or "",
                rec.get("content_type") or "",
                rec.get("body_length") or "",
                rec.get("error") or "",
                rec.get("created_at") or "",
                rec.get("completed_at") or "",
            ])

    csv_content = output.getvalue()
    output_path = getattr(args, "output", None)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(csv_content)
        print(f"Exported to {output_path}")
    else:
        print(csv_content, end="")


def _get_export_dir(project) -> "Path":
    """Return (and create) the project's exports directory."""
    from pathlib import Path
    export_dir = Path(str(project.db_path).replace("talos.db", "")) / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir


def _cmd_export_parameter(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Export a full dossier for one parameter (Markdown or JSON).
        JSON includes schema_version / engine_version / capabilities /
        candidates. Markdown is the human dossier under project exports/.
    """
    import sqlite3
    from pathlib import Path
    from talos.input_validation.db import make_param_uuid

    project = _require_active(manager)
    db_path = project.db_path
    param_uuid = args.param_uuid.strip()
    fmt = (getattr(args, "format", None) or "markdown").lower()
    if fmt == "md":
        fmt = "markdown"

    # Find parameter info (look up by UUID or param_uuid).
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        # Support looking up by either the parameter table UUID or param_uuid.
        p_row = conn.execute(
            """
            SELECT p.id, p.name, e.host, e.method, e.normalized_path,
                   p.location, p.param_type, p.semantic_type, p.seen_count,
                   p.example_values, p.is_reflected, p.reflection_count,
                   e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE p.id = ?
            LIMIT 1
            """,
            (param_uuid,),
        ).fetchone()

    # Also try looking up by computed param_uuid if not found by parameter UUID.
    probe_uuid = param_uuid
    if p_row is None:
        # param_uuid provided is already the computed hash — look up param.
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            probe_records = iv_db.get_probe_results_for_param(db_path, param_uuid)
            if probe_records:
                first = probe_records[0]
                p_row = conn.execute(
                    """
                    SELECT p.id, p.name, e.host, e.method, e.normalized_path,
                           p.location, p.param_type, p.semantic_type, p.seen_count,
                           p.example_values, p.is_reflected, p.reflection_count,
                           e.id AS endpoint_id
                    FROM parameters p
                    JOIN endpoints e ON e.id = p.endpoint_id
                    WHERE p.name = ? AND p.location = ? AND e.host = ?
                    LIMIT 1
                    """,
                    (first["param_name"], first["location"], first["host"]),
                ).fetchone()

    if p_row is None and not iv_db.get_probe_results_for_param(db_path, param_uuid):
        if not iv_db.get_param_profile(db_path, param_uuid):
            cli_error(f"No parameter data found for UUID '{param_uuid}'.")

    # Compute param_uuid from p_row if we found by parameter table UUID.
    if p_row:
        probe_uuid = make_param_uuid(p_row["host"], p_row["location"], p_row["name"])

    probe_records = iv_db.get_probe_flows_for_export(db_path, probe_uuid)

    # Synthesized intelligence profile (Module 3) + candidates (Module 11).
    intel = iv_db.get_param_profile(db_path, probe_uuid)
    if intel:
        from talos.input_validation.candidates import (
            enrich_profile_capabilities_and_candidates,
        )
        if not intel.get("candidates") or not intel.get("capabilities"):
            enrich_profile_capabilities_and_candidates(intel)

    # Module 12: JSON export with version fields.
    if fmt == "json":
        param_dict = None
        if p_row is not None:
            param_dict = {k: p_row[k] for k in p_row.keys()}
        payload = {
            "export_type": "parameter",
            "param_uuid": probe_uuid,
            "parameter": param_dict,
            "profile": intel,
            "schema_version": (intel or {}).get("schema_version"),
            "engine_version": (intel or {}).get("engine_version"),
            "profile_version": (intel or {}).get("profile_version"),
            "updated_at": (intel or {}).get("updated_at"),
            "capabilities": (intel or {}).get("capabilities") or [],
            "candidates": (intel or {}).get("candidates") or [],
            "probe_count": len(probe_records),
            "note": (
                "Candidate scores are prioritization only, not confirmed "
                "vulnerabilities."
            ),
        }
        text = json.dumps(payload, indent=2, default=str) + "\n"
        out_arg = getattr(args, "output", None)
        if out_arg:
            Path(out_arg).write_text(text, encoding="utf-8")
            print(f"Exported to {out_arg}")
        else:
            export_dir = _get_export_dir(project)
            out_path = export_dir / f"iv_parameter_{probe_uuid[:16]}.json"
            out_path.write_text(text, encoding="utf-8")
            print(f"Exported to {out_path}")
        return

    from talos.input_validation.candidates import format_candidates_lines
    from talos.input_validation.synthesize import format_profile_summary_lines

    lines: list[str] = []
    lines.append("# Input Validation — Parameter Export")
    lines.append("")
    if p_row:
        lines.append(f"**Parameter:** `{p_row['name']}`")
        lines.append(f"**Host:** `{p_row['host']}`")
        lines.append(f"**Location:** `{p_row['location']}`")
        lines.append(f"**Type:** {p_row['param_type']} / {p_row['semantic_type']}")
        lines.append(f"**Seen:** {p_row['seen_count']} flows")
        lines.append(
            f"**Reflected (passive):** "
            f"{'Yes' if p_row['is_reflected'] else 'No'} "
            f"({p_row['reflection_count']}x)"
        )
        lines.append(f"**Endpoint:** `{p_row['method']} {p_row['normalized_path']}`")
        try:
            ex_list = json.loads(p_row["example_values"] or "[]")
        except Exception:
            ex_list = []
        lines.append(
            f"**Example Values:** {', '.join(str(e) for e in ex_list) or '(none)'}"
        )
    else:
        lines.append(f"**Param UUID:** `{probe_uuid}`")
    lines.append(f"**Total Probes:** {len(probe_records)}")
    lines.append("")

    if intel:
        lines.append("## Intelligence Profile")
        lines.append("")
        lines.append(
            f"**schema_version:** `{intel.get('schema_version', '?')}` · "
            f"**engine_version:** `{intel.get('engine_version', '?')}` · "
            f"**profile_version:** `{intel.get('profile_version', '?')}` · "
            f"**updated_at:** `{intel.get('updated_at', '?')}`"
        )
        lines.append("")
        for line in format_profile_summary_lines(intel):
            lines.append(f"- {line}")
        lines.append("")
        caps = intel.get("capabilities") or []
        if caps:
            lines.append(f"**Capabilities:** {', '.join(f'`{c}`' for c in caps)}")
            lines.append("")
        cands = intel.get("candidates") or []
        if cands:
            lines.append("### Attack candidates")
            lines.append("")
            lines.append(
                "> Prioritization only — not confirmed vulnerabilities. "
                "Attack modules should verify before creating findings."
            )
            lines.append("")
            lines.append("| Attack | Score | Confidence | Reasons |")
            lines.append("|--------|------:|-----------:|---------|")
            for c in cands:
                if not isinstance(c, dict):
                    continue
                reasons = "; ".join(str(r) for r in (c.get("reasons") or [])[:3])
                lines.append(
                    f"| `{c.get('attack', '?')}` | {c.get('score', 0)} | "
                    f"{c.get('confidence', 0)} | {reasons} |"
                )
            lines.append("")
            for cline in format_candidates_lines(cands):
                lines.append(f"- {cline}")
            lines.append("")
        tested = intel.get("tested") or {}
        if tested:
            lines.append("### Tested (negative evidence)")
            lines.append("")
            for key, entry in sorted(tested.items()):
                if isinstance(entry, dict):
                    lines.append(
                        f"- `{key}`: {entry.get('outcome', '?')} "
                        f"(confidence={entry.get('confidence', 0)})"
                    )
            lines.append("")
        acceptance = (intel.get("observed") or {}).get("acceptance") or {}
        classes = acceptance.get("classes") or {}
        if classes:
            lines.append("### Acceptance by class")
            lines.append("")
            lines.append("| Class | Outcome | Confidence |")
            lines.append("|-------|---------|------------|")
            for cls, data in sorted(classes.items()):
                if isinstance(data, dict):
                    lines.append(
                        f"| `{cls}` | {data.get('outcome', '?')} | "
                        f"{data.get('confidence', 0)} |"
                    )
            lines.append("")

    if not probe_records:
        lines.append("*No probe results found — Input Validation has not run yet.*")
    else:
        current_analysis = None
        for rec in probe_records:
            analysis = rec.get("analysis", "")
            if analysis != current_analysis:
                current_analysis = analysis
                lines.append(f"## Analysis: {analysis.title()}")
                lines.append(f"")

            payload = rec.get("payload")
            payload_display = repr(payload) if payload is not None else "(original — no mutation)"
            flow_id = rec.get("flow_id") or ""
            http_status = rec.get("status_code") or "—"
            ct = rec.get("content_type") or ""
            error = rec.get("error") or ""
            req_headers = rec.get("request_headers") or "{}"
            req_body = rec.get("request_body_text") or ""
            resp_headers = rec.get("response_headers") or "{}"
            resp_body = (rec.get("response_body_text") or "")[:2048]

            lines.append(f"### Probe: {payload_display}")
            lines.append(f"")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Payload Class | `{rec.get('payload_class', '')}` |")
            lines.append(f"| Payload Index | {rec.get('payload_index', '')} |")
            lines.append(f"| HTTP Status | **{http_status}** |")
            lines.append(f"| Content-Type | {ct} |")
            lines.append(f"| Flow ID | `{flow_id}` |")
            if error:
                lines.append(f"| Error | {error} |")
            lines.append(f"")
            lines.append(f"**HTTP Request**")
            lines.append(f"```http")
            url = rec.get("url") or ""
            method = rec.get("method") or ""
            lines.append(f"{method} {url}")
            try:
                hdr_dict = json.loads(req_headers) if isinstance(req_headers, str) else req_headers
                for k, v in hdr_dict.items():
                    lines.append(f"{k}: {v}")
            except Exception:
                lines.append(req_headers)
            if req_body:
                lines.append(f"")
                lines.append(req_body[:1024])
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"**HTTP Response**")
            lines.append(f"```")
            lines.append(f"HTTP/1.1 {http_status}")
            try:
                rhdr_dict = json.loads(resp_headers) if isinstance(resp_headers, str) else resp_headers
                for k, v in list(rhdr_dict.items())[:20]:
                    lines.append(f"{k}: {v}")
            except Exception:
                lines.append(resp_headers[:500])
            if resp_body:
                lines.append(f"")
                lines.append(resp_body)
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    md_content = "\n".join(lines)
    out_arg = getattr(args, "output", None)
    if out_arg:
        Path(out_arg).write_text(md_content, encoding="utf-8")
        print(f"Exported to {out_arg}")
    else:
        export_dir = _get_export_dir(project)
        out_path = export_dir / f"iv_parameter_{probe_uuid[:16]}.md"
        out_path.write_text(md_content, encoding="utf-8")
        print(f"Exported to {out_path}")


def _cmd_export_host(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Export a host-level IV summary (Markdown or JSON) including
        capabilities/candidates. Written to project exports/ by default.
    """
    import sqlite3
    from pathlib import Path
    from talos.input_validation.db import make_param_uuid
    from talos.input_validation.candidates import list_candidates as iv_list_candidates

    project = _require_active(manager)
    db_path = project.db_path
    host = args.host.strip()
    fmt = (getattr(args, "format", None) or "markdown").lower()
    if fmt == "md":
        fmt = "markdown"

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        params = conn.execute(
            """
            SELECT DISTINCT p.name, p.location, p.param_type, p.semantic_type,
                            p.seen_count, p.is_reflected, p.reflection_count
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.host = ?
            ORDER BY p.location, p.name
            """,
            (host,),
        ).fetchall()

    host_cands = iv_list_candidates(db_path, host=host, min_score=40, limit=200)
    app_profile = iv_db.get_app_profile(db_path, host)

    param_summaries: list[dict] = []
    for p in params:
        p_uuid = make_param_uuid(host, p["location"], p["name"])
        probe_count = len(iv_db.get_probe_results_for_param(db_path, p_uuid))
        intel = iv_db.get_param_profile(db_path, p_uuid)
        param_summaries.append({
            "param_uuid": p_uuid,
            "name": p["name"],
            "location": p["location"],
            "param_type": p["param_type"],
            "semantic_type": p["semantic_type"],
            "seen_count": p["seen_count"],
            "is_reflected": bool(p["is_reflected"]),
            "probe_count": probe_count,
            "schema_version": (intel or {}).get("schema_version"),
            "capabilities": (intel or {}).get("capabilities") or [],
            "candidates": (intel or {}).get("candidates") or [],
        })

    if fmt == "json":
        payload = {
            "export_type": "host",
            "host": host,
            "app_profile": app_profile,
            "schema_version": (app_profile or {}).get("schema_version"),
            "engine_version": (app_profile or {}).get("engine_version"),
            "profile_version": (app_profile or {}).get("profile_version"),
            "updated_at": (app_profile or {}).get("updated_at"),
            "parameters": param_summaries,
            "candidates": host_cands,
            "note": (
                "Candidate scores are prioritization only, not confirmed "
                "vulnerabilities."
            ),
        }
        text = json.dumps(payload, indent=2, default=str) + "\n"
        out_arg = getattr(args, "output", None)
        safe_host = host.replace(":", "_").replace("/", "_")
        if out_arg:
            Path(out_arg).write_text(text, encoding="utf-8")
            print(f"Exported to {out_arg}")
        else:
            export_dir = _get_export_dir(project)
            out_path = export_dir / f"iv_host_{safe_host}.json"
            out_path.write_text(text, encoding="utf-8")
            print(f"Exported to {out_path}")
        return

    top_by_param: dict[str, list[str]] = {}
    for row in host_cands:
        uid = str(row.get("param_uuid") or "")
        if not uid:
            continue
        label = f"{row.get('attack')}={row.get('score')}"
        top_by_param.setdefault(uid, []).append(label)

    lines: list[str] = [
        f"# Input Validation — Host Export: `{host}`", "",
        f"**Total Parameters:** {len(params)}", "",
    ]
    if app_profile:
        lines.extend([
            f"**App schema_version:** `{app_profile.get('schema_version', '?')}` · "
            f"**engine_version:** `{app_profile.get('engine_version', '?')}` · "
            f"**updated_at:** `{app_profile.get('updated_at', '?')}`",
            "",
        ])
    lines.extend([
        "## Parameters", "",
        "| Parameter | Location | Type | Seen | Probes Run | Reflected | Top candidates |",
        "|-----------|----------|------|------|------------|-----------|----------------|",
    ])

    for p in params:
        p_uuid = make_param_uuid(host, p["location"], p["name"])
        probe_count = len(iv_db.get_probe_results_for_param(db_path, p_uuid))
        top = ", ".join((top_by_param.get(p_uuid) or [])[:3]) or "—"
        lines.append(
            f"| `{p['name']}` | {p['location']} | {p['param_type']}/{p['semantic_type']} "
            f"| {p['seen_count']} | {probe_count} | {'Yes' if p['is_reflected'] else 'No'} "
            f"| {top} |"
        )

    if host_cands:
        lines.extend([
            "",
            "## Attack candidates (prioritization only)",
            "",
            "> Scores rank investigation order. They are **not** confirmed "
            "vulnerabilities — attack modules must verify before findings.",
            "",
            "| Parameter | Attack | Score | Confidence | Reasons |",
            "|-----------|--------|------:|-----------:|---------|",
        ])
        for row in host_cands[:40]:
            reasons = "; ".join(str(r) for r in (row.get("reasons") or [])[:2])
            lines.append(
                f"| `{row.get('name')}` | `{row.get('attack')}` | "
                f"{row.get('score')} | {row.get('confidence')} | {reasons} |"
            )

    lines += ["", "## Probe Results by Parameter", ""]
    for p in params:
        p_uuid = make_param_uuid(host, p["location"], p["name"])
        probes = iv_db.get_probe_results_for_param(db_path, p_uuid)
        lines.append(f"### `{p['name']}` ({p['location']})")
        lines.append("")
        if not probes:
            lines.append("*Not yet analysed.*")
            lines.append("")
            continue
        lines.append("| Analysis | Payload | HTTP Status | Flow ID | Status |")
        lines.append("|----------|---------|-------------|---------|--------|")
        for rec in probes:
            payload = rec.get("payload")
            payload_str = repr(payload) if payload is not None else "(baseline)"
            sc = rec.get("status_code") or "—"
            fid = (rec.get("flow_id") or "")[:8] or "—"
            st = rec.get("status") or ""
            lines.append(
                f"| {rec.get('analysis','')} | `{payload_str}` | {sc} | "
                f"`{fid}` | {st} |"
            )
        lines.append("")

    md_content = "\n".join(lines)
    out_arg = getattr(args, "output", None)
    safe_host = host.replace(":", "_").replace("/", "_")
    if out_arg:
        Path(out_arg).write_text(md_content, encoding="utf-8")
        print(f"Exported to {out_arg}")
    else:
        export_dir = _get_export_dir(project)
        out_path = export_dir / f"iv_host_{safe_host}.md"
        out_path.write_text(md_content, encoding="utf-8")
        print(f"Exported to {out_path}")


def _summarise_phase_result(phase: str, result: dict) -> tuple[str, str]:
    """
    Purpose:
        Extract a short payload description and outcome summary from a phase
        result dict for use in the export CSV.
    Output:
        (payload_description, outcome_summary) — both plain strings.
    """
    if not result:
        return "", ""

    error = result.get("error")
    if error:
        return "", f"error: {error}"

    phase_short = phase.replace("iv_", "")

    if phase_short == "baseline":
        sc = result.get("status_code", "?")
        bl = result.get("body_length", "?")
        ct = result.get("content_type", "")
        return "(original flow, no mutation)", f"HTTP {sc}  {bl} bytes  {ct}"

    if phase_short == "transformations":
        transforms = result.get("transformations", [])
        return "", f"transforms={','.join(transforms) or 'none'}"

    if phase_short == "reflection":
        reflected = result.get("reflected", False)
        enc = result.get("encoding", "")
        loc = result.get("reflection_location", "")
        count = result.get("reflection_count", 0)
        if reflected:
            return "", f"reflected  encoding={enc}  location={loc}  count={count}"
        return "", "not reflected"

    return "", json.dumps(result)[:200]

