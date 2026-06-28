"""
Module: talos.input_validation.cli

Purpose:
    Command-line interface for the Input Validation Engine.
    Entry point: talos input-validation <subcommand>

    Main execution commands:
        talos input-validation run               — schedule jobs for the entire project
        talos input-validation run --host H      — single host
        talos input-validation run --endpoint ID — single endpoint
        talos input-validation run --parameter P — single parameter everywhere it appears
        talos input-validation run --ignore-cache — force re-run

    Phase-level commands (shorthand for --phase X):
        talos input-validation baseline
        talos input-validation identifier
        talos input-validation characters
        talos input-validation length
        talos input-validation types
        talos input-validation transformations
        talos input-validation reflection
        talos input-validation validation

    Each phase command supports: --host, --endpoint, --parameter, --force

    Configuration:
        talos input-validation config            — show current config
        talos input-validation config --enable
        talos input-validation config --disable
        talos input-validation config --workers N
        talos input-validation config --analysis-on  <phase>
        talos input-validation config --analysis-off <phase>

    Status:
        talos input-validation status            — show progress summary

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
        talos input-validation show <parameter_uuid> — show complete profile for a parameter
        talos input-validation export                — export all IV intelligence (CSV)

Dependencies: argparse, sys
              talos.projects.manager, talos.input_validation.config,
              talos.input_validation.db, talos.input_validation.engine,
              talos.scheduler.job
Data flow:
    CLI args -> active project lookup -> engine / config / db helpers -> stdout
Side effects:
    - Reads/writes project DB.
    - Inserts scheduler jobs.
    - Prints to stdout/stderr.
    - Exits 1 on error.
"""

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
    IV_BASELINE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
    IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION,
)


# Valid phase names for validation.
_PHASE_NAMES = {
    "baseline": IV_BASELINE,
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
        print(
            "Error: no active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
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

    # ------------------------------------------------------------------
    # Phase shorthand commands
    # ------------------------------------------------------------------
    for phase_name in _PHASE_NAMES:
        p_phase = sub.add_parser(
            phase_name,
            help=f"Run only the {phase_name} analysis phase.",
        )
        _add_scope_args(p_phase)
        p_phase.add_argument(
            "--force",
            action="store_true",
            help="Ignore cached result for this phase and re-run.",
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

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    sub.add_parser("status", help="Show Input Validation progress summary.")

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
    # show
    # ------------------------------------------------------------------
    p_show = sub.add_parser(
        "show",
        help="Display the complete Input Validation profile for a parameter (by UUID).",
    )
    p_show.add_argument(
        "param_id",
        help="UUID of the parameter row (from the parameters table) to display.",
    )

    # ------------------------------------------------------------------
    # export (with subcommands: host, endpoint, parameter, or csv)
    # ------------------------------------------------------------------
    p_export = sub.add_parser(
        "export",
        help="Export Input Validation data as Markdown or CSV.",
    )
    export_sub = p_export.add_subparsers(dest="export_target", metavar="<target>")

    p_export_param = export_sub.add_parser(
        "parameter",
        help="Export full IV profile for a parameter UUID (Markdown).",
    )
    p_export_param.add_argument("param_uuid", help="Parameter UUID (from iv_probe_results or parameters table).")

    p_export_host = export_sub.add_parser(
        "host",
        help="Export IV summary for all parameters on a host (Markdown).",
    )
    p_export_host.add_argument("host", help="Hostname (e.g. api.example.com).")

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
        _cmd_status(manager)
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
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    config = load_config(db_path)
    if not config.enabled:
        print(
            "Input Validation is disabled. "
            "Enable it with: talos input-validation config --enable",
            file=sys.stderr,
        )
        sys.exit(1)

    ignore_cache = getattr(args, "ignore_cache", False) or getattr(args, "force", False)

    # Determine scope.
    host = getattr(args, "host", None)
    endpoint_id = getattr(args, "endpoint", None)
    param_name = getattr(args, "parameter", None)

    if host:
        enqueued = iv_engine.schedule_host(
            db_path, project_id, host,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
        )
        scope_desc = f"host '{host}'"
    elif endpoint_id:
        enqueued = iv_engine.schedule_endpoint(
            db_path, project_id, endpoint_id,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
        )
        scope_desc = f"endpoint {endpoint_id}"
    elif param_name:
        enqueued = iv_engine.schedule_parameter(
            db_path, project_id, param_name,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
        )
        scope_desc = f"parameter '{param_name}'"
    else:
        enqueued = iv_engine.schedule_project(
            db_path, project_id,
            phase_filter=phase_filter,
            ignore_cache=ignore_cache,
        )
        scope_desc = "entire project"

    phase_desc = f" [{phase_filter}]" if phase_filter else ""
    if enqueued == 0:
        print(
            f"No new jobs enqueued for {scope_desc}{phase_desc}. "
            "All analyses may already be complete. "
            "Use --ignore-cache / --force to re-run.",
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

    config = load_config(db_path)
    changed = False

    if args.enable and args.disable:
        print("Error: cannot use --enable and --disable together.", file=sys.stderr)
        sys.exit(1)

    if args.enable:
        config.enabled = True
        changed = True
    if args.disable:
        config.enabled = False
        changed = True
    if args.workers is not None:
        if args.workers < 1:
            print("Error: --workers must be >= 1.", file=sys.stderr)
            sys.exit(1)
        config.workers = args.workers
        changed = True
    if args.analysis_on:
        phase = args.analysis_on.lower()
        if phase not in _PHASE_NAMES:
            print(
                f"Error: unknown phase '{phase}'. Valid: {', '.join(_PHASE_NAMES)}",
                file=sys.stderr,
            )
            sys.exit(1)
        setattr(config.analyses, phase, True)
        changed = True
    if args.analysis_off:
        phase = args.analysis_off.lower()
        if phase not in _PHASE_NAMES:
            print(
                f"Error: unknown phase '{phase}'. Valid: {', '.join(_PHASE_NAMES)}",
                file=sys.stderr,
            )
            sys.exit(1)
        setattr(config.analyses, phase, False)
        changed = True

    if changed:
        save_config(db_path, config)
        print("Configuration updated.")

    print(format_config(config))


def _cmd_status(manager: ProjectManager) -> None:
    """Show Input Validation progress summary."""
    project = _require_active(manager)
    status = iv_db.get_iv_status(project.db_path)
    print(
        f"Input Validation Status\n"
        f"  Parameters : {status['total_params']}\n"
        f"  Completed  : {status['completed']}\n"
        f"  Running    : {status['running']}\n"
        f"  Queued     : {status['queued']}\n"
        f"  Failed     : {status['failed']}\n"
    )


def _cmd_clear_cache(
    manager: ProjectManager,
    args: argparse.Namespace,
) -> None:
    """
    Purpose:
        Delete IV cache data.  Scope is controlled by --host, --endpoint,
        or --parameter; without any flag the entire cache is cleared.
    """
    project = _require_active(manager)
    db_path = project.db_path

    host = getattr(args, "host", None)
    endpoint_id = getattr(args, "endpoint", None)
    param_name = getattr(args, "parameter", None)

    if host:
        param_n = iv_db.clear_param_cache(db_path, host=host)
        refl_n = iv_db.clear_reflection_cache(db_path, host=host)
        scope = f"host '{host}'"
    elif endpoint_id:
        param_n = iv_db.clear_param_cache_for_endpoint(db_path, endpoint_id)
        refl_n = iv_db.clear_reflection_cache(db_path, endpoint_id=endpoint_id)
        scope = f"endpoint {endpoint_id}"
    elif param_name:
        param_n = iv_db.clear_param_cache(db_path, param_name=param_name)
        refl_n = iv_db.clear_reflection_cache(db_path, param_name=param_name)
        scope = f"parameter '{param_name}'"
    else:
        param_n, refl_n = iv_db.clear_all_iv_cache(db_path)
        scope = "entire project"

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
        Display the complete passive + active IV profile for one parameter.
        Shows per-probe results from iv_probe_results (one row per HTTP request
        sent) plus analysis summaries (transformations, reflection).
    Input:
        args.param_id — UUID of the parameter row from the parameters table.
    """
    project = _require_active(manager)
    db_path = project.db_path
    profile = iv_db.get_parameter_profile(db_path, args.param_id)

    if profile is None:
        print(
            f"No parameter found with UUID '{args.param_id}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    param_uuid = profile.get("param_uuid", "")

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
        f"  Reflected  : {'Yes' if profile['is_reflected'] else 'No'} "
        f"({profile['reflection_count']}x)"
    )
    if profile["reflection_locations"]:
        print(
            f"  Refl. loc  : {', '.join(profile['reflection_locations'])}\n"
            f"  Refl. enc  : {', '.join(profile['reflection_encoding'])}"
        )
    print(
        f"  Examples   : {', '.join(str(e) for e in profile['examples']) or '(none)'}"
    )
    print()

    # Per-probe results from iv_probe_results (the canonical scan evidence).
    probe_records = iv_db.get_probe_results_for_param(db_path, param_uuid)
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
        Export a full Markdown dossier for one parameter by param_uuid.
        Contains: parameter summary, per-probe replay flows with exact
        payloads and HTTP responses, and analysis summaries.
        Written to <project_dir>/exports/iv_parameter_<uuid>.md.
    """
    import sqlite3
    from pathlib import Path
    from talos.input_validation.db import make_param_uuid

    project = _require_active(manager)
    db_path = project.db_path
    param_uuid = args.param_uuid.strip()

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
        print(f"No parameter data found for UUID '{param_uuid}'.", file=sys.stderr)
        sys.exit(1)

    # Compute param_uuid from p_row if we found by parameter table UUID.
    if p_row:
        probe_uuid = make_param_uuid(p_row["host"], p_row["location"], p_row["name"])

    probe_records = iv_db.get_probe_flows_for_export(db_path, probe_uuid)

    lines: list[str] = []
    lines.append(f"# Input Validation — Parameter Export")
    lines.append(f"")
    if p_row:
        lines.append(f"**Parameter:** `{p_row['name']}`")
        lines.append(f"**Host:** `{p_row['host']}`")
        lines.append(f"**Location:** `{p_row['location']}`")
        lines.append(f"**Type:** {p_row['param_type']} / {p_row['semantic_type']}")
        lines.append(f"**Seen:** {p_row['seen_count']} flows")
        lines.append(f"**Reflected (passive):** {'Yes' if p_row['is_reflected'] else 'No'} ({p_row['reflection_count']}x)")
        lines.append(f"**Endpoint:** `{p_row['method']} {p_row['normalized_path']}`")
        try:
            ex_list = json.loads(p_row["example_values"] or "[]")
        except Exception:
            ex_list = []
        lines.append(f"**Example Values:** {', '.join(str(e) for e in ex_list) or '(none)'}")
    else:
        lines.append(f"**Param UUID:** `{probe_uuid}`")
    lines.append(f"**Total Probes:** {len(probe_records)}")
    lines.append(f"")

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
    export_dir = _get_export_dir(project)
    out_path = export_dir / f"iv_parameter_{probe_uuid[:16]}.md"
    out_path.write_text(md_content, encoding="utf-8")
    print(f"Exported to {out_path}")


def _cmd_export_host(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Export a Markdown summary for all IV-analysed parameters on a host.
        Written to <project_dir>/exports/iv_host_<host>.md.
    """
    import sqlite3
    from talos.input_validation.db import make_param_uuid

    project = _require_active(manager)
    db_path = project.db_path
    host = args.host.strip()

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

    lines: list[str] = [
        f"# Input Validation — Host Export: `{host}`", "",
        f"**Total Parameters:** {len(params)}", "",
        "## Parameters", "",
        "| Parameter | Location | Type | Seen | Probes Run | Reflected |",
        "|-----------|----------|------|------|------------|-----------|",
    ]

    for p in params:
        p_uuid = make_param_uuid(host, p["location"], p["name"])
        probe_count = len(iv_db.get_probe_results_for_param(db_path, p_uuid))
        lines.append(
            f"| `{p['name']}` | {p['location']} | {p['param_type']}/{p['semantic_type']} "
            f"| {p['seen_count']} | {probe_count} | {'Yes' if p['is_reflected'] else 'No'} |"
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
            lines.append(f"| {rec.get('analysis','')} | `{payload_str}` | {sc} | `{fid}` | {st} |")
        lines.append("")

    md_content = "\n".join(lines)
    export_dir = _get_export_dir(project)
    safe_host = host.replace(":", "_").replace("/", "_")
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

