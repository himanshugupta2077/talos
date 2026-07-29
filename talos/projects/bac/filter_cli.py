"""
Module: talos.projects.bac.filter_cli

Purpose:
    CLI commands for managing the per-project BAC-decision-filter.yaml.
    Provides four commands under 'talos attack bac filter':
        init      — Write the sample BAC-decision-filter.yaml to the project directory.
        show      — Print the current filter configuration.
        validate  — Load and validate the filter, reporting structure and errors.
        apply     — Re-evaluate stored bac_results against the current filter;
                    reject TRIAGING findings that flip POSSIBLE_BAC→SECURE.

    The filter file lives at <project_data_dir>/BAC-decision-filter.yaml.
    It is consumed by the BAC engine at attack execution time to determine
    whether each replayed response represents POSSIBLE_BAC, SECURE, or UNKNOWN.

Dependencies: argparse, sys, pathlib
              talos.projects.manager
              talos.projects.bac.decision_filter
              talos.projects.bac.reclassify
Data flow:
    attack_cli → bac.cli → filter_cli commands → filesystem reads/writes / DB writes
Side effects:
    init     — Creates BAC-decision-filter.yaml on disk (exits 1 on conflict
               unless --force is passed).
    show/validate — Read-only; prints to stdout/stderr.
    apply    — may update bac_results + findings (unless --dry-run).
"""
from talos.cli_output import (
    add_force_argument,
    cli_error,
    cli_usage_error,
    cli_precondition_error,
    confirm_or_exit,
)

import argparse
from pathlib import Path

from talos.projects.manager import ProjectManager
from talos.projects.bac.decision_filter import (
    FILTER_FILENAME,
    SAMPLE_FILTER_YAML,
    validate_filter_file,
)


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _require_active(manager: ProjectManager):
    """
    Purpose: Return the active project or exit with a clear error.
    Side effects: May call sys.exit(1).
    """
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def _filter_path(project) -> Path:
    """
    Purpose:
        Return the absolute path to the project's BAC decision filter file.
    Input:  project — active Project instance.
    Output: Path to BAC-decision-filter.yaml.
    """
    return Path(project.data_dir) / FILTER_FILENAME


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_filter_init(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Write the sample BAC-decision-filter.yaml to the project data directory.
        Exits 1 if the file already exists and --force was not passed.
        The generated file is a starting point — the operator should customise it
        to match the application's actual authorization failure patterns.

    Side effects:
        Creates BAC-decision-filter.yaml on disk.
        Does not overwrite an existing file unless --force is set.
    """
    project = _require_active(manager)
    dest = _filter_path(project)
    existed = dest.exists()

    if existed and not args.force:
        cli_error(
            f"Filter file already exists: {dest}\n"
            "Edit it directly, or re-run with --force to overwrite."
        )

    dest.write_text(SAMPLE_FILTER_YAML, encoding="utf-8")
    action = "Overwrote" if existed else "Created"
    print(f"{action} BAC decision filter: {dest}")
    print(
        "\nEdit the file to match your application's authorization enforcement patterns.\n"
        "Run 'talos attack bac filter validate' to verify the configuration.\n"
        "Run 'talos attack bac filter show' to review the current configuration.\n"
        "After edits, run 'talos attack bac filter apply' to reclassify stored results."
    )


def cmd_filter_show(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Print the contents of the project's BAC-decision-filter.yaml to stdout.
        Exits 1 if the file does not exist.
    Side effects: Read-only; prints to stdout.
    """
    project = _require_active(manager)
    dest = _filter_path(project)

    if not dest.exists():
        cli_error(
            f"No filter file found at: {dest}\n"
            "Run 'talos attack bac filter init' to create a starter configuration."
        )

    print(f"# {dest}\n")
    print(dest.read_text(encoding="utf-8"))


def cmd_filter_validate(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Load and validate the BAC-decision-filter.yaml.
        Prints a structural summary on success.
        Prints the error and exits 1 on failure.
    Side effects: Read-only; prints to stdout/stderr.
    """
    project = _require_active(manager)
    data_dir = Path(project.data_dir)

    ok, message = validate_filter_file(data_dir)

    if ok:
        print(f"OK  {message}")
    else:
        cli_error(f"FAIL  {message}")


def cmd_filter_apply(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Re-evaluate stored bac_results against the current decision filter.
        POSSIBLE_BAC→SECURE rewrites the result and auto-rejects TRIAGING findings
        (CONFIRMED too when --force). Reverse POSSIBLE_BAC is reported only.
    """
    from talos.projects.bac.reclassify import (
        FilterApplyError,
        apply_bac_decision_filter,
    )

    project = _require_active(manager)
    db_path: Path = project.db_path  # type: ignore[attr-defined]
    data_dir = Path(project.data_dir)
    dry_run = bool(getattr(args, "dry_run", False))
    force = bool(getattr(args, "force", False))

    if not dry_run:
        confirm_or_exit(
            "Re-evaluate bac results against the decision filter and "
            "auto-reject matching findings?",
            force=force,
        )

    try:
        summary = apply_bac_decision_filter(
            db_path,
            data_dir,
            dry_run=dry_run,
            include_confirmed=force,
        )
    except FilterApplyError as exc:
        cli_error(str(exc))

    _print_apply_summary(summary)


def _print_apply_summary(summary) -> None:
    """Pretty-print ApplySummary to stdout."""
    mode = "DRY-RUN" if summary.dry_run else "APPLIED"
    print(f"BAC decision filter apply ({mode})")
    print(f"  Results total              : {summary.results_total}")
    print(f"  Results unchanged          : {summary.results_unchanged}")
    print(f"  Results updated            : {summary.results_updated}")
    print(f"  Findings rejected          : {summary.findings_rejected}")
    print(f"  Findings skipped CONFIRMED : {summary.findings_skipped_confirmed}")
    print(f"  Findings skipped other     : {summary.findings_skipped_other}")
    print(f"  Would create finding       : {summary.would_create_finding}")
    print(f"  Incomplete (missing flow)  : {summary.incomplete}")

    interesting = [r for r in summary.rows if r.action != "unchanged"]
    if not interesting:
        print("\nNo changes.")
        return

    print(f"\nChanges ({len(interesting)}):")
    for r in interesting[:50]:
        fid = (r.finding_id or "-")[:8]
        print(
            f"  {r.replay_flow_id[:8]}  {r.old_verdict}→{r.new_verdict}  "
            f"finding={fid}  {r.action}"
            + (f"  — {r.reason}" if r.reason else "")
        )
    if len(interesting) > 50:
        print(f"  … and {len(interesting) - 50} more")


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_filter_parser(bac_sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Purpose:
        Register the 'filter' subcommand group under the 'bac' subparser.
        Adds: init | show | validate | apply
    Input:
        bac_sub — SubParsersAction from the 'bac' parser.
    Side effects: Adds 'filter' to the bac subparser group.
    """
    filter_p = bac_sub.add_parser(
        "filter",
        help="Manage the BAC decision filter configuration file.",
        description=(
            "Manage BAC-decision-filter.yaml — the per-project file that tells\n"
            "Talos how to distinguish POSSIBLE_BAC from SECURE responses.\n\n"
            "Without this file, Talos falls back to a built-in heuristic\n"
            "(status 401/403 → SECURE, status 200 → POSSIBLE_BAC).\n\n"
            "With a filter file, Talos uses your application-specific patterns\n"
            "to make more accurate verdicts.\n\n"
            "Workflow:\n"
            "  talos attack bac filter init      # create starter config\n"
            "  # edit BAC-decision-filter.yaml\n"
            "  talos attack bac filter validate  # verify syntax and structure\n"
            "  talos attack bac filter show      # review the active config\n"
            "  talos attack bac filter apply     # reclassify stored results"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    filter_sub = filter_p.add_subparsers(dest="filter_cmd", metavar="<command>")
    filter_sub.required = True

    # init
    init_p = filter_sub.add_parser(
        "init",
        help="Create a starter BAC-decision-filter.yaml in the project directory.",
        description=(
            "Writes a sample BAC-decision-filter.yaml to the active project's\n"
            "data directory.  The file includes commented examples for common\n"
            "authorization enforcement patterns (401, 403, redirect, etc.).\n\n"
            "Exits 1 if the file already exists.  Use --force to overwrite."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_p.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite an existing BAC-decision-filter.yaml.",
    )

    # show
    filter_sub.add_parser(
        "show",
        help="Print the current BAC-decision-filter.yaml configuration.",
    )

    # validate
    filter_sub.add_parser(
        "validate",
        help="Validate the BAC-decision-filter.yaml syntax and structure.",
        description=(
            "Parses the filter file and reports:\n"
            "  - Number of groups and rules per detection section.\n"
            "  - Parse errors with the exact rule location.\n\n"
            "Exits 0 on success, 1 on error."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # apply
    apply_p = filter_sub.add_parser(
        "apply",
        help=(
            "Re-evaluate bac_results against the current filter; "
            "auto-reject TRIAGING findings that flip POSSIBLE_BAC→SECURE."
        ),
        description=(
            "Re-apply BAC-decision-filter.yaml to stored bac_results offline.\n"
            "Responses that now match passed_detection become SECURE; linked\n"
            "TRIAGING findings are auto-rejected as false positives with a\n"
            "system timeline reason. Reverse POSSIBLE_BAC is reported only\n"
            "(no new findings in v1)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    apply_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned changes without writing to the database.",
    )
    add_force_argument(
        apply_p,
        help=(
            "Skip confirmation (required non-interactively). "
            "Also auto-reject CONFIRMED findings on POSSIBLE_BAC→SECURE."
        ),
    )


# ------------------------------------------------------------------ #
# Entry point called by bac.cli                                        #
# ------------------------------------------------------------------ #

def run_filter_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Dispatch to the correct filter command handler based on args.filter_cmd.
    Input:
        manager — ProjectManager instance.
        args    — Parsed namespace; args.filter_cmd selects the handler.
    Side effects:
        Delegates to the appropriate cmd_filter_* handler; may sys.exit().
    """
    dispatch = {
        "init":     cmd_filter_init,
        "show":     cmd_filter_show,
        "validate": cmd_filter_validate,
        "apply":    cmd_filter_apply,
    }

    handler = dispatch.get(args.filter_cmd)
    if handler is None:
        cli_usage_error(f"Unknown filter command: '{args.filter_cmd}'")

    handler(manager, args)
