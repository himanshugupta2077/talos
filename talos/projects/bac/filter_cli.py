"""
Module: talos.projects.bac.filter_cli

Purpose:
    CLI commands for managing the per-project BAC-decision-filter.yaml.
    Provides three commands under 'talos attack bac filter':
        init      — Write the sample BAC-decision-filter.yaml to the project directory.
        show      — Print the current filter configuration.
        validate  — Load and validate the filter, reporting structure and errors.

    The filter file lives at <project_data_dir>/BAC-decision-filter.yaml.
    It is consumed by the BAC engine at attack execution time to determine
    whether each replayed response represents POSSIBLE_BAC, SECURE, or UNKNOWN.

Dependencies: argparse, sys, pathlib
              talos.projects.manager
              talos.projects.bac.decision_filter
Data flow:
    attack_cli → bac.cli → filter_cli commands → filesystem reads/writes
Side effects:
    init     — Creates BAC-decision-filter.yaml on disk (exits 1 on conflict
               unless --force is passed).
    show     — Read-only; prints to stdout.
    validate — Read-only; prints to stdout/stderr.
"""

import argparse
import sys
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
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
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

    if dest.exists() and not args.force:
        print(
            f"Filter file already exists: {dest}\n"
            "Edit it directly, or re-run with --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    dest.write_text(SAMPLE_FILTER_YAML, encoding="utf-8")
    action = "Overwrote" if dest.exists() else "Created"
    print(f"{action} BAC decision filter: {dest}")
    print(
        "\nEdit the file to match your application's authorization enforcement patterns.\n"
        "Run 'talos attack bac filter validate' to verify the configuration.\n"
        "Run 'talos attack bac filter show' to review the current configuration."
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
        print(
            f"No filter file found at: {dest}\n"
            "Run 'talos attack bac filter init' to create a starter configuration.",
            file=sys.stderr,
        )
        sys.exit(1)

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
        print(f"FAIL  {message}", file=sys.stderr)
        sys.exit(1)


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_filter_parser(bac_sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Purpose:
        Register the 'filter' subcommand group under the 'bac' subparser.
        Adds: init | show | validate
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
            "  talos attack bac filter show      # review the active config"
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
    }

    handler = dispatch.get(args.filter_cmd)
    if handler is None:
        print(f"Unknown filter command: '{args.filter_cmd}'", file=sys.stderr)
        sys.exit(1)

    handler(manager, args)
