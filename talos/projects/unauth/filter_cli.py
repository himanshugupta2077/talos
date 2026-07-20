"""
Module: talos.projects.unauth.filter_cli

Purpose:
    CLI commands for managing the per-project unauth-decision-filter.yaml.
    Entry point: talos attack unauth filter <subcommand>

    Subcommands:
        init     — Write the default unauth-decision-filter.yaml to the project data dir.
        show     — Print the current filter file contents.
        validate — Parse the filter file and report any structural errors.

Dependencies: argparse, sys, talos.projects.manager,
              talos.projects.unauth.decision_filter
Data flow:
    attack_cli → run_unauth_filter_cli → init | show | validate
Side effects:
    init: creates one YAML file on disk.
    show/validate: read-only.
"""
from talos.cli_output import (
    cli_error,
    cli_usage_error,
    cli_precondition_error,
)

import argparse
import sys
from pathlib import Path

from talos.projects.manager import ProjectManager


def _require_active(manager: ProjectManager):
    """Return the active project or exit with a clear error."""
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def cmd_unauth_filter_init(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Write the default unauth-decision-filter.yaml to the project data dir.
        No-op with a message if the file already exists.
    """
    from talos.projects.unauth.decision_filter import write_default_filter, FILTER_FILENAME

    project = _require_active(manager)
    data_dir: Path = project.db_path.parent  # type: ignore[attr-defined]
    written = write_default_filter(data_dir)
    if written:
        print(f"Created: {data_dir / FILTER_FILENAME}")
        print("Edit the file to customise BYPASS/SECURE detection patterns.")
    else:
        print(f"Already exists: {data_dir / FILTER_FILENAME}")
        print("Delete it and re-run 'init' to reset to defaults.")


def cmd_unauth_filter_show(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Print the current unauth-decision-filter.yaml contents to stdout.
    """
    from talos.projects.unauth.decision_filter import FILTER_FILENAME

    project = _require_active(manager)
    data_dir: Path = project.db_path.parent  # type: ignore[attr-defined]
    filter_path = data_dir / FILTER_FILENAME

    if not filter_path.exists():
        cli_error(
            f"No filter file found at: {filter_path}\n"
            "Run 'talos attack unauth filter init' to create one."
        )

    print(filter_path.read_text(encoding="utf-8"))


def cmd_unauth_filter_validate(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Parse unauth-decision-filter.yaml and report structural errors.
        Prints 'OK' on success; lists errors and exits 1 on failure.
    """
    from talos.projects.unauth.decision_filter import load_filter, FILTER_FILENAME

    project = _require_active(manager)
    data_dir: Path = project.db_path.parent  # type: ignore[attr-defined]
    filter_path = data_dir / FILTER_FILENAME

    if not filter_path.exists():
        cli_error(
            f"No filter file found at: {filter_path}\n"
            "Run 'talos attack unauth filter init' to create one."
        )

    result = load_filter(data_dir)
    if result is None:
        cli_error(
            f"{filter_path} could not be parsed.\n"
            "Check the YAML syntax and structure."
        )

    passed_groups = (
        len(result.passed_detection.groups) if result.passed_detection else 0
    )
    failed_groups = (
        len(result.failed_detection.groups) if result.failed_detection else 0
    )
    print(f"OK — {filter_path.name}")
    print(f"  Version             : {result.version}")
    print(f"  passed_detection    : {passed_groups} group(s)")
    print(f"  failed_detection    : {failed_groups} group(s)")


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_unauth_filter_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Purpose:
        Register the 'filter' subcommand group under the unauth subparser.
    Input:   sub — SubParsersAction from the unauth parser.
    Side effects: Adds 'filter' to the unauth subparser group.
    """
    filter_p = sub.add_parser(
        "filter",
        help="Manage the unauth-decision-filter.yaml (init | show | validate).",
        description=(
            "The unauth decision filter determines how replayed responses are\n"
            "classified: BYPASS (auth enforcement failed) or SECURE (denied).\n\n"
            "Subcommands:\n"
            "  init      — Write the default filter file (no-op if exists).\n"
            "  show      — Print the current filter file.\n"
            "  validate  — Parse and validate the filter file structure."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fsub = filter_p.add_subparsers(dest="unauth_filter_cmd", metavar="<subcommand>")
    fsub.required = True
    fsub.add_parser("init",     help="Write default unauth-decision-filter.yaml.")
    fsub.add_parser("show",     help="Print the current filter file.")
    fsub.add_parser("validate", help="Validate the filter file structure.")


def run_unauth_filter_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Dispatch to the correct unauth filter subcommand handler.
    Input:
        manager — ProjectManager instance.
        args    — Parsed namespace; args.unauth_filter_cmd selects the handler.
    Side effects: Delegates to handler; may sys.exit().
    """
    dispatch = {
        "init":     cmd_unauth_filter_init,
        "show":     cmd_unauth_filter_show,
        "validate": cmd_unauth_filter_validate,
    }
    handler = dispatch.get(args.unauth_filter_cmd)
    if handler is None:
        cli_usage_error(f"Unknown unauth filter subcommand: '{args.unauth_filter_cmd}'")
    handler(manager, args)
