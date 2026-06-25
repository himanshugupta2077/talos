"""
Module: talos.projects.auth_config_cli

Purpose:
    Command-line interface for the auth-config model: multi-flow authentication
    with per-flow Python extractor scripts and a Session Health Engine.

    Flow management:
        talos auth-config add-flow      <role_id> <flow_id>
        talos auth-config remove-flow   <role_id> <flow_id>
        talos auth-config list-flows    <role_id>

    Extractor management:
        talos auth-config set-extractor    <role_id> <flow_id> <python_file>
        talos auth-config show-extractor   <role_id> <flow_id>
        talos auth-config edit-extractor   <role_id> <flow_id>
        talos auth-config remove-extractor <role_id> <flow_id>

    Runtime:
        talos auth-config test     <role_id> <flow_id>   Run one flow + extractor; show results.
        talos auth-config validate <role_id>              Run all flows; validate against auth requirements.
        talos auth-config refresh  <role_id>              Force regeneration of full auth state.
        talos auth-config status   <role_id>              Show current auth state + age.
        talos auth-config show     <role_id>              Show complete configuration.

    Session Health Engine:
        talos auth-config set-ttl         <role_id> --ttl <s> [--refresh-before <s>]
        talos auth-config add-expiry-signal   <role_id> [--body TEXT ...] [--status CODE ...] [--header NAME VALUE]
        talos auth-config clear-expiry-signals <role_id>
        talos auth-config set-validation      <role_id> <url> [--expected-status N] [--body-contains TEXT] [--body-not-contains TEXT]
        talos auth-config clear-validation    <role_id>
        talos auth-config add-control-flow    <role_id> <flow_id>
        talos auth-config remove-control-flow <role_id> <flow_id>
        talos auth-config list-control-flows  <role_id>

    The extractor is a Python file with this signature:
        def extract(response):
            # response.status   — HTTP status code (int)
            # response.headers  — header dict (lowercase keys)
            # response.body     — decoded body text (str)
            # response.cookies  — cookie dict
            return {"artifact_name": "value"}

Dependencies: argparse, asyncio, json, os, subprocess, sys, tempfile
              talos.projects.manager, talos.projects.auth,
              talos.replay.db, talos.replay.engine
Data flow:
    CLI args → active project DB → auth CRUD functions / replay engine → stdout
Side effects:
    - Flow/extractor commands write to auth_flow_config table.
    - refresh/validate/test send outbound HTTP; write role_auth_state.
    - Session health commands write to session_health_config /
      session_health_control_flows.
    - All commands require an active project.
    - Exits 1 on hard errors.
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.manager import ProjectManager
from talos.projects.auth import (
    get_auth_config,
    list_auth_flow_configs,
    add_auth_flow,
    remove_auth_flow,
    set_flow_extractor,
    get_flow_extractor,
    remove_flow_extractor,
    get_role_auth_state,
    store_role_auth_state,
    get_session_health_config,
    set_session_health_config,
    list_session_health_control_flows,
    add_session_health_control_flow,
    remove_session_health_control_flow,
)
from talos.replay import db as replay_db
from talos.replay.engine import replay_flow


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_auth_config_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse auth-config subcommand arguments and dispatch to handlers.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'auth-config'.
    Side effects:
        Dispatches to the appropriate command handler.
        Exits 1 for missing active project or unknown subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos auth-config",
        description="Manage multi-flow authentication config and session health.",
    )
    sub = parser.add_subparsers(dest="cmd", metavar="<command>")
    sub.required = True

    # ---- flow management ----
    p_add_flow = sub.add_parser("add-flow", help="Add a flow to the role's auth config.")
    p_add_flow.add_argument("role_id", help="UUID of the role.")
    p_add_flow.add_argument("flow_id", help="UUID of the flow to add.")

    p_remove_flow = sub.add_parser("remove-flow", help="Remove a flow from the role's auth config.")
    p_remove_flow.add_argument("role_id", help="UUID of the role.")
    p_remove_flow.add_argument("flow_id", help="UUID of the flow to remove.")

    p_list_flows = sub.add_parser("list-flows", help="List flows in the role's auth config.")
    p_list_flows.add_argument("role_id", help="UUID of the role.")

    # ---- extractor management ----
    p_set_ext = sub.add_parser("set-extractor", help="Attach a Python extractor to a flow.")
    p_set_ext.add_argument("role_id", help="UUID of the role.")
    p_set_ext.add_argument("flow_id", help="UUID of the flow.")
    p_set_ext.add_argument("python_file", help="Path to the Python extractor file.")

    p_show_ext = sub.add_parser("show-extractor", help="Print the extractor code for a flow.")
    p_show_ext.add_argument("role_id", help="UUID of the role.")
    p_show_ext.add_argument("flow_id", help="UUID of the flow.")

    p_edit_ext = sub.add_parser(
        "edit-extractor",
        help="Open the extractor in $EDITOR (creates a blank template if none set).",
    )
    p_edit_ext.add_argument("role_id", help="UUID of the role.")
    p_edit_ext.add_argument("flow_id", help="UUID of the flow.")

    p_rm_ext = sub.add_parser("remove-extractor", help="Delete the extractor for a flow.")
    p_rm_ext.add_argument("role_id", help="UUID of the role.")
    p_rm_ext.add_argument("flow_id", help="UUID of the flow.")

    # ---- runtime commands ----
    p_test = sub.add_parser(
        "test",
        help="Run a single flow, execute its extractor, and show returned artifacts.",
    )
    p_test.add_argument("role_id", help="UUID of the role.")
    p_test.add_argument("flow_id", help="UUID of the flow.")

    p_validate = sub.add_parser(
        "validate",
        help="Run all flows for a role and validate the result against auth requirements.",
    )
    p_validate.add_argument("role_id", help="UUID of the role.")

    p_refresh = sub.add_parser(
        "refresh",
        help="Force regeneration of the full auth state for a role.",
    )
    p_refresh.add_argument("role_id", help="UUID of the role.")

    p_status = sub.add_parser(
        "status",
        help="Show the current auth state (collected values + age) for a role.",
    )
    p_status.add_argument("role_id", help="UUID of the role.")

    p_show = sub.add_parser(
        "show",
        help="Show the complete auth-config for a role (flows, extractors, health config).",
    )
    p_show.add_argument("role_id", help="UUID of the role.")

    # ---- session health: TTL ----
    p_set_ttl = sub.add_parser(
        "set-ttl",
        help="Configure TTL-based session refresh for a role (Layer 1).",
    )
    p_set_ttl.add_argument("role_id", help="UUID of the role.")
    p_set_ttl.add_argument(
        "--ttl",
        type=int,
        required=True,
        metavar="SECONDS",
        help="Token lifetime in seconds (e.g. 1200 for 20 min).",
    )
    p_set_ttl.add_argument(
        "--refresh-before",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Seconds before expiry to pre-refresh (default: 120).",
    )

    # ---- session health: expiry signals ----
    p_add_sig = sub.add_parser(
        "add-expiry-signal",
        help="Add response-based expiry signals for a role (Layer 2).",
    )
    p_add_sig.add_argument("role_id", help="UUID of the role.")
    p_add_sig.add_argument(
        "--body",
        dest="body_signals",
        action="append",
        default=[],
        metavar="TEXT",
        help="Body substring that signals session expiry (repeatable).",
    )
    p_add_sig.add_argument(
        "--status",
        dest="status_codes",
        action="append",
        type=int,
        default=[],
        metavar="CODE",
        help="HTTP status code that signals session expiry (repeatable).",
    )
    p_add_sig.add_argument(
        "--header",
        dest="header_signals",
        action="append",
        nargs=2,
        metavar=("NAME", "VALUE"),
        default=[],
        help="Header name + value substring that signals expiry (repeatable).",
    )

    p_clear_sig = sub.add_parser(
        "clear-expiry-signals",
        help="Clear all expiry signal configuration for a role.",
    )
    p_clear_sig.add_argument("role_id", help="UUID of the role.")

    # ---- session health: validation endpoint ----
    p_set_val = sub.add_parser(
        "set-validation",
        help="Set a validation endpoint for Layer 3 session health checking.",
    )
    p_set_val.add_argument("role_id", help="UUID of the role.")
    p_set_val.add_argument("url", help="Full URL to validate the session against.")
    p_set_val.add_argument(
        "--expected-status",
        type=int,
        default=200,
        metavar="CODE",
        help="Expected HTTP status from the validation endpoint (default: 200).",
    )
    p_set_val.add_argument(
        "--body-contains",
        dest="body_contains",
        action="append",
        default=[],
        metavar="TEXT",
        help="String that must appear in validation response body (repeatable).",
    )
    p_set_val.add_argument(
        "--body-not-contains",
        dest="body_not_contains",
        action="append",
        default=[],
        metavar="TEXT",
        help="String that must NOT appear in validation response body (repeatable).",
    )

    p_clear_val = sub.add_parser(
        "clear-validation",
        help="Clear the validation endpoint configuration for a role.",
    )
    p_clear_val.add_argument("role_id", help="UUID of the role.")

    # ---- session health: control flows ----
    p_add_cf = sub.add_parser(
        "add-control-flow",
        help="Add a control flow for Layer 4 session health checking.",
    )
    p_add_cf.add_argument("role_id", help="UUID of the role.")
    p_add_cf.add_argument("flow_id", help="UUID of the control flow.")

    p_rm_cf = sub.add_parser(
        "remove-control-flow",
        help="Remove a control flow from session health checking.",
    )
    p_rm_cf.add_argument("role_id", help="UUID of the role.")
    p_rm_cf.add_argument("flow_id", help="UUID of the flow.")

    p_list_cf = sub.add_parser(
        "list-control-flows",
        help="List all control flows for session health checking.",
    )
    p_list_cf.add_argument("role_id", help="UUID of the role.")

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    dispatch = {
        "add-flow":             lambda: cmd_add_flow(db_path, args),
        "remove-flow":          lambda: cmd_remove_flow(db_path, args),
        "list-flows":           lambda: cmd_list_flows(db_path, args),
        "set-extractor":        lambda: cmd_set_extractor(db_path, args),
        "show-extractor":       lambda: cmd_show_extractor(db_path, args),
        "edit-extractor":       lambda: cmd_edit_extractor(db_path, args),
        "remove-extractor":     lambda: cmd_remove_extractor(db_path, args),
        "test":                 lambda: cmd_test(db_path, project_id, args),
        "validate":             lambda: cmd_validate(db_path, project_id, args),
        "refresh":              lambda: cmd_refresh(db_path, project_id, args),
        "status":               lambda: cmd_status(db_path, args),
        "show":                 lambda: cmd_show(db_path, args),
        "set-ttl":              lambda: cmd_set_ttl(db_path, args),
        "add-expiry-signal":    lambda: cmd_add_expiry_signal(db_path, args),
        "clear-expiry-signals": lambda: cmd_clear_expiry_signals(db_path, args),
        "set-validation":       lambda: cmd_set_validation(db_path, args),
        "clear-validation":     lambda: cmd_clear_validation(db_path, args),
        "add-control-flow":     lambda: cmd_add_control_flow(db_path, args),
        "remove-control-flow":  lambda: cmd_remove_control_flow(db_path, args),
        "list-control-flows":   lambda: cmd_list_control_flows(db_path, args),
    }

    handler = dispatch.get(args.cmd)
    if handler is None:
        print(f"Unknown command: {args.cmd}", file=sys.stderr)
        sys.exit(1)
    handler()


# ------------------------------------------------------------------ #
# Flow management                                                      #
# ------------------------------------------------------------------ #

def cmd_add_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a flow to the role's auth config.
        Validates that both the role and the flow exist.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Inserts a row into auth_flow_config.
        Exits 1 if role/flow not found or already added.
    """
    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        print(f"Error: Flow '{args.flow_id}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        config_id = add_auth_flow(db_path, args.role_id, args.flow_id)
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            print(
                f"Error: Flow '{args.flow_id}' is already in the auth config for this role.",
                file=sys.stderr,
            )
        else:
            print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Flow added to auth config.")
    print(f"  role    : {args.role_id}")
    print(f"  flow    : {args.flow_id}")
    print(f"  config  : {config_id}")
    print("Next: talos auth-config set-extractor <role_id> <flow_id> <extractor.py>")


def cmd_remove_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a flow from the role's auth config.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Deletes the row from auth_flow_config.
        Exits 1 if not found.
    """
    removed = remove_auth_flow(db_path, args.role_id, args.flow_id)
    if not removed:
        print(
            f"Error: Flow '{args.flow_id}' not in auth config for role '{args.role_id}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Flow removed from auth config.")
    print(f"  role : {args.role_id}")
    print(f"  flow : {args.flow_id}")


def cmd_list_flows(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all flows in the role's auth config.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str).
    Side effects:
        Prints flow list to stdout.
    """
    configs = list_auth_flow_configs(db_path, args.role_id)
    if not configs:
        print(f"No flows configured for role '{args.role_id}'.")
        print("Use: talos auth-config add-flow <role_id> <flow_id>")
        return

    print(f"Auth flows for role {args.role_id}:")
    for i, cfg in enumerate(configs, 1):
        has_extractor = cfg["extractor_code"] is not None
        ext_label = "extractor: set" if has_extractor else "extractor: (none)"
        print(f"  [{i}] {cfg['flow_id']}  —  {ext_label}")


# ------------------------------------------------------------------ #
# Extractor management                                                 #
# ------------------------------------------------------------------ #

def cmd_set_extractor(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Read a Python extractor file and store its content in auth_flow_config.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str),
                  python_file (str path).
    Side effects:
        Reads the file; writes extractor_code to auth_flow_config.
        Exits 1 if the flow is not in auth config or the file can't be read.
    """
    file_path = Path(args.python_file)
    if not file_path.exists():
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        code = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate the extractor compiles and defines extract().
    _validate_extractor_code(code)

    updated = set_flow_extractor(db_path, args.role_id, args.flow_id, code)
    if not updated:
        print(
            f"Error: Flow '{args.flow_id}' not in auth config for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Extractor set.")
    print(f"  role : {args.role_id}")
    print(f"  flow : {args.flow_id}")
    print(f"  file : {file_path}")


def cmd_show_extractor(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Print the extractor code for a specific (role, flow) pair.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Prints extractor code to stdout.
    """
    code = get_flow_extractor(db_path, args.role_id, args.flow_id)
    if code is None:
        print(
            f"No extractor set for flow '{args.flow_id}' in role '{args.role_id}'.",
        )
        print("Use: talos auth-config set-extractor <role_id> <flow_id> <file.py>")
        return

    print(f"Extractor for role={args.role_id}  flow={args.flow_id}:")
    print("---")
    print(code)


def cmd_edit_extractor(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Open the extractor code in $EDITOR.  If no extractor exists yet, opens
        a blank template.  Saves the result back to the DB on editor exit.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Writes extractor_code to auth_flow_config.
        Exits 1 if flow not in auth config or editor not found.
    """
    # Verify the flow is in auth config.
    configs = list_auth_flow_configs(db_path, args.role_id)
    flow_ids = [c["flow_id"] for c in configs]
    if args.flow_id not in flow_ids:
        print(
            f"Error: Flow '{args.flow_id}' not in auth config for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    existing = get_flow_extractor(db_path, args.role_id, args.flow_id)
    template = existing if existing else _EXTRACTOR_TEMPLATE

    editor = os.environ.get("EDITOR", "vi")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="talos_extractor_",
        delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(template)
        tmp_path = tmp.name

    try:
        result = subprocess.run([editor, tmp_path])
        if result.returncode != 0:
            print(f"Editor exited with code {result.returncode}. Extractor not saved.", file=sys.stderr)
            sys.exit(1)

        code = Path(tmp_path).read_text(encoding="utf-8")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    if not code.strip():
        print("Empty extractor. Not saved.")
        return

    _validate_extractor_code(code)
    set_flow_extractor(db_path, args.role_id, args.flow_id, code)
    print("Extractor saved.")


def cmd_remove_extractor(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear the extractor code for a (role, flow) pair.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Sets extractor_code to NULL; prints confirmation.
    """
    removed = remove_flow_extractor(db_path, args.role_id, args.flow_id)
    if not removed:
        print(
            f"Error: Flow '{args.flow_id}' not in auth config for role '{args.role_id}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Extractor removed for flow '{args.flow_id}'.")


# ------------------------------------------------------------------ #
# Runtime commands                                                     #
# ------------------------------------------------------------------ #

def cmd_test(db_path: Path, project_id: str, args: argparse.Namespace) -> None:
    """
    Purpose:
        Replay a single flow, run its extractor, and show the returned artifacts.
        Does not validate against auth requirements and does not store state.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        args       — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Sends outbound HTTP; writes a replay flow row.
        Prints extracted artifacts to stdout.
    """
    code = get_flow_extractor(db_path, args.role_id, args.flow_id)
    if code is None:
        print(
            f"Error: No extractor set for flow '{args.flow_id}'. "
            "Run 'talos auth-config set-extractor' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Replaying flow {args.flow_id} ...")
    outcome = asyncio.run(
        replay_flow(
            flow_id=args.flow_id,
            db_path=db_path,
            project_id=project_id,
            source="manual_replay",
            replay_reason="auth_config_test",
        )
    )

    if not outcome.success or outcome.replayed_flow_id is None:
        print(f"Error: Replay failed — {outcome.failure_reason}.", file=sys.stderr)
        sys.exit(1)

    replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
    if replayed is None:
        print("Error: Replayed flow not found in DB.", file=sys.stderr)
        sys.exit(1)

    response = _build_response_obj(replayed)

    print(f"  replay status : {outcome.status_code}")
    print("Running extractor ...")

    artifacts = _run_extractor(code, response)
    if artifacts is None:
        print("Error: Extractor raised an exception (see above).", file=sys.stderr)
        sys.exit(1)

    if not artifacts:
        print("Extractor returned empty dict — no artifacts extracted.")
    else:
        print("Extracted artifacts:")
        for k, v in artifacts.items():
            display = v[:40] + "..." if len(str(v)) > 40 else str(v)
            print(f"  {k} = {display}")


def cmd_validate(db_path: Path, project_id: str, args: argparse.Namespace) -> None:
    """
    Purpose:
        Run all flows for a role, execute their extractors, merge the results,
        and validate the collected artifacts against the required auth config.
        Prints pass/fail for each required artifact.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        args       — parsed args with: role_id (str).
    Side effects:
        Sends outbound HTTP; writes replay flow rows; prints validation result.
        Exits 1 if required artifacts are missing.
    """
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    if not required:
        print(
            "Error: No auth requirements configured. "
            "Run 'talos auth set --cookie <name>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    merged, errors = _run_all_flows_and_extract(db_path, project_id, args.role_id)

    if errors:
        for err in errors:
            print(f"  Warning: {err}", file=sys.stderr)

    print("Required Auth:")
    all_ok = True
    for name in sorted(required):
        if name in merged:
            print(f"  \u2713 {name}")
        else:
            print(f"  \u2717 {name}")
            all_ok = False

    if all_ok:
        print("\nAuthentication Configuration Valid")
    else:
        print("\nMissing Authentication Artifact", file=sys.stderr)
        sys.exit(1)


def cmd_refresh(db_path: Path, project_id: str, args: argparse.Namespace) -> None:
    """
    Purpose:
        Force regeneration of the full auth state for a role.
        Runs all configured flows, executes extractors, validates against auth
        requirements, and stores the result in role_auth_state.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        args       — parsed args with: role_id (str).
    Side effects:
        Sends outbound HTTP; writes replay flow rows and role_auth_state.
        Exits 1 on flow/extraction/validation failure.
    """
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    if not required:
        print(
            "Error: No auth requirements configured. "
            "Run 'talos auth set --cookie <name>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    configs = list_auth_flow_configs(db_path, args.role_id)
    if not configs:
        print(
            f"Error: No flows configured for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    merged, errors = _run_all_flows_and_extract(db_path, project_id, args.role_id)

    if errors:
        for err in errors:
            print(f"  Warning: {err}")

    missing = required - set(merged.keys())
    if missing:
        print(f"Error: Missing artifacts after refresh: {', '.join(sorted(missing))}", file=sys.stderr)
        sys.exit(1)

    collected_at = datetime.now(timezone.utc).isoformat()
    store_role_auth_state(db_path, args.role_id, merged, collected_at)

    print(f"Auth state refreshed for role {args.role_id}.")
    print(f"  collected_at : {collected_at}")
    for k in sorted(merged.keys()):
        v = str(merged[k])
        display = v[:40] + "..." if len(v) > 40 else v
        print(f"  {k} = {display}")


def cmd_status(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show the current auth state (collected artifacts + age) for a role.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str).
    Side effects:
        Prints auth state to stdout.
    """
    result = get_role_auth_state(db_path, args.role_id)
    health_cfg = get_session_health_config(db_path, args.role_id)
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    print(f"Role: {args.role_id}\n")

    if not result["state"]:
        print("  No auth state collected.")
        print("  Run: talos auth-config refresh <role_id>")
        return

    collected_at_str = result["collected_at"]
    collected_at = datetime.fromisoformat(collected_at_str)
    now = datetime.now(timezone.utc)
    age_s = (now - collected_at.replace(tzinfo=timezone.utc)).total_seconds()
    ttl = health_cfg["ttl_seconds"]
    expires_in = ttl - age_s

    for name in sorted(required):
        tick = "\u2713" if name in result["state"] else "\u2717"
        print(f"  {tick}  {name}")

    print()
    print(f"  Generated : {collected_at_str}")
    if expires_in > 0:
        print(f"  Expires   : in {int(expires_in)}s  (TTL: {ttl}s)")
    else:
        print(f"  Expired   : {int(-expires_in)}s ago  (TTL: {ttl}s)")


def cmd_show(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show the complete auth-config for a role: required artifacts, flows,
        extractors, and session health configuration.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str).
    Side effects:
        Prints complete config to stdout.
    """
    auth_req = get_auth_config(db_path)
    flow_configs = list_auth_flow_configs(db_path, args.role_id)
    health_cfg = get_session_health_config(db_path, args.role_id)
    control_flows = list_session_health_control_flows(db_path, args.role_id)

    print(f"Role: {args.role_id}\n")

    print("Required Auth:")
    for name in auth_req["cookies"]:
        print(f"  - {name}  (cookie)")
    for name in auth_req["headers"]:
        print(f"  - {name}  (header)")
    if not auth_req["cookies"] and not auth_req["headers"]:
        print("  (none — run 'talos auth set')")

    print("\nFlows:")
    if not flow_configs:
        print("  (none — run 'talos auth-config add-flow')")
    for cfg in flow_configs:
        ext = "set" if cfg["extractor_code"] else "(none)"
        print(f"  - {cfg['flow_id']}")
        print(f"      extractor: {ext}")

    print("\nSession Health:")
    print(f"  TTL              : {health_cfg['ttl_seconds']}s")
    print(f"  Refresh before   : {health_cfg['refresh_before_seconds']}s")

    body_sigs = health_cfg["expiry_body_signals"]
    status_codes = health_cfg["expiry_status_codes"]
    header_sigs = health_cfg["expiry_header_signals"]
    if body_sigs or status_codes or header_sigs:
        print("  Expiry signals:")
        for s in body_sigs:
            print(f"    body_contains: {s!r}")
        for c in status_codes:
            print(f"    status_code  : {c}")
        for hdr, vals in header_sigs.items():
            for v in vals:
                print(f"    header       : {hdr} = {v!r}")
    else:
        print("  Expiry signals   : (none)")

    if health_cfg["validation_endpoint_url"]:
        print(f"  Validation URL   : {health_cfg['validation_endpoint_url']}")
        print(f"  Expected status  : {health_cfg['validation_expected_status']}")
    else:
        print("  Validation URL   : (none)")

    if control_flows:
        print("  Control flows:")
        for fid in control_flows:
            print(f"    - {fid}")
    else:
        print("  Control flows    : (none)")


# ------------------------------------------------------------------ #
# Session health commands                                              #
# ------------------------------------------------------------------ #

def cmd_set_ttl(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Configure TTL-based refresh for a role (Layer 1).
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args: role_id (str), ttl (int),
                  refresh_before (int|None).
    Side effects:
        Upserts session_health_config row; prints confirmation.
    """
    kwargs: dict = {"ttl_seconds": args.ttl}
    if args.refresh_before is not None:
        kwargs["refresh_before_seconds"] = args.refresh_before

    set_session_health_config(db_path, args.role_id, **kwargs)

    rb = args.refresh_before if args.refresh_before is not None else "(unchanged)"
    print(f"Session health TTL updated for role {args.role_id}.")
    print(f"  ttl            : {args.ttl}s")
    print(f"  refresh_before : {rb}")


def cmd_add_expiry_signal(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Append expiry signals to the session health config (Layer 2).
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args: role_id, body_signals (list), status_codes (list),
                  header_signals (list of [name, value] pairs).
    Side effects:
        Merges new signals into the existing session_health_config row.
    """
    if not args.body_signals and not args.status_codes and not args.header_signals:
        print(
            "Error: Provide at least one --body, --status, or --header signal.",
            file=sys.stderr,
        )
        sys.exit(1)

    current = get_session_health_config(db_path, args.role_id)

    body = list(current["expiry_body_signals"])
    for s in args.body_signals:
        if s not in body:
            body.append(s)

    codes = list(current["expiry_status_codes"])
    for c in args.status_codes:
        if c not in codes:
            codes.append(c)

    header_sigs: dict = dict(current["expiry_header_signals"])
    for name, value in args.header_signals:
        header_sigs.setdefault(name.lower(), [])
        if value not in header_sigs[name.lower()]:
            header_sigs[name.lower()].append(value)

    set_session_health_config(
        db_path,
        args.role_id,
        expiry_body_signals=body,
        expiry_status_codes=codes,
        expiry_header_signals=header_sigs,
    )
    print(f"Expiry signals updated for role {args.role_id}.")
    if args.body_signals:
        print(f"  body   : {args.body_signals}")
    if args.status_codes:
        print(f"  status : {args.status_codes}")
    if args.header_signals:
        for name, value in args.header_signals:
            print(f"  header : {name} = {value!r}")


def cmd_clear_expiry_signals(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear all expiry signal configuration for a role.
    Side effects:
        Resets body, status, and header signals to empty in session_health_config.
    """
    set_session_health_config(
        db_path,
        args.role_id,
        expiry_body_signals=[],
        expiry_status_codes=[],
        expiry_header_signals={},
    )
    print(f"Expiry signals cleared for role {args.role_id}.")


def cmd_set_validation(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set or replace the validation endpoint for Layer 3 health checking.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args: role_id (str), url (str),
                  expected_status (int), body_contains (list),
                  body_not_contains (list).
    Side effects:
        Upserts session_health_config; prints confirmation.
    """
    set_session_health_config(
        db_path,
        args.role_id,
        validation_endpoint_url=args.url,
        validation_expected_status=args.expected_status,
        validation_body_contains=args.body_contains,
        validation_body_not_contains=args.body_not_contains,
    )
    print(f"Validation endpoint configured for role {args.role_id}.")
    print(f"  url             : {args.url}")
    print(f"  expected status : {args.expected_status}")
    if args.body_contains:
        print(f"  body contains   : {args.body_contains}")
    if args.body_not_contains:
        print(f"  body not contains: {args.body_not_contains}")


def cmd_clear_validation(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove the validation endpoint configuration for a role.
    Side effects:
        Sets validation_endpoint_url to None in session_health_config.
    """
    set_session_health_config(
        db_path,
        args.role_id,
        validation_endpoint_url=None,
        validation_body_contains=[],
        validation_body_not_contains=[],
    )
    print(f"Validation endpoint cleared for role {args.role_id}.")


def cmd_add_control_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a control flow for Layer 4 session health checking.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args: role_id (str), flow_id (str).
    Side effects:
        Inserts into session_health_control_flows.
    """
    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        print(f"Error: Flow '{args.flow_id}' not found.", file=sys.stderr)
        sys.exit(1)

    inserted = add_session_health_control_flow(db_path, args.role_id, args.flow_id)
    if not inserted:
        print(f"Control flow '{args.flow_id}' already added for role '{args.role_id}'.")
    else:
        print(f"Control flow added.")
        print(f"  role : {args.role_id}")
        print(f"  flow : {args.flow_id}")


def cmd_remove_control_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a control flow from session health checking.
    Side effects:
        Deletes from session_health_control_flows.
        Exits 1 if not found.
    """
    removed = remove_session_health_control_flow(db_path, args.role_id, args.flow_id)
    if not removed:
        print(
            f"Error: Control flow '{args.flow_id}' not found for role '{args.role_id}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Control flow removed: {args.flow_id}")


def cmd_list_control_flows(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all control flows configured for a role.
    Side effects:
        Prints flow IDs to stdout.
    """
    flows = list_session_health_control_flows(db_path, args.role_id)
    if not flows:
        print(f"No control flows configured for role '{args.role_id}'.")
        print("Use: talos auth-config add-control-flow <role_id> <flow_id>")
        return

    print(f"Control flows for role {args.role_id}:")
    for fid in flows:
        print(f"  - {fid}")


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

_EXTRACTOR_TEMPLATE = """\
def extract(response):
    \"\"\"
    Extract authentication artifacts from the replay response.

    Parameters:
        response.status   (int)  — HTTP status code
        response.headers  (dict) — lowercase header names → values
        response.body     (str)  — decoded response body
        response.cookies  (dict) — cookie name → value

    Return:
        dict mapping artifact names to values.
        Keys must match the names in 'talos auth show'.

    Example:
        return {
            "sessionid": response.cookies.get("sessionid", ""),
            "Authorization": "Bearer " + response.body.split('"token":"')[1].split('"')[0],
        }
    \"\"\"
    return {}
"""


def _validate_extractor_code(code: str) -> None:
    """
    Purpose:
        Compile the extractor code and verify it defines an extract() function.
        Exits 1 with a clear error if the code is invalid Python or missing the
        function definition.
    Input:  code — Python source string.
    Output: None
    Side effects:
        Exits 1 on syntax error or missing extract().
    """
    try:
        compiled = compile(code, "<extractor>", "exec")
    except SyntaxError as exc:
        print(f"Error: Extractor has a syntax error: {exc}", file=sys.stderr)
        sys.exit(1)

    ns: dict = {}
    try:
        exec(compiled, ns)  # noqa: S102
    except Exception as exc:
        print(f"Error: Extractor raised exception during load: {exc}", file=sys.stderr)
        sys.exit(1)

    if "extract" not in ns or not callable(ns["extract"]):
        print(
            "Error: Extractor must define a callable named 'extract(response)'.",
            file=sys.stderr,
        )
        sys.exit(1)


def _build_response_obj(flow: dict) -> types.SimpleNamespace:
    """
    Purpose:
        Build a simple response namespace from a replayed flow dict so that
        extractor scripts can access .status, .headers, .body, .cookies.
    Input:  flow — flow dict from replay_db.get_flow_for_replay().
    Output: SimpleNamespace with status, headers, body, cookies.
    Side effects: None.
    """
    import json as _json

    status: int = flow.get("status_code") or 0

    raw_headers = flow.get("response_headers", "{}")
    if isinstance(raw_headers, str):
        try:
            headers: dict = _json.loads(raw_headers)
        except (ValueError, TypeError):
            headers = {}
    else:
        headers = dict(raw_headers)
    headers = {k.lower(): v for k, v in headers.items()}

    raw_body = flow.get("response_body", b"")
    if isinstance(raw_body, (bytes, bytearray)):
        body: str = raw_body.decode("utf-8", errors="replace")
    else:
        body = str(raw_body) if raw_body else ""

    raw_cookies = flow.get("request_cookies", "{}")
    if isinstance(raw_cookies, str):
        try:
            cookies: dict = _json.loads(raw_cookies)
        except (ValueError, TypeError):
            cookies = {}
    else:
        cookies = dict(raw_cookies)

    # Also parse Set-Cookie headers from response for cookie extraction.
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        for part in set_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies.setdefault(k.strip(), v.strip())

    return types.SimpleNamespace(
        status=status,
        headers=headers,
        body=body,
        cookies=cookies,
    )


def _run_extractor(
    code: str,
    response: types.SimpleNamespace,
) -> Optional[dict]:
    """
    Purpose:
        Execute the extractor code in an isolated namespace and call extract().
    Input:
        code     — Python source of the extractor.
        response — SimpleNamespace passed to extract().
    Output:
        Dict returned by extract(), or None if an exception was raised.
    Side effects:
        Prints exception traceback to stderr on error.
    """
    ns: dict = {}
    try:
        exec(compile(code, "<extractor>", "exec"), ns)  # noqa: S102
        result = ns["extract"](response)
    except Exception as exc:  # noqa: BLE001
        import traceback
        print("Extractor exception:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None

    if not isinstance(result, dict):
        print(
            f"Error: extract() must return a dict, got {type(result).__name__}.",
            file=sys.stderr,
        )
        return None

    return {str(k): str(v) for k, v in result.items()}


def _run_all_flows_and_extract(
    db_path: Path,
    project_id: str,
    role_id: str,
) -> tuple[dict, list[str]]:
    """
    Purpose:
        Replay all configured flows for a role, execute their extractors, and
        merge the resulting key-value pairs into a single dict.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        role_id    — UUID of the role.
    Output:
        (merged_dict, errors) where merged_dict is the union of all extractor
        results (later flows overwrite earlier ones on key conflicts) and errors
        is a list of non-fatal warning strings.
    Side effects:
        Sends outbound HTTP; writes replay flow rows.
    """
    configs = list_auth_flow_configs(db_path, role_id)
    merged: dict = {}
    errors: list[str] = []

    for cfg in configs:
        flow_id = cfg["flow_id"]
        code = cfg["extractor_code"]

        if code is None:
            errors.append(f"No extractor for flow {flow_id} — skipped.")
            continue

        print(f"  Replaying {flow_id} ...")
        outcome = asyncio.run(
            replay_flow(
                flow_id=flow_id,
                db_path=db_path,
                project_id=project_id,
                source="manual_replay",
                replay_reason="auth_config_refresh",
            )
        )

        if not outcome.success or outcome.replayed_flow_id is None:
            errors.append(f"Flow {flow_id} replay failed: {outcome.failure_reason}")
            continue

        replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
        if replayed is None:
            errors.append(f"Flow {flow_id}: replayed flow not found in DB.")
            continue

        response = _build_response_obj(replayed)
        artifacts = _run_extractor(code, response)

        if artifacts is None:
            errors.append(f"Flow {flow_id}: extractor raised an exception.")
            continue

        merged.update(artifacts)
        print(f"  Extracted {len(artifacts)} artifact(s) from {flow_id}.")

    return merged, errors


def _role_exists(db_path: Path, role_id: str) -> bool:
    """
    Purpose:
        Return True if a role with the given ID exists in the project database.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID string to look up.
    Output: bool
    Side effects: None (read-only).
    """
    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT 1 FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
    return row is not None
