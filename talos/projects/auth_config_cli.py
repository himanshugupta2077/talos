"""
Module: talos.projects.auth_config_cli

Purpose:
    Command-line interface for the auth-config model: multi-flow authentication
    with per-flow Python extractor scripts and a Session Health Engine.

    Role arguments accept a role name or UUID. Names are resolved once at
    dispatch (CLI-001) so scripts can use human-readable role labels.

    Flow management:
        talos auth-config add-flow      <role> <flow_id>
        talos auth-config remove-flow   <role> <flow_id>
        talos auth-config list-flows    <role>

    Extractor management:
        talos auth-config set-extractor    <role> <flow_id> <python_file>
        talos auth-config show-extractor   <role> <flow_id>
        talos auth-config edit-extractor   <role> <flow_id>
        talos auth-config remove-extractor <role> <flow_id>

    Runtime:
        talos auth-config test     <role> <flow_id>   Run one flow + extractor; show results.
        talos auth-config validate <role>              Run all flows; validate against auth requirements.
        talos auth-config refresh  <role>              Force regeneration of full auth state.
        talos auth-config status   <role>              Show current auth state + age.
        talos auth-config show     <role>              Show complete configuration.

    Session Health Engine (three layers):
        Layer 1 — TTL:
        talos auth-config set-ttl         <role> --ttl <s> [--refresh-before <s>]
        Layer 2 — Expiry signals:
        talos auth-config add-expiry-signal   <role> [--body TEXT ...] [--status CODE ...] [--header NAME VALUE]
        talos auth-config clear-expiry-signals <role>
        Layer 3 — Validation flows (control flows; no URL CLI):
        talos auth-config add-control-flow    <role> <flow_id>
        talos auth-config remove-control-flow <role> <flow_id>
        talos auth-config list-control-flows  <role>

    Provider / manual session:
        talos auth-config set-provider    <role> auto|manual
        talos auth-config show-provider   <role>
        talos auth-config set-session     <role> [path]

    Session recovery (CLI-021):
        talos auth-config clear-session   <role>   Clear manual session config
        talos auth-config reset-health    <role>   Reset Layer 2 suspicion counter

    The extractor is a Python file with this signature:
        def extract(response):
            # response.status   — HTTP status code (int)
            # response.headers  — header dict (lowercase keys)
            # response.body     — decoded body text (str)
            # response.cookies  — cookie dict
            return {"artifact_name": "value"}

Dependencies: argparse, asyncio, json, os, subprocess, sys, tempfile
              talos.projects.manager, talos.projects.auth, talos.projects.access,
              talos.replay.db, talos.replay.engine
Data flow:
    CLI args → resolve role name/UUID → active project DB → auth CRUD /
    replay engine → stdout
Side effects:
    - Flow/extractor commands write to auth_flow_config table.
    - refresh/validate/test send outbound HTTP; write role_auth_state.
    - Session health commands write to session_health_config /
      session_health_control_flows.
    - clear-session deletes manual_session_config; reset-health zeros
      session_suspicion_state (CLI-021 recovery).
    - All commands require a bound project (registry ACTIVE, --project, or TALOS_PROJECT).
    - Exits 1 on hard errors.
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
import asyncio
import json
import os
import platform
import subprocess
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.manager import ProjectManager
from talos.projects.access import resolve_role
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
    reset_suspicion,
)
from talos.projects.auth_provider import (
    PROVIDER_AUTO,
    PROVIDER_MANUAL,
    VALID_PROVIDERS,
    SESSION_READY,
    SESSION_EXPIRING,
    SESSION_EXPIRED,
    SESSION_FAILED,
    SESSION_WAITING_FOR_USER,
    get_provider,
    set_provider,
    get_manual_session_config,
    set_manual_session_config,
    clear_manual_session_config,
    get_manual_session_expiry,
    get_session_display_state,
    parse_session_file,
    format_session_template,
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
    p_add_flow.add_argument("role_id", help="Role name or UUID.")
    p_add_flow.add_argument("flow_id", help="UUID of the flow to add.")

    p_remove_flow = sub.add_parser("remove-flow", help="Remove a flow from the role's auth config.")
    p_remove_flow.add_argument("role_id", help="Role name or UUID.")
    p_remove_flow.add_argument("flow_id", help="UUID of the flow to remove.")

    p_list_flows = sub.add_parser("list-flows", help="List flows in the role's auth config.")
    p_list_flows.add_argument("role_id", help="Role name or UUID.")
    add_format_argument(p_list_flows)

    # ---- extractor management ----
    p_set_ext = sub.add_parser("set-extractor", help="Attach a Python extractor to a flow.")
    p_set_ext.add_argument("role_id", help="Role name or UUID.")
    p_set_ext.add_argument("flow_id", help="UUID of the flow.")
    p_set_ext.add_argument("python_file", help="Path to the Python extractor file.")

    p_show_ext = sub.add_parser("show-extractor", help="Print the extractor code for a flow.")
    p_show_ext.add_argument("role_id", help="Role name or UUID.")
    p_show_ext.add_argument("flow_id", help="UUID of the flow.")
    add_format_argument(p_show_ext)

    p_edit_ext = sub.add_parser(
        "edit-extractor",
        help="Open the extractor in $EDITOR (creates a blank template if none set).",
    )
    p_edit_ext.add_argument("role_id", help="Role name or UUID.")
    p_edit_ext.add_argument("flow_id", help="UUID of the flow.")

    p_rm_ext = sub.add_parser("remove-extractor", help="Delete the extractor for a flow.")
    p_rm_ext.add_argument("role_id", help="Role name or UUID.")
    p_rm_ext.add_argument("flow_id", help="UUID of the flow.")

    # ---- runtime commands ----
    p_test = sub.add_parser(
        "test",
        help="Run a single flow, execute its extractor, and show returned artifacts.",
    )
    p_test.add_argument("role_id", help="Role name or UUID.")
    p_test.add_argument("flow_id", help="UUID of the flow.")
    add_format_argument(p_test)

    p_validate = sub.add_parser(
        "validate",
        help="Validate a role's session (MANUAL: control flows; AUTO: login extractors).",
    )
    p_validate.add_argument("role_id", help="Role name or UUID.")
    p_validate.add_argument(
        "--flow",
        dest="flow_ids",
        action="append",
        default=[],
        metavar="FLOW_ID",
        help=(
            "Limit Layer 3 validation to this control flow UUID (repeatable). "
            "Default: all configured validation flows. MANUAL provider only."
        ),
    )

    p_refresh = sub.add_parser(
        "refresh",
        help="Force regeneration of the full auth state for a role.",
    )
    p_refresh.add_argument("role_id", help="Role name or UUID.")

    p_status = sub.add_parser(
        "status",
        help="Show the current auth state (collected values + age) for a role.",
    )
    p_status.add_argument("role_id", help="Role name or UUID.")
    add_format_argument(p_status)

    p_show = sub.add_parser(
        "show",
        help="Show the complete auth-config for a role (flows, extractors, health config).",
    )
    p_show.add_argument("role_id", help="Role name or UUID.")
    add_format_argument(p_show)

    # ---- session health: TTL ----
    p_set_ttl = sub.add_parser(
        "set-ttl",
        help="Configure TTL-based session refresh for a role (Layer 1).",
    )
    p_set_ttl.add_argument("role_id", help="Role name or UUID.")
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
    p_add_sig.add_argument("role_id", help="Role name or UUID.")
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
    p_clear_sig.add_argument("role_id", help="Role name or UUID.")
    add_force_argument(p_clear_sig)

    # ---- session health: validation flows ----
    p_add_cf = sub.add_parser(
        "add-control-flow",
        help="Add a validation flow for session health checking.",
    )
    p_add_cf.add_argument("role_id", help="Role name or UUID.")
    p_add_cf.add_argument("flow_id", help="UUID of the validation flow.")

    p_rm_cf = sub.add_parser(
        "remove-control-flow",
        help="Remove a validation flow from session health checking.",
    )
    p_rm_cf.add_argument("role_id", help="Role name or UUID.")
    p_rm_cf.add_argument("flow_id", help="UUID of the flow.")

    p_list_cf = sub.add_parser(
        "list-control-flows",
        help="List all validation flows for session health checking.",
    )
    p_list_cf.add_argument("role_id", help="Role name or UUID.")
    add_format_argument(p_list_cf)

    # ---- authentication provider ----
    p_set_prov = sub.add_parser(
        "set-provider",
        help="Set the authentication provider for a role (auto or manual).",
    )
    p_set_prov.add_argument("role_id", help="Role name or UUID.")
    p_set_prov.add_argument(
        "provider",
        choices=list(VALID_PROVIDERS),
        help="Provider type: 'auto' (replay login flows) or 'manual' (tester supplies artifacts).",
    )

    p_show_prov = sub.add_parser(
        "show-provider",
        help="Show the configured authentication provider for a role.",
    )
    p_show_prov.add_argument("role_id", help="Role name or UUID.")
    add_format_argument(p_show_prov)

    p_set_session = sub.add_parser(
        "set-session",
        help=(
            "Manage the manual session config file for a role. Two forms:\n"
            "  talos auth-config set-session <role> path   — print (creating if needed)\n"
            "                                                 the session file path;\n"
            "                                                 edit it by hand.\n"
            "  talos auth-config set-session <role>         — parse the edited file,\n"
            "                                                 validate, and apply it.\n"
            "  <role> is a role name or UUID."
        ),
    )
    p_set_session.add_argument("role_id", help="Role name or UUID.")
    p_set_session.add_argument(
        "action",
        nargs="?",
        default=None,
        choices=["path"],
        help=(
            "If 'path', print the session file path (creating a template if it "
            "does not exist yet) and exit without parsing or applying anything."
        ),
    )

    # ---- session recovery (CLI-021) ----
    p_clear_session = sub.add_parser(
        "clear-session",
        help=(
            "Clear the manual session configuration for a role "
            "(recovery from WAITING_FOR_USER / bad session)."
        ),
    )
    p_clear_session.add_argument("role_id", help="Role name or UUID.")

    p_reset_health = sub.add_parser(
        "reset-health",
        help=(
            "Reset the session health suspicion counter for a role "
            "(recovery from permanently degraded Layer 2 confidence)."
        ),
    )
    p_reset_health.add_argument("role_id", help="Role name or UUID.")

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")

    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    # Accept role name or UUID on every subcommand that takes role_id (CLI-001).
    if getattr(args, "role_id", None) is not None:
        args.role_id = _resolve_role_id(db_path, args.role_id)

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
        "add-control-flow":     lambda: cmd_add_control_flow(db_path, args),
        "remove-control-flow":  lambda: cmd_remove_control_flow(db_path, args),
        "list-control-flows":   lambda: cmd_list_control_flows(db_path, args),
        "set-provider":         lambda: cmd_set_provider(db_path, args),
        "show-provider":        lambda: cmd_show_provider(db_path, args),
        "set-session":          lambda: cmd_set_session(project, args),
        "clear-session":        lambda: cmd_clear_session(db_path, args),
        "reset-health":         lambda: cmd_reset_health(db_path, args),
    }

    handler = dispatch.get(args.cmd)
    if handler is None:
        cli_usage_error(f"Unknown command: {args.cmd}")
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
        cli_error(f"Role '{args.role_id}' not found.")

    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        cli_error(f"Flow '{args.flow_id}' not found.")

    try:
        config_id = add_auth_flow(db_path, args.role_id, args.flow_id)
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            cli_error(
                f"Flow '{args.flow_id}' is already in the auth config for this role."
            )
        else:
            cli_error(str(exc))

    print(f"Flow added to auth config.")
    print(f"  role    : {args.role_id}")
    print(f"  flow    : {args.flow_id}")
    print(f"  config  : {config_id}")
    print("Next: talos auth-config set-extractor <role> <flow_id> <extractor.py>")


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
        cli_error(f"Flow '{args.flow_id}' not in auth config for role '{args.role_id}'.")
    print(f"Flow removed from auth config.")
    print(f"  role : {args.role_id}")
    print(f"  flow : {args.flow_id}")


def cmd_list_flows(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all flows in the role's auth config.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), optional output_format.
    Side effects:
        Prints flow list to stdout (table or JSON).
    """
    configs = list_auth_flow_configs(db_path, args.role_id)
    if wants_json(args):
        cli_json([
            {
                "flow_id": cfg["flow_id"],
                "role_id": cfg.get("role_id", args.role_id),
                "has_extractor": cfg.get("extractor_code") is not None,
            }
            for cfg in configs
        ])
        return

    if not configs:
        print(f"No flows configured for role '{args.role_id}'.")
        print("Use: talos auth-config add-flow <role> <flow_id>")
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
        cli_error(f"File '{file_path}' not found.")

    try:
        code = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        cli_error(f"Error reading file: {exc}")

    # Validate the extractor compiles and defines extract().
    _validate_extractor_code(code)

    updated = set_flow_extractor(db_path, args.role_id, args.flow_id, code)
    if not updated:
        cli_error(
            f"Flow '{args.flow_id}' not in auth config for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first."
        )

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
        Prints extractor code to stdout (or JSON envelope with code).
    """
    code = get_flow_extractor(db_path, args.role_id, args.flow_id)
    if wants_json(args):
        cli_json({
            "role_id": args.role_id,
            "flow_id": args.flow_id,
            "extractor_code": code,
        })
        return

    if code is None:
        print(
            f"No extractor set for flow '{args.flow_id}' in role '{args.role_id}'.",
        )
        print("Use: talos auth-config set-extractor <role> <flow_id> <file.py>")
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
        cli_error(
            f"Flow '{args.flow_id}' not in auth config for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first."
        )

    existing = get_flow_extractor(db_path, args.role_id, args.flow_id)
    template = existing if existing else _EXTRACTOR_TEMPLATE

    if platform.system() == "Windows":
        editor = "notepad.exe"
    else:
        editor = "subl"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="talos_extractor_",
        delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(template)
        tmp_path = tmp.name

    try:
        result = subprocess.run([editor, tmp_path])
    except FileNotFoundError:
        cli_error(f"Editor '{editor}' was not found.")

    code = Path(tmp_path).read_text(encoding="utf-8")
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
        cli_error(f"Flow '{args.flow_id}' not in auth config for role '{args.role_id}'.")
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
        args       — parsed args with: role_id (str), flow_id (str),
                     optional output_format (table|json).
    Side effects:
        Sends outbound HTTP; writes a replay flow row.
        Prints extracted artifacts to stdout (full values; JSON via --format json).
    """
    code = get_flow_extractor(db_path, args.role_id, args.flow_id)
    if code is None:
        cli_error(
            f"No extractor set for flow '{args.flow_id}'. "
            "Run 'talos auth-config set-extractor' first."
        )

    if not wants_json(args):
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
        cli_error(f"Replay failed — {outcome.failure_reason}.")

    replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
    if replayed is None:
        cli_error("Replayed flow not found in DB.")

    response = _build_response_obj(replayed)

    if not wants_json(args):
        print(f"  replay status : {outcome.status_code}")
        print("Running extractor ...")

    artifacts = _run_extractor(code, response)
    if artifacts is None:
        cli_error("Extractor raised an exception (see above).")

    # Coerce values to strings for stable JSON / table output (full values).
    artifacts_out = {str(k): str(v) for k, v in (artifacts or {}).items()}

    if wants_json(args):
        cli_json(
            {
                "role_id": args.role_id,
                "flow_id": args.flow_id,
                "replay_flow_id": outcome.replayed_flow_id,
                "replay_status": outcome.status_code,
                "artifacts": artifacts_out,
                "stored": False,
            }
        )
        return

    if not artifacts_out:
        print("Extractor returned empty dict — no artifacts extracted.")
    else:
        print("Extracted artifacts (full values):")
        for k, v in artifacts_out.items():
            print(f"  {k} = {v}")


def cmd_validate(db_path: Path, project_id: str, args: argparse.Namespace) -> None:
    """
    Purpose:
        Validate the current auth state for a role.  Works for both AUTO and
        MANUAL providers.

        MANUAL — Verifies in this order:
                    1. Auth artifact names are configured ('talos auth set').
                    2. Manual session values exist and are not expired.
                    3. A validation method (control flow or validation endpoint)
                       is configured — validation is mandatory.
                    4. Artifacts are applied to role_auth_state.
                    5. Validation request succeeds using the configured session.
                 If any check fails the command exits 1.  Session is only
                 marked READY after all checks pass.

        AUTO   — Verifies:
                    1. Auth artifact names are configured.
                    2. At least one flow with an extractor is configured.
                    3. All required artifacts are extractable from flows.
                 If any check fails the command exits 1.

    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        args       — parsed args with: role_id (str).
    Side effects:
        MANUAL: may send outbound HTTP for validation; writes role_auth_state.
        AUTO:   sends outbound HTTP; writes replay flow rows.
        Prints validation result; exits 1 on failure.
    """
    provider = get_provider(db_path, args.role_id)

    if provider == PROVIDER_MANUAL:
        # Check 1: auth artifact names must be configured.
        auth_req = get_auth_config(db_path)
        if not auth_req["cookies"] and not auth_req["headers"]:
            cli_precondition_error(
                "No auth requirements configured. "
                "Run 'talos auth set --cookie <name>' or '--header <name>' first."
            )

        # Check 2: manual session values must exist and not be expired.
        cfg = get_manual_session_config(db_path, args.role_id)
        if cfg is None:
            cli_precondition_error(
                f"No manual session configured for role '{args.role_id}'. "
                "Run 'talos auth-config set-session' first."
            )

        from talos.projects.auth_provider import apply_manual_session
        applied = apply_manual_session(db_path, args.role_id)
        if not applied:
            expiry = get_manual_session_expiry(db_path, args.role_id)
            if expiry is None:
                cli_error(
                    "Manual session has no TTL or expiry set. "
                    "Run 'talos auth-config set-session' to add expiry.",
                    exit_code=None,
                )
            else:
                cli_error(
                    "Manual session has expired. "
                    "Run 'talos auth-config set-session' to update credentials.",
                    exit_code=None,
                )
            print("  Status: WAITING_FOR_USER")
            sys.exit(1)

        # Check 3: at least one validation flow must be configured.
        control_flows = list_session_health_control_flows(db_path, args.role_id)
        if not control_flows:
            cli_precondition_error(
                "No validation flow configured for this role. "
                "Run: talos auth-config add-control-flow <role> <flow_id>"
            )

        flow_filter = list(getattr(args, "flow_ids", None) or [])
        if flow_filter:
            unknown = [f for f in flow_filter if f not in control_flows]
            if unknown:
                cli_error(
                    "Flow(s) not configured as validation flows for this role: "
                    + ", ".join(unknown)
                )
            control_flows = flow_filter

        # Check 4+5: run validation using applied artifacts.
        from talos.projects.session_health import validate_session
        state_info = get_role_auth_state(db_path, args.role_id)
        alive = validate_session(
            db_path,
            args.role_id,
            project_id,
            state_info["state"],
            control_flow_ids=control_flows,
        )
        if alive:
            print(f"  Status: {SESSION_READY}")
            if flow_filter:
                print(f"  Validated flow(s): {', '.join(flow_filter)}")
        else:
            print("  Status: FAILED", file=sys.stderr)
            cli_error(
                "Validation request did not succeed. Check your session values "
                "and validation configuration."
            )
        return

    # AUTO provider: auth artifacts + flows + successful extraction.
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    if not required:
        cli_precondition_error(
            "No auth requirements configured. "
            "Run 'talos auth set --cookie <name>' first."
        )

    configs = list_auth_flow_configs(db_path, args.role_id)
    if not configs:
        cli_error(
            f"No flows configured for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow <role> <flow_id>' first."
        )

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
        cli_error("\nMissing Authentication Artifact")


def cmd_refresh(db_path: Path, project_id: str, args: argparse.Namespace) -> None:
    """
    Purpose:
        Force regeneration of the full auth state for a role.

        AUTO   — Replays all configured login flows, executes extractors,
                 validates against auth requirements, and stores the result.

        MANUAL — Verifies that auth artifact names are configured, applies the
                 stored manual session artifacts into role_auth_state after
                 checking that the session has not expired, and then runs Layer
                 3/4 validation.  If validation fails, role_auth_state is cleared
                 so the scheduler will not use stale credentials.  No HTTP login
                 flows are replayed.

    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        args       — parsed args with: role_id (str).
    Side effects:
        AUTO:   sends outbound HTTP; writes replay flow rows and role_auth_state.
        MANUAL: writes role_auth_state from stored config; may send outbound HTTP
                for validation; clears role_auth_state on validation failure.
        Exits 1 on failure.
    """
    provider = get_provider(db_path, args.role_id)

    if provider == PROVIDER_MANUAL:
        # Check auth artifact names are configured.
        auth_req = get_auth_config(db_path)
        if not auth_req["cookies"] and not auth_req["headers"]:
            cli_error(
            "No auth requirements configured. "
            "Run 'talos auth set --cookie <name>' or '--header <name>' first."
        )

        cfg = get_manual_session_config(db_path, args.role_id)
        if cfg is None:
            cli_error(
            f"No manual session configured for role '{args.role_id}'.\n"
            "Run 'talos auth-config set-session' to provide credentials."
        )

        from talos.projects.auth_provider import apply_manual_session
        applied = apply_manual_session(db_path, args.role_id)
        if not applied:
            expiry = get_manual_session_expiry(db_path, args.role_id)
            if expiry is None:
                msg = "Manual session has no TTL or expiry set."
            else:
                msg = "Manual session has expired."
            cli_error(
            f"{msg}\n"
            "Run 'talos auth-config set-session' to update credentials."
        )

        state_info = get_role_auth_state(db_path, args.role_id)
        print(f"Manual session applied for role {args.role_id}.")
        expiry = get_manual_session_expiry(db_path, args.role_id)
        if expiry is not None:
            import datetime as _dt
            now = _dt.datetime.now(_dt.timezone.utc)
            remaining = int((expiry - now).total_seconds())
            print(f"  Expires in : {remaining}s  ({expiry.isoformat()})")
        for k in sorted(state_info["state"].keys()):
            v = str(state_info["state"][k])
            display = v[:40] + "..." if len(v) > 40 else v
            print(f"  {k} = {display}")

        # Run validation so the tester knows whether the session is actually healthy.
        # Validation is mandatory — if no validation flow is configured, refresh fails.
        control_flows = list_session_health_control_flows(db_path, args.role_id)
        if not control_flows:
            # Clear role_auth_state so stale credentials are not used.
            store_role_auth_state(db_path, args.role_id, {}, datetime.now(timezone.utc).isoformat())
            cli_error(
            "\nError: No validation flow configured. "
            "Session applied but NOT marked ready.\n"
            "Run: talos auth-config add-control-flow <role> <flow_id>"
        )

        from talos.projects.session_health import validate_session
        alive = validate_session(db_path, args.role_id, project_id, state_info["state"])
        if not alive:
            # Clear role_auth_state so the scheduler does not use bad credentials.
            store_role_auth_state(db_path, args.role_id, {}, datetime.now(timezone.utc).isoformat())
            cli_error(
            "\nError: Validation failed — session is NOT ready. "
            "Check your session values and validation configuration."
        )

        print(f"\n  Status: {SESSION_READY}")
        return

    # AUTO provider: original refresh logic.
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    if not required:
        cli_precondition_error(
            "No auth requirements configured. "
            "Run 'talos auth set --cookie <name>' first."
        )

    configs = list_auth_flow_configs(db_path, args.role_id)
    if not configs:
        cli_error(
            f"No flows configured for role '{args.role_id}'. "
            "Run 'talos auth-config add-flow' first."
        )

    merged, errors = _run_all_flows_and_extract(db_path, project_id, args.role_id)

    if errors:
        for err in errors:
            print(f"  Warning: {err}")

    missing = required - set(merged.keys())
    if missing:
        cli_error(f"Missing artifacts after refresh: {', '.join(sorted(missing))}")

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
        Show the current auth state (provider, session state, collected artifacts
        and age) for a role.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), optional output_format.
    Side effects:
        Prints auth state to stdout (table or JSON).
    """
    provider = get_provider(db_path, args.role_id)
    session_state = get_session_display_state(db_path, args.role_id)

    if wants_json(args):
        payload: dict = {
            "role_id": args.role_id,
            "provider": provider,
            "session": session_state,
        }
        if provider == PROVIDER_MANUAL:
            cfg = get_manual_session_config(db_path, args.role_id)
            expiry = get_manual_session_expiry(db_path, args.role_id)
            state_info = get_role_auth_state(db_path, args.role_id)
            payload["manual_session"] = cfg
            payload["expires_at"] = expiry.isoformat() if expiry else None
            payload["artifacts"] = state_info.get("state") or {}
            payload["collected_at"] = state_info.get("collected_at")
        else:
            result = get_role_auth_state(db_path, args.role_id)
            health_cfg = get_session_health_config(db_path, args.role_id)
            auth_req = get_auth_config(db_path)
            payload["artifacts"] = result.get("state") or {}
            payload["collected_at"] = result.get("collected_at")
            payload["required"] = {
                "cookies": list(auth_req.get("cookies") or []),
                "headers": list(auth_req.get("headers") or []),
            }
            payload["session_health"] = health_cfg
        cli_json(payload)
        return

    print(f"Role: {args.role_id}\n")
    print(f"  Provider : {provider.upper()}")
    print(f"  Session  : {session_state}")

    if provider == PROVIDER_MANUAL:
        cfg = get_manual_session_config(db_path, args.role_id)
        if cfg is None:
            print("\n  No manual session configured.")
            print("  Run: talos auth-config set-session <role>")
            return

        expiry = get_manual_session_expiry(db_path, args.role_id)
        now = datetime.now(timezone.utc)
        if expiry:
            remaining = (expiry - now).total_seconds()
            if remaining > 0:
                print(f"  Expires  : in {int(remaining)}s  ({expiry.isoformat()})")
            else:
                print(f"  Expires  : EXPIRED {int(-remaining)}s ago")
        else:
            print("  Expires  : (no TTL or expiry set)")

        print(f"  Updated  : {cfg['updated_at']}")

        state_info = get_role_auth_state(db_path, args.role_id)
        if state_info["state"]:
            print(f"\n  Active artifacts ({len(state_info['state'])}):")
            for name in sorted(state_info["state"].keys()):
                v = str(state_info["state"][name])
                display = v[:40] + "..." if len(v) > 40 else v
                print(f"    {name} = {display}")
        else:
            print("\n  No active artifacts. Run: talos auth-config refresh <role>")
        return

    # AUTO provider display.
    result = get_role_auth_state(db_path, args.role_id)
    health_cfg = get_session_health_config(db_path, args.role_id)
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    if not result["state"]:
        print("\n  No auth state collected.")
        print("  Run: talos auth-config refresh <role>")
        return

    collected_at_str = result["collected_at"]
    collected_at = datetime.fromisoformat(collected_at_str)
    now = datetime.now(timezone.utc)
    age_s = (now - collected_at.replace(tzinfo=timezone.utc)).total_seconds()
    ttl = health_cfg["ttl_seconds"]
    expires_in = ttl - age_s

    print()
    for name in sorted(required):
        tick = "\u2713" if name in result["state"] else "\u2717"
        print(f"  {tick}  {name}")

    print()
    print(f"  Generated : {collected_at_str}")
    if expires_in > 0:
        print(f"  Expires   : in {int(expires_in)}s  (TTL: {ttl}s)")
    else:
        print(f"  Expired   : {int(-expires_in)}s ago  (TTL: {ttl}s)")
    print(f"  Refreshed : {int(age_s)}s ago")


def cmd_show(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show the complete auth-config for a role: provider, required artifacts,
        flows/extractors (AUTO), manual session config (MANUAL), and session
        health configuration.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str).
    Side effects:
        Prints complete config to stdout.
    """
    provider = get_provider(db_path, args.role_id)
    auth_req = get_auth_config(db_path)
    health_cfg = get_session_health_config(db_path, args.role_id)
    control_flows = list_session_health_control_flows(db_path, args.role_id)

    if wants_json(args):
        payload: dict = {
            "role_id": args.role_id,
            "provider": provider,
            "required_auth": {
                "cookies": list(auth_req.get("cookies") or []),
                "headers": list(auth_req.get("headers") or []),
            },
            "session_health": health_cfg,
            "control_flows": control_flows,
        }
        if provider == PROVIDER_MANUAL:
            payload["manual_session"] = get_manual_session_config(db_path, args.role_id)
        else:
            flow_configs = list_auth_flow_configs(db_path, args.role_id)
            payload["flows"] = [
                {
                    "flow_id": cfg["flow_id"],
                    "has_extractor": cfg.get("extractor_code") is not None,
                }
                for cfg in flow_configs
            ]
        cli_json(payload)
        return

    print(f"Role: {args.role_id}\n")
    print(f"Provider: {provider.upper()}")

    if provider == PROVIDER_MANUAL:
        cfg = get_manual_session_config(db_path, args.role_id)
        print("\nManual Session:")
        if cfg is None:
            print("  (none — run 'talos auth-config set-session <role>')")
        else:
            if cfg["headers"]:
                print("  Headers:")
                for name, value in cfg["headers"].items():
                    display = str(value)[:40] + "..." if len(str(value)) > 40 else str(value)
                    print(f"    {name}: {display}")
            else:
                print("  Headers: (none)")
            if cfg["cookies"]:
                print("  Cookies:")
                for name, value in cfg["cookies"].items():
                    display = str(value)[:40] + "..." if len(str(value)) > 40 else str(value)
                    print(f"    {name}: {display}")
            else:
                print("  Cookies: (none)")
            expiry = get_manual_session_expiry(db_path, args.role_id)
            if cfg["expires_at"]:
                print(f"  Expires at : {cfg['expires_at']}")
            elif cfg["ttl_seconds"] is not None:
                print(f"  TTL        : {cfg['ttl_seconds']}s")
            else:
                print("  Expiry     : (none — session is not usable)")
            if expiry:
                import datetime as _dt
                now = _dt.datetime.now(_dt.timezone.utc)
                remaining = int((expiry - now).total_seconds())
                if remaining > 0:
                    print(f"  Remaining  : {remaining}s")
                else:
                    print(f"  Status     : EXPIRED ({int(-remaining)}s ago)")
            print(f"  Updated    : {cfg['updated_at']}")
    else:
        flow_configs = list_auth_flow_configs(db_path, args.role_id)
        print("\nRequired Auth:")
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

    if control_flows:
        print("  Validation flows:")
        for fid in control_flows:
            print(f"    - {fid}")
    else:
        print("  Validation flows : (none — run: talos auth-config add-control-flow <role> <flow_id>)")


# ------------------------------------------------------------------ #
# Authentication provider commands                                     #
# ------------------------------------------------------------------ #

def cmd_set_provider(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set the authentication provider for a role to AUTO or MANUAL.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str), provider (str).
    Side effects:
        Upserts role_auth_provider row; prints confirmation.
        Exits 1 if role not found.
    """
    if not _role_exists(db_path, args.role_id):
        cli_error(f"Role '{args.role_id}' not found.")

    try:
        set_provider(db_path, args.role_id, args.provider)
    except ValueError as exc:
        cli_error(str(exc))

    print(f"Provider set for role {args.role_id}.")
    print(f"  Provider : {args.provider.upper()}")

    if args.provider == PROVIDER_MANUAL:
        print(
            "\nNext steps:\n"
            "  1. talos auth-config set-session <role>   — paste auth artifacts\n"
            "  2. talos auth-config refresh <role>       — apply artifacts\n"
            "  3. talos auth-config validate <role>      — confirm session is READY"
        )
    else:
        existing_flows = list_auth_flow_configs(db_path, args.role_id)
        if not existing_flows:
            print(
                "\nNext steps:\n"
                "  1. talos auth-config add-flow <role> <flow_id>            — add login flow\n"
                "  2. talos auth-config set-extractor <role> <flow_id> <file> — set extractor\n"
                "  3. talos auth-config refresh <role>                        — test refresh"
            )


def cmd_show_provider(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show the configured authentication provider for a role and its current
        session state.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str).
    Side effects:
        Prints provider and session state to stdout.
    """
    provider = get_provider(db_path, args.role_id)
    session_state = get_session_display_state(db_path, args.role_id)

    if wants_json(args):
        payload: dict = {
            "role_id": args.role_id,
            "provider": provider,
            "session": session_state,
        }
        if provider == PROVIDER_MANUAL:
            expiry = get_manual_session_expiry(db_path, args.role_id)
            payload["expires_at"] = expiry.isoformat() if expiry else None
        cli_json(payload)
        return

    print(f"Role     : {args.role_id}")
    print(f"Provider : {provider.upper()}")
    print(f"Session  : {session_state}")

    if provider == PROVIDER_MANUAL:
        expiry = get_manual_session_expiry(db_path, args.role_id)
        if expiry:
            now = datetime.now(timezone.utc)
            remaining = int((expiry - now).total_seconds())
            if remaining > 0:
                print(f"Expires  : in {remaining}s")
            else:
                print(f"Expires  : EXPIRED {int(-remaining)}s ago")
        else:
            print("Expires  : (no TTL or expiry set)")


def cmd_set_session(project, args: argparse.Namespace) -> None:
    """
    Purpose:
        Manage the manual session configuration file for a role, stored
        persistently inside the project's data directory (no temp files,
        no external editor launched by Talos).

        Two forms:
            talos auth-config set-session <role> path
                Print the session file path (creating it from a template if
                it does not exist yet) and exit. The tester edits this file
                with whatever tool they prefer.

            talos auth-config set-session <role>
                Parse the (already edited) session file, verify the role's
                provider is MANUAL and that the project has at least one auth
                artifact defined (via 'talos auth set'), then apply the
                session and run validation/refresh — exactly as before.

        If validation fails the session config is saved but role_auth_state is
        cleared — the session is NOT marked ready until validation passes.
        This prevents the scheduler from using unconfirmed credentials.

    Input:
        project — Active Project instance (needs .db_path, .id, .data_dir).
        args    — parsed args with: role_id (str), action ('path' | None).
    Side effects:
        'path' form: creates the session file (template) if absent; no DB writes.
        No-arg form: writes manual_session_config and role_auth_provider.
        Writes role_auth_state when validation passes; clears it when validation
        fails.
        Exits 1 if the role is not found, the file is missing/empty/invalid, or
        prerequisites (provider=manual, project auth artifacts) are not met.
    """
    db_path = project.db_path
    project_id = project.id
    role_id = args.role_id

    if not _role_exists(db_path, role_id):
        cli_error(f"Role '{role_id}' not found.")

    session_path = project.auth_session_path(role_id)
    session_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- Form 1: print the path (create a template if missing), then stop. ---- #
    if args.action == "path":
        if not session_path.exists():
            import sqlite3 as _sqlite3
            with _sqlite3.connect(str(db_path)) as _conn:
                _row = _conn.execute(
                    "SELECT name FROM roles WHERE id = ?", (role_id,)
                ).fetchone()
            role_name = _row[0] if _row else role_id
            existing = get_manual_session_config(db_path, role_id)
            template = format_session_template(role_name, existing)
            session_path.write_text(template, encoding="utf-8")

        print(str(session_path))
        return

    # ---- Form 2: parse the existing file, validate prerequisites, apply. ---- #
    if not session_path.exists():
        cli_error(
            f"Session file not found at {session_path}.\n"
            f"Run 'talos auth-config set-session {role_id} path' first, "
            "edit the file, then re-run this command."
        )

    provider = get_provider(db_path, role_id)
    if provider != PROVIDER_MANUAL:
        cli_error(
            f"Role '{role_id}' auth provider is '{provider}', not 'manual'.\n"
            f"Run 'talos auth-config set-provider {role_id} manual' first."
        )

    project_auth = get_auth_config(db_path)
    if not project_auth["cookies"] and not project_auth["headers"]:
        cli_error(
            "No project-wide auth artifacts are defined.\n"
            "Run 'talos auth set --header <name>' or 'talos auth set --cookie <name>' "
            "first, so Talos knows which artifacts constitute authentication."
        )

    content = session_path.read_text(encoding="utf-8")
    if not content.strip():
        cli_error(
            f"Session file at {session_path} is empty. Edit it before "
            "re-running this command."
        )

    parsed = parse_session_file(content)

    if not parsed["headers"] and not parsed["cookies"]:
        cli_error(
            "No headers or cookies found in the session file. "
            f"Edit {session_path} to add at least one header or cookie value. "
            "Session not saved."
        )

    if parsed["expires_at"] is None and parsed["ttl_seconds"] is None:
        cli_error(
            "No expiry defined (expires_at or ttl_seconds is required). "
            f"Edit {session_path} and re-run. Session not saved."
        )

    set_manual_session_config(
        db_path,
        role_id,
        headers=parsed["headers"],
        cookies=parsed["cookies"],
        expires_at=parsed["expires_at"],
        ttl_seconds=parsed["ttl_seconds"],
    )

    # Apply artifacts to role_auth_state immediately.
    from talos.projects.auth_provider import apply_manual_session
    applied = apply_manual_session(db_path, role_id)

    print(f"\nManual session loaded from {session_path} for role {role_id}.")
    if parsed["headers"]:
        print(f"  Headers  : {', '.join(parsed['headers'].keys())}")
    if parsed["cookies"]:
        print(f"  Cookies  : {', '.join(parsed['cookies'].keys())}")
    if parsed["expires_at"]:
        print(f"  Expires  : {parsed['expires_at']}")
    elif parsed["ttl_seconds"] is not None:
        print(f"  TTL      : {parsed['ttl_seconds']}s")

    if not applied:
        print(f"  Status   : {SESSION_WAITING_FOR_USER}")
        print("\nSession could not be applied (possibly expired). Check expiry values.")
        return

    # Automatically run validate and status.
    # A validation flow is required to confirm the session.
    control_flows = list_session_health_control_flows(db_path, role_id)
    if not control_flows:
        # No validation flow configured: session is applied but cannot be confirmed.
        # Clear role_auth_state so the scheduler does not use unverified credentials.
        store_role_auth_state(
            db_path, role_id, {}, datetime.now(timezone.utc).isoformat()
        )
        print(
            "\n  Status   : PENDING_VALIDATION\n"
            "\nSession saved but no validation flow is configured — "
            "session is NOT ready for scheduler use.\n"
            "Add a validation flow then re-run set-session:\n"
            "  talos auth-config add-control-flow <role> <flow_id>"
        )
        return

    # Run Layer 3/4 validation using the applied session.
    from talos.projects.session_health import validate_session
    state_info = get_role_auth_state(db_path, role_id)
    alive = validate_session(db_path, role_id, project_id, state_info["state"])

    if alive:
        print(f"  Status   : {SESSION_READY}")
        print("\nSession validated and ready.")
    else:
        # Validation failed — clear role_auth_state so the session is not used.
        store_role_auth_state(
            db_path, role_id, {}, datetime.now(timezone.utc).isoformat()
        )
        print(
            f"  Status   : {SESSION_FAILED}\n"
            "\nValidation failed. Session config is saved but NOT active.\n"
            "Fix the session values or validation config, then re-run:\n"
            f"  talos auth-config set-session {role_id}",
            file=sys.stderr,
        )


# ------------------------------------------------------------------ #
# Session recovery (CLI-021)                                           #
# ------------------------------------------------------------------ #

def cmd_clear_session(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear the manual session configuration for a role so operators can
        recover from a stuck WAITING_FOR_USER / bad session without SQLite
        edits. Wires clear_manual_session_config().
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str, resolved UUID).
    Output: None
    Side effects:
        Deletes the role's manual_session_config row (no-op if absent).
        Prints "Session cleared." to stdout.
        Exits 1 if the role is not found.
    """
    if not _role_exists(db_path, args.role_id):
        cli_error(f"Role '{args.role_id}' not found.")

    clear_manual_session_config(db_path, args.role_id)
    print("Session cleared.")


def cmd_reset_health(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Reset the Layer 2 session health suspicion counter for a role so
        operators can recover from permanently degraded health confidence
        without SQLite edits. Wires reset_suspicion().
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args with: role_id (str, resolved UUID).
    Output: None
    Side effects:
        Upserts session_suspicion_state with suspicion_count=0.
        Prints "Health suspicion reset." to stdout.
        Exits 1 if the role is not found.
    """
    if not _role_exists(db_path, args.role_id):
        cli_error(f"Role '{args.role_id}' not found.")

    reset_suspicion(db_path, args.role_id)
    print("Health suspicion reset.")


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
        cli_usage_error("Provide at least one --body, --status, or --header signal.")

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
        Confirms interactively unless --force; non-interactive requires --force.
    Side effects:
        May prompt; resets body, status, and header signals to empty.
    """
    confirm_or_exit(
        f"Clear all expiry signals for role '{args.role_id}'?",
        force=bool(getattr(args, "force", False)),
    )
    set_session_health_config(
        db_path,
        args.role_id,
        expiry_body_signals=[],
        expiry_status_codes=[],
        expiry_header_signals={},
    )
    print(f"Expiry signals cleared for role {args.role_id}.")


def cmd_add_control_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a validation flow for session health checking.
        The flow is replayed with the current auth state injected; if the
        response status matches the original baseline, the session is alive.
    Input:
        db_path — Path to the project's talos.db.
        args    — parsed args: role_id (str), flow_id (str).
    Side effects:
        Inserts into session_health_control_flows.
    """
    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        cli_error(f"Flow '{args.flow_id}' not found.")

    inserted = add_session_health_control_flow(db_path, args.role_id, args.flow_id)
    if not inserted:
        print(f"Validation flow '{args.flow_id}' already added for role '{args.role_id}'.")
    else:
        print(f"Validation flow added.")
        print(f"  role : {args.role_id}")
        print(f"  flow : {args.flow_id}")


def cmd_remove_control_flow(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a validation flow from session health checking.
    Side effects:
        Deletes from session_health_control_flows.
        Exits 1 if not found.
    """
    removed = remove_session_health_control_flow(db_path, args.role_id, args.flow_id)
    if not removed:
        cli_error(f"Validation flow '{args.flow_id}' not found for role '{args.role_id}'.")
    print(f"Validation flow removed: {args.flow_id}")


def cmd_list_control_flows(db_path: Path, args: argparse.Namespace) -> None:
    """
    Purpose:
        List all control flows configured for a role.
    Side effects:
        Prints flow IDs to stdout (table or JSON).
    """
    flows = list_session_health_control_flows(db_path, args.role_id)
    if wants_json(args):
        cli_json([{"flow_id": fid, "role_id": args.role_id} for fid in flows])
        return

    if not flows:
        print(f"No control flows configured for role '{args.role_id}'.")
        print("Use: talos auth-config add-control-flow <role> <flow_id>")
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
        cli_error(f"Extractor has a syntax error: {exc}")

    ns: dict = {}
    try:
        exec(compiled, ns)  # noqa: S102
    except Exception as exc:
        cli_error(f"Extractor raised exception during load: {exc}")

    if "extract" not in ns or not callable(ns["extract"]):
        cli_error("Extractor must define a callable named 'extract(response)'.")


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
        cli_error(f"extract() must return a dict, got {type(result).__name__}.", exit_code=None)
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


def _resolve_role_id(db_path: Path, name_or_id: str) -> str:
    """
    Purpose:
        Resolve a CLI role argument (name or UUID) to the role UUID.
        Name is tried first, then UUID — same order as resolve_role().
    Input:
        db_path    — Path to the project's talos.db.
        name_or_id — Role name or full UUID as supplied on the CLI.
    Output:
        Role UUID string.
    Side effects:
        Prints an error and exits 1 when the role does not exist.
    """
    role = resolve_role(db_path, name_or_id)
    if role is None:
        cli_error(f"Role '{name_or_id}' not found.")
    return role["id"]


def _role_exists(db_path: Path, role_id: str) -> bool:
    """
    Purpose:
        Return True if a role with the given ID exists in the project database.
        Used as a defence-in-depth check after name/UUID resolution.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID string to look up.
    Output: bool
    Side effects: None (read-only).
    """
    return resolve_role(db_path, role_id) is not None
