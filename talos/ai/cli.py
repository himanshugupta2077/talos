"""
Module: talos.ai.cli

Purpose:
    Thin CLI for the AI layer. All orchestration goes through WorkflowEngine.
    Phase A commands: start, stop, resume, reset-budget, status, mode,
    tools list, audit list.

Dependencies: argparse, talos.cli_output, talos.ai.workflow.engine
Data flow:
    argv → argparse → WorkflowEngine → stdout / stderr
Side effects:
    Session and audit DB writes; confirmation prompts for reset-budget / modes.
"""

from __future__ import annotations

import argparse
import json
import sys

from talos.ai.models import (
    DEFAULT_AUTONOMY_MODE,
    EXPERIMENTAL_MODES,
    parse_mode,
)
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError
from talos.ai.workflow import session as session_store
from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_info,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    confirm_or_exit,
    wants_json,
)
from talos.projects.manager import ProjectManager


def run_ai_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Dispatch `talos ai <subcommand>`.
    Input:
        manager — ProjectManager with optional process project bind.
        argv    — arguments after `ai`.
    Side effects:
        Subcommand-specific DB and stdout effects.
    """
    parser = argparse.ArgumentParser(
        prog="talos ai",
        description=(
            "Talos AI layer — policy-gated agent (suggest-first). "
            "Phase A: sessions, tools list, READ/context tools via sealed execute."
        ),
    )
    sub = parser.add_subparsers(dest="ai_cmd", metavar="<command>")

    # start
    p_start = sub.add_parser("start", help="Start an AI session (pinned to project)")
    p_start.add_argument("--goal", default="", help="Engagement goal / objective")
    p_start.add_argument(
        "--mode",
        default=DEFAULT_AUTONOMY_MODE.value,
        help=f"Autonomy mode (default: {DEFAULT_AUTONOMY_MODE.value})",
    )
    p_start.add_argument(
        "--force-stop-existing",
        action="store_true",
        help="Stop any existing active session for this project",
    )
    add_force_argument(p_start)
    add_format_argument(p_start)

    # stop
    p_stop = sub.add_parser("stop", help="Stop the active (or named) AI session")
    p_stop.add_argument("session_id", nargs="?", default=None)
    add_format_argument(p_stop)

    # resume
    p_resume = sub.add_parser("resume", help="Resume a stopped session (same pin)")
    p_resume.add_argument("session_id", help="Session UUID to resume")
    add_format_argument(p_resume)

    # reset-budget
    p_rb = sub.add_parser("reset-budget", help="Reset usage counters (operator)")
    p_rb.add_argument("session_id", nargs="?", default=None)
    add_force_argument(p_rb)
    add_format_argument(p_rb)

    # status
    p_status = sub.add_parser("status", help="Show session status, budgets, grants")
    p_status.add_argument("session_id", nargs="?", default=None)
    add_format_argument(p_status)

    # mode
    p_mode = sub.add_parser("mode", help="Show or set autonomy mode")
    mode_sub = p_mode.add_subparsers(dest="mode_cmd", metavar="<mode-command>")
    p_mode_set = mode_sub.add_parser("set", help="Set mode on active session")
    p_mode_set.add_argument("mode", help="suggest-only|step|auto-low|…")
    p_mode_set.add_argument(
        "--ack",
        default=None,
        help="Required once for auto-aggressive: I_ACCEPT_AUTO_AGGRESSIVE=<project_id>",
    )
    p_mode_set.add_argument(
        "--session",
        default=None,
        dest="session_id",
        help="Target session id (default: active)",
    )
    add_force_argument(p_mode_set)
    add_format_argument(p_mode_set)
    p_mode_clear = mode_sub.add_parser(
        "clear-aggressive-ack",
        help="Revoke project auto-aggressive acknowledgement",
    )
    add_force_argument(p_mode_clear)

    # tools
    p_tools = sub.add_parser("tools", help="Inspect allowlisted tools")
    tools_sub = p_tools.add_subparsers(dest="tools_cmd", metavar="<tools-command>")
    p_tools_list = tools_sub.add_parser("list", help="List registered tools")
    add_format_argument(p_tools_list)

    # audit
    p_audit = sub.add_parser("audit", help="AI audit log")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd", metavar="<audit-command>")
    p_audit_list = audit_sub.add_parser("list", help="List audit events")
    p_audit_list.add_argument("--session", default=None, dest="session_id")
    p_audit_list.add_argument("--limit", type=int, default=50)
    add_format_argument(p_audit_list)

    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return

    args = parser.parse_args(argv)
    engine = WorkflowEngine(manager)

    try:
        if args.ai_cmd == "start":
            _cmd_start(engine, args)
        elif args.ai_cmd == "stop":
            _cmd_stop(engine, args)
        elif args.ai_cmd == "resume":
            _cmd_resume(engine, args)
        elif args.ai_cmd == "reset-budget":
            _cmd_reset_budget(engine, args)
        elif args.ai_cmd == "status":
            _cmd_status(engine, args)
        elif args.ai_cmd == "mode":
            _cmd_mode(engine, args)
        elif args.ai_cmd == "tools":
            _cmd_tools(engine, args)
        elif args.ai_cmd == "audit":
            _cmd_audit(engine, args)
        else:
            parser.print_help()
            sys.exit(2)
    except WorkflowEngineError as exc:
        if exc.exit_code == 3:
            cli_precondition_error(str(exc))
        if exc.exit_code == 2:
            cli_usage_error(str(exc))
        cli_error(str(exc), exit_code=exc.exit_code)


def _session_payload(session) -> dict:
    return {
        "session_id": session.session_id,
        "project_id": session.project_id,
        "pinned_project_id": session.pinned_project_id,
        "goal": session.goal,
        "mode": session.mode.value,
        "status": session.status.value,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "budgets": session.budgets.to_dict(),
        "usage": session.usage.to_dict(),
    }


def _cmd_start(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    try:
        mode = parse_mode(args.mode)
    except ValueError as exc:
        cli_usage_error(str(exc))

    force = bool(getattr(args, "force", False))

    # Design: enabling any auto-* requires interactive confirm / --force.
    if mode in EXPERIMENTAL_MODES:
        confirm_or_exit(
            f"Start AI session in experimental mode '{mode.value}'?",
            force=force,
        )

    # Only prompt to stop an existing session when one is actually active.
    if args.force_stop_existing:
        project = engine.manager.active()
        if project is not None:
            existing = session_store.get_active_session(project.db_path, project.id)
            if existing is not None:
                confirm_or_exit(
                    "Stop the existing active AI session for this project?",
                    force=force,
                )

    session = engine.start(
        args.goal or "",
        mode=mode,
        force_stop_existing=bool(args.force_stop_existing),
    )
    if wants_json(args):
        cli_json(_session_payload(session))
        return
    cli_success(f"AI session started ({session.mode.value})")
    print()
    print(f"Session:  {session.session_id}")
    print(f"Project:  {session.pinned_project_id}")
    print(f"Status:   {session.status.value}")
    if session.goal:
        print(f"Goal:     {session.goal}")
    if session.mode.value == "suggest-only":
        cli_info(
            "Execute is off in suggest-only; use 'talos ai mode set step' to enable."
        )
    elif mode in EXPERIMENTAL_MODES:
        cli_info(f"Mode '{session.mode.value}' is experimental.")


def _cmd_stop(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    session = engine.stop(args.session_id)
    if wants_json(args):
        cli_json(_session_payload(session))
        return
    cli_success(f"AI session stopped: {session.session_id}")


def _cmd_resume(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    session = engine.resume(args.session_id)
    if wants_json(args):
        cli_json(_session_payload(session))
        return
    cli_success(f"AI session resumed: {session.session_id}")


def _cmd_reset_budget(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    confirm_or_exit(
        "Reset AI session budget counters?",
        force=bool(args.force),
    )
    session = engine.reset_budget(args.session_id)
    if wants_json(args):
        cli_json(_session_payload(session))
        return
    cli_success(f"Budget reset for session {session.session_id}")
    print(f"Status: {session.status.value}")


def _cmd_status(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    payload = engine.status(args.session_id)
    if wants_json(args):
        cli_json(payload)
        return
    print(f"Session:     {payload['session_id']}")
    print(f"Project:     {payload['pinned_project_id']}")
    print(f"Status:      {payload['status']}")
    print(f"Mode:        {payload['mode']}")
    print(f"Goal:        {payload['goal'] or '(none)'}")
    print(f"Tools:       {payload['tools_registered']} registered")
    print(f"Created:     {payload['created_at']}")
    print(f"Updated:     {payload['updated_at']}")
    print()
    print("Budgets:")
    # budgets_json keys are max_*; usage_json keys drop the max_ prefix
    # (e.g. max_tool_calls → tool_calls, max_wall_clock_s → wall_clock_s).
    usage = payload.get("usage") or {}
    for key, val in (payload.get("budgets") or {}).items():
        usage_key = key[4:] if key.startswith("max_") else key
        used = usage.get(usage_key, 0)
        print(f"  {key}: {used} / {val}")
    caps = payload.get("granted_capabilities") or []
    print()
    print(f"Granted capabilities ({len(caps)}):")
    if not caps:
        print("  (none — suggest-only)")
    else:
        for c in caps:
            print(f"  - {c}")


def _cmd_mode(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    if args.mode_cmd == "set":
        try:
            mode = parse_mode(args.mode)
        except ValueError as exc:
            cli_usage_error(str(exc))

        if mode in EXPERIMENTAL_MODES:
            confirm_or_exit(
                f"Enable experimental mode '{mode.value}'?",
                force=bool(args.force),
            )
        session = engine.set_mode(
            mode,
            session_id=getattr(args, "session_id", None),
            aggressive_ack_phrase=getattr(args, "ack", None),
        )
        if wants_json(args):
            cli_json(_session_payload(session))
            return
        cli_success(f"Mode set to {session.mode.value}")
        print(f"Session: {session.session_id}")
        return

    if args.mode_cmd == "clear-aggressive-ack":
        confirm_or_exit(
            "Clear auto-aggressive acknowledgement for this project?",
            force=bool(args.force),
        )
        engine.clear_aggressive_ack()
        cli_success("Cleared auto-aggressive acknowledgement")
        return

    cli_usage_error("Usage: talos ai mode set <mode> | clear-aggressive-ack")


def _cmd_tools(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    if args.tools_cmd != "list":
        cli_usage_error("Usage: talos ai tools list")
    tools = engine.list_tools()
    if wants_json(args):
        cli_json({"tools": tools, "count": len(tools)})
        return
    print(f"Registered tools: {len(tools)}")
    print()
    for t in tools:
        caps = ", ".join(t.get("policy", {}).get("capabilities") or [])
        tags = ",".join(t.get("tags") or [])
        print(f"  {t['name']:28}  caps=[{caps}]  tags={tags}")
        print(f"    {t.get('description', '')}")


def _cmd_audit(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    if args.audit_cmd != "list":
        cli_usage_error("Usage: talos ai audit list")
    events = engine.list_audit(
        session_id=getattr(args, "session_id", None),
        limit=int(getattr(args, "limit", 50) or 50),
    )
    if wants_json(args):
        cli_json({"events": events, "count": len(events)})
        return
    if not events:
        print("No audit events.")
        return
    for ev in events:
        print(
            f"{ev['created_at']}  {ev['event_type']:24}  "
            f"session={ev.get('session_id') or '-'}"
        )
        payload = ev.get("payload") or {}
        # Compact one-line payload preview.
        preview = json.dumps(payload, sort_keys=True, default=str)
        if len(preview) > 120:
            preview = preview[:117] + "..."
        print(f"  {preview}")
