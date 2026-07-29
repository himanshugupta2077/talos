"""
Module: talos.ai.cli

Purpose:
    Thin CLI for the AI layer. All orchestration goes through WorkflowEngine.
    Phase A+B: sessions, tools, audit, suggest/approve/deny/pending/plans,
    notes show|edit|export.

Dependencies: argparse, talos.cli_output, talos.ai.workflow.engine
Data flow:
    argv → argparse → WorkflowEngine → stdout / stderr
Side effects:
    Session, plans, notes, audit DB writes; confirmation prompts as needed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

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
            "Sessions, offline heuristic suggest/approve, notes, READ tools."
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

    # suggest
    p_suggest = sub.add_parser(
        "suggest",
        help="One offline planner turn → immutable suggestions (+ plans in step)",
    )
    p_suggest.add_argument(
        "--auto-reads",
        action="store_true",
        help="In step/auto-*: auto-execute READ-only tools after validate",
    )
    p_suggest.add_argument(
        "-n",
        "--n",
        type=int,
        default=5,
        dest="max_suggestions",
        help="Max suggestions this turn (default 5)",
    )
    p_suggest.add_argument("--session", default=None, dest="session_id")
    add_format_argument(p_suggest)

    # approve
    p_approve = sub.add_parser(
        "approve",
        help="Approve plan_id (or suggestion_id → latest pending plan) and execute",
    )
    p_approve.add_argument("target_id", help="plan_id or suggestion_id")
    p_approve.add_argument("--session", default=None, dest="session_id")
    add_format_argument(p_approve)

    # deny
    p_deny = sub.add_parser("deny", help="Deny plan_id or all plans for suggestion_id")
    p_deny.add_argument("target_id", help="plan_id or suggestion_id")
    p_deny.add_argument("--reason", default=None, help="Optional deny reason")
    p_deny.add_argument("--session", default=None, dest="session_id")
    add_format_argument(p_deny)

    # pending
    p_pending = sub.add_parser(
        "pending", help="List suggestions and plans awaiting approval"
    )
    p_pending.add_argument("--session", default=None, dest="session_id")
    add_format_argument(p_pending)

    # plans show
    p_plans = sub.add_parser("plans", help="Inspect ExecutionPlans")
    plans_sub = p_plans.add_subparsers(dest="plans_cmd", metavar="<plans-command>")
    p_plans_show = plans_sub.add_parser(
        "show", help="Show plan vs linked immutable suggestion"
    )
    p_plans_show.add_argument("plan_id", help="ExecutionPlan id")
    p_plans_show.add_argument("--session", default=None, dest="session_id")
    add_format_argument(p_plans_show)

    # notes
    p_notes = sub.add_parser("notes", help="Structured app notes (AI-only store)")
    notes_sub = p_notes.add_subparsers(dest="notes_cmd", metavar="<notes-command>")
    p_notes_show = notes_sub.add_parser("show", help="Show current notes document")
    add_format_argument(p_notes_show)
    p_notes_export = notes_sub.add_parser(
        "export", help="Export notes JSON (same as show --format json)"
    )
    add_format_argument(p_notes_export)
    p_notes_edit = notes_sub.add_parser(
        "edit", help="Edit full notes JSON in $EDITOR (optimistic revision)"
    )
    add_force_argument(p_notes_edit)
    add_format_argument(p_notes_edit)

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
        elif args.ai_cmd == "suggest":
            _cmd_suggest(engine, args)
        elif args.ai_cmd == "approve":
            _cmd_approve(engine, args)
        elif args.ai_cmd == "deny":
            _cmd_deny(engine, args)
        elif args.ai_cmd == "pending":
            _cmd_pending(engine, args)
        elif args.ai_cmd == "plans":
            _cmd_plans(engine, args)
        elif args.ai_cmd == "notes":
            _cmd_notes(engine, args)
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

    if mode in EXPERIMENTAL_MODES:
        confirm_or_exit(
            f"Start AI session in experimental mode '{mode.value}'?",
            force=force,
        )

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
    print(
        f"Pending:     {payload.get('pending_plan_count', 0)} plans, "
        f"{payload.get('suggestion_count', 0)} suggestions"
    )
    print(f"Created:     {payload['created_at']}")
    print(f"Updated:     {payload['updated_at']}")
    print()
    print("Budgets:")
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
        preview = json.dumps(payload, sort_keys=True, default=str)
        if len(preview) > 120:
            preview = preview[:117] + "..."
        print(f"  {preview}")


def _cmd_suggest(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    result = engine.suggest(
        session_id=getattr(args, "session_id", None),
        auto_reads=bool(getattr(args, "auto_reads", False)),
        max_suggestions=int(getattr(args, "max_suggestions", 5) or 5),
    )
    if wants_json(args):
        cli_json(result)
        return
    cli_success(
        f"Suggest turn: {result['suggestion_count']} suggestion(s), "
        f"{result['pending_plan_count']} pending plan(s), "
        f"{result['auto_executed_count']} auto-executed"
    )
    print(f"Session: {result['session_id']}  mode={result['mode']}")
    print()
    for s in result.get("suggestions") or []:
        print(f"  [{s['suggestion_id'][:8]}…]  {s['tool_name']}")
        if s.get("reason"):
            print(f"      reason: {s['reason']}")
        if s.get("cli_preview"):
            print(f"      preview: {s['cli_preview']}")
        args_s = json.dumps(s.get("arguments") or {}, sort_keys=True, default=str)
        if len(args_s) > 100:
            args_s = args_s[:97] + "..."
        print(f"      args: {args_s}")
    if result.get("pending_plans"):
        print()
        print("Pending plans (approve with: talos ai approve <plan_id>):")
        for p in result["pending_plans"]:
            print(f"  plan={p['plan_id']}  tool={p['tool_name']}")
    if result.get("auto_executed"):
        print()
        print("Auto-executed:")
        for o in result["auto_executed"]:
            flag = "ok" if o.get("success") else "FAIL"
            print(f"  [{flag}] {o['tool_name']}: {o.get('summary')}")
    if result.get("rejects"):
        print()
        print("Rejected:")
        for r in result["rejects"]:
            print(f"  {r.get('tool_name') or r.get('suggestion_id')}: {r.get('code')} — {r.get('message')}")
    if result["mode"] == "suggest-only" and result["suggestion_count"]:
        print()
        cli_info(
            "suggest-only: suggestions recorded but not executable. "
            "Run 'talos ai mode set step' then approve (or re-suggest)."
        )


def _cmd_approve(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    result = engine.approve(
        args.target_id,
        session_id=getattr(args, "session_id", None),
    )
    if wants_json(args):
        cli_json(result)
        return
    obs = result.get("observation") or {}
    flag = "ok" if obs.get("success") else "FAIL"
    cli_success(f"Approved and executed ({flag}): {result['tool_name']}")
    print(f"Plan:         {result['plan_id']}")
    print(f"Suggestion:   {result['suggestion_id']}")
    print(f"Observation:  {obs.get('observation_id')}")
    print(f"Summary:      {obs.get('summary')}")


def _cmd_deny(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    result = engine.deny(
        args.target_id,
        session_id=getattr(args, "session_id", None),
        reason=getattr(args, "reason", None),
    )
    if wants_json(args):
        cli_json(result)
        return
    ids = result.get("denied_plan_ids") or []
    cli_success(f"Denied {len(ids)} plan(s) for {result['target_id']}")
    for pid in ids:
        print(f"  {pid}")


def _cmd_pending(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    result = engine.pending(session_id=getattr(args, "session_id", None))
    if wants_json(args):
        cli_json(result)
        return
    print(f"Session: {result['session_id']}  mode={result['mode']}")
    print(
        f"Suggestions: {result['suggestion_count']}  "
        f"Pending plans: {result['pending_plan_count']}"
    )
    print()
    if result.get("pending_plans"):
        print("Pending plans:")
        for p in result["pending_plans"]:
            print(f"  {p['plan_id']}  {p['tool_name']}")
            print(f"    args={json.dumps(p.get('arguments') or {}, sort_keys=True)}")
    else:
        print("No pending plans.")
    print()
    if result.get("suggestions"):
        print("Recent suggestions:")
        for s in result["suggestions"][:20]:
            print(f"  {s['suggestion_id'][:8]}…  {s['tool_name']}  {s.get('reason') or ''}")


def _cmd_plans(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    if args.plans_cmd != "show":
        cli_usage_error("Usage: talos ai plans show <plan_id>")
    result = engine.show_plan(
        args.plan_id,
        session_id=getattr(args, "session_id", None),
    )
    if wants_json(args):
        cli_json(result)
        return
    plan = result.get("plan") or {}
    sugg = result.get("suggestion") or {}
    print(f"Plan:       {plan.get('plan_id')}")
    print(f"Status:     {plan.get('status')}")
    print(f"Tool:       {plan.get('tool_name')}")
    print(f"Suggestion: {plan.get('suggestion_id')}")
    print(f"Plan args:  {json.dumps(plan.get('arguments') or {}, sort_keys=True)}")
    if sugg:
        print(
            f"Sugg args:  {json.dumps(sugg.get('arguments') or {}, sort_keys=True)}"
        )
        print(f"Reason:     {sugg.get('reason') or '(none)'}")
        print(f"Preview:    {sugg.get('cli_preview') or '(none)'}")
    if result.get("args_differ"):
        cli_info("Normalized plan args differ from immutable suggestion args.")


def _cmd_notes(engine: WorkflowEngine, args: argparse.Namespace) -> None:
    if args.notes_cmd in (None,):
        cli_usage_error("Usage: talos ai notes show|edit|export")

    if args.notes_cmd in ("show", "export"):
        payload = engine.notes_show()
        if wants_json(args) or args.notes_cmd == "export":
            # export always JSON body on stdout
            if args.notes_cmd == "export" and not wants_json(args):
                print(json.dumps(payload, indent=2, sort_keys=True, default=str))
                return
            cli_json(payload)
            return
        print(f"Project:   {payload.get('project_id')}")
        print(f"Revision:  {payload.get('revision')}")
        print(f"Updated:   {payload.get('updated_at') or '(never)'} by {payload.get('updated_by') or '-'}")
        print()
        print(json.dumps(payload.get("doc") or {}, indent=2, sort_keys=True, default=str))
        return

    if args.notes_cmd == "edit":
        current = engine.notes_show()
        doc = current.get("doc") or {}
        rev = int(current.get("revision") or 0)
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "vi"
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="talos-ai-notes-",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(json.dumps(doc, indent=2, sort_keys=True, default=str))
            tmp.write("\n")
            path = Path(tmp.name)
        try:
            rc = subprocess.call([editor, str(path)])
            if rc != 0:
                cli_error(f"Editor exited with code {rc}", exit_code=1)
            raw = path.read_text(encoding="utf-8")
            try:
                new_doc = json.loads(raw)
            except json.JSONDecodeError as exc:
                cli_error(f"Invalid JSON after edit: {exc}", exit_code=1)
            if not isinstance(new_doc, dict):
                cli_error("Notes document must be a JSON object", exit_code=1)
            if not bool(getattr(args, "force", False)):
                confirm_or_exit(
                    f"Save notes as revision {rev + 1 if rev > 0 else 1}?",
                    force=False,
                )
            # Optimistic concurrency against revision we loaded.
            if_rev = rev if rev > 0 else None
            # When force, still use if_revision for safety unless force means skip confirm only.
            updated = engine.notes_replace(
                new_doc, if_revision=if_rev, updated_by="operator"
            )
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if wants_json(args):
            cli_json(updated)
            return
        cli_success(f"Notes saved (revision {updated.get('revision')})")
        return

    cli_usage_error("Usage: talos ai notes show|edit|export")
