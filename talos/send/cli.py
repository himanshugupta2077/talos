"""
Module: talos.send.cli

Purpose:
    CLI for Talos Repeater Phase 2 (mutable send — full CLI surface):

        talos send from <flow_id> [--raw-out PATH]
        talos send edit <flow_id> [--send] [--editor CMD] …
        talos send once <flow_id> [edits…] [--repeat N|--parallel N] …
        talos send redo <execution_flow_id>
        talos send dup <flow_id>
        talos send show <flow_id> [--body …] [--full]
        talos send export <flow_id> --out DIR
        talos send history --from <id> [--session] [--parent] …
        talos send tree --from <id>
        talos send diff <a> <b> [--side request|response|both]
        talos send note <flow_id> --text …

    All commands require a bound project. Execution is immediate (no scheduler).
    AI contract: fully non-interactive; --format json on once/show/history/diff/…

Dependencies: argparse, asyncio, os, shutil, subprocess, sys, pathlib
              talos.cli_output, talos.projects.manager, talos.send.*
Data flow:
    argv → project gate → handlers → engine / db → stdout
Side effects:
    - once/redo/edit --send: outbound HTTP + DB insert
    - from/edit: may write a raw request file
    - note: UPDATE flow_meta on send rows only
    - export: write files under --out
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    cli_success,
    wants_json,
)
from talos.projects.manager import ProjectManager
from talos.replay.diff import compute_diff
from talos.send import db as send_db
from talos.send import draft as draft_mod
from talos.send.engine import (
    MAX_PROFILE_N,
    MultiSendOutcome,
    SendOutcome,
    redo_send,
    send_once,
    send_parallel,
    send_repeat,
)
from talos.send.request_diff import compute_request_diff, enhance_response_diff


# ------------------------------------------------------------------ #
# Entry                                                                #
# ------------------------------------------------------------------ #

def run_send_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse send subcommands and dispatch.
    Input:
        manager — ProjectManager with projects root / optional override.
        argv    — args after 'send'.
    Side effects:
        Delegates to handlers; may exit via cli_error.
    """
    parser = argparse.ArgumentParser(
        prog="talos send",
        description=(
            "Repeater: edit a captured request, send, review. "
            "Never mutates the baseline flow (new row per send). "
            "Distinct from 'talos replay' (exact re-send). "
            "Phase 2: branch, multi-send (capped), full inspect, request+response diff."
        ),
    )
    sub = parser.add_subparsers(dest="send_cmd", metavar="<command>")
    sub.required = True

    # --- from ---
    p_from = sub.add_parser(
        "from",
        help="Materialize an editable raw HTTP draft from a flow (no send, no DB write).",
    )
    p_from.add_argument("flow_id", help="UUID of the baseline or previous execution.")
    p_from.add_argument(
        "--raw-out",
        dest="raw_out",
        metavar="PATH",
        help="Write raw request to PATH (default: temp file).",
    )
    add_format_argument(p_from)

    # --- edit ---
    p_edit = sub.add_parser(
        "edit",
        help=(
            "Open raw draft in $EDITOR (or --editor). "
            "Optional --send runs once with the saved file. "
            "Non-interactive without --editor: use 'from' + once --raw-file."
        ),
    )
    p_edit.add_argument("flow_id", help="Parent flow UUID to materialize.")
    p_edit.add_argument(
        "--raw-out",
        dest="raw_out",
        metavar="PATH",
        help="Write raw request to PATH (default: temp file).",
    )
    p_edit.add_argument(
        "--editor",
        metavar="CMD",
        help="Editor command (default: $VISUAL or $EDITOR).",
    )
    p_edit.add_argument(
        "--send",
        dest="do_send",
        action="store_true",
        help="After save, send once using the edited raw file.",
    )
    p_edit.add_argument(
        "--source",
        choices=["manual_send", "ai_send"],
        default="manual_send",
        help="Flow source when --send (default: manual_send).",
    )
    p_edit.add_argument(
        "--reason",
        metavar="TEXT",
        help="Optional replay_reason when --send.",
    )
    p_edit.add_argument(
        "--note",
        metavar="TEXT",
        help="Optional flow_meta.note when --send.",
    )
    p_edit.add_argument(
        "--session",
        metavar="UUID",
        help="Optional session_id when --send.",
    )
    p_edit.add_argument(
        "--no-update-content-length",
        dest="no_update_content_length",
        action="store_true",
        help="When --send: do not fix Content-Length.",
    )
    add_format_argument(p_edit)

    # --- once ---
    p_once = sub.add_parser(
        "once",
        help="Apply edits, send once (or --repeat/--parallel), store new flow(s).",
    )
    p_once.add_argument(
        "flow_id",
        help="Parent flow UUID to fork from (capture or previous send).",
    )
    _add_edit_flags(p_once)
    p_once.add_argument(
        "--source",
        choices=["manual_send", "ai_send"],
        default="manual_send",
        help="Flow source label (default: manual_send).",
    )
    p_once.add_argument(
        "--reason",
        metavar="TEXT",
        help="Optional label stored as replay_reason (e.g. manual_probe, ai_probe).",
    )
    p_once.add_argument(
        "--note",
        metavar="TEXT",
        help="Optional note stored in flow_meta.note.",
    )
    p_once.add_argument(
        "--session",
        metavar="UUID",
        help="Stamp flow_meta.session_id for branching / history filter.",
    )
    profile = p_once.add_mutually_exclusive_group()
    profile.add_argument(
        "--repeat",
        type=int,
        metavar="N",
        help=f"Sequential N sends of the same draft (1–{MAX_PROFILE_N}).",
    )
    profile.add_argument(
        "--parallel",
        type=int,
        metavar="N",
        help=f"Concurrent N sends (1–{MAX_PROFILE_N}; concurrency ≤ 10).",
    )
    p_once.add_argument(
        "--delay-ms",
        type=int,
        default=0,
        metavar="M",
        dest="delay_ms",
        help="Delay between sequential --repeat sends only (milliseconds).",
    )
    add_format_argument(p_once)

    # --- redo ---
    p_redo = sub.add_parser(
        "redo",
        help="Re-send exact as-sent request of a previous execution (no further edits).",
    )
    p_redo.add_argument(
        "flow_id",
        help="Execution (or any) flow UUID whose as-sent request is re-fired.",
    )
    p_redo.add_argument(
        "--source",
        choices=["manual_send", "ai_send"],
        default="manual_send",
        help="Flow source label (default: manual_send).",
    )
    p_redo.add_argument("--reason", metavar="TEXT", help="Optional replay_reason.")
    p_redo.add_argument("--note", metavar="TEXT", help="Optional flow_meta.note.")
    p_redo.add_argument(
        "--session",
        metavar="UUID",
        help="Optional session_id for the new execution.",
    )
    add_format_argument(p_redo)

    # --- dup ---
    p_dup = sub.add_parser(
        "dup",
        help=(
            "Create a logical branch marker (new session_id UUID, no HTTP). "
            "Later: once --session <id> stamps executions on this branch."
        ),
    )
    p_dup.add_argument(
        "flow_id",
        help="Parent/baseline flow UUID to fork messaging from.",
    )
    add_format_argument(p_dup)

    # --- show ---
    p_show = sub.add_parser(
        "show",
        help="Show request/response for a send or any flow.",
    )
    p_show.add_argument("flow_id", help="Flow UUID.")
    p_show.add_argument(
        "--body",
        choices=["request", "response", "both", "none"],
        default="none",
        help="Include body content (default: none; previews only in JSON without --full).",
    )
    p_show.add_argument(
        "--full",
        action="store_true",
        help=(
            "Include full body bytes as UTF-8 (replace errors). "
            "Warn: large responses can produce huge JSON."
        ),
    )
    add_format_argument(p_show)

    # --- export ---
    p_export = sub.add_parser(
        "export",
        help="Write request.http + response.http under --out DIR.",
    )
    p_export.add_argument("flow_id", help="Flow UUID.")
    p_export.add_argument(
        "--out",
        required=True,
        metavar="DIR",
        dest="out_dir",
        help="Output directory (created if missing).",
    )
    add_format_argument(p_export)

    # --- history ---
    p_hist = sub.add_parser(
        "history",
        help="List send executions under a baseline / root original_flow_id.",
    )
    p_hist.add_argument(
        "--from",
        dest="from_flow_id",
        required=True,
        metavar="FLOW_ID",
        help="Baseline or any flow in the chain (resolved to root).",
    )
    p_hist.add_argument(
        "--session",
        metavar="UUID",
        help="Filter by flow_meta.session_id.",
    )
    p_hist.add_argument(
        "--parent",
        metavar="FLOW_ID",
        dest="parent_flow_id",
        help="Filter by flow_meta.parent_flow_id.",
    )
    p_hist.add_argument(
        "--source",
        choices=["manual_send", "ai_send"],
        help="Filter by source.",
    )
    p_hist.add_argument(
        "--limit",
        type=int,
        default=100,
        metavar="N",
        help="Max rows (default 100).",
    )
    add_format_argument(p_hist)

    # --- tree ---
    p_tree = sub.add_parser(
        "tree",
        help="ASCII parent→child tree of send executions under a root.",
    )
    p_tree.add_argument(
        "--from",
        dest="from_flow_id",
        required=True,
        metavar="FLOW_ID",
        help="Baseline or any flow in the chain (resolved to root).",
    )
    p_tree.add_argument(
        "--limit",
        type=int,
        default=200,
        metavar="N",
        help="Max executions considered (default 200).",
    )
    add_format_argument(p_tree)

    # --- diff ---
    p_diff = sub.add_parser(
        "diff",
        help="Request and/or response diff between two flows.",
    )
    p_diff.add_argument("flow_a", help="Baseline / left flow UUID.")
    p_diff.add_argument("flow_b", help="Execution / right flow UUID.")
    p_diff.add_argument(
        "--side",
        choices=["request", "response", "both"],
        default="both",
        help="Which side(s) to compare (default: both).",
    )
    add_format_argument(p_diff)

    # --- note ---
    p_note = sub.add_parser(
        "note",
        help="Set flow_meta.note on a send execution only (never proxy_capture).",
    )
    p_note.add_argument("flow_id", help="Send execution flow UUID.")
    p_note.add_argument(
        "--text",
        required=True,
        metavar="TEXT",
        help="Note text to store.",
    )
    add_format_argument(p_note)

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )

    dispatch = {
        "from": cmd_send_from,
        "edit": cmd_send_edit,
        "once": cmd_send_once,
        "redo": cmd_send_redo,
        "dup": cmd_send_dup,
        "show": cmd_send_show,
        "export": cmd_send_export,
        "history": cmd_send_history,
        "tree": cmd_send_tree,
        "diff": cmd_send_diff,
        "note": cmd_send_note,
    }
    handler = dispatch.get(args.send_cmd)
    if handler is None:
        parser.error(f"Unknown send command: {args.send_cmd}")
    handler(project, args)


def _add_edit_flags(p: argparse.ArgumentParser) -> None:
    """Shared structured/raw edit flags for once (and compose with --raw-file)."""
    p.add_argument("--method", metavar="METHOD", help="Override HTTP method.")
    p.add_argument(
        "--url",
        metavar="URL",
        help="Override absolute URL (re-derives host/path/query).",
    )
    p.add_argument(
        "--path",
        metavar="PATH",
        help="Override path only; keep host/scheme; rebuild URL.",
    )
    p.add_argument(
        "--host",
        metavar="HOST",
        help="Override host (URL + Host header unless --no-sync-host).",
    )
    p.add_argument(
        "--no-sync-host",
        dest="no_sync_host",
        action="store_true",
        help="With --host: do not update the Host header.",
    )
    p.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="Name: value",
        help="Set/replace a header (repeatable).",
    )
    p.add_argument(
        "--remove-header",
        action="append",
        default=[],
        dest="remove_header",
        metavar="Name",
        help="Remove a header (repeatable).",
    )
    p.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Set/replace a cookie (Cookie header + map; repeatable).",
    )
    p.add_argument(
        "--remove-cookie",
        action="append",
        default=[],
        dest="remove_cookie",
        metavar="NAME",
        help="Remove a cookie (repeatable).",
    )
    p.add_argument(
        "--query",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set/replace a query parameter (repeatable).",
    )
    p.add_argument(
        "--remove-query",
        action="append",
        default=[],
        dest="remove_query",
        metavar="KEY",
        help="Drop a query parameter (repeatable).",
    )
    p.add_argument(
        "--json-set",
        action="append",
        default=[],
        dest="json_set",
        metavar="KEY=VALUE",
        help="Set top-level JSON object key (string value; body must be JSON object).",
    )
    body_group = p.add_mutually_exclusive_group()
    body_group.add_argument(
        "--body",
        metavar="STRING",
        help="Request body as a UTF-8 string.",
    )
    body_group.add_argument(
        "--body-file",
        dest="body_file",
        metavar="PATH",
        help="Read request body from a file (binary-safe).",
    )
    body_group.add_argument(
        "--body-stdin",
        dest="body_stdin",
        action="store_true",
        help="Read request body from stdin (binary-safe).",
    )
    p.add_argument(
        "--raw-file",
        dest="raw_file",
        metavar="PATH",
        help="Full raw HTTP request message (request-line + headers + body).",
    )
    p.add_argument(
        "--no-update-content-length",
        dest="no_update_content_length",
        action="store_true",
        help=(
            "Do not fix Content-Length to match body. "
            "Default is ON (Burp-like): strip stale CL and set correct length. "
            "Use this for deliberate edge / smuggling tests."
        ),
    )


# ------------------------------------------------------------------ #
# Handlers                                                             #
# ------------------------------------------------------------------ #

def cmd_send_from(project: object, args: argparse.Namespace) -> None:
    """Materialize draft raw HTTP from a flow. No send, no DB write."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow_id = args.flow_id

    try:
        draft, out_path, _raw = send_db.materialize_draft_path(
            db_path,
            flow_id,
            Path(args.raw_out) if args.raw_out else None,
        )
    except FileNotFoundError:
        cli_error(f"Flow '{flow_id}' not found.")

    body_len = len(draft["request_body"]) if draft.get("request_body") else 0
    payload = {
        "parent_flow_id": flow_id,
        "original_flow_id": draft["original_flow_id"],
        "method": draft["method"],
        "url": draft["url"],
        "header_count": len(draft.get("request_headers") or {}),
        "request_body_len": body_len,
        "raw_path": str(out_path),
    }

    if wants_json(args):
        cli_json(payload)
        return

    cli_success(
        "Draft materialized (not sent).",
        {
            "Parent": flow_id,
            "Original": draft["original_flow_id"],
            "Method": draft["method"],
            "URL": draft["url"],
            "Headers": str(payload["header_count"]),
            "Body bytes": str(body_len),
            "Raw file": str(out_path),
        },
    )


def cmd_send_edit(project: object, args: argparse.Namespace) -> None:
    """Materialize raw, open editor; optional --send after save."""
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id  # type: ignore[attr-defined]
    flow_id = args.flow_id

    editor = args.editor or os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        if not sys.stdin.isatty() and not args.editor:
            cli_error(
                "No editor available in non-interactive mode. "
                "Pass --editor CMD, or use: talos send from … && "
                "talos send once … --raw-file PATH."
            )
        cli_error(
            "No editor configured. Set $VISUAL or $EDITOR, or pass --editor CMD."
        )

    try:
        draft, out_path, _raw = send_db.materialize_draft_path(
            db_path,
            flow_id,
            Path(args.raw_out) if args.raw_out else None,
        )
    except FileNotFoundError:
        cli_error(f"Flow '{flow_id}' not found.")

    # Resolve editor binary (first token) for PATH check when simple command.
    editor_bin = editor.split()[0] if editor else ""
    if editor_bin and not Path(editor_bin).is_file() and shutil.which(editor_bin) is None:
        cli_error(f"Editor not found: {editor_bin}")

    try:
        # shell=True allows $EDITOR="code --wait" style commands.
        rc = subprocess.call(f'{editor} "{out_path}"', shell=True)
    except OSError as exc:
        cli_error(f"Failed to launch editor: {exc}")
    if rc != 0:
        cli_error(f"Editor exited with status {rc}; not sending.")

    payload = {
        "parent_flow_id": flow_id,
        "original_flow_id": draft["original_flow_id"],
        "raw_path": str(out_path),
        "sent": False,
        "execution_flow_id": None,
    }

    if not args.do_send:
        if wants_json(args):
            cli_json(payload)
            return
        cli_success(
            "Draft edited (not sent).",
            {
                "Parent": flow_id,
                "Raw file": str(out_path),
                "Hint": "talos send once <id> --raw-file " + str(out_path),
            },
        )
        return

    raw_message = out_path.read_bytes()
    outcome = asyncio.run(
        send_once(
            flow_id,
            db_path,
            project_id,
            source=args.source,
            reason=args.reason,
            note=args.note,
            session_id=args.session,
            update_content_length=not args.no_update_content_length,
            raw_message=raw_message,
        )
    )
    _handle_once_preconditions(outcome, flow_id)
    payload["sent"] = True
    payload["execution_flow_id"] = outcome.execution_flow_id
    # Re-use once printer for consistent AI contract when sending.
    _print_once_outcome(outcome, args)


def cmd_send_once(project: object, args: argparse.Namespace) -> None:
    """Apply edits, send once or multi-profile, store new flow(s)."""
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id  # type: ignore[attr-defined]
    parent_id = args.flow_id

    if args.repeat is not None and args.parallel is not None:
        cli_error("Use only one of --repeat or --parallel.", exit_code=2)
    if args.delay_ms and args.parallel is not None:
        cli_error("--delay-ms applies only to --repeat (sequential).", exit_code=2)
    if args.delay_ms < 0:
        cli_error("--delay-ms must be >= 0.", exit_code=2)

    kwargs = _build_send_kwargs(args)

    try:
        if args.repeat is not None:
            multi = asyncio.run(
                send_repeat(
                    parent_id,
                    db_path,
                    project_id,
                    args.repeat,
                    delay_ms=args.delay_ms,
                    **kwargs,
                )
            )
            _print_multi_outcome(multi, args)
            return
        if args.parallel is not None:
            multi = asyncio.run(
                send_parallel(
                    parent_id,
                    db_path,
                    project_id,
                    args.parallel,
                    **kwargs,
                )
            )
            _print_multi_outcome(multi, args)
            return

        outcome = asyncio.run(
            send_once(parent_id, db_path, project_id, **kwargs)
        )
    except ValueError as exc:
        cli_error(str(exc), exit_code=2)

    _handle_once_preconditions(outcome, parent_id)
    _print_once_outcome(outcome, args)


def cmd_send_redo(project: object, args: argparse.Namespace) -> None:
    """Re-send as-sent request of a previous execution."""
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id  # type: ignore[attr-defined]
    flow_id = args.flow_id

    outcome = asyncio.run(
        redo_send(
            flow_id,
            db_path,
            project_id,
            source=args.source,
            reason=args.reason,
            note=args.note,
            session_id=args.session,
        )
    )
    _handle_once_preconditions(outcome, flow_id)
    _print_once_outcome(outcome, args)


def cmd_send_dup(project: object, args: argparse.Namespace) -> None:
    """Print a new session_id for branching (no HTTP, no DB write)."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow_id = args.flow_id

    flow = send_db.get_flow_for_send(db_path, flow_id)
    if flow is None:
        cli_error(f"Flow '{flow_id}' not found.")

    root_id = send_db.resolve_root_flow_id(flow)
    session_id = str(uuid.uuid4())
    payload = {
        "session_id": session_id,
        "parent_flow_id": flow_id,
        "original_flow_id": root_id,
        "message": (
            "Branch created (no HTTP). "
            f"Use: talos send once {flow_id} --session {session_id} …"
        ),
    }

    if wants_json(args):
        cli_json(payload)
        return

    cli_success(
        "Branch session created (no send).",
        {
            "session_id": session_id,
            "parent_flow_id": flow_id,
            "original_flow_id": root_id,
            "next": f"talos send once {flow_id} --session {session_id} …",
        },
    )


def cmd_send_show(project: object, args: argparse.Namespace) -> None:
    """Show request/response for a flow with optional full bodies."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow = send_db.get_flow_show(db_path, args.flow_id)
    if flow is None:
        cli_error(f"Flow '{args.flow_id}' not found.")

    meta = flow.get("flow_meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    req_len = flow.get("request_body_len") or 0
    resp_len = flow.get("response_body_len") or 0
    payload = {
        "id": flow["id"],
        "method": flow["method"],
        "url": flow["url"],
        "status_code": flow.get("status_code"),
        "source": flow.get("source"),
        "original_flow_id": flow.get("original_flow_id"),
        "parent_flow_id": meta.get("parent_flow_id"),
        "session_id": meta.get("session_id"),
        "note": meta.get("note"),
        "verdict": meta.get("verdict"),
        "replay_reason": flow.get("replay_reason"),
        "replay_error": flow.get("replay_error"),
        "content_type": flow.get("content_type") or "",
        "request_body_len": req_len,
        "response_body_len": resp_len,
        "captured_at": flow.get("captured_at"),
        "endpoint_id": flow.get("endpoint_id"),
        "request_headers": _headers_as_dict(flow.get("request_headers")),
        "response_headers": _headers_as_dict(flow.get("response_headers")),
        "flow_meta": meta,
    }

    include_req = args.body in ("request", "both")
    include_resp = args.body in ("response", "both")
    # JSON without --body still gets short previews (Phase 1 AI habit).
    if wants_json(args):
        if include_req or args.full:
            if args.full or include_req:
                payload["request_body"] = _body_as_text(
                    flow.get("request_body"), full=args.full or include_req
                )
        else:
            payload["request_body_preview"] = _preview_body(flow.get("request_body"))
        if include_resp or args.full:
            if args.full or include_resp:
                payload["response_body"] = _body_as_text(
                    flow.get("response_body"), full=args.full or include_resp
                )
        else:
            payload["response_body_preview"] = _preview_body(flow.get("response_body"))
        # --full without --body still dumps both for operators who asked for full.
        if args.full and args.body == "none":
            payload["request_body"] = _body_as_text(flow.get("request_body"), full=True)
            payload["response_body"] = _body_as_text(flow.get("response_body"), full=True)
            payload.pop("request_body_preview", None)
            payload.pop("response_body_preview", None)
        cli_json(payload)
        return

    lines = [
        f"  id              : {payload['id']}",
        f"  method          : {payload['method']}",
        f"  url             : {payload['url']}",
        f"  status_code     : {payload['status_code'] if payload['status_code'] is not None else '—'}",
        f"  source          : {payload['source']}",
        f"  original_flow_id: {payload['original_flow_id'] or '—'}",
        f"  parent_flow_id  : {payload['parent_flow_id'] or '—'}",
        f"  session_id      : {payload['session_id'] or '—'}",
        f"  verdict         : {payload['verdict'] or '—'}",
        f"  reason          : {payload['replay_reason'] or '—'}",
        f"  note            : {payload['note'] or '—'}",
        f"  error           : {payload['replay_error'] or '—'}",
        f"  request_bytes   : {req_len}",
        f"  response_bytes  : {resp_len}",
        f"  content_type    : {payload['content_type'] or '—'}",
        f"  captured_at     : {payload['captured_at'] or '—'}",
    ]
    print("\n".join(lines))

    if include_req or (args.full and args.body == "none"):
        print("\n--- request body ---")
        print(_body_as_text(flow.get("request_body"), full=True) or "(empty)")
    if include_resp or (args.full and args.body == "none"):
        print("\n--- response body ---")
        print(_body_as_text(flow.get("response_body"), full=True) or "(empty)")


def cmd_send_export(project: object, args: argparse.Namespace) -> None:
    """Export request.http + response under --out DIR."""
    db_path = project.db_path  # type: ignore[attr-defined]
    try:
        result = send_db.export_flow_http(
            db_path, args.flow_id, Path(args.out_dir)
        )
    except FileNotFoundError:
        cli_error(f"Flow '{args.flow_id}' not found.")
    except OSError as exc:
        cli_error(f"Export failed: {exc}")

    if wants_json(args):
        cli_json(result)
        return

    cli_success(
        "Exported.",
        {
            "flow_id": result["flow_id"],
            "out_dir": result["out_dir"],
            "request": result["request_path"],
            "response": result["response_path"],
            "request_bytes": str(result["request_bytes"]),
            "response_bytes": str(result["response_bytes"]),
        },
    )


def cmd_send_history(project: object, args: argparse.Namespace) -> None:
    """List send executions under a root with Phase 2 filters/columns."""
    db_path = project.db_path  # type: ignore[attr-defined]
    root_arg = args.from_flow_id

    rows = send_db.list_send_history(
        db_path,
        root_arg,
        limit=max(1, args.limit),
        session_id=args.session,
        parent_flow_id=args.parent_flow_id,
        source=args.source,
    )

    parent = send_db.get_flow_for_send(db_path, root_arg)
    root_id = send_db.resolve_root_flow_id(parent) if parent else root_arg

    if wants_json(args):
        cli_json(
            {
                "from": root_arg,
                "original_flow_id": root_id,
                "session_id": args.session,
                "parent_flow_id": args.parent_flow_id,
                "source": args.source,
                "count": len(rows),
                "executions": [
                    {
                        "id": r["id"],
                        "parent_flow_id": r.get("parent_flow_id"),
                        "session_id": r.get("session_id"),
                        "method": r["method"],
                        "url": r["url"],
                        "status_code": r.get("status_code"),
                        "source": r.get("source"),
                        "verdict": r.get("verdict"),
                        "replay_reason": r.get("replay_reason"),
                        "note": r.get("note"),
                        "replay_error": r.get("replay_error"),
                        "profile": r.get("profile"),
                        "profile_index": r.get("profile_index"),
                        "profile_count": r.get("profile_count"),
                        "request_body_len": r.get("request_body_len") or 0,
                        "response_body_len": r.get("response_body_len") or 0,
                        "captured_at": r.get("captured_at"),
                        "flow_meta": r.get("flow_meta") or {},
                    }
                    for r in rows
                ],
            }
        )
        return

    if not rows:
        print(f"No send executions for original_flow_id={root_id}")
        return

    print(f"Send history for original_flow_id={root_id}  ({len(rows)} execution(s))\n")
    print(
        f"{'ID':<38} {'PARENT':<10} {'SESS':<8} {'ST':>4} {'VER':<10} "
        f"{'REQ':>5} {'RESP':>5}  NOTE/REASON"
    )
    print("-" * 110)
    for r in rows:
        parent_s = (r.get("parent_flow_id") or "")[:8]
        sess = (r.get("session_id") or "")[:8]
        note = r.get("note") or r.get("replay_reason") or ""
        print(
            f"{r['id']:<38} "
            f"{parent_s:<10} "
            f"{sess:<8} "
            f"{_fmt_status(r.get('status_code')):>4} "
            f"{(r.get('verdict') or '—')[:10]:<10} "
            f"{(r.get('request_body_len') or 0):>5} "
            f"{(r.get('response_body_len') or 0):>5}  "
            f"{note}"
        )


def cmd_send_tree(project: object, args: argparse.Namespace) -> None:
    """ASCII parent→child tree."""
    db_path = project.db_path  # type: ignore[attr-defined]
    lines = send_db.build_send_tree(
        db_path, args.from_flow_id, limit=max(1, args.limit)
    )
    parent = send_db.get_flow_for_send(db_path, args.from_flow_id)
    root_id = (
        send_db.resolve_root_flow_id(parent) if parent else args.from_flow_id
    )

    if wants_json(args):
        cli_json(
            {
                "from": args.from_flow_id,
                "original_flow_id": root_id,
                "lines": lines,
            }
        )
        return

    if not lines:
        print(f"No send executions for original_flow_id={root_id}")
        return
    print("\n".join(lines))


def cmd_send_diff(project: object, args: argparse.Namespace) -> None:
    """Request and/or response dual-sided diff."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow_a = send_db.get_flow_for_send(db_path, args.flow_a)
    flow_b = send_db.get_flow_for_send(db_path, args.flow_b)
    if flow_a is None:
        cli_error(f"Flow '{args.flow_a}' not found.")
    if flow_b is None:
        cli_error(f"Flow '{args.flow_b}' not found.")

    right = dict(flow_b)
    if "replay_error" not in right:
        right["replay_error"] = flow_b.get("replay_error")

    payload: dict = {
        "flow_a": args.flow_a,
        "flow_b": args.flow_b,
        "side": args.side,
    }

    if args.side in ("request", "both"):
        payload["request"] = compute_request_diff(flow_a, flow_b)

    if args.side in ("response", "both"):
        diff = compute_diff(flow_a, right)
        payload["response"] = enhance_response_diff(
            flow_a,
            right,
            verdict=diff.verdict,
            status_changed=diff.status_changed,
            status_diff=diff.status_diff,
            length_diff=diff.length_diff,
        )
        # Top-level convenience keys (Phase 1 AI habit + Phase 2).
        payload["verdict"] = diff.verdict
        payload["status_changed"] = diff.status_changed
        payload["status_diff"] = diff.status_diff
        payload["length_diff"] = diff.length_diff
        payload["status_a"] = flow_a.get("status_code")
        payload["status_b"] = flow_b.get("status_code")

    if wants_json(args):
        cli_json(payload)
        return

    print(f"  flow_a : {args.flow_a}")
    print(f"  flow_b : {args.flow_b}")
    print(f"  side   : {args.side}")

    if "request" in payload:
        req = payload["request"]
        print("\n  [request]")
        print(f"    changed     : {req['changed']}")
        if req["method_changed"]:
            print(f"    method      : {req['method_a']} → {req['method_b']}")
        if req["url_changed"]:
            print(f"    url         : {req['url_a']} → {req['url_b']}")
        if req["path_changed"]:
            print(f"    path        : {req['path_a']} → {req['path_b']}")
        if req["query_changed"]:
            print(f"    query       : {req['query_a']!r} → {req['query_b']!r}")
        hdrs = req["headers"]
        if hdrs["added"] or hdrs["removed"] or hdrs["changed"]:
            print(
                f"    headers     : +{len(hdrs['added'])} "
                f"-{len(hdrs['removed'])} ~{len(hdrs['changed'])}"
            )
        print(
            f"    body        : equal={req['body_equal']} "
            f"len {req['body_len_a']} → {req['body_len_b']} "
            f"(Δ{req['body_len_delta']})"
        )
        if req.get("body_text_diff"):
            print("    body_diff   :")
            for line in req["body_text_diff"][:80]:
                print(f"      {line}")

    if "response" in payload:
        resp = payload["response"]
        print("\n  [response]")
        print(f"    verdict     : {resp['verdict']}")
        print(
            f"    status      : {resp['status_a']} → {resp['status_b']}"
            f"  ({resp['status_diff'] or 'unchanged'})"
        )
        print(f"    length_diff : {resp['length_diff']}")
        if resp.get("content_type_changed"):
            print(
                f"    content_type: {resp['content_type_a']!r} → "
                f"{resp['content_type_b']!r}"
            )
        rh = resp["headers"]
        if rh["added"] or rh["removed"] or rh["changed"]:
            print(
                f"    headers     : +{len(rh['added'])} "
                f"-{len(rh['removed'])} ~{len(rh['changed'])}"
            )
        if resp.get("body_text_diff"):
            print("    body_diff   :")
            for line in resp["body_text_diff"][:80]:
                print(f"      {line}")


def cmd_send_note(project: object, args: argparse.Namespace) -> None:
    """Update flow_meta.note on send rows only."""
    db_path = project.db_path  # type: ignore[attr-defined]
    ok, err = send_db.update_send_note(db_path, args.flow_id, args.text)
    if not ok:
        if "not found" in err.lower():
            cli_error(err)
        cli_error(err)

    payload = {"id": args.flow_id, "note": args.text, "updated": True}
    if wants_json(args):
        cli_json(payload)
        return
    cli_success("Note updated.", {"id": args.flow_id, "note": args.text})


# ------------------------------------------------------------------ #
# Output helpers                                                       #
# ------------------------------------------------------------------ #

def _handle_once_preconditions(outcome: SendOutcome, parent_id: str) -> None:
    if outcome.failure_reason == "flow_not_found":
        cli_error(f"Flow '{parent_id}' not found.")
    if outcome.failure_reason == "endpoint_annotated_logout":
        cli_precondition_error(
            f"Flow '{parent_id}' belongs to a logout endpoint — send blocked."
        )
    if outcome.failure_reason and outcome.failure_reason.startswith("raw_parse_error"):
        cli_error(outcome.failure_reason)
    if outcome.failure_reason and outcome.failure_reason.startswith("edit_error"):
        cli_error(outcome.failure_reason)
    if outcome.failure_reason and outcome.failure_reason.startswith("invalid_source"):
        cli_error(outcome.failure_reason, exit_code=2)


def _print_once_outcome(outcome: SendOutcome, args: argparse.Namespace) -> None:
    payload = {
        "execution_flow_id": outcome.execution_flow_id,
        "parent_flow_id": outcome.parent_flow_id,
        "original_flow_id": outcome.original_flow_id,
        "status_code": outcome.status_code,
        "verdict": outcome.verdict,
        "success": outcome.success,
        "failure_reason": outcome.failure_reason,
        "request_body_len": outcome.request_body_len,
        "response_body_len": outcome.response_body_len,
        "source": outcome.source,
        "session_id": outcome.session_id,
        "note": outcome.note,
        "profile": outcome.profile,
        "profile_index": outcome.profile_index,
        "profile_count": outcome.profile_count,
    }

    if wants_json(args):
        cli_json(payload)
        if not outcome.success and outcome.execution_flow_id is None:
            sys.exit(1)
        return

    fields = {
        "execution_flow_id": outcome.execution_flow_id or "—",
        "parent_flow_id": outcome.parent_flow_id,
        "original_flow_id": outcome.original_flow_id,
        "status_code": (
            str(outcome.status_code) if outcome.status_code is not None else "—"
        ),
        "verdict": outcome.verdict or "—",
        "request_body_len": str(outcome.request_body_len),
        "response_body_len": str(outcome.response_body_len),
        "source": outcome.source,
    }
    if outcome.session_id:
        fields["session_id"] = outcome.session_id
    if outcome.note:
        fields["note"] = outcome.note
    if outcome.profile != "once":
        fields["profile"] = (
            f"{outcome.profile} {outcome.profile_index + 1}/{outcome.profile_count}"
        )
    if outcome.failure_reason:
        fields["failure_reason"] = outcome.failure_reason

    if outcome.success:
        cli_success("Sent.", fields)
    else:
        cli_success("Send finished with error (flow stored).", fields)


def _print_multi_outcome(multi: MultiSendOutcome, args: argparse.Namespace) -> None:
    # Precondition failures on first outcome with nothing stored.
    if multi.outcomes:
        first = multi.outcomes[0]
        if first.failure_reason in (
            "flow_not_found",
            "endpoint_annotated_logout",
        ) or (
            first.failure_reason
            and first.failure_reason.startswith(
                ("raw_parse_error", "edit_error", "invalid_source")
            )
        ):
            _handle_once_preconditions(first, multi.parent_flow_id)

    executions = []
    for o in multi.outcomes:
        executions.append(
            {
                "execution_flow_id": o.execution_flow_id,
                "parent_flow_id": o.parent_flow_id,
                "status_code": o.status_code,
                "verdict": o.verdict,
                "success": o.success,
                "failure_reason": o.failure_reason,
                "profile_index": o.profile_index,
                "request_body_len": o.request_body_len,
                "response_body_len": o.response_body_len,
            }
        )

    payload = {
        "profile": multi.profile,
        "profile_count": multi.profile_count,
        "parent_flow_id": multi.parent_flow_id,
        "original_flow_id": multi.original_flow_id,
        "session_id": multi.session_id,
        "execution_flow_ids": multi.execution_flow_ids,
        "stored_count": len(multi.execution_flow_ids),
        "success_count": sum(1 for o in multi.outcomes if o.success),
        "executions": executions,
    }

    if wants_json(args):
        cli_json(payload)
        if not multi.any_stored:
            sys.exit(1)
        return

    print(
        f"  profile           : {multi.profile} × {multi.profile_count}\n"
        f"  parent_flow_id    : {multi.parent_flow_id}\n"
        f"  original_flow_id  : {multi.original_flow_id}\n"
        f"  session_id        : {multi.session_id or '—'}\n"
        f"  stored            : {len(multi.execution_flow_ids)}\n"
        f"  success           : {payload['success_count']}"
    )
    print(
        f"\n{'IDX':>3} {'STATUS':>6} {'VERDICT':<10} EXECUTION_ID"
    )
    for o in multi.outcomes:
        print(
            f"{o.profile_index:>3} "
            f"{_fmt_status(o.status_code):>6} "
            f"{(o.verdict or '—')[:10]:<10} "
            f"{o.execution_flow_id or '—'}"
        )
    if not multi.any_stored:
        sys.exit(1)


def _build_send_kwargs(args: argparse.Namespace) -> dict:
    headers = _parse_header_args(args.header)
    query_params = _parse_query_args(args.query)
    cookies = _parse_kv_args(args.cookie, flag="--cookie")
    json_sets = _parse_kv_args(args.json_set, flag="--json-set")
    body, body_set = _resolve_body(args)

    raw_message: Optional[bytes] = None
    if args.raw_file:
        raw_path = Path(args.raw_file).expanduser()
        if not raw_path.is_file():
            cli_error(f"Raw request file not found: {raw_path}")
        raw_message = raw_path.read_bytes()

    return {
        "source": args.source,
        "reason": args.reason,
        "note": args.note,
        "session_id": args.session,
        "update_content_length": not args.no_update_content_length,
        "method": args.method,
        "url": args.url,
        "path": args.path,
        "host": args.host,
        "sync_host_header": not args.no_sync_host,
        "headers": headers or None,
        "remove_headers": args.remove_header or None,
        "query_params": query_params or None,
        "remove_query": args.remove_query or None,
        "cookies": cookies or None,
        "remove_cookies": args.remove_cookie or None,
        "json_sets": json_sets or None,
        "body": body,
        "body_set": body_set,
        "raw_message": raw_message,
    }


def _parse_header_args(items: list[str]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in items or []:
        if ":" not in item:
            cli_error(
                f"Invalid --header {item!r}: expected 'Name: value'.",
                exit_code=2,
            )
        name, value = item.split(":", 1)
        name = name.strip()
        if not name:
            cli_error(
                f"Invalid --header {item!r}: empty header name.",
                exit_code=2,
            )
        result.append((name, value.strip()))
    return result


def _parse_query_args(items: list[str]) -> list[tuple[str, str]]:
    return _parse_kv_args(items, flag="--query")


def _parse_kv_args(items: list[str], *, flag: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in items or []:
        if "=" not in item:
            cli_error(
                f"Invalid {flag} {item!r}: expected KEY=VALUE.",
                exit_code=2,
            )
        key, value = item.split("=", 1)
        if not key:
            cli_error(
                f"Invalid {flag} {item!r}: empty key.",
                exit_code=2,
            )
        result.append((key, value))
    return result


def _resolve_body(args: argparse.Namespace) -> tuple[Optional[bytes], bool]:
    """Return (body_bytes, body_was_explicitly_set)."""
    if getattr(args, "body", None) is not None:
        return args.body.encode("utf-8"), True
    if getattr(args, "body_file", None):
        path = Path(args.body_file).expanduser()
        if not path.is_file():
            cli_error(f"Body file not found: {path}")
        return path.read_bytes(), True
    if getattr(args, "body_stdin", False):
        return sys.stdin.buffer.read(), True
    return None, False


def _headers_as_dict(value: object) -> dict:
    import json as _json

    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = _json.loads(value) if value else {}
            return dict(parsed) if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _preview_body(value: object, limit: int = 512) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value[:limit].decode("utf-8", errors="replace")
        if len(value) > limit:
            text += "…"
        return text
    text = str(value)
    return text[:limit] + ("…" if len(text) > limit else "")


def _body_as_text(value: object, *, full: bool = False, limit: int = 512) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        if full:
            return value.decode("utf-8", errors="replace")
        text = value[:limit].decode("utf-8", errors="replace")
        if len(value) > limit:
            text += "…"
        return text
    text = str(value)
    if full:
        return text
    return text[:limit] + ("…" if len(text) > limit else "")


def _fmt_status(code: object) -> str:
    if code is None:
        return "—"
    return str(code)
