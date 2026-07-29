"""
Module: talos.send.cli

Purpose:
    CLI for Talos Repeater Phase 1 (mutable send):

        talos send from <flow_id> [--raw-out PATH]
        talos send once <flow_id> [edit options…]
        talos send show <flow_id> [--format table|json]
        talos send history --from <id> [--format table|json]
        talos send diff <flow_a> <flow_b> [--format table|json]

    All commands require a bound project (registry ACTIVE, --project, or
    TALOS_PROJECT). Execution is immediate (no scheduler) in Phase 1.

    AI contract: fully non-interactive; --format json on once/show/history/diff.

Dependencies: argparse, asyncio, sys, pathlib
              talos.cli_output, talos.projects.manager, talos.send.*
Data flow:
    argv → project gate → handlers → engine / db → stdout
Side effects:
    - once: outbound HTTP + DB insert
    - from: may write a raw request file
    - show/history/diff: read-only
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
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
from talos.send.engine import SendOutcome, send_once


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
            "Repeater: edit a captured request, send once, review. "
            "Never mutates the baseline flow (new row per send). "
            "Distinct from 'talos replay' (exact re-send)."
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

    # --- once ---
    p_once = sub.add_parser(
        "once",
        help="Apply edits, send once, store a new flow with lineage.",
    )
    p_once.add_argument(
        "flow_id",
        help="Parent flow UUID to fork from (capture or previous send).",
    )
    p_once.add_argument("--method", metavar="METHOD", help="Override HTTP method.")
    p_once.add_argument(
        "--url",
        metavar="URL",
        help="Override absolute URL (re-derives host/path/query).",
    )
    p_once.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="Name: value",
        help="Set/replace a header (repeatable).",
    )
    p_once.add_argument(
        "--remove-header",
        action="append",
        default=[],
        dest="remove_header",
        metavar="Name",
        help="Remove a header (repeatable).",
    )
    p_once.add_argument(
        "--query",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set/replace a query parameter (repeatable).",
    )
    body_group = p_once.add_mutually_exclusive_group()
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
    p_once.add_argument(
        "--raw-file",
        dest="raw_file",
        metavar="PATH",
        help="Full raw HTTP request message (request-line + headers + body).",
    )
    p_once.add_argument(
        "--no-update-content-length",
        dest="no_update_content_length",
        action="store_true",
        help=(
            "Do not fix Content-Length to match body. "
            "Default is ON (Burp-like): strip stale CL and set correct length. "
            "Use this for deliberate edge / smuggling tests."
        ),
    )
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
    add_format_argument(p_once)

    # --- show ---
    p_show = sub.add_parser(
        "show",
        help="Show request/response summary for a send or any flow.",
    )
    p_show.add_argument("flow_id", help="Flow UUID.")
    add_format_argument(p_show)

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
        "--limit",
        type=int,
        default=100,
        metavar="N",
        help="Max rows (default 100).",
    )
    add_format_argument(p_hist)

    # --- diff ---
    p_diff = sub.add_parser(
        "diff",
        help="Response-side verdict between two flows (reuse replay.diff).",
    )
    p_diff.add_argument("flow_a", help="Baseline / left flow UUID.")
    p_diff.add_argument("flow_b", help="Execution / right flow UUID.")
    add_format_argument(p_diff)

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )

    if args.send_cmd == "from":
        cmd_send_from(project, args)
    elif args.send_cmd == "once":
        cmd_send_once(project, args)
    elif args.send_cmd == "show":
        cmd_send_show(project, args)
    elif args.send_cmd == "history":
        cmd_send_history(project, args)
    elif args.send_cmd == "diff":
        cmd_send_diff(project, args)
    else:
        parser.error(f"Unknown send command: {args.send_cmd}")


# ------------------------------------------------------------------ #
# Handlers                                                             #
# ------------------------------------------------------------------ #

def cmd_send_from(project: object, args: argparse.Namespace) -> None:
    """Materialize draft raw HTTP from a flow. No send, no DB write."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow_id = args.flow_id

    flow = send_db.get_flow_for_send(db_path, flow_id)
    if flow is None:
        cli_error(f"Flow '{flow_id}' not found.")

    draft = draft_mod.draft_from_flow(flow)
    raw = draft_mod.draft_to_raw_bytes(draft)

    if args.raw_out:
        out_path = Path(args.raw_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)
    else:
        tmp = tempfile.NamedTemporaryFile(
            prefix=f"talos-send-{flow_id[:8]}-",
            suffix=".http",
            delete=False,
        )
        tmp.write(raw)
        tmp.close()
        out_path = Path(tmp.name)

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


def cmd_send_once(project: object, args: argparse.Namespace) -> None:
    """Apply edits, send once immediately, store new flow."""
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id  # type: ignore[attr-defined]
    parent_id = args.flow_id

    headers = _parse_header_args(args.header)
    query_params = _parse_query_args(args.query)
    body, body_set = _resolve_body(args)

    raw_message: Optional[bytes] = None
    if args.raw_file:
        raw_path = Path(args.raw_file).expanduser()
        if not raw_path.is_file():
            cli_error(f"Raw request file not found: {raw_path}")
        raw_message = raw_path.read_bytes()

    outcome = asyncio.run(
        send_once(
            parent_id,
            db_path,
            project_id,
            source=args.source,
            reason=args.reason,
            update_content_length=not args.no_update_content_length,
            method=args.method,
            url=args.url,
            headers=headers or None,
            remove_headers=args.remove_header or None,
            query_params=query_params or None,
            body=body,
            body_set=body_set,
            raw_message=raw_message,
        )
    )

    if outcome.failure_reason == "flow_not_found":
        cli_error(f"Flow '{parent_id}' not found.")

    if outcome.failure_reason == "endpoint_annotated_logout":
        cli_precondition_error(
            f"Flow '{parent_id}' belongs to a logout endpoint — send blocked."
        )

    if outcome.failure_reason and outcome.failure_reason.startswith("raw_parse_error"):
        cli_error(outcome.failure_reason)

    _print_once_outcome(outcome, args)


def cmd_send_show(project: object, args: argparse.Namespace) -> None:
    """Show concise request/response for a flow."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow = send_db.get_flow_show(db_path, args.flow_id)
    if flow is None:
        cli_error(f"Flow '{args.flow_id}' not found.")

    meta = flow.get("flow_meta") or {}
    req_len = flow.get("request_body_len") or 0
    resp_len = flow.get("response_body_len") or 0
    payload = {
        "id": flow["id"],
        "method": flow["method"],
        "url": flow["url"],
        "status_code": flow.get("status_code"),
        "source": flow.get("source"),
        "original_flow_id": flow.get("original_flow_id"),
        "parent_flow_id": meta.get("parent_flow_id") if isinstance(meta, dict) else None,
        "replay_reason": flow.get("replay_reason"),
        "replay_error": flow.get("replay_error"),
        "content_type": flow.get("content_type") or "",
        "request_body_len": req_len,
        "response_body_len": resp_len,
        "captured_at": flow.get("captured_at"),
        "endpoint_id": flow.get("endpoint_id"),
        "request_headers": _headers_as_dict(flow.get("request_headers")),
        "response_headers": _headers_as_dict(flow.get("response_headers")),
        "flow_meta": meta if isinstance(meta, dict) else {},
    }

    if wants_json(args):
        # Include body previews (truncated) for AI.
        payload["request_body_preview"] = _preview_body(flow.get("request_body"))
        payload["response_body_preview"] = _preview_body(flow.get("response_body"))
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
        f"  reason          : {payload['replay_reason'] or '—'}",
        f"  error           : {payload['replay_error'] or '—'}",
        f"  request_bytes   : {req_len}",
        f"  response_bytes  : {resp_len}",
        f"  content_type    : {payload['content_type'] or '—'}",
        f"  captured_at     : {payload['captured_at'] or '—'}",
    ]
    print("\n".join(lines))


def cmd_send_history(project: object, args: argparse.Namespace) -> None:
    """List send executions under a root original_flow_id."""
    db_path = project.db_path  # type: ignore[attr-defined]
    root_arg = args.from_flow_id

    # Validate the from-id exists when possible (warn only if missing — allow
    # listing by raw UUID that only appears as original_flow_id).
    rows = send_db.list_send_history(
        db_path, root_arg, limit=max(1, args.limit)
    )

    # Resolve display root.
    parent = send_db.get_flow_for_send(db_path, root_arg)
    root_id = send_db.resolve_root_flow_id(parent) if parent else root_arg

    if wants_json(args):
        cli_json(
            {
                "from": root_arg,
                "original_flow_id": root_id,
                "count": len(rows),
                "executions": [
                    {
                        "id": r["id"],
                        "parent_flow_id": r.get("parent_flow_id"),
                        "method": r["method"],
                        "url": r["url"],
                        "status_code": r.get("status_code"),
                        "source": r.get("source"),
                        "replay_reason": r.get("replay_reason"),
                        "replay_error": r.get("replay_error"),
                        "request_body_len": r.get("request_body_len") or 0,
                        "response_body_len": r.get("response_body_len") or 0,
                        "captured_at": r.get("captured_at"),
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
        f"{'ID':<38} {'SRC':<12} {'ST':>4} {'REQ':>6} {'RESP':>6}  METHOD URL"
    )
    print("-" * 100)
    for r in rows:
        rid = r["id"]
        print(
            f"{rid:<38} "
            f"{(r.get('source') or '')[:12]:<12} "
            f"{_fmt_status(r.get('status_code')):>4} "
            f"{(r.get('request_body_len') or 0):>6} "
            f"{(r.get('response_body_len') or 0):>6}  "
            f"{r.get('method', '')} {r.get('url', '')}"
        )


def cmd_send_diff(project: object, args: argparse.Namespace) -> None:
    """Response-side diff verdict between two flows."""
    db_path = project.db_path  # type: ignore[attr-defined]
    flow_a = send_db.get_flow_for_send(db_path, args.flow_a)
    flow_b = send_db.get_flow_for_send(db_path, args.flow_b)
    if flow_a is None:
        cli_error(f"Flow '{args.flow_a}' not found.")
    if flow_b is None:
        cli_error(f"Flow '{args.flow_b}' not found.")

    # Map flow_b into the shape compute_diff expects (replay_error key).
    right = dict(flow_b)
    if "replay_error" not in right:
        right["replay_error"] = flow_b.get("replay_error")

    diff = compute_diff(flow_a, right)

    a_req = len(flow_a.get("request_body") or b"") if flow_a.get("request_body") else 0
    b_req = len(flow_b.get("request_body") or b"") if flow_b.get("request_body") else 0
    a_resp = len(flow_a.get("response_body") or b"") if flow_a.get("response_body") else 0
    b_resp = len(flow_b.get("response_body") or b"") if flow_b.get("response_body") else 0

    payload = {
        "flow_a": args.flow_a,
        "flow_b": args.flow_b,
        "verdict": diff.verdict,
        "status_changed": diff.status_changed,
        "status_diff": diff.status_diff,
        "length_diff": diff.length_diff,
        "status_a": flow_a.get("status_code"),
        "status_b": flow_b.get("status_code"),
        "request_body_len_a": a_req,
        "request_body_len_b": b_req,
        "response_body_len_a": a_resp,
        "response_body_len_b": b_resp,
        "method_a": flow_a.get("method"),
        "method_b": flow_b.get("method"),
        "url_a": flow_a.get("url"),
        "url_b": flow_b.get("url"),
    }

    if wants_json(args):
        cli_json(payload)
        return

    print(
        f"  flow_a     : {args.flow_a}\n"
        f"  flow_b     : {args.flow_b}\n"
        f"  status     : {payload['status_a']} → {payload['status_b']}"
        f"  ({diff.status_diff or 'unchanged'})\n"
        f"  length_diff: {diff.length_diff} (response bytes)\n"
        f"  req_bytes  : {a_req} → {b_req}\n"
        f"  verdict    : {diff.verdict}"
    )


# ------------------------------------------------------------------ #
# Output helpers                                                       #
# ------------------------------------------------------------------ #

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
    }

    if wants_json(args):
        cli_json(payload)
        if not outcome.success and outcome.failure_reason not in (
            None,
            "flow_not_found",
            "endpoint_annotated_logout",
        ):
            # Network failures still stored — exit 0 for AI chaining when stored?
            # Spec: print failure_reason; treat stored attempt as completed.
            # Use exit 0 when we have an execution id (auditable attempt).
            if outcome.execution_flow_id is None:
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
    if outcome.failure_reason:
        fields["failure_reason"] = outcome.failure_reason

    if outcome.success:
        cli_success("Sent.", fields)
    else:
        # Attempt stored with error — still surface fields for operators/AI.
        cli_success("Send finished with error (flow stored).", fields)


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
    result: list[tuple[str, str]] = []
    for item in items or []:
        if "=" not in item:
            cli_error(
                f"Invalid --query {item!r}: expected KEY=VALUE.",
                exit_code=2,
            )
        key, value = item.split("=", 1)
        if not key:
            cli_error(
                f"Invalid --query {item!r}: empty key.",
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


def _fmt_status(code: object) -> str:
    if code is None:
        return "—"
    return str(code)
