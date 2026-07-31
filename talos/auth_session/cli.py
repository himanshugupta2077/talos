"""
Module: talos.auth_session.cli

Purpose:
    Operator CLI for Authentication & Session Testing (Phase 2).
    Entry point: ``talos attack auth-session <subcommand>``

    Subcommands (Phase 2):
        bind              Bind auth_config field → auth type (jwt)
        unbind            Remove binding (RESTRICT / --force cascade)
        show-bindings     List bindings
        generate          Create pending candidates (no HTTP)
        candidates list|show
        approve           pending|failed|done → approved
        reject            pending → rejected
        suite list        List catalog test_ids for an auth type

    Phase 3 adds: run, results
    Phase 4 adds: filter

Dependencies: argparse, sys, json; db, candidates, config, suite; cli_output
Data flow: attack_cli → run_auth_session_cli → handlers → DB
Side effects: DB writes for bind/generate/approve/reject; stdout/stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    cli_usage_error,
    wants_json,
)
from talos.auth_session import db as as_db
from talos.auth_session.candidates import generate_candidates
from talos.auth_session.config import dump_binding_config
from talos.auth_session.models import (
    AUTH_TYPE_JWT,
    KNOWN_AUTH_TYPES,
    KNOWN_FAMILIES,
    LOCATION_COOKIE,
    LOCATION_HEADER,
    STATUS_FAILED,
    STATUS_PENDING,
)
from talos.auth_session.suite_jwt import CORE_JWT_TEST_CASES, alg_degradation_tests
from talos.auth_session.types import ANALYZERS
from talos.projects.auth import get_auth_config
from talos.projects.manager import ProjectManager


# ------------------------------------------------------------------ #
# Parser                                                               #
# ------------------------------------------------------------------ #


def build_auth_session_parser(sub: argparse._SubParsersAction) -> None:
    """
    Purpose:
        Register ``auth-session`` under ``talos attack``.
    Side effects: Mutates parent subparsers.
    """
    parser = sub.add_parser(
        "auth-session",
        help=(
            "Authentication & Session Testing — bind auth fields to JWT, "
            "generate mutation candidates, approve/reject (run in Phase 3)."
        ),
        description=(
            "Probe whether a *presented* credential is validated "
            "(signature, algorithm, claims, structure). Distinct from "
            "unauth (auth removed) and BAC (other-role session swap)."
        ),
    )
    as_sub = parser.add_subparsers(dest="auth_session_cmd", metavar="<command>")
    as_sub.required = True

    # ---- bind ---- #
    p_bind = as_sub.add_parser(
        "bind",
        help="Bind an auth_config header/cookie to an auth type (jwt).",
    )
    p_bind.add_argument(
        "--type",
        dest="auth_type",
        default=AUTH_TYPE_JWT,
        choices=sorted(KNOWN_AUTH_TYPES),
        help="Auth type (default: jwt).",
    )
    loc = p_bind.add_mutually_exclusive_group(required=True)
    loc.add_argument(
        "--header",
        dest="header_name",
        metavar="NAME",
        help="Header name already in auth_config (e.g. Authorization).",
    )
    loc.add_argument(
        "--cookie",
        dest="cookie_name",
        metavar="NAME",
        help="Cookie name already in auth_config.",
    )
    p_bind.add_argument(
        "--role",
        dest="role",
        metavar="NAME|UUID",
        help="Optional preferred role for baseline selection.",
    )
    p_bind.add_argument(
        "--config-json",
        dest="config_json",
        metavar="JSON",
        help="Optional binding config JSON (claim_elevation, disabled_tests, …).",
    )
    p_bind.set_defaults(_as_handler=cmd_bind)

    # ---- unbind ---- #
    p_unbind = as_sub.add_parser(
        "unbind",
        help="Remove a binding (refuses when approved/running/results exist).",
    )
    uloc = p_unbind.add_mutually_exclusive_group(required=True)
    uloc.add_argument("--header", dest="header_name", metavar="NAME")
    uloc.add_argument("--cookie", dest="cookie_name", metavar="NAME")
    uloc.add_argument(
        "--id",
        dest="binding_id",
        metavar="UUID",
        help="Binding UUID.",
    )
    p_unbind.add_argument(
        "--force",
        action="store_true",
        help=(
            "Cascade-delete pending/rejected candidates then remove binding. "
            "Still refuses approved/running/done/failed or results."
        ),
    )
    p_unbind.set_defaults(_as_handler=cmd_unbind)

    # ---- show-bindings ---- #
    p_show_b = as_sub.add_parser(
        "show-bindings",
        help="List auth-session bindings.",
    )
    add_format_argument(p_show_b)
    p_show_b.set_defaults(_as_handler=cmd_show_bindings)

    # ---- generate ---- #
    p_gen = as_sub.add_parser(
        "generate",
        help="Create pending mutation candidates (insert-if-absent; no HTTP).",
    )
    p_gen.add_argument(
        "--binding",
        dest="binding_id",
        metavar="UUID",
        help="Limit to one binding id.",
    )
    p_gen.add_argument(
        "--flow",
        dest="flow_id",
        metavar="UUID",
        help="Explicit baseline flow.",
    )
    p_gen.add_argument(
        "--endpoint",
        dest="endpoint_id",
        metavar="UUID",
        help="Generate for one testable endpoint.",
    )
    p_gen.add_argument(
        "--module",
        dest="module",
        metavar="NAME|UUID",
        help="Generate for endpoints in one module.",
    )
    p_gen.add_argument(
        "--role",
        dest="role",
        metavar="NAME|UUID",
        help="Prefer role-tagged flows.",
    )
    p_gen.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
        help="Repeatable: only these test_ids.",
    )
    p_gen.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
        help="Repeatable: only these families (algorithm, claims, …).",
    )
    p_gen.add_argument(
        "--force-refresh",
        action="store_true",
        help="Refresh metadata for pending/rejected only; never touch done/approved.",
    )
    p_gen.add_argument(
        "--include-unsafe-methods",
        action="store_true",
        help="Allow POST/PUT/PATCH/DELETE baselines (default: GET/HEAD/OPTIONS only).",
    )
    p_gen.set_defaults(_as_handler=cmd_generate)

    # ---- candidates ---- #
    p_cand = as_sub.add_parser(
        "candidates",
        help="List or show mutation candidates.",
    )
    cand_sub = p_cand.add_subparsers(dest="candidates_cmd", metavar="<action>")
    cand_sub.required = True

    p_clist = cand_sub.add_parser("list", help="List candidates.")
    p_clist.add_argument(
        "--status",
        dest="status",
        metavar="STATUS",
        help="Filter by status (pending|approved|rejected|running|done|failed).",
    )
    p_clist.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_clist.add_argument("--binding", dest="binding_id", metavar="UUID")
    p_clist.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
    )
    p_clist.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    p_clist.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        metavar="N",
    )
    add_format_argument(p_clist)
    p_clist.set_defaults(_as_handler=cmd_candidates_list)

    p_cshow = cand_sub.add_parser("show", help="Show one candidate.")
    p_cshow.add_argument("candidate_id", metavar="UUID")
    add_format_argument(p_cshow)
    p_cshow.set_defaults(_as_handler=cmd_candidates_show)

    # ---- approve ---- #
    p_appr = as_sub.add_parser(
        "approve",
        help="Approve candidates (pending|failed|done → approved).",
    )
    p_appr.add_argument(
        "candidate_ids",
        nargs="*",
        metavar="UUID",
        help="Candidate UUIDs (optional if --all-pending / --retry-failed).",
    )
    p_appr.add_argument(
        "--all-pending",
        action="store_true",
        help="Approve all pending in scope.",
    )
    p_appr.add_argument(
        "--retry-failed",
        action="store_true",
        help="Re-approve all failed in scope for re-test.",
    )
    p_appr.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_appr.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
    )
    p_appr.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    p_appr.set_defaults(_as_handler=cmd_approve)

    # ---- reject ---- #
    p_rej = as_sub.add_parser(
        "reject",
        help="Reject pending candidates.",
    )
    p_rej.add_argument(
        "candidate_ids",
        nargs="*",
        metavar="UUID",
        help="Candidate UUIDs (optional if --all-pending).",
    )
    p_rej.add_argument(
        "--all-pending",
        action="store_true",
        help="Reject all pending in scope.",
    )
    p_rej.add_argument(
        "--reason",
        dest="reason",
        metavar="TEXT",
        help="Optional reject reason.",
    )
    p_rej.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_rej.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
    )
    p_rej.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    p_rej.set_defaults(_as_handler=cmd_reject)

    # ---- suite list ---- #
    p_suite = as_sub.add_parser(
        "suite",
        help="Inspect the test suite catalog.",
    )
    suite_sub = p_suite.add_subparsers(dest="suite_cmd", metavar="<action>")
    suite_sub.required = True
    p_slist = suite_sub.add_parser(
        "list",
        help="List test_ids for an auth type (core + optional alg matrix).",
    )
    p_slist.add_argument(
        "--type",
        dest="auth_type",
        default=AUTH_TYPE_JWT,
        choices=sorted(KNOWN_AUTH_TYPES),
    )
    p_slist.add_argument(
        "--alg",
        dest="observed_alg",
        metavar="ALG",
        help="Include Phase-1 algorithm-degradation rows for this observed alg.",
    )
    p_slist.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    add_format_argument(p_slist)
    p_slist.set_defaults(_as_handler=cmd_suite_list)


def run_auth_session_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Dispatch auth-session subcommands.
    Side effects: Handler may write DB / exit.
    """
    handler = getattr(args, "_as_handler", None)
    if handler is None:
        cli_usage_error("Missing auth-session subcommand.")
    handler(manager, args)


# ------------------------------------------------------------------ #
# Shared helpers                                                       #
# ------------------------------------------------------------------ #


def _require_active(manager: ProjectManager):
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _location_and_name(args: argparse.Namespace) -> tuple[str, str]:
    if getattr(args, "header_name", None):
        return LOCATION_HEADER, args.header_name.strip()
    if getattr(args, "cookie_name", None):
        return LOCATION_COOKIE, args.cookie_name.strip()
    cli_usage_error("Provide --header NAME or --cookie NAME.")


def _resolve_role_id(db_path, role: Optional[str]) -> Optional[str]:
    if not role:
        return None
    from talos.projects.access import resolve_role

    resolved = resolve_role(db_path, role)
    if resolved is None:
        cli_error(f"Role '{role}' not found.")
    return resolved["id"]


def _resolve_module_id(db_path, module: Optional[str]) -> Optional[str]:
    if not module:
        return None
    from talos.projects.access import resolve_module

    resolved = resolve_module(db_path, module)
    if resolved is None:
        cli_error(f"Module '{module}' not found.")
    return resolved["id"]


def _auth_config_has_field(db_path, location: str, name: str) -> bool:
    cfg = get_auth_config(db_path)
    if location == LOCATION_HEADER:
        return any(h.lower() == name.lower() for h in cfg["headers"])
    if location == LOCATION_COOKIE:
        return name in cfg["cookies"] or any(
            c.lower() == name.lower() for c in cfg["cookies"]
        )
    return False


def _candidate_to_dict(c) -> dict[str, Any]:
    return {
        "id": c.id,
        "binding_id": c.binding_id,
        "endpoint_id": c.endpoint_id,
        "baseline_flow_id": c.baseline_flow_id,
        "auth_type": c.auth_type,
        "test_id": c.test_id,
        "test_family": c.test_family,
        "title": c.title,
        "mutation_summary": c.mutation_summary,
        "token_fingerprint": c.token_fingerprint,
        "risk_hint": c.risk_hint,
        "status": c.status,
        "reject_reason": c.reject_reason,
        "meta_json": c.meta_json,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


def _binding_to_dict(b) -> dict[str, Any]:
    return {
        "id": b.id,
        "location": b.location,
        "name": b.name,
        "auth_type": b.auth_type,
        "role_id": b.role_id,
        "config_json": b.config_json,
        "created_at": b.created_at,
        "updated_at": b.updated_at,
    }


def _print_candidate_table(rows: list) -> None:
    if not rows:
        print("No candidates.")
        return
    # Compact table
    print(
        f"{'ID':<36}  {'STATUS':<10}  {'FAMILY':<18}  {'TEST_ID':<36}  "
        f"{'ENDPOINT':<12}  TITLE"
    )
    print("-" * 140)
    for c in rows:
        ep = (c.endpoint_id or "")[:12]
        print(
            f"{c.id:<36}  {c.status:<10}  {c.test_family:<18}  "
            f"{c.test_id:<36}  {ep:<12}  {c.title}"
        )


# ------------------------------------------------------------------ #
# Commands                                                             #
# ------------------------------------------------------------------ #


def cmd_bind(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    location, name = _location_and_name(args)

    if not _auth_config_has_field(db_path, location, name):
        kind = "--header" if location == LOCATION_HEADER else "--cookie"
        cli_precondition_error(
            f"'{name}' is not in auth_config. "
            f"Add it first: talos auth set {kind} {name}"
        )

    existing = as_db.get_binding_by_field(db_path, location, name)
    if existing is not None:
        cli_error(
            f"Binding already exists for {location} '{name}' "
            f"(id={existing.id}, type={existing.auth_type}). "
            "Unbind first or use a different field."
        )

    role_id = _resolve_role_id(db_path, getattr(args, "role", None))
    config_json = getattr(args, "config_json", None) or "{}"
    if config_json and config_json != "{}":
        try:
            parsed = json.loads(config_json)
            if not isinstance(parsed, dict):
                cli_usage_error("--config-json must be a JSON object.")
            config_json = dump_binding_config(parsed)
        except json.JSONDecodeError as exc:
            cli_usage_error(f"Invalid --config-json: {exc}")

    try:
        binding = as_db.insert_binding(
            db_path,
            location=location,
            name=name,
            auth_type=args.auth_type,
            role_id=role_id,
            config_json=config_json,
        )
    except ValueError as exc:
        cli_error(str(exc))
    except Exception as exc:  # IntegrityError etc.
        cli_error(f"Failed to create binding: {exc}")

    print(f"Bound {location} '{name}' → {binding.auth_type}")
    print()
    print("UUID:")
    print(binding.id)
    print()
    print("Next: talos attack auth-session generate [--endpoint UUID | --flow UUID]")


def cmd_unbind(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path

    binding = None
    if getattr(args, "binding_id", None):
        binding = as_db.get_binding(db_path, args.binding_id)
        if binding is None:
            cli_error(f"Binding '{args.binding_id}' not found.")
    else:
        location, name = _location_and_name(args)
        binding = as_db.get_binding_by_field(db_path, location, name)
        if binding is None:
            cli_error(f"No binding for {location} '{name}'.")

    counts = as_db.count_candidates_for_binding(db_path, binding.id)
    has_results = as_db.binding_has_results(db_path, binding.id)

    blocked_statuses = ("approved", "running", "done", "failed")
    blocked = {s: counts.get(s, 0) for s in blocked_statuses if counts.get(s, 0)}
    if blocked or has_results:
        parts = [f"{s}={n}" for s, n in blocked.items()]
        if has_results:
            parts.append("results_exist=yes")
        cli_precondition_error(
            "Cannot unbind: binding has protected candidates or results "
            f"({', '.join(parts)}). Reject/cancel approved work first; "
            "v1 refuses delete when done/failed or result rows exist."
        )

    pending = counts.get(STATUS_PENDING, 0)
    rejected = counts.get("rejected", 0)
    soft = pending + rejected
    if soft > 0 and not args.force:
        cli_precondition_error(
            f"Binding has {pending} pending and {rejected} rejected candidate(s). "
            "Re-run with --force to cascade-delete pending/rejected and unbind."
        )

    if soft > 0 and args.force:
        as_db.cascade_reject_pending_for_binding(db_path, binding.id)

    try:
        deleted = as_db.delete_binding(db_path, binding.id)
    except Exception as exc:
        cli_error(f"Failed to unbind: {exc}")

    if not deleted:
        cli_error("Binding not found at delete time.")

    print(f"Unbound {binding.location} '{binding.name}' (id={binding.id})")


def cmd_show_bindings(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    rows = as_db.list_bindings(project.db_path)
    if wants_json(args):
        cli_json([_binding_to_dict(b) for b in rows])
        return
    if not rows:
        print("No auth-session bindings. Use: talos attack auth-session bind --type jwt --header Authorization")
        return
    print(f"{'ID':<36}  {'LOC':<8}  {'NAME':<24}  {'TYPE':<8}  ROLE")
    print("-" * 100)
    for b in rows:
        print(
            f"{b.id:<36}  {b.location:<8}  {b.name:<24}  "
            f"{b.auth_type:<8}  {b.role_id or '-'}"
        )


def cmd_generate(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path

    if getattr(args, "endpoint_id", None) and getattr(args, "module", None):
        cli_usage_error("--endpoint and --module are mutually exclusive.")

    role_id = _resolve_role_id(db_path, getattr(args, "role", None))
    module_id = _resolve_module_id(db_path, getattr(args, "module", None))

    families = getattr(args, "families", None)
    if families:
        bad = [f for f in families if f not in KNOWN_FAMILIES]
        if bad:
            cli_usage_error(
                f"Unknown family {bad!r}; known: {sorted(KNOWN_FAMILIES)}"
            )

    try:
        stats = generate_candidates(
            db_path,
            project.id,
            binding_id=getattr(args, "binding_id", None),
            flow_id=getattr(args, "flow_id", None),
            endpoint_id=getattr(args, "endpoint_id", None),
            module_id=module_id,
            role_id=role_id,
            test_ids=getattr(args, "test_ids", None),
            families=families,
            force_refresh=bool(getattr(args, "force_refresh", False)),
            include_unsafe_methods=bool(
                getattr(args, "include_unsafe_methods", False)
            ),
        )
    except ValueError as exc:
        cli_usage_error(str(exc))

    print("Auth-session generate complete")
    print()
    print(f"  Bindings processed : {stats.bindings_processed}")
    print(f"  Flows processed    : {stats.flows_processed}")
    print(f"  Created            : {stats.created}")
    print(f"  Refreshed          : {stats.refreshed}")
    print(f"  Skipped existing   : {stats.skipped_existing}")
    print(f"  Skipped no token   : {stats.skipped_no_token}")
    print(f"  Skipped unsafe meth: {stats.skipped_unsafe_method}")
    print(f"  Skipped no baseline: {stats.skipped_no_baseline}")
    if stats.skip_reasons:
        # Cap noise
        print()
        print("Skip samples (up to 10):")
        for reason in stats.skip_reasons[:10]:
            print(f"  - {reason}")
    print()
    if stats.created or stats.refreshed:
        print("Review: talos attack auth-session candidates list --status pending")
        print("Approve: talos attack auth-session approve --all-pending")
    elif "no_bindings" in stats.skip_reasons:
        print("No bindings. Create one: talos attack auth-session bind --type jwt --header Authorization")


def cmd_candidates_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    rows = as_db.list_candidates(
        project.db_path,
        status=getattr(args, "status", None),
        endpoint_id=getattr(args, "endpoint_id", None),
        binding_id=getattr(args, "binding_id", None),
        test_ids=getattr(args, "test_ids", None),
        families=getattr(args, "families", None),
        limit=getattr(args, "limit", None),
    )
    if wants_json(args):
        cli_json([_candidate_to_dict(c) for c in rows])
        return
    _print_candidate_table(rows)
    print()
    print(f"Total: {len(rows)}")


def cmd_candidates_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    cand = as_db.get_candidate(project.db_path, args.candidate_id)
    if cand is None:
        cli_error(f"Candidate '{args.candidate_id}' not found.")
    if wants_json(args):
        cli_json(_candidate_to_dict(cand))
        return
    print(f"Candidate {cand.id}")
    print(f"  Status            : {cand.status}")
    print(f"  Binding           : {cand.binding_id}")
    print(f"  Endpoint          : {cand.endpoint_id or '-'}")
    print(f"  Baseline flow     : {cand.baseline_flow_id}")
    print(f"  Auth type         : {cand.auth_type}")
    print(f"  Test id           : {cand.test_id}")
    print(f"  Family            : {cand.test_family}")
    print(f"  Title             : {cand.title}")
    print(f"  Mutation summary  : {cand.mutation_summary}")
    print(f"  Risk hint         : {cand.risk_hint or '-'}")
    print(f"  Token fingerprint : {cand.token_fingerprint or '-'}")
    print(f"  Reject reason     : {cand.reject_reason or '-'}")
    print(f"  Meta              : {cand.meta_json}")
    print(f"  Created           : {cand.created_at}")
    print(f"  Updated           : {cand.updated_at}")


def _collect_ids_for_lifecycle(
    db_path,
    args: argparse.Namespace,
    *,
    mode: str,
) -> list[str]:
    """
    Union of positional IDs and filter matches for approve/reject.
    mode: approve | reject | approve_retry_failed
    """
    ids: list[str] = list(getattr(args, "candidate_ids", None) or [])
    endpoint_id = getattr(args, "endpoint_id", None)
    test_ids = getattr(args, "test_ids", None)
    families = getattr(args, "families", None)
    all_pending = bool(getattr(args, "all_pending", False))
    retry_failed = bool(getattr(args, "retry_failed", False))

    if mode == "approve":
        if all_pending:
            rows = as_db.list_candidates(
                db_path,
                status=STATUS_PENDING,
                endpoint_id=endpoint_id,
                test_ids=test_ids,
                families=families,
            )
            ids.extend(r.id for r in rows)
        if retry_failed:
            rows = as_db.list_candidates(
                db_path,
                status=STATUS_FAILED,
                endpoint_id=endpoint_id,
                test_ids=test_ids,
                families=families,
            )
            ids.extend(r.id for r in rows)
        # Filters without --all-pending: if filters present and no positional,
        # still need --all-pending or ids (design: union of matches).
        # When only filters + positional empty and no flags → error.
    elif mode == "reject":
        if all_pending:
            rows = as_db.list_candidates(
                db_path,
                status=STATUS_PENDING,
                endpoint_id=endpoint_id,
                test_ids=test_ids,
                families=families,
            )
            ids.extend(r.id for r in rows)

    # Deduplicate preserving order
    seen: set[str] = set()
    out: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def cmd_approve(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    ids = _collect_ids_for_lifecycle(db_path, args, mode="approve")
    if not ids:
        if not args.candidate_ids and not args.all_pending and not args.retry_failed:
            cli_usage_error(
                "Provide candidate UUID(s), --all-pending, and/or --retry-failed."
            )
        print("No matching candidates to approve.")
        return

    approved, skipped = as_db.approve_candidates(db_path, ids)
    print(f"Approved: {len(approved)}")
    if skipped:
        print(f"Skipped : {len(skipped)} (wrong status or missing)")
    if approved:
        print()
        print(
            "Run is Phase 3 — not wired yet. "
            "After Phase 3: talos attack auth-session run …"
        )


def cmd_reject(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    ids = _collect_ids_for_lifecycle(db_path, args, mode="reject")
    if not ids:
        if not args.candidate_ids and not args.all_pending:
            cli_usage_error(
                "Provide candidate UUID(s) or --all-pending."
            )
        print("No matching candidates to reject.")
        return

    rejected, skipped = as_db.reject_candidates(
        db_path, ids, reason=getattr(args, "reason", None)
    )
    print(f"Rejected: {len(rejected)}")
    if skipped:
        print(f"Skipped : {len(skipped)} (not pending or missing)")


def cmd_suite_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    # Suite list does not require project for core catalog, but keep
    # active project optional for consistency with other attack cmds.
    auth_type = args.auth_type
    if auth_type not in ANALYZERS:
        cli_error(f"Unsupported auth type {auth_type!r}")

    rows: list[dict[str, Any]] = []
    for case in CORE_JWT_TEST_CASES:
        rows.append({
            "test_id": case.test_id,
            "family": case.family,
            "title": case.title,
            "risk_hint": case.risk_hint,
            "requires_claims": list(case.requires_claims),
            "description": case.description,
            "source": "core",
        })
    observed = getattr(args, "observed_alg", None)
    if observed:
        for case in alg_degradation_tests(observed):
            rows.append({
                "test_id": case.test_id,
                "family": case.family,
                "title": case.title,
                "risk_hint": case.risk_hint,
                "requires_claims": [],
                "description": case.description,
                "source": "algorithm_degrade",
            })

    families = getattr(args, "families", None)
    if families:
        fam_set = set(families)
        rows = [r for r in rows if r["family"] in fam_set]

    if wants_json(args):
        cli_json(rows)
        return

    print(f"Auth-session suite ({auth_type})"
          + (f" + degrade for alg={observed}" if observed else " core"))
    print()
    print(f"{'TEST_ID':<42}  {'FAMILY':<18}  {'RISK':<10}  TITLE")
    print("-" * 110)
    for r in rows:
        print(
            f"{r['test_id']:<42}  {r['family']:<18}  "
            f"{r['risk_hint']:<10}  {r['title']}"
        )
    print()
    print(f"Total: {len(rows)}")
    if not observed:
        print(
            "Tip: pass --alg RS256 to include Phase-1 algorithm-degradation test_ids."
        )
