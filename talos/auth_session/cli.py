"""
Module: talos.auth_session.cli

Purpose:
    Operator CLI for Authentication & Session Testing (Phases 2–5 complete).
    Entry point: ``talos attack auth-session <subcommand>``

    Subcommands:
        bind              Bind auth_config field → auth type (jwt)
        unbind            Remove binding (RESTRICT / --force cascade)
        show-bindings     List bindings
        generate          Create pending candidates (no HTTP)
        candidates list|show
        approve           pending|failed|done → approved
        reject            pending → rejected
        unapprove         approved → pending
        run               Enqueue approved candidates (or --right-now)
        results list|show
        status            Overview: bindings + candidate/result tallies
        filter init|show|validate
        suite list        List catalog test_ids for an auth type
                          (--alg expands full alg-degradation matrix)

Dependencies: argparse, asyncio, json, uuid; db, candidates, engine; scheduler
Data flow: attack_cli → run_auth_session_cli → handlers → DB / scheduler / HTTP
Side effects: DB writes; optional outbound HTTP for --right-now; filter init writes YAML.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
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
    STATUS_APPROVED,
    STATUS_FAILED,
    STATUS_PENDING,
)
from talos.auth_session.suite_jwt import CORE_JWT_TEST_CASES, alg_degradation_tests
from talos.auth_session.types import ANALYZERS
from talos.projects.auth import get_auth_config
from talos.projects.manager import ProjectManager
from talos.scheduler.job import AUTH_SESSION_ATTACK, PRIORITY_MANUAL
import talos.scheduler.db as sched_db


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
            "Authentication & Session Testing — bind JWT fields, generate "
            "mutation candidates, approve, run (one job per test_id); "
            "decision filter + WEAK_VALIDATION findings."
        ),
        description=(
            "Probe whether a *presented* credential is validated "
            "(signature, algorithm, claims, structure). Distinct from "
            "unauth (auth removed) and BAC (other-role session swap).\n\n"
            "Workflow:\n"
            "  1. talos auth set --header Authorization\n"
            "  2. talos attack auth-session bind --type jwt --header Authorization\n"
            "  3. talos attack auth-session generate --endpoint <uuid>\n"
            "  4. talos attack auth-session candidates list --status pending\n"
            "  5. talos attack auth-session approve --all-pending "
            "[--test-id jwt.alg_none]\n"
            "  6. talos attack auth-session run [--right-now]\n"
            "  7. talos attack auth-session results list "
            "--verdict WEAK_VALIDATION\n"
            "  8. talos finding list\n\n"
            "Each approved test_id is one scheduler job and one new outbound "
            "HTTP flow. Algorithm degradation expands from the observed JWT "
            "alg (full product matrix; core jwt.alg_none* owns pure none)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "See also: docs/design-auth-session-testing-engine.md, "
            "docs/cli-cheat-sheet.md (Attack — auth-session)."
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
    add_format_argument(p_bind)
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
    add_format_argument(p_gen)
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
    add_format_argument(p_appr)
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
    add_format_argument(p_rej)
    p_rej.set_defaults(_as_handler=cmd_reject)

    # ---- unapprove (optional design transition approved → pending) ---- #
    p_unap = as_sub.add_parser(
        "unapprove",
        help="Move approved candidates back to pending (re-review / unbind).",
    )
    p_unap.add_argument(
        "candidate_ids",
        nargs="*",
        metavar="UUID",
        help="Candidate UUIDs (optional if --all-approved).",
    )
    p_unap.add_argument(
        "--all-approved",
        action="store_true",
        help="Unapprove all approved candidates in scope.",
    )
    p_unap.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_unap.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
    )
    p_unap.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    add_format_argument(p_unap)
    p_unap.set_defaults(_as_handler=cmd_unapprove)

    # ---- run ---- #
    p_run = as_sub.add_parser(
        "run",
        help="Enqueue approved candidates as auth_session_attack jobs (one per test_id).",
    )
    p_run.add_argument(
        "--candidate",
        dest="candidate_ids",
        action="append",
        default=None,
        metavar="UUID",
        help="Repeatable: only these approved candidate UUIDs.",
    )
    p_run.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_run.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
        help="Repeatable: filter by test_id.",
    )
    p_run.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
        help="Repeatable: filter by test_family.",
    )
    p_run.add_argument(
        "--binding",
        dest="binding_id",
        metavar="UUID",
        help="Limit to one binding.",
    )
    p_run.add_argument(
        "--right-now",
        action="store_true",
        help="Execute immediately in-process (bypass scheduler queue).",
    )
    add_format_argument(p_run)
    p_run.set_defaults(_as_handler=cmd_run)

    # ---- results ---- #
    p_res = as_sub.add_parser(
        "results",
        help="List or show auth-session results (one row per mutated replay).",
    )
    res_sub = p_res.add_subparsers(dest="results_cmd", metavar="<action>")
    res_sub.required = True

    p_rlist = res_sub.add_parser("list", help="List results.")
    p_rlist.add_argument("--endpoint", dest="endpoint_id", metavar="UUID")
    p_rlist.add_argument("--candidate", dest="candidate_id", metavar="UUID")
    p_rlist.add_argument("--binding", dest="binding_id", metavar="UUID")
    p_rlist.add_argument(
        "--test-id",
        dest="test_ids",
        action="append",
        default=None,
        metavar="ID",
    )
    p_rlist.add_argument(
        "--family",
        dest="families",
        action="append",
        default=None,
        metavar="FAM",
    )
    p_rlist.add_argument(
        "--verdict",
        dest="verdict",
        metavar="V",
        help="WEAK_VALIDATION | SECURE | UNKNOWN",
    )
    p_rlist.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        metavar="N",
    )
    add_format_argument(p_rlist)
    p_rlist.set_defaults(_as_handler=cmd_results_list)

    p_rshow = res_sub.add_parser("show", help="Show one result by replay flow UUID.")
    p_rshow.add_argument("replay_flow_id", metavar="UUID")
    add_format_argument(p_rshow)
    p_rshow.set_defaults(_as_handler=cmd_results_show)

    # ---- status (operator overview) ---- #
    p_status = as_sub.add_parser(
        "status",
        help="Overview: bindings, candidates by status, results by verdict.",
    )
    p_status.add_argument(
        "--endpoint",
        dest="endpoint_id",
        metavar="UUID",
        help="Scope tallies to one endpoint.",
    )
    add_format_argument(p_status)
    p_status.set_defaults(_as_handler=cmd_status)

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
        help=(
            "Include full algorithm-degradation matrix rows for this observed "
            "alg (e.g. RS256 → HS*/ES256/PS256)."
        ),
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

    # ---- filter ---- #
    p_filter = as_sub.add_parser(
        "filter",
        help="Manage auth-session-decision-filter.yaml (init | show | validate).",
        description=(
            "Project-tunable SECURE / WEAK_VALIDATION patterns for mutated-token "
            "replays. No reclassify/apply in v1 — edit filter then re-run candidates."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fsub = p_filter.add_subparsers(dest="auth_session_filter_cmd", metavar="<subcommand>")
    fsub.required = True
    fsub.add_parser(
        "init",
        help="Write default auth-session-decision-filter.yaml (no-op if exists).",
    )
    fsub.add_parser("show", help="Print the current filter file.")
    fsub.add_parser("validate", help="Parse and validate the filter file structure.")
    p_filter.set_defaults(_as_handler=cmd_filter)


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
    return _canonical_auth_field_name(db_path, location, name) is not None


def _canonical_auth_field_name(
    db_path,
    location: str,
    name: str,
) -> Optional[str]:
    """
    Return the auth_config spelling of a field, or None if not configured.

    Headers: case-insensitive match (return auth_config's casing).
    Cookies: exact match preferred, then case-insensitive fallback.
    """
    cfg = get_auth_config(db_path)
    field = (name or "").strip()
    if not field:
        return None
    if location == LOCATION_HEADER:
        for h in cfg["headers"]:
            if h.lower() == field.lower():
                return h
        return None
    if location == LOCATION_COOKIE:
        if field in cfg["cookies"]:
            return field
        for c in cfg["cookies"]:
            if c.lower() == field.lower():
                return c
        return None
    return None


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

    canonical = _canonical_auth_field_name(db_path, location, name)
    if canonical is None:
        kind = "--header" if location == LOCATION_HEADER else "--cookie"
        cli_precondition_error(
            f"'{name}' is not in auth_config. "
            f"Add it first: talos auth set {kind} {name}"
        )
    # Store the auth_config spelling so lookups stay consistent.
    name = canonical

    existing = as_db.get_binding_by_field(db_path, location, name)
    if existing is not None:
        cli_error(
            f"Binding already exists for {location} '{existing.name}' "
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

    if wants_json(args):
        cli_json(_binding_to_dict(binding))
        return

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
        hint = (
            "Unapprove approved candidates first "
            "(`talos attack auth-session unapprove --all-approved`), "
            "then unbind --force for remaining pending/rejected. "
            "v1 refuses delete when done/failed or result rows exist."
        )
        cli_precondition_error(
            "Cannot unbind: binding has protected candidates or results "
            f"({', '.join(parts)}). {hint}"
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

    payload = {
        "bindings_processed": stats.bindings_processed,
        "flows_processed": stats.flows_processed,
        "created": stats.created,
        "refreshed": stats.refreshed,
        "skipped_existing": stats.skipped_existing,
        "skipped_no_token": stats.skipped_no_token,
        "skipped_unsafe_method": stats.skipped_unsafe_method,
        "skipped_no_baseline": stats.skipped_no_baseline,
        "skip_reasons": list(stats.skip_reasons[:50]),
    }
    if wants_json(args):
        cli_json(payload)
        return

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
    Union of positional IDs and filter matches for approve/reject/unapprove.
    mode: approve | reject | unapprove
    """
    ids: list[str] = list(getattr(args, "candidate_ids", None) or [])
    endpoint_id = getattr(args, "endpoint_id", None)
    test_ids = getattr(args, "test_ids", None)
    families = getattr(args, "families", None)
    all_pending = bool(getattr(args, "all_pending", False))
    retry_failed = bool(getattr(args, "retry_failed", False))
    all_approved = bool(getattr(args, "all_approved", False))

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
    elif mode == "unapprove":
        if all_approved:
            rows = as_db.list_candidates(
                db_path,
                status=STATUS_APPROVED,
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
        if wants_json(args):
            cli_json({
                "approved": [],
                "skipped": [],
                "approved_count": 0,
                "skipped_count": 0,
            })
            return
        print("No matching candidates to approve.")
        return

    approved, skipped = as_db.approve_candidates(db_path, ids)
    if wants_json(args):
        cli_json({
            "approved": list(approved),
            "skipped": list(skipped),
            "approved_count": len(approved),
            "skipped_count": len(skipped),
        })
        return
    print(f"Approved: {len(approved)}")
    if skipped:
        print(f"Skipped : {len(skipped)} (wrong status or missing)")
    if approved:
        print()
        print("Next: talos attack auth-session run [--endpoint UUID] [--right-now]")


def cmd_reject(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    ids = _collect_ids_for_lifecycle(db_path, args, mode="reject")
    if not ids:
        if not args.candidate_ids and not args.all_pending:
            cli_usage_error(
                "Provide candidate UUID(s) or --all-pending."
            )
        if wants_json(args):
            cli_json({"rejected": [], "skipped": [], "rejected_count": 0})
            return
        print("No matching candidates to reject.")
        return

    rejected, skipped = as_db.reject_candidates(
        db_path, ids, reason=getattr(args, "reason", None)
    )
    if wants_json(args):
        cli_json({
            "rejected": list(rejected),
            "skipped": list(skipped),
            "rejected_count": len(rejected),
            "skipped_count": len(skipped),
        })
        return
    print(f"Rejected: {len(rejected)}")
    if skipped:
        print(f"Skipped : {len(skipped)} (not pending or missing)")


def cmd_unapprove(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    ids = _collect_ids_for_lifecycle(db_path, args, mode="unapprove")
    if not ids:
        if not args.candidate_ids and not args.all_approved:
            cli_usage_error(
                "Provide candidate UUID(s) or --all-approved."
            )
        if wants_json(args):
            cli_json({"unapproved": [], "skipped": [], "unapproved_count": 0})
            return
        print("No matching candidates to unapprove.")
        return

    moved, skipped = as_db.unapprove_candidates(db_path, ids)
    if wants_json(args):
        cli_json({
            "unapproved": list(moved),
            "skipped": list(skipped),
            "unapproved_count": len(moved),
            "skipped_count": len(skipped),
        })
        return
    print(f"Unapproved (→ pending): {len(moved)}")
    if skipped:
        print(f"Skipped : {len(skipped)} (not approved or missing)")


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue one auth_session_attack job per approved candidate, or
        execute immediately with --right-now.
    Side effects:
        Scheduler job rows and/or outbound HTTP + result rows.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    families = getattr(args, "families", None)
    if families:
        bad = [f for f in families if f not in KNOWN_FAMILIES]
        if bad:
            cli_usage_error(
                f"Unknown family {bad!r}; known: {sorted(KNOWN_FAMILIES)}"
            )

    candidate_ids = getattr(args, "candidate_ids", None)
    rows = as_db.list_candidates(
        db_path,
        status=STATUS_APPROVED,
        endpoint_id=getattr(args, "endpoint_id", None),
        binding_id=getattr(args, "binding_id", None),
        test_ids=getattr(args, "test_ids", None),
        families=families,
        candidate_ids=candidate_ids,
    )

    if not rows:
        cli_error(
            "No approved candidates match filters. "
            "Approve first: talos attack auth-session approve --all-pending"
        )

    right_now = bool(getattr(args, "right_now", False))
    as_json = wants_json(args)

    if right_now:
        _run_right_now(db_path, project_id, rows, as_json=as_json)
        return

    enqueued = 0
    dedup_skipped = 0
    job_ids: list[str] = []
    for cand in rows:
        if as_db.has_pending_auth_session_duplicate(
            db_path,
            flow_id=cand.baseline_flow_id,
            test_id=cand.test_id,
            binding_id=cand.binding_id,
        ):
            dedup_skipped += 1
            continue

        meta_dict = {
            "candidate_id": cand.id,
            "binding_id": cand.binding_id,
            "auth_type": cand.auth_type,
            "test_id": cand.test_id,
            "test_family": cand.test_family,
            "baseline_flow_id": cand.baseline_flow_id,
            "endpoint_id": cand.endpoint_id,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=AUTH_SESSION_ATTACK,
            project_id=project_id,
            flow_id=cand.baseline_flow_id,
            endpoint_id=cand.endpoint_id,
            priority=PRIORITY_MANUAL,
            meta=json.dumps(meta_dict, separators=(",", ":")),
        )
        job_ids.append(job_id)
        enqueued += 1

    if as_json:
        cli_json({
            "mode": "enqueue",
            "approved_matched": len(rows),
            "jobs_enqueued": enqueued,
            "dedup_skipped": dedup_skipped,
            "job_ids": job_ids,
        })
        if enqueued == 0 and not dedup_skipped:
            cli_error("No jobs were enqueued.")
        return

    print("Auth-session run complete")
    print()
    print(f"  Approved matched   : {len(rows)}")
    print(f"  Jobs enqueued      : {enqueued}")
    if dedup_skipped:
        print(f"  Skipped (dup)      : {dedup_skipped}")

    if enqueued == 0:
        if dedup_skipped:
            print(
                "\nAll matching jobs are already pending or running. "
                "Check 'talos scheduler status' for progress."
            )
            return
        cli_error("No jobs were enqueued.")

    print(
        "\nRun 'talos scheduler status' to monitor. "
        "Inspect: talos attack auth-session results list"
    )
    print("WEAK_VALIDATION findings appear under: talos finding list")


def _run_right_now(
    db_path,
    project_id: str,
    rows: list,
    *,
    as_json: bool = False,
) -> None:
    """Execute approved candidates immediately (one HTTP request each)."""
    from talos.auth_session.engine import execute_auth_session_job
    from talos.auth_session.findings_bridge import maybe_create_auth_session_finding
    from talos.auth_session.models import VERDICT_WEAK_VALIDATION

    if not as_json:
        print(f"Auth-session --right-now: {len(rows)} candidate(s)")
        print()

    done = 0
    failed = 0
    findings = 0
    outcomes: list[dict[str, Any]] = []
    for cand in rows:
        as_db.mark_candidate_running(db_path, cand.id)
        meta = {
            "candidate_id": cand.id,
            "binding_id": cand.binding_id,
            "auth_type": cand.auth_type,
            "test_id": cand.test_id,
            "test_family": cand.test_family,
            "baseline_flow_id": cand.baseline_flow_id,
            "endpoint_id": cand.endpoint_id,
        }
        try:
            outcome = asyncio.run(
                execute_auth_session_job(
                    flow_id=cand.baseline_flow_id,
                    meta=meta,
                    db_path=db_path,
                    project_id=project_id,
                )
            )
        except Exception as exc:  # noqa: BLE001
            as_db.mark_candidate_failed(
                db_path, cand.id, skip_reason=f"unexpected_error: {exc}"
            )
            outcomes.append({
                "candidate_id": cand.id,
                "test_id": cand.test_id,
                "ok": False,
                "failure_reason": f"unexpected_error: {exc}",
            })
            if not as_json:
                print(f"  FAIL  {cand.test_id}: unexpected_error: {exc}")
            failed += 1
            continue

        if outcome.failure_reason:
            as_db.mark_candidate_failed(
                db_path, cand.id, skip_reason=outcome.failure_reason
            )
            outcomes.append({
                "candidate_id": cand.id,
                "test_id": cand.test_id,
                "ok": False,
                "verdict": outcome.auth_session_verdict,
                "failure_reason": outcome.failure_reason,
                "replay_flow_id": outcome.replayed_flow_id,
            })
            if not as_json:
                print(
                    f"  FAIL  {cand.test_id}: {outcome.failure_reason} "
                    f"(verdict={outcome.auth_session_verdict})"
                )
            failed += 1
        else:
            as_db.mark_candidate_done(db_path, cand.id)
            finding_id = None
            finding_note = ""
            if outcome.auth_session_verdict == VERDICT_WEAK_VALIDATION:
                finding_id = maybe_create_auth_session_finding(
                    db_path=db_path,
                    project_id=project_id,
                    verdict=outcome.auth_session_verdict,
                    endpoint_id=outcome.endpoint_id or cand.endpoint_id,
                    original_flow_id=outcome.original_flow_id,
                    replayed_flow_id=outcome.replayed_flow_id,
                    test_id=outcome.test_id,
                    auth_type=outcome.auth_type or cand.auth_type,
                    job_id=None,
                    diff_verdict=outcome.diff_verdict,
                    risk_hint=cand.risk_hint,
                    mutation_summary=cand.mutation_summary,
                    candidate_id=cand.id,
                    binding_id=cand.binding_id,
                )
                if finding_id:
                    findings += 1
                    finding_note = f"  finding={finding_id[:8]}"
            outcomes.append({
                "candidate_id": cand.id,
                "test_id": cand.test_id,
                "ok": True,
                "verdict": outcome.auth_session_verdict,
                "diff_verdict": outcome.diff_verdict,
                "replay_status": outcome.replay_status,
                "replay_flow_id": outcome.replayed_flow_id,
                "finding_id": finding_id,
            })
            if not as_json:
                print(
                    f"  {outcome.auth_session_verdict:<16}  {cand.test_id}  "
                    f"status={outcome.replay_status}  diff={outcome.diff_verdict}  "
                    f"replay={outcome.replayed_flow_id or '—'}"
                    f"{finding_note}"
                )
            done += 1

    if as_json:
        cli_json({
            "mode": "right_now",
            "approved_matched": len(rows),
            "done": done,
            "failed": failed,
            "findings": findings,
            "outcomes": outcomes,
        })
        return

    print()
    print(f"Done: {done}  Failed/skipped: {failed}  Findings: {findings}")
    print("Inspect: talos attack auth-session results list")
    print("Findings: talos finding list")


def cmd_filter(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Dispatch filter init | show | validate."""
    sub = getattr(args, "auth_session_filter_cmd", None)
    if sub == "init":
        cmd_filter_init(manager, args)
    elif sub == "show":
        cmd_filter_show(manager, args)
    elif sub == "validate":
        cmd_filter_validate(manager, args)
    else:
        cli_usage_error(f"Unknown auth-session filter subcommand: {sub!r}")


def cmd_filter_init(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """Write default auth-session-decision-filter.yaml (no-op if exists)."""
    from talos.auth_session.decision_filter import (
        FILTER_FILENAME,
        write_default_filter,
    )

    project = _require_active(manager)
    data_dir = project.db_path.parent
    written = write_default_filter(data_dir)
    if written:
        print(f"Created: {data_dir / FILTER_FILENAME}")
        print(
            "Edit the file to customise WEAK_VALIDATION / SECURE patterns. "
            "Re-run candidates after edits (no filter apply in v1)."
        )
    else:
        print(f"Already exists: {data_dir / FILTER_FILENAME}")
        print("Delete it and re-run 'init' to reset to defaults.")


def cmd_filter_show(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """Print current filter file to stdout."""
    from talos.auth_session.decision_filter import FILTER_FILENAME

    project = _require_active(manager)
    filter_path = project.db_path.parent / FILTER_FILENAME
    if not filter_path.exists():
        cli_error(
            f"No filter file found at: {filter_path}\n"
            "Run 'talos attack auth-session filter init' to create one."
        )
    print(filter_path.read_text(encoding="utf-8"))


def cmd_filter_validate(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """Parse filter YAML and report structural OK or errors."""
    from talos.auth_session.decision_filter import FILTER_FILENAME, load_filter

    project = _require_active(manager)
    data_dir = project.db_path.parent
    filter_path = data_dir / FILTER_FILENAME
    if not filter_path.exists():
        cli_error(
            f"No filter file found at: {filter_path}\n"
            "Run 'talos attack auth-session filter init' to create one."
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
    print(f"  passed_detection    : {passed_groups} group(s)  → SECURE")
    print(f"  failed_detection    : {failed_groups} group(s)  → WEAK_VALIDATION")
    print("  No match            : falls through to status+diff heuristic")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    rows = as_db.list_results(
        project.db_path,
        endpoint_id=getattr(args, "endpoint_id", None),
        candidate_id=getattr(args, "candidate_id", None),
        binding_id=getattr(args, "binding_id", None),
        test_ids=getattr(args, "test_ids", None),
        families=getattr(args, "families", None),
        verdict=getattr(args, "verdict", None),
        limit=getattr(args, "limit", None),
    )
    verdict_counts: dict[str, int] = {}
    for r in rows:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1

    if wants_json(args):
        cli_json({
            "results": [_result_to_dict(r) for r in rows],
            "total": len(rows),
            "verdict_counts": verdict_counts,
        })
        return
    if not rows:
        print("No auth-session results.")
        return
    print(
        f"{'REPLAY_FLOW':<36}  {'VERDICT':<16}  {'DIFF':<10}  "
        f"{'HTTP':<6}  {'TEST_ID':<36}"
    )
    print("-" * 120)
    for r in rows:
        http = str(r.replay_status) if r.replay_status is not None else "—"
        diff = r.diff_verdict or "—"
        print(
            f"{r.replay_flow_id:<36}  {r.verdict:<16}  {diff:<10}  "
            f"{http:<6}  {r.test_id}"
        )
    print()
    print(f"Total: {len(rows)}")
    if verdict_counts:
        parts = [f"{v}={n}" for v, n in sorted(verdict_counts.items())]
        print(f"By verdict: {', '.join(parts)}")
    weak = verdict_counts.get("WEAK_VALIDATION", 0)
    if weak:
        print(f"Findings: talos finding list  ({weak} WEAK_VALIDATION in this list)")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    project = _require_active(manager)
    result = as_db.get_result(project.db_path, args.replay_flow_id)
    if result is None:
        cli_error(f"Result for replay '{args.replay_flow_id}' not found.")
    if wants_json(args):
        cli_json(_result_to_dict(result))
        return
    print(f"Auth-session result {result.replay_flow_id}")
    print(f"  Verdict           : {result.verdict}")
    print(f"  Diff verdict      : {result.diff_verdict or '-'}")
    print(f"  Original status   : {result.original_status if result.original_status is not None else '-'}")
    print(f"  Replay status     : {result.replay_status if result.replay_status is not None else '-'}")
    print(f"  Test id           : {result.test_id}")
    print(f"  Family            : {result.test_family or '-'}")
    print(f"  Mutation summary  : {result.mutation_summary or '-'}")
    print(f"  Candidate         : {result.candidate_id}")
    print(f"  Binding           : {result.binding_id}")
    print(f"  Auth type         : {result.auth_type}")
    print(f"  Endpoint          : {result.endpoint_id or '-'}")
    print(f"  Original flow     : {result.original_flow_id}")
    print(f"  Failure reason    : {result.failure_reason or '-'}")
    print(f"  Matched section   : {result.matched_section or '-'}")
    print(f"  Created           : {result.created_at}")


def _result_to_dict(r) -> dict[str, Any]:
    return {
        "replay_flow_id": r.replay_flow_id,
        "original_flow_id": r.original_flow_id,
        "endpoint_id": r.endpoint_id,
        "candidate_id": r.candidate_id,
        "binding_id": r.binding_id,
        "auth_type": r.auth_type,
        "test_id": r.test_id,
        "test_family": r.test_family,
        "mutation_summary": r.mutation_summary,
        "original_status": r.original_status,
        "replay_status": r.replay_status,
        "diff_verdict": r.diff_verdict,
        "verdict": r.verdict,
        "matched_section": r.matched_section,
        "matched_group": r.matched_group,
        "matched_rules": r.matched_rules,
        "failure_reason": r.failure_reason,
        "created_at": r.created_at,
    }


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Operator overview of bindings, candidate statuses, and result verdicts.
    Side effects: Read-only DB queries.
    """
    project = _require_active(manager)
    db_path = project.db_path
    endpoint_id = getattr(args, "endpoint_id", None)

    bindings = as_db.list_bindings(db_path)
    candidates = as_db.list_candidates(
        db_path,
        endpoint_id=endpoint_id,
        limit=None,
    )
    results = as_db.list_results(
        db_path,
        endpoint_id=endpoint_id,
        limit=None,
    )

    by_status: dict[str, int] = {}
    for c in candidates:
        by_status[c.status] = by_status.get(c.status, 0) + 1
    by_verdict: dict[str, int] = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1

    payload = {
        "bindings": len(bindings),
        "binding_details": [
            {
                "id": b.id,
                "location": b.location,
                "name": b.name,
                "auth_type": b.auth_type,
            }
            for b in bindings
        ],
        "candidates_total": len(candidates),
        "candidates_by_status": by_status,
        "results_total": len(results),
        "results_by_verdict": by_verdict,
        "endpoint_id": endpoint_id,
    }

    if wants_json(args):
        cli_json(payload)
        return

    scope = f" (endpoint={endpoint_id[:12]}…)" if endpoint_id else ""
    print(f"Auth-session status{scope}")
    print()
    print(f"  Bindings           : {len(bindings)}")
    for b in bindings:
        print(f"    - {b.location} '{b.name}' → {b.auth_type}  ({b.id[:8]}…)")
    if not bindings:
        print("    (none — bind with: talos attack auth-session bind "
              "--type jwt --header Authorization)")
    print()
    print(f"  Candidates         : {len(candidates)}")
    for status in (
        STATUS_PENDING,
        STATUS_APPROVED,
        "rejected",
        "running",
        "done",
        STATUS_FAILED,
    ):
        n = by_status.get(status, 0)
        if n or status in (STATUS_PENDING, STATUS_APPROVED):
            print(f"    {status:<12} : {n}")
    print()
    print(f"  Results            : {len(results)}")
    if by_verdict:
        for v in ("WEAK_VALIDATION", "SECURE", "UNKNOWN"):
            n = by_verdict.get(v, 0)
            if n:
                print(f"    {v:<16} : {n}")
        for v, n in sorted(by_verdict.items()):
            if v not in ("WEAK_VALIDATION", "SECURE", "UNKNOWN"):
                print(f"    {v:<16} : {n}")
    else:
        print("    (none yet — run approved candidates)")
    print()
    if by_status.get(STATUS_PENDING):
        print("Next: talos attack auth-session approve --all-pending")
    elif by_status.get(STATUS_APPROVED):
        print("Next: talos attack auth-session run [--right-now]")
    elif by_verdict.get("WEAK_VALIDATION"):
        print("Inspect: talos attack auth-session results list "
              "--verdict WEAK_VALIDATION")
        print("Findings: talos finding list")


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
            "Tip: pass --alg RS256 to include the full algorithm-degradation "
            "matrix (HS*/ES*/PS* cross-family + same-family downgrades)."
        )
