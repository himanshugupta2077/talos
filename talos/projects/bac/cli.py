"""
Module: talos.projects.bac.cli

Purpose:
    Command-line interface for BAC (Broken Access Control) attack generation.
    Entry point: talos attack bac <module>

    Commands:
        talos attack bac session-swap   [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac method-fuzz    [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac content-type   [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac url-fuzz       [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac header-inject  [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac host-fuzz      [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac role-inject    [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac parser-confuse [--role NAME|UUID] [--endpoint UUID]
                                        [--module NAME|UUID] [--auto-generate]
        talos attack bac filter         init | show | validate

    Each command:
        1. Scans the access matrix for BAC candidates (respecting Endpoint Policy
           exclusions and optional scope filters).
        2. Validates auth prerequisites for each attacker role.
        3. Generates scheduler jobs (one per flow × variant).
        4. Prints a summary of enqueued jobs.

    --role NAME|UUID  — Restrict candidate generation to a specific attacker role.
                        When omitted, all role pairs from the access matrix are used.
    --endpoint UUID   — Endpoint execution scope (mutually exclusive with --module).
                        The endpoint must be qualified and not excluded.
    --module NAME|UUID — Module execution scope (mutually exclusive with --endpoint).
                        Accepts a module name or UUID (CLI-004; resolved like roles).
    --auto-generate   — Auto-generate a session token for each attacker role that
                        lacks one (replays the login flow inline).

    filter            — Manage BAC-decision-filter.yaml (init | show | validate | apply).

    Auth prerequisites (checked per attacker role):
        - At least one auth flow with an extractor configured → ERROR + no jobs if missing.
        - auth_config non-empty      → ERROR + no jobs if missing.
        - auth state (role_auth_state) covers all required artifacts → ERROR unless --auto-generate.

Dependencies: argparse, json, sys, uuid
              talos.projects.manager, talos.projects.access,
              talos.projects.bac.candidates, talos.projects.bac.auth_prereq,
              talos.projects.bac.variants, talos.projects.bac.filter_cli,
              talos.scheduler.db
Data flow:
    attack_cli.run_attack_cli → run_bac_cli → bac.candidates → bac.auth_prereq
        → scheduler.db.enqueue_job
Side effects:
    - Reads project DB (read-only operations until job enqueue).
    - Inserts rows into scheduler_jobs.
    - With --auto-generate: sends outbound HTTP; writes role_session_tokens.
    - Exits 1 on hard errors.
"""
from talos.cli_output import (
    cli_error,
    cli_usage_error,
    cli_precondition_error,
)

import argparse
import json
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.projects.bac.candidates import restrict_candidates_to_flows, scan_candidates
from talos.projects.bac.auth_prereq import check_auth_prereqs
from talos.projects.bac.variants import VARIANTS_BY_ATTACK
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    BAC_SESSION_SWAP, BAC_METHOD_FUZZ, BAC_CONTENT_TYPE,
    BAC_URL_FUZZ, BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT,
    BAC_PARSER_CONFUSE,
    PRIORITY_MANUAL,
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
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def _resolve_attacker_role_id(db_path, role_name: str) -> str:
    """
    Purpose:
        Resolve a role name (or UUID) to its UUID for BAC --role filters.
    Raises:
        SystemExit(1) if the role does not exist.
    """
    from talos.projects.access import resolve_role

    role = resolve_role(db_path, role_name)
    if role is None:
        cli_error(f"Role '{role_name}' not found.")
    return role["id"]


def _validate_endpoint_scope(db_path, project_id: str, endpoint_id: str) -> None:
    """
    Purpose:
        Validate that an --endpoint UUID exists and is eligible for BAC testing.
        Prints a specific error when the endpoint is missing, unqualified, or
        excluded so the tester knows why no jobs were generated.
    Raises:
        SystemExit(1) on validation failure.
    """
    import sqlite3
    from talos.projects.policy import get_effective_policy

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            """
            SELECT id, method, host, normalized_path
            FROM endpoints
            WHERE id = ? AND project_id = ?
            """,
            (endpoint_id, project_id),
        ).fetchone()

    if row is None:
        cli_error(f"Endpoint '{endpoint_id}' not found in this project.")

    policy = get_effective_policy(
        db_path, project_id, endpoint_id, row[3]  # normalized_path
    )
    if policy.excluded:
        cli_precondition_error(
            f"Endpoint '{endpoint_id}' is excluded from testing "
            f"({row[1]} {row[2]}{row[3]}). "
            "Re-include it with 'talos endpoint include endpoint <id>' first."
        )
    if not policy.qualified:
        reason = policy.qualification_reason or "unqualified"
        cli_precondition_error(
            f"Endpoint '{endpoint_id}' is not qualified for testing "
            f"({row[1]} {row[2]}{row[3]}; reason: {reason}). "
            "Capture a 2xx proxy_capture flow and ensure it is not marked "
            "logout or dangerous."
        )


def _resolve_module_scope(db_path, name_or_id: str) -> tuple[str, str]:
    """
    Purpose:
        Resolve a --module name or UUID to (module_id, display_name).
        Name is tried first, then UUID — same order as resolve_module() / CLI-004.
    Raises:
        SystemExit(1) if the module does not exist.
    """
    from talos.projects.access import resolve_module

    module = resolve_module(db_path, name_or_id)
    if module is None:
        cli_error(f"Module '{name_or_id}' not found.")
    return module["id"], module["name"]


def _enqueue_bac_jobs(
    manager: ProjectManager,
    attack_type: str,
    role_name_filter: str | None,
    auto_generate: bool,
    endpoint_id: str | None = None,
    module_id: str | None = None,
    flow_ids: list[str] | None = None,
) -> None:
    """
    Purpose:
        Core logic shared by all BAC subcommands.
        Scans candidates (respecting Endpoint Policy + scope filters), validates
        auth prereqs, and enqueues BAC jobs.
    Input:
        manager          — ProjectManager instance.
        attack_type      — BAC job type constant (e.g. bac_session_swap).
        role_name_filter — Attacker role name or UUID filter; None = all roles.
        auto_generate    — Whether to auto-generate session tokens.
        endpoint_id      — Optional single-endpoint scope UUID.
        module_id        — Optional module scope as name or UUID (resolved here).
        flow_ids         — Optional operator-selected flow UUIDs (`--flow`).
    Side effects:
        Reads from DB; inserts scheduler jobs; prints to stdout/stderr.
        Exits 1 when no candidates exist after prereq validation.
    """
    project = _require_active(manager)
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    # Optionally resolve the filter role ID.
    attacker_role_id_filter: str | None = None
    if role_name_filter is not None:
        attacker_role_id_filter = _resolve_attacker_role_id(db_path, role_name_filter)

    # Validate optional scope filters early with clear errors.
    module_name: str | None = None
    if endpoint_id is not None:
        _validate_endpoint_scope(db_path, project_id, endpoint_id)
    if module_id is not None:
        # CLI may pass a human name; resolve to UUID before candidate scan.
        module_id, module_name = _resolve_module_scope(db_path, module_id)

    # Scan access matrix for BAC candidates (testable endpoints only).
    candidates = scan_candidates(
        db_path,
        project_id,
        attacker_role_id=attacker_role_id_filter,
        endpoint_id=endpoint_id,
        module_id=module_id,
    )
    if flow_ids:
        candidates = restrict_candidates_to_flows(candidates, flow_ids)

    if not candidates:
        scope_hints: list[str] = []
        if role_name_filter:
            scope_hints.append(f"attacker role '{role_name_filter}'")
        if endpoint_id:
            scope_hints.append(f"endpoint '{endpoint_id}'")
        if module_id:
            scope_hints.append(f"module '{module_name or module_id}'")
        if flow_ids:
            scope_hints.append(f"{len(flow_ids)} selected flow(s)")
        if scope_hints:
            print(
                f"No BAC candidates found for {' + '.join(scope_hints)}. "
                "Check the access matrix (talos access show), ensure successful "
                "2xx proxy_capture flows exist for the target role, and confirm "
                "the endpoint is not excluded (talos endpoint show).",
                file=sys.stderr,
            )
        else:
            cli_error(
            "No BAC candidates found. "
            "Configure the access matrix (talos access server set), "
            "ensure flows are captured with tagged roles and modules, "
            "and verify endpoints are not excluded (talos endpoint list)."
        )

    variants = VARIANTS_BY_ATTACK.get(attack_type, [])
    if not variants:
        cli_error(f"No variants defined for attack type '{attack_type}'.")

    total_enqueued = 0
    total_auth_skipped = 0
    total_dedup_skipped = 0

    # Group candidates by attacker role to check prereqs once per role.
    prereq_cache: dict[str, bool] = {}  # role_id → passed (True/False)
    prereq_errors_printed: set[str] = set()

    for candidate in candidates:
        attk_id = candidate.attacker_role_id
        attk_name = candidate.attacker_role_name

        # Check and cache auth prerequisites for this attacker role.
        if attk_id not in prereq_cache:
            result = check_auth_prereqs(
                db_path=db_path,
                project_id=project_id,
                role_id=attk_id,
                role_name=attk_name,
                auto_generate=auto_generate,
            )
            if not result.passed:
                prereq_cache[attk_id] = False
                if attk_id not in prereq_errors_printed:
                    prereq_errors_printed.add(attk_id)
                    print(
                        f"\nAuth prerequisites FAILED for attacker role: {attk_name}",
                        file=sys.stderr,
                    )
                    for err in result.errors:
                        print(f"  Error: {err}", file=sys.stderr)
                    print("  No jobs generated for this role.", file=sys.stderr)
            else:
                prereq_cache[attk_id] = True
                if auto_generate:
                    print(f"  Auth state ready for role: {attk_name}")

        if not prereq_cache.get(attk_id, False):
            total_auth_skipped += len(candidate.flow_ids) * len(variants)
            continue

        # Enqueue one job per (flow, variant) combination.
        for flow_id in candidate.flow_ids:
            for variant in variants:
                variant_name = variant["name"]
                # Skip if an identical job is already pending or running.
                if sched_db.has_pending_bac_duplicate(
                    db_path, attack_type, flow_id, attk_id, variant_name
                ):
                    total_dedup_skipped += 1
                    continue
                meta_dict = {
                    "attacker_role_id": attk_id,
                    "target_role_id": candidate.target_role_id,
                    "module_id": candidate.module_id,
                    "variant": variant_name,
                }
                job_id = str(uuid.uuid4())
                sched_db.enqueue_job(
                    db_path=db_path,
                    job_id=job_id,
                    job_type=attack_type,
                    project_id=project_id,
                    flow_id=flow_id,
                    priority=PRIORITY_MANUAL,
                    meta=json.dumps(meta_dict),
                )
                total_enqueued += 1

    # Summary output.
    attack_label = attack_type.replace("bac_", "").replace("_", "-")
    print(f"\nBAC [{attack_label}] generation complete.")
    print(f"  Candidates scanned : {len(candidates)}")
    print(f"  Jobs enqueued      : {total_enqueued}")
    if total_auth_skipped:
        print(f"  Jobs skipped (auth prereq failed) : {total_auth_skipped}")
    if total_dedup_skipped:
        print(f"  Jobs skipped (already queued)     : {total_dedup_skipped}")

    if total_enqueued == 0:
        if total_dedup_skipped:
            # Intentional no-op: work is already queued (EXIT_OK).
            print(
                "\nAll jobs are already pending or running. "
                "Check 'talos scheduler status' for progress.",
                file=sys.stderr,
            )
        elif total_auth_skipped:
            cli_precondition_error(
                "No jobs were enqueued. Fix auth prerequisites above and re-run."
            )
        else:
            cli_error(
                "No jobs were enqueued. No matching candidates or all targets "
                "were skipped."
            )

    print(
        "\nRun 'talos scheduler status' to monitor execution. "
        "Use 'talos finding list' to review attack findings."
    )


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def _scope_from_args(
    args: argparse.Namespace,
) -> tuple[str | None, str | None, list[str]]:
    """
    Purpose:
        Extract optional --endpoint / --module / --flow scope from parsed args.
        Defaults to (None, None, []) when attributes are absent.
    """
    from talos.projects.flow_scope import normalize_flow_ids

    return (
        getattr(args, "endpoint", None),
        getattr(args, "module", None),
        normalize_flow_ids(getattr(args, "flows", None)),
    )


def cmd_bac_session_swap(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate direct session-swap BAC jobs.
        Replays target-role flows using the attacker role's session token.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_SESSION_SWAP, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_method_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate HTTP method manipulation BAC jobs.
        Applies verb changes (GET→POST, POST→GET, etc.) and X-HTTP-Method-Override.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_METHOD_FUZZ, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_content_type(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate content-type confusion BAC jobs.
        Changes request Content-Type to confuse server-side parsers.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_CONTENT_TYPE, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_url_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate URL manipulation BAC jobs.
        Tests trailing slash, double slash, dot segments, encoding, and case variants.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_URL_FUZZ, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_header_inject(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate header injection BAC jobs.
        Injects X-Original-URL, X-Forwarded-For, X-Forwarded-Host, etc.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_HEADER_INJECT, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_host_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate Host header BAC jobs.
        Replaces Host with example.com, localhost, or 127.0.0.1.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_HOST_FUZZ, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_role_inject(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate role parameter injection BAC jobs.
        Injects isAdmin=true, role=admin, and similar escalation parameters.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_ROLE_INJECT, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


def cmd_bac_parser_confuse(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate parser-confusion BAC jobs.
        Exploits discrepancies between how gateways and backends parse
        duplicate parameters, duplicate headers, and conflicting framing.
    """
    endpoint_id, module_id, flow_ids = _scope_from_args(args)
    _enqueue_bac_jobs(
        manager, BAC_PARSER_CONFUSE, args.role, args.auto_generate,
        endpoint_id=endpoint_id, module_id=module_id, flow_ids=flow_ids,
    )


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def _add_bac_shared_args(parser: argparse.ArgumentParser) -> None:
    """
    Purpose:
        Add shared scope and auth arguments to a bac subcommand parser.

        Execution scope is mutually exclusive:
            (no flag)  → project scope
            --module   → module scope
            --endpoint → endpoint scope
            --flow     → selected captures only (repeatable)
    Side effects: Modifies the parser in-place.
    """
    parser.add_argument(
        "--role",
        metavar="NAME|UUID",
        default=None,
        help=(
            "Restrict candidate generation to this attacker role (name or UUID). "
            "When omitted, all access-matrix role pairs are used."
        ),
    )
    # Project | Module | Endpoint | Flow — exactly one execution mode.
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--endpoint",
        metavar="UUID",
        default=None,
        help=(
            "Endpoint execution scope: generate BAC jobs for this single "
            "endpoint UUID only. Mutually exclusive with --module / --flow. "
            "The endpoint must be qualified and not excluded."
        ),
    )
    scope.add_argument(
        "--module",
        metavar="NAME|UUID",
        default=None,
        help=(
            "Module execution scope: generate BAC jobs only for flows/"
            "endpoints inside this module (name or UUID). Mutually exclusive "
            "with --endpoint / --flow."
        ),
    )
    scope.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        help=(
            "Flow execution scope: only these captured flow UUIDs "
            "(repeatable or comma-separated). Mutually exclusive with "
            "--endpoint / --module. Still requires an access-matrix candidate "
            "that includes the flow."
        ),
    )
    parser.add_argument(
        "--auto-generate",
        action="store_true",
        dest="auto_generate",
        default=False,
        help=(
            "Automatically generate a session token for roles that lack one "
            "by replaying their configured login flow."
        ),
    )


def build_bac_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Purpose:
        Register the 'bac' subcommand group and all seven BAC sub-subcommands
        under the parent 'attack' parser's subparsers.
    Input:
        sub — SubParsersAction from the parent 'attack' parser.
    Side effects: Adds 'bac' to the attack subparser group.
    """
    bac_p = sub.add_parser(
        "bac",
        help="BAC (Broken Access Control) attack modules.",
        description=(
            "Generate and schedule BAC attack jobs from the access matrix.\n\n"
            "All commands scan the access matrix for BAC candidates, validate\n"
            "auth prerequisites for each attacker role, and enqueue scheduler\n"
            "jobs that the scheduler executes and reports on.\n\n"
            "Candidate generation only includes testable endpoints from the\n"
            "Endpoint Policy layer (qualified, not excluded). Use\n"
            "'talos endpoint exclude' to remove endpoints from BAC forever.\n\n"
            "Execution scope (mutually exclusive — default is whole project):\n"
            "  --endpoint UUID       only this endpoint\n"
            "  --module NAME|UUID    only this module\n"
            "  --flow UUID           only these captures (repeatable)\n\n"
            "Additional filters:\n"
            "  --role NAME|UUID      only this attacker role\n\n"
            "Auth prerequisites per attacker role:\n"
            "  - At least one auth flow + extractor  (talos auth-config add-flow + set-extractor)\n"
            "  - Auth requirements configured         (talos auth set)\n"
            "  - Auth state collected                 (talos auth-config refresh, or --auto-generate)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bac_sub = bac_p.add_subparsers(dest="bac_cmd", metavar="<module>")
    bac_sub.required = True

    # session-swap
    p = bac_sub.add_parser(
        "session-swap",
        help="Direct session swap: replay target-role flows with attacker-role token.",
        description=(
            "Replays all flows captured under the target role + module using the\n"
            "attacker role's session token.  POSSIBLE_BAC when the server accepts\n"
            "the lower-privilege token without a 401/403.\n\n"
            "Example:\n"
            "  talos attack bac session-swap\n"
            "  talos attack bac session-swap --role customer --auto-generate\n"
            "  talos attack bac session-swap --endpoint <uuid>\n"
            "  talos attack bac session-swap --module payments --role customer"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # method-fuzz
    p = bac_sub.add_parser(
        "method-fuzz",
        help="HTTP Method Manipulation: change verb or inject X-HTTP-Method-Override.",
        description=(
            "Applies multiple HTTP method variants to candidate flows:\n"
            "  GET→POST, GET→PUT, GET→HEAD\n"
            "  POST→GET, POST→PUT, POST→PATCH\n"
            "  PUT→PATCH\n"
            "  X-HTTP-Method-Override: PUT / DELETE\n\n"
            "Variants that do not match the original flow method are skipped."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # content-type
    p = bac_sub.add_parser(
        "content-type",
        help="Content-Type Confusion: change request Content-Type to bypass parsers.",
        description=(
            "Applies content-type mutation variants:\n"
            "  JSON → Form, JSON → Multipart\n"
            "  Form → JSON, XML → JSON\n"
            "  Invalid content-type (application/octet-stream)\n\n"
            "Variants that require a specific source content-type are skipped when\n"
            "the original flow does not match."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # url-fuzz
    p = bac_sub.add_parser(
        "url-fuzz",
        help="URL Manipulation: trailing slash, double slash, dot segments, encoding.",
        description=(
            "Applies URL path transformation variants:\n"
            "  /admin → /admin/          (trailing slash)\n"
            "  /admin/users → /admin//users  (double slash)\n"
            "  /admin/users → /admin/./users  (dot segment)\n"
            "  /admin/users → /admin/../admin/users  (back traversal)\n"
            "  /admin → /%61dmin         (percent-encoded first char)\n"
            "  /admin → /Admin           (mixed case)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # header-inject
    p = bac_sub.add_parser(
        "header-inject",
        help="Header Manipulation: inject X-Original-URL, X-Forwarded-For, etc.",
        description=(
            "Injects proxy/routing headers to test reverse-proxy misconfigurations:\n"
            "  X-Original-URL: <path>\n"
            "  X-Rewrite-URL: <path>\n"
            "  X-Forwarded-For: 127.0.0.1\n"
            "  X-Forwarded-Host: localhost\n"
            "  X-Forwarded-Proto: https\n"
            "  X-Real-IP: 127.0.0.1"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # host-fuzz
    p = bac_sub.add_parser(
        "host-fuzz",
        help="Host Header Changes: replace Host with example.com, localhost, 127.0.0.1.",
        description=(
            "Replaces the Host header to test Host-based routing bypass:\n"
            "  Host: example.com\n"
            "  Host: localhost\n"
            "  Host: 127.0.0.1"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # role-inject
    p = bac_sub.add_parser(
        "role-inject",
        help="Role Parameter Injection: inject isAdmin=true, role=admin, etc.",
        description=(
            "Injects role-escalation parameters to test server-side privilege logic:\n"
            "  Query params: isAdmin=true, role=admin, admin=1,\n"
            '               access_level=999, permissions=["admin"]\n'
            "  Duplicate:    role=user&role=admin\n"
            "  Headers:      X-Role: admin, X-Admin: true"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # parser-confuse
    p = bac_sub.add_parser(
        "parser-confuse",
        help="Parser Confusion: duplicate params, HPP, duplicate headers, TE/CL conflicts.",
        description=(
            "Exploits parser discrepancies between proxies, gateways, and backends:\n"
            "  duplicate_id_param     — duplicate first query param (first vs last wins)\n"
            "  hpp_id_param           — inject id=0 via HTTP Parameter Pollution\n"
            "  duplicate_accept       — inject duplicate Accept header\n"
            "  duplicate_content_type — inject second Content-Type: text/plain\n"
            "  te_cl_conflict         — conflicting Transfer-Encoding + Content-Length"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_bac_shared_args(p)

    # filter
    from talos.projects.bac.filter_cli import build_filter_parser
    build_filter_parser(bac_sub)


# ------------------------------------------------------------------ #
# Entry point called by attack_cli                                     #
# ------------------------------------------------------------------ #

def run_bac_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Dispatch to the correct BAC command handler based on args.bac_cmd.
    Input:
        manager — ProjectManager instance.
        args    — Parsed namespace; args.bac_cmd selects the handler.
    Side effects:
        Delegates to the appropriate cmd_bac_* handler; may sys.exit().
    """
    dispatch = {
        "session-swap":   cmd_bac_session_swap,
        "method-fuzz":    cmd_bac_method_fuzz,
        "content-type":   cmd_bac_content_type,
        "url-fuzz":       cmd_bac_url_fuzz,
        "header-inject":  cmd_bac_header_inject,
        "host-fuzz":      cmd_bac_host_fuzz,
        "role-inject":    cmd_bac_role_inject,
        "parser-confuse": cmd_bac_parser_confuse,
    }

    if args.bac_cmd == "filter":
        from talos.projects.bac.filter_cli import run_filter_cli
        run_filter_cli(manager, args)
        return

    handler = dispatch.get(args.bac_cmd)
    if handler is None:
        cli_usage_error(f"Unknown BAC module: '{args.bac_cmd}'")

    handler(manager, args)
