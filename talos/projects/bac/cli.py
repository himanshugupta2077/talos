"""
Module: talos.projects.bac.cli

Purpose:
    Command-line interface for BAC (Broken Access Control) attack generation.
    Entry point: talos attack bac <module>

    Commands:
        talos attack bac session-swap   [--role NAME] [--auto-generate]
        talos attack bac method-fuzz    [--role NAME] [--auto-generate]
        talos attack bac content-type   [--role NAME] [--auto-generate]
        talos attack bac url-fuzz       [--role NAME] [--auto-generate]
        talos attack bac header-inject  [--role NAME] [--auto-generate]
        talos attack bac host-fuzz      [--role NAME] [--auto-generate]
        talos attack bac role-inject    [--role NAME] [--auto-generate]
        talos attack bac filter         init | show | validate

    Each command:
        1. Scans the access matrix for BAC candidates.
        2. Validates auth prerequisites for each attacker role.
        3. Generates scheduler jobs (one per flow × variant).
        4. Prints a summary of enqueued jobs.

    --role NAME      — Restrict candidate generation to a specific attacker role.
                       When omitted, all role pairs from the access matrix are used.
    --auto-generate  — Auto-generate a session token for each attacker role that
                       lacks one (replays the login flow inline).

    filter           — Manage BAC-decision-filter.yaml (init | show | validate).

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

import argparse
import json
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.projects.bac.candidates import BacCandidate, scan_candidates
from talos.projects.bac.auth_prereq import check_auth_prereqs
from talos.projects.bac.variants import VARIANTS_BY_ATTACK
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    BAC_SESSION_SWAP, BAC_METHOD_FUZZ, BAC_CONTENT_TYPE,
    BAC_URL_FUZZ, BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT,
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
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return project


def _resolve_attacker_role_id(db_path, role_name: str) -> str:
    """
    Purpose:
        Resolve a role name to its UUID.
    Raises:
        SystemExit(1) if the role does not exist.
    """
    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT id FROM roles WHERE name = ?", (role_name,)
        ).fetchone()
    if row is None:
        print(f"Error: Role '{role_name}' not found.", file=sys.stderr)
        sys.exit(1)
    return row[0]


def _enqueue_bac_jobs(
    manager: ProjectManager,
    attack_type: str,
    role_name_filter: str | None,
    auto_generate: bool,
) -> None:
    """
    Purpose:
        Core logic shared by all seven bac subcommands.
        Scans candidates, validates auth prereqs, and enqueues BAC jobs.
    Input:
        manager          — ProjectManager instance.
        attack_type      — BAC job type constant (e.g. bac_session_swap).
        role_name_filter — Attacker role name filter; None = all roles.
        auto_generate    — Whether to auto-generate session tokens.
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

    # Scan access matrix for BAC candidates.
    candidates = scan_candidates(db_path, project_id, attacker_role_id_filter)

    if not candidates:
        if role_name_filter:
            print(
                f"No BAC candidates found for attacker role '{role_name_filter}'. "
                "Check the access matrix (talos access show).",
                file=sys.stderr,
            )
        else:
            print(
                "No BAC candidates found. "
                "Configure the access matrix (talos access server set) "
                "and ensure flows are captured with tagged roles and modules.",
                file=sys.stderr,
            )
        sys.exit(1)

    variants = VARIANTS_BY_ATTACK.get(attack_type, [])
    if not variants:
        print(f"Error: No variants defined for attack type '{attack_type}'.", file=sys.stderr)
        sys.exit(1)

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
                        print(f"  ERROR: {err}", file=sys.stderr)
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
            print(
                "\nAll jobs are already pending or running. "
                "Check 'talos scheduler status' for progress.",
                file=sys.stderr,
            )
        else:
            print(
                "\nNo jobs were enqueued. Fix auth prerequisites above and re-run.",
                file=sys.stderr,
            )
        sys.exit(1)

    print(
        "\nRun 'talos scheduler status' to monitor execution. "
        "Results appear in 'talos ui' under the Attacks view."
    )


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_bac_session_swap(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate direct session-swap BAC jobs.
        Replays target-role flows using the attacker role's session token.
    """
    _enqueue_bac_jobs(manager, BAC_SESSION_SWAP, args.role, args.auto_generate)


def cmd_bac_method_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate HTTP method manipulation BAC jobs.
        Applies verb changes (GET→POST, POST→GET, etc.) and X-HTTP-Method-Override.
    """
    _enqueue_bac_jobs(manager, BAC_METHOD_FUZZ, args.role, args.auto_generate)


def cmd_bac_content_type(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate content-type confusion BAC jobs.
        Changes request Content-Type to confuse server-side parsers.
    """
    _enqueue_bac_jobs(manager, BAC_CONTENT_TYPE, args.role, args.auto_generate)


def cmd_bac_url_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate URL manipulation BAC jobs.
        Tests trailing slash, double slash, dot segments, encoding, and case variants.
    """
    _enqueue_bac_jobs(manager, BAC_URL_FUZZ, args.role, args.auto_generate)


def cmd_bac_header_inject(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate header injection BAC jobs.
        Injects X-Original-URL, X-Forwarded-For, X-Forwarded-Host, etc.
    """
    _enqueue_bac_jobs(manager, BAC_HEADER_INJECT, args.role, args.auto_generate)


def cmd_bac_host_fuzz(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate Host header BAC jobs.
        Replaces Host with example.com, localhost, or 127.0.0.1.
    """
    _enqueue_bac_jobs(manager, BAC_HOST_FUZZ, args.role, args.auto_generate)


def cmd_bac_role_inject(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate role parameter injection BAC jobs.
        Injects isAdmin=true, role=admin, and similar escalation parameters.
    """
    _enqueue_bac_jobs(manager, BAC_ROLE_INJECT, args.role, args.auto_generate)


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def _add_bac_shared_args(parser: argparse.ArgumentParser) -> None:
    """
    Purpose:
        Add the shared --role and --auto-generate arguments to a bac subcommand parser.
    Side effects: Modifies the parser in-place.
    """
    parser.add_argument(
        "--role",
        metavar="NAME",
        default=None,
        help=(
            "Restrict candidate generation to this attacker role name. "
            "When omitted, all access-matrix role pairs are used."
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
            "  talos attack bac session-swap --role customer --auto-generate"
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
        "session-swap":  cmd_bac_session_swap,
        "method-fuzz":   cmd_bac_method_fuzz,
        "content-type":  cmd_bac_content_type,
        "url-fuzz":      cmd_bac_url_fuzz,
        "header-inject": cmd_bac_header_inject,
        "host-fuzz":     cmd_bac_host_fuzz,
        "role-inject":   cmd_bac_role_inject,
    }

    if args.bac_cmd == "filter":
        from talos.projects.bac.filter_cli import run_filter_cli
        run_filter_cli(manager, args)
        return

    handler = dispatch.get(args.bac_cmd)
    if handler is None:
        print(f"Unknown BAC module: '{args.bac_cmd}'", file=sys.stderr)
        sys.exit(1)

    handler(manager, args)
