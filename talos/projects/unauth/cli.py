"""
Module: talos.projects.unauth.cli

Purpose:
    Command-line interface for the Unauth attack module.
    Entry point: talos attack unauth <subcommand>

    Subcommands:
        run     — Generate UNAUTH_ATTACK scheduler jobs for all testable endpoints.
        config  — Show or set unauth auto-run (scheduler auth_test auto-enqueue).
        filter  — Manage the unauth-decision-filter.yaml file (init|show|validate).

    'talos attack unauth run' logic:
        0. Require HTTP artifacts or a credentialed platform NTLM profile.
           NTLM-only: print a note and keep baseline recipes only.
        1. Fetch all qualified, non-excluded endpoints via endpoint policy,
           or use operator `--flow UUID` (repeatable) and skip auto ranking.
        2. For each endpoint, use the configured baseline flow (or the
           explicit capture when `--flow` is set).
        3. Select all recipes or restrict them to one Unauth technique.
        4. Enqueue one UNAUTH_ATTACK job per flow and recipe.
        5. Skip identical pending or running jobs.
        6. Print a summary.

    'talos attack unauth config' (CLI-005):
        Exposes the engine flag unauth_auto_run. When enabled, the scheduler
        auto-enqueues classic auth_test (Authentication Bypass) jobs for
        qualified endpoints that lack results. Distinct from 'unauth run'.

    Filtering is fully owned by the Endpoint Policy system (qualified=1,
    exclusion flags, path rules).  No per-attack exclusion logic exists here.

Dependencies: argparse, json, sys, uuid
              talos.projects.manager, talos.projects.endpoints,
              talos.projects.attack_config, talos.projects.unauth.recipes,
              talos.scheduler.db
Data flow:
    attack_cli.run_attack_cli → run_unauth_cli → recipes / attack_config
        → scheduler.db.enqueue_job or attack_config table
Side effects:
    - Reads project DB (read-only until enqueue / config write).
    - Inserts rows into scheduler_jobs (run).
    - Writes attack_config.unauth_auto_run (config --auto-run).
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
from talos.projects.unauth.recipes import UNAUTH_RECIPES
from talos.scheduler import db as sched_db
from talos.scheduler.job import UNAUTH_ATTACK, PRIORITY_MANUAL


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _require_active(manager: ProjectManager):
    """Return the active project or exit with a clear error."""
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def _get_testable_flows(db_path, project_id: str) -> list[dict]:
    """
    Purpose:
        Return a list of dicts {endpoint_id, flow_id, host, path} for all
        testable endpoints: qualified=1, not excluded (logout/dangerous),
        having a baseline flow.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project UUID.
    Output:
        List of dicts with endpoint and baseline flow info.
    Side effects: None (read-only).
    """
    import sqlite3
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT e.id          AS endpoint_id,
                   e.host        AS host,
                   e.path        AS path,
                   ep.baseline_flow_id AS flow_id
            FROM endpoints e
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
              AND ep.qualified  = 1
              AND ep.logout     = 0
              AND ep.dangerous  = 0
              AND ep.excluded   = 0
              AND ep.baseline_flow_id IS NOT NULL
            """,
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _has_pending_unauth_duplicate(
    db_path,
    flow_id: str,
    technique: str,
    request_mutation,
) -> bool:
    """
    Check whether an identical UNAUTH_ATTACK job is already pending
    or running.
    """
    import sqlite3

    req_str = request_mutation or ""

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            """
            SELECT 1
            FROM scheduler_jobs
            WHERE job_type = ?
              AND flow_id = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.technique') = ?
              AND COALESCE(
                    json_extract(meta, '$.request_mutation'),
                    ''
                  ) = ?
            LIMIT 1
            """,
            (
                UNAUTH_ATTACK,
                flow_id,
                technique,
                req_str,
            ),
        ).fetchone()

    return row is not None


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_unauth_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate UNAUTH_ATTACK scheduler jobs for all testable endpoints.

    Input:
        manager — ProjectManager instance.
        args    — Namespace with:
                    technique (str|None) — Restrict execution to one
                                           Unauth technique.
                    flows (list|None)    — Explicit flow UUIDs (`--flow`).

    Side effects:
        Inserts scheduler_jobs rows and prints a summary.
    """
    project = _require_active(manager)
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    technique_filter: str | None = args.technique

    from talos.projects.flow_scope import lookup_flows, normalize_flow_ids

    wanted = normalize_flow_ids(getattr(args, "flows", None))
    if wanted:
        found, missing = lookup_flows(db_path, wanted)
        testable = []
        skipped_blocked = 0
        for ref in found:
            if ref.policy_blocked:
                skipped_blocked += 1
                continue
            testable.append(
                {
                    "endpoint_id": ref.endpoint_id,
                    "flow_id": ref.flow_id,
                    "host": ref.host,
                    "path": ref.path,
                }
            )
        if missing:
            print(
                "Unknown flow id(s): " + ", ".join(missing),
                file=sys.stderr,
            )
        if skipped_blocked:
            print(
                f"Skipped {skipped_blocked} flow(s) on logout/dangerous/"
                "excluded endpoints.",
                file=sys.stderr,
            )
        if not testable:
            cli_error(
                "No usable flows. Check UUIDs and endpoint policy "
                "(logout / dangerous / excluded)."
            )
    else:
        testable = _get_testable_flows(db_path, project_id)
        if not testable:
            cli_error(
                "No testable endpoints found. Ensure endpoints are qualified "
                "(talos endpoint list) and have 2xx proxy_capture flows."
            )

    from talos.projects.auth_mechanism import (
        missing_auth_error,
        resolve_auth_mechanism,
        uncovered_ntlm_hosts,
    )

    mechanism = resolve_auth_mechanism(db_path)
    if not mechanism.ready:
        hosts = sorted({str(ep.get("host") or "") for ep in testable if ep.get("host")})
        cli_error(missing_auth_error(hosts))
    if mechanism.ntlm_only:
        uncovered = uncovered_ntlm_hosts(
            mechanism,
            {str(ep.get("host") or "") for ep in testable},
        )
        if uncovered:
            cli_error(
                "Platform NTLM is configured but no credentialed profile "
                f"matches: {', '.join(uncovered)}. "
                "Run 'talos proxy auth add --host <host> --type ntlmv2 "
                "--username USER --password PASS'."
            )
        print(
            "Platform NTLM: captured requests have no Authorization header.\n"
            "Unauth will send without platform NTLM "
            "(expect 401 if the origin requires Windows auth).\n"
            "Header-mutation techniques are skipped; baseline (+ request "
            "mutations) only."
        )

    # Optionally restrict recipes to one Unauth technique.
    recipes = [
        recipe
        for recipe in UNAUTH_RECIPES
        if (
            technique_filter is None
            or recipe["technique"] == technique_filter
        )
    ]
    if mechanism.ntlm_only:
        recipes = [recipe for recipe in recipes if recipe["technique"] == "baseline"]

    if not recipes:
        if mechanism.ntlm_only and technique_filter not in (None, "baseline"):
            cli_error(
                f"Technique {technique_filter!r} requires HTTP auth artifacts "
                "(cookie/header names). This project is platform NTLM only. "
                "Use 'talos attack unauth run' (baseline) or "
                "'--technique baseline'."
            )
        cli_error(f"No recipes match technique={technique_filter!r}.")

    total_enqueued = 0
    total_dedup_skipped = 0
    total_no_flow = 0

    for ep in testable:
        flow_id = ep["flow_id"]
        if not flow_id:
            total_no_flow += 1
            continue

        for recipe in recipes:
            technique = recipe["technique"]
            req_mut = recipe["request_mutation"]

            if _has_pending_unauth_duplicate(
                    db_path,
                    flow_id,
                    technique,
                    req_mut,
                ):
                total_dedup_skipped += 1
                continue

            meta_dict = {
                "technique": technique,
                "request_mutation": req_mut,
                "request_type": recipe["request_type"],
            }
            sched_db.enqueue_job(
                db_path=db_path,
                job_id=str(uuid.uuid4()),
                job_type=UNAUTH_ATTACK,
                project_id=project_id,
                flow_id=flow_id,
                priority=PRIORITY_MANUAL,
                meta=json.dumps(meta_dict),
            )
            total_enqueued += 1

    # Summary output.
    print(f"\nUnauth attack generation complete.")
    print(f"  Endpoints scanned    : {len(testable)}")
    print(f"  Recipes applied      : {len(recipes)}")
    print(f"  Jobs enqueued        : {total_enqueued}")
    if total_dedup_skipped:
        print(f"  Jobs skipped (dup)   : {total_dedup_skipped}")
    if total_no_flow:
        print(f"  Endpoints skipped (no baseline flow) : {total_no_flow}")

    if total_enqueued == 0:
        if total_dedup_skipped:
            # Intentional no-op: work is already queued (EXIT_OK).
            print(
                "\nAll jobs are already pending or running. "
                "Check 'talos scheduler status' for progress.",
                file=sys.stderr,
            )
        else:
            # No work produced — treat as general failure (not a usage error).
            cli_error(
                "No jobs were enqueued. No matching endpoints or all targets "
                "were skipped."
            )

    print(
        "\nRun 'talos scheduler status' to monitor execution. "
        "Use 'talos finding list' to review attack findings."
    )


def cmd_unauth_config(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show or update the unauth auto-run flag (CLI-005).

        When enabled, the scheduler auto-enqueues classic auth_test jobs
        (Authentication Bypass) for qualified endpoints that have no result
        and no pending/running auth_test job. Default is off.

        This is distinct from 'talos attack unauth run', which enqueues
        UNAUTH_ATTACK jobs with technique/mutation recipes.

    Input:
        manager — ProjectManager instance.
        args    — Namespace with optional auto_run ('on'|'off'|None).
                  Optional config_action 'show' (default behaviour).

    Side effects:
        May write attack_config.unauth_auto_run; always prints current state.
    """
    from talos.projects.attack_config import (
        get_unauth_auto_run,
        set_unauth_auto_run,
    )

    project = _require_active(manager)
    db_path = project.db_path  # type: ignore[attr-defined]

    auto_run = getattr(args, "auto_run", None)
    if auto_run is not None:
        enabled = auto_run == "on"
        set_unauth_auto_run(db_path, enabled)
        print(
            f"Auto Run set to: {'Enabled' if enabled else 'Disabled'}"
        )

    current = get_unauth_auto_run(db_path)
    print(f"Auto Run : {'Enabled' if current else 'Disabled'}")


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_unauth_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Purpose:
        Register the 'unauth' subcommand group under the parent 'attack' parser.
    Input:   sub — SubParsersAction from the parent 'attack' parser.
    Side effects: Adds 'unauth' to the attack subparser group.
    """
    unauth_p = sub.add_parser(
        "unauth",
        help="Unauthenticated access attack testing.",
        description=(
            "Generate and schedule Unauth attack jobs.\n\n"
            "Every replay first removes all configured authentication.\n"
            "Talos then applies an Unauth technique and, where configured,\n"
            "an optional request mutation.\n\n"
            "Pipeline:\n"
            "  remove all configured auth\n"
            "      -> apply Unauth technique\n"
            "      -> apply optional request mutation\n"
            "      -> replay\n\n"
            "Auto-run (config):\n"
            "  When enabled, the scheduler auto-enqueues classic auth_test\n"
            "  jobs for untested qualified endpoints. Distinct from 'run'.\n\n"
            "Endpoint inclusion/exclusion is fully managed by the Endpoint Policy\n"
            "system (talos endpoint exclude). No per-attack exclusion logic exists."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    usub = unauth_p.add_subparsers(dest="unauth_cmd", metavar="<command>")
    usub.required = True

    # run
    run_p = usub.add_parser(
        "run",
        help="Enqueue unauth attack jobs for all testable endpoints.",
        description=(
            "Scans all qualified endpoints and enqueues one UNAUTH_ATTACK job\n"
            "per (baseline flow, recipe) combination.\n\n"
            "Pass --flow UUID (repeatable) to probe only those captures and\n"
            "skip auto ranking. Logout / dangerous / excluded endpoints are\n"
            "still skipped.\n\n"
            "Every job removes all configured authentication before applying\n"
            "the selected Unauth technique and optional request mutation.\n\n"
            "Examples:\n"
            "  talos attack unauth run\n"
            "  talos attack unauth run --technique baseline\n"
            "  talos attack unauth run --flow <uuid>\n"
            "  talos attack unauth run --flow <uuid1> --flow <uuid2>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument(
        "--technique",
        dest="technique",
        default=None,
        metavar="NAME",
        help=(
            "Restrict execution to one Unauth technique "
            "(e.g. baseline, malformed_auth, auth_null). "
            "Default: run all configured recipes."
        ),
    )
    run_p.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        help=(
            "Probe only this captured flow (repeatable or comma-separated). "
            "Skips auto ranking of testable endpoints."
        ),
    )

    # config (CLI-005)
    config_p = usub.add_parser(
        "config",
        help="Show or set unauth auto-run (scheduler auth_test auto-enqueue).",
        description=(
            "Show or update the unauth auto-run flag.\n\n"
            "When Auto Run is Enabled, the scheduler (while the proxy is running)\n"
            "auto-enqueues classic auth_test jobs (Authentication Bypass) for\n"
            "qualified endpoints that have no auth_test result and no pending\n"
            "or running auth_test job. Default is Disabled.\n\n"
            "This is distinct from 'talos attack unauth run', which enqueues\n"
            "UNAUTH_ATTACK recipe jobs.\n\n"
            "Examples:\n"
            "  talos attack unauth config show\n"
            "  talos attack unauth config --auto-run on\n"
            "  talos attack unauth config --auto-run off"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    config_p.add_argument(
        "config_action",
        nargs="?",
        choices=["show"],
        default=None,
        help="Show the current Auto Run setting (default when no flags).",
    )
    config_p.add_argument(
        "--auto-run",
        dest="auto_run",
        choices=["on", "off"],
        default=None,
        metavar="on|off",
        help=(
            "Enable (on) or disable (off) scheduler auto-enqueue of auth_test "
            "jobs for untested qualified endpoints."
        ),
    )

    # filter
    from talos.projects.unauth.filter_cli import build_unauth_filter_parser
    build_unauth_filter_parser(usub)


def run_unauth_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Dispatch to the correct unauth command handler based on args.unauth_cmd.
    Input:
        manager — ProjectManager instance.
        args    — Parsed namespace; args.unauth_cmd selects the handler.
    Side effects:
        Delegates to handler; may sys.exit().
    """
    if args.unauth_cmd == "run":
        cmd_unauth_run(manager, args)

    elif args.unauth_cmd == "config":
        cmd_unauth_config(manager, args)

    elif args.unauth_cmd == "filter":
        from talos.projects.unauth.filter_cli import run_unauth_filter_cli
        run_unauth_filter_cli(manager, args)

    else:
        cli_usage_error(f"Unknown unauth command: '{args.unauth_cmd}'")
