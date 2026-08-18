"""
Module: talos.sqli.cli

Purpose:
    Command-line interface for SQL injection testing.
    Entry point: talos attack sqli <subcommand>

    Subcommands:
        techniques  — catalogue of SQL payloads
        run         — enqueue one sqli_attack job per (flow, point, payload)
                      (--right-now executes immediately)
        results     — list | show
        status      — verdict + job tallies

    Operator always names the flow(s) with --flow UUID.

Dependencies: argparse, talos.cli_output, talos.sqli.*, talos.scheduler
Data flow: attack_cli → run_sqli_cli → enqueue / engine
Side effects: scheduler_jobs inserts; optional outbound HTTP on --right-now.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import uuid
from pathlib import Path

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_info,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    wants_json,
)
from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.job import PRIORITY_MANUAL, SQLI_ATTACK
from talos.sqli.candidates import (
    SqliCandidate,
    normalize_flow_ids,
    select_sqli_candidates_for_flows,
)
from talos.sqli.db import count_sqli_verdicts, get_sqli_result, list_sqli_results
from talos.sqli.models import (
    FAMILIES,
    TECHNIQUE_CATALOG,
    TECHNIQUE_NAMES,
    InjectionPoint,
)
from talos.sqli.payloads import generate_sqli_payloads


def _require_active(manager: ProjectManager):
    """Return the active project or exit 3."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _select(manager: ProjectManager, args: argparse.Namespace) -> list[SqliCandidate]:
    """Purpose: Require --flow and load those captures."""
    project = _require_active(manager)
    flow_ids = normalize_flow_ids(getattr(args, "flows", None))
    if not flow_ids:
        cli_usage_error(
            "Pass --flow UUID to scan a captured request. "
            "Use 'talos flow list' to copy a flow id. "
            "Repeat --flow or comma-separate to scan several."
        )
    if not project.scope:
        cli_precondition_error(
            "Project scope is empty. Add Basic Scope prefixes with "
            "'talos project scope' before SQLi testing."
        )
    candidates, missing = select_sqli_candidates_for_flows(
        project.db_path,
        in_scope_prefixes=list(project.scope or []),
        flow_ids=flow_ids,
    )
    if missing:
        cli_error(
            "Unknown flow id(s): " + ", ".join(missing) + ". "
            "Use 'talos flow list' to copy a captured flow UUID."
        )
    return candidates


def _has_pending_duplicate(
    db_path: Path,
    flow_id: str,
    param_name: str,
    technique: str,
) -> bool:
    """Purpose: Skip identical pending/running sqli_attack jobs."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM scheduler_jobs
            WHERE job_type = ?
              AND flow_id = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.param_name') = ?
              AND json_extract(meta, '$.technique') = ?
            LIMIT 1
            """,
            (SQLI_ATTACK, flow_id, param_name, technique),
        ).fetchone()
    return row is not None


def cmd_techniques(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Print the SQLi technique catalogue. manager unused."""
    del manager
    if wants_json(args):
        cli_json(list(TECHNIQUE_CATALOG))
        return
    print(f"{'TECHNIQUE':<22} {'FAMILY':<10} DESCRIPTION")
    for item in TECHNIQUE_CATALOG:
        print(
            f"{item['name']:<22} {item['family']:<10} {item['description']}"
        )


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue sqli_attack jobs (or execute immediately with --right-now).
        Each job creates a unique replay flow.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    technique = getattr(args, "technique", None)
    family = getattr(args, "family", None)
    if technique and technique not in TECHNIQUE_NAMES:
        cli_usage_error(
            f"unknown SQLi technique {technique!r}. "
            f"See: talos attack sqli techniques"
        )
    if family and family not in FAMILIES:
        cli_usage_error(
            f"unknown SQLi family {family!r}. "
            f"Expected one of: {', '.join(FAMILIES)}"
        )

    try:
        payloads = generate_sqli_payloads(
            techniques=[technique] if technique else None,
            families=[family] if family else None,
        )
    except ValueError as exc:
        cli_usage_error(str(exc))

    candidates = _select(manager, args)
    if not candidates:
        cli_error(
            "None of the specified flows are usable SQLi targets "
            "(out of scope, or annotated logout/dangerous/excluded)."
        )

    empty_points = [c for c in candidates if not c.points]
    usable = [c for c in candidates if c.points]
    if not usable:
        cli_error(
            "No injectable entry points on the selected flow(s). "
            "v1 scans query parameters, JSON body fields/indexes, and form fields."
        )

    right_now = bool(getattr(args, "right_now", False))
    as_json = wants_json(args)

    planned: list[tuple[SqliCandidate, InjectionPoint, object]] = []
    for cand in usable:
        for point in cand.points:
            for payload in payloads:
                planned.append((cand, point, payload))

    if right_now:
        _run_right_now(db_path, project_id, planned, as_json=as_json)
        return

    enqueued = 0
    skipped = 0
    jobs: list[dict] = []
    for cand, point, payload in planned:
        if _has_pending_duplicate(db_path, cand.flow_id, point.name, payload.technique):
            skipped += 1
            continue
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": payload.payload,
            "original_value": point.original,
            "delay_s": payload.delay_s,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=SQLI_ATTACK,
            project_id=project_id,
            endpoint_id=cand.endpoint_id,
            flow_id=cand.flow_id,
            priority=PRIORITY_MANUAL,
            meta=json.dumps(meta),
        )
        enqueued += 1
        jobs.append(
            {
                "job_id": job_id,
                "flow_id": cand.flow_id,
                "param_name": point.name,
                "technique": payload.technique,
            }
        )

    if as_json:
        cli_json(
            {
                "mode": "enqueue",
                "candidates": len(usable),
                "flows_without_points": [c.flow_id for c in empty_points],
                "entry_points": sum(len(c.points) for c in usable),
                "payloads": len(payloads),
                "jobs_enqueued": enqueued,
                "jobs_skipped_dup": skipped,
                "jobs": jobs,
            }
        )
        return

    print("\nSQLi attack generation complete.")
    print(f"  Flows scanned      : {len(usable)}")
    print(f"  Entry points       : {sum(len(c.points) for c in usable)}")
    print(f"  Payloads each      : {len(payloads)}")
    print(f"  Jobs enqueued      : {enqueued}")
    if skipped:
        print(f"  Jobs skipped (dup) : {skipped}")
    if empty_points:
        print(
            "  Flows with no points: "
            + ", ".join(c.flow_id for c in empty_points)
        )
    if enqueued == 0:
        if skipped:
            print(
                "\nAll jobs are already pending or running. "
                "Check 'talos scheduler status' for progress."
            )
            return
        cli_error("No jobs were enqueued.")
    print(
        "\nEach job writes a unique replay flow. "
        "Run 'talos scheduler status' to monitor execution. "
        "Use 'talos attack sqli results list' and 'talos finding list' to review."
    )


def _run_right_now(
    db_path: Path,
    project_id: str,
    planned: list,
    *,
    as_json: bool,
) -> None:
    """
    Purpose:
        Execute probes in-process (still one unique flow per payload).
    Side effects: outbound HTTP; flows + sqli_results + findings.
    """
    from talos.sqli.engine import execute_sqli_job
    from talos.sqli.findings_bridge import maybe_create_sqli_finding

    outcomes: list[dict] = []
    findings = 0
    for cand, point, payload in planned:
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": payload.payload,
            "original_value": point.original,
            "delay_s": payload.delay_s,
        }
        outcome = asyncio.run(
            execute_sqli_job(
                flow_id=cand.flow_id,
                meta=meta,
                db_path=db_path,
                project_id=project_id,
            )
        )
        finding_id = maybe_create_sqli_finding(
            db_path=db_path,
            project_id=project_id,
            outcome=outcome,
        )
        if finding_id:
            findings += 1
        outcomes.append(
            {
                "flow_id": cand.flow_id,
                "replay_flow_id": outcome.replayed_flow_id,
                "param_name": point.name,
                "technique": outcome.technique,
                "verdict": outcome.verdict,
                "dbms": outcome.dbms,
                "evidence": outcome.evidence,
                "finding_id": finding_id,
                "failure_reason": outcome.failure_reason,
            }
        )

    if as_json:
        cli_json(
            {
                "mode": "right_now",
                "probes": len(outcomes),
                "findings": findings,
                "results": outcomes,
            }
        )
        return

    print(f"\nSQLi --right-now complete. Probes: {len(outcomes)}")
    for row in outcomes:
        replay = (row["replay_flow_id"] or "—")[:8]
        print(
            f"  {row['verdict']:<10} {row['technique']:<22} "
            f"{row['param_name']:<20} replay={replay}"
        )
    print(f"  Findings created : {findings}")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List stored SQLi probe results (unique replay flows)."""
    project = _require_active(manager)
    rows = list_sqli_results(
        project.db_path,
        verdict=getattr(args, "verdict", None),
        technique=getattr(args, "technique", None),
        family=getattr(args, "family", None),
        host=getattr(args, "host", None),
        flow_id=getattr(args, "flow", None),
        limit=int(getattr(args, "limit", 200) or 200),
    )
    if wants_json(args):
        cli_json(rows)
        return
    if not rows:
        cli_info("No SQLi results yet. Run 'talos attack sqli run --flow <uuid>'.")
        return
    print(
        f"{'VERDICT':<10} {'FAMILY':<8} {'TECH':<20} {'PARAM':<18} "
        f"{'DBMS':<10} {'METHOD':<7} {'PATH':<24} REPLAY"
    )
    for row in rows:
        print(
            f"{row.get('verdict') or '':<10} "
            f"{(row.get('technique_family') or ''):<8} "
            f"{(row.get('technique') or ''):<20} "
            f"{(row.get('param_name') or '')[:18]:<18} "
            f"{(row.get('dbms') or '—')[:10]:<10} "
            f"{(row.get('method') or ''):<7} "
            f"{(row.get('path') or '')[:24]:<24} "
            f"{row.get('replay_flow_id')}"
        )
    print(f"\n{len(rows)} result(s). Each replay_flow_id is a unique probe flow.")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Show one SQLi result by replay flow UUID."""
    project = _require_active(manager)
    replay_id = args.replay_flow_id
    row = get_sqli_result(project.db_path, replay_id)
    if row is None:
        cli_error(f"SQLi result not found: {replay_id}")
    if wants_json(args):
        cli_json(row)
        return
    fields = {
        "Replay flow": row.get("replay_flow_id"),
        "Original flow": row.get("original_flow_id"),
        "Technique": row.get("technique"),
        "Family": row.get("technique_family"),
        "Verdict": row.get("verdict"),
        "Param": f"{row.get('location')} {row.get('param_name')}",
        "Payload": row.get("payload_sent") or "—",
        "DBMS": row.get("dbms") or "—",
        "Evidence": row.get("evidence") or "—",
        "Risk hint": row.get("risk_hint") or "—",
        "Elapsed ms": row.get("elapsed_ms"),
        "Host": row.get("host"),
        "Method / path": f"{row.get('method')} {row.get('path')}",
        "Replay status": row.get("replay_status"),
    }
    cli_success("SQLi probe result", fields)


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Verdict histogram + sqli_attack job pressure."""
    project = _require_active(manager)
    counts = count_sqli_verdicts(project.db_path)
    with sqlite3.connect(str(project.db_path)) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (SQLI_ATTACK,),
        ).fetchall()
    jobs = {r[0]: int(r[1]) for r in rows}
    payload = {"verdicts": counts, "jobs": jobs}
    if wants_json(args):
        cli_json(payload)
        return
    print("SQLi status")
    print("  Verdicts:")
    if counts:
        for name, n in sorted(counts.items()):
            print(f"    {name:<16} {n}")
    else:
        print("    (none)")
    print("  Jobs:")
    if jobs:
        for name, n in sorted(jobs.items()):
            print(f"    {name:<16} {n}")
    else:
        print("    (none)")


def build_sqli_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Purpose: Register 'sqli' under talos attack."""
    sqli_p = sub.add_parser(
        "sqli",
        help="SQL injection testing.",
        description=(
            "Scan operator-picked flows for SQL injection.\n\n"
            "Pass --flow UUID (repeatable). The engine walks every query\n"
            "parameter, JSON body field/array index, and form field, then\n"
            "appends error / UNION / boolean / time payloads.\n\n"
            "Each (entry point × payload) is one scheduler job and one\n"
            "unique replay flow. A finding is created when a probe shows a\n"
            "new DBMS error, a UNION column-count leak, or a time delay."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ssub = sqli_p.add_subparsers(dest="sqli_cmd", metavar="<command>")
    ssub.required = True

    tech_p = ssub.add_parser("techniques", help="List SQLi payload techniques.")
    add_format_argument(tech_p)

    run_p = ssub.add_parser(
        "run",
        help="Enqueue SQLi probe jobs for one or more flows.",
        description=(
            "Scan captured flows for SQL injection.\n\n"
            "Examples:\n"
            "  talos attack sqli run --flow <uuid>\n"
            "  talos attack sqli run --flow <uuid> --family error\n"
            "  talos attack sqli run --flow <uuid> --technique quote_single\n"
            "  talos attack sqli run --flow <uuid> --right-now"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        required=True,
        help="Captured flow to scan (repeatable or comma-separated).",
    )
    run_p.add_argument(
        "--technique",
        metavar="NAME",
        choices=list(TECHNIQUE_NAMES),
        help="Restrict to one payload (default: all).",
    )
    run_p.add_argument(
        "--family",
        metavar="NAME",
        choices=list(FAMILIES),
        help="Restrict to error | union | boolean | time.",
    )
    run_p.add_argument(
        "--right-now",
        dest="right_now",
        action="store_true",
        help="Execute immediately (still writes unique replay flows).",
    )
    add_format_argument(run_p)

    res_p = ssub.add_parser("results", help="Inspect SQLi probe results.")
    rsub = res_p.add_subparsers(dest="sqli_results_cmd", metavar="<command>")
    rsub.required = True
    rlist = rsub.add_parser("list", help="List SQLi results.")
    rlist.add_argument("--verdict", choices=["SQLI", "SECURE", "UNKNOWN"])
    rlist.add_argument("--technique", metavar="NAME")
    rlist.add_argument("--family", choices=list(FAMILIES))
    rlist.add_argument("--host", metavar="HOST")
    rlist.add_argument("--flow", metavar="UUID", help="Filter by original or replay flow.")
    rlist.add_argument("--limit", type=int, default=200)
    add_format_argument(rlist)
    rshow = rsub.add_parser("show", help="Show one result by replay flow UUID.")
    rshow.add_argument("replay_flow_id")
    add_format_argument(rshow)

    stat_p = ssub.add_parser("status", help="SQLi verdict and job tallies.")
    add_format_argument(stat_p)


def run_sqli_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Dispatch sqli subcommands."""
    cmd = args.sqli_cmd
    if cmd == "techniques":
        cmd_techniques(manager, args)
    elif cmd == "run":
        cmd_run(manager, args)
    elif cmd == "results":
        if args.sqli_results_cmd == "list":
            cmd_results_list(manager, args)
        elif args.sqli_results_cmd == "show":
            cmd_results_show(manager, args)
        else:
            cli_usage_error("usage: talos attack sqli results list|show")
    elif cmd == "status":
        cmd_status(manager, args)
    else:
        cli_usage_error(f"unknown sqli command: {cmd}")
