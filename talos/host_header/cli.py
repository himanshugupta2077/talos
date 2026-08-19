"""
Module: talos.host_header.cli

Purpose:
    Command-line interface for host-header injection testing.
    Entry point: talos attack host-header <subcommand>

    Subcommands:
        techniques  — catalogue of Host / override-header payloads
        run         — enqueue one host_header_attack job per
                      (flow, header, payload) (--right-now executes immediately)
        results     — list | show
        status      — verdict + job tallies

    Operator always names the flow(s) with --flow UUID.

Dependencies: argparse, talos.cli_output, talos.host_header.*, talos.scheduler
Data flow: attack_cli → run_host_header_cli → enqueue / engine
Side effects: scheduler_jobs inserts; optional outbound HTTP on --right-now.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import uuid
from dataclasses import replace
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
from talos.host_header.candidates import (
    HostHeaderCandidate,
    normalize_flow_ids,
    select_host_header_candidates_for_flows,
)
from talos.host_header.db import (
    count_host_header_verdicts,
    get_host_header_result,
    list_host_header_results,
)
from talos.host_header.inject import match_injection_points, normalize_param_names
from talos.host_header.models import CANARY_HOST, FAMILIES, InjectionPoint
from talos.host_header.payloads import (
    TECHNIQUE_CATALOG,
    generate_host_header_payloads,
    payload_applies,
    render_payload,
)
from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.job import HOST_HEADER_ATTACK, PRIORITY_HIGH, PRIORITY_MANUAL


def _require_active(manager: ProjectManager):
    """Return the active project or exit 3."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _select(manager: ProjectManager, args: argparse.Namespace) -> list[HostHeaderCandidate]:
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
            "'talos project scope' before host-header testing."
        )
    candidates, missing = select_host_header_candidates_for_flows(
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
    """Purpose: Skip identical pending/running host_header_attack jobs."""
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
            (HOST_HEADER_ATTACK, flow_id, param_name, technique),
        ).fetchone()
    return row is not None


def cmd_techniques(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Print the host-header technique catalogue. manager unused."""
    del manager
    family = getattr(args, "family", None)
    catalog = list(TECHNIQUE_CATALOG)
    if family:
        if family not in FAMILIES:
            cli_usage_error(
                f"unknown host-header family {family!r}. "
                f"Expected one of: {', '.join(FAMILIES)}"
            )
        catalog = [row for row in catalog if str(row["family"]) == family]
    if wants_json(args):
        cli_json(catalog)
        return
    print(f"{'TECHNIQUE':<22} {'FAMILY':<14} DESCRIPTION")
    for item in catalog:
        print(
            f"{str(item['name']):<22} {str(item['family']):<14} {item['description']}"
        )
    print(f"\n{len(catalog)} technique(s). Canary host: {CANARY_HOST}")


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue host_header_attack jobs (or execute immediately with --right-now).
        Each job creates a unique replay flow.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    technique = getattr(args, "technique", None)
    family = getattr(args, "family", None)
    param_filters = normalize_param_names(getattr(args, "params", None))
    if family and family not in FAMILIES:
        cli_usage_error(
            f"unknown host-header family {family!r}. "
            f"Expected one of: {', '.join(FAMILIES)}"
        )

    try:
        payloads = generate_host_header_payloads(
            techniques=[technique] if technique else None,
            families=[family] if family else None,
        )
    except ValueError as exc:
        cli_usage_error(str(exc))

    candidates = _select(manager, args)
    if not candidates:
        cli_error(
            "None of the specified flows are usable host-header targets "
            "(out of scope, or annotated logout/dangerous/excluded)."
        )

    empty_points = [c for c in candidates if not c.points]
    usable = [c for c in candidates if c.points]
    if not usable:
        cli_error(
            "No host-related headers on the selected flow(s). "
            "v1 always offers Host plus X-Forwarded-Host / X-Host / Forwarded "
            "and related override headers."
        )

    if param_filters:
        narrowed: list[HostHeaderCandidate] = []
        for cand in usable:
            matched, missing = match_injection_points(
                cand.points,
                param_filters,
                url=cand.url,
                normalized_path=cand.normalized_path,
            )
            if missing:
                available = ", ".join(
                    f"{point.location}:{point.name}" for point in cand.points
                ) or "(none)"
                cli_error(
                    f"No header matching {', '.join(missing)} "
                    f"on flow {cand.flow_id}. Available: {available}"
                )
            if not matched:
                cli_error(
                    f"No header matching "
                    f"{', '.join(param_filters)} on flow {cand.flow_id}."
                )
            narrowed.append(replace(cand, points=tuple(matched)))
        usable = narrowed

    right_now = bool(getattr(args, "right_now", False))
    high_priority = bool(getattr(args, "high_priority", True))
    priority = PRIORITY_HIGH if high_priority else PRIORITY_MANUAL
    as_json = wants_json(args)

    planned: list[tuple[HostHeaderCandidate, InjectionPoint, object]] = []
    for cand in usable:
        for point in cand.points:
            for payload in payloads:
                if not payload_applies(payload, point.name):
                    continue
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
        sent = render_payload(
            payload,
            point.original,
            url=cand.url,
            header_name=point.name,
        )
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": sent,
            "original_value": point.original,
            "canary_host": CANARY_HOST,
            "inject_mode": payload.inject_mode,
            "normalized_path": point.normalized_path,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=HOST_HEADER_ATTACK,
            project_id=project_id,
            endpoint_id=cand.endpoint_id,
            flow_id=cand.flow_id,
            priority=priority,
            meta=json.dumps(meta),
        )
        enqueued += 1
        jobs.append(
            {
                "job_id": job_id,
                "flow_id": cand.flow_id,
                "param_name": point.name,
                "technique": payload.technique,
                "priority": priority,
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
                "params": param_filters,
                "jobs_enqueued": enqueued,
                "jobs_skipped_dup": skipped,
                "priority": priority,
                "high_priority": high_priority,
                "jobs": jobs,
            }
        )
        return

    print("\nHost-header injection attack generation complete.")
    print(f"  Flows scanned      : {len(usable)}")
    print(f"  Headers            : {sum(len(c.points) for c in usable)}")
    if param_filters:
        print(f"  Header filter      : {', '.join(param_filters)}")
    print(f"  Payloads each      : {len(payloads)}")
    print(f"  Jobs enqueued      : {enqueued}")
    print(
        f"  Priority           : "
        f"{'high (' + str(PRIORITY_HIGH) + ') — ahead of other pending jobs' if high_priority else 'manual (' + str(PRIORITY_MANUAL) + ')'}"
    )
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
        "\nEach job writes a unique replay flow (visible in the Talos Burp "
        "extension under Host Header Injection). "
        "Run 'talos scheduler status' to monitor execution. "
        "Use 'talos attack host-header results list' and "
        "'talos finding list' to review."
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
    Side effects: outbound HTTP; flows + host_header_results + findings.
    """
    from talos.host_header.engine import execute_host_header_job
    from talos.host_header.findings_bridge import maybe_create_host_header_finding

    outcomes: list[dict] = []
    findings = 0
    for cand, point, payload in planned:
        sent = render_payload(
            payload,
            point.original,
            url=cand.url,
            header_name=point.name,
        )
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": sent,
            "original_value": point.original,
            "canary_host": CANARY_HOST,
            "inject_mode": payload.inject_mode,
            "normalized_path": point.normalized_path,
        }
        outcome = asyncio.run(
            execute_host_header_job(
                flow_id=cand.flow_id,
                meta=meta,
                db_path=db_path,
                project_id=project_id,
            )
        )
        finding_id = maybe_create_host_header_finding(
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
                "reflected_url": outcome.reflected_url,
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

    print(f"\nHost-header --right-now complete. Probes: {len(outcomes)}")
    for row in outcomes:
        replay = (row["replay_flow_id"] or "—")[:8]
        print(
            f"  {row['verdict']:<16} {row['technique']:<22} "
            f"{row['param_name']:<24} replay={replay}"
        )
    print(f"  Findings created : {findings}")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List stored host-header probe results (unique replay flows)."""
    project = _require_active(manager)
    rows = list_host_header_results(
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
        cli_info(
            "No host-header results yet. "
            "Run 'talos attack host-header run --flow <uuid>'."
        )
        return
    print(
        f"{'VERDICT':<16} {'FAMILY':<14} {'TECH':<22} {'HEADER':<22} "
        f"{'METHOD':<7} {'PATH':<24} REPLAY"
    )
    for row in rows:
        print(
            f"{row.get('verdict') or '':<16} "
            f"{(row.get('technique_family') or ''):<14} "
            f"{(row.get('technique') or ''):<22} "
            f"{(row.get('param_name') or '')[:22]:<22} "
            f"{(row.get('method') or ''):<7} "
            f"{(row.get('path') or '')[:24]:<24} "
            f"{row.get('replay_flow_id')}"
        )
    print(f"\n{len(rows)} result(s). Each replay_flow_id is a unique probe flow.")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Show one host-header result by replay flow UUID."""
    project = _require_active(manager)
    replay_id = args.replay_flow_id
    row = get_host_header_result(project.db_path, replay_id)
    if row is None:
        cli_error(f"Host-header result not found: {replay_id}")
    if wants_json(args):
        cli_json(row)
        return
    fields = {
        "Replay flow": row.get("replay_flow_id"),
        "Original flow": row.get("original_flow_id"),
        "Technique": row.get("technique"),
        "Family": row.get("technique_family"),
        "Verdict": row.get("verdict"),
        "Header": f"{row.get('location')} {row.get('param_name')}",
        "Payload": row.get("payload_sent") or "—",
        "Reflected": row.get("reflected_url") or "—",
        "Evidence": row.get("evidence") or "—",
        "Risk hint": row.get("risk_hint") or "—",
        "Elapsed ms": row.get("elapsed_ms"),
        "Host": row.get("host"),
        "Method / path": f"{row.get('method')} {row.get('path')}",
        "Replay status": row.get("replay_status"),
    }
    cli_success("Host-header probe result", fields)


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Verdict histogram + host_header_attack job pressure."""
    project = _require_active(manager)
    counts = count_host_header_verdicts(project.db_path)
    with sqlite3.connect(str(project.db_path)) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (HOST_HEADER_ATTACK,),
        ).fetchall()
    jobs = {r[0]: int(r[1]) for r in rows}
    payload = {"verdicts": counts, "jobs": jobs}
    if wants_json(args):
        cli_json(payload)
        return
    print("Host-header injection status")
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


def build_host_header_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Purpose: Register 'host-header' under talos attack."""
    hh_p = sub.add_parser(
        "host-header",
        aliases=["hhi", "host_header", "host-header-injection"],
        help="Host-header injection testing.",
        description=(
            "Scan operator-picked flows for host-header injection "
            "(password-reset / cache / absolute URL generation).\n\n"
            "Pass --flow UUID (repeatable). The engine mutates Host and\n"
            "related override headers (X-Forwarded-Host, X-Host, Forwarded,\n"
            "…), connecting to the original origin. Optional --header\n"
            "restricts the scan to one header.\n\n"
            "Each (header × payload) is one scheduler job and one unique\n"
            "replay flow (shown in the Talos Burp extension). A finding is\n"
            "created when a probe reflects the canary host in a URL-shaped\n"
            "response sink that was not in the captured baseline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ssub = hh_p.add_subparsers(dest="host_header_cmd", metavar="<command>")
    ssub.required = True

    tech_p = ssub.add_parser("techniques", help="List host-header payload techniques.")
    tech_p.add_argument(
        "--family",
        metavar="NAME",
        choices=list(FAMILIES),
        help=(
            "Restrict to absolute | port | ambiguous | absolute_url | "
            "encoded | bypass | crlf."
        ),
    )
    add_format_argument(tech_p)

    run_p = ssub.add_parser(
        "run",
        help="Enqueue host-header probe jobs for one or more flows.",
        description=(
            "Scan captured flows for host-header injection.\n\n"
            "Examples:\n"
            "  talos attack host-header run --flow <uuid>\n"
            "  talos attack host-header run --flow <uuid> --header Host\n"
            "  talos attack host-header run --flow <uuid> --family absolute\n"
            "  talos attack host-header run --flow <uuid> --technique abs_canary\n"
            "  talos attack host-header run --flow <uuid> --right-now\n"
            "  talos attack host-header run --flow <uuid> --no-high-priority"
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
        "--header",
        "--param",
        "--parameter",
        dest="params",
        action="append",
        metavar="NAME",
        help=(
            "Restrict to one header on the flow (optional). Host, "
            "X-Forwarded-Host, Forwarded, or header:Name. Repeatable or "
            "comma-separated."
        ),
    )
    run_p.add_argument(
        "--technique",
        metavar="NAME",
        help="Restrict to one payload technique (default: all).",
    )
    run_p.add_argument(
        "--family",
        metavar="NAME",
        choices=list(FAMILIES),
        help=(
            "Restrict to absolute | port | ambiguous | absolute_url | "
            "encoded | bypass | crlf."
        ),
    )
    run_p.add_argument(
        "--right-now",
        dest="right_now",
        action="store_true",
        help="Execute immediately (still writes unique replay flows).",
    )
    run_p.add_argument(
        "--high-priority",
        dest="high_priority",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            f"Enqueue at priority {PRIORITY_HIGH} so host-header runs before "
            f"other pending jobs (default). --no-high-priority uses normal "
            f"manual priority {PRIORITY_MANUAL}."
        ),
    )
    add_format_argument(run_p)

    res_p = ssub.add_parser("results", help="Inspect host-header probe results.")
    rsub = res_p.add_subparsers(dest="host_header_results_cmd", metavar="<command>")
    rsub.required = True
    rlist = rsub.add_parser("list", help="List host-header results.")
    rlist.add_argument("--verdict", choices=["HOST_HEADER", "SECURE", "UNKNOWN"])
    rlist.add_argument("--technique", metavar="NAME")
    rlist.add_argument("--family", choices=list(FAMILIES))
    rlist.add_argument("--host", metavar="HOST")
    rlist.add_argument("--flow", metavar="UUID", help="Filter by original or replay flow.")
    rlist.add_argument("--limit", type=int, default=200)
    add_format_argument(rlist)
    rshow = rsub.add_parser("show", help="Show one result by replay flow UUID.")
    rshow.add_argument("replay_flow_id")
    add_format_argument(rshow)

    stat_p = ssub.add_parser("status", help="Host-header verdict and job tallies.")
    add_format_argument(stat_p)


def run_host_header_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Dispatch host-header subcommands."""
    cmd = args.host_header_cmd
    if cmd == "techniques":
        cmd_techniques(manager, args)
    elif cmd == "run":
        cmd_run(manager, args)
    elif cmd == "results":
        if args.host_header_results_cmd == "list":
            cmd_results_list(manager, args)
        elif args.host_header_results_cmd == "show":
            cmd_results_show(manager, args)
        else:
            cli_usage_error("usage: talos attack host-header results list|show")
    elif cmd == "status":
        cmd_status(manager, args)
    else:
        cli_usage_error(f"unknown host-header command: {cmd}")
