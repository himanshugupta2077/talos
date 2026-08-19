"""
Module: talos.xss.cli

Purpose:
    Command-line interface for XSS / HTML injection testing.
    Entry point: talos attack xss <subcommand>

    Subcommands:
        techniques  — catalogue of XSS / HTMLI payloads
        run         — enqueue one xss_attack job per
                      (flow, point, payload) (--right-now executes immediately)
        results     — list | show
        status      — verdict + job tallies

    Operator always names the flow(s) with --flow UUID.

Dependencies: argparse, talos.cli_output, talos.xss.*, talos.scheduler
Data flow: attack_cli → run_xss_cli → enqueue / engine
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
from talos.xss.candidates import (
    XssCandidate,
    normalize_flow_ids,
    select_xss_candidates_for_flows,
)
from talos.xss.db import (
    count_xss_verdicts,
    get_xss_result,
    list_xss_results,
)
from talos.xss.inject import match_injection_points, normalize_param_names
from talos.xss.models import FAMILIES, InjectionPoint
from talos.xss.payloads import (
    TECHNIQUE_CATALOG,
    generate_xss_payloads,
    render_payload,
)
from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.job import XSS_ATTACK, PRIORITY_HIGH, PRIORITY_MANUAL


def _require_active(manager: ProjectManager):
    """Return the active project or exit 3."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _select(manager: ProjectManager, args: argparse.Namespace) -> list[XssCandidate]:
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
            "'talos project scope' before xss testing."
        )
    candidates, missing = select_xss_candidates_for_flows(
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
    """Purpose: Skip identical pending/running xss_attack jobs."""
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
            (XSS_ATTACK, flow_id, param_name, technique),
        ).fetchone()
    return row is not None


def cmd_techniques(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Print the xss technique catalogue. manager unused."""
    del manager
    family = getattr(args, "family", None)
    catalog = list(TECHNIQUE_CATALOG)
    if family:
        if family not in FAMILIES:
            cli_usage_error(
                f"unknown xss family {family!r}. "
                f"Expected one of: {', '.join(FAMILIES)}"
            )
        catalog = [row for row in catalog if str(row["family"]) == family]
    if wants_json(args):
        cli_json(catalog)
        return
    print(f"{'TECHNIQUE':<28} {'FAMILY':<10} {'CTX':<10} DESCRIPTION")
    for item in catalog:
        print(
            f"{str(item['name']):<28} {str(item['family']):<12} "
            f"{str(item.get('risk_class') or ''):<8} {item['description']}"
        )
    print(f"\n{len(catalog)} technique(s).")


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue xss_attack jobs (or execute immediately with --right-now).
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
            f"unknown xss family {family!r}. "
            f"Expected one of: {', '.join(FAMILIES)}"
        )

    try:
        payloads = generate_xss_payloads(
            techniques=[technique] if technique else None,
            families=[family] if family else None,
        )
    except ValueError as exc:
        cli_usage_error(str(exc))

    candidates = _select(manager, args)
    if not candidates:
        cli_error(
            "None of the specified flows are usable xss targets "
            "(out of scope, or annotated logout/dangerous/excluded)."
        )

    empty_points = [c for c in candidates if not c.points]
    usable = [c for c in candidates if c.points]
    if not usable:
        cli_error(
            "No injectable entry points on the selected flow(s). "
            "v1 scans query parameters, JSON body fields/indexes, form fields, "
            "multipart filenames, and path parameters."
        )

    if param_filters:
        narrowed: list[XssCandidate] = []
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
                    f"No entry point matching {', '.join(missing)} "
                    f"on flow {cand.flow_id}. Available: {available}"
                )
            if not matched:
                cli_error(
                    f"No entry point matching "
                    f"{', '.join(param_filters)} on flow {cand.flow_id}."
                )
            narrowed.append(replace(cand, points=tuple(matched)))
        usable = narrowed

    right_now = bool(getattr(args, "right_now", False))
    high_priority = bool(getattr(args, "high_priority", True))
    priority = PRIORITY_HIGH if high_priority else PRIORITY_MANUAL
    as_json = wants_json(args)

    planned: list[tuple[XssCandidate, InjectionPoint, object]] = []
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
        sent = render_payload(payload, point.original)
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": sent,
            "original_value": point.original,
            "risk_class": payload.risk_class,
            "inject_mode": payload.inject_mode,
            "path_index": point.path_index,
            "normalized_path": point.normalized_path,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=XSS_ATTACK,
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

    print("\nXSS attack generation complete.")
    print(f"  Flows scanned      : {len(usable)}")
    print(f"  Entry points       : {sum(len(c.points) for c in usable)}")
    if param_filters:
        print(f"  Parameter filter   : {', '.join(param_filters)}")
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
        "extension under XSS). "
        "Run 'talos scheduler status' to monitor execution. "
        "Use 'talos attack xss results list' and "
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
    Side effects: outbound HTTP; flows + xss_results + findings.
    """
    from talos.xss.engine import execute_xss_job
    from talos.xss.findings_bridge import maybe_create_xss_finding

    outcomes: list[dict] = []
    findings = 0
    for cand, point, payload in planned:
        sent = render_payload(payload, point.original)
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "location": point.location,
            "param_name": point.name,
            "surface_kind": point.surface_kind,
            "payload_sent": sent,
            "original_value": point.original,
            "risk_class": payload.risk_class,
            "inject_mode": payload.inject_mode,
            "path_index": point.path_index,
            "normalized_path": point.normalized_path,
        }
        outcome = asyncio.run(
            execute_xss_job(
                flow_id=cand.flow_id,
                meta=meta,
                db_path=db_path,
                project_id=project_id,
            )
        )
        finding_id = maybe_create_xss_finding(
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
                "context_hint": outcome.context_hint,
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

    print(f"\nXSS --right-now complete. Probes: {len(outcomes)}")
    for row in outcomes:
        replay = (row["replay_flow_id"] or "—")[:8]
        print(
            f"  {row['verdict']:<16} {row['technique']:<26} "
            f"{row['param_name']:<20} replay={replay}"
        )
    print(f"  Findings created : {findings}")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List stored xss probe results (unique replay flows)."""
    project = _require_active(manager)
    rows = list_xss_results(
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
            "No xss results yet. "
            "Run 'talos attack xss run --flow <uuid>'."
        )
        return
    print(
        f"{'VERDICT':<16} {'FAMILY':<10} {'TECH':<24} {'PARAM':<18} "
        f"{'CTX':<10} {'METHOD':<7} {'PATH':<24} REPLAY"
    )
    for row in rows:
        print(
            f"{row.get('verdict') or '':<16} "
            f"{(row.get('technique_family') or ''):<10} "
            f"{(row.get('technique') or ''):<24} "
            f"{(row.get('param_name') or '')[:18]:<18} "
            f"{(row.get('context_hint') or '—')[:8]:<8} "
            f"{(row.get('method') or ''):<7} "
            f"{(row.get('path') or '')[:24]:<24} "
            f"{row.get('replay_flow_id')}"
        )
    print(f"\n{len(rows)} result(s). Each replay_flow_id is a unique probe flow.")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Show one xss result by replay flow UUID."""
    project = _require_active(manager)
    replay_id = args.replay_flow_id
    row = get_xss_result(project.db_path, replay_id)
    if row is None:
        cli_error(f"XSS result not found: {replay_id}")
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
        "Context": row.get("context_hint") or "—",
        "Encoding": row.get("encoding_hint") or "—",
        "Evidence": row.get("evidence") or "—",
        "Risk hint": row.get("risk_hint") or "—",
        "Elapsed ms": row.get("elapsed_ms"),
        "Host": row.get("host"),
        "Method / path": f"{row.get('method')} {row.get('path')}",
        "Replay status": row.get("replay_status"),
    }
    cli_success("XSS probe result", fields)


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Verdict histogram + xss_attack job pressure."""
    project = _require_active(manager)
    counts = count_xss_verdicts(project.db_path)
    with sqlite3.connect(str(project.db_path)) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (XSS_ATTACK,),
        ).fetchall()
    jobs = {r[0]: int(r[1]) for r in rows}
    payload = {"verdicts": counts, "jobs": jobs}
    if wants_json(args):
        cli_json(payload)
        return
    print("XSS status")
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


def build_xss_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Purpose: Register 'xss' under talos attack."""
    pt_p = sub.add_parser(
        "xss",
        aliases=["htmli", "html_injection"],
        help="XSS / HTML injection testing.",
        description=(
            "Scan operator-picked flows for XSS and HTML injection.\n\n"
            "Pass --flow UUID (repeatable). The engine walks query parameters,\n"
            "JSON body fields/indexes, form fields, multipart filenames, and\n"
            "path parameters, then injects HTML/JS, HTMLI, attribute, event,\n"
            "JS-context, URI, encoded, WAF-bypass, and polyglot payloads.\n"
            "Optional --param restricts the scan to one entry point.\n\n"
            "Each (entry point × payload) is one scheduler job and one unique\n"
            "replay flow (shown in the Talos Burp extension under XSS). A\n"
            "finding is created when the TalosXss canary reflects with an\n"
            "unencoded JS sink (XSS) or unencoded HTML markup (HTMLI)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ssub = pt_p.add_subparsers(dest="xss_cmd", metavar="<command>")
    ssub.required = True

    tech_p = ssub.add_parser("techniques", help="List xss payload techniques.")
    tech_p.add_argument(
        "--family",
        metavar="NAME",
        choices=list(FAMILIES),
        help="Restrict to html_tag | htmli | html_attr | event | js | url | encoded | bypass | polyglot.",
    )
    add_format_argument(tech_p)

    run_p = ssub.add_parser(
        "run",
        help="Enqueue XSS / HTMLI probe jobs for one or more flows.",
        description=(
            "Scan captured flows for XSS / HTML injection.\n\n"
            "Examples:\n"
            "  talos attack xss run --flow <uuid>\n"
            "  talos attack xss run --flow <uuid> --param q\n"
            "  talos attack xss run --flow <uuid> --family html_tag\n"
            "  talos attack xss run --flow <uuid> --technique script_alert\n"
            "  talos attack xss run --flow <uuid> --right-now\n"
            "  talos attack xss run --flow <uuid> --no-high-priority"
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
        "--param",
        "--parameter",
        dest="params",
        action="append",
        metavar="NAME",
        help=(
            "Restrict to one entry point on the flow (optional). Query key, "
            "JSON path (user.file / [0]), form field, path param, multipart "
            "filename, or location:name (query:file). Repeatable or comma-separated."
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
        help="Restrict to html_tag | htmli | html_attr | event | js | url | encoded | bypass | polyglot.",
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
            f"Enqueue at priority {PRIORITY_HIGH} so xss runs before "
            f"other pending jobs (default). --no-high-priority uses normal "
            f"manual priority {PRIORITY_MANUAL}."
        ),
    )
    add_format_argument(run_p)

    res_p = ssub.add_parser("results", help="Inspect xss probe results.")
    rsub = res_p.add_subparsers(dest="xss_results_cmd", metavar="<command>")
    rsub.required = True
    rlist = rsub.add_parser("list", help="List xss results.")
    rlist.add_argument("--verdict", choices=["XSS", "HTMLI", "SECURE", "UNKNOWN"])
    rlist.add_argument("--technique", metavar="NAME")
    rlist.add_argument("--family", choices=list(FAMILIES))
    rlist.add_argument("--host", metavar="HOST")
    rlist.add_argument("--flow", metavar="UUID", help="Filter by original or replay flow.")
    rlist.add_argument("--limit", type=int, default=200)
    add_format_argument(rlist)
    rshow = rsub.add_parser("show", help="Show one result by replay flow UUID.")
    rshow.add_argument("replay_flow_id")
    add_format_argument(rshow)

    stat_p = ssub.add_parser("status", help="XSS verdict and job tallies.")
    add_format_argument(stat_p)


def run_xss_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Dispatch xss subcommands."""
    cmd = args.xss_cmd
    if cmd == "techniques":
        cmd_techniques(manager, args)
    elif cmd == "run":
        cmd_run(manager, args)
    elif cmd == "results":
        if args.xss_results_cmd == "list":
            cmd_results_list(manager, args)
        elif args.xss_results_cmd == "show":
            cmd_results_show(manager, args)
        else:
            cli_usage_error("usage: talos attack xss results list|show")
    elif cmd == "status":
        cmd_status(manager, args)
    else:
        cli_usage_error(f"unknown xss command: {cmd}")
