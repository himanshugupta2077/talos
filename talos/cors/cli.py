"""
Module: talos.cors.cli

Purpose:
    Command-line interface for CORS misconfiguration testing.
    Entry point: talos attack cors <subcommand>

    Subcommands:
        candidates  — list selected 200 OK in-scope baselines
        techniques  — catalogue of Origin payloads
        run         — enqueue one cors_attack job per (flow, technique)
                      (--right-now executes immediately, still unique flows)
        results     — list | show
        status      — verdict + job tallies

    Same operator flow as unauth / auth-session: run enqueues scheduler
    jobs; each job writes a unique replay flow.

Dependencies: argparse, talos.cli_output, talos.cors.*, talos.scheduler
Data flow: attack_cli → run_cors_cli → candidates / enqueue / engine
Side effects: scheduler_jobs inserts; optional outbound HTTP on --right-now.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

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
from talos.cors.candidates import (
    DEFAULT_CANDIDATE_LIMIT,
    CorsCandidate,
    normalize_flow_ids,
    select_cors_candidates,
    select_cors_candidates_for_flows,
)
from talos.cors.db import count_cors_verdicts, get_cors_result, list_cors_results
from talos.cors.models import TECHNIQUE_CATALOG, TECHNIQUE_NAMES
from talos.cors.payloads import generate_cors_payloads
from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.job import CORS_ATTACK, PRIORITY_MANUAL


def _require_active(manager: ProjectManager):
    """Return the active project or exit 3."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _select(manager: ProjectManager, args: argparse.Namespace) -> list[CorsCandidate]:
    """Purpose: Shared candidate picker for run / candidates."""
    project = _require_active(manager)
    flow_ids = normalize_flow_ids(getattr(args, "flows", None))
    if flow_ids:
        candidates, missing = select_cors_candidates_for_flows(
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
    raw_limit = getattr(args, "limit", None)
    if raw_limit is None:
        limit = DEFAULT_CANDIDATE_LIMIT
    else:
        limit = max(1, int(raw_limit))
    return select_cors_candidates(
        project.db_path,
        in_scope_prefixes=list(project.scope or []),
        limit=limit,
        endpoint_id=getattr(args, "endpoint", None),
        host=getattr(args, "host", None),
    )


def _has_pending_duplicate(db_path: Path, flow_id: str, technique: str) -> bool:
    """Purpose: Skip identical pending/running cors_attack jobs."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM scheduler_jobs
            WHERE job_type = ?
              AND flow_id = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.technique') = ?
            LIMIT 1
            """,
            (CORS_ATTACK, flow_id, technique),
        ).fetchone()
    return row is not None


def cmd_candidates(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List selected CORS baselines. Side effects: stdout only."""
    project = _require_active(manager)
    if not project.scope:
        cli_precondition_error(
            "Project scope is empty. Add Basic Scope prefixes with "
            "'talos project scope' before CORS testing."
        )
    rows = _select(manager, args)
    if wants_json(args):
        cli_json([c.to_dict() for c in rows])
        return
    if not rows:
        if normalize_flow_ids(getattr(args, "flows", None)):
            cli_info(
                "None of the specified flows are usable CORS baselines "
                "(out of scope, or annotated logout/dangerous/excluded)."
            )
        else:
            cli_info(
                "No CORS candidates (need in-scope proxy_capture flows with 200 OK)."
            )
        return
    print(f"{'METHOD':<7} {'ORIGIN?':<8} {'HOST':<28} {'PATH':<32} FLOW")
    for cand in rows:
        flag = "yes" if cand.origin_was_present else "synth"
        print(
            f"{cand.method:<7} {flag:<8} {cand.host[:28]:<28} "
            f"{cand.path[:32]:<32} {cand.flow_id}"
        )
    print(f"\n{len(rows)} candidate(s). Origin?=synth means Origin was synthesized from the host URL.")


def cmd_techniques(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Print the CORS technique catalogue. manager unused."""
    del manager
    if wants_json(args):
        cli_json(list(TECHNIQUE_CATALOG))
        return
    print(f"{'TECHNIQUE':<22} {'FAMILY':<22} DESCRIPTION")
    for item in TECHNIQUE_CATALOG:
        print(
            f"{item['name']:<22} {item['family']:<22} {item['description']}"
        )


def _payloads_for(
    candidate: CorsCandidate,
    *,
    nonce: str,
    technique: Optional[str],
) -> list:
    """Purpose: Build payloads for one candidate, optional technique filter."""
    names = [technique] if technique else None
    return generate_cors_payloads(
        baseline_origin=candidate.baseline_origin,
        request_method=candidate.method,
        nonce=nonce,
        techniques=names,
    )


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue cors_attack jobs (or execute immediately with --right-now).
        Each job creates a unique replay flow.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id
    if not project.scope:
        cli_precondition_error(
            "Project scope is empty. Add Basic Scope prefixes with "
            "'talos project scope' before CORS testing."
        )

    technique = getattr(args, "technique", None)
    if technique and technique not in TECHNIQUE_NAMES:
        cli_usage_error(
            f"unknown CORS technique {technique!r}. "
            f"See: talos attack cors techniques"
        )

    candidates = _select(manager, args)
    if not candidates:
        if normalize_flow_ids(getattr(args, "flows", None)):
            cli_error(
                "None of the specified flows are usable CORS baselines "
                "(out of scope, or annotated logout/dangerous/excluded)."
            )
        cli_error(
            "No CORS candidates found. Capture in-scope traffic that returns "
            "200 OK (POST/PATCH/PUT preferred, then GET), or pass --flow UUID."
        )

    nonce = secrets.token_hex(4)
    right_now = bool(getattr(args, "right_now", False))
    as_json = wants_json(args)

    planned: list[tuple[CorsCandidate, object]] = []
    for cand in candidates:
        for payload in _payloads_for(cand, nonce=nonce, technique=technique):
            planned.append((cand, payload))

    if right_now:
        _run_right_now(db_path, project_id, planned, as_json=as_json)
        return

    enqueued = 0
    skipped = 0
    jobs: list[dict] = []
    for cand, payload in planned:
        if _has_pending_duplicate(db_path, cand.flow_id, payload.technique):
            skipped += 1
            continue
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "origin_sent": payload.origin,
            "attacker_controlled": payload.attacker_controlled,
            "baseline_origin": cand.baseline_origin,
            "origin_was_present": cand.origin_was_present,
            "nonce": nonce,
            "method_override": payload.method_override,
            "acr_method": payload.acr_method,
            "acr_headers": payload.acr_headers,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=CORS_ATTACK,
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
                "technique": payload.technique,
                "origin_sent": payload.origin,
            }
        )

    if as_json:
        cli_json(
            {
                "mode": "enqueue",
                "candidates": len(candidates),
                "jobs_enqueued": enqueued,
                "jobs_skipped_dup": skipped,
                "nonce": nonce,
                "jobs": jobs,
            }
        )
        return

    print("\nCORS attack generation complete.")
    print(f"  Candidates scanned : {len(candidates)}")
    print(f"  Jobs enqueued      : {enqueued}")
    if skipped:
        print(f"  Jobs skipped (dup) : {skipped}")
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
        "Use 'talos attack cors results list' and 'talos finding list' to review."
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
        Execute probes in-process (still one unique flow per technique).
    Side effects: outbound HTTP; flows + cors_results + findings.
    """
    from talos.cors.engine import execute_cors_job
    from talos.cors.findings_bridge import maybe_create_cors_finding

    outcomes: list[dict] = []
    findings = 0
    for cand, payload in planned:
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "origin_sent": payload.origin,
            "attacker_controlled": payload.attacker_controlled,
            "baseline_origin": cand.baseline_origin,
            "origin_was_present": cand.origin_was_present,
            "method_override": payload.method_override,
            "acr_method": payload.acr_method,
            "acr_headers": payload.acr_headers,
        }
        outcome = asyncio.run(
            execute_cors_job(
                flow_id=cand.flow_id,
                meta=meta,
                db_path=db_path,
                project_id=project_id,
            )
        )
        finding_id = maybe_create_cors_finding(
            db_path=db_path,
            project_id=project_id,
            outcome=outcome,
            method=cand.method,
            path=cand.path,
        )
        if finding_id:
            findings += 1
        outcomes.append(
            {
                "flow_id": cand.flow_id,
                "replay_flow_id": outcome.replayed_flow_id,
                "technique": outcome.technique,
                "verdict": outcome.verdict,
                "origin_sent": outcome.origin_sent,
                "acao": outcome.acao,
                "acac": outcome.acac,
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

    print(f"\nCORS --right-now complete. Probes: {len(outcomes)}")
    for row in outcomes:
        replay = (row["replay_flow_id"] or "—")[:8]
        print(
            f"  {row['verdict']:<16} {row['technique']:<22} "
            f"replay={replay} origin={row['origin_sent']}"
        )
    print(f"  Findings created : {findings}")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List stored CORS probe results (unique replay flows)."""
    project = _require_active(manager)
    rows = list_cors_results(
        project.db_path,
        verdict=getattr(args, "verdict", None),
        technique=getattr(args, "technique", None),
        host=getattr(args, "host", None),
        limit=int(getattr(args, "limit", 200) or 200),
    )
    if wants_json(args):
        cli_json(rows)
        return
    if not rows:
        cli_info("No CORS results yet. Run 'talos attack cors run'.")
        return
    print(
        f"{'VERDICT':<16} {'TECH':<22} {'REFL':<5} {'ACAC':<5} "
        f"{'METHOD':<7} {'PATH':<28} REPLAY"
    )
    for row in rows:
        print(
            f"{row.get('verdict') or '':<16} "
            f"{(row.get('technique') or ''):<22} "
            f"{'yes' if row.get('reflected') else 'no':<5} "
            f"{'yes' if row.get('credentials') else 'no':<5} "
            f"{(row.get('method') or ''):<7} "
            f"{(row.get('path') or '')[:28]:<28} "
            f"{row.get('replay_flow_id')}"
        )
    print(f"\n{len(rows)} result(s). Each replay_flow_id is a unique probe flow.")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Show one CORS result by replay flow UUID."""
    project = _require_active(manager)
    replay_id = args.replay_flow_id
    row = get_cors_result(project.db_path, replay_id)
    if row is None:
        cli_error(f"CORS result not found: {replay_id}")
    if wants_json(args):
        cli_json(row)
        return
    fields = {
        "Replay flow": row.get("replay_flow_id"),
        "Original flow": row.get("original_flow_id"),
        "Technique": row.get("technique"),
        "Family": row.get("technique_family"),
        "Verdict": row.get("verdict"),
        "Origin sent": row.get("origin_sent"),
        "ACAO": row.get("acao") or "—",
        "ACAC": row.get("acac") or "—",
        "Reflected": "yes" if row.get("reflected") else "no",
        "Credentials": "yes" if row.get("credentials") else "no",
        "Wildcard": "yes" if row.get("wildcard") else "no",
        "Risk hint": row.get("risk_hint") or "—",
        "Host": row.get("host"),
        "Method / path": f"{row.get('method')} {row.get('path')}",
        "Replay status": row.get("replay_status"),
    }
    cli_success("CORS probe result", fields)


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Verdict histogram + cors_attack job pressure."""
    project = _require_active(manager)
    counts = count_cors_verdicts(project.db_path)
    jobs: dict[str, int] = {}
    with sqlite3.connect(str(project.db_path)) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (CORS_ATTACK,),
        ).fetchall()
    jobs = {r[0]: int(r[1]) for r in rows}
    payload = {"verdicts": counts, "jobs": jobs}
    if wants_json(args):
        cli_json(payload)
        return
    print("CORS status")
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


def build_cors_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Purpose: Register 'cors' under talos attack."""
    cors_p = sub.add_parser(
        "cors",
        help="CORS misconfiguration testing.",
        description=(
            "Test in-scope 200 OK endpoints for CORS origin reflection.\n\n"
            "Candidate selection prefers POST / PATCH / PUT, then GET, and\n"
            "prefers requests that already send Origin. Missing Origin is\n"
            "synthesized from the request host URL. Default run takes the\n"
            f"top {DEFAULT_CANDIDATE_LIMIT} endpoints, then every technique.\n"
            "Pass --flow UUID (repeatable) to probe only those captures.\n\n"
            "Each technique is one scheduler job and one unique replay flow.\n"
            "A finding is created only when an attacker origin or subdomain\n"
            "is reflected in Access-Control-Allow-Origin. Credentials / *\n"
            "are extra evidence on that one PRIMARY finding, not standalone."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    csub = cors_p.add_subparsers(dest="cors_cmd", metavar="<command>")
    csub.required = True

    cand_p = csub.add_parser("candidates", help="List selected 200 OK CORS baselines.")
    cand_p.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_CANDIDATE_LIMIT,
        help=f"Max endpoints (default {DEFAULT_CANDIDATE_LIMIT}; ignored with --flow).",
    )
    cand_p.add_argument("--endpoint", metavar="UUID")
    cand_p.add_argument("--host", metavar="HOST")
    cand_p.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        help="Use this captured flow (repeatable or comma-separated). Skips auto ranking.",
    )
    add_format_argument(cand_p)

    tech_p = csub.add_parser("techniques", help="List CORS Origin techniques.")
    add_format_argument(tech_p)

    run_p = csub.add_parser(
        "run",
        help="Enqueue CORS probe jobs (one unique flow per technique).",
        description=(
            "Select in-scope 200 OK flows and enqueue one cors_attack job\n"
            "per technique. Scheduler execution stores a unique replay flow.\n\n"
            "Examples:\n"
            "  talos attack cors run\n"
            "  talos attack cors run --technique arbitrary_https\n"
            "  talos attack cors run --flow <uuid>\n"
            "  talos attack cors run --flow <uuid1> --flow <uuid2>\n"
            "  talos attack cors run --right-now"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument("--technique", metavar="NAME", choices=list(TECHNIQUE_NAMES))
    run_p.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_CANDIDATE_LIMIT,
        help=f"Max endpoints to probe (default {DEFAULT_CANDIDATE_LIMIT}; ignored with --flow).",
    )
    run_p.add_argument("--endpoint", metavar="UUID")
    run_p.add_argument("--host", metavar="HOST")
    run_p.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        help="Probe only this captured flow (repeatable or comma-separated).",
    )
    run_p.add_argument(
        "--right-now",
        dest="right_now",
        action="store_true",
        help="Execute immediately (still writes unique replay flows).",
    )
    add_format_argument(run_p)

    res_p = csub.add_parser("results", help="Inspect CORS probe results.")
    rsub = res_p.add_subparsers(dest="cors_results_cmd", metavar="<command>")
    rsub.required = True
    rlist = rsub.add_parser("list", help="List CORS results.")
    rlist.add_argument("--verdict", choices=["CORS_MISCONFIG", "SECURE", "UNKNOWN"])
    rlist.add_argument("--technique", metavar="NAME")
    rlist.add_argument("--host", metavar="HOST")
    rlist.add_argument("--limit", type=int, default=200)
    add_format_argument(rlist)
    rshow = rsub.add_parser("show", help="Show one result by replay flow UUID.")
    rshow.add_argument("replay_flow_id")
    add_format_argument(rshow)

    stat_p = csub.add_parser("status", help="CORS verdict and job tallies.")
    add_format_argument(stat_p)


def run_cors_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Dispatch cors subcommands."""
    cmd = args.cors_cmd
    if cmd == "candidates":
        cmd_candidates(manager, args)
    elif cmd == "techniques":
        cmd_techniques(manager, args)
    elif cmd == "run":
        cmd_run(manager, args)
    elif cmd == "results":
        if args.cors_results_cmd == "list":
            cmd_results_list(manager, args)
        elif args.cors_results_cmd == "show":
            cmd_results_show(manager, args)
        else:
            cli_usage_error("usage: talos attack cors results list|show")
    elif cmd == "status":
        cmd_status(manager, args)
    else:
        cli_usage_error(f"unknown cors command: {cmd}")
