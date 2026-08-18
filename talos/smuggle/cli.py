"""
Module: talos.smuggle.cli

Purpose:
    Command-line interface for HTTP request smuggling.
    Entry point: talos attack smuggle <subcommand>

    Subcommands:
        techniques  — catalogue of CL/TE probes
        run         — enqueue one smuggle_attack job per (flow, technique)
                      (--right-now executes immediately)
        results     — list | show
        status      — verdict + job tallies

    Operator always names the flow(s) with --flow UUID.

Dependencies: argparse, talos.cli_output, talos.smuggle.*, talos.scheduler
Data flow: attack_cli → run_smuggle_cli → enqueue / engine
Side effects: scheduler_jobs inserts; optional outbound HTTP on --right-now.
"""

from __future__ import annotations

import argparse
import json
import secrets
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
from talos.scheduler.job import PRIORITY_MANUAL, SMUGGLE_ATTACK
from talos.smuggle.candidates import (
    SmuggleCandidate,
    normalize_flow_ids,
    select_smuggle_candidates_for_flows,
)
from talos.smuggle.db import (
    count_smuggle_verdicts,
    get_smuggle_result,
    list_smuggle_results,
)
from talos.smuggle.models import TECHNIQUE_CATALOG, TECHNIQUE_NAMES
from talos.smuggle.payloads import canary_path_for, generate_smuggle_payloads


def _require_active(manager: ProjectManager):
    """Return the active project or exit 3."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


def _select(manager: ProjectManager, args: argparse.Namespace) -> list[SmuggleCandidate]:
    """Purpose: Require --flow and load those captures."""
    project = _require_active(manager)
    flow_ids = normalize_flow_ids(getattr(args, "flows", None))
    if not flow_ids:
        cli_usage_error(
            "Pass --flow UUID to probe a captured request. "
            "Use 'talos flow list' to copy a flow id. "
            "Repeat --flow or comma-separate to scan several."
        )
    if not project.scope:
        cli_precondition_error(
            "Project scope is empty. Add Basic Scope prefixes with "
            "'talos project scope' before smuggle testing."
        )
    candidates, missing = select_smuggle_candidates_for_flows(
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


def _has_pending_duplicate(db_path: Path, flow_id: str, technique: str) -> bool:
    """Purpose: Skip identical pending/running smuggle_attack jobs."""
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
            (SMUGGLE_ATTACK, flow_id, technique),
        ).fetchone()
    return row is not None


def cmd_techniques(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Print the smuggle technique catalogue. manager unused."""
    del manager
    if wants_json(args):
        cli_json(list(TECHNIQUE_CATALOG))
        return
    print(f"{'TECHNIQUE':<16} {'FAMILY':<16} DESCRIPTION")
    for item in TECHNIQUE_CATALOG:
        print(
            f"{item['name']:<16} {item['family']:<16} {item['description']}"
        )


def cmd_run(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Enqueue smuggle_attack jobs (or execute immediately with --right-now).
        Each job creates a unique replay flow and a Burp snapshot row.
    """
    project = _require_active(manager)
    db_path = project.db_path
    project_id = project.id

    technique = getattr(args, "technique", None)
    if technique and technique not in TECHNIQUE_NAMES:
        cli_usage_error(
            f"unknown smuggle technique {technique!r}. "
            f"See: talos attack smuggle techniques"
        )

    try:
        payloads = generate_smuggle_payloads(
            host="placeholder.invalid",
            nonce="preview",
            techniques=[technique] if technique else None,
        )
    except ValueError as exc:
        cli_usage_error(str(exc))

    candidates = _select(manager, args)
    if not candidates:
        cli_error(
            "None of the specified flows are usable smuggle targets "
            "(out of scope, or annotated logout/dangerous/excluded)."
        )

    nonce = secrets.token_hex(4)
    canary = canary_path_for(nonce)
    right_now = bool(getattr(args, "right_now", False))
    as_json = wants_json(args)

    planned: list[tuple[SmuggleCandidate, object]] = []
    for cand in candidates:
        for payload in payloads:
            planned.append((cand, payload))

    if right_now:
        _run_right_now(db_path, project_id, planned, nonce=nonce, as_json=as_json)
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
            "nonce": nonce,
            "canary_path": canary,
        }
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=SMUGGLE_ATTACK,
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

    print("\nHTTP request smuggling generation complete.")
    print(f"  Flows scanned      : {len(candidates)}")
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
        "\nEach job writes a unique replay flow and a Burp snapshot row. "
        "Run 'talos scheduler status' to monitor execution. "
        "Use 'talos attack smuggle results list' and 'talos finding list' to review."
    )


def _run_right_now(
    db_path: Path,
    project_id: str,
    planned: list,
    *,
    nonce: str,
    as_json: bool,
) -> None:
    """
    Purpose:
        Execute probes in-process (still one unique flow per technique).
    Side effects: outbound HTTP; flows + smuggle_results + findings + Burp.
    """
    from talos.smuggle.engine import execute_smuggle_job
    from talos.smuggle.findings_bridge import maybe_create_smuggle_finding

    canary = canary_path_for(nonce)
    outcomes: list[dict] = []
    findings = 0
    for cand, payload in planned:
        meta = {
            "technique": payload.technique,
            "technique_family": payload.family,
            "nonce": nonce,
            "canary_path": canary,
        }
        outcome = execute_smuggle_job(
            flow_id=cand.flow_id,
            meta=meta,
            db_path=db_path,
            project_id=project_id,
        )
        finding_id = maybe_create_smuggle_finding(
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
                "technique": outcome.technique,
                "verdict": outcome.verdict,
                "desync_signal": outcome.desync_signal,
                "ntlm_used": outcome.ntlm_used,
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

    print(f"\nSmuggle --right-now complete. Probes: {len(outcomes)}")
    for row in outcomes:
        replay = (row["replay_flow_id"] or "—")[:8]
        print(
            f"  {row['verdict']:<12} {row['technique']:<14} "
            f"replay={replay} ntlm={'yes' if row['ntlm_used'] else 'no'}"
        )
    print(f"  Findings created : {findings}")


def cmd_results_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: List stored smuggle probe results (unique replay flows)."""
    project = _require_active(manager)
    rows = list_smuggle_results(
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
        cli_info("No smuggle results yet. Run 'talos attack smuggle run --flow <uuid>'.")
        return
    print(
        f"{'VERDICT':<12} {'TECH':<14} {'NTLM':<5} "
        f"{'BASE':<5} {'FOLL':<5} {'PATH':<28} REPLAY"
    )
    for row in rows:
        print(
            f"{row.get('verdict') or '':<12} "
            f"{(row.get('technique') or ''):<14} "
            f"{'yes' if row.get('ntlm_used') else 'no':<5} "
            f"{str(row.get('baseline_status') or '—'):<5} "
            f"{str(row.get('followup_status') or '—'):<5} "
            f"{(row.get('path') or '')[:28]:<28} "
            f"{row.get('replay_flow_id')}"
        )
    print(f"\n{len(rows)} result(s). Each replay_flow_id is a unique probe flow.")


def cmd_results_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Show one smuggle result by replay flow UUID."""
    project = _require_active(manager)
    replay_id = args.replay_flow_id
    row = get_smuggle_result(project.db_path, replay_id)
    if row is None:
        cli_error(f"Smuggle result not found: {replay_id}")
    if wants_json(args):
        cli_json(row)
        return
    fields = {
        "Replay flow": row.get("replay_flow_id"),
        "Original flow": row.get("original_flow_id"),
        "Technique": row.get("technique"),
        "Family": row.get("technique_family"),
        "Verdict": row.get("verdict"),
        "Desync signal": row.get("desync_signal") or "—",
        "Evidence": row.get("evidence") or "—",
        "Canary": row.get("canary_path") or "—",
        "NTLM": "yes" if row.get("ntlm_used") else "no",
        "Baseline status": row.get("baseline_status"),
        "Probe status": row.get("probe_status"),
        "Follow-up status": row.get("followup_status"),
        "Host": row.get("host"),
        "Method / path": f"{row.get('method')} {row.get('path')}",
        "Failure": row.get("failure_reason") or "—",
    }
    cli_success("HTTP request smuggling probe result", fields)


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Verdict histogram + smuggle_attack job pressure."""
    project = _require_active(manager)
    counts = count_smuggle_verdicts(project.db_path)
    with sqlite3.connect(str(project.db_path)) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (SMUGGLE_ATTACK,),
        ).fetchall()
    jobs = {r[0]: int(r[1]) for r in rows}
    payload = {"verdicts": counts, "jobs": jobs}
    if wants_json(args):
        cli_json(payload)
        return
    print("HTTP request smuggling status")
    print("  Verdicts:")
    if counts:
        for name, n in sorted(counts.items()):
            print(f"    {name:<12} {n}")
    else:
        print("    (none)")
    print("  Jobs:")
    if jobs:
        for name, n in sorted(jobs.items()):
            print(f"    {name:<12} {n}")
    else:
        print("    (none)")


def build_smuggle_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Purpose: Register 'smuggle' under talos attack."""
    smuggle_p = sub.add_parser(
        "smuggle",
        help="HTTP request smuggling (CL/TE desync).",
        description=(
            "Probe a captured flow for HTTP request smuggling.\n\n"
            "Pass --flow UUID (repeatable). Each technique is one scheduler\n"
            "job and one unique replay flow. Probes are raw HTTP/1.1 to the\n"
            "origin (NTLM handshake on the same connection when platform\n"
            "auth is configured). Requests appear in the Talos Burp extension.\n\n"
            "A finding is created only when a follow-up request is poisoned\n"
            "(status flip to 400/404/405, canary echo, or extra response)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ssub = smuggle_p.add_subparsers(dest="smuggle_cmd", metavar="<command>")
    ssub.required = True

    tech_p = ssub.add_parser("techniques", help="List CL/TE smuggling techniques.")
    add_format_argument(tech_p)

    run_p = ssub.add_parser(
        "run",
        help="Enqueue smuggle jobs (one unique flow per technique).",
        description=(
            "Enqueue one smuggle_attack job per technique on the named flow(s).\n\n"
            "Examples:\n"
            "  talos attack smuggle run --flow <uuid>\n"
            "  talos attack smuggle run --flow <uuid> --technique cl_te\n"
            "  talos attack smuggle run --flow <uuid1> --flow <uuid2>\n"
            "  talos attack smuggle run --flow <uuid> --right-now"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument("--technique", metavar="NAME", choices=list(TECHNIQUE_NAMES))
    run_p.add_argument(
        "--flow",
        dest="flows",
        action="append",
        metavar="UUID",
        help="Probe this captured flow (repeatable or comma-separated). Required.",
    )
    run_p.add_argument(
        "--right-now",
        dest="right_now",
        action="store_true",
        help="Execute immediately (still writes unique replay flows).",
    )
    add_format_argument(run_p)

    res_p = ssub.add_parser("results", help="Inspect smuggle probe results.")
    rsub = res_p.add_subparsers(dest="smuggle_results_cmd", metavar="<command>")
    rsub.required = True
    rlist = rsub.add_parser("list", help="List smuggle results.")
    rlist.add_argument("--verdict", choices=["SMUGGLE", "SECURE", "UNKNOWN"])
    rlist.add_argument("--technique", metavar="NAME")
    rlist.add_argument("--host", metavar="HOST")
    rlist.add_argument("--limit", type=int, default=200)
    add_format_argument(rlist)
    rshow = rsub.add_parser("show", help="Show one result by replay flow UUID.")
    rshow.add_argument("replay_flow_id")
    add_format_argument(rshow)

    stat_p = ssub.add_parser("status", help="Smuggle verdict and job tallies.")
    add_format_argument(stat_p)


def run_smuggle_cli(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Purpose: Dispatch smuggle subcommands."""
    cmd = args.smuggle_cmd
    if cmd == "techniques":
        cmd_techniques(manager, args)
    elif cmd == "run":
        cmd_run(manager, args)
    elif cmd == "results":
        if args.smuggle_results_cmd == "list":
            cmd_results_list(manager, args)
        elif args.smuggle_results_cmd == "show":
            cmd_results_show(manager, args)
        else:
            cli_usage_error("usage: talos attack smuggle results list|show")
    elif cmd == "status":
        cmd_status(manager, args)
    else:
        cli_usage_error(f"unknown smuggle command: {cmd}")
