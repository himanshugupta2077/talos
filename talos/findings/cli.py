"""
Module: talos.findings.cli

Purpose:
    Command-line interface for the Findings subsystem.
    Entry point: talos finding <subcommand>

    Commands:
        talos finding list                          List PRIMARY findings (default)
        talos finding list --linked                 List LINKED findings only
        talos finding list --all                    List PRIMARY and LINKED findings
        talos finding show <uuid>                   Show finding detail
        talos finding confirm <uuid>                Mark finding as CONFIRMED
        talos finding reject <uuid>                 Mark finding as REJECTED
        talos finding reopen <uuid>                 Revert CONFIRMED/REJECTED/DUPLICATE → TRIAGING
        talos finding confirm|reject|reopen <uuid> --linked
                                                    Bulk status change on PRIMARY + linked
        talos finding duplicate <uuid> --of <uuid>  Mark as DUPLICATE of another finding
        talos finding note set <uuid>               Set free-form analyst notes (stdin)
        talos finding note clear <uuid>             Clear analyst notes
        talos finding group create "<name>"         Create a new finding group
        talos finding group add <group> <finding>   Add finding to group
        talos finding group remove <group> <finding>Remove finding from group
        talos finding group remove <group>          Remove group only (use --remove-findings
                                                    to also delete member findings)
        talos finding group list                    List all groups
        talos finding report <uuid>                 Print Markdown report for one finding
        talos finding report --group <group>        Print combined Markdown report for a group

    All commands require a bound project (registry ACTIVE, --project, or TALOS_PROJECT).

    Relationship notes:
        PRIMARY / LINKED group related attack results for display.
        Status changes affect one finding by default.
        --linked on confirm/reject/reopen is a one-time bulk op on a PRIMARY
        finding and its currently linked children (no status inheritance).

Dependencies: argparse, sys
              talos.projects.manager, talos.findings.db, talos.findings.model,
              talos.findings.report
Data flow:
    talos.__main__ → run_finding_cli(manager, argv)
Side effects:
    - Write commands: update findings DB.
    - Report command: prints Markdown to stdout.
    - All commands exit 1 on hard errors.
"""
from talos.cli_output import (
    EXIT_USAGE,
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_json,
    cli_usage_error,
    cli_precondition_error,
    confirm_or_exit,
    wants_json,
)

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from talos.projects.manager import ProjectManager
import talos.findings.db as findings_db
from talos.findings.model import (
    FINDING_STATUSES,
    FINDING_STATUS_TRIAGING,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_REJECTED,
    FINDING_STATUS_DUPLICATE,
    RELATION_TYPE_PRIMARY,
    RELATION_TYPE_LINKED,
    TIMELINE_ACTOR_ANALYST,
    ATTACK_DISPLAY,
)
from talos.findings.report import generate_finding_report, generate_group_report


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _require_active(manager: ProjectManager):
    """Return the active project or exit with a clear error."""
    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")
    return project


def _resolve_group(db_path: Path, project_id: str, name_or_id: str) -> dict:
    """
    Purpose:
        Resolve a group by name first, then by UUID.
    Raises:
        SystemExit(1) if the group cannot be found.
    """
    group = findings_db.get_group_by_name(db_path, project_id, name_or_id)
    if group is None:
        group = findings_db.get_group(db_path, name_or_id)
    if group is None:
        cli_error(f"Group '{name_or_id}' not found.")
    return group


def _require_finding(db_path: Path, finding_id: str) -> dict:
    """
    Purpose:
        Fetch a finding by UUID or exit with an error.
    Raises:
        SystemExit(1) if not found.
    """
    finding = findings_db.get_finding(db_path, finding_id)
    if finding is None:
        cli_error(f"Finding '{finding_id}' not found.")
    return finding


def _short(uid: str) -> str:
    """Return the first 8 characters of a UUID for display."""
    return uid[:8] if uid else "?"


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

def run_finding_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse finding subcommands and dispatch to the appropriate handler.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'finding'.
    Side effects:
        May write to DB, print to stdout/stderr, or call sys.exit().
    """
    if not argv or argv[0] in ("--help", "-h"):
        _print_finding_usage()
        sys.exit(0)

    subcommand = argv[0]
    rest = argv[1:]

    if subcommand == "list":
        _cmd_list(manager, rest)
    elif subcommand == "show":
        _cmd_show(manager, rest)
    elif subcommand == "confirm":
        _cmd_confirm(manager, rest)
    elif subcommand == "reject":
        _cmd_reject(manager, rest)
    elif subcommand == "reopen":
        _cmd_reopen(manager, rest)
    elif subcommand == "duplicate":
        _cmd_duplicate(manager, rest)
    elif subcommand == "note":
        _cmd_note(manager, rest)
    elif subcommand == "group":
        _cmd_group(manager, rest)
    elif subcommand == "report":
        _cmd_report(manager, rest)
    else:
        cli_error(f"Unknown finding subcommand '{subcommand}'.", exit_code=None)
        _print_finding_usage()
        sys.exit(EXIT_USAGE)


# ------------------------------------------------------------------ #
# finding list                                                         #
# ------------------------------------------------------------------ #

def _cmd_list(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage:
        talos finding list [--status STATUS]
        talos finding list --linked [--status STATUS]
        talos finding list --all [--status STATUS]

    Default relation filter is PRIMARY (main findings page).
    """
    parser = argparse.ArgumentParser(prog="talos finding list", add_help=True)
    parser.add_argument(
        "--status",
        choices=list(FINDING_STATUSES),
        default=None,
        help="Filter by status (TRIAGING, CONFIRMED, REJECTED, DUPLICATE).",
    )
    relation_group = parser.add_mutually_exclusive_group()
    relation_group.add_argument(
        "--linked",
        action="store_true",
        help="Show LINKED findings only.",
    )
    relation_group.add_argument(
        "--all",
        action="store_true",
        dest="show_all",
        help="Show PRIMARY and LINKED findings.",
    )
    add_format_argument(parser)
    args = parser.parse_args(argv)
    project = _require_active(manager)
    db_path = project.db_path

    if args.show_all:
        relation_type = None
        relation_label = " (all relations)"
    elif args.linked:
        relation_type = RELATION_TYPE_LINKED
        relation_label = " (LINKED only)"
    else:
        relation_type = RELATION_TYPE_PRIMARY
        relation_label = " (PRIMARY only)"

    findings = findings_db.list_findings(
        db_path, project.id, status=args.status, relation_type=relation_type
    )
    if wants_json(args):
        cli_json(findings)
        return

    if not findings:
        status_label = f" with status {args.status}" if args.status else ""
        print(f"No findings{status_label}{relation_label}.")
        return

    header = (
        f"{'UUID':38}  {'STATUS':10}  {'REL':7}  {'LINKED':6}  "
        f"{'ATTACK':12}  {'VERDICT':15}  {'MODULE':14}  {'ROLE':12}  TITLE"
    )
    print(header)
    print("-" * len(header))
    for f in findings:
        attack_label = ATTACK_DISPLAY.get(f["attack_type"], f["attack_type"])[:12]
        title = (f["title"] or "")[:50]
        evidence = findings_db.list_evidence(db_path, f["id"])
        module_ev = _find_evidence(evidence, "module")
        role_ev = _find_evidence(evidence, "role")
        module_label = (module_ev["label"].split(": ", 1)[-1][:14] if module_ev else "—")
        role_label = (role_ev["label"].split(": ", 1)[-1][:12] if role_ev else "—")
        rel = (f.get("relation_type") or RELATION_TYPE_PRIMARY)[:7]
        linked_count = f.get("linked_count", 0)
        linked_str = str(linked_count) if rel == RELATION_TYPE_PRIMARY else "—"
        print(
            f"{f['id']:38}  {f['status']:10}  {rel:7}  {linked_str:6}  "
            f"{attack_label:12}  {f['verdict']:15}  "
            f"{module_label:14}  {role_label:12}  {title}"
        )


# ------------------------------------------------------------------ #
# finding show                                                         #
# ------------------------------------------------------------------ #

def _cmd_show(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage: talos finding show <uuid> [--format table|json]
    """
    if not argv:
        cli_usage_error("Finding show requires a UUID.")

    parser = argparse.ArgumentParser(prog="talos finding show", add_help=True)
    parser.add_argument("finding_id", help="Finding UUID.")
    add_format_argument(parser)
    args = parser.parse_args(argv)

    project = _require_active(manager)
    db_path = project.db_path
    finding = _require_finding(db_path, args.finding_id)

    attack_label = ATTACK_DISPLAY.get(finding["attack_type"], finding["attack_type"].upper())
    relation = finding.get("relation_type") or RELATION_TYPE_PRIMARY
    linked = (
        findings_db.list_linked_findings(db_path, finding["id"])
        if relation == RELATION_TYPE_PRIMARY
        else []
    )
    duplicates = findings_db.list_duplicates_of(db_path, finding["id"])
    evidence = findings_db.list_evidence(db_path, finding["id"])
    timeline = findings_db.list_timeline(db_path, finding["id"])

    if wants_json(args):
        cli_json({
            "finding": finding,
            "linked_findings": linked,
            "duplicates": duplicates,
            "evidence": evidence,
            "timeline": timeline,
        })
        return

    print(f"Finding: {finding['id']}")
    print(f"  Title:       {finding['title']}")
    print(f"  Status:      {finding['status']}")
    print(f"  Relation:    {relation}")
    if relation == RELATION_TYPE_LINKED and finding.get("parent_finding_id"):
        parent = findings_db.get_finding(db_path, finding["parent_finding_id"])
        parent_status = parent["status"] if parent else "?"
        print(f"  Primary:     {finding['parent_finding_id']}  ({parent_status})")
    if finding.get("cluster_key"):
        print(f"  Cluster:     {finding['cluster_key']}")
    print(f"  Attack:      {attack_label}")
    print(f"  Verdict:     {finding['verdict']}")
    print(f"  Endpoint:    {finding.get('endpoint_id') or '—'}")
    print(f"  Created:     {finding['created_at']}")
    print(f"  Updated:     {finding['updated_at']}")
    if finding["status"] == FINDING_STATUS_DUPLICATE and finding.get("duplicate_of"):
        print(f"  Duplicate of: {finding['duplicate_of']}")

    if relation == RELATION_TYPE_PRIMARY:
        if linked:
            print(f"  Linked findings ({len(linked)}):")
            for lf in linked:
                print(
                    f"    {lf['id']}  {lf['status']:10}  "
                    f"{(lf.get('title') or '')[:50]}"
                )
        else:
            print("  Linked findings: none")

    if duplicates:
        print(f"  Duplicates ({len(duplicates)}):")
        for d in duplicates:
            print(f"    {d['id']}")

    module_ev = _find_evidence(evidence, "module")
    role_ev = _find_evidence(evidence, "role")
    if module_ev or role_ev:
        print()
        if module_ev:
            print(f"  Module:      {module_ev['label'].split(': ', 1)[-1]}  ({module_ev.get('reference_id') or '—'})")
        if role_ev:
            print(f"  Role:        {role_ev['label'].split(': ', 1)[-1]}  ({role_ev.get('reference_id') or '—'})")

    if evidence:
        print(f"\n  Evidence ({len(evidence)} items):")
        for ev in evidence:
            ref = ev.get("reference_id") or "—"
            print(f"    [{ev['evidence_type']:28}] {ev['label'][:60]}  ref={ref}")

    if timeline:
        print(f"\n  Timeline ({len(timeline)} events):")
        for ev in timeline:
            print(f"    {ev['created_at']}  [{ev['actor']}]  {ev['event']}")

    _print_flow_comparison(db_path, evidence)

    if finding.get("notes", "").strip():
        print(f"\n  Notes:\n    {finding['notes']}")


def _find_evidence(evidence: list[dict], evidence_type: str) -> Optional[dict]:
    """Return the first evidence item of the given type, or None."""
    for ev in evidence:
        if ev["evidence_type"] == evidence_type:
            return ev
    return None


def _fetch_flow_row(db_path: Path, flow_id: str) -> Optional[dict]:
    """Purpose: Fetch a flow's key display fields for the original-vs-attack comparison."""
    import sqlite3
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT method, url, status_code, content_type, response_body "
            "FROM flows WHERE id = ?",
            (flow_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _print_flow_comparison(db_path: Path, evidence: list[dict]) -> None:
    """
    Purpose:
        Print a side-by-side Original Flow vs Attack Replay Flow comparison
        (method/URL/status/body length) plus the replay diff verdict, so
        'finding show' answers "what changed" without needing the full report.
    """
    orig_ev = _find_evidence(evidence, "original_flow")
    replay_ev = _find_evidence(evidence, "replay_flow")
    if not orig_ev and not replay_ev:
        return

    orig = _fetch_flow_row(db_path, orig_ev["reference_id"]) if orig_ev and orig_ev.get("reference_id") else None
    replay = _fetch_flow_row(db_path, replay_ev["reference_id"]) if replay_ev and replay_ev.get("reference_id") else None
    if not orig and not replay:
        return

    print("\n  Original Flow vs. Attack Replay Flow:")

    def _body_len(row: Optional[dict]) -> int:
        if not row:
            return 0
        body = row.get("response_body")
        if body is None:
            return 0
        return len(body) if isinstance(body, (bytes, str)) else 0

    if orig:
        print(f"    Original : {orig.get('method', '?')} {orig.get('url', '?')}")
        print(f"               status={orig.get('status_code', '?')}  body_len={_body_len(orig)}  id={orig_ev.get('reference_id')}")
    else:
        print("    Original : (not available)")

    if replay:
        print(f"    Attack   : {replay.get('method', '?')} {replay.get('url', '?')}")
        print(f"               status={replay.get('status_code', '?')}  body_len={_body_len(replay)}  id={replay_ev.get('reference_id')}")
    else:
        print("    Attack   : (not available)")

    if orig and replay:
        status_changed = orig.get("status_code") != replay.get("status_code")
        len_delta = _body_len(replay) - _body_len(orig)
        print(f"    Delta    : status {'changed' if status_changed else 'unchanged'} "
              f"({orig.get('status_code', '?')} → {replay.get('status_code', '?')}), "
              f"body length delta {len_delta:+d} bytes")


# ------------------------------------------------------------------ #
# finding confirm / reject / reopen                                    #
# ------------------------------------------------------------------ #

def _parse_status_args(argv: list[str], command: str) -> argparse.Namespace:
    """Parse <uuid> [--linked] [--force] for confirm / reject / reopen."""
    parser = argparse.ArgumentParser(prog=f"talos finding {command}", add_help=True)
    parser.add_argument("finding_id", help="UUID of the finding.")
    parser.add_argument(
        "--linked",
        action="store_true",
        help=(
            "Also update all currently LINKED findings under this PRIMARY. "
            "Only valid on a PRIMARY finding. One-time bulk op — no inheritance."
        ),
    )
    add_force_argument(
        parser,
        help="Skip confirmation when --linked would overwrite mixed statuses.",
    )
    return parser.parse_args(argv)


def _cmd_confirm(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding confirm <uuid> [--linked] [--force]"""
    args = _parse_status_args(argv, "confirm")
    _change_status(
        manager, args.finding_id, FINDING_STATUS_CONFIRMED, "confirmed",
        include_linked=args.linked, force=args.force,
    )


def _cmd_reject(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding reject <uuid> [--linked] [--force]"""
    args = _parse_status_args(argv, "reject")
    _change_status(
        manager, args.finding_id, FINDING_STATUS_REJECTED, "rejected",
        include_linked=args.linked, force=args.force,
    )


def _cmd_reopen(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding reopen <uuid> [--linked] [--force]"""
    args = _parse_status_args(argv, "reopen")
    project = _require_active(manager)
    db_path = project.db_path
    finding = _require_finding(db_path, args.finding_id)

    if args.linked:
        _bulk_status_change(
            db_path, finding, FINDING_STATUS_TRIAGING, "reopened",
            force=args.force,
        )
        return

    current = finding["status"]
    if current == FINDING_STATUS_TRIAGING:
        print(f"Finding {_short(args.finding_id)} is already TRIAGING.")
        return

    ok = findings_db.update_finding_status(
        db_path, args.finding_id, FINDING_STATUS_TRIAGING, duplicate_of=None
    )
    if not ok:
        cli_error(f"Could not update finding '{args.finding_id}'.")

    findings_db.add_timeline_event(
        db_path, args.finding_id,
        f"Status changed from {current} → TRIAGING",
        actor=TIMELINE_ACTOR_ANALYST,
    )
    print(f"Finding {_short(args.finding_id)} reopened → TRIAGING.")


def _change_status(
    manager: ProjectManager,
    finding_id: str,
    new_status: str,
    label: str,
    *,
    include_linked: bool = False,
    force: bool = False,
) -> None:
    project = _require_active(manager)
    db_path = project.db_path
    finding = _require_finding(db_path, finding_id)

    if include_linked:
        _bulk_status_change(
            db_path, finding, new_status, label, force=force,
        )
        return

    old = finding["status"]
    if old == new_status:
        print(f"Finding {_short(finding_id)} is already {new_status}.")
        return

    ok = findings_db.update_finding_status(db_path, finding_id, new_status)
    if not ok:
        cli_error(f"Could not update finding '{finding_id}'.")

    findings_db.add_timeline_event(
        db_path, finding_id,
        f"Status changed from {old} → {new_status}",
        actor=TIMELINE_ACTOR_ANALYST,
    )
    print(f"Finding {_short(finding_id)} {label} ({new_status}).")


def _bulk_status_change(
    db_path: Path,
    primary: dict,
    new_status: str,
    label: str,
    *,
    force: bool = False,
) -> None:
    """
    Purpose:
        Apply new_status to a PRIMARY finding and all currently LINKED children.
        Refuses --linked on a LINKED finding (no auto parent resolve).
        Prompts for confirmation when statuses are mixed, unless force=True.
        Writes a timeline event on every affected finding.
    """
    relation = primary.get("relation_type") or RELATION_TYPE_PRIMARY
    if relation != RELATION_TYPE_PRIMARY:
        parent = primary.get("parent_finding_id") or "?"
        cli_error(
            f"--linked can only be used with a PRIMARY finding.\n"
            f"{primary['id']} is linked to {parent}."
        )

    linked = findings_db.list_linked_findings(db_path, primary["id"])
    targets = [primary, *linked]
    status_counts = Counter(f["status"] for f in targets)
    total = len(targets)

    if not force:
        print(f"This will update {total} finding{'s' if total != 1 else ''}:\n")
        for st, cnt in sorted(status_counts.items()):
            print(f"  {st}: {cnt}")
        print()
        changing = {
            st: cnt for st, cnt in status_counts.items() if st != new_status
        }
        if changing:
            for st, cnt in sorted(changing.items()):
                print(
                    f"  {cnt} {st} finding{'s' if cnt != 1 else ''} "
                    f"will be changed to {new_status}."
                )
            print()
        confirm_or_exit("Continue?")

    linked_count = len(linked)
    for f in targets:
        old = f["status"]
        if old == new_status and f["id"] != primary["id"]:
            # Still record timeline for bulk visibility? Spec says each
            # affected finding receives its own timeline event for status
            # changes. Skip if already at target to avoid noise.
            continue
        ok = findings_db.update_finding_status(
            db_path, f["id"], new_status, duplicate_of=None
        )
        if not ok:
            cli_error(f"Could not update finding '{f['id']}'.")

        if f["id"] == primary["id"]:
            event = (
                f"Status changed from {old} → {new_status}"
                + (
                    f"\nBulk linked status operation affected "
                    f"{linked_count} linked finding"
                    f"{'s' if linked_count != 1 else ''}"
                    if linked_count
                    else "\nBulk linked status operation (no linked findings)"
                )
            )
        else:
            event = (
                f"Status changed from {old} → {new_status}\n"
                f"Changed through linked bulk operation from {primary['id']}"
            )
        findings_db.add_timeline_event(
            db_path, f["id"], event, actor=TIMELINE_ACTOR_ANALYST,
        )

    print(
        f"Finding {_short(primary['id'])} {label} ({new_status}) "
        f"with {linked_count} linked finding{'s' if linked_count != 1 else ''}."
    )


# ------------------------------------------------------------------ #
# finding duplicate                                                    #
# ------------------------------------------------------------------ #

def _cmd_duplicate(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage: talos finding duplicate <uuid> --of <canonical-uuid>
    """
    parser = argparse.ArgumentParser(prog="talos finding duplicate", add_help=True)
    parser.add_argument("finding_id", help="UUID of the finding to mark as duplicate.")
    parser.add_argument("--of", required=True, dest="canonical_id",
                        help="UUID of the canonical finding this is a duplicate of.")
    args = parser.parse_args(argv)

    project = _require_active(manager)
    db_path = project.db_path

    _require_finding(db_path, args.finding_id)
    _require_finding(db_path, args.canonical_id)

    old_status = findings_db.get_finding(db_path, args.finding_id)["status"]
    ok = findings_db.update_finding_status(
        db_path, args.finding_id, FINDING_STATUS_DUPLICATE,
        duplicate_of=args.canonical_id,
    )
    if not ok:
        cli_error(f"Could not update finding '{args.finding_id}'.")

    findings_db.add_timeline_event(
        db_path, args.finding_id,
        f"Status changed from {old_status} → DUPLICATE of {args.canonical_id}",
        actor=TIMELINE_ACTOR_ANALYST,
    )
    print(
        f"Finding {_short(args.finding_id)} marked as DUPLICATE of "
        f"{_short(args.canonical_id)}."
    )


# ------------------------------------------------------------------ #
# finding group                                                        #
# ------------------------------------------------------------------ #

def _cmd_group(manager: ProjectManager, argv: list[str]) -> None:
    """Dispatch to group subcommands."""
    if not argv or argv[0] in ("--help", "-h"):
        _print_group_usage()
        sys.exit(0)

    sub = argv[0]
    rest = argv[1:]

    if sub == "create":
        _cmd_group_create(manager, rest)
    elif sub == "add":
        _cmd_group_add(manager, rest)
    elif sub == "remove":
        _cmd_group_remove(manager, rest)
    elif sub == "list":
        _cmd_group_list(manager, rest)
    else:
        cli_error(f"Unknown group subcommand '{sub}'.", exit_code=None)
        _print_group_usage()
        sys.exit(EXIT_USAGE)


def _cmd_group_create(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding group create "<name>" """
    if not argv:
        cli_usage_error("Group create requires a name.")
    name = " ".join(argv).strip()
    project = _require_active(manager)
    db_path = project.db_path

    import sqlite3 as _sqlite3
    try:
        gid = findings_db.create_group(db_path, project.id, name)
    except _sqlite3.IntegrityError:
        cli_error(f"A group named '{name}' already exists.")

    print(f"Group created: '{name}'  ({gid})")


def _cmd_group_add(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding group add <group> <finding>"""
    if len(argv) < 2:
        cli_usage_error("Group add requires <group> and <finding>.")
    project = _require_active(manager)
    db_path = project.db_path

    group = _resolve_group(db_path, project.id, argv[0])
    _require_finding(db_path, argv[1])

    added = findings_db.add_to_group(db_path, group["id"], argv[1])
    if added:
        print(
            f"Finding {_short(argv[1])} added to group '{group['name']}'."
        )
    else:
        print(
            f"Finding {_short(argv[1])} is already in group '{group['name']}'."
        )


def _cmd_group_remove(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage:
        talos finding group remove <group> <finding>   — remove one finding from group
        talos finding group remove <group>             — delete the group itself
            [--remove-findings]                        — also delete member findings
            [--force]                                  — skip confirmation (required non-interactive)
    """
    if not argv:
        cli_usage_error("Group remove requires at least a group name/id.")

    project = _require_active(manager)
    db_path = project.db_path

    # Determine if this is a group-only delete or a member-remove command.
    # Heuristic: if only 1 positional arg OR last arg is a flag, this is group delete.
    # Otherwise, 2 positional args = group + finding.
    positional = [a for a in argv if not a.startswith("--")]
    flags = [a for a in argv if a.startswith("--")]
    remove_findings_flag = "--remove-findings" in flags
    force = "--force" in flags

    if len(positional) >= 2:
        # Remove one finding from a group.
        group = _resolve_group(db_path, project.id, positional[0])
        finding_id = positional[1]
        _require_finding(db_path, finding_id)
        removed = findings_db.remove_from_group(db_path, group["id"], finding_id)
        if removed:
            print(f"Finding {_short(finding_id)} removed from group '{group['name']}'.")
        else:
            cli_error(f"Finding {_short(finding_id)} was not in group '{group['name']}'.")
        return

    # Delete the group itself.
    group = _resolve_group(db_path, project.id, positional[0])

    if remove_findings_flag:
        members = findings_db.list_group_findings(db_path, group["id"])
        if members:
            confirm_or_exit(
                f"Delete group '{group['name']}' and {len(members)} finding(s)?",
                force=force,
            )
        deleted = findings_db.delete_group(db_path, group["id"], remove_findings=True)
        print(
            f"Group '{group['name']}' deleted along with {deleted} finding(s)."
        )
    else:
        confirm_or_exit(
            f"Delete group '{group['name']}' (findings preserved)?",
            force=force,
        )
        findings_db.delete_group(db_path, group["id"], remove_findings=False)
        print(f"Group '{group['name']}' deleted (findings preserved).")


def _cmd_group_list(manager: ProjectManager, argv: list[str]) -> None:
    """Usage: talos finding group list [--format table|json]"""
    parser = argparse.ArgumentParser(prog="talos finding group list", add_help=True)
    add_format_argument(parser)
    args = parser.parse_args(argv)

    project = _require_active(manager)
    groups = findings_db.list_groups(project.db_path, project.id)
    if wants_json(args):
        cli_json(groups)
        return
    if not groups:
        print("No finding groups.")
        return
    header = f"{'UUID':38}  {'MEMBERS':7}  NAME"
    print(header)
    print("-" * len(header))
    for g in groups:
        print(f"{g['id']:38}  {g['member_count']:7}  {g['name']}")


# ------------------------------------------------------------------ #
# finding note set | clear                                             #
# ------------------------------------------------------------------ #

def _read_notes_stdin() -> str:
    """
    Purpose:
        Read free-form notes from stdin (pipe or interactive Ctrl-D).
    Output:
        Notes text with a single trailing newline stripped.
    Side effects:
        Prints a prompt to stderr when stdin is a TTY.
    """
    if sys.stdin.isatty():
        print(
            "Enter notes (end with Ctrl-D on empty line):",
            file=sys.stderr,
        )
    text = sys.stdin.read()
    if text.endswith("\n"):
        text = text[:-1]
    return text


def _cmd_note(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage:
        talos finding note set <uuid>     # notes from stdin
        talos finding note clear <uuid>
    """
    def _print_note_usage(stream=sys.stdout) -> None:
        print(
            "Usage:\n"
            "  talos finding note set <uuid>    Set notes (read from stdin)\n"
            "  talos finding note clear <uuid>  Clear notes",
            file=stream,
        )

    if not argv:
        _print_note_usage(sys.stderr)
        sys.exit(1)
    if argv[0] in ("--help", "-h"):
        _print_note_usage(sys.stdout)
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]

    if action not in ("set", "clear"):
        cli_error(f"Unknown note action '{action}'. Use set or clear.", exit_code=None)
        _print_note_usage(sys.stderr)
        sys.exit(EXIT_USAGE)

    if not rest:
        cli_usage_error(f"Finding note {action} requires a finding UUID.")

    project = _require_active(manager)
    db_path = project.db_path
    finding_id = rest[0]
    _require_finding(db_path, finding_id)

    if action == "set":
        notes = _read_notes_stdin()
        if not notes.strip():
            cli_error(
            "Notes text is empty. "
            "Pipe text or type notes, or use 'talos finding note clear'."
        )
        ok = findings_db.update_finding_notes(db_path, finding_id, notes)
        if not ok:
            cli_error(f"Could not update finding '{finding_id}'.")
        findings_db.add_timeline_event(
            db_path,
            finding_id,
            "Analyst notes updated",
            actor=TIMELINE_ACTOR_ANALYST,
        )
        print(f"Notes set on finding {_short(finding_id)}.")
        return

    ok = findings_db.update_finding_notes(db_path, finding_id, "")
    if not ok:
        cli_error(f"Could not update finding '{finding_id}'.")
    findings_db.add_timeline_event(
        db_path,
        finding_id,
        "Analyst notes cleared",
        actor=TIMELINE_ACTOR_ANALYST,
    )
    print(f"Notes cleared on finding {_short(finding_id)}.")


# ------------------------------------------------------------------ #
# finding report                                                       #
# ------------------------------------------------------------------ #

def _cmd_report(manager: ProjectManager, argv: list[str]) -> None:
    """
    Usage:
        talos finding report <uuid>
        talos finding report --group <name-or-uuid>
    """
    parser = argparse.ArgumentParser(prog="talos finding report", add_help=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("finding_id", nargs="?", help="UUID of the finding.")
    group.add_argument("--group", dest="group_ref", default=None,
                       help="Group name or UUID; produces a combined group report.")
    args = parser.parse_args(argv)

    project = _require_active(manager)
    db_path = project.db_path

    if args.group_ref:
        grp = _resolve_group(db_path, project.id, args.group_ref)
        try:
            report = generate_group_report(db_path, grp["id"])
        except ValueError as exc:
            cli_error(str(exc))
    else:
        if not args.finding_id:
            cli_usage_error("Provide a finding UUID or --group.")
        try:
            report = generate_finding_report(db_path, args.finding_id)
        except ValueError as exc:
            cli_error(str(exc))

    print(report)


# ------------------------------------------------------------------ #
# Usage strings                                                        #
# ------------------------------------------------------------------ #

def _print_finding_usage() -> None:
    print(
        "Usage: talos finding <subcommand> [args]\n\n"
        "Subcommands:\n"
        "  list                           List PRIMARY findings (default)\n"
        "  list --linked                  List LINKED findings only\n"
        "  list --all                     List PRIMARY and LINKED findings\n"
        "  list [--status STATUS]         Filter by lifecycle status\n"
        "  show <uuid>                    Show finding detail, evidence, and timeline\n"
        "  confirm <uuid>                 Mark finding as CONFIRMED\n"
        "  reject <uuid>                  Mark finding as REJECTED\n"
        "  reopen <uuid>                  Revert CONFIRMED/REJECTED/DUPLICATE → TRIAGING\n"
        "  confirm|reject|reopen <uuid> --linked [--force]\n"
        "                                 Bulk status change on PRIMARY + all currently\n"
        "                                 linked findings (PRIMARY only; one-time op)\n"
        "  duplicate <uuid> --of <uuid>   Mark finding as DUPLICATE of another\n"
        "  note set <uuid>                Set free-form analyst notes (stdin)\n"
        "  note clear <uuid>              Clear analyst notes\n"
        "  group create '<name>'          Create a new finding group\n"
        "  group add <group> <finding>    Add a finding to a group\n"
        "  group remove <group> <finding> Remove a finding from a group\n"
        "  group remove <group> [--remove-findings] [--force]\n"
        "                                 Delete a group (confirm; --force skips)\n"
        "  group list                     List all groups with member counts\n"
        "  report <uuid>                  Generate Markdown vulnerability report\n"
        "  report --group <group>         Generate combined group report\n"
    )


def _print_group_usage() -> None:
    print(
        "Usage: talos finding group <subcommand>\n\n"
        "Subcommands:\n"
        "  create '<name>'          Create a named group\n"
        "  add <group> <finding>    Add finding to group\n"
        "  remove <group> <finding> Remove finding from group\n"
        "  remove <group> [--remove-findings] [--force]\n"
        "                           Delete group (confirm; --force skips)\n"
        "  list                     List all groups\n"
    )
