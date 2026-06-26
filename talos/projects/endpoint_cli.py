"""
Module: talos.projects.endpoint_cli

Purpose:
    Command-line interface for endpoint annotation management and the
    Endpoint Policy system.

    Subcommands:
        talos endpoint mark   <endpoint_id> (--logout | --dangerous | --safe)
        talos endpoint unmark <endpoint_id> (--logout | --dangerous)
        talos endpoint show   <endpoint_id>

        talos endpoint priority set endpoint <endpoint_id> <level>
        talos endpoint priority set path     "<pattern>"   <level>
        talos endpoint priority clear endpoint <endpoint_id>
        talos endpoint priority clear path     "<pattern>"

        talos endpoint exclude endpoint <endpoint_id>
        talos endpoint exclude path     "<pattern>"
        talos endpoint include endpoint <endpoint_id>
        talos endpoint include path     "<pattern>"

        talos endpoint rules list

    Safety annotation semantics (mark/unmark):
        logout    — never replay (any mode — manual or auto).
        dangerous — skip in automated replay; manual replay is still allowed.
        safe      — (--mark --safe only) clears both tags; restores default.

    Priority semantics:
        manual_priority always overrides auto_priority.
        Valid levels: CRITICAL | HIGH | NORMAL | LOW

    Exclusion semantics:
        excluded endpoints are never returned for attack candidate generation
        regardless of their priority.

    (Original mark/unmark subcommands are preserved for backward compatibility)

Dependencies: argparse, sys, talos.projects.manager, talos.projects.annotations,
              talos.projects.policy, talos.projects.policy_score, talos.replay.db
Data flow:
    CLI args → active project DB → annotations / policy modules → stdout
Side effects:
    - mark/unmark write to endpoint_policy (via annotations module).
    - priority/exclude/include write to endpoint_policy or policy_rules.
    - show and rules list are read-only.
    - All commands require an active project.
    - Exits 1 if no active project or endpoint not found.
"""

import argparse
import sys

from talos.projects.manager import ProjectManager
import talos.projects.annotations as annotations_mod
import talos.projects.policy as policy_mod
from talos.projects.policy_score import format_score_breakdown
import talos.replay.db as replay_db


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_endpoint_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse endpoint subcommand arguments and dispatch to the handler.
    Input:
        manager — ProjectManager instance carrying the projects root path.
        argv    — argument list after 'endpoint'.
    Side effects:
        Dispatches to command handlers.
        Prints usage and exits 1 for unrecognised subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos endpoint",
        description="Manage endpoint safety annotations and policy.",
    )
    sub = parser.add_subparsers(dest="endpoint_cmd", metavar="<command>")
    sub.required = True

    # talos endpoint mark <id> (--logout | --dangerous | --safe)
    p_mark = sub.add_parser(
        "mark",
        help="Add a safety annotation to an endpoint.",
    )
    p_mark.add_argument("endpoint_id", help="UUID of the endpoint to annotate.")
    group_mark = p_mark.add_mutually_exclusive_group(required=True)
    group_mark.add_argument(
        "--logout",
        action="store_true",
        help="Tag as logout endpoint — never replayed in any mode.",
    )
    group_mark.add_argument(
        "--dangerous",
        action="store_true",
        help="Tag as dangerous — skipped in automated replay; manual is still allowed.",
    )
    group_mark.add_argument(
        "--safe",
        action="store_true",
        help="Clear all annotations — restore default safe state.",
    )

    # talos endpoint unmark <id> (--logout | --dangerous)
    p_unmark = sub.add_parser(
        "unmark",
        help="Remove an annotation tag from an endpoint.",
    )
    p_unmark.add_argument("endpoint_id", help="UUID of the endpoint.")
    group_unmark = p_unmark.add_mutually_exclusive_group(required=True)
    group_unmark.add_argument(
        "--logout",
        action="store_true",
        help="Remove the logout tag.",
    )
    group_unmark.add_argument(
        "--dangerous",
        action="store_true",
        help="Remove the dangerous tag.",
    )

    # talos endpoint show <id>
    p_show = sub.add_parser(
        "show",
        help="Display endpoint details, annotations, and policy.",
    )
    p_show.add_argument("endpoint_id", help="UUID of the endpoint to display.")

    # talos endpoint priority set/clear endpoint/path ...
    p_priority = sub.add_parser(
        "priority",
        help="Set or clear manual priority overrides.",
    )
    _build_priority_parser(p_priority)

    # talos endpoint exclude endpoint/path ...
    p_exclude = sub.add_parser(
        "exclude",
        help="Exclude an endpoint or path pattern from candidate generation.",
    )
    _build_target_parser(p_exclude)

    # talos endpoint include endpoint/path ...
    p_include = sub.add_parser(
        "include",
        help="Re-include a previously excluded endpoint or path pattern.",
    )
    _build_target_parser(p_include)

    # talos endpoint rules list
    sub.add_parser(
        "rules",
        help="List all active path-based policy rules.",
    )

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    cmd = args.endpoint_cmd
    if cmd == "mark":
        cmd_endpoint_mark(project, args)
    elif cmd == "unmark":
        cmd_endpoint_unmark(project, args)
    elif cmd == "show":
        cmd_endpoint_show(project, args)
    elif cmd == "priority":
        cmd_priority(project, args)
    elif cmd == "exclude":
        cmd_exclude(project, args)
    elif cmd == "include":
        cmd_include(project, args)
    elif cmd == "rules":
        cmd_rules_list(project, args)


# ------------------------------------------------------------------ #
# Parser helpers for new subcommands                                   #
# ------------------------------------------------------------------ #

def _build_priority_parser(parser: argparse.ArgumentParser) -> None:
    """
    Purpose:
        Add 'set' and 'clear' subcommands to the priority parser.
    Input:
        parser — ArgumentParser for the 'priority' subcommand.
    Side effects:
        Mutates parser in-place.
    """
    sub = parser.add_subparsers(dest="priority_cmd", metavar="<set|clear>")
    sub.required = True

    p_set = sub.add_parser("set", help="Set manual priority on an endpoint or path.")
    set_target = p_set.add_subparsers(dest="priority_target", metavar="<endpoint|path>")
    set_target.required = True

    p_set_ep = set_target.add_parser("endpoint", help="Set priority on a specific endpoint.")
    p_set_ep.add_argument("endpoint_id", help="UUID of the endpoint.")
    p_set_ep.add_argument(
        "level",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Priority level (CRITICAL|HIGH|NORMAL|LOW).",
    )

    p_set_path = set_target.add_parser(
        "path", help="Set priority on all matching path endpoints."
    )
    p_set_path.add_argument("pattern", help="Path glob pattern (e.g. /api/admin/*).")
    p_set_path.add_argument(
        "level",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Priority level (CRITICAL|HIGH|NORMAL|LOW).",
    )

    p_clear = sub.add_parser(
        "clear",
        help="Remove a manual priority override from an endpoint or path rule.",
    )
    clear_target = p_clear.add_subparsers(dest="priority_target", metavar="<endpoint|path>")
    clear_target.required = True

    p_clear_ep = clear_target.add_parser(
        "endpoint", help="Clear manual priority from a specific endpoint."
    )
    p_clear_ep.add_argument("endpoint_id", help="UUID of the endpoint.")

    p_clear_path = clear_target.add_parser(
        "path", help="Remove a path priority rule entirely."
    )
    p_clear_path.add_argument("pattern", help="Path glob pattern to remove.")


def _build_target_parser(parser: argparse.ArgumentParser) -> None:
    """
    Purpose:
        Add 'endpoint' and 'path' subcommands for exclude/include.
    Input:
        parser — ArgumentParser for the 'exclude' or 'include' subcommand.
    Side effects:
        Mutates parser in-place.
    """
    sub = parser.add_subparsers(dest="excl_target", metavar="<endpoint|path>")
    sub.required = True

    p_ep = sub.add_parser("endpoint", help="Target a specific endpoint.")
    p_ep.add_argument("endpoint_id", help="UUID of the endpoint.")

    p_path = sub.add_parser("path", help="Target all endpoints matching a path pattern.")
    p_path.add_argument("pattern", help="Path glob pattern (e.g. /static/*).")


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_endpoint_mark(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set a safety flag on an endpoint, or clear all flags (--safe).
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str), logout/dangerous/safe (bool).
    Side effects:
        Writes to endpoint_policy (dangerous/logout columns) via annotations module.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"

    if args.safe:
        annotations_mod.clear_annotations(db_path, endpoint_id)
        print(f"Cleared all annotations on {ep_label}")
    elif args.logout:
        annotations_mod.add_annotation(db_path, endpoint_id, "logout")
        print(f"Marked {ep_label} as logout")
    elif args.dangerous:
        annotations_mod.add_annotation(db_path, endpoint_id, "dangerous")
        print(f"Marked {ep_label} as dangerous")


def cmd_endpoint_unmark(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Clear a specific safety flag from an endpoint.
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str), logout/dangerous (bool).
    Side effects:
        Clears the flag in endpoint_policy. No-op if already clear.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"

    if args.logout:
        annotations_mod.remove_annotation(db_path, endpoint_id, "logout")
        print(f"Removed logout annotation from {ep_label}")
    elif args.dangerous:
        annotations_mod.remove_annotation(db_path, endpoint_id, "dangerous")
        print(f"Removed dangerous annotation from {ep_label}")


def cmd_endpoint_show(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Display the endpoint record and its full unified policy (priority,
        exclusion, dangerous, logout, score breakdown, notes, tags).
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str).
    Side effects:
        Reads endpoint and policy from DB; prints to stdout.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"

    policy = policy_mod.get_effective_policy(
        db_path=db_path,
        project_id=project_id,
        endpoint_id=endpoint_id,
        normalized_path=endpoint["normalized_path"],
    )

    excl_str      = "YES" if policy.excluded   else "no"
    dangerous_str = "YES" if policy.dangerous  else "no"
    logout_str    = "YES" if policy.logout     else "no"
    manual_str    = policy.manual_priority or "—"
    source_str    = policy.source
    if policy.matching_rule:
        source_str += f" (rule: {policy.matching_rule})"

    breakdown_str = format_score_breakdown(
        score=policy.auto_score,
        level=policy.effective_level,
        contributors=policy.auto_breakdown,
    )

    notes_str = policy.notes or "—"
    tags_policy_str = ", ".join(policy.tags) if policy.tags else "—"

    print(
        f"Endpoint  : {endpoint_id}\n"
        f"  {ep_label}\n\n"
        f"--- Endpoint Policy ---\n"
        f"  Effective Priority : {policy.effective_level}  (source: {source_str})\n"
        f"  Manual Override    : {manual_str}\n"
        f"  Excluded           : {excl_str}\n"
        f"  Dangerous          : {dangerous_str}\n"
        f"  Logout             : {logout_str}\n"
        f"{breakdown_str}\n"
        f"  Notes : {notes_str}\n"
        f"  Tags  : {tags_policy_str}"
    )


# ------------------------------------------------------------------ #
# Priority command handler                                             #
# ------------------------------------------------------------------ #

def cmd_priority(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Handle 'talos endpoint priority set/clear endpoint/path ...' commands.
    Input:
        project — active Project instance.
        args    — parsed args (priority_cmd, priority_target, target-specific args).
    Side effects:
        Calls policy_mod functions; exits 1 on not-found or invalid input.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.priority_cmd == "set":
        level = args.level.upper()
        if args.priority_target == "endpoint":
            endpoint = replay_db.get_endpoint_by_id(db_path, args.endpoint_id)
            if endpoint is None:
                print(f"Error: Endpoint '{args.endpoint_id}' not found.", file=sys.stderr)
                sys.exit(1)
            try:
                policy_mod.set_manual_priority(db_path, args.endpoint_id, level)
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)
            ep_label = (
                f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
            )
            print(f"Manual priority set to {level} on {ep_label}")

        elif args.priority_target == "path":
            try:
                policy_mod.set_path_rule(
                    db_path, project_id, args.pattern, priority=level, excluded=False
                )
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)
            print(f"Path rule set: '{args.pattern}' → priority {level}")

    elif args.priority_cmd == "clear":
        if args.priority_target == "endpoint":
            endpoint = replay_db.get_endpoint_by_id(db_path, args.endpoint_id)
            if endpoint is None:
                print(f"Error: Endpoint '{args.endpoint_id}' not found.", file=sys.stderr)
                sys.exit(1)
            policy_mod.clear_manual_priority(db_path, args.endpoint_id)
            ep_label = (
                f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
            )
            print(f"Manual priority cleared on {ep_label} — reverts to auto priority")

        elif args.priority_target == "path":
            deleted = policy_mod.delete_path_rule(db_path, project_id, args.pattern)
            if deleted:
                print(f"Path priority rule removed: '{args.pattern}'")
            else:
                print(f"No path rule found for pattern '{args.pattern}'")


# ------------------------------------------------------------------ #
# Exclude / include command handlers                                   #
# ------------------------------------------------------------------ #

def cmd_exclude(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Exclude an endpoint or path pattern from all attack candidate generation.
    Input:
        project — active Project instance.
        args    — parsed args: excl_target ('endpoint'|'path') + target args.
    Side effects:
        Writes to endpoint_policy (endpoint) or policy_rules (path).
        Exits 1 if endpoint not found.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.excl_target == "endpoint":
        endpoint = replay_db.get_endpoint_by_id(db_path, args.endpoint_id)
        if endpoint is None:
            print(f"Error: Endpoint '{args.endpoint_id}' not found.", file=sys.stderr)
            sys.exit(1)
        policy_mod.set_excluded(db_path, args.endpoint_id, excluded=True)
        ep_label = (
            f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
        )
        print(f"Excluded: {ep_label}")

    elif args.excl_target == "path":
        # Preserve any existing priority rule on this pattern.
        existing_priority = None
        for rule in policy_mod.list_path_rules(db_path, project_id):
            if rule["pattern"] == args.pattern:
                existing_priority = rule["priority"]
                break
        policy_mod.set_path_rule(
            db_path, project_id, args.pattern,
            priority=existing_priority,
            excluded=True,
        )
        print(f"Path exclusion rule added: '{args.pattern}'")


def cmd_include(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Re-include a previously excluded endpoint or path pattern.
    Input:
        project — active Project instance.
        args    — parsed args: excl_target ('endpoint'|'path') + target args.
    Side effects:
        Clears excluded flag on endpoint_policy or removes/updates path rule.
        Exits 1 if endpoint not found.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.excl_target == "endpoint":
        endpoint = replay_db.get_endpoint_by_id(db_path, args.endpoint_id)
        if endpoint is None:
            print(f"Error: Endpoint '{args.endpoint_id}' not found.", file=sys.stderr)
            sys.exit(1)
        policy_mod.set_excluded(db_path, args.endpoint_id, excluded=False)
        ep_label = (
            f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
        )
        print(f"Re-included: {ep_label}")

    elif args.excl_target == "path":
        rules = policy_mod.list_path_rules(db_path, project_id)
        existing = next((r for r in rules if r["pattern"] == args.pattern), None)
        if existing is None:
            print(f"No path rule found for '{args.pattern}' — nothing to include.")
            return
        if existing["priority"] is None:
            # Rule only exists for exclusion — remove it entirely.
            policy_mod.delete_path_rule(db_path, project_id, args.pattern)
            print(f"Path exclusion rule removed: '{args.pattern}'")
        else:
            # Keep the priority rule but clear exclusion.
            policy_mod.set_path_rule(
                db_path, project_id, args.pattern,
                priority=existing["priority"],
                excluded=False,
            )
            print(
                f"Path exclusion cleared for '{args.pattern}' "
                f"(priority rule {existing['priority']} retained)"
            )


# ------------------------------------------------------------------ #
# Rules list command handler                                           #
# ------------------------------------------------------------------ #

def cmd_rules_list(project: object, _args: argparse.Namespace) -> None:
    """
    Purpose:
        Display all active path-based policy rules for the active project.
    Input:
        project — active Project instance.
    Side effects:
        Reads policy_rules table; prints to stdout.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    rules = policy_mod.list_path_rules(db_path, project_id)
    if not rules:
        print(
            "No path rules defined.\n"
            "Use 'talos endpoint priority set path <pattern> <level>' or\n"
            "    'talos endpoint exclude path <pattern>' to create one."
        )
        return

    print(f"{len(rules)} path rule(s):\n")
    for rule in rules:
        priority_str = rule["priority"] or "—"
        excl_str = "excluded" if rule["excluded"] else "included"
        print(
            f"  {rule['pattern']}\n"
            f"    Priority  : {priority_str}\n"
            f"    Exclusion : {excl_str}\n"
            f"    Created   : {rule['created_at']}\n"
        )

