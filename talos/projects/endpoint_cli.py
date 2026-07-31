"""
Module: talos.projects.endpoint_cli

Purpose:
    Command-line interface for endpoint annotation management and the
    Endpoint Policy system.

    Subcommands:
        talos endpoint list   — inventory of captured endpoints (with filters)
        talos endpoint params <id>  — parameter inventory + url_features (URL Sink)
        talos endpoint mark   <id> [<id> ...] (--logout | --dangerous | --safe)
        talos endpoint unmark <id> [<id> ...] (--logout | --dangerous)
        talos endpoint show   <id>
        talos endpoint policy <id>  — effective-policy explanation
        talos endpoint export [<id>] [--endpoints <id> ...]

        talos endpoint notes set|clear <endpoint_id>
        talos endpoint tags add|remove|set|clear <id> [<id> ...] [--tag T ...]

        talos endpoint priority set endpoint <id> [<id> ...] LEVEL
        talos endpoint priority clear endpoint <id> [<id> ...]
        talos endpoint priority set|clear path "<pattern>" ...

        talos endpoint exclude|include endpoint <id> [<id> ...]
        talos endpoint exclude|include path "<pattern>"

        talos endpoint rules              — list path rules (compat alias)
        talos endpoint rule add|update|delete|list|show|preview

    Bulk mutations (multi-ID):
        Validate all IDs first; reject complete op if any ID is invalid;
        execute in one DB transaction; dedupe IDs; report affected vs
        unchanged; support --format json.

    JSON inventory (list/show/rules/policy) exposes **resolved** policy state,
    not raw database rows — same resolver as attack candidate generation.

Dependencies: argparse, sys, talos.projects.manager, talos.projects.annotations,
              talos.projects.policy, talos.projects.policy_score,
              talos.projects.access, talos.replay.db
Data flow:
    CLI args → bound project DB → annotations / policy modules → stdout
Side effects:
    - mark/unmark/priority/exclude/tags write via policy bulk or path-rule APIs.
    - list, show, policy, rules, rule list/show/preview are read-only.
    - Requires a bound project (registry ACTIVE, --project, or TALOS_PROJECT).
    - Exits 3 if no project bound; exits 1 if endpoint/rule not found.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_json,
    cli_usage_error,
    cli_precondition_error,
    wants_json,
)
from talos.projects.manager import ProjectManager
from talos.projects.access import resolve_role
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
        Dispatches to command handlers; may exit on usage errors.
    """
    parser = argparse.ArgumentParser(
        prog="talos endpoint",
        description="Manage endpoint safety annotations and policy.",
    )
    sub = parser.add_subparsers(dest="endpoint_cmd", metavar="<command>")
    sub.required = True

    # talos endpoint list
    p_list = sub.add_parser(
        "list",
        help="List captured endpoints (UUID, method, host, path, policy).",
    )
    p_list.add_argument(
        "--method", default=None, metavar="METHOD",
        help="Filter by HTTP method (case-insensitive, e.g. GET).",
    )
    p_list.add_argument(
        "--host", default=None, metavar="HOST",
        help="Filter by host or canonical origin (case-insensitive).",
    )
    p_list.add_argument(
        "--qualified", action="store_true", default=False,
        help="Show only qualified endpoints (have a 2xx proxy_capture baseline).",
    )
    p_list.add_argument(
        "--excluded", action="store_true", default=False,
        help="Show only excluded endpoints (endpoint flag or path rule).",
    )
    p_list.add_argument(
        "--search", default=None, metavar="TEXT",
        help="Case-insensitive substring match on host or path.",
    )
    p_list.add_argument(
        "--role", default=None, metavar="NAME|UUID",
        help="Filter to endpoints observed under this role (name or UUID).",
    )
    p_list.add_argument(
        "--priority", default=None, metavar="LEVEL",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Filter by effective priority (CRITICAL|HIGH|NORMAL|LOW).",
    )
    add_format_argument(p_list)

    # talos endpoint mark <id> [<id> ...]
    p_mark = sub.add_parser(
        "mark",
        help="Add a safety annotation to one or more endpoints.",
    )
    p_mark.add_argument(
        "endpoint_ids", nargs="+", metavar="ENDPOINT_ID",
        help="Endpoint UUID(s).",
    )
    group_mark = p_mark.add_mutually_exclusive_group(required=True)
    group_mark.add_argument(
        "--logout", action="store_true",
        help="Tag as logout endpoint — never replayed in any mode.",
    )
    group_mark.add_argument(
        "--dangerous", action="store_true",
        help="Tag as dangerous — skipped in automated replay.",
    )
    group_mark.add_argument(
        "--safe", action="store_true",
        help="Clear all annotations — restore default safe state.",
    )
    add_format_argument(p_mark)

    # talos endpoint unmark <id> [<id> ...]
    p_unmark = sub.add_parser(
        "unmark",
        help="Remove an annotation tag from one or more endpoints.",
    )
    p_unmark.add_argument(
        "endpoint_ids", nargs="+", metavar="ENDPOINT_ID",
        help="Endpoint UUID(s).",
    )
    group_unmark = p_unmark.add_mutually_exclusive_group(required=True)
    group_unmark.add_argument("--logout", action="store_true", help="Remove logout tag.")
    group_unmark.add_argument(
        "--dangerous", action="store_true", help="Remove dangerous tag.",
    )
    add_format_argument(p_unmark)

    # talos endpoint show <id>
    p_show = sub.add_parser(
        "show",
        help="Display endpoint details, annotations, and policy.",
    )
    p_show.add_argument("endpoint_id", help="UUID of the endpoint to display.")
    add_format_argument(p_show)

    # talos endpoint policy <id>
    p_policy = sub.add_parser(
        "policy",
        help="Explain effective policy for an endpoint (why the final state exists).",
    )
    p_policy.add_argument("endpoint_id", help="UUID of the endpoint.")
    add_format_argument(p_policy)

    # talos endpoint priority
    p_priority = sub.add_parser(
        "priority",
        help="Set or clear manual priority overrides.",
    )
    _build_priority_parser(p_priority)

    # talos endpoint exclude / include
    p_exclude = sub.add_parser(
        "exclude",
        help="Exclude an endpoint or path pattern from candidate generation.",
    )
    _build_target_parser(p_exclude)

    p_include = sub.add_parser(
        "include",
        help="Re-include a previously excluded endpoint or path pattern.",
    )
    _build_target_parser(p_include)

    # talos endpoint rules  (compat alias for rule list)
    p_rules = sub.add_parser(
        "rules",
        help="List all active path-based policy rules (alias for 'rule list').",
    )
    add_format_argument(p_rules)

    # talos endpoint rule  (canonical resource)
    p_rule = sub.add_parser(
        "rule",
        help="Manage path-based policy rules (add/update/delete/list/show/preview).",
    )
    _build_rule_parser(p_rule)

    # talos endpoint export
    # talos endpoint params <endpoint_id> — URL Sink / parameter inventory
    p_params = sub.add_parser(
        "params",
        help=(
            "List parameter inventory for an endpoint (name, location, type, "
            "url_features score/NRS/categories). Use after proxy capture."
        ),
    )
    p_params.add_argument(
        "endpoint_id",
        help="Endpoint UUID (from 'talos endpoint list').",
    )
    p_params.add_argument(
        "--min-score",
        type=int,
        default=0,
        metavar="N",
        help="Only show parameters with url_features.score >= N (default 0).",
    )
    p_params.add_argument(
        "--network-resource",
        action="store_true",
        help="Only show possible_network_resource=true rows.",
    )
    p_params.add_argument(
        "--location",
        default=None,
        metavar="LOC",
        help="Filter by location (query|body|header|cookie|path|response).",
    )
    add_format_argument(p_params)

    p_export = sub.add_parser(
        "export",
        help="Export complete endpoint dossier(s) as Markdown.",
    )
    p_export.add_argument(
        "endpoint_id", nargs="?", default=None,
        help="UUID of a single endpoint (legacy form).",
    )
    p_export.add_argument(
        "--endpoints", nargs="+", metavar="ENDPOINT_ID", default=None,
        help="One or more endpoint UUIDs to export.",
    )

    # notes / tags
    p_notes = sub.add_parser(
        "notes",
        help="Set or clear free-form analyst notes on an endpoint.",
    )
    _build_notes_parser(p_notes)

    p_tags = sub.add_parser(
        "tags",
        help="Manage arbitrary labels on endpoint(s) (add/remove/set/clear).",
    )
    _build_tags_parser(p_tags)

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )

    cmd = args.endpoint_cmd
    if cmd == "list":
        cmd_endpoint_list(project, args)
    elif cmd == "params":
        cmd_endpoint_params(project, args)
    elif cmd == "mark":
        cmd_endpoint_mark(project, args)
    elif cmd == "unmark":
        cmd_endpoint_unmark(project, args)
    elif cmd == "show":
        cmd_endpoint_show(project, args)
    elif cmd == "policy":
        cmd_endpoint_policy(project, args)
    elif cmd == "priority":
        cmd_priority(project, args)
    elif cmd == "exclude":
        cmd_exclude(project, args)
    elif cmd == "include":
        cmd_include(project, args)
    elif cmd == "rules":
        cmd_rules_list(project, args)
    elif cmd == "rule":
        cmd_rule(project, args)
    elif cmd == "export":
        cmd_endpoint_export(project, args)
    elif cmd == "notes":
        cmd_notes(project, args)
    elif cmd == "tags":
        cmd_tags(project, args)


# ------------------------------------------------------------------ #
# Parser helpers                                                       #
# ------------------------------------------------------------------ #

def _build_notes_parser(parser: argparse.ArgumentParser) -> None:
    """Add 'set' and 'clear' subcommands to the notes parser."""
    sub = parser.add_subparsers(dest="notes_cmd", metavar="<set|clear>")
    sub.required = True

    p_set = sub.add_parser(
        "set",
        help="Replace notes (read from stdin; end interactive input with Ctrl-D).",
    )
    p_set.add_argument("endpoint_id", help="UUID of the endpoint.")

    p_clear = sub.add_parser("clear", help="Clear notes on an endpoint.")
    p_clear.add_argument("endpoint_id", help="UUID of the endpoint.")


def _build_tags_parser(parser: argparse.ArgumentParser) -> None:
    """
    Purpose:
        Tags subcommands accept one or more endpoint IDs.
        Tags may be supplied as ``--tag T`` (preferred for bulk) or as trailing
        positional labels after a single endpoint ID (legacy).
    """
    sub = parser.add_subparsers(dest="tags_cmd", metavar="<add|remove|set|clear>")
    sub.required = True

    for name, help_text in (
        ("add", "Add one or more tags (merge, no duplicates)."),
        ("remove", "Remove one or more tags."),
        ("set", "Replace the full tag list."),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument(
            "items", nargs="+", metavar="ENDPOINT_ID_OR_TAG",
            help=(
                "Endpoint UUID(s). With --tag, all positionals are IDs. "
                "Without --tag (legacy): first is ID, remaining are tags."
            ),
        )
        p.add_argument(
            "--tag", action="append", dest="tag_flags", default=None,
            metavar="TAG",
            help="Tag label (repeatable). Prefer this form for multi-ID ops.",
        )
        add_format_argument(p)

    p_clear = sub.add_parser("clear", help="Remove all tags from endpoint(s).")
    p_clear.add_argument(
        "endpoint_ids", nargs="+", metavar="ENDPOINT_ID",
        help="Endpoint UUID(s).",
    )
    add_format_argument(p_clear)


def _build_priority_parser(parser: argparse.ArgumentParser) -> None:
    """Add 'set' and 'clear' subcommands to the priority parser."""
    sub = parser.add_subparsers(dest="priority_cmd", metavar="<set|clear>")
    sub.required = True

    p_set = sub.add_parser("set", help="Set manual priority on endpoint(s) or a path.")
    set_target = p_set.add_subparsers(dest="priority_target", metavar="<endpoint|path>")
    set_target.required = True

    p_set_ep = set_target.add_parser(
        "endpoint", help="Set priority on one or more endpoints.",
    )
    # tokens = ENDPOINT_ID [ENDPOINT_ID ...] LEVEL  (level is last; nargs=+
    # would otherwise swallow the level if modeled as a separate positional).
    p_set_ep.add_argument(
        "tokens",
        nargs="+",
        metavar="ENDPOINT_ID|LEVEL",
        help="One or more endpoint UUIDs followed by CRITICAL|HIGH|NORMAL|LOW.",
    )
    add_format_argument(p_set_ep)

    p_set_path = set_target.add_parser(
        "path", help="Set priority on all matching path endpoints.",
    )
    p_set_path.add_argument("pattern", help="Path glob pattern (e.g. /api/admin/*).")
    p_set_path.add_argument(
        "level",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Priority level (CRITICAL|HIGH|NORMAL|LOW).",
    )
    add_format_argument(p_set_path)

    p_clear = sub.add_parser(
        "clear",
        help="Remove a manual priority override from endpoint(s) or a path rule.",
    )
    clear_target = p_clear.add_subparsers(
        dest="priority_target", metavar="<endpoint|path>",
    )
    clear_target.required = True

    p_clear_ep = clear_target.add_parser(
        "endpoint", help="Clear manual priority from endpoint(s).",
    )
    p_clear_ep.add_argument(
        "endpoint_ids", nargs="+", metavar="ENDPOINT_ID",
        help="Endpoint UUID(s).",
    )
    add_format_argument(p_clear_ep)

    p_clear_path = clear_target.add_parser(
        "path", help="Remove a path priority rule entirely.",
    )
    p_clear_path.add_argument("pattern", help="Path glob pattern to remove.")
    add_format_argument(p_clear_path)


def _build_target_parser(parser: argparse.ArgumentParser) -> None:
    """Add 'endpoint' and 'path' subcommands for exclude/include."""
    sub = parser.add_subparsers(dest="excl_target", metavar="<endpoint|path>")
    sub.required = True

    p_ep = sub.add_parser("endpoint", help="Target one or more endpoints.")
    p_ep.add_argument(
        "endpoint_ids", nargs="+", metavar="ENDPOINT_ID",
        help="Endpoint UUID(s).",
    )
    add_format_argument(p_ep)

    p_path = sub.add_parser("path", help="Target all endpoints matching a path pattern.")
    p_path.add_argument("pattern", help="Path glob pattern (e.g. /static/*).")
    add_format_argument(p_path)


def _build_rule_parser(parser: argparse.ArgumentParser) -> None:
    """First-class policy-rule resource: add/update/delete/list/show/preview."""
    sub = parser.add_subparsers(dest="rule_cmd", metavar="<add|update|delete|list|show|preview>")
    sub.required = True

    p_add = sub.add_parser("add", help="Create a path policy rule.")
    p_add.add_argument("pattern", help="Path glob pattern (e.g. /api/admin/*).")
    p_add.add_argument(
        "--priority", default=None, metavar="LEVEL",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Optional priority for matching endpoints.",
    )
    p_add.add_argument(
        "--exclude", action="store_true", default=False,
        help="Exclude matching endpoints from candidate generation.",
    )
    add_format_argument(p_add)

    p_upd = sub.add_parser("update", help="Update an existing path policy rule by id.")
    p_upd.add_argument("rule_id", help="UUID of the rule.")
    p_upd.add_argument(
        "--priority", default=None, metavar="LEVEL",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Set priority on the rule.",
    )
    p_upd.add_argument(
        "--clear-priority", action="store_true", default=False,
        help="Remove priority from the rule (leave exclusion intact).",
    )
    excl_group = p_upd.add_mutually_exclusive_group()
    excl_group.add_argument(
        "--exclude", action="store_true", default=False,
        help="Mark the rule as excluding matching endpoints.",
    )
    excl_group.add_argument(
        "--include", action="store_true", default=False,
        help="Clear exclusion on the rule.",
    )
    add_format_argument(p_upd)

    p_del = sub.add_parser("delete", help="Delete a path policy rule by id.")
    p_del.add_argument("rule_id", help="UUID of the rule.")
    add_format_argument(p_del)

    p_list = sub.add_parser("list", help="List all path policy rules.")
    add_format_argument(p_list)

    p_show = sub.add_parser("show", help="Show one path policy rule.")
    p_show.add_argument("rule_id", help="UUID of the rule.")
    add_format_argument(p_show)

    p_prev = sub.add_parser(
        "preview",
        help="Preview which endpoints a path pattern would affect.",
    )
    p_prev.add_argument("pattern", help="Path glob pattern to preview.")
    p_prev.add_argument(
        "--priority", default=None, metavar="LEVEL",
        choices=["critical", "high", "normal", "low",
                 "CRITICAL", "HIGH", "NORMAL", "LOW"],
        help="Optional proposed priority for impact stats.",
    )
    p_prev.add_argument(
        "--exclude", action="store_true", default=False,
        help="Preview impact of excluding matching endpoints.",
    )
    add_format_argument(p_prev)


# ------------------------------------------------------------------ #
# Shared helpers                                                       #
# ------------------------------------------------------------------ #

def _parse_url_features_row(row) -> dict:
    """
    Purpose:
        Parse parameters.url_features JSON from a sqlite Row / mapping.
    Side effects: None.
    """
    import json

    raw = None
    try:
        raw = row["url_features"] if "url_features" in row.keys() else None
    except Exception:
        try:
            raw = row["url_features"]
        except Exception:
            raw = None
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _require_endpoint(db_path, endpoint_id: str) -> dict:
    """Load an endpoint row or exit with a clear error."""
    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        cli_error(f"Endpoint '{endpoint_id}' not found.")
    return endpoint


def _endpoint_label(endpoint: dict) -> str:
    """Return 'METHOD origin/path' for success messages (canonical origin in host)."""
    host = endpoint.get("host") or ""
    path = endpoint.get("normalized_path") or ""
    return f"{endpoint.get('method', '')} {host}{path}"


def _print_bulk_result(
    result: dict,
    *,
    action: str,
    args: argparse.Namespace | None = None,
) -> None:
    """
    Purpose:
        Emit bulk mutation summary in table or JSON form.
    """
    if wants_json(args):
        cli_json({
            "action": action,
            "affected": result["affected"],
            "unchanged": result["unchanged"],
            "affected_ids": result["affected_ids"],
            "unchanged_ids": result["unchanged_ids"],
            "endpoints": result["endpoints"],
            "count": result["count"],
        })
        return

    print(
        f"{action}: {result['affected']} affected, "
        f"{result['unchanged']} unchanged "
        f"({result['count']} endpoint(s))."
    )
    for ep in result["endpoints"]:
        label = f"{ep.get('method', '')} {ep.get('host', '')}{ep.get('path', '')}"
        print(f"  [{ep['status']}] {ep['id']}  {label}")


def _run_bulk(
    fn,
    *args,
    action: str,
    cli_args: argparse.Namespace | None = None,
    **kwargs,
) -> None:
    """Invoke a bulk policy mutation and print the result; map errors to CLI."""
    try:
        result = fn(*args, **kwargs)
    except policy_mod.BulkEndpointError as exc:
        cli_error(str(exc))
    except ValueError as exc:
        cli_error(str(exc))
    _print_bulk_result(result, action=action, args=cli_args)


def _parse_tag_items(
    items: list[str],
    tag_flags: list[str] | None,
    *,
    require_tags: bool,
) -> tuple[list[str], list[str]]:
    """
    Purpose:
        Resolve endpoint IDs and tags from hybrid CLI forms.
        --tag present → all positionals are IDs.
        --tag absent  → first positional is ID, rest are tags (legacy single-ID).
    """
    # MagicMock / non-list values for tag_flags must not be treated as flags.
    flags: list[str] | None
    if tag_flags is None:
        flags = None
    elif isinstance(tag_flags, list):
        flags = tag_flags
    else:
        flags = None

    if flags is not None:
        ids = policy_mod.dedupe_endpoint_ids(items)
        tags = list(flags)
        if require_tags and not any(t.strip() for t in tags):
            cli_usage_error("At least one --tag is required.")
        return ids, tags

    if not items:
        cli_usage_error("At least one endpoint ID is required.")
    endpoint_id = items[0]
    tags = list(items[1:])
    if require_tags and not tags:
        cli_usage_error(
            "Provide tag labels as trailing arguments or via --tag. "
            "Example: talos endpoint tags add <id> admin  OR  "
            "talos endpoint tags add <id1> <id2> --tag admin"
        )
    return [endpoint_id], tags


# ------------------------------------------------------------------ #
# list / show / policy                                                 #
# ------------------------------------------------------------------ #

def cmd_endpoint_list(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        List captured endpoints with effective priority, qualification, and
        exclusion. Primary discovery command for endpoint UUIDs.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]

    role_id: str | None = None
    if args.role:
        role = resolve_role(db_path, args.role)
        if role is None:
            cli_error(f"Role '{args.role}' not found.")
        role_id = role["id"]

    qualified_filter = True if args.qualified else None
    excluded_filter = True if args.excluded else None

    try:
        endpoints = policy_mod.list_endpoints(
            db_path,
            project_id,
            method=args.method,
            host=args.host,
            qualified=qualified_filter,
            excluded=excluded_filter,
            search=args.search,
            role_id=role_id,
            priority=args.priority,
        )
    except ValueError as exc:
        cli_error(str(exc))

    if wants_json(args):
        cli_json(policy_mod.format_endpoint_list_json(endpoints))
        return

    if not endpoints:
        print(
            "No endpoints match the given filters."
            if _has_list_filters(args)
            else "No endpoints captured yet."
        )
        return

    # Table uses host_display when available so operators see hostname, not only origin.
    def _host_col(e: dict) -> str:
        return e.get("host_display") or e.get("host") or ""

    uuid_w = max(len("UUID"), max(len(e["id"]) for e in endpoints))
    method_w = max(len("Method"), max(len(e["method"] or "") for e in endpoints))
    host_w = max(len("Host"), max(len(_host_col(e)) for e in endpoints))
    path_w = max(len("Path"), max(len(e["normalized_path"] or "") for e in endpoints))
    prio_w = max(len("Priority"), max(len(e["effective_level"] or "") for e in endpoints))
    qual_w = len("Qualified")
    excl_w = len("Excluded")

    header = (
        f"{'UUID':<{uuid_w}}  {'Method':<{method_w}}  {'Host':<{host_w}}  "
        f"{'Path':<{path_w}}  {'Priority':<{prio_w}}  "
        f"{'Qualified':<{qual_w}}  {'Excluded':<{excl_w}}"
    )
    print(header)
    print("-" * len(header))
    for e in endpoints:
        print(
            f"{e['id']:<{uuid_w}}  "
            f"{e['method']:<{method_w}}  "
            f"{_host_col(e):<{host_w}}  "
            f"{e['normalized_path']:<{path_w}}  "
            f"{e['effective_level']:<{prio_w}}  "
            f"{'yes' if e['qualified'] else 'no':<{qual_w}}  "
            f"{'yes' if e['excluded'] else 'no':<{excl_w}}"
        )
    print(f"\n{len(endpoints)} endpoint(s).")


def _has_list_filters(args: argparse.Namespace) -> bool:
    """True when at least one list filter is set."""
    return bool(
        args.method
        or args.host
        or args.qualified
        or args.excluded
        or args.search
        or args.role
        or args.priority
    )


def cmd_endpoint_params(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        List parameter inventory for one endpoint with URL Sink url_features
        summary (score, NRS, categories) for post-capture triage.
    Side effects: Read-only DB; prints table or JSON.
    """
    import json
    import sqlite3

    from talos.input_validation.db import make_param_uuid

    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = (args.endpoint_id or "").strip()
    ep = _require_endpoint(db_path, endpoint_id)

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, name, location, param_type, semantic_type,
                   seen_count, is_reflected, reflection_count,
                   example_values, url_features
            FROM parameters
            WHERE endpoint_id = ?
            ORDER BY location, name
            """,
            (endpoint_id,),
        ).fetchall()

    min_score = int(getattr(args, "min_score", 0) or 0)
    nrs_only = bool(getattr(args, "network_resource", False))
    loc_filter = (getattr(args, "location", None) or "").strip().lower() or None

    items: list[dict] = []
    host = ep.get("host") or ""
    # Prefer host_display when origin-aware (same as export).
    host_key = host
    if "://" in host:
        # origin form — make_param_uuid historically uses host column value
        host_key = host

    for r in rows:
        uf = _parse_url_features_row(r)
        try:
            score = int(uf.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        nrs = bool(uf.get("possible_network_resource"))
        if score < min_score:
            continue
        if nrs_only and not nrs:
            continue
        loc = (r["location"] or "").strip().lower()
        if loc_filter and loc != loc_filter:
            continue
        cats = uf.get("name_categories") or []
        if not isinstance(cats, list):
            cats = []
        primary = uf.get("name_category")
        try:
            examples = json.loads(r["example_values"] or "[]")
        except (json.JSONDecodeError, TypeError):
            examples = []
        param_uuid = make_param_uuid(host_key, r["location"] or "", r["name"] or "")
        items.append({
            "id": r["id"],
            "param_uuid": param_uuid,
            "name": r["name"],
            "location": r["location"],
            "param_type": r["param_type"],
            "semantic_type": r["semantic_type"],
            "seen_count": r["seen_count"],
            "is_reflected": bool(r["is_reflected"]),
            "examples": examples[:3] if isinstance(examples, list) else [],
            "url_features": uf,
            "url_score": score,
            "possible_network_resource": nrs,
            "name_category": primary,
            "name_categories": cats,
        })

    if wants_json(args):
        cli_json({
            "endpoint_id": endpoint_id,
            "method": ep.get("method"),
            "host": host,
            "path": ep.get("normalized_path") or ep.get("path"),
            "count": len(items),
            "parameters": items,
        })
        return

    print(
        f"\nParameters: {ep.get('method', '')} "
        f"{host}{ep.get('normalized_path') or ep.get('path') or ''}"
    )
    print(f"Endpoint: {endpoint_id}")
    print("=" * 78)
    if not items:
        print("  (no parameters match filters — capture traffic or lower --min-score)")
        print()
        return

    # Compact table
    print(
        f"{'Name':<28} {'Loc':<10} {'Type':<14} "
        f"{'Score':>5} {'NRS':>3} {'Category':<16} Seen"
    )
    print("-" * 78)
    for it in items:
        cat = it.get("name_category") or (
            ",".join(it["name_categories"][:2]) if it["name_categories"] else "—"
        )
        type_s = f"{it['param_type'] or '?'}/{it['semantic_type'] or '?'}"
        name = (it["name"] or "")[:28]
        print(
            f"{name:<28} {(it['location'] or ''):<10} {type_s:<14} "
            f"{it['url_score']:>5} {'Y' if it['possible_network_resource'] else 'n':>3} "
            f"{str(cat)[:16]:<16} {it['seen_count']}"
        )
    print(f"\n{len(items)} parameter(s).")
    print(
        "Tip: talos input-validation show <param_uuid>  "
        "(param_uuid = sha256(host|location|name)[:32])"
    )
    print()


def cmd_endpoint_mark(project: object, args: argparse.Namespace) -> None:
    """Bulk-capable mark: --logout | --dangerous | --safe on one or more IDs."""
    db_path = project.db_path  # type: ignore[attr-defined]
    ids = list(args.endpoint_ids)

    if args.safe:
        _run_bulk(
            policy_mod.bulk_set_safety,
            db_path,
            ids,
            clear_all=True,
            action="mark --safe",
            cli_args=args,
        )
    elif args.logout:
        _run_bulk(
            policy_mod.bulk_set_safety,
            db_path,
            ids,
            logout=True,
            action="mark --logout",
            cli_args=args,
        )
    elif args.dangerous:
        _run_bulk(
            policy_mod.bulk_set_safety,
            db_path,
            ids,
            dangerous=True,
            action="mark --dangerous",
            cli_args=args,
        )


def cmd_endpoint_unmark(project: object, args: argparse.Namespace) -> None:
    """Bulk-capable unmark: clear --logout or --dangerous on one or more IDs."""
    db_path = project.db_path  # type: ignore[attr-defined]
    ids = list(args.endpoint_ids)

    if args.logout:
        _run_bulk(
            policy_mod.bulk_set_safety,
            db_path,
            ids,
            logout=False,
            action="unmark --logout",
            cli_args=args,
        )
    elif args.dangerous:
        _run_bulk(
            policy_mod.bulk_set_safety,
            db_path,
            ids,
            dangerous=False,
            action="unmark --dangerous",
            cli_args=args,
        )


def cmd_endpoint_show(project: object, args: argparse.Namespace) -> None:
    """Display endpoint record and full unified policy."""
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        cli_error(f"Endpoint '{endpoint_id}' not found.")

    ep_label = _endpoint_label(endpoint)
    origin, host_display = policy_mod.split_origin_identity(endpoint.get("host") or "")

    policy = policy_mod.get_effective_policy(
        db_path=db_path,
        project_id=project_id,
        endpoint_id=endpoint_id,
        normalized_path=endpoint["normalized_path"],
    )
    explanation = policy_mod.explain_endpoint_policy(
        db_path, project_id, endpoint_id, endpoint["normalized_path"],
    )

    if wants_json(args):
        cli_json({
            "id": endpoint_id,
            "method": endpoint.get("method"),
            "origin": origin,
            "host": host_display,
            "path": endpoint.get("normalized_path"),
            "normalized_path": endpoint.get("normalized_path"),
            "label": ep_label,
            "policy": explanation,
        })
        return

    excl_str = "YES" if policy.excluded else "no"
    dangerous_str = "YES" if policy.dangerous else "no"
    logout_str = "YES" if policy.logout else "no"
    manual_str = policy.manual_priority or "—"
    source_str = policy.source
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
        f"  {ep_label}\n"
        f"  Origin  : {origin or '—'}\n\n"
        f"--- Endpoint Policy ---\n"
        f"  Effective Priority : {policy.effective_level}  (source: {source_str})\n"
        f"  Manual Override    : {manual_str}\n"
        f"  Excluded           : {excl_str}"
        f"{f'  (source: {policy.exclusion_source})' if policy.exclusion_source else ''}\n"
        f"  Dangerous          : {dangerous_str}\n"
        f"  Logout             : {logout_str}\n"
        f"  Qualified          : {'YES' if policy.qualified else 'no'}"
        f"  ({policy.qualification_reason})\n"
        f"{breakdown_str}\n"
        f"  Notes : {notes_str}\n"
        f"  Tags  : {tags_policy_str}"
    )


def cmd_endpoint_policy(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Explicit effective-policy explanation for operators and Control Panel.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        cli_error(f"Endpoint '{endpoint_id}' not found.")

    explanation = policy_mod.explain_endpoint_policy(
        db_path, project_id, endpoint_id, endpoint["normalized_path"],
    )
    origin, _ = policy_mod.split_origin_identity(endpoint.get("host") or "")
    ep_line = (
        f"{endpoint.get('method', '')} "
        f"{origin or endpoint.get('host', '')}"
        f"{endpoint.get('normalized_path', '')}"
    )

    if wants_json(args):
        payload = dict(explanation)
        payload["endpoint"] = {
            "id": endpoint_id,
            "method": endpoint.get("method"),
            "origin": origin,
            "path": endpoint.get("normalized_path"),
            "label": ep_line,
        }
        cli_json(payload)
        return

    pr = explanation["priority"]
    ex = explanation["exclusion"]
    qu = explanation["qualification"]
    sf = explanation["safety"]
    bl = explanation["baseline"]

    manual_str = pr["manual"] or "—"
    rule_str = "—"
    if pr.get("rule"):
        rule_str = (
            f"{pr['rule'].get('pattern')} "
            f"({pr['rule'].get('priority')})"
        )
        if pr["rule"].get("id"):
            rule_str += f"  id={pr['rule']['id']}"

    excl_src = ex.get("source") or "—"
    excl_rule = ex.get("rule_pattern") or "—"

    print(
        f"Endpoint\n"
        f"{ep_line}\n\n"
        f"Priority\n"
        f"Effective    {pr['effective']}\n"
        f"Source       {pr['source']}\n"
        f"Rule         {rule_str}\n"
        f"Auto         {pr['auto']['priority']}\n"
        f"Auto score   {pr['auto']['score']}\n"
        f"Manual       {manual_str}\n\n"
        f"Exclusion\n"
        f"Effective    {'YES' if ex['effective'] else 'NO'}\n"
        f"Source       {excl_src}\n"
        f"Rule         {excl_rule}\n\n"
        f"Qualification\n"
        f"Qualified    {'YES' if qu['qualified'] else 'NO'}\n"
        f"Reason       {qu['reason']}\n\n"
        f"Safety\n"
        f"Dangerous    {'YES' if sf['dangerous'] else 'NO'}\n"
        f"Logout       {'YES' if sf['logout'] else 'NO'}\n\n"
        f"Baseline\n"
        f"Flow         {bl['flow_id'] or '—'}\n"
        f"Status       {bl['status'] if bl['status'] is not None else '—'}"
    )


# ------------------------------------------------------------------ #
# Notes / tags                                                         #
# ------------------------------------------------------------------ #

def _read_notes_stdin() -> str:
    """Read free-form notes from stdin (pipe or interactive Ctrl-D)."""
    if sys.stdin.isatty():
        print(
            "Enter notes (end with Ctrl-D on empty line):",
            file=sys.stderr,
        )
    text = sys.stdin.read()
    if text.endswith("\n"):
        text = text[:-1]
    return text


def cmd_notes(project: object, args: argparse.Namespace) -> None:
    """Handle 'talos endpoint notes set|clear <endpoint_id>'."""
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id
    endpoint = _require_endpoint(db_path, endpoint_id)
    ep_label = _endpoint_label(endpoint)

    if args.notes_cmd == "set":
        notes = _read_notes_stdin()
        if not notes.strip():
            cli_error(
                "Notes text is empty. "
                "Pipe text or type notes, or use 'talos endpoint notes clear'."
            )
        policy_mod.set_notes(db_path, endpoint_id, notes)
        print(f"Notes set on {ep_label}")
    elif args.notes_cmd == "clear":
        policy_mod.set_notes(db_path, endpoint_id, "")
        print(f"Notes cleared on {ep_label}")


def cmd_tags(project: object, args: argparse.Namespace) -> None:
    """Handle bulk-capable tags add|remove|set|clear."""
    db_path = project.db_path  # type: ignore[attr-defined]
    action = args.tags_cmd

    if action == "clear":
        _run_bulk(
            policy_mod.bulk_clear_tags,
            db_path,
            list(args.endpoint_ids),
            action="tags clear",
            cli_args=args,
        )
        return

    require_tags = action in ("add", "remove", "set")
    raw_flags = getattr(args, "tag_flags", None)
    tag_flags = raw_flags if isinstance(raw_flags, list) else None
    items = list(getattr(args, "items", []) or [])
    ids, tags = _parse_tag_items(
        items,
        tag_flags,
        require_tags=require_tags and action != "set",
    )
    if action == "set" and not tags and tag_flags is None and len(items) < 2:
        cli_usage_error(
            "No tags provided. Use 'talos endpoint tags clear' to remove all tags."
        )

    if action == "add":
        _run_bulk(
            policy_mod.bulk_add_tags, db_path, ids, tags,
            action="tags add", cli_args=args,
        )
    elif action == "remove":
        _run_bulk(
            policy_mod.bulk_remove_tags, db_path, ids, tags,
            action="tags remove", cli_args=args,
        )
    elif action == "set":
        cleaned = policy_mod.clean_tag_list(tags)
        if not cleaned:
            cli_error(
                "No non-empty tags provided. "
                "Use 'talos endpoint tags clear' to remove all tags."
            )
        _run_bulk(
            policy_mod.bulk_set_tags, db_path, ids, cleaned,
            action="tags set", cli_args=args,
        )
    else:
        cli_usage_error(f"Unknown tags action '{action}'.")


# ------------------------------------------------------------------ #
# Priority / exclude / include                                         #
# ------------------------------------------------------------------ #

def cmd_priority(project: object, args: argparse.Namespace) -> None:
    """Handle priority set/clear for endpoint(s) or path."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.priority_cmd == "set":
        if args.priority_target == "endpoint":
            tokens = list(args.tokens)
            if len(tokens) < 2:
                cli_usage_error(
                    "Usage: talos endpoint priority set endpoint "
                    "<id> [<id> ...] CRITICAL|HIGH|NORMAL|LOW"
                )
            level = tokens[-1].upper()
            if level not in policy_mod.VALID_LEVELS:
                cli_error(
                    f"Invalid priority level '{tokens[-1]}'. "
                    f"Valid: {', '.join(sorted(policy_mod.VALID_LEVELS))}"
                )
            ids = tokens[:-1]
            _run_bulk(
                policy_mod.bulk_set_manual_priority,
                db_path,
                ids,
                level,
                action=f"priority set {level}",
                cli_args=args,
            )
        elif args.priority_target == "path":
            level = args.level.upper()
            try:
                rule_id = policy_mod.set_path_rule(
                    db_path, project_id, args.pattern,
                    priority=level, excluded=False,
                )
            except ValueError as exc:
                cli_error(str(exc))
            if wants_json(args):
                rule = policy_mod.get_path_rule(db_path, project_id, rule_id)
                cli_json({"action": "priority set path", "rule": rule})
                return
            print(f"Path rule set: '{args.pattern}' → priority {level}")

    elif args.priority_cmd == "clear":
        if args.priority_target == "endpoint":
            ids = list(args.endpoint_ids)
            _run_bulk(
                policy_mod.bulk_set_manual_priority,
                db_path,
                ids,
                None,
                action="priority clear",
                cli_args=args,
            )
        elif args.priority_target == "path":
            deleted = policy_mod.delete_path_rule(db_path, project_id, args.pattern)
            if wants_json(args):
                cli_json({
                    "action": "priority clear path",
                    "pattern": args.pattern,
                    "deleted": deleted,
                })
                return
            if deleted:
                print(f"Path priority rule removed: '{args.pattern}'")
            else:
                print(f"No path rule found for pattern '{args.pattern}'")


def cmd_exclude(project: object, args: argparse.Namespace) -> None:
    """Exclude endpoint(s) or a path pattern."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.excl_target == "endpoint":
        ids = list(args.endpoint_ids)
        _run_bulk(
            policy_mod.bulk_set_excluded,
            db_path,
            ids,
            True,
            action="exclude",
            cli_args=args,
        )
    elif args.excl_target == "path":
        existing_priority = None
        for rule in policy_mod.list_path_rules(db_path, project_id):
            if rule["pattern"] == args.pattern:
                existing_priority = rule["priority"]
                break
        rule_id = policy_mod.set_path_rule(
            db_path, project_id, args.pattern,
            priority=existing_priority,
            excluded=True,
        )
        if wants_json(args):
            rule = policy_mod.get_path_rule(db_path, project_id, rule_id)
            cli_json({"action": "exclude path", "rule": rule})
            return
        print(f"Path exclusion rule added: '{args.pattern}'")


def cmd_include(project: object, args: argparse.Namespace) -> None:
    """Re-include endpoint(s) or clear a path exclusion."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if args.excl_target == "endpoint":
        ids = list(args.endpoint_ids)
        _run_bulk(
            policy_mod.bulk_set_excluded,
            db_path,
            ids,
            False,
            action="include",
            cli_args=args,
        )
    elif args.excl_target == "path":
        rules = policy_mod.list_path_rules(db_path, project_id)
        existing = next((r for r in rules if r["pattern"] == args.pattern), None)
        if existing is None:
            if wants_json(args):
                cli_json({
                    "action": "include path",
                    "pattern": args.pattern,
                    "changed": False,
                })
                return
            print(f"No path rule found for '{args.pattern}' — nothing to include.")
            return
        if existing["priority"] is None:
            policy_mod.delete_path_rule(db_path, project_id, args.pattern)
            msg = f"Path exclusion rule removed: '{args.pattern}'"
        else:
            policy_mod.set_path_rule(
                db_path, project_id, args.pattern,
                priority=existing["priority"],
                excluded=False,
            )
            msg = (
                f"Path exclusion cleared for '{args.pattern}' "
                f"(priority rule {existing['priority']} retained)"
            )
        if wants_json(args):
            cli_json({
                "action": "include path",
                "pattern": args.pattern,
                "changed": True,
                "message": msg,
            })
            return
        print(msg)


# ------------------------------------------------------------------ #
# Rules list (compat) + first-class rule resource                      #
# ------------------------------------------------------------------ #

def cmd_rules_list(project: object, args: argparse.Namespace) -> None:
    """Compat: ``talos endpoint rules`` → rule list."""
    _cmd_rule_list(project, args)


def cmd_rule(project: object, args: argparse.Namespace) -> None:
    """Dispatch first-class rule subcommands."""
    action = args.rule_cmd
    if action == "add":
        _cmd_rule_add(project, args)
    elif action == "update":
        _cmd_rule_update(project, args)
    elif action == "delete":
        _cmd_rule_delete(project, args)
    elif action == "list":
        _cmd_rule_list(project, args)
    elif action == "show":
        _cmd_rule_show(project, args)
    elif action == "preview":
        _cmd_rule_preview(project, args)
    else:
        cli_usage_error(f"Unknown rule action '{action}'.")


def _cmd_rule_list(project: object, args: argparse.Namespace) -> None:
    """List all path-based policy rules."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    rules = policy_mod.list_path_rules(db_path, project_id)
    if wants_json(args):
        cli_json({"rules": rules, "count": len(rules)})
        return

    if not rules:
        print(
            "No path rules defined.\n"
            "Use 'talos endpoint rule add <pattern> --priority HIGH' or\n"
            "    'talos endpoint rule add <pattern> --exclude' to create one.\n"
            "Legacy: 'talos endpoint priority set path' / 'exclude path'."
        )
        return

    print(f"{len(rules)} path rule(s):\n")
    for rule in rules:
        priority_str = rule["priority"] or "—"
        excl_str = "excluded" if rule["excluded"] else "included"
        print(
            f"  {rule['id']}\n"
            f"    Pattern   : {rule['pattern']}\n"
            f"    Priority  : {priority_str}\n"
            f"    Exclusion : {excl_str}\n"
            f"    Created   : {rule['created_at']}\n"
        )


def _cmd_rule_show(project: object, args: argparse.Namespace) -> None:
    """Show one rule by id."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]
    rule = policy_mod.get_path_rule(db_path, project_id, args.rule_id)
    if rule is None:
        cli_error(f"Policy rule '{args.rule_id}' not found.")
    if wants_json(args):
        cli_json(rule)
        return
    priority_str = rule["priority"] or "—"
    excl_str = "excluded" if rule["excluded"] else "included"
    print(
        f"Rule       : {rule['id']}\n"
        f"Pattern    : {rule['pattern']}\n"
        f"Priority   : {priority_str}\n"
        f"Exclusion  : {excl_str}\n"
        f"Created    : {rule['created_at']}"
    )


def _cmd_rule_add(project: object, args: argparse.Namespace) -> None:
    """Create or replace a path rule."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]
    if args.priority is None and not args.exclude:
        cli_usage_error(
            "Provide --priority LEVEL and/or --exclude when adding a rule."
        )
    try:
        rule = policy_mod.add_path_rule(
            db_path,
            project_id,
            args.pattern,
            priority=args.priority.upper() if args.priority else None,
            excluded=bool(args.exclude),
        )
    except ValueError as exc:
        cli_error(str(exc))
    if wants_json(args):
        cli_json({"action": "rule add", "rule": rule})
        return
    prio = rule["priority"] or "—"
    excl = "excluded" if rule["excluded"] else "included"
    print(
        f"Rule added: {rule['id']}\n"
        f"  Pattern  : {rule['pattern']}\n"
        f"  Priority : {prio}\n"
        f"  State    : {excl}"
    )


def _cmd_rule_update(project: object, args: argparse.Namespace) -> None:
    """Partial update of a path rule by id."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if (
        args.priority is None
        and not args.clear_priority
        and not args.exclude
        and not args.include
    ):
        cli_usage_error(
            "Provide at least one of: --priority, --clear-priority, "
            "--exclude, --include."
        )

    excluded: bool | None = None
    if args.exclude:
        excluded = True
    elif args.include:
        excluded = False

    try:
        rule = policy_mod.update_path_rule(
            db_path,
            project_id,
            args.rule_id,
            priority=args.priority.upper() if args.priority else ...,
            excluded=excluded,
            clear_priority=bool(args.clear_priority),
        )
    except ValueError as exc:
        cli_error(str(exc))

    if wants_json(args):
        cli_json({"action": "rule update", "rule": rule})
        return
    prio = rule["priority"] or "—"
    excl = "excluded" if rule["excluded"] else "included"
    print(
        f"Rule updated: {rule['id']}\n"
        f"  Pattern  : {rule['pattern']}\n"
        f"  Priority : {prio}\n"
        f"  State    : {excl}"
    )


def _cmd_rule_delete(project: object, args: argparse.Namespace) -> None:
    """Delete a path rule by id."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]
    deleted = policy_mod.delete_path_rule_by_id(db_path, project_id, args.rule_id)
    if not deleted:
        cli_error(f"Policy rule '{args.rule_id}' not found.")
    if wants_json(args):
        cli_json({
            "action": "rule delete",
            "rule_id": args.rule_id,
            "deleted": True,
        })
        return
    print(f"Rule deleted: {args.rule_id}")


def _cmd_rule_preview(project: object, args: argparse.Namespace) -> None:
    """Preview path-rule impact using the live matcher and resolver."""
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]
    try:
        preview = policy_mod.preview_path_rule_impact(
            db_path,
            project_id,
            args.pattern,
            priority=args.priority.upper() if args.priority else None,
            excluded=True if args.exclude else None,
        )
    except ValueError as exc:
        cli_error(str(exc))

    if wants_json(args):
        cli_json(preview)
        return

    cur = preview["current"]
    prop = preview["proposed"]
    bp = cur["by_priority"]

    print(f"Pattern: {preview['pattern']}")
    print(f"Matching endpoints: {preview['matching_count']}\n")
    print("Current state")
    print(f"  Qualified: {cur['qualified']}")
    print(f"  Excluded: {cur['excluded']}")
    print(f"  Critical: {bp['critical']}")
    print(f"  High: {bp['high']}")
    print(f"  Normal: {bp['normal']}")
    print(f"  Low: {bp['low']}\n")

    print("Proposed impact")
    if prop.get("excluded") is True:
        print(f"  Newly excluded: {prop['newly_excluded']}")
        print(f"  Already excluded: {prop['already_excluded']}")
    if prop.get("priority"):
        print(f"  Priority → {prop['priority']}: {prop['priority_changes']} would change")
    if prop.get("excluded") is not True and not prop.get("priority"):
        print("  (no --priority / --exclude; listing matches only)")

    if preview["endpoints"]:
        print("\nAffected endpoints")
        for ep in preview["endpoints"][:50]:
            origin = ep.get("origin") or ep.get("host") or ""
            print(f"  {ep['method']}  {origin}{ep['path']}")
        if len(preview["endpoints"]) > 50:
            print(f"  … and {len(preview['endpoints']) - 50} more")


# ------------------------------------------------------------------ #
# Export                                                               #
# ------------------------------------------------------------------ #

def cmd_endpoint_export(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Export complete endpoint dossier(s) as Markdown under exports/.
        Supports single positional id or ``--endpoints id id …``.
    """
    ids: list[str] = []
    if args.endpoints:
        ids.extend(args.endpoints)
    if args.endpoint_id:
        ids.append(args.endpoint_id)
    ids = policy_mod.dedupe_endpoint_ids(ids)
    if not ids:
        cli_usage_error(
            "Provide an endpoint UUID or --endpoints <id> [<id> ...]."
        )

    try:
        policy_mod.validate_endpoint_ids_exist(project.db_path, ids)  # type: ignore[attr-defined]
    except policy_mod.BulkEndpointError as exc:
        cli_error(str(exc))

    paths = []
    for eid in ids:
        out = _export_one_endpoint(project, eid)
        paths.append(str(out))
        print(f"Exported to {out}")

    if len(paths) > 1:
        print(f"\n{len(paths)} dossier(s) written.")


def _export_one_endpoint(project: object, endpoint_id: str) -> Path:
    """
    Purpose:
        Write one Markdown dossier for an endpoint; return output path.
    """
    import json
    import sqlite3
    from datetime import datetime, timezone  # noqa: F401 — kept for future stamps
    from talos.input_validation.db import (
        make_param_uuid,
        get_probe_results_for_param,
        get_reflection_cache_entry,
    )

    db_path = project.db_path    # type: ignore[attr-defined]
    endpoint_id = endpoint_id.strip()

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        ep = conn.execute(
            """
            SELECT id, method, host, path, normalized_path, content_type,
                   auth_required, roles_seen, first_seen, last_seen
            FROM endpoints WHERE id = ?
            """,
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            cli_error(f"Endpoint '{endpoint_id}' not found.")

        params = conn.execute(
            """
            SELECT id, name, location, param_type, semantic_type,
                   seen_count, is_reflected, reflection_count, example_values,
                   url_features
            FROM parameters WHERE endpoint_id = ?
            ORDER BY location, name
            """,
            (endpoint_id,),
        ).fetchall()

        captured_flows = conn.execute(
            """
            SELECT id, method, url, status_code, captured_at, role_id
            FROM flows
            WHERE endpoint_id = ? AND source = 'proxy_capture'
            ORDER BY captured_at DESC
            LIMIT 20
            """,
            (endpoint_id,),
        ).fetchall()

        replay_flows = conn.execute(
            """
            SELECT id, method, url, status_code, source, replay_reason,
                   captured_at, COALESCE(flow_meta, '{}') AS flow_meta
            FROM flows
            WHERE endpoint_id = ? AND source != 'proxy_capture'
            ORDER BY captured_at DESC
            LIMIT 50
            """,
            (endpoint_id,),
        ).fetchall()

    safety_tags = annotations_mod.get_annotations(db_path, endpoint_id)
    notes_text, policy_tags = policy_mod.get_notes_and_tags(db_path, endpoint_id)
    origin, host_display = policy_mod.split_origin_identity(ep["host"] or "")

    lines: list[str] = [
        "# Endpoint Dossier",
        "",
        f"**Endpoint ID:** `{endpoint_id}`",
        f"**Method:** `{ep['method']}`",
        f"**Path:** `{ep['normalized_path']}`",
        f"**Origin:** `{origin or ep['host']}`",
        f"**Host:** `{host_display or ep['host']}`",
        f"**Auth Required:** {'Yes' if ep['auth_required'] else 'Unknown'}",
        f"**First Seen:** {ep['first_seen']}",
        f"**Last Seen:** {ep['last_seen']}",
    ]
    if safety_tags:
        lines.append(f"**Annotations:** {', '.join(safety_tags)}")
    if policy_tags:
        lines.append(f"**Tags:** {', '.join(policy_tags)}")
    if notes_text.strip():
        lines.append(f"**Notes:** {notes_text}")
    lines += ["", "---", ""]

    lines.append(f"## Parameters ({len(params)})")
    lines.append("")
    if params:
        lines.append(
            "| Name | Location | Type | Seen | Reflected | "
            "URL score | NRS | Categories |"
        )
        lines.append(
            "|------|----------|------|------|-----------|"
            "----------:|-----|------------|"
        )
        for p in params:
            uf = _parse_url_features_row(p)
            cats = uf.get("name_categories") or []
            if isinstance(cats, list) and cats:
                cat_txt = ", ".join(str(c) for c in cats)
            else:
                cat_txt = str(uf.get("name_category") or "—")
            try:
                score = int(uf.get("score") or 0)
            except (TypeError, ValueError):
                score = 0
            nrs = "yes" if uf.get("possible_network_resource") else "no"
            lines.append(
                f"| `{p['name']}` | {p['location']} | "
                f"{p['param_type']}/{p['semantic_type']} | "
                f"{p['seen_count']} | {'Yes' if p['is_reflected'] else 'No'} | "
                f"{score} | {nrs} | {cat_txt} |"
            )
    else:
        lines.append("*No parameters discovered yet.*")
    lines.append("")

    lines.append("## Input Validation")
    lines.append("")
    has_iv = False
    for p in params:
        # IV param key uses host display when host column is origin-aware.
        host_key = host_display or ep["host"]
        p_uuid = make_param_uuid(host_key, p["location"], p["name"])
        probes = get_probe_results_for_param(db_path, p_uuid)
        refl = get_reflection_cache_entry(
            db_path, endpoint_id, p["name"], p["location"],
        )
        if not probes:
            continue
        has_iv = True
        lines.append(f"### `{p['name']}` ({p['location']})")
        lines.append("")
        lines.append("| Analysis | Payload | HTTP Status | Flow ID | Status |")
        lines.append("|----------|---------|-------------|---------|--------|")
        for rec in probes:
            payload = rec.get("payload")
            payload_str = repr(payload) if payload is not None else "(baseline)"
            sc = rec.get("status_code") or "—"
            fid = (rec.get("flow_id") or "")[:8] or "—"
            st = rec.get("status") or ""
            lines.append(
                f"| {rec.get('analysis', '')} | `{payload_str}` | {sc} | `{fid}` | {st} |"
            )
        if refl and refl.get("status") == "completed":
            try:
                rr = json.loads(refl.get("result") or "{}")
            except Exception:
                rr = {}
            reflected = rr.get("reflected", False)
            enc = rr.get("encoding", "")
            loc = rr.get("reflection_location", "")
            lines.append("")
            lines.append(
                f"**Reflection:** {'Reflected' if reflected else 'Not reflected'}"
                + (f"  encoding={enc}  location={loc}" if reflected else "")
            )
        lines.append("")
    if not has_iv:
        lines.append("*Input Validation has not run yet for this endpoint.*")
        lines.append("")

    lines.append("## Captured Flows")
    lines.append("")
    if captured_flows:
        lines.append("| Flow ID | Status | Captured At | Role |")
        lines.append("|---------|--------|-------------|------|")
        for f in captured_flows:
            lines.append(
                f"| `{f['id'][:16]}…` | {f['status_code'] or '—'} | "
                f"{f['captured_at'][:19]} | `{(f['role_id'] or '')[:8]}…` |"
            )
    else:
        lines.append("*No captured flows.*")
    lines.append("")

    lines.append("## Replay Flows")
    lines.append("")
    if replay_flows:
        lines.append("| Flow ID | Source | Reason | Status | Generated By |")
        lines.append("|---------|--------|--------|--------|--------------|")
        for f in replay_flows:
            try:
                fmeta = json.loads(f["flow_meta"] or "{}")
            except Exception:
                fmeta = {}
            generated_by = fmeta.get("generated_by", "")
            lines.append(
                f"| `{f['id'][:16]}…` | {f['source']} | {f['replay_reason'] or '—'} | "
                f"{f['status_code'] or '—'} | {generated_by or '—'} |"
            )
    else:
        lines.append("*No replay flows.*")
    lines.append("")

    md_content = "\n".join(lines)
    export_dir = Path(str(db_path).replace("talos.db", "")) / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    out_path = export_dir / f"endpoint_{endpoint_id[:16]}.md"
    out_path.write_text(md_content, encoding="utf-8")
    return out_path
