"""
Module: talos.configuration.http_cli

Purpose:
    CLI for the HTTP Manipulation Engine under ``talos config http``.

    Commands:
        list / show / create / delete / enable / disable / set-priority
        set-match / clear-match / add-action / remove-action / reorder
        export / import / enable-engine / disable-engine

    Rules are stored in layered YAML (global config.yaml or project.yaml).
    Effective view concatenates all layers; CRUD always targets one layer
    (--global or project).

Dependencies: argparse, json, sys, yaml, talos.cli_output, configuration.*
Data flow:
    argv → ConfigurationManager layer read/write → stdout
Side effects:
    Writes YAML; may notify proxy of config changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

import yaml

from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_info,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    confirm_or_exit,
    wants_json,
)
from talos.configuration.http_rules import (
    ACTION_OPS,
    HttpRuleError,
    find_rule,
    new_rule_id,
    normalize_action,
    normalize_match,
    normalize_rule,
    parse_action_cli,
    parse_rules,
    rules_for_storage,
    sort_rules,
)
from talos.configuration.manager import ConfigError, ConfigurationManager
from talos.configuration.merge import get_path
from talos.projects.manager import NO_ACTIVE_PROJECT_HINT, ProjectManager


# ------------------------------------------------------------------ #
# Entry                                                                #
# ------------------------------------------------------------------ #


def run_http_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse and dispatch ``talos config http`` subcommands.
    Side effects: Reads/writes config; prints; may exit.
    """
    parser = build_http_parser()
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return

    args = parser.parse_args(argv)
    handlers = {
        "list": cmd_list,
        "show": cmd_show,
        "create": cmd_create,
        "update": cmd_update,
        "delete": cmd_delete,
        "enable": cmd_enable,
        "disable": cmd_disable,
        "set-priority": cmd_set_priority,
        "set-match": cmd_set_match,
        "clear-match": cmd_clear_match,
        "add-action": cmd_add_action,
        "remove-action": cmd_remove_action,
        "reorder": cmd_reorder,
        "export": cmd_export,
        "import": cmd_import,
        "enable-engine": cmd_enable_engine,
        "disable-engine": cmd_disable_engine,
        "actions": cmd_actions_help,
    }
    handler = handlers.get(args.http_command)
    if handler is None:
        parser.print_help()
        sys.exit(2)
    handler(manager, args)


def build_http_parser() -> argparse.ArgumentParser:
    """
    Purpose: Build argparse tree for HTTP rule management.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos config http",
        description=(
            "HTTP Manipulation Engine — declarative rules that modify HTTP "
            "requests and responses flowing through the proxy. "
            "Rules live in layered config (global and/or project). "
            "Default: engine on, no rules (traffic unmodified)."
        ),
    )
    sub = parser.add_subparsers(dest="http_command")

    p_list = sub.add_parser("list", help="List effective HTTP rules (all layers).")
    add_format_argument(p_list)
    p_list.add_argument(
        "--direction",
        choices=["request", "response", "both"],
        help="Filter by direction.",
    )
    p_list.add_argument(
        "--layer",
        choices=["default", "global", "project", "cli"],
        help="Show only rules from one layer.",
    )
    p_list.add_argument(
        "--enabled-only",
        action="store_true",
        help="Hide disabled rules.",
    )

    p_show = sub.add_parser("show", help="Show one rule by id (or unique prefix).")
    p_show.add_argument("id", help="Rule UUID or unique prefix.")
    add_format_argument(p_show)

    p_create = sub.add_parser(
        "create",
        help="Create a rule in project (or --global) config.",
    )
    p_create.add_argument("--name", required=True, help="Human-readable rule name.")
    p_create.add_argument("--description", default="", help="Optional description.")
    p_create.add_argument(
        "--direction",
        choices=["request", "response", "both"],
        default="request",
        help="Which half of the HTTP exchange (default: request).",
    )
    p_create.add_argument(
        "--priority",
        type=int,
        default=100,
        help="Execution order (lower first; default 100).",
    )
    p_create.add_argument(
        "--disabled",
        action="store_true",
        help="Create the rule disabled.",
    )
    p_create.add_argument(
        "--scope",
        choices=["global", "project", "endpoint"],
        help="Optional scope label (endpoint scoping is via --match-*).",
    )
    p_create.add_argument("--match-host", action="append", default=[], help="Match host (repeatable).")
    p_create.add_argument("--match-path", action="append", default=[], help="Match path glob (repeatable).")
    p_create.add_argument("--match-path-prefix", action="append", default=[], dest="match_path_prefix")
    p_create.add_argument("--match-method", action="append", default=[], help="Match HTTP method.")
    p_create.add_argument("--match-status", action="append", default=[], type=int, help="Match response status.")
    p_create.add_argument("--match-content-type", action="append", default=[], dest="match_content_type")
    p_create.add_argument("--match-header-exists", action="append", default=[], dest="match_header_exists")
    p_create.add_argument("--match-endpoint-id", action="append", default=[], dest="match_endpoint_id")
    p_create.add_argument(
        "--match-role", action="append", default=[], dest="match_role", help="Match role name."
    )
    p_create.add_argument(
        "--match-module", action="append", default=[], dest="match_module", help="Match module name."
    )
    p_create.add_argument(
        "--action",
        action="append",
        default=[],
        dest="actions",
        help=(
            "Compact action spec (repeatable). Examples: "
            "header.remove:If-None-Match, header.replace:User-Agent=Talos, "
            "status.override:200, delay:500, drop"
        ),
    )
    p_create.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Store in global config.yaml instead of project.yaml.",
    )

    p_update = sub.add_parser(
        "update",
        help="Replace fields on an existing rule (name, match, actions, …).",
    )
    p_update.add_argument("id", help="Rule UUID or unique prefix.")
    p_update.add_argument("--name", help="New display name.")
    p_update.add_argument("--description", help="New description (empty string clears).")
    p_update.add_argument(
        "--direction",
        choices=["request", "response", "both"],
        help="Which half of the HTTP exchange.",
    )
    p_update.add_argument("--priority", type=int, help="Execution order (lower first).")
    p_update.add_argument(
        "--enabled",
        choices=["true", "false"],
        help="Enable or disable the rule.",
    )
    p_update.add_argument("--match-host", action="append", default=[], help="Match host (repeatable).")
    p_update.add_argument("--match-path", action="append", default=[], help="Match path glob (repeatable).")
    p_update.add_argument(
        "--match-path-prefix", action="append", default=[], dest="match_path_prefix"
    )
    p_update.add_argument("--match-method", action="append", default=[], help="Match HTTP method.")
    p_update.add_argument(
        "--match-status", action="append", default=[], type=int, help="Match response status."
    )
    p_update.add_argument(
        "--match-content-type", action="append", default=[], dest="match_content_type"
    )
    p_update.add_argument(
        "--match-header-exists", action="append", default=[], dest="match_header_exists"
    )
    p_update.add_argument(
        "--match-endpoint-id", action="append", default=[], dest="match_endpoint_id"
    )
    p_update.add_argument(
        "--match-role", action="append", default=[], dest="match_role", help="Match role name."
    )
    p_update.add_argument(
        "--match-module", action="append", default=[], dest="match_module", help="Match module name."
    )
    p_update.add_argument(
        "--clear-match",
        action="store_true",
        help="Clear all match conditions (always match for direction).",
    )
    p_update.add_argument(
        "--action",
        action="append",
        default=None,
        dest="actions",
        help="Replace entire action list (repeatable compact specs). Omit to keep actions.",
    )
    p_update.add_argument(
        "--clear-actions",
        action="store_true",
        help="Remove all actions (rule becomes a no-op until actions are added).",
    )
    p_update.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Update in global config.yaml (default: project).",
    )

    p_delete = sub.add_parser("delete", help="Delete a rule from its owning layer.")
    p_delete.add_argument("id", help="Rule UUID or unique prefix.")
    p_delete.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Delete from global layer (default: project).",
    )
    add_force_argument(p_delete)

    for name, help_text in (
        ("enable", "Enable a rule."),
        ("disable", "Disable a rule without deleting it."),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("id", help="Rule UUID or unique prefix.")
        p.add_argument("--global", dest="global_scope", action="store_true")

    p_pri = sub.add_parser("set-priority", help="Change rule priority.")
    p_pri.add_argument("id", help="Rule UUID or unique prefix.")
    p_pri.add_argument("priority", type=int, help="New priority (lower runs first).")
    p_pri.add_argument("--global", dest="global_scope", action="store_true")

    p_match = sub.add_parser("set-match", help="Set or merge match conditions on a rule.")
    p_match.add_argument("id", help="Rule UUID or unique prefix.")
    p_match.add_argument("--host", action="append", default=[])
    p_match.add_argument("--path", action="append", default=[])
    p_match.add_argument("--path-prefix", action="append", default=[], dest="path_prefix")
    p_match.add_argument("--method", action="append", default=[])
    p_match.add_argument("--status", action="append", default=[], type=int)
    p_match.add_argument("--content-type", action="append", default=[], dest="content_type")
    p_match.add_argument("--header-exists", action="append", default=[], dest="header_exists")
    p_match.add_argument("--endpoint-id", action="append", default=[], dest="endpoint_id")
    p_match.add_argument(
        "--replace",
        action="store_true",
        help="Replace entire match object instead of merging.",
    )
    p_match.add_argument("--global", dest="global_scope", action="store_true")

    p_cm = sub.add_parser("clear-match", help="Clear all match conditions (rule always matches).")
    p_cm.add_argument("id")
    p_cm.add_argument("--global", dest="global_scope", action="store_true")

    p_aa = sub.add_parser("add-action", help="Append an action to a rule.")
    p_aa.add_argument("id")
    p_aa.add_argument(
        "action",
        help="Compact action spec (see: talos config http actions).",
    )
    p_aa.add_argument("--global", dest="global_scope", action="store_true")

    p_ra = sub.add_parser("remove-action", help="Remove action by 0-based index.")
    p_ra.add_argument("id")
    p_ra.add_argument("index", type=int, help="0-based action index.")
    p_ra.add_argument("--global", dest="global_scope", action="store_true")

    p_re = sub.add_parser(
        "reorder",
        help="Rewrite priorities to 100,200,300… in current list order.",
    )
    p_re.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Reorder global layer rules only (default: project).",
    )

    p_ex = sub.add_parser("export", help="Export rules as YAML or JSON.")
    add_format_argument(p_ex)
    p_ex.add_argument(
        "--layer",
        choices=["effective", "global", "project"],
        default="effective",
        help="Which rules to export (default: effective).",
    )
    p_ex.add_argument("-o", "--output", help="Write to file instead of stdout.")

    p_im = sub.add_parser("import", help="Import rules from a YAML/JSON file into a layer.")
    p_im.add_argument("file", help="Path to YAML or JSON file (list of rules or {rules: [...]}).")
    p_im.add_argument(
        "--replace",
        action="store_true",
        help="Replace layer rules instead of appending.",
    )
    p_im.add_argument("--global", dest="global_scope", action="store_true")
    add_force_argument(p_im)

    p_ee = sub.add_parser("enable-engine", help="Set http.enabled=true (master switch).")
    p_ee.add_argument("--global", dest="global_scope", action="store_true")
    p_de = sub.add_parser("disable-engine", help="Set http.enabled=false (no rules run).")
    p_de.add_argument("--global", dest="global_scope", action="store_true")

    sub.add_parser(
        "actions",
        help="List supported action opcodes and CLI compact forms.",
    )

    return parser


# ------------------------------------------------------------------ #
# Commands                                                             #
# ------------------------------------------------------------------ #


def cmd_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """List effective rules with optional filters."""
    cfg_mgr, project, effective = _load(manager)
    rules = list(effective.http.rules)
    if getattr(args, "direction", None):
        d = args.direction
        rules = [r for r in rules if r.get("direction") == d or r.get("direction") == "both"]
    if getattr(args, "layer", None):
        rules = [r for r in rules if r.get("source") == args.layer]
    if getattr(args, "enabled_only", False):
        rules = [r for r in rules if r.get("enabled", True)]

    if wants_json(args):
        cli_json(
            {
                "enabled": effective.http.enabled,
                "rules": rules,
                "count": len(rules),
            }
        )
        return

    print(f"HTTP Manipulation Engine: {'enabled' if effective.http.enabled else 'DISABLED'}")
    print(f"{len(rules)} rule(s)\n")
    if not rules:
        print("No HTTP rules configured. Traffic is not modified.")
        print("Create one: talos config http create --name '…' --action header.replace:X-Foo=bar")
        return
    for rule in rules:
        _print_rule_summary(rule)


def cmd_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Show one rule in detail."""
    _, _, effective = _load(manager)
    try:
        rule = find_rule(list(effective.http.rules), args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found.")
        return
    if wants_json(args):
        cli_json(rule)
        return
    _print_rule_detail(rule)


def cmd_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Create a new rule in project or global layer."""
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)

    match: dict[str, Any] = {}
    if args.match_host:
        match["host"] = args.match_host if len(args.match_host) > 1 else args.match_host[0]
    if args.match_path:
        match["path"] = args.match_path if len(args.match_path) > 1 else args.match_path[0]
    if args.match_path_prefix:
        match["path_prefix"] = (
            args.match_path_prefix
            if len(args.match_path_prefix) > 1
            else args.match_path_prefix[0]
        )
    if args.match_method:
        match["method"] = args.match_method if len(args.match_method) > 1 else args.match_method[0]
    if args.match_status:
        match["status_code"] = (
            args.match_status if len(args.match_status) > 1 else args.match_status[0]
        )
    if args.match_content_type:
        match["content_type"] = (
            args.match_content_type
            if len(args.match_content_type) > 1
            else args.match_content_type[0]
        )
    if args.match_header_exists:
        match["header_exists"] = args.match_header_exists
    if args.match_endpoint_id:
        match["endpoint_id"] = (
            args.match_endpoint_id
            if len(args.match_endpoint_id) > 1
            else args.match_endpoint_id[0]
        )
    if getattr(args, "match_role", None):
        match["role"] = (
            args.match_role if len(args.match_role) > 1 else args.match_role[0]
        )
    if getattr(args, "match_module", None):
        match["module"] = (
            args.match_module if len(args.match_module) > 1 else args.match_module[0]
        )

    actions: list[dict[str, Any]] = []
    try:
        for spec in args.actions or []:
            actions.append(parse_action_cli(spec))
        rule = normalize_rule(
            {
                "id": new_rule_id(),
                "name": args.name,
                "description": args.description or "",
                "enabled": not bool(args.disabled),
                "priority": int(args.priority),
                "direction": args.direction,
                "scope": args.scope
                or ("global" if global_scope else "project"),
                "match": match,
                "actions": actions,
            }
        )
    except HttpRuleError as exc:
        cli_usage_error(str(exc))
        return

    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    layer_rules.append(rule)
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule create {rule['id']}")

    print(f"Created HTTP rule: {rule['id']}")
    print(f"  name     : {rule['name']}")
    print(f"  direction: {rule['direction']}")
    print(f"  priority : {rule['priority']}")
    print(f"  layer    : {'global' if global_scope else 'project'}")
    print(f"  actions  : {len(rule['actions'])}")


def cmd_update(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Replace selected fields on an existing rule in project or global layer.
        Match is replaced wholesale when any --match-* or --clear-match is set.
        Actions are replaced when --action is provided or --clear-actions is set.
    Side effects: Writes YAML; may notify proxy.
    """
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)

    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(
            f"HTTP rule '{args.id}' not found in "
            f"{'global' if global_scope else 'project'} layer. "
            "Use --global if the rule lives in global config."
        )
        return

    target = None
    for r in layer_rules:
        if r["id"] == rule["id"]:
            target = r
            break
    if target is None:
        cli_error(f"HTTP rule '{args.id}' not found.")
        return

    try:
        if args.name is not None:
            name = str(args.name).strip()
            if not name:
                cli_usage_error("--name cannot be empty.")
                return
            target["name"] = name
        if args.description is not None:
            target["description"] = str(args.description)
        if args.direction is not None:
            target["direction"] = args.direction
        if args.priority is not None:
            target["priority"] = int(args.priority)
        if args.enabled is not None:
            target["enabled"] = args.enabled == "true"

        match_touched = bool(args.clear_match) or any(
            (
                args.match_host,
                args.match_path,
                args.match_path_prefix,
                args.match_method,
                args.match_status,
                args.match_content_type,
                args.match_header_exists,
                args.match_endpoint_id,
                getattr(args, "match_role", None),
                getattr(args, "match_module", None),
            )
        )
        if match_touched:
            if args.clear_match:
                target["match"] = {}
            else:
                match: dict[str, Any] = {}
                if args.match_host:
                    match["host"] = (
                        args.match_host if len(args.match_host) > 1 else args.match_host[0]
                    )
                if args.match_path:
                    match["path"] = (
                        args.match_path if len(args.match_path) > 1 else args.match_path[0]
                    )
                if args.match_path_prefix:
                    match["path_prefix"] = (
                        args.match_path_prefix
                        if len(args.match_path_prefix) > 1
                        else args.match_path_prefix[0]
                    )
                if args.match_method:
                    match["method"] = (
                        args.match_method
                        if len(args.match_method) > 1
                        else args.match_method[0]
                    )
                if args.match_status:
                    match["status_code"] = (
                        args.match_status
                        if len(args.match_status) > 1
                        else args.match_status[0]
                    )
                if args.match_content_type:
                    match["content_type"] = (
                        args.match_content_type
                        if len(args.match_content_type) > 1
                        else args.match_content_type[0]
                    )
                if args.match_header_exists:
                    match["header_exists"] = args.match_header_exists
                if args.match_endpoint_id:
                    match["endpoint_id"] = (
                        args.match_endpoint_id
                        if len(args.match_endpoint_id) > 1
                        else args.match_endpoint_id[0]
                    )
                if getattr(args, "match_role", None):
                    match["role"] = (
                        args.match_role if len(args.match_role) > 1 else args.match_role[0]
                    )
                if getattr(args, "match_module", None):
                    match["module"] = (
                        args.match_module
                        if len(args.match_module) > 1
                        else args.match_module[0]
                    )
                target["match"] = normalize_match(match)

        if args.clear_actions:
            target["actions"] = []
        elif args.actions is not None:
            target["actions"] = [parse_action_cli(spec) for spec in args.actions]

        # Re-normalize full rule for validation.
        normalized = normalize_rule(target, default_source=target.get("source"))
        target.clear()
        target.update(normalized)
    except HttpRuleError as exc:
        cli_usage_error(str(exc))
        return

    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule update {target['id']}")
    print(f"Updated HTTP rule: {target['id']}")
    print(f"  name     : {target['name']}")
    print(f"  direction: {target['direction']}")
    print(f"  priority : {target['priority']}")
    print(f"  enabled  : {target.get('enabled', True)}")
    print(f"  actions  : {len(target.get('actions') or [])}")


def cmd_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Delete a rule from project or global layer."""
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)

    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(
            f"HTTP rule '{args.id}' not found in "
            f"{'global' if global_scope else 'project'} layer. "
            "Use --global if the rule lives in global config."
        )
        return

    confirm_or_exit(
        f"Delete HTTP rule '{rule['name']}' ({rule['id'][:8]}…)?",
        force=bool(getattr(args, "force", False)),
    )
    new_rules = [r for r in layer_rules if r["id"] != rule["id"]]
    _write_layer_rules(cfg_mgr, project, global_scope, new_rules)
    _notify_proxy(project, f"http rule delete {rule['id']}")
    print(f"Deleted HTTP rule: {rule['id']}")


def cmd_enable(manager: ProjectManager, args: argparse.Namespace) -> None:
    _set_enabled(manager, args, True)


def cmd_disable(manager: ProjectManager, args: argparse.Namespace) -> None:
    _set_enabled(manager, args, False)


def _set_enabled(manager: ProjectManager, args: argparse.Namespace, enabled: bool) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return
    for r in layer_rules:
        if r["id"] == rule["id"]:
            r["enabled"] = enabled
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule {'enable' if enabled else 'disable'} {rule['id']}")
    print(f"{'Enabled' if enabled else 'Disabled'} HTTP rule: {rule['id']}")


def cmd_set_priority(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return
    for r in layer_rules:
        if r["id"] == rule["id"]:
            r["priority"] = int(args.priority)
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule priority {rule['id']}")
    print(f"Updated priority for {rule['id']}: {args.priority}")


def cmd_set_match(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return

    patch: dict[str, Any] = {}
    if args.host:
        patch["host"] = args.host if len(args.host) > 1 else args.host[0]
    if args.path:
        patch["path"] = args.path if len(args.path) > 1 else args.path[0]
    if args.path_prefix:
        patch["path_prefix"] = (
            args.path_prefix if len(args.path_prefix) > 1 else args.path_prefix[0]
        )
    if args.method:
        patch["method"] = args.method if len(args.method) > 1 else args.method[0]
    if args.status:
        patch["status_code"] = args.status if len(args.status) > 1 else args.status[0]
    if args.content_type:
        patch["content_type"] = (
            args.content_type if len(args.content_type) > 1 else args.content_type[0]
        )
    if args.header_exists:
        patch["header_exists"] = args.header_exists
    if args.endpoint_id:
        patch["endpoint_id"] = (
            args.endpoint_id if len(args.endpoint_id) > 1 else args.endpoint_id[0]
        )

    if not patch and not args.replace:
        cli_usage_error("Provide at least one match field, or --replace with fields.")

    for r in layer_rules:
        if r["id"] == rule["id"]:
            if args.replace:
                r["match"] = normalize_match(patch)
            else:
                merged = dict(r.get("match") or {})
                merged.update(patch)
                r["match"] = normalize_match(merged)
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule match {rule['id']}")
    print(f"Updated match conditions for {rule['id']}")


def cmd_clear_match(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return
    for r in layer_rules:
        if r["id"] == rule["id"]:
            r["match"] = {}
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule clear-match {rule['id']}")
    print(f"Cleared match conditions for {rule['id']} (matches all traffic).")


def cmd_add_action(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
        action = parse_action_cli(args.action)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return
    for r in layer_rules:
        if r["id"] == rule["id"]:
            r.setdefault("actions", []).append(action)
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule add-action {rule['id']}")
    print(f"Added action {action['op']} to {rule['id']}")


def cmd_remove_action(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
    try:
        rule = find_rule(layer_rules, args.id)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return
    if rule is None:
        cli_error(f"HTTP rule '{args.id}' not found in target layer.")
        return
    for r in layer_rules:
        if r["id"] == rule["id"]:
            actions = r.get("actions") or []
            if args.index < 0 or args.index >= len(actions):
                cli_error(
                    f"Action index {args.index} out of range (0..{len(actions) - 1})."
                )
                return
            removed = actions.pop(args.index)
            print(f"Removed action [{args.index}] {removed.get('op')} from {rule['id']}")
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, f"http rule remove-action {rule['id']}")


def cmd_reorder(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Rewrite priorities to 100, 200, 300… preserving current sort order."""
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    layer_rules = sort_rules(_read_layer_rules(cfg_mgr, project, global_scope))
    for i, rule in enumerate(layer_rules):
        rule["priority"] = (i + 1) * 100
    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, "http rules reorder")
    print(f"Reordered {len(layer_rules)} rule(s) in {'global' if global_scope else 'project'} layer.")


def cmd_export(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, effective = _load(manager)
    layer = getattr(args, "layer", "effective")
    if layer == "effective":
        rules = rules_for_storage(list(effective.http.rules))
    elif layer == "global":
        rules = rules_for_storage(_read_layer_rules(cfg_mgr, project, True))
    else:
        if project is None:
            cli_precondition_error(NO_ACTIVE_PROJECT_HINT)
            return
        rules = rules_for_storage(_read_layer_rules(cfg_mgr, project, False))

    payload = {
        "http": {
            "enabled": effective.http.enabled,
            "rules": rules,
        }
    }
    fmt = getattr(args, "format", "table")
    if fmt == "json" or wants_json(args):
        text = json.dumps(payload, indent=2)
    else:
        text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)

    out = getattr(args, "output", None)
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"Exported {len(rules)} rule(s) to {out}")
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def cmd_import(manager: ProjectManager, args: argparse.Namespace) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)

    path = Path(args.file)
    if not path.exists():
        cli_error(f"File not found: {path}")
        return
    raw_text = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(raw_text)
        else:
            data = yaml.safe_load(raw_text)
    except Exception as exc:
        cli_error(f"Failed to parse {path}: {exc}")
        return

    if isinstance(data, dict):
        if "rules" in data:
            raw_rules = data["rules"]
        elif "http" in data and isinstance(data["http"], dict):
            raw_rules = data["http"].get("rules") or []
        else:
            cli_error("Import file must be a list of rules or {rules: [...]} / {http: {rules: [...]}}.")
            return
    elif isinstance(data, list):
        raw_rules = data
    else:
        cli_error("Import file must be a list or mapping.")
        return

    try:
        imported = parse_rules(raw_rules)
    except HttpRuleError as exc:
        cli_error(str(exc))
        return

    if args.replace:
        confirm_or_exit(
            f"Replace all rules in {'global' if global_scope else 'project'} layer "
            f"with {len(imported)} imported rule(s)?",
            force=bool(getattr(args, "force", False)),
        )
        layer_rules = imported
    else:
        layer_rules = _read_layer_rules(cfg_mgr, project, global_scope)
        existing_ids = {r["id"] for r in layer_rules}
        for rule in imported:
            if rule["id"] in existing_ids:
                rule["id"] = new_rule_id()
            layer_rules.append(rule)

    _write_layer_rules(cfg_mgr, project, global_scope, layer_rules)
    _notify_proxy(project, "http rules import")
    print(
        f"Imported {len(imported)} rule(s) into "
        f"{'global' if global_scope else 'project'} layer "
        f"({'replace' if args.replace else 'append'})."
    )


def cmd_enable_engine(manager: ProjectManager, args: argparse.Namespace) -> None:
    _set_engine(manager, args, True)


def cmd_disable_engine(manager: ProjectManager, args: argparse.Namespace) -> None:
    _set_engine(manager, args, False)


def _set_engine(manager: ProjectManager, args: argparse.Namespace, enabled: bool) -> None:
    cfg_mgr, project, _ = _load(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    _require_scope(project, global_scope)
    try:
        cfg_mgr.set_value(
            "http.enabled",
            enabled,
            global_scope=global_scope,
            project_data_dir=Path(project.data_dir) if project and not global_scope else None,
            project_db_path=project.db_path if project and not global_scope else None,
        )
    except ConfigError as exc:
        cli_error(str(exc))
        return
    _notify_proxy(project, f"http.enabled={enabled}")
    print(f"HTTP Manipulation Engine {'enabled' if enabled else 'disabled'}.")


def cmd_actions_help(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Print supported action opcodes and compact CLI forms."""
    print("Supported action ops:\n")
    for op in sorted(ACTION_OPS):
        print(f"  {op}")
    print(
        "\nCompact CLI forms for --action / add-action:\n"
        "  header.remove:Name\n"
        "  header.add:Name=Value\n"
        "  header.replace:Name=Value\n"
        "  header.rename:Old->New\n"
        "  cookie.remove:Name\n"
        "  cookie.replace:Name=Value\n"
        "  query.add:Name=Value | query.remove:Name | query.replace:Name=Value\n"
        "  method.replace:POST\n"
        "  url.host:evil.example\n"
        "  url.path:/new/path\n"
        "  body.append:suffix | body.prepend:prefix\n"
        "  body.regex_replace:pattern=>replacement\n"
        "  status.override:403\n"
        "  delay:500          (milliseconds)\n"
        "  drop | abort\n"
    )


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _load(manager: ProjectManager):
    from talos.config import TalosConfig

    config = TalosConfig.from_env()
    # Prefer ProjectManager root when available.
    data_dir = getattr(manager, "_root", None)
    if data_dir is not None:
        # manager._root is projects dir
        data_dir = Path(data_dir).parent
    else:
        data_dir = config.data_dir
    cfg_mgr = ConfigurationManager(data_dir)
    project = manager.active()
    if project is not None:
        effective = cfg_mgr.load_for_project(project)
    else:
        effective = cfg_mgr.load()
    return cfg_mgr, project, effective


def _require_scope(project, global_scope: bool) -> None:
    if not global_scope and project is None:
        cli_precondition_error(NO_ACTIVE_PROJECT_HINT)


def _read_layer_rules(
    cfg_mgr: ConfigurationManager,
    project,
    global_scope: bool,
) -> list[dict[str, Any]]:
    try:
        layer = cfg_mgr.get_layer(
            global_scope=global_scope,
            project_data_dir=Path(project.data_dir) if project and not global_scope else None,
        )
    except ConfigError as exc:
        cli_error(str(exc))
        return []
    raw = get_path(layer, "http.rules", []) or []
    try:
        return parse_rules(raw)
    except HttpRuleError as exc:
        cli_error(f"Corrupt http.rules in layer: {exc}")
        return []


def _write_layer_rules(
    cfg_mgr: ConfigurationManager,
    project,
    global_scope: bool,
    rules: list[dict[str, Any]],
) -> None:
    stored = rules_for_storage(rules)
    try:
        cfg_mgr.set_value(
            "http.rules",
            stored,
            global_scope=global_scope,
            project_data_dir=Path(project.data_dir) if project and not global_scope else None,
            project_db_path=project.db_path if project and not global_scope else None,
        )
    except ConfigError as exc:
        cli_error(str(exc))


def _notify_proxy(project, reason: str) -> None:
    if project is None:
        return
    try:
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(project.id, reason)
    except Exception:
        pass


def _print_rule_summary(rule: dict[str, Any]) -> None:
    status = "on " if rule.get("enabled", True) else "off"
    source = rule.get("source") or "?"
    actions = rule.get("actions") or []
    match = rule.get("match") or {}
    match_bits = []
    if match.get("host"):
        match_bits.append(f"host={match['host']}")
    if match.get("path"):
        match_bits.append(f"path={match['path']}")
    if match.get("method"):
        match_bits.append(f"method={match['method']}")
    if match.get("endpoint_id"):
        match_bits.append(f"endpoint={match['endpoint_id']}")
    match_s = ", ".join(match_bits) if match_bits else "all"
    print(
        f"  {rule['id'][:8]}…  [{status}]  prio={rule.get('priority', 100):<4}  "
        f"{rule.get('direction', 'request'):<8}  {source:<8}  {rule.get('name')}"
    )
    print(f"           match: {match_s}  actions: {len(actions)}")


def _print_rule_detail(rule: dict[str, Any]) -> None:
    print(f"id        : {rule.get('id')}")
    print(f"name      : {rule.get('name')}")
    print(f"description: {rule.get('description') or '(none)'}")
    print(f"enabled   : {rule.get('enabled', True)}")
    print(f"priority  : {rule.get('priority', 100)}")
    print(f"direction : {rule.get('direction')}")
    print(f"scope     : {rule.get('scope') or '(unset)'}")
    print(f"source    : {rule.get('source') or '?'}")
    print(f"match     : {yaml.safe_dump(rule.get('match') or {}, default_flow_style=True).strip()}")
    actions = rule.get("actions") or []
    print(f"actions   : {len(actions)}")
    for i, action in enumerate(actions):
        print(f"  [{i}] {yaml.safe_dump(action, default_flow_style=True).strip()}")
