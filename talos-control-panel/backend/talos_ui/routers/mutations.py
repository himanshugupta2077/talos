"""
HTTP Manipulation Engine API (legacy path prefix /api/mutations).

Purpose:
    Control Panel surface for layered ``http.rules``. All writes go through
    ``talos config http …``; reads use ``talos config http list --format json``.

Dependencies: fastapi, pydantic, json, talos_ui.cli
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from .. import cli

router = APIRouter(prefix="/api/mutations", tags=["http-rules"])


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _last_json(results) -> dict:
    """Parse JSON stdout from the last successful CLI step."""
    if not results:
        return {}
    last = results[-1]
    text = getattr(last, "stdout", None) or ""
    if not text.strip():
        if isinstance(last, dict):
            text = last.get("stdout") or ""
        else:
            d = last.to_dict() if hasattr(last, "to_dict") else {}
            text = d.get("stdout") or ""
    try:
        return json.loads(text)
    except Exception:
        return {}


def _steps(results) -> dict:
    return {"steps": [r.to_dict() if hasattr(r, "to_dict") else r for r in results]}


def _is_global_source(source: str | None) -> bool:
    return (source or "").lower() in ("global", "default")


def _action_to_cli(action: dict[str, Any] | str) -> str:
    """
    Purpose:
        Convert a structured action dict (or pass-through compact string) into
        the compact CLI form expected by ``config http create/update --action``.
    Input:
        action — mapping with ``op`` (+ fields) or a compact string.
    Output:
        Compact action string.
    Side effects: None.
    """
    if isinstance(action, str):
        return action
    op = str(action.get("op") or action.get("type") or "").strip().lower()
    if not op:
        raise ValueError("Action requires 'op'")
    if op in ("drop", "abort"):
        return op
    if op == "header.rename":
        return f"header.rename:{action.get('from')}->{action.get('to')}"
    if op in ("header.remove", "cookie.remove", "query.remove"):
        return f"{op}:{action.get('name', '')}"
    if op in (
        "header.add",
        "header.replace",
        "cookie.add",
        "cookie.replace",
        "query.add",
        "query.replace",
    ):
        return f"{op}:{action.get('name', '')}={action.get('value', '')}"
    if op in ("url.host", "url.path", "method.replace", "body.append", "body.prepend"):
        return f"{op}:{action.get('value', '')}"
    if op == "body.regex_replace":
        return (
            f"body.regex_replace:{action.get('pattern', '')}"
            f"=>{action.get('replacement', '')}"
        )
    if op == "status.override":
        return f"status.override:{action.get('value', '')}"
    if op == "delay":
        ms = action.get("ms", action.get("value", 0))
        return f"delay:{ms}"
    raise ValueError(f"Unsupported action op for CLI: {op}")


def _match_cli_flags(match: dict[str, Any] | None) -> list[str]:
    """
    Purpose:
        Build --match-* argv fragments for create/update from a match dict.
    Side effects: None.
    """
    flags: list[str] = []
    if not match:
        return flags

    def vals(key: str) -> list[str]:
        raw = match.get(key)
        if raw is None or raw == "" or raw == []:
            return []
        if isinstance(raw, list):
            return [str(v) for v in raw]
        return [str(raw)]

    for host in vals("host"):
        flags += ["--match-host", host]
    for path in vals("path"):
        flags += ["--match-path", path]
    for path in vals("path_prefix"):
        flags += ["--match-path-prefix", path]
    for method in vals("method"):
        flags += ["--match-method", method]
    for status in vals("status_code"):
        flags += ["--match-status", str(status)]
    for ct in vals("content_type"):
        flags += ["--match-content-type", ct]
    for header in vals("header_exists"):
        flags += ["--match-header-exists", header]
    for endpoint_id in vals("endpoint_id"):
        flags += ["--match-endpoint-id", endpoint_id]
    for role in vals("role"):
        flags += ["--match-role", role]
    for module in vals("module"):
        flags += ["--match-module", module]
    return flags


def _global_flag(global_scope: bool) -> list[str]:
    return ["--global"] if global_scope else []


# ------------------------------------------------------------------ #
# List / engine                                                        #
# ------------------------------------------------------------------ #


@router.get("")
def list_rules(project_id: str):
    """
    Purpose:
        List effective HTTP rules for the project (all layers).
    Output:
        { enabled, rules, count, summary } plus alias key ``mutations``.
    """
    result = cli.run_scoped(project_id, ["config", "http", "list", "--format", "json"])
    payload = _last_json(result)
    rules = payload.get("rules") or []
    enabled = payload.get("enabled", True)
    active = [r for r in rules if r.get("enabled", True)]
    request_n = sum(
        1
        for r in active
        if str(r.get("direction", "request")).lower() in ("request", "both")
    )
    response_n = sum(
        1
        for r in active
        if str(r.get("direction", "request")).lower() in ("response", "both")
    )
    disabled_n = sum(1 for r in rules if not r.get("enabled", True))
    return {
        "enabled": enabled,
        "rules": rules,
        "count": payload.get("count", len(rules)),
        "mutations": rules,
        "summary": {
            "active": len(active),
            "request": request_n,
            "response": response_n,
            "disabled": disabled_n,
            "total": len(rules),
        },
    }


class EngineBody(BaseModel):
    enabled: bool
    global_scope: bool = False


@router.post("/engine")
def set_engine(project_id: str, body: EngineBody):
    """
    Purpose:
        Toggle the HTTP Manipulation Engine master switch (http.enabled).
    """
    cmd = "enable-engine" if body.enabled else "disable-engine"
    args = ["config", "http", cmd, *_global_flag(body.global_scope)]
    results = cli.run_scoped(project_id, args)
    return _steps(results)


# ------------------------------------------------------------------ #
# Create / update                                                      #
# ------------------------------------------------------------------ #


class CreateRuleBody(BaseModel):
    """
    Create a project- or global-layer HTTP rule.

    Prefer structured ``actions`` (list of op dicts or compact strings) and
    ``match``. Legacy ``key``/``value`` still builds a header.replace action.
    """

    name: str
    direction: str = "request"
    priority: int = 50
    description: str = ""
    enabled: bool = True
    global_scope: bool = False
    match: dict[str, Any] = Field(default_factory=dict)
    actions: list[Any] = Field(default_factory=list)
    # Legacy convenience fields
    match_host: str | None = None
    match_path: str | None = None
    key: str | None = None
    value: str | None = None
    type: str | None = None  # ignored; was always "header"


@router.post("")
def create_rule(project_id: str, body: CreateRuleBody):
    """
    Purpose:
        Create an HTTP rule in project (default) or global layer.
    """
    match = dict(body.match or {})
    if body.match_host:
        match.setdefault("host", body.match_host)
    if body.match_path:
        match.setdefault("path", body.match_path)

    action_specs: list[str] = []
    try:
        for action in body.actions or []:
            action_specs.append(_action_to_cli(action))
    except ValueError as exc:
        return {"error": str(exc), "steps": []}

    if body.key and body.value is not None:
        action_specs.append(f"header.replace:{body.key}={body.value}")
    if not action_specs:
        return {
            "error": "Provide at least one action (or key/value for header.replace).",
            "steps": [],
        }

    args = [
        "config",
        "http",
        "create",
        "--name",
        body.name or (f"Header {body.key}" if body.key else "HTTP rule"),
        "--direction",
        body.direction,
        "--priority",
        str(body.priority),
    ]
    if body.description:
        args += ["--description", body.description]
    if not body.enabled:
        args.append("--disabled")
    args += _match_cli_flags(match)
    for spec in action_specs:
        args += ["--action", spec]
    args += _global_flag(body.global_scope)

    results = cli.run_scoped(project_id, args)
    return _steps(results)


class UpdateRuleBody(BaseModel):
    """Full or partial rule update. Match/actions replace when provided."""

    name: str | None = None
    description: str | None = None
    direction: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    match: Optional[dict[str, Any]] = None
    clear_match: bool = False
    actions: Optional[list[Any]] = None
    clear_actions: bool = False
    global_scope: bool = False


@router.post("/{rule_id}/update")
def update_rule(project_id: str, rule_id: str, body: UpdateRuleBody):
    """
    Purpose:
        Update fields on an existing rule via ``talos config http update``.
    """
    args = ["config", "http", "update", rule_id]
    if body.name is not None:
        args += ["--name", body.name]
    if body.description is not None:
        args += ["--description", body.description]
    if body.direction is not None:
        args += ["--direction", body.direction]
    if body.priority is not None:
        args += ["--priority", str(body.priority)]
    if body.enabled is not None:
        args += ["--enabled", "true" if body.enabled else "false"]

    if body.clear_match:
        args.append("--clear-match")
    elif body.match is not None:
        flags = _match_cli_flags(body.match)
        if flags:
            args += flags
        else:
            args.append("--clear-match")

    if body.clear_actions:
        args.append("--clear-actions")
    elif body.actions is not None:
        if not body.actions:
            args.append("--clear-actions")
        else:
            try:
                for action in body.actions:
                    args += ["--action", _action_to_cli(action)]
            except ValueError as exc:
                return {"error": str(exc), "steps": []}

    args += _global_flag(body.global_scope)
    results = cli.run_scoped(project_id, args)
    return _steps(results)


@router.delete("/{rule_id}")
def delete_rule(project_id: str, rule_id: str, global_scope: bool = False):
    args = [
        "config",
        "http",
        "delete",
        rule_id,
        "--force",
        *_global_flag(global_scope),
    ]
    results = cli.run_scoped(project_id, args)
    return _steps(results)


@router.post("/{rule_id}/enable")
def enable_rule(project_id: str, rule_id: str, global_scope: bool = False):
    args = ["config", "http", "enable", rule_id, *_global_flag(global_scope)]
    results = cli.run_scoped(project_id, args)
    return _steps(results)


@router.post("/{rule_id}/disable")
def disable_rule(project_id: str, rule_id: str, global_scope: bool = False):
    args = ["config", "http", "disable", rule_id, *_global_flag(global_scope)]
    results = cli.run_scoped(project_id, args)
    return _steps(results)


class PriorityBody(BaseModel):
    priority: int
    global_scope: bool = False


@router.post("/{rule_id}/priority")
def set_priority(project_id: str, rule_id: str, body: PriorityBody):
    args = [
        "config",
        "http",
        "set-priority",
        rule_id,
        str(body.priority),
        *_global_flag(body.global_scope),
    ]
    results = cli.run_scoped(project_id, args)
    return _steps(results)


class EditRuleBody(BaseModel):
    """Legacy edit: treat key/value as adding a header.replace action."""

    key: str | None = None
    value: str | None = None
    global_scope: bool = False


@router.post("/{rule_id}/edit")
def edit_rule(project_id: str, rule_id: str, body: EditRuleBody):
    if not body.key or body.value is None:
        return {"error": "key and value required", "steps": []}
    results = cli.run_scoped(
        project_id,
        [
            "config",
            "http",
            "add-action",
            rule_id,
            f"header.replace:{body.key}={body.value}",
            *_global_flag(body.global_scope),
        ],
    )
    return _steps(results)


@router.post("/{rule_id}/duplicate")
def duplicate_rule(project_id: str, rule_id: str, global_scope: bool = False):
    """
    Purpose:
        Duplicate a rule by reading the effective list and creating a copy in
        the same layer (project unless the source is global).
    """
    listed = cli.run_scoped(project_id, ["config", "http", "list", "--format", "json"])
    payload = _last_json(listed)
    rules = payload.get("rules") or []
    source = None
    for rule in rules:
        rid = str(rule.get("id", ""))
        if rid == rule_id or rid.startswith(rule_id):
            source = rule
            break
    if source is None:
        return {
            "error": f"Rule '{rule_id}' not found",
            "steps": [s.to_dict() for s in listed],
        }

    layer_global = global_scope or _is_global_source(source.get("source"))
    name = f"{source.get('name') or 'Rule'} (copy)"
    actions = source.get("actions") or []
    try:
        action_specs = [_action_to_cli(a) for a in actions]
    except ValueError as exc:
        return {"error": str(exc), "steps": []}
    if not action_specs:
        return {"error": "Source rule has no actions to duplicate", "steps": []}

    args = [
        "config",
        "http",
        "create",
        "--name",
        name,
        "--direction",
        str(source.get("direction") or "request"),
        "--priority",
        str(int(source.get("priority") or 50)),
    ]
    if source.get("description"):
        args += ["--description", str(source["description"])]
    if source.get("enabled") is False:
        args.append("--disabled")
    args += _match_cli_flags(source.get("match") or {})
    for spec in action_specs:
        args += ["--action", spec]
    args += _global_flag(layer_global)

    results = cli.run_scoped(project_id, args)
    return _steps(results)


# ------------------------------------------------------------------ #
# Import / export / reorder                                            #
# ------------------------------------------------------------------ #


@router.get("/export")
def export_rules(project_id: str, layer: str = "effective"):
    """
    Purpose:
        Export rules as JSON payload (same shape as CLI export --format json).
    """
    if layer not in ("effective", "global", "project"):
        layer = "effective"
    results = cli.run_scoped(
        project_id,
        ["config", "http", "export", "--format", "json", "--layer", layer],
    )
    payload = _last_json(results)
    return {
        "payload": payload,
        "steps": [r.to_dict() for r in results],
    }


class ImportBody(BaseModel):
    """Import rules from a JSON document (list, {rules}, or {http:{rules}})."""

    content: str | dict[str, Any] | list[Any]
    replace: bool = False
    global_scope: bool = False


@router.post("/import")
def import_rules(project_id: str, body: ImportBody):
    """
    Purpose:
        Import rules via temp file + ``talos config http import``.
    """
    if isinstance(body.content, str):
        text = body.content
    else:
        text = json.dumps(body.content, indent=2)

    # Flags before the file path so argparse receives them with the positional.
    args_with_flags = ["config", "http", "import"]
    if body.replace:
        args_with_flags += ["--replace", "--force"]
    args_with_flags += _global_flag(body.global_scope)

    results = cli.run_scoped_with_temp_file(
        project_id,
        args_with_flags,
        text,
        suffix=".json",
    )
    return _steps(results)


class ReorderBody(BaseModel):
    global_scope: bool = False


@router.post("/reorder")
def reorder_rules(project_id: str, body: ReorderBody | None = None):
    """
    Purpose:
        Rewrite priorities to 100,200,300… in current list order (layer-scoped).
    """
    global_scope = bool(body.global_scope) if body else False
    args = ["config", "http", "reorder", *_global_flag(global_scope)]
    results = cli.run_scoped(project_id, args)
    return _steps(results)
