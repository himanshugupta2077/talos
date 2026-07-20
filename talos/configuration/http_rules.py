"""
Module: talos.configuration.http_rules

Purpose:
    Rule model, validation, matching helpers, and layer-scoped CRUD for the
    HTTP Manipulation Engine. Rules live in layered configuration under
    ``http.rules`` (global ``config.yaml`` and/or project ``project.yaml``).

    Effective rules are the concatenation of rules from every layer
    (defaults → global → project → CLI), sorted by priority ascending.
    Empty match conditions mean "always match" for the rule's direction.

Dependencies: copy, fnmatch, re, uuid, typing
Data flow:
    YAML layers → normalize_rule / parse_rules → EffectiveConfig.http.rules
    CLI CRUD → mutate layer list → save_yaml_file
Side effects:
    CRUD helpers write YAML via ConfigurationManager.set_value.
"""

from __future__ import annotations

import fnmatch
import re
import uuid
from copy import deepcopy
from typing import Any, MutableMapping, Optional

# Directions accepted on a rule.
DIRECTIONS = frozenset({"request", "response", "both"})

# Supported action opcodes. Request-only and response-only are enforced at
# apply time; unknown ops raise ValueError at validate time.
ACTION_OPS = frozenset(
    {
        # Headers
        "header.add",
        "header.remove",
        "header.replace",
        "header.rename",
        # Cookies (request Cookie / response Set-Cookie)
        "cookie.add",
        "cookie.remove",
        "cookie.replace",
        # Query string (request only)
        "query.add",
        "query.remove",
        "query.replace",
        # URL / method (request only)
        "url.host",
        "url.path",
        "method.replace",
        # Body
        "body.regex_replace",
        "body.append",
        "body.prepend",
        # Response status
        "status.override",
        # Transport
        "delay",
        "drop",
        "abort",
    }
)

# Ops that only make sense on the request half.
REQUEST_ONLY_OPS = frozenset(
    {
        "query.add",
        "query.remove",
        "query.replace",
        "url.host",
        "url.path",
        "method.replace",
    }
)

# Ops that only make sense on the response half.
RESPONSE_ONLY_OPS = frozenset(
    {
        "status.override",
    }
)


class HttpRuleError(ValueError):
    """
    Purpose:
        Validation or CRUD failure for HTTP rules.
    """


def new_rule_id() -> str:
    """
    Purpose: Allocate a stable UUID for a new rule.
    Side effects: None.
    """
    return str(uuid.uuid4())


def empty_match() -> dict[str, Any]:
    """
    Purpose: Return an empty match-condition dict (matches everything).
    Side effects: None.
    """
    return {}


def normalize_action(raw: Any) -> dict[str, Any]:
    """
    Purpose:
        Coerce a raw action mapping into a validated dict with ``op`` set.
    Input:
        raw — mapping with at least ``op`` (or legacy ``type``).
    Output:
        Normalized action dict.
    Side effects: None.
    Raises:
        HttpRuleError on missing/unknown op.
    """
    if not isinstance(raw, dict):
        raise HttpRuleError(f"Action must be a mapping, got {type(raw).__name__}")
    op = raw.get("op") or raw.get("type")
    if not op or not isinstance(op, str):
        raise HttpRuleError("Action requires string field 'op'")
    op = op.strip().lower()
    if op not in ACTION_OPS:
        raise HttpRuleError(
            f"Unknown action op '{op}'. Supported: {', '.join(sorted(ACTION_OPS))}"
        )
    action = {k: v for k, v in raw.items() if k not in ("type",)}
    action["op"] = op
    _validate_action_fields(action)
    return action


def _validate_action_fields(action: dict[str, Any]) -> None:
    """
    Purpose: Enforce required fields per action op.
    Side effects: None.
    """
    op = action["op"]
    if op in (
        "header.add",
        "header.remove",
        "header.replace",
        "cookie.add",
        "cookie.remove",
        "cookie.replace",
        "query.add",
        "query.remove",
        "query.replace",
    ):
        if not action.get("name"):
            raise HttpRuleError(f"Action {op} requires 'name'")
    if op in (
        "header.add",
        "header.replace",
        "cookie.add",
        "cookie.replace",
        "query.add",
        "query.replace",
        "url.host",
        "url.path",
        "method.replace",
        "body.append",
        "body.prepend",
    ):
        if "value" not in action or action["value"] is None:
            raise HttpRuleError(f"Action {op} requires 'value'")
    if op == "header.rename":
        if not action.get("from") or not action.get("to"):
            raise HttpRuleError("Action header.rename requires 'from' and 'to'")
    if op == "body.regex_replace":
        if not action.get("pattern"):
            raise HttpRuleError("Action body.regex_replace requires 'pattern'")
        if "replacement" not in action:
            raise HttpRuleError("Action body.regex_replace requires 'replacement'")
        try:
            re.compile(str(action["pattern"]))
        except re.error as exc:
            raise HttpRuleError(f"Invalid regex pattern: {exc}") from exc
    if op == "status.override":
        try:
            code = int(action.get("value"))
        except (TypeError, ValueError) as exc:
            raise HttpRuleError("Action status.override requires integer 'value'") from exc
        if code < 100 or code > 599:
            raise HttpRuleError(f"Invalid HTTP status code: {code}")
    if op == "delay":
        ms = action.get("ms", action.get("value"))
        try:
            ms_i = int(ms)
        except (TypeError, ValueError) as exc:
            raise HttpRuleError("Action delay requires integer 'ms'") from exc
        if ms_i < 0:
            raise HttpRuleError("Action delay ms must be >= 0")
        action["ms"] = ms_i


def normalize_match(raw: Any) -> dict[str, Any]:
    """
    Purpose:
        Normalize match conditions; drop empty values.
    Input:
        raw — mapping or None.
    Output:
        Clean match dict.
    Side effects: None.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise HttpRuleError(f"match must be a mapping, got {type(raw).__name__}")
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        out[str(key)] = value
    # Normalize common aliases
    if "methods" in out and "method" not in out:
        out["method"] = out.pop("methods")
    if "status_codes" in out and "status_code" not in out:
        out["status_code"] = out.pop("status_codes")
    return out


def normalize_rule(raw: Any, *, default_source: Optional[str] = None) -> dict[str, Any]:
    """
    Purpose:
        Validate and normalize a single rule dict for storage / runtime.
    Input:
        raw            — rule mapping from YAML or CLI.
        default_source — optional source label injected when absent.
    Output:
        Normalized rule (always has id, name, enabled, priority, direction,
        match, actions).
    Side effects: None.
    Raises:
        HttpRuleError on invalid structure.
    """
    if not isinstance(raw, dict):
        raise HttpRuleError(f"Rule must be a mapping, got {type(raw).__name__}")

    rule_id = raw.get("id") or new_rule_id()
    name = (raw.get("name") or "").strip() or f"rule-{str(rule_id)[:8]}"
    description = str(raw.get("description") or "")
    enabled = bool(raw.get("enabled", True))
    try:
        priority = int(raw.get("priority", 100))
    except (TypeError, ValueError) as exc:
        raise HttpRuleError(f"Rule priority must be an integer: {raw.get('priority')!r}") from exc

    direction = str(raw.get("direction") or "request").strip().lower()
    if direction not in DIRECTIONS:
        raise HttpRuleError(
            f"Invalid direction '{direction}'. Use request, response, or both."
        )

    match = normalize_match(raw.get("match"))
    actions_raw = raw.get("actions") or []
    if not isinstance(actions_raw, list):
        raise HttpRuleError("Rule 'actions' must be a list")
    actions = [normalize_action(a) for a in actions_raw]

    rule: dict[str, Any] = {
        "id": str(rule_id),
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "direction": direction,
        "match": match,
        "actions": actions,
    }
    # Optional scope label for operator clarity (global|project|endpoint).
    # Endpoint scoping is expressed via match (path/host/endpoint_id).
    scope = raw.get("scope")
    if scope:
        rule["scope"] = str(scope)
    if default_source is not None:
        rule["source"] = default_source
    elif "source" in raw:
        rule["source"] = raw["source"]
    return rule


def parse_rules(
    raw_list: Any,
    *,
    source: Optional[str] = None,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Parse a list of raw rule mappings into normalized rules.
    Input:
        raw_list — list from YAML or empty.
        source   — layer label stamped onto each rule (runtime only).
    Output:
        List of normalized rule dicts.
    Side effects: None.
    """
    if raw_list is None:
        return []
    if not isinstance(raw_list, list):
        raise HttpRuleError("http.rules must be a list of rule objects")
    return [normalize_rule(item, default_source=source) for item in raw_list]


def rules_for_storage(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Purpose:
        Strip runtime-only fields (source) before writing YAML.
    Side effects: None.
    """
    stored: list[dict[str, Any]] = []
    for rule in rules:
        item = deepcopy(rule)
        item.pop("source", None)
        # Omit empty description / match for tidy YAML
        if not item.get("description"):
            item.pop("description", None)
        if not item.get("match"):
            item["match"] = {}
        stored.append(item)
    return stored


def sort_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Purpose:
        Sort rules by priority ascending, then name, then id (stable).
    Side effects: None.
    """
    return sorted(
        rules,
        key=lambda r: (int(r.get("priority", 100)), str(r.get("name", "")), str(r.get("id", ""))),
    )


def merge_rule_layers(
    *layers: tuple[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """
    Purpose:
        Concatenate rule lists from multiple layers, stamp source, sort.
        Later layers do not replace earlier ones — all rules apply.
        Duplicate ids across layers: both kept (ids should be unique;
        operators should not reuse ids across scopes).
    Input:
        layers — (source_label, rules) pairs in precedence order
                 (defaults first, CLI last).
    Output:
        Sorted combined rule list with ``source`` set on each rule.
    Side effects: None.
    """
    combined: list[dict[str, Any]] = []
    for source, rules in layers:
        for rule in rules:
            item = deepcopy(rule)
            item["source"] = source
            combined.append(item)
    return sort_rules(combined)


def find_rule(rules: list[dict[str, Any]], rule_id: str) -> Optional[dict[str, Any]]:
    """
    Purpose:
        Find a rule by full UUID or unique prefix.
    Output:
        Rule dict or None. Raises HttpRuleError if prefix is ambiguous.
    Side effects: None.
    """
    needle = rule_id.strip().lower()
    if not needle:
        return None
    exact = [r for r in rules if str(r.get("id", "")).lower() == needle]
    if exact:
        return exact[0]
    prefix = [r for r in rules if str(r.get("id", "")).lower().startswith(needle)]
    if len(prefix) == 1:
        return prefix[0]
    if len(prefix) > 1:
        raise HttpRuleError(
            f"Ambiguous rule id prefix '{rule_id}' matches {len(prefix)} rules."
        )
    return None


def rule_applies_to_direction(rule: dict[str, Any], direction: str) -> bool:
    """
    Purpose:
        Return True when the rule should be evaluated for request or response.
    Side effects: None.
    """
    d = str(rule.get("direction", "request")).lower()
    if d == "both":
        return True
    return d == direction


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _as_int_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in _as_str_list(value):
        try:
            result.append(int(item))
        except ValueError:
            continue
    return result


def match_host(pattern: str, host: str) -> bool:
    """
    Purpose:
        Match host: exact (case-insensitive), suffix ``.example.com``,
        or fnmatch glob (``*.example.com``).
    Side effects: None.
    """
    host_l = (host or "").lower().rstrip(".")
    pat = (pattern or "").lower().rstrip(".")
    if not pat:
        return True
    if pat.startswith("*."):
        suffix = pat[1:]  # .example.com
        return host_l == pat[2:] or host_l.endswith(suffix)
    if "*" in pat or "?" in pat:
        return fnmatch.fnmatch(host_l, pat)
    if pat.startswith("."):
        return host_l.endswith(pat) or host_l == pat[1:]
    return host_l == pat


def match_path(pattern: str, path: str) -> bool:
    """
    Purpose:
        Match path with fnmatch (``/api/*``) or exact string.
    Side effects: None.
    """
    path_v = path or "/"
    pat = pattern or ""
    if not pat:
        return True
    if "*" in pat or "?" in pat or "[" in pat:
        return fnmatch.fnmatch(path_v, pat)
    return path_v == pat or path_v.startswith(pat.rstrip("/") + "/") and pat.endswith("/")


def rule_matches(
    rule: dict[str, Any],
    *,
    direction: str,
    method: str = "",
    host: str = "",
    path: str = "",
    url: str = "",
    status_code: Optional[int] = None,
    headers: Optional[MutableMapping[str, str]] = None,
    content_type: str = "",
    endpoint_id: Optional[str] = None,
    role_id: Optional[str] = None,
    module_id: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
) -> bool:
    """
    Purpose:
        Evaluate whether all match conditions on a rule succeed for the
        current HTTP message and Talos context.
    Input:
        rule / direction / HTTP fields / optional Talos context keys.
    Output:
        True when the rule should fire.
    Side effects: None.
    """
    if not rule.get("enabled", True):
        return False
    if not rule_applies_to_direction(rule, direction):
        return False

    match = rule.get("match") or {}
    if not match:
        return True

    headers = headers or {}
    context = context or {}

    # Host
    if "host" in match:
        hosts = _as_str_list(match["host"])
        if hosts and not any(match_host(h, host) for h in hosts):
            return False

    # Path / path_prefix
    if "path" in match:
        paths = _as_str_list(match["path"])
        if paths and not any(match_path(p, path) for p in paths):
            return False
    if "path_prefix" in match:
        prefixes = _as_str_list(match["path_prefix"])
        if prefixes and not any((path or "/").startswith(p) for p in prefixes):
            return False

    # Method
    if "method" in match:
        methods = [m.upper() for m in _as_str_list(match["method"])]
        if methods and method.upper() not in methods:
            return False

    # Status (response)
    if "status_code" in match:
        codes = _as_int_list(match["status_code"])
        if codes and (status_code is None or int(status_code) not in codes):
            return False

    # Content-Type
    if "content_type" in match:
        wanted = [c.lower() for c in _as_str_list(match["content_type"])]
        ct = (content_type or _header_get(headers, "Content-Type") or "").lower()
        if wanted and not any(w in ct for w in wanted):
            return False

    # Header exists
    if "header_exists" in match:
        names = _as_str_list(match["header_exists"])
        for name in names:
            if _header_get(headers, name) is None:
                return False

    # Header value (exact, case-sensitive on value)
    if "header_value" in match:
        hv = match["header_value"]
        if isinstance(hv, dict):
            pairs = [hv]
        elif isinstance(hv, list):
            pairs = hv
        else:
            pairs = []
        for pair in pairs:
            if not isinstance(pair, dict):
                continue
            name = pair.get("name") or pair.get("header")
            value = pair.get("value")
            if not name:
                continue
            actual = _header_get(headers, str(name))
            if actual is None or (value is not None and actual != str(value)):
                return False

    # Query parameter presence / value (request URL)
    if "query" in match or "query_param" in match:
        from urllib.parse import parse_qs, urlsplit

        qspec = match.get("query") or match.get("query_param")
        query = urlsplit(url).query if url else ""
        params = parse_qs(query, keep_blank_values=True)
        specs = qspec if isinstance(qspec, list) else [qspec]
        for spec in specs:
            if isinstance(spec, str):
                if spec not in params:
                    return False
            elif isinstance(spec, dict):
                name = str(spec.get("name") or "")
                if not name or name not in params:
                    return False
                if "value" in spec and str(spec["value"]) not in params.get(name, []):
                    return False

    # Body regex (expensive — optional)
    if "body_regex" in match:
        body = context.get("body") or ""
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = ""
        pattern = str(match["body_regex"])
        try:
            if not re.search(pattern, str(body)):
                return False
        except re.error:
            return False

    # Talos context
    if "endpoint_id" in match:
        wanted_eps = set(_as_str_list(match["endpoint_id"]))
        if wanted_eps and (endpoint_id or "") not in wanted_eps:
            return False
    if "role_id" in match:
        wanted = set(_as_str_list(match["role_id"]))
        if wanted and (role_id or context.get("role_id") or "") not in wanted:
            return False
    if "module_id" in match:
        wanted = set(_as_str_list(match["module_id"]))
        if wanted and (module_id or context.get("module_id") or "") not in wanted:
            return False
    # Boolean context flags (replay, bac, scheduler, …)
    for flag in (
        "replay",
        "passive_capture",
        "scheduler",
        "bac",
        "unauthenticated",
        "input_validation",
    ):
        if flag in match:
            expected = bool(match[flag])
            actual = bool(context.get(flag, False))
            if actual != expected:
                return False
    if "module" in match:
        # Module name (not id) — compare case-insensitively when provided.
        names = {n.lower() for n in _as_str_list(match["module"])}
        actual_name = str(context.get("module_name") or "").lower()
        if names and actual_name not in names:
            return False
    if "role" in match:
        names = {n.lower() for n in _as_str_list(match["role"])}
        actual_name = str(context.get("role_name") or "").lower()
        if names and actual_name not in names:
            return False

    return True


def _header_get(headers: MutableMapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return None


def parse_action_cli(spec: str) -> dict[str, Any]:
    """
    Purpose:
        Parse a compact CLI action string into an action dict.

        Formats:
            header.remove:Name
            header.add:Name=Value
            header.replace:Name=Value
            header.rename:Old->New
            cookie.remove:Name
            cookie.replace:Name=Value
            query.replace:Name=Value
            method.replace:POST
            url.host:evil.com
            url.path:/new
            body.append:suffix
            body.prepend:prefix
            body.regex_replace:pattern=>replacement
            status.override:403
            delay:500
            drop
            abort

    Side effects: None.
    """
    text = spec.strip()
    if not text:
        raise HttpRuleError("Empty action spec")
    lower = text.lower()
    if lower in ("drop", "abort"):
        return normalize_action({"op": lower})

    if ":" not in text:
        raise HttpRuleError(
            f"Invalid action spec '{spec}'. Expected op:args (e.g. header.remove:If-None-Match)"
        )
    op, rest = text.split(":", 1)
    op = op.strip().lower()
    rest = rest.strip()

    if op == "header.rename":
        if "->" not in rest:
            raise HttpRuleError("header.rename expects Old->New")
        old, new = rest.split("->", 1)
        return normalize_action({"op": op, "from": old.strip(), "to": new.strip()})
    if op in ("header.remove", "cookie.remove", "query.remove"):
        return normalize_action({"op": op, "name": rest})
    if op in (
        "header.add",
        "header.replace",
        "cookie.add",
        "cookie.replace",
        "query.add",
        "query.replace",
    ):
        if "=" not in rest:
            raise HttpRuleError(f"{op} expects Name=Value")
        name, value = rest.split("=", 1)
        return normalize_action({"op": op, "name": name.strip(), "value": value})
    if op in ("url.host", "url.path", "method.replace", "body.append", "body.prepend"):
        return normalize_action({"op": op, "value": rest})
    if op == "body.regex_replace":
        if "=>" not in rest:
            raise HttpRuleError("body.regex_replace expects pattern=>replacement")
        pattern, replacement = rest.split("=>", 1)
        return normalize_action(
            {"op": op, "pattern": pattern, "replacement": replacement}
        )
    if op == "status.override":
        return normalize_action({"op": op, "value": int(rest)})
    if op == "delay":
        return normalize_action({"op": op, "ms": int(rest)})
    raise HttpRuleError(f"Unsupported action op in CLI: {op}")
