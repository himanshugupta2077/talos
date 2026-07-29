"""
Module: talos.intruder.template

Purpose:
    Parse ``{{variables}}``, validate path inject gates, and implement the
    normative Phase 1 render algorithm (named inject via surface.inject_value
    then raw string replace).

Dependencies: re, copy, talos.input_validation.surface, talos.intruder.models
Data flow:
    baseline snapshot + template vars + strategy bindings → AttemptSpec
Side effects: None (pure).
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Optional

from talos.input_validation.surface import inject_value
from talos.intruder.models import (
    ERR_PATH_INJECT_UNAVAILABLE,
    LOCATION_BODY,
    LOCATION_COOKIE,
    LOCATION_HEADER,
    LOCATION_PATH,
    LOCATION_QUERY,
    LOCATION_RAW,
    AttemptSpec,
    TemplateVariable,
)

# {{name}} — simple identifier names
_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

# Named inject order (design contract).
_INJECT_ORDER = (
    LOCATION_PATH,
    LOCATION_QUERY,
    LOCATION_HEADER,
    LOCATION_COOKIE,
    LOCATION_BODY,
)


def parse_template_variables(text: str) -> list[str]:
    """Return unique {{var}} names in first-seen order from free-form text."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _VAR_RE.finditer(text or ""):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def discover_vars_from_baseline(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[bytes],
) -> list[str]:
    """Scan URL, headers, and body for {{placeholders}}."""
    chunks: list[str] = [url or ""]
    for k, v in (headers or {}).items():
        chunks.append(str(k))
        chunks.append(str(v))
    if body:
        try:
            chunks.append(body.decode("utf-8"))
        except UnicodeDecodeError:
            chunks.append(body.decode("latin-1", errors="replace"))
    text = "\n".join(chunks)
    return parse_template_variables(text)


def path_has_brace(normalized_path: str, name: str) -> bool:
    """True when normalized_path contains ``{name}`` placeholder."""
    if not normalized_path or not name:
        return False
    return "{" + name + "}" in normalized_path


def validate_path_inject(
    variables: list[TemplateVariable],
    normalized_path: str,
    *,
    strategy_bound: Optional[set[str]] = None,
) -> Optional[str]:
    """
    Return error code path_inject_unavailable if a path var lacks braces.
    Fixed-only unused path vars are still validated when strategy-bound or not fixed.
    """
    bound = strategy_bound
    for var in variables:
        if var.location != LOCATION_PATH:
            continue
        if var.is_fixed() and (bound is None or var.name not in bound):
            # Fixed path values still need inject at render time.
            pass
        name = var.inject_name()
        if not path_has_brace(normalized_path, name):
            return ERR_PATH_INJECT_UNAVAILABLE
    return None


def render_attempt(
    baseline: dict[str, Any],
    variables: list[TemplateVariable],
    strategy_vars: dict[str, str],
    *,
    attempt_index: int = 0,
    normalized_path: str = "",
    skip_auth_artifacts: bool = False,
) -> AttemptSpec:
    """
    Normative render algorithm:

    1. Start from baseline snapshot (method, url, headers, body).
    2. Build binding map: fixed_value then strategy overlay for strategy-bound.
    3. Named inject in order path→query→header→cookie→body.
    4. Raw mode: literal replace of {{name}} in url/headers/body.
    5. Strip Content-Length.
    """
    method = str(baseline.get("method") or "GET")
    url = str(baseline.get("url") or "")
    headers = deepcopy(dict(baseline.get("headers") or {}))
    # Normalize header keys/values to str.
    headers = {str(k): str(v) for k, v in headers.items()}
    body = baseline.get("body")
    if isinstance(body, str):
        body = body.encode("utf-8")
    elif body is not None and not isinstance(body, (bytes, bytearray)):
        body = bytes(body)

    # Build binding map
    bindings: dict[str, str] = {}
    var_by_name = {v.name: v for v in variables}
    for var in variables:
        if var.fixed_value is not None:
            bindings[var.name] = str(var.fixed_value)
    for name, value in strategy_vars.items():
        bindings[name] = str(value)

    # Partition
    named = [v for v in variables if v.location != LOCATION_RAW]
    raw_vars = [v for v in variables if v.location == LOCATION_RAW]

    # Named inject in deterministic location order, then name order within.
    for loc in _INJECT_ORDER:
        loc_vars = sorted(
            [v for v in named if v.location == loc],
            key=lambda v: v.name,
        )
        for var in loc_vars:
            if var.name not in bindings:
                continue
            value = bindings[var.name]
            if skip_auth_artifacts:
                from talos.input_validation.surface import is_auth_artifact
                if is_auth_artifact(
                    location=var.location,
                    name=var.inject_name(),
                    semantic_type=var.semantic_type or "",
                ):
                    continue
            url, headers, body = inject_value(
                var.location,
                var.inject_name(),
                value,
                url,
                headers,
                body,
                normalized_path=normalized_path,
                semantic_type=var.semantic_type or "",
            )

    # Raw replacements (all occurrences)
    for var in sorted(raw_vars, key=lambda v: v.name):
        if var.name not in bindings:
            continue
        value = bindings[var.name]
        placeholder = "{{" + var.name + "}}"
        # Also accept spaced form {{ name }}
        spaced = re.compile(r"\{\{\s*" + re.escape(var.name) + r"\s*\}\}")
        url = spaced.sub(value, url)
        for hk in list(headers.keys()):
            headers[hk] = spaced.sub(value, headers[hk])
            if placeholder in hk:
                new_k = spaced.sub(value, hk)
                if new_k != hk:
                    headers[new_k] = headers.pop(hk)
        if body is not None:
            try:
                text = body.decode("utf-8")
                enc = "utf-8"
            except UnicodeDecodeError:
                text = body.decode("latin-1")
                enc = "latin-1"
            text = spaced.sub(value, text)
            body = text.encode(enc)

    # Strip Content-Length so httpx recomputes
    for k in list(headers.keys()):
        if k.lower() == "content-length":
            del headers[k]

    return AttemptSpec(
        attempt_index=attempt_index,
        variables=dict(strategy_vars),
        method=method,
        url=url,
        headers=headers,
        body=body if body is None else bytes(body),
    )


def variables_from_config(config: dict[str, Any]) -> list[TemplateVariable]:
    """Parse template.variables from session config document."""
    tmpl = config.get("template") or {}
    raw = tmpl.get("variables") or []
    out: list[TemplateVariable] = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            out.append(TemplateVariable.from_dict(item))
    return out


def baseline_from_config(config: dict[str, Any]) -> dict[str, Any]:
    """Extract method/url/headers/body snapshot from config template."""
    tmpl = config.get("template") or {}
    body = tmpl.get("body")
    if isinstance(body, str):
        body_b: Optional[bytes] = body.encode("utf-8")
    elif body is None:
        body_b = None
    else:
        body_b = bytes(body) if not isinstance(body, bytes) else body
    headers = tmpl.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    return {
        "method": tmpl.get("method") or "GET",
        "url": tmpl.get("url") or "",
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": body_b,
        "normalized_path": tmpl.get("normalized_path") or "",
        "role_id": (config.get("session") or {}).get("role_id"),
        "module_id": (config.get("session") or {}).get("module_id"),
        "endpoint_id": (config.get("session") or {}).get("endpoint_id"),
        "base_flow_id": (config.get("session") or {}).get("base_flow_id"),
        "project_id": (config.get("session") or {}).get("project_id"),
    }
