"""
Module: talos.burp.trace

Purpose:
    Structured grouping metadata attached to flow_meta['burp'] so the
    replay/attack engines can emit HTTP headers and the Burp extension
    can rebuild:

        <engine>
          <endpoint label>   e.g. GET /api/users/{id}

Dependencies: dataclasses, urllib.parse
Data flow: engine send → attach_burp_trace → flow_meta['burp'] → headers
Side effects: Mutates the supplied flow_meta dict in place.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

ENGINE_INPUT_VALIDATION = "input-validation"
ENGINE_UNAUTH = "unauth"
ENGINE_BAC = "bac"
ENGINE_AUTH_SESSION = "auth-session"
ENGINE_CORS = "cors"
ENGINE_SQLI = "sqli"
ENGINE_XSS = "xss"
ENGINE_PATH_TRAVERSAL = "path-traversal"
ENGINE_SSRF = "ssrf"
ENGINE_OPEN_REDIRECT = "open-redirect"
ENGINE_HOST_HEADER = "host-header"
ENGINE_SMUGGLE = "smuggle"
ENGINE_INTRUDER = "intruder"
ENGINE_PASSIVE = "passive"
ENGINE_ERROR_INTEL = "error-intel"
ENGINE_FINDINGS = "findings"

GROUP_ENDPOINTS = "endpoints"

ENGINE_LABELS: dict[str, str] = {
    ENGINE_FINDINGS: "Findings",
    ENGINE_INPUT_VALIDATION: "Input Validation",
    ENGINE_UNAUTH: "Unauthenticated Execution",
    ENGINE_BAC: "BAC",
    ENGINE_AUTH_SESSION: "Auth-Session Testing",
    ENGINE_CORS: "CORS Misconfiguration",
    ENGINE_SQLI: "SQL Injection",
    ENGINE_XSS: "XSS",
    ENGINE_PATH_TRAVERSAL: "Path Traversal",
    ENGINE_SSRF: "SSRF",
    ENGINE_OPEN_REDIRECT: "Open Redirect",
    ENGINE_HOST_HEADER: "Host Header Injection",
    ENGINE_SMUGGLE: "HTTP Request Smuggling",
    ENGINE_INTRUDER: "Intruder",
    ENGINE_PASSIVE: "Secret Detection",
    ENGINE_ERROR_INTEL: "Error Intelligence",
}

GROUP_LABELS: dict[str, str] = {
    GROUP_ENDPOINTS: "Endpoints",
}

_DETAIL_KEYS: tuple[str, ...] = (
    "analysis",
    "param",
    "location",
    "payload_type",
    "technique",
    "variant",
    "auth_type",
    "test_id",
    "origin",
    "attempt",
)


@dataclass(frozen=True)
class BurpTrace:
    """
    Purpose:
        One request's place in the Burp tree plus optional probe detail.
    Fields:
        engine          — stable token (input-validation, unauth, …).
        group           — grouping dimension (endpoints; not shown in tree).
        endpoint_id     — Talos endpoint UUID when known.
        endpoint_label  — display path (METHOD + normalized path).
        host            — hostname[:port], never a URL.
        engine_label    — human label for the engine node.
        group_label     — human label for the group (unused in the tree).
        extras          — optional probe fields (param, analysis, technique…).
        project_id      — Talos project slug; gates the Burp tab.
        project_name    — display name for the Burp picker / banner.
        record_id       — stable row id shared by snapshot + ingest.
    """

    engine: str
    group: str
    endpoint_label: str
    host: str = ""
    endpoint_id: str = ""
    engine_label: str = ""
    group_label: str = ""
    extras: dict[str, str] = field(default_factory=dict)
    project_id: str = ""
    project_name: str = ""
    record_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """
        Purpose:
            Serialize into flow_meta['burp'].
        Output:
            JSON-safe dict.
        Side effects: None.
        """
        payload: dict[str, Any] = {
            "engine": self.engine,
            "group": self.group,
            "endpoint_label": self.endpoint_label,
            "host": self.host,
            "endpoint_id": self.endpoint_id,
            "engine_label": self.engine_label or ENGINE_LABELS.get(self.engine, ""),
            "group_label": self.group_label or GROUP_LABELS.get(self.group, ""),
            "project_id": self.project_id,
            "project_name": self.project_name,
            "record_id": self.record_id,
        }
        if self.extras:
            payload["extras"] = dict(self.extras)
        return payload


def endpoint_label(method: str, path: str) -> str:
    """
    Purpose:
        Build the tree leaf label used in Burp (and X-Talos-Endpoint).
    Input:
        method — HTTP method (GET, POST, …).
        path   — normalized_path when available, else raw path.
    Output:
        "METHOD /path" (empty method/path collapsed safely).
    Side effects: None.
    """
    verb = (method or "").strip().upper() or "GET"
    route = (path or "").strip() or "/"
    if not route.startswith("/"):
        route = "/" + route
    return f"{verb} {route}"


def normalize_host(value: object) -> str:
    """
    Purpose:
        Collapse a host / origin / URL to hostname[:port].
    Input:
        value — host string or URL (e.g. http://myapp.local:3000).
    Output:
        netloc when parseable, else the original stripped token.
    Side effects: None.
    """
    text = _clean(value)
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        if parsed.netloc:
            return parsed.netloc
    return text.split("/")[0]


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _detail_from_extras(extras: Mapping[str, str]) -> str:
    if extras.get("detail"):
        return extras["detail"]
    parts = [extras[key] for key in _DETAIL_KEYS if extras.get(key)]
    return " · ".join(parts)


def attach_burp_trace(
    flow_meta: dict,
    *,
    engine: str,
    flow: Mapping[str, Any],
    endpoint_id: str = "",
    host: str = "",
    extras: Optional[Mapping[str, Any]] = None,
    group: str = GROUP_ENDPOINTS,
    project_id: str = "",
    project_name: str = "",
    record_id: str = "",
    tree_label: str = "",
) -> dict:
    """
    Purpose:
        Stamp engine/endpoint grouping onto flow_meta['burp'].
    Input:
        flow_meta   — existing metadata dict (mutated in place).
        engine      — stable engine token.
        flow        — request fields (method, path, normalized_path, host).
        endpoint_id — Talos endpoint UUID.
        host        — hostname or origin (normalized).
        extras       — optional probe fields.
        group        — grouping token (default endpoints).
        project_id   — Talos project slug (flow['project_id'] used when empty).
        project_name — display name.
        record_id    — stable row id; generated when omitted.
        tree_label   — override for the mid-level tree node (Findings groups).
    Output:
        The same flow_meta dict.
    Side effects: Writes flow_meta['burp'].
    """
    method = _clean(flow.get("method"))
    path = _clean(flow.get("normalized_path")) or _clean(flow.get("path"))
    resolved_host = normalize_host(host or flow.get("host"))
    resolved_id = _clean(endpoint_id) or _clean(flow.get("endpoint_id"))
    cleaned_extras: dict[str, str] = {}
    if extras:
        for key, value in extras.items():
            text = _clean(value)
            if text:
                cleaned_extras[str(key)] = text
    detail = _detail_from_extras(cleaned_extras)
    if detail:
        cleaned_extras["detail"] = detail
    token = _clean(engine) or ENGINE_INPUT_VALIDATION
    grp = _clean(group) or GROUP_ENDPOINTS
    pid = _clean(project_id) or _clean(flow.get("project_id"))
    pname = _clean(project_name) or _clean(flow.get("project_name"))
    rid = _clean(record_id) or str(uuid.uuid4())
    label = _clean(tree_label) or endpoint_label(method, path)
    trace = BurpTrace(
        engine=token,
        group=grp,
        endpoint_label=label,
        host=resolved_host,
        endpoint_id=resolved_id,
        engine_label=ENGINE_LABELS.get(token, ""),
        group_label=GROUP_LABELS.get(grp, ""),
        extras=cleaned_extras,
        project_id=pid,
        project_name=pname,
        record_id=rid,
    )
    flow_meta["burp"] = trace.to_dict()
    return flow_meta


def attach_iv_burp_trace(
    flow_meta: dict,
    *,
    flow: Mapping[str, Any],
    endpoint_id: str = "",
    host: str = "",
    parameter_name: str = "",
    location: str = "",
    analysis: str = "",
    payload_type: str = "",
    project_id: str = "",
    project_name: str = "",
) -> dict:
    """
    Purpose:
        Stamp Input Validation grouping onto flow_meta['burp'].
    Input:
        flow_meta      — existing IV flow_meta (mutated in place).
        flow           — base/mutated flow with method/path/normalized_path.
        endpoint_id    — Talos endpoint UUID.
        host           — hostname or origin.
        parameter_name — probe parameter.
        location       — query/body/header/cookie/path.
        analysis       — IV analysis phase.
        payload_type   — probe payload type.
        project_id     — Talos project slug.
        project_name   — display name.
    Output:
        The same flow_meta dict.
    Side effects: Writes flow_meta['burp'].
    """
    extras = {
        "param": parameter_name,
        "location": location,
        "analysis": analysis,
        "payload_type": payload_type,
    }
    return attach_burp_trace(
        flow_meta,
        engine=ENGINE_INPUT_VALIDATION,
        flow=flow,
        endpoint_id=endpoint_id,
        host=host,
        extras=extras,
        project_id=project_id,
        project_name=project_name,
    )


def trace_from_flow_meta(flow_meta: Optional[Mapping[str, Any]]) -> Optional[BurpTrace]:
    """
    Purpose:
        Parse a BurpTrace from flow_meta['burp'] when present and valid.
    Input:
        flow_meta — stored/in-flight flow metadata, or None.
    Output:
        BurpTrace, or None when the block is missing/invalid.
    Side effects: None.
    """
    if not flow_meta:
        return None
    raw = flow_meta.get("burp")
    if not isinstance(raw, Mapping):
        return None
    engine = _clean(raw.get("engine"))
    group = _clean(raw.get("group"))
    label = _clean(raw.get("endpoint_label"))
    if not engine or not group or not label:
        return None
    extras_raw = raw.get("extras") if isinstance(raw.get("extras"), Mapping) else {}
    extras = {
        str(key): _clean(value)
        for key, value in extras_raw.items()
        if _clean(value)
    }
    return BurpTrace(
        engine=engine,
        group=group,
        endpoint_label=label,
        host=normalize_host(raw.get("host")),
        endpoint_id=_clean(raw.get("endpoint_id")),
        engine_label=_clean(raw.get("engine_label")) or ENGINE_LABELS.get(engine, ""),
        group_label=_clean(raw.get("group_label")) or GROUP_LABELS.get(group, ""),
        extras=extras,
        project_id=_clean(raw.get("project_id")),
        project_name=_clean(raw.get("project_name")),
        record_id=_clean(raw.get("record_id")),
    )
