"""
Module: talos.xss.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the XSS / HTML injection engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_XSS = "XSS"
"""Probe reflected a JS execution sink (script, event handler, javascript:)."""

VERDICT_HTMLI = "HTMLI"
"""Probe reflected raw HTML markup without a confirmed JS sink."""

VERDICT_SECURE = "SECURE"
"""No raw XSS / HTMLI signal on this probe (missing or encoded only)."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

XSS_VERDICTS: tuple[str, ...] = (
    VERDICT_XSS,
    VERDICT_HTMLI,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "xss"
"""Findings attack_module label (cluster XSS:<endpoint_id>)."""

CANARY = "TalosXss"
"""Unique marker embedded in every payload so reflection is unambiguous."""

FAMILY_HTML_TAG = "html_tag"
FAMILY_HTMLI = "htmli"
FAMILY_HTML_ATTR = "html_attr"
FAMILY_EVENT = "event"
FAMILY_JS = "js"
FAMILY_URL = "url"
FAMILY_ENCODED = "encoded"
FAMILY_BYPASS = "bypass"
FAMILY_POLYGLOT = "polyglot"

FAMILIES: tuple[str, ...] = (
    FAMILY_HTML_TAG,
    FAMILY_HTMLI,
    FAMILY_HTML_ATTR,
    FAMILY_EVENT,
    FAMILY_JS,
    FAMILY_URL,
    FAMILY_ENCODED,
    FAMILY_BYPASS,
    FAMILY_POLYGLOT,
)

RISK_XSS = "xss"
RISK_HTMLI = "htmli"

RISK_CLASSES: tuple[str, ...] = (RISK_XSS, RISK_HTMLI)

CONTEXT_HTML_BODY = "html_body"
CONTEXT_HTML_ATTR = "html_attr"
CONTEXT_SCRIPT = "script"
CONTEXT_COMMENT = "comment"
CONTEXT_STYLE = "style"
CONTEXT_URL = "url"
CONTEXT_JSON = "json"
CONTEXT_GENERIC = "generic"

INJECT_REPLACE = "replace"
INJECT_APPEND = "append"

INJECT_MODES: tuple[str, ...] = (INJECT_REPLACE, INJECT_APPEND)


@dataclass(frozen=True)
class XssPayload:
    """
    Purpose:
        One XSS / HTMLI payload to send in a captured field.

    Fields:
        technique    — unique id (job meta / results).
        family       — html_tag | htmli | html_attr | event | js | url |
                       encoded | bypass | polyglot.
        payload      — string written into the field (replace) or appended
                       after the original (append).
        description  — one-line operator explanation.
        risk_class   — xss (JS sink) | htmli (markup only).
        context      — intended breakout context.
        inject_mode  — append (default) | replace.
        canary       — reflection marker (default TalosXss).
    """

    technique: str
    family: str
    payload: str
    description: str
    risk_class: str = RISK_XSS
    context: str = CONTEXT_HTML_BODY
    inject_mode: str = INJECT_APPEND
    canary: str = CANARY

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "risk_class": self.risk_class,
            "context": self.context,
            "inject_mode": self.inject_mode,
            "canary": self.canary,
        }


@dataclass(frozen=True)
class InjectionPoint:
    """
    Purpose:
        One mutable field on a captured request.

    Fields:
        location         — query | body | path.
        name             — query key, form field, JSON path, path param,
                           or multipart field name.
        original         — captured string value.
        surface_kind     — query | json_body | form_body | path |
                           multipart_filename.
        path_index       — path segment index when location=path.
        normalized_path  — endpoint ``/users/{id}`` template when known.
    """

    location: str
    name: str
    original: str
    surface_kind: str
    path_index: Optional[int] = None
    normalized_path: str = ""

    def to_dict(self) -> dict:
        """Purpose: JSON-ready injection point. Output: dict."""
        out = {
            "location": self.location,
            "name": self.name,
            "original": self.original,
            "surface_kind": self.surface_kind,
        }
        if self.path_index is not None:
            out["path_index"] = self.path_index
        if self.normalized_path:
            out["normalized_path"] = self.normalized_path
        return out


@dataclass
class XssOutcome:
    """
    Purpose:
        Result of one XSS / HTMLI probe (one unique replay flow).
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    endpoint_id: Optional[str]
    host: str
    method: str
    path: str
    technique: str
    technique_family: str
    location: str
    param_name: str
    payload_sent: str
    original_value: str
    original_status: Optional[int]
    replay_status: Optional[int]
    elapsed_ms: Optional[int]
    context_hint: Optional[str]
    encoding_hint: Optional[str]
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)
