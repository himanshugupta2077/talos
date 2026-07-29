"""
Module: talos.error_intel.detectors.orchestrator

Purpose:
    Run Error Intelligence detector stages A–G on a decoded response and
    return structured matches + disclosure artifacts.

    Stage order (specific → structural → generic):
        A  StackTraceDetector
        B  DatabaseErrorDetector
        C  FrameworkErrorDetector
        D  InfrastructureErrorDetector
        E  SecurityErrorDetector
        F  DisclosureExtractor  (always on 5xx or after primary hit)
        G  HttpGenericDetector  (only if no stronger hit, policy-gated)

    Pure relative to DB/network.  No Findings.  No normalize/fingerprint
    (Phase 4) or severity scoring (Phase 3) here — those consume matches.

Dependencies:
    detectors.{stack_trace, database, framework, infrastructure,
               security, disclosure, http_generic, base},
    config, constants, models
Data flow:
    body/text → ErrorDetectResult(matches, artifacts, primary, …)
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Union

from talos.error_intel.config import ErrorIntelConfig, default_config
from talos.error_intel.constants import (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
    DETECTOR_FAMILIES,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_DISCLOSURE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_HTTP,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_STACK,
)
from talos.error_intel.detectors.base import decode_body_text
from talos.error_intel.detectors.database import DatabaseErrorDetector
from talos.error_intel.detectors.disclosure import DisclosureExtractor
from talos.error_intel.detectors.framework import FrameworkErrorDetector
from talos.error_intel.detectors.http_generic import HttpGenericDetector
from talos.error_intel.detectors.infrastructure import InfrastructureErrorDetector
from talos.error_intel.detectors.security import SecurityErrorDetector
from talos.error_intel.detectors.stack_trace import StackTraceDetector
from talos.error_intel.models import ErrorArtifact, RawErrorMatch

# Specificity rank for primary selection (higher = more specific).
_FAMILY_RANK: dict[str, int] = {
    DETECTOR_FAMILY_STACK: 100,
    DETECTOR_FAMILY_DATABASE: 90,
    DETECTOR_FAMILY_FRAMEWORK: 70,
    DETECTOR_FAMILY_SECURITY: 60,
    DETECTOR_FAMILY_INFRA: 50,
    DETECTOR_FAMILY_DISCLOSURE: 40,
    DETECTOR_FAMILY_HTTP: 10,
}

_CONF_RANK: dict[str, int] = {
    CONFIDENCE_CONFIRMED_PATTERN: 40,
    CONFIDENCE_HIGH: 30,
    CONFIDENCE_MEDIUM: 20,
    CONFIDENCE_WEAK: 10,
}

# Families considered "strong" (suppress Stage G when present).
_STRONG_FAMILIES = frozenset({
    DETECTOR_FAMILY_STACK,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_INFRA,
})

# Bare web-server / app-server default status pages (nginx/Apache/IIS/Tomcat/
# Jetty chrome). Alone they are treated like Stage G generics: only kept when
# store_generic_http_errors is true OR status is 5xx OR a deeper signal
# (stack / DB / security / non-default framework) is also present.
# See architecture: "404 default pages — only stored if store_generic…".
_DEFAULT_SERVER_PAGE_DETECTORS = frozenset({
    "infra_nginx",
    "infra_apache",
    "infra_iis",
    "infra_nginx_header",
    "fw_tomcat",
    "fw_jetty",
})


@dataclass
class ErrorDetectResult:
    """
    Purpose:
        Bundle of detector outputs for one response (Phase 2 contract).

    Fields:
        matches      — all RawErrorMatch hits (stages A–G that fired)
        artifacts    — disclosure artifacts (paths/hosts/versions/…)
        primary      — highest-specificity match (cluster seed for Phase 4)
        text         — decoded body text that was scanned (may be truncated)
        status_code  — echo of input status
        detectors_fired — ordered unique detector_id list
        strong_hit   — True when a non-generic stage fired
    """

    matches: list[RawErrorMatch] = field(default_factory=list)
    artifacts: list[ErrorArtifact] = field(default_factory=list)
    primary: Optional[RawErrorMatch] = None
    text: str = ""
    status_code: Optional[int] = None
    detectors_fired: list[str] = field(default_factory=list)
    strong_hit: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize for tests / debug. Side effects: None."""
        return {
            "match_count": len(self.matches),
            "artifact_count": len(self.artifacts),
            "primary_detector": self.primary.detector_id if self.primary else None,
            "primary_family": self.primary.family if self.primary else None,
            "primary_exception": self.primary.exception_type if self.primary else None,
            "detectors_fired": list(self.detectors_fired),
            "strong_hit": self.strong_hit,
            "status_code": self.status_code,
            "families": sorted({m.family for m in self.matches}),
        }


class ErrorDetectorOrchestrator:
    """
    Purpose:
        Own detector instances and run stages A–G on a response body.
    """

    def __init__(
        self,
        config: Optional[ErrorIntelConfig] = None,
        *,
        max_matches_per_stage: int = 12,
        max_total_matches: int = 40,
    ) -> None:
        self.config = config if config is not None else default_config()
        cap = max(1, int(max_matches_per_stage))
        self._max_total = max(1, int(max_total_matches))
        self.stack = StackTraceDetector(max_matches=cap)
        self.database = DatabaseErrorDetector(max_matches=cap)
        self.framework = FrameworkErrorDetector(max_matches=cap)
        self.infrastructure = InfrastructureErrorDetector(max_matches=cap)
        self.security = SecurityErrorDetector(max_matches=cap)
        self.disclosure = DisclosureExtractor(max_matches=cap)
        self.http_generic = HttpGenericDetector(max_matches=min(5, cap))

    def detect(
        self,
        body: Optional[Union[str, bytes]] = None,
        *,
        text: Optional[str] = None,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, Any]] = None,
        content_type: Optional[str] = None,
    ) -> ErrorDetectResult:
        """
        Purpose:
            Run stages A–G on a response and return ErrorDetectResult.
        Input:
            body — raw body (str/bytes); ignored if text is provided
            text — pre-decoded scan text
            status_code / headers / content_type — context for stages D–G
        Output:
            ErrorDetectResult (may have empty matches)
        Side effects: None.
        """
        hdr_map = _normalize_headers(headers)
        if text is not None:
            scan_text = text
        else:
            scan_text = decode_body_text(
                body,
                max_bytes=max(1, int(self.config.max_body_scan)),
            )

        result = ErrorDetectResult(text=scan_text, status_code=status_code)
        if not scan_text and not hdr_map and status_code is None:
            return result

        matches: list[RawErrorMatch] = []
        ctx = dict(
            status_code=status_code,
            headers=hdr_map or None,
            content_type=content_type,
        )

        # Stage A — stack traces
        matches.extend(self.stack.detect(scan_text, **ctx))
        # Stage B — database
        if len(matches) < self._max_total:
            matches.extend(self.database.detect(scan_text, **ctx))
        # Stage C — framework
        if len(matches) < self._max_total:
            matches.extend(self.framework.detect(scan_text, **ctx))
        # Stage D — infrastructure
        if len(matches) < self._max_total:
            matches.extend(self.infrastructure.detect(scan_text, **ctx))
        # Stage E — security
        if len(matches) < self._max_total:
            matches.extend(self.security.detect(scan_text, **ctx))

        is_5xx = _is_5xx(status_code)
        allow_generic = bool(self.config.store_generic_http_errors) or is_5xx

        # BUG-02: bare nginx/Apache/Tomcat/IIS default pages are not "strong"
        # under default config — same storage policy as Stage G. Keep them
        # only when store_generic is on, status is 5xx, or a deeper signal
        # (stack/DB/security/non-default framework/infra) also fired.
        matches = _apply_default_page_policy(matches, allow_generic=allow_generic)

        strong = any(m.family in _STRONG_FAMILIES for m in matches)
        result.strong_hit = strong

        # Stage F — disclosure (always on 5xx or when primary/strong hit)
        disc_matches, artifacts = self.disclosure.extract(
            scan_text,
            status_code=status_code,
            headers=hdr_map or None,
            content_type=content_type,
            force=is_5xx or strong,
            has_primary_error=strong,
        )
        result.artifacts = artifacts
        if len(matches) < self._max_total:
            matches.extend(disc_matches)

        # Stage G — generic HTTP only when no strong stage hit AND
        # (store_generic_http_errors OR status is 5xx). Disclosure-only is
        # not "strong"; those matches are kept, but Stage G still policy-gated.
        if not strong and len(matches) < self._max_total:
            if allow_generic:
                matches.extend(self.http_generic.detect(scan_text, **ctx))

        if len(matches) > self._max_total:
            matches = matches[: self._max_total]

        result.matches = matches
        result.primary = pick_primary_match(matches)
        result.detectors_fired = _unique_detector_ids(matches)
        # Recompute strong after all stages
        result.strong_hit = any(m.family in _STRONG_FAMILIES for m in matches)
        return result


def detect_errors(
    body: Optional[Union[str, bytes]] = None,
    *,
    text: Optional[str] = None,
    status_code: Optional[int] = None,
    headers: Optional[Mapping[str, Any]] = None,
    content_type: Optional[str] = None,
    config: Optional[ErrorIntelConfig] = None,
) -> ErrorDetectResult:
    """
    Purpose:
        Module-level convenience wrapper around ErrorDetectorOrchestrator.
    Side effects: None.
    """
    return ErrorDetectorOrchestrator(config=config).detect(
        body,
        text=text,
        status_code=status_code,
        headers=headers,
        content_type=content_type,
    )


def pick_primary_match(matches: list[RawErrorMatch]) -> Optional[RawErrorMatch]:
    """
    Purpose:
        Choose the highest-specificity / highest-confidence match as the
        primary cluster seed (Phase 3–4 will refine).
    Side effects: None.
    """
    if not matches:
        return None

    def _key(m: RawErrorMatch) -> tuple[int, int, int]:
        fam = _FAMILY_RANK.get(m.family, 0)
        conf = _CONF_RANK.get(m.confidence, 0)
        # Prefer matches that extracted an exception_type
        has_exc = 1 if m.exception_type else 0
        return (fam, conf, has_exc)

    return max(matches, key=_key)


def _unique_detector_ids(matches: list[RawErrorMatch]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in matches:
        if m.detector_id not in seen:
            seen.add(m.detector_id)
            out.append(m.detector_id)
    return out


def _normalize_headers(
    headers: Optional[Mapping[str, Any]],
) -> dict[str, str]:
    if not headers:
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k is None or v is None:
            continue
        out[str(k)] = str(v)
    return out


def _is_5xx(status_code: Optional[int]) -> bool:
    if status_code is None:
        return False
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return False
    return 500 <= code <= 599


def _is_default_server_page(match: RawErrorMatch) -> bool:
    """True when match is bare nginx/Apache/IIS/Tomcat/Jetty status chrome."""
    return (match.detector_id or "") in _DEFAULT_SERVER_PAGE_DETECTORS


def _apply_default_page_policy(
    matches: list[RawErrorMatch],
    *,
    allow_generic: bool,
) -> list[RawErrorMatch]:
    """
    Purpose:
        Drop bare server default-page hits unless generic storage is allowed
        or a deeper (non-default-page) strong signal is also present.

    Side effects: None (returns a new list).
    """
    if not matches:
        return matches
    deep = [m for m in matches if not _is_default_server_page(m)]
    bare = [m for m in matches if _is_default_server_page(m)]
    if not bare:
        return matches
    if deep:
        # Stack / DB / security / real framework / non-default infra keep
        # the default-page matches as secondary tech tags.
        return matches
    if allow_generic:
        return matches
    # Bare 4xx (or unknown status) default pages only — suppress flood.
    return []


# Silence unused import warning for DETECTOR_FAMILIES (useful for external checks)
_ = DETECTOR_FAMILIES
