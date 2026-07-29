"""
Module: talos.error_intel.classify

Purpose:
    Map detector output (RawErrorMatch + artifacts) to cluster classification
    fields: category, severity, language/framework/database/server,
    disclosure flags, confidence score, normalized message/stack, and
    fingerprint (Phases 3–4 combined consumer).

    Deterministic additive scoring → clamp 0–100 → severity bands
    (same spirit as ``talos.passive.scoring``).  No LLM.  No Findings.

Dependencies:
    dataclasses; talos.error_intel.{constants, fingerprint, models, normalize}
    talos.error_intel.detectors.orchestrator (ErrorDetectResult, pick_primary)
Data flow:
    ErrorDetectResult → ClassifiedError → (db upsert later)
Side effects: None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

from talos.error_intel.constants import (
    CATEGORY_DATABASE,
    CATEGORY_DISCLOSURE,
    CATEGORY_FRAMEWORK,
    CATEGORY_HTTP,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_SECURITY,
    CATEGORY_STACK_TRACE,
    CATEGORY_UNKNOWN,
    CATEGORY_VALIDATION,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
    DEFAULT_EVIDENCE_SNIPPET_MAX,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_DISCLOSURE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_HTTP,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_STACK,
    ERROR_INTEL_VERSION,
    LANG_UNKNOWN,
    SCORE_CRITICAL_MIN,
    SCORE_HIGH_MIN,
    SCORE_MEDIUM_MIN,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from talos.error_intel.detectors.base import normalize_exception_type
from talos.error_intel.detectors.database import vendor_from_sqlstate
from talos.error_intel.detectors.orchestrator import (
    ErrorDetectResult,
    detect_errors,
    pick_primary_match,
)
from talos.error_intel.redact import redact_error_text
from talos.error_intel.fingerprint import (
    compute_fingerprint,
    fingerprint_status_bucket,
    identity_status_bucket,
)
from talos.error_intel.models import ErrorArtifact, RawErrorMatch
from talos.error_intel.normalize import (
    extract_message_norm,
    extract_normalized_stack_from_match,
    normalize_error_text,
)

# ---------------------------------------------------------------------------
# Confidence seed → numeric base
# ---------------------------------------------------------------------------

_CONF_POINTS: dict[str, int] = {
    CONFIDENCE_CONFIRMED_PATTERN: 95,
    CONFIDENCE_HIGH: 80,
    CONFIDENCE_MEDIUM: 55,
    CONFIDENCE_WEAK: 30,
}

# Family → base severity score before boosts
_FAMILY_BASE_SCORE: dict[str, int] = {
    DETECTOR_FAMILY_STACK: 72,
    DETECTOR_FAMILY_DATABASE: 74,
    DETECTOR_FAMILY_FRAMEWORK: 55,
    DETECTOR_FAMILY_SECURITY: 48,
    DETECTOR_FAMILY_INFRA: 38,
    DETECTOR_FAMILY_DISCLOSURE: 65,
    DETECTOR_FAMILY_HTTP: 28,
}

# Family → default category
_FAMILY_CATEGORY: dict[str, str] = {
    DETECTOR_FAMILY_STACK: CATEGORY_STACK_TRACE,
    DETECTOR_FAMILY_DATABASE: CATEGORY_DATABASE,
    DETECTOR_FAMILY_FRAMEWORK: CATEGORY_FRAMEWORK,
    DETECTOR_FAMILY_SECURITY: CATEGORY_SECURITY,
    DETECTOR_FAMILY_INFRA: CATEGORY_INFRASTRUCTURE,
    DETECTOR_FAMILY_DISCLOSURE: CATEGORY_DISCLOSURE,
    DETECTOR_FAMILY_HTTP: CATEGORY_HTTP,
}

# High-value framework debug chrome (boost to high)
_DEBUG_FRAMEWORKS = frozenset({
    "werkzeug",
    "django",
    "laravel",
    "spring",  # Whitelabel alone is medium; with stack becomes high via stack
    "aspnet",
    "symfony",
    "rails",
})

# Credential / connection-string / private-key signals → critical boost
_CRITICAL_LEAK_RE = re.compile(
    r"(?i)(?:"
    r"password\s*[=:]\s*\S+|"
    r"jdbc:[a-z0-9+]+://[^\s]+|"
    r"(?:mysql|postgres|mongodb|redis)://[^\s]+:[^\s]+@|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"api[_-]?key\s*[=:]\s*[A-Za-z0-9_\-]{16,}|"
    r"secret[_-]?key\s*[=:]\s*\S+|"
    r"connectionstring\s*[=:]|"
    r"/actuator/(?:env|heapdump|configprops)"
    r")"
)

_SQL_FRAGMENT_RE = re.compile(
    r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b.{0,80}"
    r"(?:SELECT|INSERT|FROM|WHERE|INTO|VALUES)?"
)


@dataclass
class ClassifiedError:
    """
    Purpose:
        Fully classified primary error ready for fingerprint + cluster store.

    Fields map 1:1 to planned error_clusters columns (plus fingerprint inputs).
    """

    category: str
    severity: str
    severity_score: int
    language: str = LANG_UNKNOWN
    framework: Optional[str] = None
    database: Optional[str] = None
    server: Optional[str] = None
    exception_type: Optional[str] = None
    message_norm: Optional[str] = None
    technologies: list[str] = field(default_factory=list)
    has_stack_trace: bool = False
    has_path_leak: bool = False
    has_internal_host: bool = False
    has_version_leak: bool = False
    confidence: int = 0
    evidence_snippet: Optional[str] = None
    fingerprint: str = ""
    status_bucket: str = ""
    normalized_stack: str = ""
    normalized_message: str = ""
    primary: Optional[RawErrorMatch] = None
    detectors: list[str] = field(default_factory=list)
    scanner_version: str = ERROR_INTEL_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Serialize for tests / debug. Side effects: None."""
        return {
            "category": self.category,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "language": self.language,
            "framework": self.framework,
            "database": self.database,
            "server": self.server,
            "exception_type": self.exception_type,
            "message_norm": self.message_norm,
            "technologies": list(self.technologies),
            "has_stack_trace": self.has_stack_trace,
            "has_path_leak": self.has_path_leak,
            "has_internal_host": self.has_internal_host,
            "has_version_leak": self.has_version_leak,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "status_bucket": self.status_bucket,
            "detectors": list(self.detectors),
            "scanner_version": self.scanner_version,
            "primary_detector": (
                self.primary.detector_id if self.primary else None
            ),
        }


def severity_from_score(score: int) -> str:
    """
    Purpose:
        Map additive score to severity band.
    Side effects: None.
    """
    s = max(0, min(100, int(score)))
    if s >= SCORE_CRITICAL_MIN:
        return SEVERITY_CRITICAL
    if s >= SCORE_HIGH_MIN:
        return SEVERITY_HIGH
    if s >= SCORE_MEDIUM_MIN:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def confidence_from_seed(seed: Optional[str]) -> int:
    """Map RawErrorMatch.confidence seed string to 0–100. Side effects: None."""
    if not seed:
        return 30
    return _CONF_POINTS.get(str(seed), 30)


def classify_from_detect(
    result: ErrorDetectResult,
    *,
    status_code: Optional[int] = None,
    evidence_snippet_max: int = DEFAULT_EVIDENCE_SNIPPET_MAX,
) -> Optional[ClassifiedError]:
    """
    Purpose:
        Classify an ErrorDetectResult into a ClassifiedError with fingerprint.

    Input:
        result — detector orchestrator output
        status_code — override status (defaults to result.status_code)
        evidence_snippet_max — cap for evidence_snippet

    Output:
        ClassifiedError, or None when there are no matches and no
        standalone disclosure artifacts that should form a cluster.

    Side effects: None.
    """
    status = status_code if status_code is not None else result.status_code
    matches = list(result.matches or [])
    artifacts = list(result.artifacts or [])

    primary = result.primary or pick_primary_match(matches)

    # Disclosure-only path: artifacts without primary match
    if primary is None:
        if not artifacts:
            return None
        return _classify_disclosure_only(
            artifacts,
            status_code=status,
            evidence_snippet_max=evidence_snippet_max,
            detectors=list(result.detectors_fired or []),
        )

    flags = _disclosure_flags(artifacts, matches)
    has_stack = _has_stack_trace(matches, primary)
    flags["has_stack_trace"] = flags["has_stack_trace"] or has_stack

    category = _resolve_category(primary, matches)
    language = _resolve_language(primary, matches)
    framework = _resolve_framework(matches)
    database = _resolve_database(matches)
    server = _resolve_server(matches)
    exception_type = primary.exception_type
    if not exception_type:
        for m in matches:
            if m.exception_type and m.family in (
                DETECTOR_FAMILY_STACK,
                DETECTOR_FAMILY_DATABASE,
            ):
                exception_type = m.exception_type
                break
    # Canonicalize short JVM/CLR names → FQCN for fingerprint stability (BUG-04).
    exception_type = normalize_exception_type(exception_type)

    technologies = _collect_technologies(matches)
    if framework and framework not in technologies:
        technologies.append(framework)
    if database and database not in technologies:
        technologies.append(database)
    if server and server not in technologies:
        technologies.append(server)

    # Normalize + message for fingerprint
    norm_stack = extract_normalized_stack_from_match(primary)
    if not norm_stack:
        for m in matches:
            if m.family == DETECTOR_FAMILY_STACK:
                norm_stack = extract_normalized_stack_from_match(m)
                if norm_stack:
                    break

    snippet = primary.raw_snippet or ""
    message_norm = extract_message_norm(
        snippet,
        exception_type=exception_type,
    )
    # Prefer structured message from metadata when present
    meta = primary.metadata or {}
    if meta.get("message") and not message_norm:
        message_norm = extract_message_norm(str(meta["message"]))
    if meta.get("title") and not message_norm:
        message_norm = extract_message_norm(str(meta["title"]))

    score = _score_severity(
        primary=primary,
        matches=matches,
        category=category,
        has_stack=flags["has_stack_trace"],
        has_path=flags["has_path_leak"],
        has_host=flags["has_internal_host"],
        has_version=flags["has_version_leak"],
        framework=framework,
        database=database,
        status_code=status,
        evidence_text=snippet,
    )
    severity = severity_from_score(score)

    conf = confidence_from_seed(primary.confidence)
    # Slight boost when multiple strong families agree
    strong_families = {
        m.family
        for m in matches
        if m.family
        in {
            DETECTOR_FAMILY_STACK,
            DETECTOR_FAMILY_DATABASE,
            DETECTOR_FAMILY_FRAMEWORK,
            DETECTOR_FAMILY_SECURITY,
        }
    }
    if len(strong_families) >= 2:
        conf = min(100, conf + 5)

    body_error_shaped = True  # we have detector hits
    # Display / cluster status_bucket reflects the observation HTTP status.
    # Fingerprint identity drops status when exception/stack is present so
    # the same exception merges across proxy 500 / IV 400 / BAC 200 (BUG-01).
    bucket = fingerprint_status_bucket(
        status,
        body_error_shaped=body_error_shaped,
    )
    fp_bucket = identity_status_bucket(
        status,
        body_error_shaped=body_error_shaped,
        exception_type=exception_type,
        normalized_stack=norm_stack,
    )

    fp = compute_fingerprint(
        status_bucket=fp_bucket,
        category=category,
        language=language or LANG_UNKNOWN,
        exception_type=exception_type,
        framework=framework,
        database=database,
        normalized_stack=norm_stack,
        normalized_message=message_norm,
        server=server,
    )

    evidence = normalize_error_text(snippet) if snippet else None
    # BUG-12: mask credentials before persist/CLI display
    evidence = redact_error_text(evidence, max_len=evidence_snippet_max)

    detectors = list(result.detectors_fired or [])
    if not detectors:
        detectors = _unique_ids(matches)

    return ClassifiedError(
        category=category,
        severity=severity,
        severity_score=score,
        language=language or LANG_UNKNOWN,
        framework=framework,
        database=database,
        server=server,
        exception_type=exception_type,
        message_norm=message_norm or None,
        technologies=technologies,
        has_stack_trace=flags["has_stack_trace"],
        has_path_leak=flags["has_path_leak"],
        has_internal_host=flags["has_internal_host"],
        has_version_leak=flags["has_version_leak"],
        confidence=conf,
        evidence_snippet=evidence,
        fingerprint=fp,
        status_bucket=bucket,
        normalized_stack=norm_stack,
        normalized_message=message_norm,
        primary=primary,
        detectors=detectors,
        scanner_version=ERROR_INTEL_VERSION,
    )


def classify_error(
    body: Optional[Union[str, bytes]] = None,
    *,
    text: Optional[str] = None,
    status_code: Optional[int] = None,
    headers: Optional[Mapping[str, Any]] = None,
    content_type: Optional[str] = None,
    config: Any = None,
    evidence_snippet_max: int = DEFAULT_EVIDENCE_SNIPPET_MAX,
) -> Optional[ClassifiedError]:
    """
    Purpose:
        Convenience: run detectors then classify + fingerprint.
    Side effects: None.
    """
    result = detect_errors(
        body,
        text=text,
        status_code=status_code,
        headers=headers,
        content_type=content_type,
        config=config,
    )
    return classify_from_detect(
        result,
        status_code=status_code,
        evidence_snippet_max=evidence_snippet_max,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _classify_disclosure_only(
    artifacts: Sequence[ErrorArtifact],
    *,
    status_code: Optional[int],
    evidence_snippet_max: int,
    detectors: list[str],
) -> ClassifiedError:
    flags = {
        "has_stack_trace": False,
        "has_path_leak": False,
        "has_internal_host": False,
        "has_version_leak": False,
    }
    values: list[str] = []
    for a in artifacts:
        kind = (a.kind or "").lower()
        if kind == "path":
            flags["has_path_leak"] = True
        elif kind in {"host", "ip", "private_ip", "internal_host"}:
            flags["has_internal_host"] = True
        elif kind == "version":
            flags["has_version_leak"] = True
        if a.value:
            values.append(str(a.value))

    score = 50
    if flags["has_path_leak"]:
        score = 72
    elif flags["has_internal_host"]:
        score = 62
    elif flags["has_version_leak"]:
        score = 48
    severity = severity_from_score(score)

    message = extract_message_norm("; ".join(values[:4]) if values else "disclosure")
    bucket = fingerprint_status_bucket(status_code, body_error_shaped=True)
    # Disclosure-only has no exception/stack — keep status in identity.
    fp_bucket = identity_status_bucket(
        status_code,
        body_error_shaped=True,
        exception_type=None,
        normalized_stack=None,
    )
    evidence = normalize_error_text("\n".join(values[:8]))
    if evidence and len(evidence) > evidence_snippet_max:
        evidence = evidence[: evidence_snippet_max - 1] + "…"

    fp = compute_fingerprint(
        status_bucket=fp_bucket,
        category=CATEGORY_DISCLOSURE,
        language=LANG_UNKNOWN,
        exception_type=None,
        framework=None,
        database=None,
        normalized_stack="",
        normalized_message=message,
        server=None,
    )
    return ClassifiedError(
        category=CATEGORY_DISCLOSURE,
        severity=severity,
        severity_score=score,
        language=LANG_UNKNOWN,
        message_norm=message or None,
        has_path_leak=flags["has_path_leak"],
        has_internal_host=flags["has_internal_host"],
        has_version_leak=flags["has_version_leak"],
        confidence=55,
        evidence_snippet=evidence or None,
        fingerprint=fp,
        status_bucket=bucket,
        normalized_message=message,
        detectors=detectors or ["disclosure"],
    )


def _disclosure_flags(
    artifacts: Sequence[ErrorArtifact],
    matches: Sequence[RawErrorMatch],
) -> dict[str, bool]:
    flags = {
        "has_stack_trace": False,
        "has_path_leak": False,
        "has_internal_host": False,
        "has_version_leak": False,
    }
    for a in artifacts:
        kind = (a.kind or "").lower()
        if kind == "path":
            flags["has_path_leak"] = True
        elif kind in {"host", "ip", "private_ip", "internal_host"}:
            flags["has_internal_host"] = True
        elif kind == "version":
            flags["has_version_leak"] = True

    for m in matches:
        meta = m.metadata or {}
        if meta.get("has_stack_trace"):
            flags["has_stack_trace"] = True
        if m.family == DETECTOR_FAMILY_DISCLOSURE:
            kind = str(meta.get("kind") or meta.get("artifact_kind") or "").lower()
            if kind == "path" or "path" in m.detector_id:
                flags["has_path_leak"] = True
            if kind in {"host", "ip"} or "host" in m.detector_id or "ip" in m.detector_id:
                flags["has_internal_host"] = True
            if kind == "version" or "version" in m.detector_id:
                flags["has_version_leak"] = True
    return flags


def _has_stack_trace(
    matches: Sequence[RawErrorMatch],
    primary: RawErrorMatch,
) -> bool:
    if primary.family == DETECTOR_FAMILY_STACK:
        meta = primary.metadata or {}
        if meta.get("has_stack_trace") is False and not meta.get("frames"):
            # Exception class only — still count as stack_trace category
            return bool(meta.get("frames")) or "Traceback" in (primary.raw_snippet or "")
        return True
    for m in matches:
        if m.family == DETECTOR_FAMILY_STACK:
            return True
        if (m.metadata or {}).get("has_stack_trace"):
            return True
    return False


def _resolve_category(
    primary: RawErrorMatch,
    matches: Sequence[RawErrorMatch],
) -> str:
    # Prefer category_hint when valid
    hint = primary.category_hint
    if hint and hint != CATEGORY_UNKNOWN:
        # Stack primary with database secondary stays stack_trace (more specific)
        if primary.family == DETECTOR_FAMILY_STACK:
            return CATEGORY_STACK_TRACE
        if primary.family == DETECTOR_FAMILY_DATABASE:
            return CATEGORY_DATABASE
        if primary.family == DETECTOR_FAMILY_HTTP:
            # Distinguish validation vs http from hint
            if hint == CATEGORY_VALIDATION:
                return CATEGORY_VALIDATION
            return CATEGORY_HTTP
        return hint

    fam = primary.family
    if fam in _FAMILY_CATEGORY:
        cat = _FAMILY_CATEGORY[fam]
        if fam == DETECTOR_FAMILY_HTTP:
            # 4xx-ish validation
            if primary.category_hint == CATEGORY_VALIDATION:
                return CATEGORY_VALIDATION
            status = (primary.metadata or {}).get("status_code")
            try:
                if status is not None and 400 <= int(status) < 500:
                    return CATEGORY_VALIDATION
            except (TypeError, ValueError):
                pass
        return cat
    return CATEGORY_UNKNOWN


def _resolve_language(
    primary: RawErrorMatch,
    matches: Sequence[RawErrorMatch],
) -> str:
    if primary.language and primary.language != LANG_UNKNOWN:
        return primary.language
    for m in matches:
        if m.language and m.language != LANG_UNKNOWN:
            return m.language
    return LANG_UNKNOWN


def _resolve_framework(matches: Sequence[RawErrorMatch]) -> Optional[str]:
    for m in matches:
        meta = m.metadata or {}
        fw = meta.get("framework")
        if fw:
            return str(fw).lower()
        techs = meta.get("technologies") or []
        if m.family == DETECTOR_FAMILY_FRAMEWORK and techs:
            return str(techs[0]).lower()
        # Stack tech tags that are frameworks
        for t in techs:
            tl = str(t).lower()
            if tl in _DEBUG_FRAMEWORKS or tl in {
                "hibernate",
                "spring",
                "express",
                "nextjs",
                "fastapi",
            }:
                if tl in {"hibernate"}:
                    continue  # hibernate is often ORM not page framework
                return tl
    # Hibernate as framework tag when present
    for m in matches:
        techs = (m.metadata or {}).get("technologies") or []
        for t in techs:
            if str(t).lower() == "hibernate":
                return "hibernate"
            if str(t).lower() == "spring":
                return "spring"
    return None


def _resolve_database(matches: Sequence[RawErrorMatch]) -> Optional[str]:
    for m in matches:
        if m.family != DETECTOR_FAMILY_DATABASE:
            continue
        meta = m.metadata or {}
        vendor = meta.get("database") or meta.get("vendor")
        if vendor:
            return str(vendor).lower()
        # BUG-11: pure SQLSTATE bodies often leave vendor empty until mapped
        sqlstate = meta.get("sqlstate") or meta.get("error_code")
        mapped = vendor_from_sqlstate(str(sqlstate) if sqlstate else None)
        if mapped:
            return mapped
        # Exception type form SQLSTATE:42P01
        exc = m.exception_type or ""
        if exc.upper().startswith("SQLSTATE:"):
            mapped = vendor_from_sqlstate(exc.split(":", 1)[-1])
            if mapped:
                return mapped
    # Tech hints from stack
    for m in matches:
        for t in (m.metadata or {}).get("technologies") or []:
            tl = str(t).lower()
            if tl in {
                "mysql",
                "mariadb",
                "postgresql",
                "postgres",
                "oracle",
                "sqlite",
                "mongodb",
                "redis",
                "sqlserver",
            }:
                return "postgresql" if tl == "postgres" else tl
    return None


def _resolve_server(matches: Sequence[RawErrorMatch]) -> Optional[str]:
    for m in matches:
        meta = m.metadata or {}
        srv = meta.get("server")
        if srv:
            return str(srv).lower()
        if m.family == DETECTOR_FAMILY_INFRA:
            techs = meta.get("technologies") or []
            if techs:
                return str(techs[0]).lower()
        if m.family == DETECTOR_FAMILY_FRAMEWORK:
            fw = meta.get("framework")
            if fw in {"tomcat", "jetty"}:
                return str(fw).lower()
    for m in matches:
        for t in (m.metadata or {}).get("technologies") or []:
            tl = str(t).lower()
            if tl in {
                "tomcat",
                "jetty",
                "nginx",
                "apache",
                "iis",
                "cloudflare",
                "envoy",
                "haproxy",
            }:
                return tl
    return None


def _collect_technologies(matches: Sequence[RawErrorMatch]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in matches:
        techs = (m.metadata or {}).get("technologies") or []
        for t in techs:
            key = str(t).lower()
            if key and key not in seen:
                seen.add(key)
                out.append(key)
        for key_name in ("framework", "server", "vendor", "database"):
            v = (m.metadata or {}).get(key_name)
            if v:
                key = str(v).lower()
                if key and key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def _score_severity(
    *,
    primary: RawErrorMatch,
    matches: Sequence[RawErrorMatch],
    category: str,
    has_stack: bool,
    has_path: bool,
    has_host: bool,
    has_version: bool,
    framework: Optional[str],
    database: Optional[str],
    status_code: Optional[int],
    evidence_text: str,
) -> int:
    base = _FAMILY_BASE_SCORE.get(primary.family, 30)

    # Category adjustments
    if category == CATEGORY_VALIDATION:
        base = min(base, 30)
        # Structured validation (codes / problem+json) → medium-ish
        meta = primary.metadata or {}
        if meta.get("code") or meta.get("error_code") or meta.get("problem_json"):
            base = max(base, 45)
    if category == CATEGORY_HTTP:
        try:
            code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            code = None
        if code is not None and 500 <= code <= 599:
            base = max(base, 42)
        else:
            base = min(base, 28)

    # Framework debug chrome
    if category == CATEGORY_FRAMEWORK and framework in _DEBUG_FRAMEWORKS:
        base = max(base, 70)
    if primary.detector_id in {
        "fw_werkzeug",
        "fw_django_debug",
        "fw_laravel_whoops",
        "fw_aspnet_ysod",
    }:
        base = max(base, 72)

    # Infra default pages stay lower
    if category == CATEGORY_INFRASTRUCTURE:
        srv = (primary.metadata or {}).get("server") or ""
        try:
            code = int(status_code) if status_code is not None else 0
        except (TypeError, ValueError):
            code = 0
        if code == 404 or (isinstance(srv, str) and srv in {"nginx", "apache"} and code < 500):
            base = min(base, 28)
        elif code >= 500:
            base = max(base, 42)

    score = base

    if has_stack:
        score += 8
    if database and has_stack:
        score += 18  # stack + SQL → critical band
    elif database:
        score += 6
    if has_path:
        score += 12
    if has_host:
        score += 8
    if has_version:
        score += 4

    # Critical leak patterns
    blob = evidence_text or ""
    for m in matches:
        if m.raw_snippet:
            blob += "\n" + m.raw_snippet
    if _CRITICAL_LEAK_RE.search(blob):
        score += 25
    if has_stack and _SQL_FRAGMENT_RE.search(blob):
        score += 12

    # Confidence seed mild influence
    conf_pts = confidence_from_seed(primary.confidence)
    if conf_pts >= 90:
        score += 3
    elif conf_pts <= 30:
        score -= 5

    return max(0, min(100, int(score)))


def _unique_ids(matches: Sequence[RawErrorMatch]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in matches:
        if m.detector_id not in seen:
            seen.add(m.detector_id)
            out.append(m.detector_id)
    return out
