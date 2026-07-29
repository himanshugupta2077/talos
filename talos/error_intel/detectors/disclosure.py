"""
Module: talos.error_intel.detectors.disclosure

Purpose:
    Stage F — information disclosure extractors (paths, hosts, versions).

    Plan contract:
        - Run after a primary error hit, **or** always on 5xx candidates.
        - Prefer attaching as **artifacts** on the observation; emit
          RawErrorMatch with family=disclosure when standalone leaks matter
          (path leak without exception still worth recording).

    Lifts path / internal-IP / hostname ideas from
    ``talos.passive.detectors.infrastructure`` without bolting onto secret
    scan (no finding bridge; different ownership: error *event* artifacts).

Dependencies: re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → (list[RawErrorMatch], list[ErrorArtifact])
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_DISCLOSURE,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
    DETECTOR_FAMILY_DISCLOSURE,
    LANG_UNKNOWN,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
)
from talos.error_intel.models import ErrorArtifact, RawErrorMatch

# Absolute filesystem paths (unix + windows + jar-ish)
_FS_PATH = re.compile(
    r"(?<![A-Za-z0-9_/])"
    r"("
    r"(?:/(?:home|Users|var|opt|usr|app|src|tmp|etc|data|srv)/[A-Za-z0-9_./\-]{2,220})"
    r"|(?:[A-Za-z]:\\(?:Users|home|src|app|Program Files|Windows)\\[A-Za-z0-9_\\.\-]{2,220})"
    r"|(?:file:/[A-Za-z0-9_./\-]{3,220})"
    r"|(?:[A-Za-z0-9_.\-]+\.(?:jar|war|ear)!\S{0,80})"
    r")",
)

# Private / link-local IPv4 (lifted spirit of passive InfrastructureDetector)
_PRIVATE_IP = re.compile(
    r"(?<![0-9])"
    r"("
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(?:192\.168\.\d{1,3}\.\d{1,3})"
    r"|(?:172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})"
    r"|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(?:169\.254\.\d{1,3}\.\d{1,3})"
    r")"
    r"(?![0-9])"
)

_INTERNAL_HOST = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.(?:internal|local|corp|lan|intranet|home))"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

# Version / library strings
_VERSION = re.compile(
    r"\b("
    r"Spring Boot\s+v?[\d.]+|"
    r"OpenJDK[^\n,]{0,40}|"
    r"Java(?:TM)?\s*(?:SE)?\s*Runtime[^\n,]{0,40}|"
    r"Python\s+[\d.]+|"
    r"PHP\s+[\d.]+|"
    r"nginx/[\d.]+|"
    r"Apache/[\d.]+|"
    r"OpenSSL\s+[\d.a-z]+|"
    r"Microsoft-IIS/[\d.]+|"
    r"\.NET(?:\s+Core)?\s+[\d.]+|"
    r"Node\.js\s+v?[\d.]+|"
    r"Hibernate\s+(?:ORM\s+)?[\d.]+"
    r")",
    re.IGNORECASE,
)

# Username-ish in error messages (careful — only explicit patterns)
_USER_IN_MSG = re.compile(
    r"\b(?:user(?:name)?|uid|login)\s*[:=]\s*['\"]?([A-Za-z0-9_.@-]{2,64})['\"]?",
    re.IGNORECASE,
)

_DB_NAME = re.compile(
    r"\b(?:database|db|schema)\s*[:=]\s*['\"]?([A-Za-z0-9_.-]{2,64})['\"]?",
    re.IGNORECASE,
)

_MAX_PATHS = 15
_MAX_HOSTS = 10
_MAX_VERSIONS = 10


class DisclosureExtractor:
    """
    Purpose:
        Stage F — extract disclosure artifacts and optional disclosure matches.
    """

    def __init__(self, *, max_matches: int = DEFAULT_STAGE_MATCH_CAP) -> None:
        self._max = max(1, int(max_matches))

    def extract(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
        force: bool = False,
        has_primary_error: bool = False,
    ) -> tuple[list[RawErrorMatch], list[ErrorArtifact]]:
        """
        Purpose:
            Extract path/host/version disclosures from error text.
        Input:
            force — always run (orchestrator sets True for 5xx or after primary)
            has_primary_error — True when stages A–E already hit
        Output:
            (disclosure RawErrorMatches, ErrorArtifacts)
        Side effects: None.
        """
        del content_type
        if not text or not text.strip():
            return [], self._artifacts_from_headers(headers)

        should_run = force or has_primary_error or _is_5xx(status_code)
        if not should_run:
            return [], []

        artifacts: list[ErrorArtifact] = []
        matches: list[RawErrorMatch] = []
        seen_path: set[str] = set()
        seen_host: set[str] = set()
        seen_ver: set[str] = set()

        # Paths
        for m in _FS_PATH.finditer(text):
            path = m.group(1)
            if len(path) > 300:
                path = path[:300]
            # Skip obvious URL path fragments that aren't absolute FS
            if path.startswith("/api/") or path.startswith("/v1/") or path.startswith("/static/"):
                continue
            key = path.lower()
            if key in seen_path:
                continue
            seen_path.add(key)
            artifacts.append(ErrorArtifact(kind="path", value=path, normalized=None))
            if len(seen_path) >= _MAX_PATHS:
                break

        if seen_path:
            # One aggregate disclosure match for paths
            first = next(_FS_PATH.finditer(text))
            sample = next(iter(seen_path))
            matches.append(
                build_raw_error_match(
                    detector_id="disclosure_paths",
                    family=DETECTOR_FAMILY_DISCLOSURE,
                    text=text,
                    match_start=first.start(1),
                    match_end=first.end(1),
                    exception_type=None,
                    confidence=CONFIDENCE_HIGH,
                    category_hint=CATEGORY_DISCLOSURE,
                    language=LANG_UNKNOWN,
                    metadata={
                        "disclosure_kind": "path",
                        "paths": [a.value for a in artifacts if a.kind == "path"][:_MAX_PATHS],
                        "path_count": len(seen_path),
                        "has_path_leak": True,
                    },
                    raw_snippet=sample[:500],
                )
            )

        # Private IPs
        for m in _PRIVATE_IP.finditer(text):
            ip = m.group(1)
            if ip in seen_host:
                continue
            seen_host.add(ip)
            artifacts.append(ErrorArtifact(kind="host", value=ip, normalized=ip))
            if len([a for a in artifacts if a.kind == "host"]) >= _MAX_HOSTS:
                break

        # Internal hostnames
        for m in _INTERNAL_HOST.finditer(text):
            host = m.group(1)
            key = host.lower()
            if key in seen_host:
                continue
            seen_host.add(key)
            artifacts.append(ErrorArtifact(kind="host", value=host, normalized=key))
            if len([a for a in artifacts if a.kind == "host"]) >= _MAX_HOSTS:
                break

        host_arts = [a for a in artifacts if a.kind == "host"]
        if host_arts and len(matches) < self._max:
            sample = host_arts[0].value
            pos = text.find(sample)
            if pos < 0:
                pos = 0
            matches.append(
                build_raw_error_match(
                    detector_id="disclosure_hosts",
                    family=DETECTOR_FAMILY_DISCLOSURE,
                    text=text,
                    match_start=pos,
                    match_end=pos + len(sample),
                    confidence=CONFIDENCE_MEDIUM,
                    category_hint=CATEGORY_DISCLOSURE,
                    language=LANG_UNKNOWN,
                    metadata={
                        "disclosure_kind": "host",
                        "hosts": [a.value for a in host_arts][:_MAX_HOSTS],
                        "has_internal_host": True,
                    },
                    raw_snippet=sample[:300],
                )
            )

        # Versions
        for m in _VERSION.finditer(text):
            ver = m.group(1).strip()
            key = ver.lower()
            if key in seen_ver:
                continue
            seen_ver.add(key)
            artifacts.append(ErrorArtifact(kind="version", value=ver, normalized=key))
            if len(seen_ver) >= _MAX_VERSIONS:
                break

        # Server header version
        if headers:
            for hk, hv in headers.items():
                if str(hk).lower() == "server" and hv:
                    val = str(hv).strip()
                    if val and val.lower() not in seen_ver:
                        seen_ver.add(val.lower())
                        artifacts.append(
                            ErrorArtifact(kind="version", value=val, normalized=val.lower())
                        )

        ver_arts = [a for a in artifacts if a.kind == "version"]
        if ver_arts and len(matches) < self._max:
            sample = ver_arts[0].value
            pos = text.find(sample)
            if pos < 0:
                pos = 0
            matches.append(
                build_raw_error_match(
                    detector_id="disclosure_versions",
                    family=DETECTOR_FAMILY_DISCLOSURE,
                    text=text,
                    match_start=pos,
                    match_end=pos + min(len(sample), len(text) - pos),
                    confidence=CONFIDENCE_WEAK,
                    category_hint=CATEGORY_DISCLOSURE,
                    language=LANG_UNKNOWN,
                    metadata={
                        "disclosure_kind": "version",
                        "versions": [a.value for a in ver_arts][:_MAX_VERSIONS],
                        "has_version_leak": True,
                    },
                    raw_snippet=sample[:300],
                )
            )

        # Usernames / DB names (artifacts only — no separate cluster noise)
        for m in _USER_IN_MSG.finditer(text):
            user = m.group(1)
            if user.lower() in {"null", "none", "undefined", "true", "false"}:
                continue
            artifacts.append(ErrorArtifact(kind="username", value=user, normalized=user.lower()))
            if sum(1 for a in artifacts if a.kind == "username") >= 5:
                break

        for m in _DB_NAME.finditer(text):
            dbn = m.group(1)
            artifacts.append(ErrorArtifact(kind="db_name", value=dbn, normalized=dbn.lower()))
            if sum(1 for a in artifacts if a.kind == "db_name") >= 5:
                break

        return matches[: self._max], artifacts

    def detect(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
    ) -> list[RawErrorMatch]:
        """Protocol-compatible detect (always force extract). Side effects: None."""
        matches, _ = self.extract(
            text,
            status_code=status_code,
            headers=headers,
            content_type=content_type,
            force=True,
            has_primary_error=True,
        )
        return matches

    def _artifacts_from_headers(
        self,
        headers: Optional[Mapping[str, str]],
    ) -> list[ErrorArtifact]:
        if not headers:
            return []
        out: list[ErrorArtifact] = []
        for k, v in headers.items():
            if str(k).lower() == "server" and v:
                out.append(
                    ErrorArtifact(kind="version", value=str(v).strip(), normalized=str(v).strip().lower())
                )
        return out


def _is_5xx(status_code: Optional[int]) -> bool:
    if status_code is None:
        return False
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return False
    return 500 <= code <= 599
