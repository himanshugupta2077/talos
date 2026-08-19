"""
Module: talos.ssrf.detect

Purpose:
    Decide whether a probe response shows an in-band SSRF fetch.

    Hits must be **new versus the captured baseline** so a page that
    already mentions ``localhost`` or ``ami-id`` does not become a finding.

    Confirmation is fetched *content* (cloud metadata documents, well-known
    files, internal-service banners, Burp Collaborator HTTP body). Echoed
    payload text is not evidence. Blind OAST is out of band — operator
    checks Burp Collaborator.

Dependencies: json, re
Data flow: engine → analyze_ssrf_response → verdict
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from talos.ssrf.models import (
    SINK_CLOUD,
    SINK_FILE,
    SINK_OAST,
    SINK_SERVICE,
    VERDICT_SECURE,
    VERDICT_SSRF,
)

# (regex, sink_hint, risk_hint)
_SIGNATURES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # AWS IMDS
    (
        re.compile(r"ami-[0-9a-z]{8,}", re.I),
        SINK_CLOUD,
        "aws_ami",
    ),
    (
        re.compile(r"\binstance-id\b.{0,40}\bi-[0-9a-z]+", re.I | re.S),
        SINK_CLOUD,
        "aws_instance",
    ),
    (
        re.compile(r'"accountId"\s*:\s*"\d{12}"'),
        SINK_CLOUD,
        "aws_identity",
    ),
    (
        re.compile(r"iam/security-credentials/[A-Za-z0-9+=,.@_-]+"),
        SINK_CLOUD,
        "aws_iam",
    ),
    (
        re.compile(r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]+"'),
        SINK_CLOUD,
        "aws_iam",
    ),
    (
        re.compile(r"(?m)^(?:ami-id|instance-id|local-ipv4|public-ipv4|security-groups)\s*$"),
        SINK_CLOUD,
        "aws_meta_index",
    ),
    # GCP
    (
        re.compile(r"computeMetadata/v1"),
        SINK_CLOUD,
        "gcp_meta",
    ),
    (
        re.compile(r'"access_token"\s*:\s*"[ya]\.[A-Za-z0-9_-]+'),
        SINK_CLOUD,
        "gcp_token",
    ),
    # Azure
    (
        re.compile(r'"azEnvironment"\s*:|"compute"\s*:\s*\{.{0,200}"location"', re.S),
        SINK_CLOUD,
        "azure_imds",
    ),
    (
        re.compile(r'"access_token"\s*:\s*"eyJ[A-Za-z0-9_-]+'),
        SINK_CLOUD,
        "cloud_jwt",
    ),
    # Unix file
    (
        re.compile(r"(?m)^root:[^:\n]*:0:0:"),
        SINK_FILE,
        "unix_passwd",
    ),
    (
        re.compile(r"root:x:0:0:"),
        SINK_FILE,
        "unix_passwd",
    ),
    (
        re.compile(r"(?m)^127\.0\.0\.1\s+localhost\s*$", re.I),
        SINK_FILE,
        "unix_hosts",
    ),
    (
        re.compile(r"Linux version \d+\.\d+"),
        SINK_FILE,
        "proc_version",
    ),
    # Windows file
    (
        re.compile(r"for 16-bit app support", re.I),
        SINK_FILE,
        "win_ini",
    ),
    (
        re.compile(r"\[fonts\][\s\S]{0,200}\[extensions\]", re.I),
        SINK_FILE,
        "win_ini",
    ),
    # Redis / memcached / ES / docker / etcd
    (
        re.compile(r"redis_version:|NOAUTH Authentication required|-ERR unknown command", re.I),
        SINK_SERVICE,
        "redis",
    ),
    (
        re.compile(r"(?m)^STAT pid \d+"),
        SINK_SERVICE,
        "memcached",
    ),
    (
        re.compile(r'"tagline"\s*:\s*"You Know, for Search"', re.I),
        SINK_SERVICE,
        "elasticsearch",
    ),
    (
        re.compile(r'"ApiVersion"\s*:|"GitCommit"\s*:|"Platform"\s*:\s*\{\s*"Name"\s*:\s*"linux"', re.S),
        SINK_SERVICE,
        "docker",
    ),
    (
        re.compile(r"SSH-2\.0-"),
        SINK_SERVICE,
        "ssh",
    ),
    (
        re.compile(r'"node"\s*:\s*\{.{0,80}"key"\s*:', re.S),
        SINK_SERVICE,
        "etcd",
    ),
    # Collaborator HTTP body (server fetched and returned it)
    (
        re.compile(r"Burp Collaborator(?: Server)?", re.I),
        SINK_OAST,
        "collaborator_http",
    ),
    (
        re.compile(r"oastify\.com|burpcollaborator\.net", re.I),
        SINK_OAST,
        "collaborator_http",
    ),
)


def _decode_body(raw: object) -> str:
    """Purpose: Response body to searchable text. Output: str."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def collect_signatures(text: str) -> list[tuple[str, str, str]]:
    """
    Purpose:
        Return (pattern, sink_hint, risk_hint) hits in ``text``.
    Output:
        Deduped list in catalogue order.
    """
    blob = text or ""
    hits: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for pattern, sink_hint, risk_hint in _SIGNATURES:
        if pattern.search(blob):
            key = pattern.pattern
            if key in seen:
                continue
            seen.add(key)
            hits.append((key, sink_hint, risk_hint))
    return hits


def _looks_like_json_metadata(text: str) -> Optional[tuple[str, str, str]]:
    """
    Purpose:
        Extra AWS identity-document check when JSON parses.
    Output:
        (pattern, sink, hint) or None.
    """
    blob = (text or "").strip()
    if not blob.startswith("{"):
        return None
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    keys = {str(k).lower() for k in data}
    if {"accountid", "instanceid", "region", "architecture"} <= keys or {
        "accountid",
        "instanceid",
        "availabilityzone",
    } <= keys:
        return ("aws_identity_json", SINK_CLOUD, "aws_identity")
    if "accesskeyid" in keys and "secretaccesskey" in keys:
        return ("aws_keys_json", SINK_CLOUD, "aws_iam")
    return None


def _payload_echoed(payload: str, probe_text: str) -> bool:
    """Purpose: True when the probe body merely reflects the injected URL."""
    needle = (payload or "").strip()
    if len(needle) < 8:
        return False
    return needle in (probe_text or "")


def analyze_ssrf_response(
    *,
    baseline_body: object,
    probe_body: object,
    payload_sent: str = "",
    oast_token: str = "",
) -> tuple[str, str, Optional[str], str]:
    """
    Purpose:
        Classify one probe against the captured baseline.
    Output:
        (verdict, risk_hint, sink_hint, evidence)
    """
    base_text = _decode_body(baseline_body)
    probe_text = _decode_body(probe_body)
    echoed = _payload_echoed(payload_sent, probe_text)

    base_hits = collect_signatures(base_text)
    probe_hits = collect_signatures(probe_text)
    extra = _looks_like_json_metadata(probe_text)
    if extra:
        probe_hits = list(probe_hits) + [extra]
    base_extra = _looks_like_json_metadata(base_text)
    base_keys = {item[0] for item in base_hits}
    if base_extra:
        base_keys.add(base_extra[0])

    new_hits = [item for item in probe_hits if item[0] not in base_keys]
    if echoed:
        # Payload echo can include "oastify.com" / "169.254.169.254" text.
        # Keep only content signatures that are not just the URL string.
        new_hits = [
            item
            for item in new_hits
            if item[2]
            not in {
                "collaborator_http",
                "gcp_meta",
            }
        ]

    if oast_token and len(oast_token) >= 6:
        token = oast_token
        if token in probe_text and token not in base_text and not echoed:
            new_hits.append(("oast_token", SINK_OAST, "oast_reflected"))

    if not new_hits:
        return VERDICT_SECURE, "", None, ""

    sink_hint: Optional[str] = None
    risk_hint = ""
    evidence = ""
    for pattern, sink, hint in new_hits:
        if not sink_hint and sink:
            sink_hint = sink
        if not risk_hint:
            risk_hint = hint
            evidence = pattern[:160]
            break

    return VERDICT_SSRF, risk_hint, sink_hint, evidence
