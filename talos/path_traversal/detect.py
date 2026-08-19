"""
Module: talos.path_traversal.detect

Purpose:
    Decide whether a probe response leaked a well-known file.

    Hits must be **new versus the captured baseline** so a page that
    already mentions ``localhost`` or ``root`` does not become a finding.

    Confirmation is file-content (passwd, win.ini, PHP filter base64 of
    those files, /proc/version, web.config). Path-disclosure errors
    (FileNotFoundException, failed to open stream) are not a finding.

Dependencies: re
Data flow: engine → analyze_path_traversal_response → verdict
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.path_traversal.models import (
    OS_PHP,
    OS_UNIX,
    OS_WINDOWS,
    VERDICT_PATH_TRAVERSAL,
    VERDICT_SECURE,
)

# (regex, os_hint, risk_hint, kind)
# kind=file is confirmation; baseline-new only.
_SIGNATURES: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    # Unix /etc/passwd — require the uid 0 record, not just the word "root".
    (
        re.compile(r"(?m)^root:[^:\n]*:0:0:"),
        OS_UNIX,
        "unix_passwd",
        "file",
    ),
    (
        re.compile(r"root:x:0:0:"),
        OS_UNIX,
        "unix_passwd",
        "file",
    ),
    (
        re.compile(r"root:\$[^:]+:0:0:"),
        OS_UNIX,
        "unix_passwd",
        "file",
    ),
    (
        re.compile(r"(?m)^daemon:[^:\n]*:1:"),
        OS_UNIX,
        "unix_passwd",
        "file",
    ),
    (
        re.compile(r"nologin(?:\s|$)|/bin/bash(?:\s|$)"),
        OS_UNIX,
        "unix_passwd",
        "file",
    ),
    # /etc/hosts — need more than localhost (too common on HTML).
    (
        re.compile(r"ip6-localhost|broadcasthost|# The following lines are desirable"),
        OS_UNIX,
        "unix_hosts",
        "file",
    ),
    (
        re.compile(r"(?m)^127\.0\.0\.1\s+localhost\s*$", re.I),
        OS_UNIX,
        "unix_hosts",
        "file",
    ),
    # /proc
    (
        re.compile(r"Linux version \d+\.\d+"),
        OS_UNIX,
        "proc_version",
        "file",
    ),
    (
        re.compile(r"\bDOCUMENT_ROOT="),
        OS_UNIX,
        "proc_environ",
        "file",
    ),
    # /etc/issue
    (
        re.compile(r"\\[nl](?:\s|$)"),
        OS_UNIX,
        "unix_issue",
        "file",
    ),
    # Windows win.ini — the 16-bit banner is unique.
    (
        re.compile(r"for 16-bit app support", re.I),
        OS_WINDOWS,
        "win_ini",
        "file",
    ),
    (
        re.compile(r"\[fonts\][\s\S]{0,200}\[extensions\]", re.I),
        OS_WINDOWS,
        "win_ini",
        "file",
    ),
    (
        re.compile(r"(?m)^\[MCI Extensions\]", re.I),
        OS_WINDOWS,
        "win_ini",
        "file",
    ),
    # boot.ini
    (
        re.compile(r"\[boot loader\]", re.I),
        OS_WINDOWS,
        "win_boot",
        "file",
    ),
    (
        re.compile(r"multi\(0\)disk\(0\)rdisk\(0\)", re.I),
        OS_WINDOWS,
        "win_boot",
        "file",
    ),
    # IIS web.config
    (
        re.compile(
            r"<configuration[\s\S]{0,400}<system\.web",
            re.I,
        ),
        OS_WINDOWS,
        "web_config",
        "file",
    ),
    # PHP filter base64(root:x:0:0:) → cm9vdDp4OjA6MDo
    (
        re.compile(r"cm9vdDp4OjA6MDo"),
        OS_PHP,
        "php_filter",
        "file",
    ),
    # PHP filter base64(<?php) → PD9waH
    (
        re.compile(r"PD9waHA"),
        OS_PHP,
        "php_source",
        "file",
    ),
    # ROT13 of root:x:0:0:
    (
        re.compile(r"ebbg:k:0:0:"),
        OS_PHP,
        "php_filter",
        "file",
    ),
    # file:// / include of PHP that dumps source with tags
    (
        re.compile(r"<\?php\s+(?:include|require|namespace|echo)\b"),
        OS_PHP,
        "php_source",
        "file",
    ),
)


# nologin/bash is too noisy alone — only count it when passwd-shaped
# uid fields are also present.
_NOISY_ALONE = frozenset(
    {
        r"nologin(?:\s|$)|/bin/bash(?:\s|$)",
    }
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
        Return (pattern, os_hint, risk_hint) hits in ``text``.
    Output:
        Deduped list in catalogue order.
    """
    blob = text or ""
    hits: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for pattern, os_hint, risk_hint, _kind in _SIGNATURES:
        if pattern.search(blob):
            key = pattern.pattern
            if key in seen:
                continue
            seen.add(key)
            hits.append((key, os_hint, risk_hint))
    return hits


def _drop_noisy_alone(hits: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Purpose: Drop nologin/bash unless another passwd signature also hit."""
    if not hits:
        return hits
    has_strong_passwd = any(
        item[2] == "unix_passwd" and item[0] not in _NOISY_ALONE for item in hits
    )
    if has_strong_passwd:
        return hits
    return [item for item in hits if item[0] not in _NOISY_ALONE]


def analyze_path_traversal_response(
    *,
    baseline_body: object,
    probe_body: object,
) -> tuple[str, str, Optional[str], str]:
    """
    Purpose:
        Classify one probe against the captured baseline.
    Output:
        (verdict, risk_hint, os_hint, evidence)
    """
    base_text = _decode_body(baseline_body)
    probe_text = _decode_body(probe_body)
    base_hits = _drop_noisy_alone(collect_signatures(base_text))
    probe_hits = _drop_noisy_alone(collect_signatures(probe_text))
    base_keys = {item[0] for item in base_hits}
    new_hits = [item for item in probe_hits if item[0] not in base_keys]

    if not new_hits:
        return VERDICT_SECURE, "", None, ""

    os_hint: Optional[str] = None
    risk_hint = ""
    evidence = ""
    for pattern, vendor, hint in new_hits:
        if not os_hint and vendor:
            os_hint = vendor
        if not risk_hint:
            risk_hint = hint
            evidence = pattern[:160]
            break

    return VERDICT_PATH_TRAVERSAL, risk_hint, os_hint, evidence
