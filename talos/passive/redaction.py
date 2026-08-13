"""
Module: talos.passive.redaction

Purpose:
    Secret value canonicalization, fingerprinting, and UI-safe redaction
    for Passive Source Intelligence.

    Fingerprint contract (stable across scanner versions — do not change
    casually; breaking it splits PRIMARY/LINKED clusters):

        canonical_secret = strip whitespace + optional case fold
        value_fingerprint = SHA256(f"{family}\\0{canonical_secret}".encode("utf-8"))
                           as lowercase hex digest

    Redacted display (default rule):

        first 4 chars + "****" + last 4 chars

    Short values use a fixed mask so partial secrets are not leaked by
    length.  Never use the raw secret as a log key or index name.

Dependencies: hashlib (stdlib); talos.passive.constants for mask sizes
Data flow: detector raw_value → fingerprint_secret / redact_secret → Detection
Side effects: None.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from talos.passive.constants import (
    REDACT_MASK,
    REDACT_VISIBLE_PREFIX,
    REDACT_VISIBLE_SUFFIX,
)

# Families that fingerprint case-insensitively (hex / base32-ish tokens).
# Provider-specific detectors may pass case_sensitive=False explicitly.
_CASE_FOLD_FAMILIES: frozenset[str] = frozenset({
    "provider",
    "jwt",
    "generic",
    "entropy",
    "connection_string",
})


def canonicalize_secret(
    value: str,
    *,
    case_sensitive: Optional[bool] = None,
    family: str = "",
) -> str:
    """
    Purpose:
        Normalize secret material before fingerprinting so the same secret
        observed with whitespace or trivial case differences clusters
        together.

    Input:
        value           — raw matched secret (may include surrounding space)
        case_sensitive  — if True, preserve case; if False, lowercase;
                          if None, fold case when family is in the default set
        family          — detector_family (used when case_sensitive is None)

    Output:
        Canonical string (never empty if value had non-whitespace content
        after strip; may be empty if value was only whitespace).

    Side effects: None.
    """
    if value is None:
        return ""
    canonical = value.strip()
    if case_sensitive is None:
        case_sensitive = family not in _CASE_FOLD_FAMILIES
    if not case_sensitive:
        canonical = canonical.lower()
    return canonical


def fingerprint_secret(
    family: str,
    value: str,
    *,
    case_sensitive: Optional[bool] = None,
) -> str:
    """
    Purpose:
        Produce a stable value_fingerprint for clustering and dedup.

        value_fingerprint = SHA256(detector_family + "\\0" + canonical_secret)

        Cluster key (Phase 8): PASSIVE_SECRET (one cluster; fingerprint is still stored on the detection)

    Input:
        family — detector_family string (e.g. "provider", "pem")
        value  — raw secret material
        case_sensitive — optional override for canonicalize_secret

    Output:
        64-character lowercase hex SHA-256 digest.

    Side effects: None.
    """
    fam = (family or "").strip()
    canonical = canonicalize_secret(
        value,
        case_sensitive=case_sensitive,
        family=fam,
    )
    material = f"{fam}\0{canonical}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def redact_secret(
    value: str,
    *,
    prefix: int = REDACT_VISIBLE_PREFIX,
    suffix: int = REDACT_VISIBLE_SUFFIX,
    mask: str = REDACT_MASK,
) -> str:
    """
    Purpose:
        UI/CLI-safe display form of a secret.  Shows a short prefix and
        suffix so operators can recognize known keys without copying the
        full value from list views.

    Input:
        value  — raw secret (whitespace stripped for length decisions)
        prefix — visible leading character count (default 4)
        suffix — visible trailing character count (default 4)
        mask   — middle replacement (default "****")

    Output:
        Redacted string.  Empty input → empty string.
        Very short secrets (len <= prefix + suffix) → full mask only
        (avoids revealing almost-entire short tokens).

    Side effects: None.
    """
    if value is None:
        return ""
    text = value.strip()
    if not text:
        return ""
    if len(text) <= prefix + suffix:
        return mask
    return f"{text[:prefix]}{mask}{text[-suffix:]}"


def looks_like_placeholder(value: str) -> bool:
    """
    Purpose:
        Cheap heuristic used by suppression (Phase 6) and available early
        for tests / config previews.  Not a full suppress list — that
        lives in suppress.py later.

    Input:
        value — candidate secret string

    Output:
        True when the value is empty, a common placeholder token, a
        template placeholder (${…} / {{…}}), or an env-var reference.

    Side effects: None.
    """
    if value is None:
        return True
    text = value.strip()
    if not text:
        return True

    lower = text.lower()
    if lower in {
        "null",
        "undefined",
        "none",
        "nil",
        "example",
        "changeme",
        "placeholder",
        "password",
        "secret",
        "your_api_key",
        "your-api-key",
        "xxx",
        "xxxx",
        "todo",
        "tbd",
    }:
        return True

    if text in {"YOUR_API_KEY", "API_KEY", "SECRET", "PASSWORD", "TOKEN"}:
        return True

    # Template / env placeholders
    if re.search(r"\$\{[^}]+\}", text):
        return True
    if re.search(r"\{\{[^}]+\}\}", text):
        return True
    if re.match(r"^(process\.env\.|import\.meta\.env\.)", text):
        return True

    # Repeated single character (aaaa, **** already masked)
    if len(text) >= 4 and len(set(text)) == 1:
        return True

    return False
