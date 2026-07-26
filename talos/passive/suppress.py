"""
Module: talos.passive.suppress

Purpose:
    Day-one suppression filters for Passive Source Intelligence.

    Drops or marks noise before persistence / findings:
        - empty / null / undefined
        - placeholder vocabulary
        - template syntax (${…}, {{…}})
        - angle-bracket placeholders (<secret>, <YOUR_API_KEY>)
        - plain URL / host-path strings (not credential-bearing URIs)
        - env var references (process.env.*, import.meta.env.*)
        - low-entropy trivial values
        - known public / documentation example tokens

    Used after scoring; returns (suppressed: bool, reason: str | None).

Dependencies: re; talos.passive.redaction.looks_like_placeholder; detectors.base
Data flow: RawMatch / value → should_suppress() → (bool, reason)
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.detectors.base import shannon_entropy
from talos.passive.models import RawMatch
from talos.passive.redaction import looks_like_placeholder

# Exact / lowercased vocabulary (in addition to looks_like_placeholder)
_PLACEHOLDER_EXACT: frozenset[str] = frozenset({
    "example",
    "changeme",
    "placeholder",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your-secret",
    "insert_key_here",
    "xxx",
    "xxxx",
    "todo",
    "tbd",
    "n/a",
    "na",
    "none",
    "null",
    "undefined",
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "test",
    "testing",
    "sample",
    "dummy",
    "fake",
    "default",
})

# Well-known public documentation / example tokens (not live secrets).
# Do not embed vendor-shaped live/test API key strings in source — GitHub
# push protection flags them even when synthetic.  AWS EXAMPLE tokens are
# the AWS-documented public samples.  Stripe-shaped noise is handled by
# placeholder / low-entropy / "test" vocabulary filters above.
_PUBLIC_TEST_TOKENS: frozenset[str] = frozenset({
    # AWS documentation examples (public, from AWS docs)
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})

# process.env.X / import.meta.env.X / os.environ[...] bare references
_ENV_REF = re.compile(
    r"^(?:"
    r"process\.env\.[A-Za-z_][\w]*"
    r"|import\.meta\.env\.[A-Za-z_][\w]*"
    r"|os\.environ(?:\[[^\]]+\]|\.get\([^\)]+\))"
    r"|ENV\[[^\]]+\]"
    r")$"
)

# Template / interpolation
_TEMPLATE = re.compile(r"(\$\{[^}]+\}|\{\{[^}]+\}\}|<%[=]?.+?%>)")

# Angle-bracket placeholders: <secret>, <YOUR_API_KEY>, <token>
_ANGLE_PLACEHOLDER = re.compile(r"^<[^<>]{1,80}>$")

# Credential-bearing DB/service URI schemes — secrets, never URL-noise.
_CREDENTIAL_URI_SCHEME = re.compile(
    r"^(?:"
    r"postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|"
    r"amqp|amqps|kafka|mssql|sqlserver|jdbc|cockroachdb|"
    r"cassandra|neo4j|bolt|elasticsearch"
    r")://",
    re.IGNORECASE,
)

# http(s) with embedded userinfo (https://user:pass@host) — keep as secret.
_HTTP_USERINFO = re.compile(
    r"^https?://[^/\s:@]+:[^/\s@]+@",
    re.IGNORECASE,
)

# Low-entropy thresholds for generic/contextual values
_MIN_GENERIC_LENGTH = 6
_MIN_GENERIC_ENTROPY = 2.5


def should_suppress(
    value: str,
    *,
    detector_family: str = "",
    detector_id: str = "",
    matched_key: Optional[str] = None,
    entropy: Optional[float] = None,
    raw_match: Optional[RawMatch] = None,
) -> tuple[bool, Optional[str]]:
    """
    Purpose:
        Decide whether a candidate secret should be suppressed as noise.

    Input:
        value            — raw matched secret
        detector_family  — provider | generic | contextual | entropy | …
        detector_id      — rule id
        matched_key      — assignment key when known
        entropy          — precomputed Shannon entropy (optional)
        raw_match        — full match for context (optional)

    Output:
        (True, reason) when suppressed; (False, None) when keep.

    Side effects: None.

    Notes:
        Provider CONFIRMED patterns still suppress known public example tokens
        and empty/placeholder values, but do not apply low-entropy filters
        (structured formats already constrain shape).
    """
    if value is None:
        return True, "empty"
    text = value.strip()
    if not text:
        return True, "empty"

    lower = text.lower()
    if lower in {"null", "undefined", "none", "nil", ""}:
        return True, "null_or_undefined"

    if looks_like_placeholder(text):
        return True, "placeholder"

    if lower in _PLACEHOLDER_EXACT:
        return True, "placeholder_vocabulary"

    if text in _PUBLIC_TEST_TOKENS or lower in {t.lower() for t in _PUBLIC_TEST_TOKENS}:
        return True, "public_test_token"

    if _ENV_REF.match(text):
        return True, "env_var_reference"

    if _TEMPLATE.search(text):
        return True, "template_syntax"

    if _ANGLE_PLACEHOLDER.match(text):
        return True, "angle_placeholder"

    if looks_like_url_or_hostpath(text):
        return True, "url_or_hostpath"

    # Context-side env refs: value is just an identifier from env
    if raw_match is not None:
        ctx = f"{raw_match.context_before}{raw_match.raw_value}{raw_match.context_after}"
        if re.search(
            r"(process\.env|import\.meta\.env|os\.environ)\s*[\.\[]",
            ctx,
        ) and re.search(
            r"(process\.env|import\.meta\.env|os\.environ)",
            raw_match.context_before + raw_match.context_after,
        ):
            # Value itself is process.env.API_KEY style assignment RHS
            if "process.env" in raw_match.context_before or "import.meta.env" in raw_match.context_before:
                return True, "env_var_assignment"

    # Generic / contextual / entropy: low quality values
    family = (detector_family or "").lower()
    if family in {"generic", "contextual", "entropy"}:
        if len(text) < _MIN_GENERIC_LENGTH:
            return True, "too_short"
        ent = entropy if entropy is not None else shannon_entropy(text)
        if ent < _MIN_GENERIC_ENTROPY:
            return True, "low_entropy"
        # password = "password" already covered; also key==value echo
        if matched_key and text.lower() == matched_key.lower().replace("_", ""):
            return True, "key_echo_value"
        if matched_key and text.lower() == matched_key.lower():
            return True, "key_echo_value"

    return False, None


def looks_like_url_or_hostpath(value: str) -> bool:
    """
    Purpose:
        True when value is a non-secret URL / host-path that entropy or
        contextual stages may mis-pick (e.g. //api.github.com/user).

        Connection-string URIs (postgres://…) and http(s) URLs with
        userinfo are **not** treated as noise — those can be secrets.
    Side effects: None.
    """
    text = (value or "").strip()
    if not text:
        return False

    # DB/service URIs and HTTP basic-auth URLs are secrets.
    if _CREDENTIAL_URI_SCHEME.match(text):
        return False
    if _HTTP_USERINFO.match(text):
        return False

    # Plain http(s) without credentials.
    if re.match(r"^https?://", text, re.IGNORECASE):
        return True

    # Protocol-relative URL: //host[/path]
    if text.startswith("//") and "." in text and " " not in text:
        return True

    # Bare host.tld[/path] without credentials (api.github.com/user).
    if re.search(
        r"(?i)^[A-Za-z0-9][A-Za-z0-9._-]*\."
        r"(?:com|org|net|io|dev|app|co|local|internal|gov|edu|info|biz)"
        r"(?:[:/]|$)",
        text,
    ):
        return True

    # Multi-segment path with a dotted host label.
    if text.count("/") >= 2 and "." in text and " " not in text and "://" not in text:
        return True

    return False


def is_public_test_token(value: str) -> bool:
    """
    Purpose:
        True when value is a known documentation example token.
    Side effects: None.
    """
    if not value:
        return False
    text = value.strip()
    return text in _PUBLIC_TEST_TOKENS or text.lower() in {
        t.lower() for t in _PUBLIC_TEST_TOKENS
    }
