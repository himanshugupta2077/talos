"""
Module: talos.error_intel.redact

Purpose:
    Safe display redaction for Error Intelligence evidence snippets and
    observation payloads (BUG-12).

    Severity scoring may still *detect* credential material (classify
    boosts critical on password=/JDBC URLs); stored/CLI text must not
    echo the secret in the clear.

Dependencies: re; talos.error_intel.constants
Data flow: raw snippet/payload → redact_error_text → safe string
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.error_intel.constants import DEFAULT_PAYLOAD_REDACTED_MAX

# password=secret / "password": "secret" / password: secret
_PASSWORD_KV = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|client_secret|api[_-]?key|"
    r"secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"
    r"\s*[=:]\s*)([\"']?)([^\s\"'&,;]{2,})(\2)",
)

# scheme://user:password@host
_URL_USERINFO = re.compile(
    r"(?i)\b((?:[a-z][a-z0-9+.-]*)://)([^/\s\"']+):([^@/\s\"']+)(@)",
)

# jdbc:mysql://user:pass@host or jdbc:… with user/password query params
_JDBC_URL = re.compile(
    r"(?i)\b(jdbc:[a-z0-9+]+://)([^\s\"']+)",
)
_JDBC_USERINFO = re.compile(
    r"(?i)(//)([^/\s\"'?]+):([^@/\s\"'?]+)(@)",
)
_JDBC_PWD_QUERY = re.compile(
    r"(?i)([?&](?:password|pwd|user(?:name)?)=)([^&\s\"']+)",
)

# PEM private key blocks
_PEM_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE,
)

# AWS access key id style (leave prefix recognisable)
_AWS_KEY = re.compile(r"\b(AKIA)([0-9A-Z]{16})\b")

_REDACT_MASK = "****"


def redact_error_text(
    text: Optional[str],
    *,
    max_len: Optional[int] = None,
) -> Optional[str]:
    """
    Purpose:
        Mask credential-shaped material in evidence snippets / payloads.
    Input:
        text — raw string (may be None)
        max_len — optional hard cap (ellipsis when truncated)
    Output:
        Redacted string, or None when input is None.
    Side effects: None.
    """
    if text is None:
        return None
    out = str(text)
    if not out:
        return out

    out = _PEM_BLOCK.sub(
        "-----BEGIN PRIVATE KEY-----\\n****\\n-----END PRIVATE KEY-----",
        out,
    )
    out = _PASSWORD_KV.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACT_MASK}{m.group(4)}",
        out,
    )
    out = _URL_USERINFO.sub(
        lambda m: f"{m.group(1)}{m.group(2)}:{_REDACT_MASK}{m.group(4)}",
        out,
    )
    out = _JDBC_URL.sub(_redact_jdbc, out)
    out = _AWS_KEY.sub(lambda m: f"{m.group(1)}{_REDACT_MASK}", out)

    if max_len is not None and max_len > 0 and len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out


def redact_payload(
    payload: Optional[object],
    *,
    max_len: int = DEFAULT_PAYLOAD_REDACTED_MAX,
) -> Optional[str]:
    """
    Purpose:
        Truncate + secret-redact attack payloads stored on observations.
    Side effects: None.
    """
    if payload is None:
        return None
    return redact_error_text(str(payload), max_len=max_len)


def _redact_jdbc(match: re.Match[str]) -> str:
    prefix = match.group(1)
    rest = match.group(2)
    rest = _JDBC_USERINFO.sub(
        lambda m: f"{m.group(1)}{m.group(2)}:{_REDACT_MASK}{m.group(4)}",
        rest,
    )
    rest = _JDBC_PWD_QUERY.sub(
        lambda m: f"{m.group(1)}{_REDACT_MASK}",
        rest,
    )
    return prefix + rest
