"""
Module: talos.error_intel.fingerprint

Purpose:
    Stable cluster identity for Error Intelligence (Phase 4).

    fingerprint = SHA256(
        status_bucket | category | language | exception_type |
        framework | database | normalized_stack_hash |
        normalized_message_hash | server_bucket
    )

    When exception_type or normalized stack frames are present, status_bucket
    is coerced to ``none`` so the same exception merges across HTTP statuses
    (proxy 500 / IV 400 / BAC 200). Weak-identity clusters (message-only,
    bare infra chrome) still use the real status bucket.

    Endpoint / parameter / attack_type are **never** part of the
    fingerprint — they live on error_observations only. Exact HTTP status
    is stored on observations (response_status), not identity.

Dependencies: hashlib; talos.error_intel.{candidate, constants, normalize}
Data flow: classified fields + normalized stack/message → hex fingerprint
Side effects: None.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from talos.error_intel.candidate import status_bucket as _status_bucket
from talos.error_intel.constants import (
    LANG_UNKNOWN,
    STATUS_BUCKET_NONE,
)


def short_hash(material: str, *, length: int = 32) -> str:
    """
    Purpose:
        SHA-256 hex truncated for stack/message component hashes.
    Input:
        material — UTF-8 text (empty → empty hash of empty string)
        length — hex chars to keep (default 32 = 128 bits)
    Output:
        Lowercase hex string.
    Side effects: None.
    """
    digest = hashlib.sha256(
        (material or "").encode("utf-8", errors="replace")
    ).hexdigest()
    n = max(8, min(64, int(length)))
    return digest[:n]


def stack_component_hash(normalized_stack: Optional[str]) -> str:
    """Hash of normalized stack frames (empty stack → empty string)."""
    if not normalized_stack:
        return ""
    return short_hash(normalized_stack)


def message_component_hash(normalized_message: Optional[str]) -> str:
    """Hash of normalized short message (empty → empty string)."""
    if not normalized_message:
        return ""
    return short_hash(normalized_message)


def fingerprint_status_bucket(
    status_code: Optional[int],
    *,
    body_error_shaped: bool = True,
) -> str:
    """
    Purpose:
        Resolve the *display / observation* status bucket from HTTP status.
        When status is 2xx and we already have error-shaped body hits,
        use ``2xx_error_body`` (not ``other``).

        For cluster *identity*, prefer :func:`identity_status_bucket` so
        strong exception/stack clusters do not fork on status.

    Side effects: None.
    """
    return _status_bucket(status_code, body_error_shaped=body_error_shaped)


def identity_status_bucket(
    status_code: Optional[int],
    *,
    body_error_shaped: bool = True,
    exception_type: Optional[str] = None,
    normalized_stack: Optional[str] = None,
) -> str:
    """
    Purpose:
        Status component for the fingerprint identity tuple.

        When ``exception_type`` or ``normalized_stack`` is non-empty, return
        ``none`` so proxy / IV / BAC sightings of the same exception merge.
        Otherwise return the real HTTP status bucket (weak-identity clusters).

    Side effects: None.
    """
    if (exception_type or "").strip() or (normalized_stack or "").strip():
        return STATUS_BUCKET_NONE
    return fingerprint_status_bucket(
        status_code,
        body_error_shaped=body_error_shaped,
    )


def build_identity_tuple(
    *,
    status_bucket: str,
    category: str,
    language: str,
    exception_type: Optional[str],
    framework: Optional[str],
    database: Optional[str],
    normalized_stack: Optional[str],
    normalized_message: Optional[str],
    server: Optional[str],
) -> str:
    """
    Purpose:
        Canonical pipe-joined identity material (before SHA-256).
        Useful for tests / debug. Empty optional fields become "".
    Side effects: None.
    """
    stack_h = stack_component_hash(normalized_stack)
    msg_h = message_component_hash(normalized_message)
    parts = [
        (status_bucket or STATUS_BUCKET_NONE).strip().lower(),
        (category or "unknown").strip().lower(),
        (language or LANG_UNKNOWN).strip().lower(),
        (exception_type or "").strip(),
        (framework or "").strip().lower(),
        (database or "").strip().lower(),
        stack_h,
        msg_h,
        (server or "").strip().lower(),
    ]
    return "|".join(parts)


def compute_fingerprint(
    *,
    status_bucket: str,
    category: str,
    language: str,
    exception_type: Optional[str] = None,
    framework: Optional[str] = None,
    database: Optional[str] = None,
    normalized_stack: Optional[str] = None,
    normalized_message: Optional[str] = None,
    server: Optional[str] = None,
) -> str:
    """
    Purpose:
        Compute the stable error cluster fingerprint (full SHA-256 hex).

    Identity (plan Phase 4):
        status_bucket | category | language | exception_type |
        framework | database | normalized_stack_hash |
        normalized_message_hash | server_bucket

    Callers should pass :func:`identity_status_bucket` (not the raw display
    bucket) when exception/stack identity is available.

    Output:
        64-char lowercase hex SHA-256.

    Side effects: None.
    """
    material = build_identity_tuple(
        status_bucket=status_bucket,
        category=category,
        language=language,
        exception_type=exception_type,
        framework=framework,
        database=database,
        normalized_stack=normalized_stack,
        normalized_message=normalized_message,
        server=server,
    )
    return hashlib.sha256(
        material.encode("utf-8", errors="replace")
    ).hexdigest()
