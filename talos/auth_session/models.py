"""
Module: talos.auth_session.models

Purpose:
    Dataclasses and status/verdict constants for the Authentication & Session
    Testing engine. Pure data only — no DB or network I/O.

Dependencies: dataclasses, typing
Data flow: codec / suite / (later) db / engine import these types.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ------------------------------------------------------------------ #
# Auth types                                                           #
# ------------------------------------------------------------------ #

AUTH_TYPE_JWT = "jwt"

KNOWN_AUTH_TYPES: frozenset[str] = frozenset({AUTH_TYPE_JWT})

LOCATION_HEADER = "header"
LOCATION_COOKIE = "cookie"

KNOWN_LOCATIONS: frozenset[str] = frozenset({LOCATION_HEADER, LOCATION_COOKIE})


# ------------------------------------------------------------------ #
# Candidate lifecycle (KD4)                                            #
# ------------------------------------------------------------------ #

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"

CANDIDATE_STATUSES: frozenset[str] = frozenset({
    STATUS_PENDING,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_RUNNING,
    STATUS_DONE,
    STATUS_FAILED,
})

# Bind auto-selects this many method-diverse target flows.
DEFAULT_TARGET_LIMIT = 5

# Run no longer requires approve. Pending (and leftover approved) enqueue.
RUNNABLE_STATUSES: frozenset[str] = frozenset({
    STATUS_PENDING,
    STATUS_APPROVED,
})


# ------------------------------------------------------------------ #
# Verdicts (KD7)                                                       #
# ------------------------------------------------------------------ #

VERDICT_WEAK_VALIDATION = "WEAK_VALIDATION"
VERDICT_SECURE = "SECURE"
VERDICT_UNKNOWN = "UNKNOWN"

AUTH_SESSION_VERDICTS: frozenset[str] = frozenset({
    VERDICT_WEAK_VALIDATION,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
})


# ------------------------------------------------------------------ #
# Test / mutation families                                             #
# ------------------------------------------------------------------ #

FAMILY_SIGNATURE = "signature"
FAMILY_ALGORITHM = "algorithm"
FAMILY_ALGORITHM_DEGRADE = "algorithm_degrade"
FAMILY_STRUCTURE = "structure"
FAMILY_CLAIMS = "claims"
FAMILY_KID = "kid"

KNOWN_FAMILIES: frozenset[str] = frozenset({
    FAMILY_SIGNATURE,
    FAMILY_ALGORITHM,
    FAMILY_ALGORITHM_DEGRADE,
    FAMILY_STRUCTURE,
    FAMILY_CLAIMS,
    FAMILY_KID,
})

RISK_CRITICAL = "critical"
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"


# ------------------------------------------------------------------ #
# Dataclasses                                                          #
# ------------------------------------------------------------------ #


@dataclass(frozen=True)
class TestCaseDef:
    """
    Purpose:
        One deterministic suite row (catalog entry).
    Fields:
        test_id         — stable id, e.g. ``jwt.alg_none``
        title           — short human label
        family          — signature | algorithm | algorithm_degrade | …
        description     — longer operator-facing text
        risk_hint       — critical | high | medium | low (evidence only)
        requires_claims — claim names that must exist for generate to include
    Side effects: None.
    """

    test_id: str
    title: str
    family: str
    description: str
    risk_hint: str
    requires_claims: tuple[str, ...] = ()


@dataclass(frozen=True)
class TokenContext:
    """
    Purpose:
        Parsed view of an auth field value at generate / apply time.
    Fields:
        raw_token              — compact JWT without scheme
        scheme                 — ``Bearer`` / ``Token`` / None
        header                 — decoded JWT header dict
        payload                — decoded JWT payload dict
        location               — header | cookie
        field_name             — Authorization, session, …
        original_header_value  — full original field value (scheme + token)
    Side effects: None.
    """

    raw_token: str
    scheme: Optional[str]
    header: dict[str, Any]
    payload: dict[str, Any]
    location: str
    field_name: str
    original_header_value: str


@dataclass(frozen=True)
class MutatedToken:
    """
    Purpose:
        Result of applying one test_id mutation.
    Fields:
        test_id                   — suite id applied
        new_raw_token             — compact JWT (may be two-part for missing sig)
        new_header_or_cookie_value — value to write (scheme re-applied if needed)
        mutation_summary          — human + machine readable description
        metadata                  — extra evidence (target alg, etc.)
    Side effects: None.
    """

    test_id: str
    new_raw_token: str
    new_header_or_cookie_value: str
    mutation_summary: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthSessionBinding:
    """
    Purpose:
        Row model for ``auth_session_bindings``.
    Side effects: None (pure data).
    """

    id: str
    location: str
    name: str
    auth_type: str
    role_id: Optional[str] = None
    config_json: str = "{}"
    created_at: str = ""
    updated_at: str = ""


@dataclass
class AuthSessionCandidate:
    """
    Purpose:
        Row model for ``auth_session_candidates``.
    Side effects: None (pure data).
    """

    id: str
    binding_id: str
    baseline_flow_id: str
    auth_type: str
    test_id: str
    test_family: str
    title: str
    mutation_summary: str
    status: str
    endpoint_id: Optional[str] = None
    token_fingerprint: Optional[str] = None
    risk_hint: Optional[str] = None
    reject_reason: Optional[str] = None
    skip_reason: Optional[str] = None
    meta_json: str = "{}"
    created_at: str = ""
    updated_at: str = ""


@dataclass
class AuthSessionResult:
    """
    Purpose:
        Row model for ``auth_session_results`` (one row per executed test).
    Side effects: None (pure data).
    """

    replay_flow_id: str
    original_flow_id: str
    candidate_id: str
    binding_id: str
    auth_type: str
    test_id: str
    verdict: str
    endpoint_id: Optional[str] = None
    test_family: Optional[str] = None
    mutation_summary: Optional[str] = None
    original_status: Optional[int] = None
    replay_status: Optional[int] = None
    diff_verdict: Optional[str] = None
    matched_section: Optional[str] = None
    matched_group: Optional[str] = None
    matched_rules: Optional[str] = None
    failure_reason: Optional[str] = None
    created_at: str = ""


@dataclass
class AuthSessionOutcome:
    """
    Purpose:
        Engine return value for scheduler settle (Phase 3+).
        Aligns with Unauth/BAC outcome shapes.
    Side effects: None (pure data).
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    original_status: Optional[int]
    replay_status: Optional[int]
    diff_verdict: Optional[str]
    auth_session_verdict: str
    test_id: str
    binding_id: str
    candidate_id: str
    auth_type: str
    endpoint_id: Optional[str] = None
    failure_reason: Optional[str] = None
    matched_section: Optional[str] = None
    matched_group: Optional[str] = None
    matched_rules: Optional[str] = None
