"""
Module: talos.auth_session

Purpose:
    Authentication & Session Testing attack engine.

    Probes whether a *presented* credential (JWT first) is actually validated —
    signature, algorithm, claims, structure — by applying deterministic token
    mutations, replaying one new HTTP flow per testcase, and scoring
    WEAK_VALIDATION | SECURE | UNKNOWN.

    Distinct from:
      - talos.projects.unauth  — auth removed / garbage (presence)
      - talos.projects.bac     — valid other-role session (access control)
      - talos auth test        — strip all auth (requires-auth?)
      - passive JWT detector  — client-side exposure only

Naming note (KD1):
    This package is the *attack engine* (``talos attack auth-session``).
    It is **not** ``Project.auth_session_path()`` / ``data_dir/auth_sessions/``,
    which store manual role session files for ``auth-config``.

Phase 1 (foundation): models, JWT codec/mutators, suite catalog, schema v54.
Phase 2 (bindings & candidates): db, extract, candidates generate, CLI
    (bind / generate / approve / reject / suite list). No HTTP / scheduler.

Later phases: engine, scheduler job type, decision filter, findings.

Dependencies: stdlib only for JWT mutations (base64, json); url_sink.jwt_claims
    for extract_jwt_token / decode_jwt_payload reuse.
Data flow: binding → suite list_test_cases → candidates → (later) engine → results
Side effects: Phase 2 writes bindings/candidates tables; no network.
"""

from __future__ import annotations

from talos.auth_session.models import (
    AUTH_TYPE_JWT,
    CANDIDATE_STATUSES,
    STATUS_APPROVED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_RUNNING,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
    AuthSessionBinding,
    AuthSessionCandidate,
    AuthSessionOutcome,
    AuthSessionResult,
    MutatedToken,
    TestCaseDef,
    TokenContext,
)
from talos.auth_session.types import ANALYZERS, AuthTypeAnalyzer, get_analyzer

__all__ = [
    "ANALYZERS",
    "AUTH_TYPE_JWT",
    "CANDIDATE_STATUSES",
    "STATUS_APPROVED",
    "STATUS_DONE",
    "STATUS_FAILED",
    "STATUS_PENDING",
    "STATUS_REJECTED",
    "STATUS_RUNNING",
    "VERDICT_SECURE",
    "VERDICT_UNKNOWN",
    "VERDICT_WEAK_VALIDATION",
    "AuthSessionBinding",
    "AuthSessionCandidate",
    "AuthSessionOutcome",
    "AuthSessionResult",
    "AuthTypeAnalyzer",
    "MutatedToken",
    "TestCaseDef",
    "TokenContext",
    "get_analyzer",
]
