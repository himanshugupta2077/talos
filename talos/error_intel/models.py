"""
Module: talos.error_intel.models

Purpose:
    Pure dataclasses for the Error Intelligence pipeline.

    These types are the in-memory contract between the candidate gate,
    detectors, normalize/fingerprint/classify, storage, and the public
    observe_error API.  No SQLite, no HTTP, no logging side effects.

Core objects (Phase 0 vocabulary):
    ErrorIntelJob      — minimal queue payload (flow_id; body from DB)
    RawErrorMatch      — detector hit before normalize/fingerprint
    ErrorCluster       — unique fingerprint / project identity
    ErrorObservation   — one sighting with flow / param / attack context
    ErrorArtifact      — path/host/version disclosure attached to a sighting

Dependencies: dataclasses, typing; talos.error_intel.constants
Data flow: constructed by observe/worker/detectors; consumed by db later
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ErrorIntelJob:
    """
    Purpose:
        Minimal job enqueued after FlowWorker (or attack engines) commit a
        flow.  The worker reloads response_body from the DB by flow_id so
        capture queues never hold multi-MB bodies twice.

    Fields:
        project_id   — owning project
        flow_id      — flows.id (body source of truth)
        endpoint_id  — endpoints.id when known
        url / host / path — request identity for UI / filters
        content_type — response Content-Type (may be empty)
        status_code  — HTTP status when known
        truncated    — True when capture truncated the body
        attack_type  — proxy | replay | iv | bac | unauth | …
        parameter_uuid / parameter_name — optional attack linkage
        payload_redacted — truncated payload when attack-context enrich ran
        duration_ms  — optional timing
        observed_at  — ISO timestamp of observation
        role_id / module_id — capture tags from the flow when known
    """

    project_id: str
    flow_id: str
    endpoint_id: Optional[str]
    url: str
    host: str
    path: str
    content_type: str
    status_code: Optional[int]
    truncated: bool
    attack_type: str
    parameter_uuid: Optional[str]
    parameter_name: Optional[str]
    payload_redacted: Optional[str]
    duration_ms: Optional[float]
    observed_at: str
    role_id: str = ""
    module_id: str = ""


@dataclass
class RawErrorMatch:
    """
    Purpose:
        Unscored detector hit from a stage (A–G).  Normalize, fingerprint,
        and classify turn matches into a primary ErrorCluster plus
        observation artifacts.

    Fields:
        detector_id   — stable rule id (e.g. java_sql_syntax)
        family        — stack_trace | database | framework | …
        exception_type — best-effort class name (may be None)
        raw_snippet   — bounded evidence text
        match_start / match_end — offsets into scanned text (UI highlight)
        confidence    — CONFIRMED_PATTERN | HIGH | MEDIUM | WEAK seed
        category_hint — optional category before formal classify
        language      — language family when known
        metadata      — free-form extras (frames, vendor, SQLSTATE, …)
    """

    detector_id: str
    family: str
    exception_type: Optional[str] = None
    raw_snippet: str = ""
    match_start: int = 0
    match_end: int = 0
    confidence: str = "WEAK"
    category_hint: Optional[str] = None
    language: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorArtifact:
    """
    Purpose:
        Secondary disclosure extracted from an error body (path, host,
        version).  Stored on the observation (artifacts_json), not as a
        separate cluster unless fingerprint identity differs.

    Fields:
        kind   — path | host | version | username | db_name | …
        value  — extracted string (may be partially redacted for display)
        normalized — optional normalized form for dedup within a sighting
    """

    kind: str
    value: str
    normalized: Optional[str] = None


@dataclass
class ErrorCluster:
    """
    Purpose:
        One unique error fingerprint within a project.  Many observations
        (proxy + IV + BAC) link here when normalize+fingerprint agree.

    Identity:
        UNIQUE(project_id, fingerprint).  error_id is a stable UUID.

    Fields map to planned error_clusters columns (schema v43 — Phase 5).
    """

    id: str
    project_id: str
    fingerprint: str
    category: str
    severity: str
    language: str = "unknown"
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
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 0
    scanner_version: Optional[str] = None


@dataclass
class ErrorObservation:
    """
    Purpose:
        One sighting of an ErrorCluster on a particular flow / attack
        context.  Parameter and attack_type live here — never in the
        fingerprint.

    Fields map to planned error_observations columns (schema v43 — Phase 5).
    """

    id: str
    error_id: str
    flow_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    parameter_uuid: Optional[str] = None
    parameter_name: Optional[str] = None
    attack_type: str = "unknown"
    payload_redacted: Optional[str] = None
    response_status: Optional[int] = None
    response_length: Optional[int] = None
    duration_ms: Optional[float] = None
    response_hash: Optional[str] = None
    artifacts: list[ErrorArtifact] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    observed_at: Optional[str] = None
