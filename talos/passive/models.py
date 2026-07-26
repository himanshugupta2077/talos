"""
Module: talos.passive.models

Purpose:
    Pure dataclasses for the Passive Source Intelligence pipeline.

    These types are the in-memory contract between classifier, registry,
    extractors, detectors, scoring, and (later) DB persistence.  No
    SQLite, no HTTP, no logging side effects.

Core objects:
    PassiveScanJob   — minimal queue payload (flow_id; body loaded from DB)
    SourceDocument   — one scanned body (or virtual extracted fragment)
    SourceOccurrence — one URL/flow sighting of a document
    RawMatch         — detector hit before scoring/suppression
    Detection        — classified, scored, possibly suppressed observation
    DecodeResult     — output of the Decoder Pipeline (never a finding alone)

Dependencies: dataclasses, typing; talos.passive.constants
Data flow: constructed by worker / detectors; consumed by db / finding_bridge
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from talos.passive.constants import SourceKind


@dataclass(frozen=True)
class PassiveScanJob:
    """
    Purpose:
        Minimal job enqueued after FlowWorker commits a flow.  The scan
        worker reloads response_body from the DB by flow_id so capture
        queues never hold multi-MB bodies twice.

    Fields:
        project_id   — owning project
        flow_id      — flows.id (body source of truth)
        endpoint_id  — endpoints.id when known
        url          — full request URL
        host / path  — split for candidate gates and UI
        content_type — response Content-Type (may be empty)
        truncated    — True when capture truncated the body
        role_id / module_id — capture tags from the flow
        observed_at  — ISO timestamp of observation
    """

    project_id: str
    flow_id: str
    endpoint_id: Optional[str]
    url: str
    host: str
    path: str
    content_type: str
    truncated: bool
    role_id: str
    module_id: str
    observed_at: str


@dataclass
class SourceDocument:
    """
    Purpose:
        Identity and scan state for a unique response body (or virtual
        extracted document).  Dedup key is (project_id, body_hash).

    Fields:
        id              — UUID (assigned when persisted)
        project_id      — owning project
        body_hash       — SHA-256 hex of raw body bytes
        source_kind     — SourceKind classification
        body_size       — raw byte length
        truncated       — capture truncated flag
        scanner_version — last successful SCANNER_VERSION, or None
        scan_status     — pending | scanned | skipped | error | too_large
        first_flow_id   — first flow that introduced this body
        first_seen / last_seen — ISO timestamps
        last_scanned_at — ISO when scan finished, or None
        error_message   — last error if scan_status=error
        parent_document_id — optional link for extracted virtual docs
        logical_source_name — optional build-hash normalized name
        text            — normalized scan text (in-memory only; not a DB column)
    """

    id: str
    project_id: str
    body_hash: str
    source_kind: SourceKind
    body_size: int
    truncated: bool = False
    scanner_version: Optional[str] = None
    scan_status: str = "pending"
    first_flow_id: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_scanned_at: Optional[str] = None
    error_message: Optional[str] = None
    parent_document_id: Optional[str] = None
    logical_source_name: Optional[str] = None
    text: Optional[str] = None


@dataclass
class SourceOccurrence:
    """
    Purpose:
        One sighting of a SourceDocument on a particular flow/URL.
        Always inserted even when the document was already scanned
        (dedup is document-level, not occurrence-level).

    Fields map 1:1 to source_occurrences columns (schema v39).
    """

    id: str
    document_id: str
    flow_id: str
    endpoint_id: Optional[str]
    url: str
    host: str
    path: str
    logical_source_name: Optional[str]
    content_type: str
    observed_at: str
    role_id: str
    module_id: str


@dataclass
class RawMatch:
    """
    Purpose:
        Unscored detector hit.  Scoring and suppression turn this into a
        Detection (or drop it).

    Fields:
        detector_id     — rule id (e.g. aws_access_key_id)
        detector_family — provider | generic | entropy | …
        category        — secret | infrastructure_disclosure | …
        secret_type     — stable type label for UI/findings
        matched_key     — variable / assignment key when known
        raw_value       — secret material (never log at INFO)
        match_start / match_end — offsets into scanned text
        context_before / context_after — limited windows
        encoding_chain  — e.g. ["base64", "url"] if from decoder rescan
        decode_depth    — nesting depth when match came from decoded text
        entropy         — optional Shannon entropy of raw_value
        metadata        — free-form detector extras (keywords, rule pack)
    """

    detector_id: str
    detector_family: str
    category: str
    secret_type: str
    matched_key: Optional[str]
    raw_value: str
    match_start: int
    match_end: int
    context_before: str = ""
    context_after: str = ""
    encoding_chain: list[str] = field(default_factory=list)
    decode_depth: int = 0
    entropy: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class Detection:
    """
    Purpose:
        Classified, scored, optionally suppressed observation ready for
        persistence and (when eligible) finding creation.

    Fields:
        id                 — UUID when persisted
        document_id        — source_documents.id
        occurrence_id      — best occurrence for evidence
        detector_id / detector_family / category / secret_type
        matched_key        — assignment key if any
        redacted_value     — UI-safe display
        value_fingerprint  — SHA-256(family + NUL + canonical)
        confidence_score   — 0–100 additive score
        confidence_level   — CONFIRMED_PATTERN | HIGH | MEDIUM | OBSERVATION_ONLY
        entropy            — optional
        encoding_chain     — decode path if any
        decode_depth       — depth when matched on decoded text
        match_start / match_end
        context_before / context_after
        suppressed         — True when noise filters drop auto-finding
        suppression_reason — why suppressed
        finding_id         — set when a finding was created
        raw_value_stored   — policy: evidence may hold raw secret
        created_at         — ISO timestamp when persisted
        raw_value          — in-memory only; never a list-UI field
    """

    id: str
    document_id: str
    occurrence_id: Optional[str]
    detector_id: str
    detector_family: str
    category: str
    secret_type: str
    matched_key: Optional[str]
    redacted_value: str
    value_fingerprint: str
    confidence_score: int
    confidence_level: str
    entropy: Optional[float] = None
    encoding_chain: list[str] = field(default_factory=list)
    decode_depth: int = 0
    match_start: int = 0
    match_end: int = 0
    context_before: str = ""
    context_after: str = ""
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    finding_id: Optional[str] = None
    raw_value_stored: bool = False
    created_at: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class DecodeResult:
    """
    Purpose:
        Output of the Decoder Pipeline for one candidate blob.  Encodings
        alone never create findings; decoded text is fed back into
        detector stages 1–3 only (no infinite decode loops).

    Fields:
        original          — input candidate string
        decoded           — fully decoded text (UTF-8 best-effort)
        encoding_chain    — ordered codecs applied, e.g. ["url", "base64"]
        depth             — number of successful decode steps
        success           — True when at least one codec produced output
        error             — last failure reason when success is False
    """

    original: str
    decoded: str
    encoding_chain: list[str] = field(default_factory=list)
    depth: int = 0
    success: bool = False
    error: Optional[str] = None
