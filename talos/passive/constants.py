"""
Module: talos.passive.constants

Purpose:
    Canonical string and numeric constants for the Passive Source Intelligence
    / Secret Exposure Engine.  Detectors, registry, scoring, findings bridge,
    and CLI all import vocabulary from here so labels stay stable across
    schema versions and scanner upgrades.

    Bump SCANNER_VERSION when detection behaviour changes in a way that
    requires documents to be rescanned (new rules, scoring, or suppression).

Dependencies: enum (stdlib)
Data flow: Imported by models, config, and (later phases) worker / detectors /
           findings bridge / CLI.
Side effects: None.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Scanner identity
# ---------------------------------------------------------------------------

SCANNER_VERSION = "1.3.0"
"""Semantic version of the passive detection pipeline.

Documents already scanned with this exact version are not rescanned until
the version bumps (occurrence rows are still recorded).

1.1.0 — Phases 5–7: provider rules, contextual/suppress/scoring, decoder.
1.2.0 — Phases 8–10: findings bridge, CLI, source-map sourcesContent extract.
1.3.0 — Phases 11–12 + 14–16: HTML inline extract, infra disclosures, JWT /
        connection strings, communication rules, soft scan budget, docs.
"""

# ---------------------------------------------------------------------------
# Source document kinds
# ---------------------------------------------------------------------------


class SourceKind(str, Enum):
    """
    Purpose:
        Classify a response body (or extracted virtual document) by content
        family so extractors and detectors can specialize.

    Values are stored as TEXT in SQLite; prefer the enum in Python code.
    """

    HTML = "html"
    JAVASCRIPT = "javascript"
    JSON = "json"
    XML = "xml"
    TEXT = "text"
    CSS = "css"
    SOURCEMAP = "sourcemap"
    WASM = "wasm"
    BINARY = "binary"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Scan lifecycle statuses (source_documents.scan_status)
# ---------------------------------------------------------------------------

SCAN_STATUS_PENDING = "pending"
SCAN_STATUS_SCANNED = "scanned"
SCAN_STATUS_SKIPPED = "skipped"
SCAN_STATUS_ERROR = "error"
SCAN_STATUS_TOO_LARGE = "too_large"

SCAN_STATUSES: tuple[str, ...] = (
    SCAN_STATUS_PENDING,
    SCAN_STATUS_SCANNED,
    SCAN_STATUS_SKIPPED,
    SCAN_STATUS_ERROR,
    SCAN_STATUS_TOO_LARGE,
)

# ---------------------------------------------------------------------------
# Confidence levels (score → level mapping lives in scoring.py later)
# ---------------------------------------------------------------------------

CONFIDENCE_CONFIRMED_PATTERN = "CONFIRMED_PATTERN"
"""Exact provider / structured pattern; auto-finding eligible."""

CONFIDENCE_HIGH = "HIGH"
"""High confidence; auto-finding eligible (default threshold)."""

CONFIDENCE_MEDIUM = "MEDIUM"
"""Intelligence only — no auto finding in v1 defaults."""

CONFIDENCE_OBSERVATION_ONLY = "OBSERVATION_ONLY"
"""Low-signal observation; never auto-finding by default."""

CONFIDENCE_LEVELS: tuple[str, ...] = (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_OBSERVATION_ONLY,
)

# Score bands (inclusive lower bound for level; used by scoring Phase 7)
SCORE_CONFIRMED_PATTERN_MIN = 90
SCORE_HIGH_MIN = 70
SCORE_MEDIUM_MIN = 50

# Confidence levels that create findings when threshold is HIGH
FINDING_ELIGIBLE_LEVELS: frozenset[str] = frozenset({
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
})

# ---------------------------------------------------------------------------
# Detection categories
# ---------------------------------------------------------------------------

CATEGORY_SECRET = "secret"
CATEGORY_INFRASTRUCTURE_DISCLOSURE = "infrastructure_disclosure"
CATEGORY_SENSITIVE_INFO = "sensitive_info"

DETECTION_CATEGORIES: tuple[str, ...] = (
    CATEGORY_SECRET,
    CATEGORY_INFRASTRUCTURE_DISCLOSURE,
    CATEGORY_SENSITIVE_INFO,
)

# ---------------------------------------------------------------------------
# Detector families (detector_family column / fingerprint first component)
# ---------------------------------------------------------------------------

DETECTOR_FAMILY_PROVIDER = "provider"
DETECTOR_FAMILY_GENERIC = "generic"
DETECTOR_FAMILY_ENTROPY = "entropy"
DETECTOR_FAMILY_INFRA = "infra"
DETECTOR_FAMILY_PEM = "pem"
DETECTOR_FAMILY_JWT = "jwt"
DETECTOR_FAMILY_CONNECTION_STRING = "connection_string"
DETECTOR_FAMILY_CONTEXTUAL = "contextual"

DETECTOR_FAMILIES: tuple[str, ...] = (
    DETECTOR_FAMILY_PROVIDER,
    DETECTOR_FAMILY_GENERIC,
    DETECTOR_FAMILY_ENTROPY,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_PEM,
    DETECTOR_FAMILY_JWT,
    DETECTOR_FAMILY_CONNECTION_STRING,
    DETECTOR_FAMILY_CONTEXTUAL,
)

# ---------------------------------------------------------------------------
# Findings integration labels (bridge uses these in Phase 8; defined early
# so cluster keys and attack_type stay stable from day one)
# ---------------------------------------------------------------------------

ATTACK_TYPE_PASSIVE_SECRET = "passive_secret"
ATTACK_TYPE_PASSIVE_DISCLOSURE = "passive_disclosure"

VERDICT_EXPOSED = "EXPOSED"
VERDICT_DISCLOSED = "DISCLOSED"

CLUSTER_KEY_PREFIX_PASSIVE_SECRET = "PASSIVE_SECRET"

# ---------------------------------------------------------------------------
# Decode / size defaults (overridable via PassiveScanConfig)
# ---------------------------------------------------------------------------

DEFAULT_MAX_DOCUMENT_SIZE = 2_000_000
"""Max body bytes to scan (may exceed capture max_body_size if raised later)."""

DEFAULT_MAX_DECODE_DEPTH = 3
DEFAULT_MAX_DECODE_BYTES = 256_000
DEFAULT_MAX_CANDIDATES_PER_DOCUMENT = 500
DEFAULT_QUEUE_MAXSIZE = 500
DEFAULT_MAX_SCAN_TIME_MS = 0
"""Soft scan budget per document in milliseconds (0 = disabled)."""

# Context windows stored on detections (characters)
DEFAULT_CONTEXT_BEFORE_CHARS = 40
DEFAULT_CONTEXT_AFTER_CHARS = 40

# Redaction display
REDACT_VISIBLE_PREFIX = 4
REDACT_VISIBLE_SUFFIX = 4
REDACT_MASK = "****"
"""Middle mask used by redact_secret (first N + mask + last N)."""
