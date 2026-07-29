"""
Module: talos.error_intel.constants

Purpose:
    Canonical vocabulary for Error Intelligence — categories, severities,
    languages, attack-context labels, and scanner versioning.

    Detectors, classification, DB, CLI, and (later) UI import labels from
    here so fingerprints and cluster rows stay stable across schema bumps.

    Bump ERROR_INTEL_VERSION when detection / normalize / fingerprint
    behaviour changes in a way that requires rescan invalidation
    (mirrors talos.passive.constants.SCANNER_VERSION).

Dependencies: enum (stdlib)
Data flow: Imported by models, config, candidate, and later phases
Side effects: None.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Scanner identity
# ---------------------------------------------------------------------------

ERROR_INTEL_VERSION = "0.4.3"
"""Semantic version of the Error Intelligence pipeline.

Clusters / observations scanned at this exact version are not full-rescanned
until the version bumps (sightings may still be recorded).

0.1.0 — Phases 0–1: design freeze, package skeleton, is_error_candidate gate.
0.2.0 — Phase 2: multi-stage detectors (stack / DB / framework / infra /
        security / disclosure / http_generic) + ErrorDetectorOrchestrator.
0.3.0 — Phases 3–5: classify + severity scoring, normalize + fingerprint,
        schema v43 (error_clusters / error_observations / error_intel_config).
0.4.0 — Phases 6–8: ErrorIntelQueue + ErrorIntelWorker, FlowWorker/replay
        hooks, attach_error_context, parameter/endpoint rollups, CLI.
0.4.1 — P0 fixes: fingerprint merges same exception across status buckets;
        bare nginx/Apache/Tomcat/IIS default pages gated like Stage G.
0.4.2 — P1 fixes: empty-body gate, exception FQCN canonicalize, detector FP
        tightening, attack_type fill-only, unique flow_id observation +
        atomic store/observation_count integrity (schema v44).
0.4.3 — P2/P3 fixes: versioned rescan, rescan includes 2xx candidates,
        SQLSTATE vendor map, evidence secret redaction, flow_meta attach
        durability, 2xx gate noise reduction.
"""

# ---------------------------------------------------------------------------
# Categories (v1 closed set — stored on error_clusters.category)
# ---------------------------------------------------------------------------

CATEGORY_STACK_TRACE = "stack_trace"
CATEGORY_DATABASE = "database"
CATEGORY_FRAMEWORK = "framework"
CATEGORY_INFRASTRUCTURE = "infrastructure"
CATEGORY_SECURITY = "security"
CATEGORY_VALIDATION = "validation"
CATEGORY_HTTP = "http"
CATEGORY_DISCLOSURE = "disclosure"
CATEGORY_UNKNOWN = "unknown"

ERROR_CATEGORIES: tuple[str, ...] = (
    CATEGORY_STACK_TRACE,
    CATEGORY_DATABASE,
    CATEGORY_FRAMEWORK,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_SECURITY,
    CATEGORY_VALIDATION,
    CATEGORY_HTTP,
    CATEGORY_DISCLOSURE,
    CATEGORY_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Severity bands (deterministic scoring maps into these)
# ---------------------------------------------------------------------------

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

ERROR_SEVERITIES: tuple[str, ...] = (
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

# Score → severity lower bounds (inclusive); used by classify Phase 3+
SCORE_CRITICAL_MIN = 90
SCORE_HIGH_MIN = 70
SCORE_MEDIUM_MIN = 40
# below MEDIUM → low

# ---------------------------------------------------------------------------
# Language / family labels
# ---------------------------------------------------------------------------

LANG_JAVA = "java"
LANG_CSHARP = "csharp"
LANG_PYTHON = "python"
LANG_JAVASCRIPT = "javascript"
LANG_PHP = "php"
LANG_RUBY = "ruby"
LANG_GO = "go"
LANG_RUST = "rust"
LANG_UNKNOWN = "unknown"

ERROR_LANGUAGES: tuple[str, ...] = (
    LANG_JAVA,
    LANG_CSHARP,
    LANG_PYTHON,
    LANG_JAVASCRIPT,
    LANG_PHP,
    LANG_RUBY,
    LANG_GO,
    LANG_RUST,
    LANG_UNKNOWN,
)


class ErrorLanguage(str, Enum):
    """Language family for stack / exception detectors. Stored as TEXT."""

    JAVA = LANG_JAVA
    CSHARP = LANG_CSHARP
    PYTHON = LANG_PYTHON
    JAVASCRIPT = LANG_JAVASCRIPT
    PHP = LANG_PHP
    RUBY = LANG_RUBY
    GO = LANG_GO
    RUST = LANG_RUST
    UNKNOWN = LANG_UNKNOWN


# ---------------------------------------------------------------------------
# Confidence seeds (RawErrorMatch → aggregate on cluster)
# ---------------------------------------------------------------------------

CONFIDENCE_CONFIRMED_PATTERN = "CONFIRMED_PATTERN"
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_WEAK = "WEAK"

CONFIDENCE_LEVELS: tuple[str, ...] = (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
)

# ---------------------------------------------------------------------------
# Attack / observation context (error_observations.attack_type)
# ---------------------------------------------------------------------------

ATTACK_TYPE_PROXY = "proxy"
ATTACK_TYPE_REPLAY = "replay"
ATTACK_TYPE_IV = "iv"
ATTACK_TYPE_BAC = "bac"
ATTACK_TYPE_UNAUTH = "unauth"
ATTACK_TYPE_UNKNOWN = "unknown"

ATTACK_TYPES: tuple[str, ...] = (
    ATTACK_TYPE_PROXY,
    ATTACK_TYPE_REPLAY,
    ATTACK_TYPE_IV,
    ATTACK_TYPE_BAC,
    ATTACK_TYPE_UNAUTH,
    ATTACK_TYPE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Status buckets (fingerprint identity; not exact status codes)
# ---------------------------------------------------------------------------

STATUS_BUCKET_2XX_ERROR_BODY = "2xx_error_body"
STATUS_BUCKET_4XX = "4xx"
STATUS_BUCKET_5XX = "5xx"
STATUS_BUCKET_OTHER = "other"
STATUS_BUCKET_NONE = "none"

STATUS_BUCKETS: tuple[str, ...] = (
    STATUS_BUCKET_2XX_ERROR_BODY,
    STATUS_BUCKET_4XX,
    STATUS_BUCKET_5XX,
    STATUS_BUCKET_OTHER,
    STATUS_BUCKET_NONE,
)

# ---------------------------------------------------------------------------
# Detector families (stages A–G)
# ---------------------------------------------------------------------------

DETECTOR_FAMILY_STACK = "stack_trace"
DETECTOR_FAMILY_DATABASE = "database"
DETECTOR_FAMILY_FRAMEWORK = "framework"
DETECTOR_FAMILY_INFRA = "infrastructure"
DETECTOR_FAMILY_SECURITY = "security"
DETECTOR_FAMILY_DISCLOSURE = "disclosure"
DETECTOR_FAMILY_HTTP = "http_generic"

DETECTOR_FAMILIES: tuple[str, ...] = (
    DETECTOR_FAMILY_STACK,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_DISCLOSURE,
    DETECTOR_FAMILY_HTTP,
)

# ---------------------------------------------------------------------------
# Defaults (overridable via ErrorIntelConfig)
# ---------------------------------------------------------------------------

DEFAULT_MAX_BODY_SCAN = 512_000
"""Max response bytes to scan in the worker (not the cheap gate sample)."""

DEFAULT_GATE_SNIFF_BYTES = 16_384
"""Max bytes the candidate gate may decode for marker / JSON-key sniff."""

DEFAULT_QUEUE_MAXSIZE = 500
DEFAULT_EVIDENCE_SNIPPET_MAX = 4_096
DEFAULT_RAW_SNIPPET_MAX = 8_192
DEFAULT_PAYLOAD_REDACTED_MAX = 512

# Default response header names that alone can pass the candidate gate
# (case-insensitive compare after lowercasing).
DEFAULT_ERROR_HEADER_NAMES: frozenset[str] = frozenset({
    "x-exception",
    "x-exception-message",
    "x-error",
    "x-error-message",
    "x-error-type",
    "x-debug-exception",
    "x-runtime-error",
    "x-aspnet-error",
})
"""Server / debug headers that mark a response as error-like without body."""
