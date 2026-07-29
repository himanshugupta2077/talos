"""
Module: talos.intruder.models

Purpose:
    Dataclasses and constants for Intruder Phase 1 (sessions, templates,
    attempts, segment outcomes, hard-cap defaults).

Dependencies: dataclasses, typing
Data flow:
    CLI / engine / strategies import models; pure data only.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ------------------------------------------------------------------ #
# Session status                                                       #
# ------------------------------------------------------------------ #

STATUS_DRAFT = "draft"
STATUS_CONFIGURED = "configured"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

SESSION_STATUSES: frozenset[str] = frozenset({
    STATUS_DRAFT,
    STATUS_CONFIGURED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_PAUSED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_CANCELLED,
})

CONTROL_PAUSE = "pause"
CONTROL_CANCEL = "cancel"

# Config document schema (independent of project SCHEMA_VERSION).
CONFIG_SCHEMA_VERSION = 1

# ------------------------------------------------------------------ #
# Hard safety caps (Phase 1 defaults)                                  #
# ------------------------------------------------------------------ #

DEFAULT_MAX_ATTEMPTS = 10_000
DEFAULT_MAX_RESULTS = 10_000
DEFAULT_MAX_DURATION_S = 3600.0  # active run time only
DEFAULT_AUTH_FAIL_THRESHOLD = 20
DEFAULT_CONFIRM_THRESHOLD = 1_000
DEFAULT_WORDLIST_MAX_LINES = 1_000_000
DEFAULT_WORDLIST_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB

DEFAULT_SLICE_MAX_ATTEMPTS = 100
DEFAULT_SLICE_MAX_WALL_S = 60.0

DEFAULT_RPS = 2.0
DEFAULT_MAX_CONCURRENCY = 1
DEFAULT_TIMEOUT_S = 30.0
DEFAULT_JITTER_MS = 0

RESULT_BATCH_SIZE = 50
RESULT_BATCH_FLUSH_S = 0.5
CONTROL_FLAG_CACHE_S = 0.2

# Storage modes
STORAGE_METRICS_ONLY = "metrics_only"
STORAGE_SAMPLE_FLOWS = "sample_flows"
STORAGE_ALL_FLOWS = "all_flows"

# Variable locations
LOCATION_PATH = "path"
LOCATION_QUERY = "query"
LOCATION_BODY = "body"
LOCATION_HEADER = "header"
LOCATION_COOKIE = "cookie"
LOCATION_RAW = "raw"

KNOWN_LOCATIONS: frozenset[str] = frozenset({
    LOCATION_PATH,
    LOCATION_QUERY,
    LOCATION_BODY,
    LOCATION_HEADER,
    LOCATION_COOKIE,
    LOCATION_RAW,
})

# Strategies Phase 1
STRATEGY_SINGLE = "single"
STRATEGY_SNIPER = "sniper"
PHASE1_STRATEGIES: frozenset[str] = frozenset({STRATEGY_SINGLE, STRATEGY_SNIPER})

# Generators Phase 1
GEN_WORDLIST = "wordlist"
GEN_NUMBERS = "numbers"
GEN_STATIC = "static"
PHASE1_GENERATORS: frozenset[str] = frozenset({GEN_WORDLIST, GEN_NUMBERS, GEN_STATIC})

# Processors Phase 1
PROC_URL_ENCODE = "url_encode"
PROC_BASE64_ENCODE = "base64_encode"
PHASE1_PROCESSORS: frozenset[str] = frozenset({PROC_URL_ENCODE, PROC_BASE64_ENCODE})


# ------------------------------------------------------------------ #
# Template / attempt types                                             #
# ------------------------------------------------------------------ #

@dataclass
class TemplateVariable:
    """One named injection point on the request template."""

    name: str
    location: str = LOCATION_QUERY
    path: Optional[str] = None
    original_value: Optional[str] = None
    encoding: str = "none"
    semantic_type: str = ""
    param_id: Optional[str] = None
    fixed_value: Optional[str] = None

    def inject_name(self) -> str:
        """Parameter name used for inject_value (path/header/cookie/body)."""
        return self.path or self.name

    def is_fixed(self) -> bool:
        return self.fixed_value is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "path": self.path,
            "original_value": self.original_value,
            "encoding": self.encoding,
            "semantic_type": self.semantic_type,
            "param_id": self.param_id,
            "fixed_value": self.fixed_value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TemplateVariable":
        return cls(
            name=str(d["name"]),
            location=str(d.get("location") or LOCATION_QUERY),
            path=d.get("path"),
            original_value=d.get("original_value"),
            encoding=str(d.get("encoding") or "none"),
            semantic_type=str(d.get("semantic_type") or ""),
            param_id=d.get("param_id"),
            fixed_value=d.get("fixed_value"),
        )


@dataclass
class AttemptSpec:
    """Fully rendered request ready for HTTP send."""

    attempt_index: int
    variables: dict[str, str]
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[bytes]


@dataclass
class AttemptResult:
    """Outcome of one Intruder attempt."""

    attempt_index: int
    variables: dict[str, str]
    status_code: Optional[int]
    success: bool
    failure_reason: Optional[str]
    duration_ms: Optional[float]
    metrics: dict[str, Any] = field(default_factory=dict)
    flow_id: Optional[str] = None
    match_tags: list[str] = field(default_factory=list)
    grepped: dict[str, list[str]] = field(default_factory=dict)
    interesting: bool = False
    body_length: Optional[int] = None
    word_count: Optional[int] = None
    line_count: Optional[int] = None
    body_hash: Optional[str] = None
    fingerprint: dict[str, Any] = field(default_factory=dict)
    response_body: Optional[bytes] = None
    response_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class SegmentOutcome:
    """
    Result of one scheduler time-slice / --right-now segment.

    reason:
        continue | paused | cancelled | completed | failed | process_stop
    """

    reason: str
    attempts_this_segment: int
    session_status: str
    error: Optional[str] = None


# Stable validation / precondition error codes (CLI / AI contract).
ERR_MISSING_BASELINE = "missing_baseline"
ERR_NO_VARIABLES = "no_variables"
ERR_UNBOUND_VARIABLE = "unbound_variable"
ERR_EMPTY_GENERATOR = "empty_generator"
ERR_INVALID_NUMBERS = "invalid_numbers"
ERR_SNIPER_NO_TARGETS = "sniper_no_targets"
ERR_UNKNOWN_PLUGIN = "unknown_plugin"
ERR_UNSUPPORTED_CONFIG_VERSION = "unsupported_config_version"
ERR_WORDLIST_TOO_LARGE = "wordlist_too_large"
ERR_CONFIRM_REQUIRED = "confirm_required"
ERR_ENDPOINT_ANNOTATED_LOGOUT = "endpoint_annotated_logout"
ERR_ENDPOINT_ANNOTATED_DANGEROUS = "endpoint_annotated_dangerous"
ERR_OUT_OF_SCOPE = "out_of_scope"
ERR_SESSION_BUSY = "session_busy"
ERR_PATH_INJECT_UNAVAILABLE = "path_inject_unavailable"
ERR_SESSION_NOT_FOUND = "session_not_found"
ERR_INVALID_STATUS = "invalid_status"
