"""
Module: talos.intruder.models

Purpose:
    Dataclasses and constants for Intruder (sessions, templates, attempts,
    segment outcomes, hard-cap defaults). Phase 1–5 plugins.

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
# Phase 2: per-host in-flight cap (None = no extra host limit beyond max_concurrency)
DEFAULT_MAX_CONCURRENCY_PER_HOST: int | None = None

# Phase 4 timing modes + adaptive / token_bucket defaults
TIMING_FIXED = "fixed"
TIMING_UNLIMITED = "unlimited"
TIMING_TOKEN_BUCKET = "token_bucket"
TIMING_ADAPTIVE = "adaptive"
KNOWN_TIMING_MODES: frozenset[str] = frozenset({
    TIMING_FIXED,
    TIMING_UNLIMITED,
    TIMING_TOKEN_BUCKET,
    TIMING_ADAPTIVE,
})
DEFAULT_BURST_SIZE = 1
DEFAULT_MIN_RPS = 0.25
DEFAULT_MAX_RPS = 10.0
DEFAULT_ADAPTIVE_SLOW_MS = 2000.0
DEFAULT_ADAPTIVE_WINDOW = 10
DEFAULT_ADAPTIVE_UP_FACTOR = 1.1
DEFAULT_ADAPTIVE_DOWN_FACTOR = 0.5
DEFAULT_ADAPTIVE_ERROR_STATUSES: tuple[int, ...] = (429, 503, 502, 504)

RESULT_BATCH_SIZE = 50
RESULT_BATCH_FLUSH_S = 0.5
CONTROL_FLAG_CACHE_S = 0.2

# Storage modes
STORAGE_METRICS_ONLY = "metrics_only"
STORAGE_SAMPLE_FLOWS = "sample_flows"
STORAGE_ALL_FLOWS = "all_flows"
KNOWN_STORAGE_MODES: frozenset[str] = frozenset({
    STORAGE_METRICS_ONLY,
    STORAGE_SAMPLE_FLOWS,
    STORAGE_ALL_FLOWS,
})

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

# Strategies (Phase 1 + Phase 2 multi-set)
STRATEGY_SINGLE = "single"
STRATEGY_SNIPER = "sniper"
STRATEGY_PITCHFORK = "pitchfork"
STRATEGY_CLUSTER_BOMB = "cluster_bomb"
STRATEGY_CARTESIAN = "cartesian"  # alias of cluster_bomb
STRATEGY_ZIP = "zip"
PHASE1_STRATEGIES: frozenset[str] = frozenset({STRATEGY_SINGLE, STRATEGY_SNIPER})
PHASE2_STRATEGIES: frozenset[str] = frozenset({
    STRATEGY_PITCHFORK,
    STRATEGY_CLUSTER_BOMB,
    STRATEGY_CARTESIAN,
    STRATEGY_ZIP,
})
KNOWN_STRATEGIES: frozenset[str] = PHASE1_STRATEGIES | PHASE2_STRATEGIES
# Multi-set strategies that bind each payload set to a variable in lockstep or product
MULTI_SET_STRATEGIES: frozenset[str] = frozenset({
    STRATEGY_PITCHFORK,
    STRATEGY_CLUSTER_BOMB,
    STRATEGY_CARTESIAN,
    STRATEGY_ZIP,
})

# Generators (Phase 1 + Phase 3 + Phase 4)
GEN_WORDLIST = "wordlist"
GEN_NUMBERS = "numbers"
GEN_STATIC = "static"
GEN_UUID = "uuid"
GEN_CSV = "csv"
GEN_JSON = "json"
GEN_EXAMPLE_VALUES = "example_values"
GEN_POOL = "pool"
GEN_DATES = "dates"
GEN_BRUTEFORCE = "bruteforce"
GEN_RANDOM = "random"
GEN_PATTERN = "pattern"
PHASE1_GENERATORS: frozenset[str] = frozenset({GEN_WORDLIST, GEN_NUMBERS, GEN_STATIC})
PHASE3_GENERATORS: frozenset[str] = frozenset({
    GEN_UUID,
    GEN_CSV,
    GEN_JSON,
    GEN_EXAMPLE_VALUES,
    GEN_POOL,
})
PHASE4_GENERATORS: frozenset[str] = frozenset({
    GEN_DATES,
    GEN_BRUTEFORCE,
    GEN_RANDOM,
    GEN_PATTERN,
})
KNOWN_GENERATORS: frozenset[str] = (
    PHASE1_GENERATORS | PHASE3_GENERATORS | PHASE4_GENERATORS
)

# Pool / grep defaults (Phase 3)
DEFAULT_POOL_MAX_VALUES = 50_000
DEFAULT_GREP_MAX_MATCHES = 50
DEFAULT_UUID_COUNT = 10

# Phase 4 advanced generator defaults / hard caps
DEFAULT_BRUTEFORCE_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
DEFAULT_BRUTEFORCE_MIN_LEN = 1
DEFAULT_BRUTEFORCE_MAX_LEN = 3
DEFAULT_BRUTEFORCE_MAX_COMBOS = 100_000  # refuse without --force above this
DEFAULT_RANDOM_COUNT = 100
DEFAULT_RANDOM_LENGTH = 8
DEFAULT_RANDOM_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_DATES_FORMAT = "%Y-%m-%d"
DEFAULT_DATES_STEP_DAYS = 1
DEFAULT_PATTERN_START = 0
DEFAULT_PATTERN_END = 99

# Phase 5: optional findings promote (off by default)
FINDINGS_ON_INTERESTING = "interesting"
FINDINGS_ON_MATCHED = "matched"  # alias of interesting (match tags or grep tags)
KNOWN_FINDINGS_ON: frozenset[str] = frozenset({
    FINDINGS_ON_INTERESTING,
    FINDINGS_ON_MATCHED,
})
DEFAULT_FINDINGS_PROMOTE = False
DEFAULT_FINDINGS_MAX = 25
DEFAULT_FINDINGS_ONLY_SUCCESS = True
CLUSTER_BY_SESSION = "session"
CLUSTER_BY_ENDPOINT = "endpoint"
KNOWN_FINDINGS_CLUSTER_BY: frozenset[str] = frozenset({
    CLUSTER_BY_SESSION,
    CLUSTER_BY_ENDPOINT,
})
ATTACK_TYPE_INTRUDER = "intruder"
VERDICT_INTRUDER_MATCH = "MATCH"

# Processors (Phase 1 + Phase 2)
PROC_URL_ENCODE = "url_encode"
PROC_URL_DECODE = "url_decode"
PROC_BASE64_ENCODE = "base64_encode"
PROC_BASE64_DECODE = "base64_decode"
PROC_TO_LOWER = "to_lower"
PROC_TO_UPPER = "to_upper"
PROC_HTML_ENCODE = "html_encode"
PROC_HTML_DECODE = "html_decode"
PROC_MD5 = "md5"
PROC_SHA1 = "sha1"
PROC_SHA256 = "sha256"
PROC_STRIP = "strip"
# Parameterized forms: prefix:<text>, suffix:<text> (see processors.build_processor)
PHASE1_PROCESSORS: frozenset[str] = frozenset({PROC_URL_ENCODE, PROC_BASE64_ENCODE})
PHASE2_PROCESSORS: frozenset[str] = frozenset({
    PROC_URL_DECODE,
    PROC_BASE64_DECODE,
    PROC_TO_LOWER,
    PROC_TO_UPPER,
    PROC_HTML_ENCODE,
    PROC_HTML_DECODE,
    PROC_MD5,
    PROC_SHA1,
    PROC_SHA256,
    PROC_STRIP,
})
KNOWN_PROCESSORS: frozenset[str] = PHASE1_PROCESSORS | PHASE2_PROCESSORS


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
    finding_id: Optional[str] = None
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
ERR_INVALID_STORAGE_MODE = "invalid_storage_mode"
ERR_MULTISET_UNBOUND = "multiset_unbound"
ERR_CLUSTER_BOMB_EMPTY = "cluster_bomb_empty"
ERR_INVALID_GREP = "invalid_grep"
ERR_POOL_NOT_FOUND = "pool_not_found"
ERR_PARAM_NOT_FOUND = "param_not_found"
ERR_INVALID_FILE_GENERATOR = "invalid_file_generator"
ERR_INVALID_TIMING = "invalid_timing"
ERR_BRUTEFORCE_TOO_LARGE = "bruteforce_too_large"
ERR_INVALID_DATES = "invalid_dates"
ERR_INVALID_PATTERN = "invalid_pattern"
ERR_INVALID_RANDOM = "invalid_random"
ERR_INVALID_FINDINGS = "invalid_findings"
ERR_FINDINGS_NO_MATCH = "findings_no_match"
