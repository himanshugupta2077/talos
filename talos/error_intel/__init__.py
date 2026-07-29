"""
Package: talos.error_intel

Purpose:
    Error Intelligence — passive, cross-cutting subsystem that captures
    what an HTTP error **contains** (exception types, stack frames, DB
    vendors, path leaks), fingerprints identical errors across the project,
    and links them to flows / endpoints / parameters / attacks.

    This is **not** Input Validation (IV characterizes mutation outcomes:
    accepted / rejected / …).  It is **not** a Findings subtype in v1.

    Architectural constraints (do not violate):
        - Passive only — no extra HTTP; observe stored responses only
        - Intelligence first — tables store errors + sightings; no auto
          Findings in v1
        - Capture-safe — cheap gate in FlowWorker; heavy parse on a
          dedicated queue/worker. Never block TalosAddon.response() or
          expensive work inside FlowWorker._persist_db
        - Body source of truth — job carries flow_id; worker reloads
          flows.response_body
        - Not status≥400 alone — stack traces on 200 are in scope
        - Attack modules never parse errors — call observe_error(...) or
          rely on automatic post-flow hook
        - IV remains independent — optional later link by flow_id / error_id
        - Deterministic — rules + extractors + scoring; no LLM in v1

Phase status:
    Phase 0 — design freeze (docs/architecture.md) + package skeleton
    Phase 1 — is_error_candidate gate
    Phase 2 — detector stages A–G + ErrorDetectorOrchestrator
    Phase 3 — classify (category + severity scoring)  **Done**
    Phase 4 — normalize + fingerprint               **Done**
    Phase 5 — schema v43 + db CRUD                  **Done**
    Phase 6 — queue/worker + FlowWorker/replay hooks **Done**
    Phase 7 — parameter linkage aggregations          **Done**
    Phase 8 — CLI (talos error-intel …)               **Done**
    Phase 9 — Control Panel UI (deferred)
    Phase 10 — docs + golden tests expansion

Public exports (Phases 0–8):
    ERROR_INTEL_VERSION, categories, severities, languages
    ErrorIntelJob, RawErrorMatch, ErrorCluster, ErrorObservation, …
    ErrorIntelConfig, default_config, merge_config
    is_error_candidate, is_error_candidate_from_flow, status_bucket
    observe_error, attach_error_context
    detect_errors, ErrorDetectorOrchestrator, ErrorDetectResult, pick_primary_match
    normalize_error_text, compute_fingerprint, classify_error, ClassifiedError
    ErrorIntelQueue, ErrorIntelWorker, maybe_enqueue_error_scan
    process_error_scan_sync, store helpers via talos.error_intel.db

Dependencies: stdlib + talos.passive.classifier (shared magic/CT helpers)
Data flow: FlowWorker gate → ErrorIntelQueue → ErrorIntelWorker
           → detectors → normalize → fingerprint → classify → store
Side effects: Capture path only cheap gate + enqueue; worker writes DB.
"""

from talos.error_intel.candidate import (
    is_error_candidate,
    is_error_candidate_from_flow,
    status_bucket,
)
from talos.error_intel.classify import (
    ClassifiedError,
    classify_error,
    classify_from_detect,
    confidence_from_seed,
    severity_from_score,
)
from talos.error_intel.config import (
    ErrorIntelConfig,
    config_from_dict,
    default_config,
    header_names_for_gate,
    merge_config,
)
from talos.error_intel.constants import (
    ATTACK_TYPE_BAC,
    ATTACK_TYPE_IV,
    ATTACK_TYPE_PROXY,
    ATTACK_TYPE_REPLAY,
    ATTACK_TYPE_UNAUTH,
    ATTACK_TYPE_UNKNOWN,
    ATTACK_TYPES,
    CATEGORY_DATABASE,
    CATEGORY_DISCLOSURE,
    CATEGORY_FRAMEWORK,
    CATEGORY_HTTP,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_SECURITY,
    CATEGORY_STACK_TRACE,
    CATEGORY_UNKNOWN,
    CATEGORY_VALIDATION,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
    DEFAULT_ERROR_HEADER_NAMES,
    DEFAULT_GATE_SNIFF_BYTES,
    DEFAULT_MAX_BODY_SCAN,
    DEFAULT_QUEUE_MAXSIZE,
    DETECTOR_FAMILIES,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_DISCLOSURE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_HTTP,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_STACK,
    ERROR_CATEGORIES,
    ERROR_INTEL_VERSION,
    ERROR_LANGUAGES,
    ERROR_SEVERITIES,
    ErrorLanguage,
    LANG_CSHARP,
    LANG_GO,
    LANG_JAVA,
    LANG_JAVASCRIPT,
    LANG_PHP,
    LANG_PYTHON,
    LANG_RUBY,
    LANG_RUST,
    LANG_UNKNOWN,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_BUCKET_2XX_ERROR_BODY,
    STATUS_BUCKET_4XX,
    STATUS_BUCKET_5XX,
    STATUS_BUCKET_NONE,
    STATUS_BUCKET_OTHER,
    STATUS_BUCKETS,
)
from talos.error_intel.detectors import (
    ErrorDetectResult,
    ErrorDetectorOrchestrator,
    detect_errors,
    pick_primary_match,
)
from talos.error_intel.fingerprint import (
    build_identity_tuple,
    compute_fingerprint,
    fingerprint_status_bucket,
    identity_status_bucket,
    message_component_hash,
    short_hash,
    stack_component_hash,
)
from talos.error_intel.models import (
    ErrorArtifact,
    ErrorCluster,
    ErrorIntelJob,
    ErrorObservation,
    RawErrorMatch,
)
from talos.error_intel.normalize import (
    extract_message_norm,
    extract_normalized_stack_from_match,
    normalize_error_text,
    normalize_frames,
    normalize_path_shape,
    normalize_stack_line_numbers,
)
from talos.error_intel.observe import attach_error_context, observe_error
from talos.error_intel.queue import ErrorIntelQueue
from talos.error_intel.worker import (
    ErrorIntelWorker,
    build_job_from_flow,
    infer_attack_type,
    maybe_enqueue_error_scan,
    process_error_scan_job,
    process_error_scan_sync,
)

__all__ = [
    # Identity
    "ERROR_INTEL_VERSION",
    "ErrorLanguage",
    # Categories / severities / languages
    "CATEGORY_STACK_TRACE",
    "CATEGORY_DATABASE",
    "CATEGORY_FRAMEWORK",
    "CATEGORY_INFRASTRUCTURE",
    "CATEGORY_SECURITY",
    "CATEGORY_VALIDATION",
    "CATEGORY_HTTP",
    "CATEGORY_DISCLOSURE",
    "CATEGORY_UNKNOWN",
    "ERROR_CATEGORIES",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "ERROR_SEVERITIES",
    "LANG_JAVA",
    "LANG_CSHARP",
    "LANG_PYTHON",
    "LANG_JAVASCRIPT",
    "LANG_PHP",
    "LANG_RUBY",
    "LANG_GO",
    "LANG_RUST",
    "LANG_UNKNOWN",
    "ERROR_LANGUAGES",
    "CONFIDENCE_CONFIRMED_PATTERN",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_WEAK",
    "CONFIDENCE_LEVELS",
    "ATTACK_TYPE_PROXY",
    "ATTACK_TYPE_REPLAY",
    "ATTACK_TYPE_IV",
    "ATTACK_TYPE_BAC",
    "ATTACK_TYPE_UNAUTH",
    "ATTACK_TYPE_UNKNOWN",
    "ATTACK_TYPES",
    "STATUS_BUCKET_2XX_ERROR_BODY",
    "STATUS_BUCKET_4XX",
    "STATUS_BUCKET_5XX",
    "STATUS_BUCKET_OTHER",
    "STATUS_BUCKET_NONE",
    "STATUS_BUCKETS",
    "DETECTOR_FAMILY_STACK",
    "DETECTOR_FAMILY_DATABASE",
    "DETECTOR_FAMILY_FRAMEWORK",
    "DETECTOR_FAMILY_INFRA",
    "DETECTOR_FAMILY_SECURITY",
    "DETECTOR_FAMILY_DISCLOSURE",
    "DETECTOR_FAMILY_HTTP",
    "DETECTOR_FAMILIES",
    "DEFAULT_MAX_BODY_SCAN",
    "DEFAULT_GATE_SNIFF_BYTES",
    "DEFAULT_QUEUE_MAXSIZE",
    "DEFAULT_ERROR_HEADER_NAMES",
    # Models
    "ErrorIntelJob",
    "RawErrorMatch",
    "ErrorArtifact",
    "ErrorCluster",
    "ErrorObservation",
    "ClassifiedError",
    # Config
    "ErrorIntelConfig",
    "default_config",
    "merge_config",
    "config_from_dict",
    "header_names_for_gate",
    # Phase 1 — candidate gate
    "is_error_candidate",
    "is_error_candidate_from_flow",
    "status_bucket",
    # Phase 2 — detectors
    "detect_errors",
    "ErrorDetectorOrchestrator",
    "ErrorDetectResult",
    "pick_primary_match",
    # Phase 3 — classify
    "classify_error",
    "classify_from_detect",
    "severity_from_score",
    "confidence_from_seed",
    # Phase 4 — normalize + fingerprint
    "normalize_error_text",
    "normalize_stack_line_numbers",
    "normalize_frames",
    "normalize_path_shape",
    "extract_message_norm",
    "extract_normalized_stack_from_match",
    "compute_fingerprint",
    "build_identity_tuple",
    "fingerprint_status_bucket",
    "identity_status_bucket",
    "short_hash",
    "stack_component_hash",
    "message_component_hash",
    # Phase 6 — queue / worker / observe
    "ErrorIntelQueue",
    "ErrorIntelWorker",
    "maybe_enqueue_error_scan",
    "process_error_scan_job",
    "process_error_scan_sync",
    "build_job_from_flow",
    "infer_attack_type",
    "observe_error",
    "attach_error_context",
]
