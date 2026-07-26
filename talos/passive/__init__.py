"""
Package: talos.passive

Purpose:
    Passive Source Intelligence / Secret Exposure Engine.

    Scans captured client-delivered response bodies (HTML, JavaScript,
    JSON, XML, text, CSS, source maps) for secrets and sensitive exposure
    using a deterministic detector pipeline.  High-confidence detections
    become Findings (Phase 8); lower-confidence observations stay in
    passive tables.

    This is **not** "regex every JS file and create a finding for every
    match."  Core model:

        Source container → match → detection (scored/suppressed) → finding

Architectural constraints (do not violate):
    - No heavy scan in TalosAddon.response() (proxy capture-only)
    - No expensive scan inside FlowWorker._persist_db()
    - No use of ReplayScheduler (scheduler = HTTP job execution)
    - No archive JSONL scanning
    - No silent active secret validation (outbound checks)
    - Deterministic first (no AI in v1)
    - Findings subsystem remains owner of findings lifecycle
    - PRIMARY/LINKED cluster by secret fingerprint, not by source file

Phase status:
    Phase 0 — design freeze (docs/architecture.md decision log)
    Phase 1 — package skeleton: constants, models, config, redaction
    Phase 2 — schema v39 + talos.passive.db CRUD
    Phase 3 — candidate gate + classifier + normalizer
    Phase 4 — PassiveScanQueue + SourceScanWorker + FlowWorker enqueue
    Phase 5 — detector framework + YAML rules + Stage 1 specific
    Phase 6 — contextual generic + suppress + scoring
    Phase 7 — decoder pipeline + entropy + rescan
    Phase 8 — finding bridge + PRIMARY/LINKED clustering
    Phase 9 — CLI (talos passive …)
    Phase 10 — source map sourcesContent extractor
    Phase 11 — HTML inline <script> / bootstrap JSON extractors
    Phase 12 — infrastructure / disclosure detectors (observation-first)
    Phase 13 — Control Panel UI (out of scope for core CLI package)
    Phase 14 — soft scan budget + performance hardening
    Phase 15 — rescan productization (version bump eligibility)
    Phase 16 — documentation + Talos Helper sync

Public exports:
    SCANNER_VERSION, SourceKind, confidence/category constants
    PassiveScanJob, SourceDocument, Detection, …
    PassiveScanConfig, default_config, merge_config
    fingerprint_secret, redact_secret, canonicalize_secret
    is_source_candidate, classify_source, normalize_body
    PassiveScanQueue, SourceScanWorker, maybe_enqueue_passive_scan
    DetectorOrchestrator, scan_text, scan_document
    create_passive_secret_finding, maybe_create_findings_for_detections
    extract_sourcemap_virtual_docs, extract_html_virtual_docs
    load_rule_packs, get_rule_index
    db helpers (ensure_config, upsert_document, insert_detection, …)

Dependencies: stdlib + PyYAML + project SQLite
Data flow: FlowWorker gate → PassiveScanQueue → SourceScanWorker
           → document/occurrence registry → extractors → detectors
           → detections → findings bridge
Side effects: Queue/worker write SQLite + findings; capture path only enqueues.
"""

from talos.passive.candidate import (
    is_source_candidate,
    is_source_candidate_from_flow,
)
from talos.passive.classifier import (
    classify_source,
    is_scannable_kind,
)
from talos.passive.constants import (
    ATTACK_TYPE_PASSIVE_DISCLOSURE,
    ATTACK_TYPE_PASSIVE_SECRET,
    CATEGORY_INFRASTRUCTURE_DISCLOSURE,
    CATEGORY_SECRET,
    CATEGORY_SENSITIVE_INFO,
    CLUSTER_KEY_PREFIX_PASSIVE_SECRET,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_OBSERVATION_ONLY,
    DETECTOR_FAMILY_PROVIDER,
    FINDING_ELIGIBLE_LEVELS,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_SCANNED,
    SCANNER_VERSION,
    SourceKind,
    VERDICT_DISCLOSED,
    VERDICT_EXPOSED,
)
from talos.passive.config import (
    PassiveScanConfig,
    config_from_dict,
    default_config,
    merge_config,
)
from talos.passive.detectors.orchestrator import (
    DetectorOrchestrator,
    scan_document,
    scan_text,
)
from talos.passive.models import (
    DecodeResult,
    Detection,
    PassiveScanJob,
    RawMatch,
    SourceDocument,
    SourceOccurrence,
)
from talos.passive.normalize import (
    NormalizeResult,
    normalize_body,
)
from talos.passive.queue import PassiveScanQueue
from talos.passive.redaction import (
    canonicalize_secret,
    fingerprint_secret,
    looks_like_placeholder,
    redact_secret,
)
from talos.passive.extractors.html import extract_html_virtual_docs
from talos.passive.extractors.sourcemap import extract_sourcemap_virtual_docs
from talos.passive.finding_bridge import (
    build_passive_secret_cluster_key,
    create_passive_secret_finding,
    maybe_create_findings_for_detections,
)
from talos.passive.rules_loader import get_rule_index, load_rule_packs
from talos.passive.worker import SourceScanWorker, maybe_enqueue_passive_scan
from . import db  # CRUD submodule (schema v39+)

__all__ = [
    # Identity
    "SCANNER_VERSION",
    "SourceKind",
    # Confidence / categories
    "CONFIDENCE_CONFIRMED_PATTERN",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_OBSERVATION_ONLY",
    "CONFIDENCE_LEVELS",
    "FINDING_ELIGIBLE_LEVELS",
    "CATEGORY_SECRET",
    "CATEGORY_INFRASTRUCTURE_DISCLOSURE",
    "CATEGORY_SENSITIVE_INFO",
    "DETECTOR_FAMILY_PROVIDER",
    "SCAN_STATUS_PENDING",
    "SCAN_STATUS_SCANNED",
    "ATTACK_TYPE_PASSIVE_SECRET",
    "ATTACK_TYPE_PASSIVE_DISCLOSURE",
    "VERDICT_EXPOSED",
    "VERDICT_DISCLOSED",
    "CLUSTER_KEY_PREFIX_PASSIVE_SECRET",
    # Models
    "PassiveScanJob",
    "SourceDocument",
    "SourceOccurrence",
    "RawMatch",
    "Detection",
    "DecodeResult",
    # Config
    "PassiveScanConfig",
    "default_config",
    "merge_config",
    "config_from_dict",
    # Redaction
    "canonicalize_secret",
    "fingerprint_secret",
    "redact_secret",
    "looks_like_placeholder",
    # Phase 3 — candidate / classify / normalize
    "is_source_candidate",
    "is_source_candidate_from_flow",
    "classify_source",
    "is_scannable_kind",
    "normalize_body",
    "NormalizeResult",
    # Phase 4 — queue + worker
    "PassiveScanQueue",
    "SourceScanWorker",
    "maybe_enqueue_passive_scan",
    # Phases 5–7 — detectors / rules
    "DetectorOrchestrator",
    "scan_text",
    "scan_document",
    "load_rule_packs",
    "get_rule_index",
    # Phase 8 — findings bridge
    "create_passive_secret_finding",
    "maybe_create_findings_for_detections",
    "build_passive_secret_cluster_key",
    # Phases 10–11 — extractors
    "extract_sourcemap_virtual_docs",
    "extract_html_virtual_docs",
    # DB submodule
    "db",
]
