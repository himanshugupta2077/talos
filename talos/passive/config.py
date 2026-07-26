"""
Module: talos.passive.config

Purpose:
    Pure configuration model and defaults for Passive Source Intelligence.

    Phase 1 provided the dataclass and pure merge helpers.  Phase 2 stores
    the single-row `passive_scan_config` table via `talos.passive.db`
    (`ensure_config` / `get_config` / `update_config`).  Layered YAML
    integration is Phase 14.

Defaults (design contract):
    enabled                     True for scan path once Phase 4 wires worker;
                                auto-findings remain gated by threshold +
                                Phase 8 bridge (not by this flag alone).
    auto_finding_threshold      HIGH → CONFIRMED_PATTERN + HIGH create findings
    max_document_size           2_000_000 bytes
    max_decode_depth            3
    max_decode_bytes            256_000
    max_candidates_per_document 500
    scan_html/js/json/xml/text/css/sourcemaps  True; scan_wasm False
    store_raw_secret_in_evidence True (local pentest workstation)
    store_suppressed_detections False
    queue_maxsize               500
    max_scan_time_ms            0 (disabled soft budget; set >0 for Phase 14)

    Project SQLite `passive_scan_config` is the source of truth for runtime
    (talos.passive.db).  Optional global EffectiveConfig layering under
    configuration.passive.* is reserved; project-local wins when both exist.

Dependencies: dataclasses, copy; talos.passive.constants
Data flow: default_config() / merge_config() → PassiveScanConfig
           (db.load_config → same type)
Side effects: None (pure).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, fields
from typing import Any, Mapping, Optional

from talos.passive.constants import (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    DEFAULT_MAX_CANDIDATES_PER_DOCUMENT,
    DEFAULT_MAX_DECODE_BYTES,
    DEFAULT_MAX_DECODE_DEPTH,
    DEFAULT_MAX_DOCUMENT_SIZE,
    DEFAULT_MAX_SCAN_TIME_MS,
    DEFAULT_QUEUE_MAXSIZE,
    FINDING_ELIGIBLE_LEVELS,
)


# Threshold names accepted for auto_finding_threshold
AUTO_FINDING_THRESHOLDS: tuple[str, ...] = (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    "MEDIUM",  # reserved; not default
    "OFF",     # never auto-create findings
)


@dataclass
class PassiveScanConfig:
    """
    Purpose:
        Per-project passive scan settings.  Single logical row in
        passive_scan_config (Phase 2); this class is the runtime shape.

    Fields:
        enabled — master switch for enqueue/scan (not findings alone)
        auto_finding_threshold — minimum confidence_level for findings
        max_document_size / max_decode_* / max_candidates_per_document
        scan_* — per SourceKind scan toggles
        store_raw_secret_in_evidence — include raw in finding evidence JSON
        store_suppressed_detections — persist suppressed rows (default no)
        queue_maxsize — PassiveScanQueue bound
    """

    enabled: bool = True
    auto_finding_threshold: str = CONFIDENCE_HIGH
    max_document_size: int = DEFAULT_MAX_DOCUMENT_SIZE
    max_decode_depth: int = DEFAULT_MAX_DECODE_DEPTH
    max_decode_bytes: int = DEFAULT_MAX_DECODE_BYTES
    max_candidates_per_document: int = DEFAULT_MAX_CANDIDATES_PER_DOCUMENT
    scan_html: bool = True
    scan_javascript: bool = True
    scan_json: bool = True
    scan_xml: bool = True
    scan_text: bool = True
    scan_css: bool = True
    scan_sourcemaps: bool = True
    scan_wasm: bool = False
    store_raw_secret_in_evidence: bool = True
    store_suppressed_detections: bool = False
    queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE
    max_scan_time_ms: int = DEFAULT_MAX_SCAN_TIME_MS
    """Soft per-document scan budget in ms (0 = disabled). Partial results kept."""

    def is_finding_eligible(self, confidence_level: str) -> bool:
        """
        Purpose:
            Whether a detection at confidence_level should create a finding
            under the current auto_finding_threshold.
        Input:
            confidence_level — one of CONFIDENCE_LEVELS
        Output:
            True if auto-finding is enabled for that level.
        Side effects: None.
        """
        threshold = (self.auto_finding_threshold or CONFIDENCE_HIGH).upper()
        if threshold == "OFF":
            return False
        level = (confidence_level or "").upper()
        if threshold == CONFIDENCE_CONFIRMED_PATTERN:
            return level == CONFIDENCE_CONFIRMED_PATTERN
        if threshold == CONFIDENCE_HIGH:
            return level in FINDING_ELIGIBLE_LEVELS
        if threshold == "MEDIUM":
            return level in FINDING_ELIGIBLE_LEVELS or level == "MEDIUM"
        # Unknown threshold → safe default (HIGH band only)
        return level in FINDING_ELIGIBLE_LEVELS

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON/YAML friendly). Side effects: None."""
        return asdict(self)


def default_config() -> PassiveScanConfig:
    """
    Purpose:
        Return a fresh PassiveScanConfig with design-contract defaults.
    Output:
        New PassiveScanConfig instance (not shared mutable state).
    Side effects: None.
    """
    return PassiveScanConfig()


def merge_config(
    base: Optional[PassiveScanConfig] = None,
    overrides: Optional[Mapping[str, Any]] = None,
) -> PassiveScanConfig:
    """
    Purpose:
        Merge a sparse overrides mapping onto a base config (or defaults).
        Unknown keys are ignored.  Nested structures are not used in v1.

    Input:
        base      — starting config; None → default_config()
        overrides — field name → value (bool/int/str only)

    Output:
        New PassiveScanConfig with applied overrides.

    Side effects: None (does not mutate base).
    """
    cfg = deepcopy(base) if base is not None else default_config()
    if not overrides:
        return cfg

    known = {f.name for f in fields(PassiveScanConfig)}
    for key, value in overrides.items():
        if key not in known or value is None:
            continue
        if key == "auto_finding_threshold":
            text = str(value).upper()
            allowed = {t.upper() for t in AUTO_FINDING_THRESHOLDS}
            if text in allowed:
                setattr(cfg, key, text)
            continue
        if key in {
            "enabled",
            "scan_html",
            "scan_javascript",
            "scan_json",
            "scan_xml",
            "scan_text",
            "scan_css",
            "scan_sourcemaps",
            "scan_wasm",
            "store_raw_secret_in_evidence",
            "store_suppressed_detections",
        }:
            setattr(cfg, key, bool(value))
            continue
        if key in {
            "max_document_size",
            "max_decode_depth",
            "max_decode_bytes",
            "max_candidates_per_document",
            "queue_maxsize",
            "max_scan_time_ms",
        }:
            try:
                setattr(cfg, key, int(value))
            except (TypeError, ValueError):
                continue
            continue
        # Remaining str-like fields (none today) fall through

    return cfg


def config_from_dict(data: Optional[Mapping[str, Any]]) -> PassiveScanConfig:
    """
    Purpose:
        Build PassiveScanConfig from a full or partial dict (e.g. JSON row).
    Input:
        data — mapping of field names; None → defaults
    Output:
        PassiveScanConfig
    Side effects: None.
    """
    return merge_config(default_config(), data)
