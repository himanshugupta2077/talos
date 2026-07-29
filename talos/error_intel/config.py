"""
Module: talos.error_intel.config

Purpose:
    Pure configuration model and defaults for Error Intelligence.

    Phase 0 defines the dataclass and merge helpers.  Phase 5 stores a
    single-row `error_intel_config` table via talos.error_intel.db.
    Layered YAML integration may follow later; project-local SQLite wins.

Defaults (design contract):
    enabled                      True for scan path once Phase 6 wires
                                 queue/worker (no auto Findings in v1).
    store_generic_http_errors    False — avoid flooding with 400/404 chrome
    max_body_scan                512_000 bytes
    gate_sniff_bytes             16_384 — cheap marker sample at gate
    queue_maxsize                500
    evidence_snippet_max         4_096
    error_header_names           DEFAULT_ERROR_HEADER_NAMES

Dependencies: dataclasses, copy; talos.error_intel.constants
Data flow: default_config() / merge_config() → ErrorIntelConfig
Side effects: None (pure).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Mapping, Optional

from talos.error_intel.constants import (
    DEFAULT_ERROR_HEADER_NAMES,
    DEFAULT_EVIDENCE_SNIPPET_MAX,
    DEFAULT_GATE_SNIFF_BYTES,
    DEFAULT_MAX_BODY_SCAN,
    DEFAULT_QUEUE_MAXSIZE,
)


@dataclass
class ErrorIntelConfig:
    """
    Purpose:
        Per-project Error Intelligence settings.  Single logical row in
        error_intel_config (Phase 5); this class is the runtime shape.

    Fields:
        enabled — master switch for enqueue/scan (not findings; none in v1)
        store_generic_http_errors — persist Stage G / status-only clusters
        max_body_scan — worker scan budget in bytes
        gate_sniff_bytes — candidate gate body sample size
        queue_maxsize — ErrorIntelQueue bound (Phase 6)
        evidence_snippet_max — cap for cluster evidence_snippet
        error_header_names — response headers that pass the candidate gate
    """

    enabled: bool = True
    store_generic_http_errors: bool = False
    max_body_scan: int = DEFAULT_MAX_BODY_SCAN
    gate_sniff_bytes: int = DEFAULT_GATE_SNIFF_BYTES
    queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE
    evidence_snippet_max: int = DEFAULT_EVIDENCE_SNIPPET_MAX
    error_header_names: frozenset[str] = field(
        default_factory=lambda: frozenset(DEFAULT_ERROR_HEADER_NAMES)
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON/YAML friendly). Side effects: None."""
        d = asdict(self)
        # frozenset → sorted list for stable JSON
        d["error_header_names"] = sorted(self.error_header_names)
        return d


def default_config() -> ErrorIntelConfig:
    """
    Purpose:
        Return a fresh ErrorIntelConfig with design-contract defaults.
    Output:
        New ErrorIntelConfig instance (not shared mutable state).
    Side effects: None.
    """
    return ErrorIntelConfig()


def merge_config(
    base: Optional[ErrorIntelConfig] = None,
    overrides: Optional[Mapping[str, Any]] = None,
) -> ErrorIntelConfig:
    """
    Purpose:
        Merge a sparse overrides mapping onto a base config (or defaults).
        Unknown keys are ignored.

    Input:
        base      — starting config; None → default_config()
        overrides — field name → value

    Output:
        New ErrorIntelConfig with applied overrides.

    Side effects: None (does not mutate base).
    """
    cfg = deepcopy(base) if base is not None else default_config()
    if not overrides:
        return cfg

    known = {f.name for f in fields(ErrorIntelConfig)}
    for key, value in overrides.items():
        if key not in known or value is None:
            continue
        if key in {"enabled", "store_generic_http_errors"}:
            setattr(cfg, key, bool(value))
            continue
        if key in {
            "max_body_scan",
            "gate_sniff_bytes",
            "queue_maxsize",
            "evidence_snippet_max",
        }:
            try:
                setattr(cfg, key, int(value))
            except (TypeError, ValueError):
                continue
            continue
        if key == "error_header_names":
            names = _coerce_header_names(value)
            if names is not None:
                cfg.error_header_names = names
            continue

    return cfg


def config_from_dict(data: Optional[Mapping[str, Any]]) -> ErrorIntelConfig:
    """
    Purpose:
        Build ErrorIntelConfig from a full or partial dict (e.g. JSON row).
    Input:
        data — mapping of field names; None → defaults
    Output:
        ErrorIntelConfig
    Side effects: None.
    """
    return merge_config(default_config(), data)


def _coerce_header_names(value: Any) -> Optional[frozenset[str]]:
    """Normalize a list/set/str of header names to a lowercased frozenset."""
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(",", " ").split() if p.strip()]
        return frozenset(p.lower() for p in parts) if parts else None
    if isinstance(value, (list, tuple, set, frozenset)):
        names: list[str] = []
        for item in value:  # type: ignore[assignment]
            if item is None:
                continue
            text = str(item).strip().lower()
            if text:
                names.append(text)
        return frozenset(names) if names else None
    return None


def header_names_for_gate(
    config: Optional[ErrorIntelConfig] = None,
) -> frozenset[str]:
    """
    Purpose:
        Resolve the header allow-list used by is_error_candidate.
    Input:
        config — optional; None → defaults
    Output:
        Lowercased header name frozenset.
    Side effects: None.
    """
    if config is None:
        return DEFAULT_ERROR_HEADER_NAMES
    return config.error_header_names or DEFAULT_ERROR_HEADER_NAMES
