"""
Package: talos.passive.detectors

Purpose:
    Detector pipeline for Passive Source Intelligence.

    Stages (orchestrator):
        1. Specific provider patterns (YAML) + PEM + JWT + connection strings
        2. Contextual generic assignment secrets
        3. Entropy candidates (keyword / assignment gated)
        4–5. Decoder → rescan stages 1–2 only
        6. Infrastructure / disclosure observations (Phase 12)
        7–8. Scoring + suppression (applied before persist)

    Detectors emit RawMatch; orchestrator scores, suppresses, and builds
    Detection rows.  No findings creation here (bridge owns that).

Dependencies: sibling modules + talos.passive.models
Data flow: SourceDocument.text → orchestrator.scan_text → list[Detection]
Side effects: Rule load on first scan (YAML read); no DB/HTTP.
"""

from talos.passive.detectors.orchestrator import (
    DetectorOrchestrator,
    scan_document,
    scan_text,
)

__all__ = [
    "DetectorOrchestrator",
    "scan_document",
    "scan_text",
]
