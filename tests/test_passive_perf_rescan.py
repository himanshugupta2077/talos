"""
Phase 14–15: soft scan budget / large body perf smoke + rescan after version bump.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from talos.passive.config import PassiveScanConfig, default_config
from talos.passive.constants import SCANNER_VERSION, SourceKind
from talos.passive.db import (
    get_document,
    insert_detection,
    list_detections,
    mark_document_scanned,
    reset_document_for_rescan,
    upsert_document,
)
from talos.passive.detectors.orchestrator import DetectorOrchestrator
from talos.passive import db as passive_db
from talos.projects.db import init_project_db, seed_default_context


def test_large_minified_js_no_secrets_finishes_quickly():
    """
    ~1 MB minified JS without secrets should finish under a generous bound.
    """
    # Minified-ish noise: repeated identifiers + UUIDs (not secrets)
    chunk = (
        "function a(b,c){return b+c+'"
        + "x" * 200
        + "';}var u='"
        + "a" * 32
        + "';"
    )
    # Build ~1 MiB of minified-ish noise without secret-shaped tokens
    text = chunk * ((1_050_000 // len(chunk)) + 1)
    assert len(text) > 900_000

    orch = DetectorOrchestrator(config=default_config())
    t0 = time.monotonic()
    dets = orch.scan_text(text, document_id="big")
    elapsed = time.monotonic() - t0
    # Soft budget: 15s is generous for CI; real target is much lower
    assert elapsed < 15.0, f"scan took {elapsed:.2f}s"
    # No secret findings expected from pure noise
    secret_high = [
        d
        for d in dets
        if d.category == "secret"
        and d.confidence_level in ("HIGH", "CONFIRMED_PATTERN")
        and not d.suppressed
    ]
    assert secret_high == []


def test_soft_timeout_returns_partial(monkeypatch):
    cfg = PassiveScanConfig(max_scan_time_ms=1)  # force immediate soft timeout
    orch = DetectorOrchestrator(config=cfg)
    # Still returns a list (may be empty or partial) without raising
    text = 'const k = "AKIAJFAKESECRET00001";\n' + ("x" * 10000)
    dets = orch.scan_text(text, document_id="t")
    assert isinstance(dets, list)


def test_rescan_after_scanner_version_bump(tmp_path: Path):
    """
    Documents marked scanned at an old version become rescan-eligible;
    new rules/detectors pick up secrets that were missed.
    """
    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    seed_default_context(db_path)

    body = 'const k = "AKIAJFAKESECRET00001";'
    body_hash = __import__("hashlib").sha256(body.encode()).hexdigest()
    doc, _ = upsert_document(
        db_path,
        "proj",
        body_hash,
        SourceKind.JAVASCRIPT,
        len(body.encode()),
        first_flow_id="flow-1",
    )
    # Pretend scanned with older scanner
    mark_document_scanned(db_path, doc.id, "1.0.0")
    reloaded = get_document(db_path, doc.id)
    assert reloaded is not None
    assert reloaded.scanner_version == "1.0.0"
    assert reloaded.scanner_version != SCANNER_VERSION

    # Rescan path used by CLI
    reset_document_for_rescan(db_path, doc.id)
    orch = DetectorOrchestrator()
    dets = orch.scan_text(body, document_id=doc.id)
    stored = 0
    for d in dets:
        if insert_detection(db_path, d) is not None:
            stored += 1
    mark_document_scanned(db_path, doc.id, SCANNER_VERSION)

    final = get_document(db_path, doc.id)
    assert final is not None
    assert final.scanner_version == SCANNER_VERSION
    listed = list_detections(db_path, document_id=doc.id, limit=20)
    assert any(d.detector_id == "aws_access_key_id" for d in listed)
    assert stored >= 1
