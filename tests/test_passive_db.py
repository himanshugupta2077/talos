"""
Tests for Passive Source Intelligence schema v39 + talos.passive.db CRUD.

Covers:
  - Fresh init_project_db creates passive tables and seeds config
  - migrate_project_db upgrades from schema 38 → 39
  - Document upsert / occurrence / detection round-trips
  - Detection dedup unique index
  - Config get/update
  - link_detection_finding
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.passive.config import PassiveScanConfig, default_config
from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_HIGH,
    DETECTOR_FAMILY_PROVIDER,
    SCAN_STATUS_ERROR,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_SCANNED,
    SCANNER_VERSION,
    SourceKind,
)
from talos.passive.db import (
    ensure_config,
    get_config,
    get_detection,
    get_document,
    get_document_by_hash,
    insert_detection,
    insert_occurrence,
    link_detection_finding,
    list_detections,
    list_occurrences,
    mark_document_error,
    mark_document_scanned,
    update_config,
    upsert_document,
)
from talos.passive.models import Detection
from talos.passive.redaction import fingerprint_secret, redact_secret
from talos.projects.db import (
    SCHEMA_VERSION,
    get_schema_version,
    init_project_db,
    migrate_project_db,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


# ------------------------------------------------------------------ #
# Schema                                                               #
# ------------------------------------------------------------------ #

def test_schema_version_is_current():
    """Schema v39+ passive tables; v42 = cross-flow; v43 = error intel."""
    assert SCHEMA_VERSION >= 41


def test_fresh_db_has_passive_tables(db_path: Path):
    assert get_schema_version(db_path) == SCHEMA_VERSION
    with sqlite3.connect(str(db_path)) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    for required in (
        "source_documents",
        "source_occurrences",
        "passive_detections",
        "passive_scan_config",
    ):
        assert required in names


def test_fresh_db_seeds_passive_config(db_path: Path):
    cfg = get_config(db_path)
    defaults = default_config()
    assert cfg.enabled is True
    assert cfg.auto_finding_threshold == defaults.auto_finding_threshold
    assert cfg.scan_wasm is False
    assert cfg.queue_maxsize == defaults.queue_maxsize
    assert cfg.max_document_size == defaults.max_document_size


def test_migrate_from_38_creates_passive_tables(tmp_path: Path):
    """
    Build a minimal v38-shaped DB (schema_version only + empty shell), then
    migrate to current SCHEMA_VERSION and assert passive tables exist.
    """
    path = tmp_path / "old.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (38);
            """
        )
        conn.commit()

    assert get_schema_version(path) == 38
    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION

    with sqlite3.connect(str(path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        row = conn.execute(
            "SELECT enabled, auto_finding_threshold, scan_wasm "
            "FROM passive_scan_config WHERE id = 'default'"
        ).fetchone()

    assert "source_documents" in tables
    assert "passive_detections" in tables
    assert "passive_scan_config" in tables
    assert row is not None
    assert row[0] == 1
    assert row[1] == "HIGH"
    assert row[2] == 0


def test_init_project_db_migrates_old_version(tmp_path: Path):
    """init_project_db uses _migrate_schema when version < SCHEMA_VERSION."""
    path = tmp_path / "init_migrate.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (38);
            """
        )
        conn.commit()

    init_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    cfg = ensure_config(path)
    assert cfg.enabled is True


# ------------------------------------------------------------------ #
# Config                                                               #
# ------------------------------------------------------------------ #

def test_update_config_round_trip(db_path: Path):
    cfg = get_config(db_path)
    cfg.enabled = False
    cfg.auto_finding_threshold = "OFF"
    cfg.queue_maxsize = 42
    cfg.scan_javascript = False
    cfg.max_scan_time_ms = 5000
    update_config(db_path, cfg)

    loaded = get_config(db_path)
    assert loaded.enabled is False
    assert loaded.auto_finding_threshold == "OFF"
    assert loaded.queue_maxsize == 42
    assert loaded.scan_javascript is False
    assert loaded.max_scan_time_ms == 5000
    # Unchanged fields keep defaults
    assert loaded.scan_html is True
    assert loaded.scan_wasm is False


def test_update_config_accepts_passive_scan_config_instance(db_path: Path):
    custom = PassiveScanConfig(enabled=False, max_decode_depth=1)
    update_config(db_path, custom)
    assert get_config(db_path).max_decode_depth == 1
    assert get_config(db_path).enabled is False


# ------------------------------------------------------------------ #
# Documents + occurrences                                              #
# ------------------------------------------------------------------ #

def test_upsert_document_creates_and_dedups(db_path: Path):
    doc1, created1 = upsert_document(
        db_path,
        project_id="proj-1",
        body_hash="abc" * 16,  # 48 hex-like chars; shape only
        source_kind=SourceKind.JAVASCRIPT,
        body_size=1024,
        truncated=False,
        first_flow_id="flow-1",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    assert created1 is True
    assert doc1.scan_status == SCAN_STATUS_PENDING
    assert doc1.body_size == 1024
    assert doc1.first_flow_id == "flow-1"
    assert doc1.source_kind == SourceKind.JAVASCRIPT

    doc2, created2 = upsert_document(
        db_path,
        project_id="proj-1",
        body_hash="abc" * 16,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=1024,
        first_flow_id="flow-2",
        observed_at="2026-01-02T00:00:00+00:00",
    )
    assert created2 is False
    assert doc2.id == doc1.id
    assert doc2.last_seen == "2026-01-02T00:00:00+00:00"
    # Scan state preserved
    assert doc2.scan_status == SCAN_STATUS_PENDING
    assert doc2.first_flow_id == "flow-1"

    # Different project → new document
    doc3, created3 = upsert_document(
        db_path,
        project_id="proj-2",
        body_hash="abc" * 16,
        source_kind=SourceKind.JSON,
        body_size=10,
    )
    assert created3 is True
    assert doc3.id != doc1.id


def test_get_document_by_hash_and_id(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="deadbeef" * 8,
        source_kind="html",
        body_size=50,
    )
    by_hash = get_document_by_hash(db_path, "p", "deadbeef" * 8)
    by_id = get_document(db_path, doc.id)
    assert by_hash is not None and by_hash.id == doc.id
    assert by_id is not None and by_id.body_hash == doc.body_hash
    assert get_document_by_hash(db_path, "p", "missing") is None
    assert get_document(db_path, "missing") is None


def test_mark_document_scanned_and_error(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="f" * 64,
        source_kind=SourceKind.TEXT,
        body_size=1,
    )
    mark_document_scanned(db_path, doc.id, SCANNER_VERSION)
    scanned = get_document(db_path, doc.id)
    assert scanned is not None
    assert scanned.scan_status == SCAN_STATUS_SCANNED
    assert scanned.scanner_version == SCANNER_VERSION
    assert scanned.last_scanned_at is not None
    assert scanned.error_message is None

    mark_document_error(db_path, doc.id, "boom")
    errored = get_document(db_path, doc.id)
    assert errored is not None
    assert errored.scan_status == SCAN_STATUS_ERROR
    assert errored.error_message == "boom"


def test_insert_occurrence_and_list(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="a" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=100,
    )
    occ1 = insert_occurrence(
        db_path,
        document_id=doc.id,
        flow_id="flow-a",
        url="https://app.example/static/app.js",
        host="app.example",
        path="/static/app.js",
        content_type="application/javascript",
        observed_at="2026-01-01T00:00:00+00:00",
        role_id="role-1",
        module_id="mod-1",
        endpoint_id="ep-1",
        logical_source_name="app.<BUILD_HASH>.js",
    )
    occ2 = insert_occurrence(
        db_path,
        document_id=doc.id,
        flow_id="flow-b",
        url="https://cdn.example/app.js",
        host="cdn.example",
        path="/app.js",
        content_type="application/javascript",
        observed_at="2026-01-03T00:00:00+00:00",
    )
    assert occ1.document_id == doc.id
    assert occ1.logical_source_name == "app.<BUILD_HASH>.js"

    listed = list_occurrences(db_path, doc.id)
    assert len(listed) == 2
    # Newest first
    assert listed[0].id == occ2.id
    assert listed[1].id == occ1.id


# ------------------------------------------------------------------ #
# Detections                                                           #
# ------------------------------------------------------------------ #

def _make_detection(
    document_id: str,
    *,
    detector_id: str = "aws_access_key_id",
    family: str = DETECTOR_FAMILY_PROVIDER,
    raw: str = "AKIAIOSFODNN7EXAMPLE",
    match_start: int = 10,
    confidence_level: str = CONFIDENCE_HIGH,
    confidence_score: int = 90,
    occurrence_id: str | None = None,
) -> Detection:
    fp = fingerprint_secret(family, raw)
    return Detection(
        id="",
        document_id=document_id,
        occurrence_id=occurrence_id,
        detector_id=detector_id,
        detector_family=family,
        category=CATEGORY_SECRET,
        secret_type="aws_access_key",
        matched_key="AWS_ACCESS_KEY_ID",
        redacted_value=redact_secret(raw),
        value_fingerprint=fp,
        confidence_score=confidence_score,
        confidence_level=confidence_level,
        match_start=match_start,
        match_end=match_start + len(raw),
        context_before="const key = '",
        context_after="';",
        encoding_chain=[],
        suppressed=False,
    )


def test_insert_detection_round_trip(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="b" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=200,
    )
    occ = insert_occurrence(
        db_path,
        document_id=doc.id,
        flow_id="f1",
        url="https://x/a.js",
        host="x",
        path="/a.js",
        content_type="application/javascript",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    det = _make_detection(doc.id, occurrence_id=occ.id)
    stored = insert_detection(db_path, det)
    assert stored is not None
    assert stored.id
    assert stored.redacted_value == redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert stored.raw_value is None  # never loaded from DB
    assert stored.occurrence_id == occ.id
    assert stored.encoding_chain == []

    by_id = get_detection(db_path, stored.id)
    assert by_id is not None
    assert by_id.value_fingerprint == stored.value_fingerprint


def test_insert_detection_dedup(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="c" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=50,
    )
    det = _make_detection(doc.id, match_start=5)
    first = insert_detection(db_path, det)
    second = insert_detection(db_path, det)
    assert first is not None and second is not None
    assert first.id == second.id

    # Different offset → new row
    other = _make_detection(doc.id, match_start=99)
    third = insert_detection(db_path, other)
    assert third is not None
    assert third.id != first.id

    listed = list_detections(db_path, document_id=doc.id)
    assert len(listed) == 2


def test_list_detections_filters(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="proj-filter",
        body_hash="d" * 64,
        source_kind=SourceKind.JSON,
        body_size=20,
    )
    high = insert_detection(db_path, _make_detection(doc.id, match_start=1))
    med = insert_detection(
        db_path,
        _make_detection(
            doc.id,
            detector_id="generic_password",
            family="generic",
            raw="SuperSecretValue99",
            match_start=2,
            confidence_level="MEDIUM",
            confidence_score=55,
        ),
    )
    assert high is not None and med is not None

    by_level = list_detections(
        db_path, document_id=doc.id, confidence_level=CONFIDENCE_HIGH
    )
    assert len(by_level) == 1
    assert by_level[0].id == high.id

    by_project = list_detections(db_path, project_id="proj-filter")
    assert len(by_project) == 2

    no_finding = list_detections(db_path, document_id=doc.id, has_finding=False)
    assert len(no_finding) == 2


def test_link_detection_finding(db_path: Path):
    doc, _ = upsert_document(
        db_path,
        project_id="p",
        body_hash="e" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=10,
    )
    det = insert_detection(db_path, _make_detection(doc.id))
    assert det is not None
    assert det.finding_id is None

    ok = link_detection_finding(db_path, det.id, "finding-uuid-1")
    assert ok is True
    linked = get_detection(db_path, det.id)
    assert linked is not None
    assert linked.finding_id == "finding-uuid-1"

    with_finding = list_detections(db_path, document_id=doc.id, has_finding=True)
    assert len(with_finding) == 1

    assert link_detection_finding(db_path, "no-such-id", "f") is False
