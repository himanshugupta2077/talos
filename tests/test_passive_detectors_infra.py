"""
Phase 12 tests: infrastructure / disclosure detectors (observation-only).
"""

from __future__ import annotations

from pathlib import Path

from talos.passive.constants import (
    CATEGORY_INFRASTRUCTURE_DISCLOSURE,
    CATEGORY_SENSITIVE_INFO,
    CONFIDENCE_HIGH,
    CONFIDENCE_OBSERVATION_ONLY,
)
from talos.passive.detectors.infrastructure import InfrastructureDetector
from talos.passive.detectors.orchestrator import DetectorOrchestrator
from talos.passive.finding_bridge import maybe_create_findings_for_detections
from talos.passive.config import default_config

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


def test_internal_ip_and_hostname():
    det = InfrastructureDetector()
    text = 'const api = "https://api.internal:8443"; const ip = "10.1.2.3";'
    hits = det.detect(text)
    kinds = {h.detector_id for h in hits}
    assert "internal_ip" in kinds
    assert "internal_hostname" in kinds
    for h in hits:
        assert h.detector_family == "infra"
        assert h.category in (
            CATEGORY_INFRASTRUCTURE_DISCLOSURE,
            CATEGORY_SENSITIVE_INFO,
        )
        assert h.metadata.get("auto_finding") is False


def test_sensitive_routes_aggregated_not_per_path():
    # 100 quoted API paths → one aggregate detection, not 100 rows
    paths = [f'"/api/v1/item{i}"' for i in range(100)]
    text = "const routes = [" + ", ".join(paths) + "];"
    det = InfrastructureDetector()
    hits = det.detect(text)
    route_hits = [h for h in hits if h.detector_id == "sensitive_routes_aggregate"]
    assert len(route_hits) == 1
    meta = route_hits[0].metadata or {}
    assert meta.get("route_count", 0) <= 40  # cap
    assert meta.get("route_count", 0) >= 20
    assert "routes" in meta


def test_orchestrator_infra_no_auto_finding_levels():
    text = (FIXTURES / "infra_routes.js").read_text(encoding="utf-8")
    # Add a real internal IP so we get hits even if route regex is picky
    text = text + '\nconst ip = "192.168.1.10";\nconst h = "db.corp";\n'
    orch = DetectorOrchestrator()
    dets = orch.scan_text(text, document_id="doc-1")
    infra = [d for d in dets if d.detector_family == "infra"]
    assert infra, "expected infrastructure detections"
    for d in infra:
        assert d.confidence_level not in ("CONFIRMED_PATTERN", CONFIDENCE_HIGH)
        assert d.category in (
            CATEGORY_INFRASTRUCTURE_DISCLOSURE,
            CATEGORY_SENSITIVE_INFO,
        )


def test_infra_never_creates_findings_via_bridge(tmp_path, monkeypatch):
    """Category filter on bridge must skip infrastructure detections."""
    from talos.projects.db import init_project_db, seed_default_context
    from talos.passive import db as passive_db
    from talos.passive.constants import SourceKind
    from talos.passive.models import Detection
    from talos.passive.redaction import fingerprint_secret, redact_secret
    import uuid

    db_path = tmp_path / "t.db"
    init_project_db(db_path)
    seed_default_context(db_path)
    doc, _ = passive_db.upsert_document(
        db_path,
        "p1",
        "a" * 64,
        SourceKind.JAVASCRIPT,
        10,
    )
    det = Detection(
        id=str(uuid.uuid4()),
        document_id=doc.id,
        occurrence_id=None,
        detector_id="internal_ip",
        detector_family="infra",
        category=CATEGORY_INFRASTRUCTURE_DISCLOSURE,
        secret_type="internal_ip",
        matched_key=None,
        redacted_value="10.0****.1",
        value_fingerprint=fingerprint_secret("infra", "10.0.0.1"),
        confidence_score=90,  # even if mis-scored HIGH-band
        confidence_level="CONFIRMED_PATTERN",
        suppressed=False,
        raw_value="10.0.0.1",
    )
    row = passive_db.insert_detection(db_path, det)
    assert row is not None
    cfg = default_config()
    n = maybe_create_findings_for_detections(
        db_path, "p1", [row], config=cfg
    )
    assert n == 0
    reloaded = passive_db.get_detection(db_path, row.id)
    assert reloaded is not None
    assert reloaded.finding_id is None


def test_fixture_route_cap_not_500_detections():
    text = "\n".join(f'fetch("/api/v1/path{i}")' for i in range(500))
    orch = DetectorOrchestrator()
    dets = orch.scan_text(text, document_id="doc-routes")
    route_dets = [
        d for d in dets if d.detector_id == "sensitive_routes_aggregate"
    ]
    assert len(route_dets) <= 1
    # Total detections for this noise must stay small
    assert len(dets) < 50
