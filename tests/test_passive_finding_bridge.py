"""
Phase 8 tests: finding bridge + one project-wide secret cluster.

Covers:
  - Eligible HIGH/CONFIRMED detection → finding with attack_type=passive_secret
  - Same secret in two documents → PRIMARY then LINKED
  - Different secrets → same cluster (PRIMARY + LINKED)
  - Below threshold / suppressed → no finding
  - Evidence types attached
  - Worker end-to-end auto-finding
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

import talos.findings.db as findings_db
from talos.findings.model import (
    ATTACK_DISPLAY,
    EVIDENCE_TYPE_PASSIVE_DETECTION,
    EVIDENCE_TYPE_SOURCE_DOCUMENT,
    RELATION_TYPE_LINKED,
    RELATION_TYPE_PRIMARY,
)
from talos.passive.constants import (
    ATTACK_TYPE_PASSIVE_SECRET,
    CATEGORY_SECRET,
    CONFIDENCE_MEDIUM,
    DETECTOR_FAMILY_PROVIDER,
    VERDICT_EXPOSED,
)
from talos.passive.db import (
    get_config,
    insert_detection,
    insert_occurrence,
    update_config,
    upsert_document,
)
from talos.passive.finding_bridge import (
    build_passive_secret_cluster_key,
    build_secret_exposure,
    create_passive_secret_finding,
    finding_title_for_detection,
)
from talos.passive.models import Detection
from talos.passive.queue import PassiveScanQueue
from talos.passive.redaction import fingerprint_secret, redact_secret
from talos.passive.worker import SourceScanWorker
from talos.projects.db import init_project_db, seed_default_context
from talos.projects.model import Project, ProjectStatus, ScopeConstraints
from talos.passive.constants import SourceKind
from talos.passive.models import PassiveScanJob


@pytest.fixture
def project(tmp_path: Path) -> Project:
    data_dir = tmp_path / "proj"
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    init_project_db(db_path)
    seed_default_context(db_path)
    return Project(
        id="test-proj",
        name="Test",
        description="",
        created_at=datetime.now(timezone.utc).isoformat(),
        status=ProjectStatus.ACTIVE,
        scope=["example.com"],
        data_dir=str(data_dir),
        constraints=ScopeConstraints(),
    )


def _make_detection(
    document_id: str,
    *,
    secret: str = "AKIAJFAKESECRET00001",
    family: str = DETECTOR_FAMILY_PROVIDER,
    detector_id: str = "aws_access_key_id",
    secret_type: str = "aws_access_key",
    confidence_level: str = "CONFIRMED_PATTERN",
    confidence_score: int = 95,
    suppressed: bool = False,
    occurrence_id: str | None = None,
    match_start: int = 10,
) -> Detection:
    fp = fingerprint_secret(family, secret)
    return Detection(
        id=str(uuid.uuid4()),
        document_id=document_id,
        occurrence_id=occurrence_id,
        detector_id=detector_id,
        detector_family=family,
        category=CATEGORY_SECRET,
        secret_type=secret_type,
        matched_key="accessKeyId",
        redacted_value=redact_secret(secret),
        value_fingerprint=fp,
        confidence_score=confidence_score,
        confidence_level=confidence_level,
        match_start=match_start,
        match_end=match_start + len(secret),
        context_before='const accessKeyId = "',
        context_after='";',
        suppressed=suppressed,
        raw_value=secret,
    )


def _seed_doc_with_occurrence(
    project: Project,
    body: bytes,
    *,
    path: str = "/static/a.js",
) -> tuple[str, str]:
    """Return (document_id, occurrence_id)."""
    body_hash = hashlib.sha256(body).hexdigest()
    doc, _ = upsert_document(
        project.db_path,
        project.id,
        body_hash,
        SourceKind.JAVASCRIPT,
        len(body),
        first_flow_id="flow-seed",
    )
    occ = insert_occurrence(
        project.db_path,
        document_id=doc.id,
        flow_id="flow-seed",
        url=f"https://example.com{path}",
        host="https://example.com",
        path=path,
        content_type="application/javascript",
        observed_at=datetime.now(timezone.utc).isoformat(),
    )
    return doc.id, occ.id


def test_cluster_key_format():
    assert build_passive_secret_cluster_key("abc123") == "PASSIVE_SECRET"
    assert build_passive_secret_cluster_key() == "PASSIVE_SECRET"


def test_attack_display_passive_secret():
    assert ATTACK_DISPLAY.get("passive_secret") == "Client-Side Secret Exposure"


def test_create_finding_primary(project: Project):
    doc_id, occ_id = _seed_doc_with_occurrence(project, b"const k=1;")
    det = _make_detection(doc_id, occurrence_id=occ_id)
    stored = insert_detection(project.db_path, det)
    assert stored is not None

    fid = create_passive_secret_finding(
        project.db_path,
        project.id,
        stored.id,
        raw_value=det.raw_value,
    )
    assert fid is not None
    finding = findings_db.get_finding(project.db_path, fid)
    assert finding is not None
    assert finding["attack_type"] == ATTACK_TYPE_PASSIVE_SECRET
    assert finding["verdict"] == VERDICT_EXPOSED
    assert finding["relation_type"] == RELATION_TYPE_PRIMARY
    assert finding["cluster_key"] == "PASSIVE_SECRET"
    assert finding["title"] == "Client-Side Secret Exposure"

    from talos.passive.db import get_detection

    linked = get_detection(project.db_path, stored.id)
    assert linked is not None
    assert linked.finding_id == fid

    evidence = findings_db.list_evidence(project.db_path, fid)
    types = {e["evidence_type"] for e in evidence}
    assert EVIDENCE_TYPE_PASSIVE_DETECTION in types
    assert EVIDENCE_TYPE_SOURCE_DOCUMENT in types
    det_ev = next(
        e for e in evidence if e["evidence_type"] == EVIDENCE_TYPE_PASSIVE_DETECTION
    )
    data = det_ev.get("data") or {}
    if isinstance(data, str):
        import json as _json
        data = _json.loads(data)
    assert data.get("context_before")
    assert data.get("redacted_value")
    exposure = build_secret_exposure(
        project.db_path, fid, evidence=evidence
    )
    assert exposure is not None
    assert exposure["count"] >= 1
    assert exposure["hits"][0]["redacted_value"]
    assert exposure["hits"][0]["raw_value"] == det.raw_value
    assert exposure["hits"][0]["secret_type"] == "aws_access_key"


def test_same_secret_two_docs_primary_then_linked(project: Project):
    secret = "AKIAJFAKESECRET00001"
    doc_a, occ_a = _seed_doc_with_occurrence(
        project, b"// file a\n", path="/a.js"
    )
    doc_b, occ_b = _seed_doc_with_occurrence(
        project, b"// file b different body\n", path="/b.js"
    )

    det_a = _make_detection(doc_a, secret=secret, occurrence_id=occ_a, match_start=1)
    det_b = _make_detection(doc_b, secret=secret, occurrence_id=occ_b, match_start=1)
    sa = insert_detection(project.db_path, det_a)
    sb = insert_detection(project.db_path, det_b)
    assert sa and sb
    assert sa.value_fingerprint == sb.value_fingerprint

    fid_a = create_passive_secret_finding(
        project.db_path, project.id, sa.id, raw_value=secret
    )
    fid_b = create_passive_secret_finding(
        project.db_path, project.id, sb.id, raw_value=secret
    )
    assert fid_a and fid_b
    assert fid_a != fid_b

    fa = findings_db.get_finding(project.db_path, fid_a)
    fb = findings_db.get_finding(project.db_path, fid_b)
    assert fa["relation_type"] == RELATION_TYPE_PRIMARY
    assert fb["relation_type"] == RELATION_TYPE_LINKED
    assert fb["parent_finding_id"] == fid_a
    assert fa["cluster_key"] == fb["cluster_key"] == "PASSIVE_SECRET"

    exposure = build_secret_exposure(project.db_path, fid_a)
    assert exposure is not None
    assert exposure["count"] == 2
    assert all(h["redacted_value"] for h in exposure["hits"])


def test_all_secrets_one_cluster(project: Project):
    doc_id, occ_id = _seed_doc_with_occurrence(project, b"bundle")
    d1 = _make_detection(
        doc_id,
        secret="AKIAJFAKESECRET00001",
        occurrence_id=occ_id,
        match_start=1,
    )
    d2 = _make_detection(
        doc_id,
        secret="AKIAJFAKESECRET00002",
        occurrence_id=occ_id,
        match_start=50,
    )
    s1 = insert_detection(project.db_path, d1)
    s2 = insert_detection(project.db_path, d2)
    f1 = create_passive_secret_finding(
        project.db_path, project.id, s1.id, raw_value=d1.raw_value
    )
    f2 = create_passive_secret_finding(
        project.db_path, project.id, s2.id, raw_value=d2.raw_value
    )
    assert f1 and f2
    assert f1 != f2
    fa = findings_db.get_finding(project.db_path, f1)
    fb = findings_db.get_finding(project.db_path, f2)
    assert fa["relation_type"] == RELATION_TYPE_PRIMARY
    assert fa["title"] == "Client-Side Secret Exposure"
    assert fb["relation_type"] == RELATION_TYPE_LINKED
    assert fb["parent_finding_id"] == f1
    assert "AWS" in (fb["title"] or "") or "Secret" in (fb["title"] or "")

    primaries = findings_db.list_findings(
        project.db_path, project.id, relation_type=RELATION_TYPE_PRIMARY
    )
    passive_primaries = [
        f for f in primaries if f.get("attack_type") == ATTACK_TYPE_PASSIVE_SECRET
    ]
    assert len(passive_primaries) == 1

    exposure = build_secret_exposure(project.db_path, f1)
    assert exposure is not None
    assert exposure["count"] == 2
    redacted = {h["redacted_value"] for h in exposure["hits"]}
    assert len(redacted) == 2


def test_medium_confidence_no_finding(project: Project):
    doc_id, occ_id = _seed_doc_with_occurrence(project, b"x")
    det = _make_detection(
        doc_id,
        occurrence_id=occ_id,
        confidence_level=CONFIDENCE_MEDIUM,
        confidence_score=60,
    )
    stored = insert_detection(project.db_path, det)
    fid = create_passive_secret_finding(project.db_path, project.id, stored.id)
    assert fid is None


def test_suppressed_no_finding(project: Project):
    doc_id, occ_id = _seed_doc_with_occurrence(project, b"x")
    det = _make_detection(
        doc_id, occurrence_id=occ_id, suppressed=True
    )
    stored = insert_detection(project.db_path, det)
    fid = create_passive_secret_finding(project.db_path, project.id, stored.id)
    assert fid is None


def test_threshold_off(project: Project):
    cfg = get_config(project.db_path)
    cfg.auto_finding_threshold = "OFF"
    update_config(project.db_path, cfg)

    doc_id, occ_id = _seed_doc_with_occurrence(project, b"x")
    det = _make_detection(doc_id, occurrence_id=occ_id)
    stored = insert_detection(project.db_path, det)
    fid = create_passive_secret_finding(
        project.db_path, project.id, stored.id, config=cfg
    )
    assert fid is None


def test_already_linked_returns_existing(project: Project):
    doc_id, occ_id = _seed_doc_with_occurrence(project, b"x")
    det = _make_detection(doc_id, occurrence_id=occ_id)
    stored = insert_detection(project.db_path, det)
    fid1 = create_passive_secret_finding(
        project.db_path, project.id, stored.id, raw_value=det.raw_value
    )
    fid2 = create_passive_secret_finding(project.db_path, project.id, stored.id)
    assert fid1 == fid2


def test_finding_title_aws():
    det = _make_detection("doc")
    title = finding_title_for_detection(det)
    assert "AWS" in title


def _role_module_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        module = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
    return str(role[0]), str(module[0])


def _insert_flow(db_path: Path, project_id: str, body: bytes, path: str) -> str:
    fid = str(uuid.uuid4())
    role_id, module_id = _role_module_ids(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end,
                method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id
            ) VALUES (
                ?, ?, ?, NULL,
                'GET', ?, ?, ?, '',
                '{}', '{}', NULL,
                0, 200, ?,
                ?, 0, ?,
                NULL, ?, ?
            )
            """,
            (
                fid,
                project_id,
                datetime.now(timezone.utc).isoformat(),
                f"https://example.com{path}",
                "https://example.com",
                path,
                '{"content-type": "application/javascript"}',
                body,
                "application/javascript",
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return fid


def test_worker_auto_creates_finding(project: Project):
    body = (
        Path(__file__).resolve().parent / "fixtures" / "passive" / "aws_key.js"
    ).read_bytes()
    flow_id = _insert_flow(project.db_path, project.id, body, "/static/app.js")
    role_id, module_id = _role_module_ids(project.db_path)
    q = PassiveScanQueue(maxsize=20)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(
        PassiveScanJob(
            project_id=project.id,
            flow_id=flow_id,
            endpoint_id=None,
            url="https://example.com/static/app.js",
            host="https://example.com",
            path="/static/app.js",
            content_type="application/javascript",
            truncated=False,
            role_id=role_id,
            module_id=module_id,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    deadline = time.monotonic() + 3.0
    while q.size() > 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    assert worker.finding_count >= 1
    findings = findings_db.list_findings(
        project.db_path, project_id=project.id
    )
    passive = [
        f for f in findings if f.get("attack_type") == ATTACK_TYPE_PASSIVE_SECRET
    ]
    assert len(passive) >= 1
    assert passive[0]["relation_type"] == RELATION_TYPE_PRIMARY
