"""
Phase 9 tests: talos passive CLI surface (status, config, rules, list, rescan).
"""

from __future__ import annotations

import hashlib
import io
import uuid
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import pytest

from talos.passive.cli import run_passive_cli
from talos.passive.constants import (
    CATEGORY_SECRET,
    DETECTOR_FAMILY_PROVIDER,
    SCANNER_VERSION,
    SourceKind,
)
from talos.passive.db import (
    get_config,
    insert_detection,
    insert_occurrence,
    upsert_document,
)
from talos.passive.models import Detection
from talos.passive.redaction import fingerprint_secret, redact_secret
from talos.projects.db import init_project_db, seed_default_context
from talos.projects.model import Project, ProjectStatus, ScopeConstraints


class _FakeManager:
    """Minimal ProjectManager stand-in for CLI tests."""

    def __init__(self, project: Project) -> None:
        self._project = project

    def active(self) -> Project:
        """Match ProjectManager.active() resolution surface."""
        return self._project


@pytest.fixture
def project(tmp_path: Path) -> Project:
    data_dir = tmp_path / "proj"
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    init_project_db(db_path)
    seed_default_context(db_path)
    return Project(
        id="cli-proj",
        name="CLI Test",
        description="",
        created_at=datetime.now(timezone.utc).isoformat(),
        status=ProjectStatus.ACTIVE,
        scope=["example.com"],
        data_dir=str(data_dir),
        constraints=ScopeConstraints(),
    )


def _run(manager: _FakeManager, *args: str) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_passive_cli(manager, list(args))  # type: ignore[arg-type]
    return buf.getvalue()


def test_status(project: Project):
    mgr = _FakeManager(project)
    out = _run(mgr, "status")
    assert "enabled" in out.lower() or "Passive scan status" in out
    assert SCANNER_VERSION in out


def test_config_show_and_set(project: Project):
    mgr = _FakeManager(project)
    out = _run(mgr, "config", "show")
    assert "enabled" in out
    _run(mgr, "config", "set", "enabled", "false")
    cfg = get_config(project.db_path)
    assert cfg.enabled is False
    _run(mgr, "config", "set", "auto_finding_threshold", "OFF")
    cfg = get_config(project.db_path)
    assert cfg.auto_finding_threshold == "OFF"
    _run(mgr, "config", "set", "max_scan_time_ms", "2500")
    cfg = get_config(project.db_path)
    assert cfg.max_scan_time_ms == 2500


def test_rules_list(project: Project):
    mgr = _FakeManager(project)
    out = _run(mgr, "rules", "list")
    assert "aws_access_key_id" in out or "AWS" in out


def test_documents_and_detections_list(project: Project):
    body = b"const x = 1;"
    body_hash = hashlib.sha256(body).hexdigest()
    doc, _ = upsert_document(
        project.db_path,
        project.id,
        body_hash,
        SourceKind.JAVASCRIPT,
        len(body),
    )
    insert_occurrence(
        project.db_path,
        document_id=doc.id,
        flow_id="f1",
        url="https://example.com/a.js",
        host="example.com",
        path="/a.js",
        content_type="application/javascript",
        observed_at=datetime.now(timezone.utc).isoformat(),
    )
    secret = "AKIAJFAKESECRET00001"
    det = Detection(
        id=str(uuid.uuid4()),
        document_id=doc.id,
        occurrence_id=None,
        detector_id="aws_access_key_id",
        detector_family=DETECTOR_FAMILY_PROVIDER,
        category=CATEGORY_SECRET,
        secret_type="aws_access_key",
        matched_key=None,
        redacted_value=redact_secret(secret),
        value_fingerprint=fingerprint_secret(DETECTOR_FAMILY_PROVIDER, secret),
        confidence_score=95,
        confidence_level="CONFIRMED_PATTERN",
    )
    insert_detection(project.db_path, det)

    mgr = _FakeManager(project)
    dout = _run(mgr, "documents", "list")
    assert doc.id[:8] in dout or "javascript" in dout

    det_out = _run(mgr, "detections", "list")
    assert "aws_access_key_id" in det_out
    assert "AKIA" in det_out or "****" in det_out
    # raw full secret must not appear
    assert secret not in det_out
