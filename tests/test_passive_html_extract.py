"""
Phase 11 tests: HTML inline script / bootstrap JSON extractors + worker e2e.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from talos.passive.constants import SCAN_STATUS_SCANNED, SourceKind
from talos.passive.db import (
    list_detections,
    list_documents,
    list_occurrences,
)
from talos.passive.extractors.html import extract_html_virtual_docs
from talos.passive.models import PassiveScanJob
from talos.passive.queue import PassiveScanQueue
from talos.passive.worker import SourceScanWorker
from talos.projects.db import init_project_db, seed_default_context
from talos.projects.model import Project, ProjectStatus, ScopeConstraints

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


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


def test_extract_inline_script_skips_src():
    html = (FIXTURES / "inline_aws.html").read_text(encoding="utf-8")
    virt = extract_html_virtual_docs(
        html,
        parent_document_id="parent-html",
        project_id="proj",
    )
    assert len(virt) >= 2
    kinds = {v.source_kind for v in virt}
    assert SourceKind.JAVASCRIPT in kinds
    assert SourceKind.JSON in kinds
    texts = "\n".join(v.text or "" for v in virt)
    assert "AKIAJFAKESECRET00001" in texts
    assert "AIzaSyAabcdefghijklmnopqrstuvwxyz012345" in texts
    # External vendor.js must not appear as a virtual body
    assert "vendor.js" not in texts
    names = [v.logical_source_name or "" for v in virt]
    assert any("inline-script" in n for n in names)
    assert any("bootstrap" in n or "NEXT" in n.upper() or "next" in n for n in names)


def test_extract_empty_html():
    assert extract_html_virtual_docs(
        "", parent_document_id="p", project_id="proj"
    ) == []
    assert extract_html_virtual_docs(
        "<html><body>no scripts</body></html>",
        parent_document_id="p",
        project_id="proj",
    ) == []


def test_extract_caps_scripts():
    scripts = "".join(
        f"<script>const x{i} = {i};</script>" for i in range(100)
    )
    html = f"<html><body>{scripts}</body></html>"
    virt = extract_html_virtual_docs(
        html,
        parent_document_id="p",
        project_id="proj",
        max_scripts=5,
    )
    assert len(virt) == 5


def test_worker_html_inline_secret_finding(project: Project):
    db_path = project.db_path
    html = (FIXTURES / "inline_aws.html").read_bytes()
    role = _role_module(db_path)
    flow_id = str(uuid.uuid4())
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
                'GET', ?, 'https://example.com', '/app', '',
                '{}', '{}', NULL,
                0, 200, '{}',
                ?, 0, 'text/html',
                NULL, ?, ?
            )
            """,
            (
                flow_id,
                project.id,
                datetime.now(timezone.utc).isoformat(),
                "https://example.com/app",
                html,
                role[0],
                role[1],
            ),
        )
        conn.commit()

    queue = PassiveScanQueue(maxsize=50)
    worker = SourceScanWorker(project, queue)
    worker.start()
    try:
        job = PassiveScanJob(
            project_id=project.id,
            flow_id=flow_id,
            endpoint_id=None,
            url="https://example.com/app",
            host="https://example.com",
            path="/app",
            content_type="text/html",
            truncated=False,
            role_id=role[0],
            module_id=role[1],
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
        assert queue.put(job)
        deadline = time.time() + 10
        while worker.processed_count < 1 and time.time() < deadline:
            time.sleep(0.05)
    finally:
        worker.stop(timeout=5)

    docs = list_documents(db_path, project.id, limit=50)
    # Parent HTML + at least one virtual child
    assert any(d.source_kind == SourceKind.HTML for d in docs)
    children = [d for d in docs if d.parent_document_id]
    assert children, "expected virtual HTML children"
    assert all(d.scan_status == SCAN_STATUS_SCANNED for d in children)

    dets = list_detections(db_path, project_id=project.id, limit=50)
    detector_ids = {d.detector_id for d in dets}
    assert "aws_access_key_id" in detector_ids or any(
        "AKIA" in (d.redacted_value or "") or d.secret_type == "aws_access_key"
        for d in dets
    )
    # At least one high-confidence secret from inline content
    assert any(
        d.confidence_level in ("CONFIRMED_PATTERN", "HIGH")
        and d.category == "secret"
        for d in dets
    )
    # Findings created for AWS (and possibly Google)
    assert any(d.finding_id for d in dets)


def _role_module(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        module = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
    assert role and module
    return str(role[0]), str(module[0])
