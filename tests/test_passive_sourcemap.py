"""
Phase 10 tests: source map extractor + worker e2e for sourcesContent.
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
    get_document_by_hash,
    list_detections,
    list_documents,
    list_occurrences,
)
from talos.passive.extractors.sourcemap import (
    extract_sourcemap_virtual_docs,
    parse_sourcemap_json,
)
from talos.passive.models import PassiveScanJob
from talos.passive.queue import PassiveScanQueue
from talos.passive.worker import SourceScanWorker, path_looks_like_sourcemap
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


def test_parse_sourcemap_json_valid():
    text = (FIXTURES / "aws_in_sourcemap.map").read_text(encoding="utf-8")
    data = parse_sourcemap_json(text)
    assert data is not None
    assert data["version"] == 3
    assert isinstance(data["sourcesContent"], list)


def test_parse_invalid_returns_none():
    assert parse_sourcemap_json("not json") is None
    assert parse_sourcemap_json("") is None
    assert parse_sourcemap_json("[1,2,3]") is None


def test_extract_sources_content():
    text = (FIXTURES / "aws_in_sourcemap.map").read_text(encoding="utf-8")
    virt = extract_sourcemap_virtual_docs(
        text,
        parent_document_id="parent-1",
        project_id="proj",
    )
    assert len(virt) == 2
    assert all(v.source_kind == SourceKind.JAVASCRIPT for v in virt)
    assert all(v.parent_document_id == "parent-1" for v in virt)
    assert virt[0].logical_source_name == "app/src/config.js"
    assert "AKIAJFAKESECRET00001" in (virt[0].text or "")


def test_extract_without_sources_content():
    text = (FIXTURES / "map_without_sourcescontent.map").read_text(
        encoding="utf-8"
    )
    virt = extract_sourcemap_virtual_docs(
        text,
        parent_document_id="parent-1",
        project_id="proj",
    )
    assert virt == []


def test_path_looks_like_sourcemap():
    assert path_looks_like_sourcemap("/static/app.js.map")
    assert path_looks_like_sourcemap("/x.map", "application/json")
    assert not path_looks_like_sourcemap("/static/app.js")


def _role_module_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        module = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
    return str(role[0]), str(module[0])


def _insert_flow(
    db_path: Path,
    project_id: str,
    body: bytes,
    *,
    path: str,
    content_type: str,
) -> str:
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
                f'{{"content-type": "{content_type}"}}',
                body,
                content_type,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return fid


def test_worker_sourcemap_with_aws_creates_detection(project: Project):
    body = (FIXTURES / "aws_in_sourcemap.map").read_bytes()
    flow_id = _insert_flow(
        project.db_path,
        project.id,
        body,
        path="/static/bundle.js.map",
        content_type="application/json",
    )
    role_id, module_id = _role_module_ids(project.db_path)
    q = PassiveScanQueue(maxsize=20)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(
        PassiveScanJob(
            project_id=project.id,
            flow_id=flow_id,
            endpoint_id=None,
            url="https://example.com/static/bundle.js.map",
            host="https://example.com",
            path="/static/bundle.js.map",
            content_type="application/json",
            truncated=False,
            role_id=role_id,
            module_id=module_id,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    deadline = time.monotonic() + 3.0
    while q.size() > 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    worker.stop(timeout=2.0)

    assert worker.error_count == 0
    assert worker.scanned_count >= 1

    body_hash = hashlib.sha256(body).hexdigest()
    parent = get_document_by_hash(project.db_path, project.id, body_hash)
    assert parent is not None
    assert parent.source_kind == SourceKind.SOURCEMAP
    assert parent.scan_status == SCAN_STATUS_SCANNED

    # Virtual child documents with parent linkage
    docs = list_documents(project.db_path, project.id, limit=50)
    children = [d for d in docs if d.parent_document_id == parent.id]
    assert len(children) >= 1

    # AWS detection on virtual source
    all_dets = list_detections(project.db_path, project_id=project.id, limit=50)
    aws = [d for d in all_dets if d.detector_id == "aws_access_key_id"]
    assert len(aws) >= 1
    assert aws[0].finding_id is not None


def test_worker_map_without_sourcescontent_no_crash(project: Project):
    body = (FIXTURES / "map_without_sourcescontent.map").read_bytes()
    flow_id = _insert_flow(
        project.db_path,
        project.id,
        body,
        path="/static/empty.js.map",
        content_type="application/json",
    )
    role_id, module_id = _role_module_ids(project.db_path)
    q = PassiveScanQueue(maxsize=10)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(
        PassiveScanJob(
            project_id=project.id,
            flow_id=flow_id,
            endpoint_id=None,
            url="https://example.com/static/empty.js.map",
            host="https://example.com",
            path="/static/empty.js.map",
            content_type="application/json",
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

    assert worker.error_count == 0
    parent = get_document_by_hash(
        project.db_path, project.id, hashlib.sha256(body).hexdigest()
    )
    assert parent is not None
    assert parent.scan_status == SCAN_STATUS_SCANNED
    occs = list_occurrences(project.db_path, parent.id)
    assert len(occs) == 1
