"""
Phase 4–7 tests: PassiveScanQueue + SourceScanWorker + FlowWorker enqueue.

Covers:
  - Queue drop-on-full behaviour
  - Worker: fake flow → document + occurrence
  - Same body twice → second job is occurrence-only (no second scan)
  - maybe_enqueue_passive_scan gates and never raises
  - Disabled config skips enqueue / scan
  - PNG / empty body not scanned
  - Phase 5+: AWS key body → passive_detections row + auto-finding (Phase 8)
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from talos.passive.constants import (
    SCAN_STATUS_SCANNED,
    SCANNER_VERSION,
    SourceKind,
)
from talos.passive.db import (
    get_config,
    get_document_by_hash,
    list_detections,
    list_occurrences,
    update_config,
)
from talos.passive.models import PassiveScanJob
from talos.passive.queue import PassiveScanQueue
from talos.passive.worker import (
    SourceScanWorker,
    maybe_enqueue_passive_scan,
)
from talos.projects.db import init_project_db, seed_default_context
from talos.projects.model import Project, ProjectStatus, ScopeConstraints
from talos.proxy.queue import FlowQueue
from talos.worker.worker import FlowWorker


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def project(tmp_path: Path) -> Project:
    """Minimal Project with a fresh schema-39 DB and default role/module."""
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


def _role_module_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        module = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
    assert role and module
    return str(role[0]), str(module[0])


def _insert_flow(
    db_path: Path,
    project_id: str,
    *,
    body: bytes,
    path: str = "/static/app.js",
    content_type: str = "application/javascript",
    status_code: int = 200,
    flow_id: str | None = None,
    url: str | None = None,
) -> str:
    """Insert a minimal flows row and return flow_id."""
    fid = flow_id or str(uuid.uuid4())
    role_id, module_id = _role_module_ids(db_path)
    host = "https://example.com"
    full_url = url or f"{host}{path}"
    captured = datetime.now(timezone.utc).isoformat()
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
                0, ?, ?,
                ?, 0, ?,
                NULL, ?, ?
            )
            """,
            (
                fid,
                project_id,
                captured,
                full_url,
                host,
                path,
                status_code,
                f'{{"content-type": "{content_type}"}}',
                body,
                content_type,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return fid


def _make_job(
    project: Project,
    flow_id: str,
    *,
    path: str = "/static/app.js",
    content_type: str = "application/javascript",
    truncated: bool = False,
) -> PassiveScanJob:
    role_id, module_id = _role_module_ids(project.db_path)
    return PassiveScanJob(
        project_id=project.id,
        flow_id=flow_id,
        endpoint_id=None,
        url=f"https://example.com{path}",
        host="https://example.com",
        path=path,
        content_type=content_type,
        truncated=truncated,
        role_id=role_id,
        module_id=module_id,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )


def _drain_worker(worker: SourceScanWorker, timeout: float = 3.0) -> None:
    """Process remaining queue items then stop the worker."""
    deadline = time.monotonic() + timeout
    while worker._queue.size() > 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    # Give the active item a moment to finish.
    time.sleep(0.1)
    worker.stop(timeout=2.0)


# ------------------------------------------------------------------ #
# Queue                                                                #
# ------------------------------------------------------------------ #

def test_queue_put_get_roundtrip():
    q = PassiveScanQueue(maxsize=10)
    job = PassiveScanJob(
        project_id="p",
        flow_id="f1",
        endpoint_id=None,
        url="https://example.com/a.js",
        host="example.com",
        path="/a.js",
        content_type="application/javascript",
        truncated=False,
        role_id="r",
        module_id="m",
        observed_at="2020-01-01T00:00:00+00:00",
    )
    assert q.put(job) is True
    assert q.enqueued_count == 1
    assert q.size() == 1
    got = q.get(timeout=0.5)
    assert got is not None
    assert got.flow_id == "f1"


def test_queue_drop_on_full():
    q = PassiveScanQueue(maxsize=1)
    base = dict(
        project_id="p",
        endpoint_id=None,
        url="https://example.com/a.js",
        host="example.com",
        path="/a.js",
        content_type="application/javascript",
        truncated=False,
        role_id="r",
        module_id="m",
        observed_at="2020-01-01T00:00:00+00:00",
    )
    assert q.put(PassiveScanJob(flow_id="f1", **base)) is True
    assert q.put(PassiveScanJob(flow_id="f2", **base)) is False
    assert q.dropped_job_count == 1
    assert q.enqueued_count == 1
    assert q.size() == 1


# ------------------------------------------------------------------ #
# Worker integration                                                   #
# ------------------------------------------------------------------ #

def test_worker_registers_document_and_occurrence(project: Project):
    body = b"const x = 1;\n// app bootstrap\n"
    flow_id = _insert_flow(project.db_path, project.id, body=body)
    q = PassiveScanQueue(maxsize=50)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(_make_job(project, flow_id))
    _drain_worker(worker)

    body_hash = hashlib.sha256(body).hexdigest()
    doc = get_document_by_hash(project.db_path, project.id, body_hash)
    assert doc is not None
    assert doc.source_kind == SourceKind.JAVASCRIPT
    assert doc.scan_status == SCAN_STATUS_SCANNED
    assert doc.scanner_version == SCANNER_VERSION
    assert doc.body_size == len(body)

    occs = list_occurrences(project.db_path, doc.id)
    assert len(occs) == 1
    assert occs[0].flow_id == flow_id
    assert occs[0].path == "/static/app.js"

    assert worker.scanned_count == 1
    assert worker.skipped_dup_count == 0
    assert worker.error_count == 0


def test_worker_same_body_twice_no_second_scan(project: Project):
    body = b"export const API = 'ok';\n"
    body_hash = hashlib.sha256(body).hexdigest()
    flow_a = _insert_flow(
        project.db_path,
        project.id,
        body=body,
        path="/assets/bundle.js",
    )
    flow_b = _insert_flow(
        project.db_path,
        project.id,
        body=body,
        path="/cdn/bundle.js",
    )

    q = PassiveScanQueue(maxsize=50)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(_make_job(project, flow_a, path="/assets/bundle.js"))
    q.put(_make_job(project, flow_b, path="/cdn/bundle.js"))
    _drain_worker(worker)

    doc = get_document_by_hash(project.db_path, project.id, body_hash)
    assert doc is not None
    assert doc.scan_status == SCAN_STATUS_SCANNED
    assert doc.scanner_version == SCANNER_VERSION

    occs = list_occurrences(project.db_path, doc.id)
    assert len(occs) == 2
    flow_ids = {o.flow_id for o in occs}
    assert flow_ids == {flow_a, flow_b}

    assert worker.scanned_count == 1
    assert worker.skipped_dup_count == 1


def test_worker_skips_png_magic(project: Project):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    flow_id = _insert_flow(
        project.db_path,
        project.id,
        body=png,
        path="/img/logo.png",
        content_type="text/plain",  # lied CT — magic still rejects
    )
    q = PassiveScanQueue(maxsize=10)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(
        _make_job(
            project,
            flow_id,
            path="/img/logo.png",
            content_type="text/plain",
        )
    )
    _drain_worker(worker)

    body_hash = hashlib.sha256(png).hexdigest()
    assert get_document_by_hash(project.db_path, project.id, body_hash) is None
    assert worker.scanned_count == 0
    assert worker.skipped_count >= 1


def test_worker_disabled_config_skips(project: Project):
    cfg = get_config(project.db_path)
    cfg.enabled = False
    update_config(project.db_path, cfg)

    body = b"var y = 2;\n"
    flow_id = _insert_flow(project.db_path, project.id, body=body)
    q = PassiveScanQueue(maxsize=10)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(_make_job(project, flow_id))
    _drain_worker(worker)

    body_hash = hashlib.sha256(body).hexdigest()
    assert get_document_by_hash(project.db_path, project.id, body_hash) is None
    assert worker.scanned_count == 0


def test_worker_persists_aws_detection(project: Project):
    """Phase 5+/8: synthetic AWS key in JS → detection + auto-finding."""
    fixture = (
        Path(__file__).resolve().parent / "fixtures" / "passive" / "aws_key.js"
    )
    body = fixture.read_bytes()
    flow_id = _insert_flow(project.db_path, project.id, body=body)
    q = PassiveScanQueue(maxsize=50)
    worker = SourceScanWorker(project=project, queue=q)
    worker.start()
    q.put(_make_job(project, flow_id))
    _drain_worker(worker)

    body_hash = hashlib.sha256(body).hexdigest()
    doc = get_document_by_hash(project.db_path, project.id, body_hash)
    assert doc is not None
    assert doc.scan_status == SCAN_STATUS_SCANNED
    assert worker.scanned_count == 1
    assert worker.error_count == 0
    assert worker.detection_count >= 1

    dets = list_detections(project.db_path, document_id=doc.id)
    aws = [d for d in dets if d.detector_id == "aws_access_key_id"]
    assert len(aws) == 1
    assert aws[0].finding_id is not None  # Phase 8 auto-finding
    assert not aws[0].suppressed
    assert aws[0].confidence_score >= 70
    assert worker.finding_count >= 1


# ------------------------------------------------------------------ #
# maybe_enqueue_passive_scan                                           #
# ------------------------------------------------------------------ #

def test_maybe_enqueue_js_candidate(project: Project):
    q = PassiveScanQueue(maxsize=10)
    role_id, module_id = _role_module_ids(project.db_path)
    flow = {
        "flow_id": str(uuid.uuid4()),
        "path": "/app.js",
        "url": "https://example.com/app.js",
        "host": "https://example.com",
        "status_code": 200,
        "response_body": b"const a = 1;",
        "response_body_truncated": False,
        "role_id": role_id,
        "module_id": module_id,
        "request_start": datetime.now(timezone.utc).isoformat(),
    }
    ok = maybe_enqueue_passive_scan(
        passive_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow=flow,
        endpoint_id=None,
        content_type="application/javascript",
    )
    assert ok is True
    assert q.size() == 1
    job = q.get(timeout=0.2)
    assert job is not None
    assert job.flow_id == flow["flow_id"]
    assert job.path == "/app.js"


def test_maybe_enqueue_rejects_image(project: Project):
    q = PassiveScanQueue(maxsize=10)
    flow = {
        "flow_id": str(uuid.uuid4()),
        "path": "/x.png",
        "url": "https://example.com/x.png",
        "host": "https://example.com",
        "status_code": 200,
        "response_body": b"\x89PNG\r\n\x1a\n",
        "response_body_truncated": False,
        "role_id": "r",
        "module_id": "m",
        "request_start": datetime.now(timezone.utc).isoformat(),
    }
    ok = maybe_enqueue_passive_scan(
        passive_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow=flow,
        endpoint_id=None,
        content_type="image/png",
    )
    assert ok is False
    assert q.size() == 0


def test_maybe_enqueue_none_queue_is_noop(project: Project):
    ok = maybe_enqueue_passive_scan(
        passive_queue=None,
        db_path=project.db_path,
        project_id=project.id,
        flow={"flow_id": "x", "path": "/a.js", "status_code": 200},
        endpoint_id=None,
        content_type="application/javascript",
    )
    assert ok is False


def test_maybe_enqueue_disabled(project: Project):
    cfg = get_config(project.db_path)
    cfg.enabled = False
    update_config(project.db_path, cfg)
    q = PassiveScanQueue(maxsize=10)
    ok = maybe_enqueue_passive_scan(
        passive_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow={
            "flow_id": str(uuid.uuid4()),
            "path": "/a.js",
            "status_code": 200,
            "response_body": b"x=1",
            "request_start": "2020-01-01T00:00:00+00:00",
            "role_id": "r",
            "module_id": "m",
            "url": "https://example.com/a.js",
            "host": "example.com",
        },
        endpoint_id=None,
        content_type="application/javascript",
    )
    assert ok is False
    assert q.size() == 0


# ------------------------------------------------------------------ #
# FlowWorker end-to-end enqueue                                        #
# ------------------------------------------------------------------ #

def test_flow_worker_enqueues_and_registers(project: Project):
    """FlowWorker persist → passive queue → SourceScanWorker registry."""
    role_id, module_id = _role_module_ids(project.db_path)
    body = b"function boot(){ return true; }\n"
    flow_queue = FlowQueue(maxsize=50)
    passive_queue = PassiveScanQueue(maxsize=50)

    flow_worker = FlowWorker(
        project=project,
        queue=flow_queue,
        passive_queue=passive_queue,
    )
    scan_worker = SourceScanWorker(project=project, queue=passive_queue)
    flow_worker.start()
    scan_worker.start()

    flow_id = str(uuid.uuid4())
    flow_queue.put(
        {
            "flow_id": flow_id,
            "request_start": datetime.now(timezone.utc).isoformat(),
            "response_end": datetime.now(timezone.utc).isoformat(),
            "method": "GET",
            "url": "https://example.com/static/main.js",
            "host": "https://example.com",
            "hostname": "example.com",
            "path": "/static/main.js",
            "query": "",
            "request_headers": {},
            "request_cookies": {},
            "request_body": None,
            "request_body_truncated": False,
            "status_code": 200,
            "response_headers": {"content-type": "application/javascript"},
            "response_body": body,
            "response_body_truncated": False,
            "role_id": role_id,
            "module_id": module_id,
        }
    )

    # Wait for both workers to settle.
    deadline = time.monotonic() + 5.0
    while (
        flow_worker.processed_count < 1 or scan_worker.processed_count < 1
    ) and time.monotonic() < deadline:
        time.sleep(0.05)

    flow_worker.stop(timeout=2.0)
    scan_worker.stop(timeout=2.0)

    assert flow_worker.processed_count >= 1
    body_hash = hashlib.sha256(body).hexdigest()
    doc = get_document_by_hash(project.db_path, project.id, body_hash)
    assert doc is not None
    assert doc.scan_status == SCAN_STATUS_SCANNED
    occs = list_occurrences(project.db_path, doc.id)
    assert any(o.flow_id == flow_id for o in occs)
