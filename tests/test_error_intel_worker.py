"""
Phase 6–8 tests: ErrorIntelQueue + ErrorIntelWorker + hooks + observe + CLI helpers.

Covers:
  - Queue drop-on-full behaviour
  - Worker: fake flow with Java stack → error_clusters + observation
  - Same fingerprint from two flows → one cluster, two observations
  - maybe_enqueue_error_scan gates and never raises
  - Disabled config skips enqueue / scan
  - attach_error_context enriches observations
  - infer_attack_type from flow_meta (iv / bac / proxy)
  - process_error_scan_sync inline path (replay)
  - parameter / endpoint rollups
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from talos.error_intel import (
    ATTACK_TYPE_BAC,
    ATTACK_TYPE_IV,
    ATTACK_TYPE_PROXY,
    ATTACK_TYPE_UNKNOWN,
    ERROR_INTEL_VERSION,
    attach_error_context,
    observe_error,
)
from talos.error_intel.db import (
    get_config,
    get_cluster,
    has_current_observation_for_flow,
    list_clusters,
    list_observations,
    parameter_error_rollup,
    endpoint_error_rollup,
    update_config,
)
from talos.error_intel.cli import _list_rescan_flow_ids
from talos.error_intel.models import ErrorIntelJob
from talos.error_intel.queue import ErrorIntelQueue
from talos.error_intel.redact import redact_error_text
from talos.error_intel.worker import (
    ERROR_INTEL_FLOW_META_KEY,
    ErrorIntelWorker,
    infer_attack_type,
    maybe_enqueue_error_scan,
    persist_error_context_to_flow_meta,
    process_error_scan_sync,
)
from talos.projects.db import init_project_db, seed_default_context
from talos.projects.model import Project, ProjectStatus, ScopeConstraints


JAVA_SQL = (
    "java.sql.SQLSyntaxErrorException: syntax error near 'FOO'\n"
    "\tat com.example.UserService.load(UserService.java:142)\n"
    "Caused by: org.hibernate.exception.SQLGrammarException: could not extract\n"
)

JAVA_SQL_OTHER_LINE = (
    "java.sql.SQLSyntaxErrorException: syntax error near 'FOO'\n"
    "\tat com.example.UserService.load(UserService.java:999)\n"
    "Caused by: org.hibernate.exception.SQLGrammarException: could not extract\n"
)


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def project(tmp_path: Path) -> Project:
    """Minimal Project with a fresh schema DB and default role/module."""
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
    path: str = "/api/users",
    content_type: str = "text/plain",
    status_code: int = 500,
    flow_id: str | None = None,
    url: str | None = None,
    source: str = "proxy_capture",
    flow_meta: dict | None = None,
    endpoint_id: str | None = None,
    replay_reason: str | None = None,
) -> str:
    """Insert a minimal flows row and return flow_id."""
    fid = flow_id or str(uuid.uuid4())
    role_id, module_id = _role_module_ids(db_path)
    host = "https://example.com"
    full_url = url or f"{host}{path}"
    captured = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        # Ensure optional columns exist for source / flow_meta / replay_reason
        cols = {
            r[1]
            for r in conn.execute("PRAGMA table_info(flows)").fetchall()
        }
        fields = [
            "id", "project_id", "captured_at", "response_end",
            "method", "url", "host", "path", "query",
            "request_headers", "request_cookies", "request_body",
            "request_body_truncated", "status_code", "response_headers",
            "response_body", "response_body_truncated", "content_type",
            "endpoint_id", "role_id", "module_id",
        ]
        values: list = [
            fid, project_id, captured, None,
            "GET", full_url, host, path, "",
            "{}", "{}", None,
            0, status_code, f'{{"content-type": "{content_type}"}}',
            body, 0, content_type,
            endpoint_id, role_id, module_id,
        ]
        if "source" in cols:
            fields.append("source")
            values.append(source)
        if "flow_meta" in cols:
            fields.append("flow_meta")
            values.append(json.dumps(flow_meta or {}))
        if "replay_reason" in cols:
            fields.append("replay_reason")
            values.append(replay_reason)
        placeholders = ", ".join("?" for _ in fields)
        conn.execute(
            f"INSERT INTO flows ({', '.join(fields)}) VALUES ({placeholders})",
            values,
        )
        conn.commit()
    return fid


def _make_job(
    project: Project,
    flow_id: str,
    *,
    path: str = "/api/users",
    content_type: str = "text/plain",
    status_code: int = 500,
    attack_type: str = ATTACK_TYPE_PROXY,
    parameter_uuid: str | None = None,
    parameter_name: str | None = None,
) -> ErrorIntelJob:
    return ErrorIntelJob(
        project_id=project.id,
        flow_id=flow_id,
        endpoint_id=None,
        url=f"https://example.com{path}",
        host="https://example.com",
        path=path,
        content_type=content_type,
        status_code=status_code,
        truncated=False,
        attack_type=attack_type,
        parameter_uuid=parameter_uuid,
        parameter_name=parameter_name,
        payload_redacted=None,
        duration_ms=None,
        observed_at=datetime.now(timezone.utc).isoformat(),
        role_id="",
        module_id="",
    )


# ------------------------------------------------------------------ #
# Queue                                                                #
# ------------------------------------------------------------------ #

def test_queue_drop_on_full() -> None:
    q = ErrorIntelQueue(maxsize=1)
    job1 = ErrorIntelJob(
        project_id="p",
        flow_id="f1",
        endpoint_id=None,
        url="",
        host="",
        path="/a",
        content_type="",
        status_code=500,
        truncated=False,
        attack_type="proxy",
        parameter_uuid=None,
        parameter_name=None,
        payload_redacted=None,
        duration_ms=None,
        observed_at="",
    )
    job2 = ErrorIntelJob(
        project_id="p",
        flow_id="f2",
        endpoint_id=None,
        url="",
        host="",
        path="/b",
        content_type="",
        status_code=500,
        truncated=False,
        attack_type="proxy",
        parameter_uuid=None,
        parameter_name=None,
        payload_redacted=None,
        duration_ms=None,
        observed_at="",
    )
    assert q.put(job1) is True
    assert q.put(job2) is False
    assert q.dropped_job_count == 1
    assert q.enqueued_count == 1


# ------------------------------------------------------------------ #
# Worker pipeline                                                      #
# ------------------------------------------------------------------ #

def test_worker_stores_java_stack(project: Project) -> None:
    body = JAVA_SQL.encode("utf-8")
    fid = _insert_flow(project.db_path, project.id, body=body)
    q = ErrorIntelQueue(maxsize=10)
    worker = ErrorIntelWorker(project, q)
    worker.start()
    try:
        assert q.put(_make_job(project, fid)) is True
        deadline = time.time() + 5.0
        while worker.processed_count < 1 and time.time() < deadline:
            time.sleep(0.05)
    finally:
        worker.stop(timeout=3.0)

    assert worker.processed_count >= 1
    assert worker.stored_count >= 1
    clusters = list_clusters(project.db_path, project.id)
    assert len(clusters) == 1
    assert clusters[0].has_stack_trace or clusters[0].category in (
        "stack_trace",
        "database",
    )
    obs = list_observations(project.db_path, error_id=clusters[0].id)
    assert len(obs) == 1
    assert obs[0].flow_id == fid
    assert obs[0].attack_type == ATTACK_TYPE_PROXY


def test_same_fingerprint_two_flows_one_cluster(project: Project) -> None:
    fid1 = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    fid2 = _insert_flow(
        project.db_path,
        project.id,
        body=JAVA_SQL_OTHER_LINE.encode("utf-8"),
        source="auto_replay",
        flow_meta={
            "generated_by": "input_validation",
            "parameter_uuid": "param-uuid-1",
            "parameter_name": "username",
            "payload": "A" * 100,
        },
        replay_reason="input_validation",
    )

    r1 = process_error_scan_sync(
        db_path=project.db_path,
        project_id=project.id,
        flow_id=fid1,
    )
    r2 = process_error_scan_sync(
        db_path=project.db_path,
        project_id=project.id,
        flow_id=fid2,
    )
    assert r1 and r1.get("stored")
    assert r2 and r2.get("stored")
    assert r1["fingerprint"] == r2["fingerprint"]
    assert r1["cluster_id"] == r2["cluster_id"]

    clusters = list_clusters(project.db_path, project.id)
    assert len(clusters) == 1
    assert clusters[0].observation_count >= 2

    obs = list_observations(project.db_path, error_id=clusters[0].id)
    attacks = {o.attack_type for o in obs}
    assert ATTACK_TYPE_PROXY in attacks
    assert ATTACK_TYPE_IV in attacks
    iv_obs = [o for o in obs if o.attack_type == ATTACK_TYPE_IV][0]
    assert iv_obs.parameter_uuid == "param-uuid-1"
    assert iv_obs.parameter_name == "username"


def test_skip_duplicate_flow(project: Project) -> None:
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    r1 = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    r2 = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    assert r1 and r1.get("stored")
    assert r2 and r2.get("duplicate")


def test_force_rescan(project: Project) -> None:
    """--force reprocesses and replaces the flow's single observation (BUG-07)."""
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    r1 = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    assert r1 and r1.get("stored")
    first_obs_id = r1.get("observation_id")
    r = process_error_scan_sync(
        db_path=project.db_path,
        project_id=project.id,
        flow_id=fid,
        force=True,
    )
    assert r and r.get("stored")
    obs = list_observations(project.db_path, flow_id=fid)
    # Unique flow_id: force replaces rather than stacking rows.
    assert len(obs) == 1
    if first_obs_id:
        assert obs[0].id != first_obs_id or r.get("observation_id") == first_obs_id


# ------------------------------------------------------------------ #
# Enqueue hook                                                         #
# ------------------------------------------------------------------ #

def test_maybe_enqueue_error_scan_gates(project: Project) -> None:
    q = ErrorIntelQueue(maxsize=10)
    # Healthy 200 HTML — not an error candidate
    ok = maybe_enqueue_error_scan(
        error_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow={
            "flow_id": str(uuid.uuid4()),
            "path": "/",
            "status_code": 200,
            "response_body": b"<html><body>ok</body></html>",
            "content_type": "text/html",
            "source": "proxy_capture",
        },
        content_type="text/html",
    )
    assert ok is False
    assert q.enqueued_count == 0

    # 500 with stack
    ok2 = maybe_enqueue_error_scan(
        error_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow={
            "flow_id": str(uuid.uuid4()),
            "path": "/api",
            "status_code": 500,
            "response_body": JAVA_SQL.encode("utf-8"),
            "content_type": "text/plain",
            "source": "proxy_capture",
        },
        content_type="text/plain",
    )
    assert ok2 is True
    assert q.enqueued_count == 1


def test_maybe_enqueue_disabled(project: Project) -> None:
    cfg = get_config(project.db_path)
    cfg.enabled = False
    update_config(project.db_path, cfg)
    q = ErrorIntelQueue(maxsize=10)
    ok = maybe_enqueue_error_scan(
        error_queue=q,
        db_path=project.db_path,
        project_id=project.id,
        flow={
            "flow_id": str(uuid.uuid4()),
            "path": "/api",
            "status_code": 500,
            "response_body": JAVA_SQL.encode("utf-8"),
            "content_type": "text/plain",
        },
        content_type="text/plain",
    )
    assert ok is False


def test_maybe_enqueue_never_raises(project: Project) -> None:
    # Corrupt flow — must not raise
    ok = maybe_enqueue_error_scan(
        error_queue=None,
        db_path=project.db_path,
        project_id=project.id,
        flow={},  # missing flow_id
        content_type="",
    )
    assert ok is False


def test_inline_sync_when_no_queue(project: Project) -> None:
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    ok = maybe_enqueue_error_scan(
        error_queue=None,
        db_path=project.db_path,
        project_id=project.id,
        flow={
            "flow_id": fid,
            "id": fid,
            "path": "/api/users",
            "status_code": 500,
            "response_body": JAVA_SQL.encode("utf-8"),
            "content_type": "text/plain",
            "source": "auto_replay",
            "flow_meta": {"attack_module": "bac", "attack_type": "bac_session_swap"},
            "project_id": project.id,
        },
        content_type="text/plain",
        inline_if_no_queue=True,
    )
    assert ok is True
    clusters = list_clusters(project.db_path, project.id)
    assert len(clusters) == 1
    obs = list_observations(project.db_path, flow_id=fid)
    assert len(obs) == 1
    assert obs[0].attack_type == ATTACK_TYPE_BAC


# ------------------------------------------------------------------ #
# observe / attach                                                     #
# ------------------------------------------------------------------ #

def test_observe_error_stores(project: Project) -> None:
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    result = observe_error(
        project_id=project.id,
        flow_id=fid,
        response_status=500,
        response_body=JAVA_SQL,
        content_type="text/plain",
        attack_type=ATTACK_TYPE_IV,
        parameter_uuid="p-1",
        parameter_name="q",
        db_path=project.db_path,
        force=True,
    )
    assert len(result) == 1
    assert result[0].parameter_uuid == "p-1"
    assert result[0].attack_type == ATTACK_TYPE_IV


def test_attach_error_context_enriches(project: Project) -> None:
    """BUG-06: attach fills empty parameter fields; does not overwrite attack_type."""
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    before = list_observations(project.db_path, flow_id=fid)
    assert before
    original_attack = before[0].attack_type
    assert original_attack in (ATTACK_TYPE_PROXY, ATTACK_TYPE_UNKNOWN)

    ok = attach_error_context(
        project_id=project.id,
        flow_id=fid,
        parameter_uuid="enriched-param",
        parameter_name="email",
        attack_type=ATTACK_TYPE_IV,
        payload="AAAA",
        db_path=project.db_path,
    )
    assert ok is True
    obs = list_observations(project.db_path, flow_id=fid)
    assert obs
    assert obs[0].parameter_uuid == "enriched-param"
    assert obs[0].parameter_name == "email"
    # Non-empty known attack_type is preserved (fill-only).
    if original_attack and original_attack != ATTACK_TYPE_UNKNOWN:
        assert obs[0].attack_type == original_attack
    else:
        assert obs[0].attack_type == ATTACK_TYPE_IV
    assert obs[0].payload_redacted  # payload filled when empty


# ------------------------------------------------------------------ #
# Attack type inference                                                #
# ------------------------------------------------------------------ #

def test_infer_attack_type() -> None:
    assert infer_attack_type("proxy_capture", {}) == ATTACK_TYPE_PROXY
    assert (
        infer_attack_type(
            "auto_replay",
            {"generated_by": "input_validation"},
        )
        == ATTACK_TYPE_IV
    )
    assert (
        infer_attack_type(
            "auto_replay",
            {"attack_module": "bac"},
            "bac_session_swap",
        )
        == ATTACK_TYPE_BAC
    )
    assert (
        infer_attack_type("auto_replay", {"attack_module": "unauth"})
        == "unauth"
    )


# ------------------------------------------------------------------ #
# Rollups                                                              #
# ------------------------------------------------------------------ #

def test_parameter_rollup(project: Project) -> None:
    fid = _insert_flow(
        project.db_path,
        project.id,
        body=JAVA_SQL.encode("utf-8"),
        source="auto_replay",
        flow_meta={
            "generated_by": "input_validation",
            "parameter_uuid": "param-abc",
            "parameter_name": "username",
        },
        replay_reason="input_validation",
        endpoint_id="ep-1",
    )
    process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    rows = parameter_error_rollup(project.db_path, project.id)
    assert rows
    assert rows[0]["parameter_uuid"] == "param-abc"
    assert rows[0]["observation_count"] >= 1

    ep_rows = endpoint_error_rollup(
        project.db_path, project.id, endpoint_id="ep-1"
    )
    assert ep_rows
    assert ep_rows[0]["endpoint_id"] == "ep-1"


def test_error_intel_version() -> None:
    assert ERROR_INTEL_VERSION.startswith("0.4")


def test_outdated_scanner_version_reprocesses(project: Project) -> None:
    """BUG-09: observation at old scanner_version is reprocessed without --force."""
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    r1 = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    assert r1 and r1.get("stored")
    assert has_current_observation_for_flow(project.db_path, fid)

    # Simulate older scanner version on the cluster.
    with sqlite3.connect(str(project.db_path)) as conn:
        conn.execute(
            "UPDATE error_clusters SET scanner_version = '0.0.1'"
        )
        conn.commit()
    assert not has_current_observation_for_flow(project.db_path, fid)

    r2 = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    assert r2 and r2.get("stored")
    assert has_current_observation_for_flow(project.db_path, fid)
    cluster = get_cluster(project.db_path, r2["cluster_id"])
    assert cluster is not None
    assert cluster.scanner_version == ERROR_INTEL_VERSION
    # Still one observation per flow after replace.
    assert len(list_observations(project.db_path, flow_id=fid)) == 1


def test_rescan_list_includes_2xx_json_with_body(project: Project) -> None:
    """BUG-10: bulk rescan candidates include 200 JSON bodies."""
    stack_200 = (
        b"Traceback (most recent call last):\n"
        b'  File "/app/x.py", line 1, in <module>\n'
        b"ValueError: boom\n"
    )
    fid = _insert_flow(
        project.db_path,
        project.id,
        body=stack_200,
        status_code=200,
        content_type="application/json",
        path="/api/rpc",
    )
    ids = _list_rescan_flow_ids(project.db_path, project.id, limit=50)
    assert fid in ids


def test_attach_persists_to_flow_meta(project: Project) -> None:
    """BUG-13: attach writes durable flow_meta so other processes can merge."""
    fid = _insert_flow(
        project.db_path, project.id, body=JAVA_SQL.encode("utf-8")
    )
    ok = attach_error_context(
        project_id=project.id,
        flow_id=fid,
        parameter_uuid="cross-proc-param",
        parameter_name="email",
        attack_type=ATTACK_TYPE_IV,
        payload="secret-payload",
        db_path=project.db_path,
    )
    assert ok is True
    with sqlite3.connect(str(project.db_path)) as conn:
        raw = conn.execute(
            "SELECT flow_meta FROM flows WHERE id = ?", (fid,)
        ).fetchone()[0]
    meta = json.loads(raw)
    ei = meta.get(ERROR_INTEL_FLOW_META_KEY) or {}
    assert ei.get("parameter_uuid") == "cross-proc-param"
    assert ei.get("parameter_name") == "email"
    assert ei.get("attack_type") == ATTACK_TYPE_IV

    # Process without process-local pending — context comes from flow_meta.
    from talos.error_intel.worker import pop_pending_error_context

    pop_pending_error_context(fid)  # clear in-process map
    r = process_error_scan_sync(
        db_path=project.db_path, project_id=project.id, flow_id=fid
    )
    assert r and r.get("stored")
    obs = list_observations(project.db_path, flow_id=fid)
    assert obs[0].parameter_uuid == "cross-proc-param"
    assert obs[0].parameter_name == "email"


def test_redact_error_text_masks_secrets() -> None:
    """BUG-12 unit: redact helper masks password and userinfo URLs."""
    raw = "password=SuperSecret jdbc:mysql://root:hunter2@db/app"
    out = redact_error_text(raw)
    assert out is not None
    assert "SuperSecret" not in out
    assert "hunter2" not in out
    assert "****" in out
