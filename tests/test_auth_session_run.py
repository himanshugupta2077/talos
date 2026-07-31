"""
Tests: auth-session Phase 3 run CLI, dedupe, results, candidate settle helpers.
"""

from __future__ import annotations

import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.auth_session import db as as_db
from talos.auth_session.cli import build_auth_session_parser, run_auth_session_cli
from talos.auth_session.jwt_codec import encode_jwt
from talos.auth_session.models import (
    STATUS_APPROVED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    VERDICT_WEAK_VALIDATION,
)
from talos.projects.auth import set_auth_fields
from talos.projects.db import init_project_db
from talos.scheduler.job import AUTH_SESSION_ATTACK, JOB_TYPES
import talos.scheduler.db as sched_db

PROJECT_ID = "proj-run"
EP = "ep-run"
FLOW = "flow-run"
NOW = "2026-01-01T00:00:00+00:00"
BODY = b'{"ok":true}'


def _jwt() -> str:
    return encode_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "u1", "role": "user"},
        "sig",
    )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    bearer = f"Bearer {_jwt()}"
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/me', '/api/me',
                    'application/json', 1, '[]', ?, ?)
            """,
            (EP, PROJECT_ID, NOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
            """,
            (EP, FLOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', ?, '{}', 200,
                    ?, ?, 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Authorization": bearer}),
                json.dumps({"content-type": "application/json"}),
                BODY,
                EP,
            ),
        )
        conn.commit()
    set_auth_fields(path, cookies=[], headers=["Authorization"])
    return path


@pytest.fixture()
def manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(id=PROJECT_ID, db_path=db_path)
    m = MagicMock()
    m.active.return_value = project
    return m


def _parse_as(argv: list[str]):
    parser = __import__("argparse").ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_auth_session_parser(sub)
    return parser.parse_args(["auth-session", *argv])


def _approve_one(db_path: Path, manager: MagicMock) -> str:
    run_auth_session_cli(
        manager, _parse_as(["bind", "--type", "jwt", "--header", "Authorization"])
    )
    run_auth_session_cli(manager, _parse_as(["generate", "--endpoint", EP]))
    # Approve a single deterministic test_id to keep run small
    rows = as_db.list_candidates(db_path, status=STATUS_PENDING, test_ids=["jwt.alg_none"])
    assert rows
    as_db.approve_candidates(db_path, [rows[0].id])
    return rows[0].id


def test_job_type_registered() -> None:
    assert AUTH_SESSION_ATTACK == "auth_session_attack"
    assert AUTH_SESSION_ATTACK in JOB_TYPES


def test_run_enqueues_one_job_per_candidate(manager: MagicMock, db_path: Path) -> None:
    cid = _approve_one(db_path, manager)
    # Approve a second distinct test_id
    rows = as_db.list_candidates(
        db_path, status=STATUS_PENDING, test_ids=["jwt.invalid_signature"]
    )
    assert rows
    as_db.approve_candidates(db_path, [rows[0].id])

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["run"]))
    text = out.getvalue()
    assert "Jobs enqueued" in text
    assert "2" in text or "Jobs enqueued      : 2" in text

    with sqlite3.connect(str(db_path)) as conn:
        jobs = conn.execute(
            "SELECT job_type, meta FROM scheduler_jobs WHERE job_type = ?",
            (AUTH_SESSION_ATTACK,),
        ).fetchall()
    assert len(jobs) == 2
    metas = [json.loads(j[1]) for j in jobs]
    test_ids = {m["test_id"] for m in metas}
    assert "jwt.alg_none" in test_ids
    assert "jwt.invalid_signature" in test_ids
    for m in metas:
        assert m["candidate_id"]
        assert m["binding_id"]
        assert m["baseline_flow_id"] == FLOW


def test_run_dedupe_skips_pending_duplicate(manager: MagicMock, db_path: Path) -> None:
    cid = _approve_one(db_path, manager)
    cand = as_db.get_candidate(db_path, cid)
    assert cand is not None

    # First enqueue
    run_auth_session_cli(manager, _parse_as(["run", "--candidate", cid]))
    # Second should dedupe
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["run", "--candidate", cid]))
    assert "Skipped (dup)" in out.getvalue() or "already pending" in out.getvalue()

    with sqlite3.connect(str(db_path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM scheduler_jobs WHERE job_type = ?",
            (AUTH_SESSION_ATTACK,),
        ).fetchone()[0]
    assert n == 1


def test_has_pending_auth_session_duplicate_meta_aware(db_path: Path) -> None:
    binding = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    meta_a = json.dumps({
        "test_id": "jwt.alg_none",
        "binding_id": binding.id,
        "candidate_id": "c1",
    })
    meta_b = json.dumps({
        "test_id": "jwt.invalid_signature",
        "binding_id": binding.id,
        "candidate_id": "c2",
    })
    sched_db.enqueue_job(
        db_path=db_path,
        job_id=str(uuid.uuid4()),
        job_type=AUTH_SESSION_ATTACK,
        project_id=PROJECT_ID,
        flow_id=FLOW,
        priority=100,
        meta=meta_a,
    )
    assert as_db.has_pending_auth_session_duplicate(
        db_path, flow_id=FLOW, test_id="jwt.alg_none", binding_id=binding.id
    )
    # Different test_id is NOT a duplicate
    assert not as_db.has_pending_auth_session_duplicate(
        db_path,
        flow_id=FLOW,
        test_id="jwt.invalid_signature",
        binding_id=binding.id,
    )
    sched_db.enqueue_job(
        db_path=db_path,
        job_id=str(uuid.uuid4()),
        job_type=AUTH_SESSION_ATTACK,
        project_id=PROJECT_ID,
        flow_id=FLOW,
        priority=100,
        meta=meta_b,
    )
    assert as_db.has_pending_auth_session_duplicate(
        db_path,
        flow_id=FLOW,
        test_id="jwt.invalid_signature",
        binding_id=binding.id,
    )


def test_mark_candidate_running_done_failed(db_path: Path) -> None:
    binding = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    cand = as_db.insert_candidate(
        db_path,
        binding_id=binding.id,
        baseline_flow_id=FLOW,
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
        endpoint_id=EP,
        status=STATUS_APPROVED,
    )
    running = as_db.mark_candidate_running(db_path, cand.id)
    assert running is not None
    assert running.status == STATUS_RUNNING
    done = as_db.mark_candidate_done(db_path, cand.id)
    assert done is not None
    assert done.status == STATUS_DONE

    # Re-approve and fail path
    as_db.approve_candidates(db_path, [cand.id])
    as_db.mark_candidate_running(db_path, cand.id)
    failed = as_db.mark_candidate_failed(
        db_path, cand.id, skip_reason="endpoint_excluded"
    )
    assert failed is not None
    assert failed.status == STATUS_FAILED
    assert failed.skip_reason == "endpoint_excluded"


def test_insert_and_list_results(db_path: Path) -> None:
    binding = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    cand = as_db.insert_candidate(
        db_path,
        binding_id=binding.id,
        baseline_flow_id=FLOW,
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
        endpoint_id=EP,
    )
    # Need a flow row for FK on replay_flow_id
    replay_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source, original_flow_id)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', '{}', '{}', 200,
                    '{}', 'application/json', ?, '', '', '[]', 'auto_replay', ?)
            """,
            (replay_id, PROJECT_ID, NOW, EP, FLOW),
        )
        conn.commit()

    result = as_db.insert_result(
        db_path,
        replay_flow_id=replay_id,
        original_flow_id=FLOW,
        candidate_id=cand.id,
        binding_id=binding.id,
        auth_type="jwt",
        test_id="jwt.alg_none",
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        test_family="algorithm",
        original_status=200,
        replay_status=200,
        diff_verdict="SAME",
    )
    assert result.verdict == VERDICT_WEAK_VALIDATION
    rows = as_db.list_results(db_path, endpoint_id=EP, verdict=VERDICT_WEAK_VALIDATION)
    assert len(rows) == 1
    got = as_db.get_result(db_path, replay_id)
    assert got is not None
    assert got.test_id == "jwt.alg_none"


def test_run_right_now(manager: MagicMock, db_path: Path) -> None:
    cid = _approve_one(db_path, manager)
    resp = MagicMock()
    resp.status_code = 200
    resp.content = BODY
    resp.headers = {"content-type": "application/json"}
    client = MagicMock()
    client.request = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    out = io.StringIO()
    with patch("talos.auth_session.engine.httpx.AsyncClient", return_value=client):
        with redirect_stdout(out):
            run_auth_session_cli(
                manager, _parse_as(["run", "--candidate", cid, "--right-now"])
            )
    text = out.getvalue()
    assert "WEAK_VALIDATION" in text or "Done:" in text
    cand = as_db.get_candidate(db_path, cid)
    assert cand is not None
    assert cand.status == STATUS_DONE
    results = as_db.list_results(db_path, candidate_id=cid)
    assert len(results) == 1


def test_results_list_cli(manager: MagicMock, db_path: Path) -> None:
    # Seed a result via right-now
    test_run_right_now(manager, db_path)
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["results", "list"]))
    assert "WEAK_VALIDATION" in out.getvalue() or "jwt.alg_none" in out.getvalue()


def test_scheduler_settle_marks_candidate_done(db_path: Path) -> None:
    """Unit-level settle: done path updates candidate without findings."""
    from talos.auth_session.models import AuthSessionOutcome
    from talos.scheduler.job import ReplayJob
    from talos.scheduler.scheduler import ReplayScheduler
    from talos.projects.model import Project

    binding = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    cand = as_db.insert_candidate(
        db_path,
        binding_id=binding.id,
        baseline_flow_id=FLOW,
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
        endpoint_id=EP,
        status=STATUS_APPROVED,
    )
    as_db.mark_candidate_running(db_path, cand.id)

    project = SimpleNamespace(id=PROJECT_ID, db_path=db_path)
    # Minimal Project-like object for scheduler
    sched = ReplayScheduler.__new__(ReplayScheduler)
    sched._project = project  # type: ignore[attr-defined]

    job_id = str(uuid.uuid4())
    sched_db.enqueue_job(
        db_path=db_path,
        job_id=job_id,
        job_type=AUTH_SESSION_ATTACK,
        project_id=PROJECT_ID,
        flow_id=FLOW,
        endpoint_id=EP,
        priority=100,
        meta=json.dumps({"candidate_id": cand.id, "test_id": "jwt.alg_none"}),
    )
    sched_db.mark_running(db_path, job_id)

    job = ReplayJob(
        job_id=job_id,
        endpoint_id=EP,
        flow_id=FLOW,
        job_type=AUTH_SESSION_ATTACK,
        priority=100,
        created_at=NOW,
        db_path=db_path,
        project_id=PROJECT_ID,
        status="running",
        meta=json.dumps({"candidate_id": cand.id}),
    )
    outcome = AuthSessionOutcome(
        original_flow_id=FLOW,
        replayed_flow_id=str(uuid.uuid4()),
        original_status=200,
        replay_status=200,
        diff_verdict="SAME",
        auth_session_verdict=VERDICT_WEAK_VALIDATION,
        test_id="jwt.alg_none",
        binding_id=binding.id,
        candidate_id=cand.id,
        auth_type="jwt",
        endpoint_id=EP,
        failure_reason=None,
    )
    sched._settle_auth_session_outcome(job, outcome)

    cand2 = as_db.get_candidate(db_path, cand.id)
    assert cand2 is not None
    assert cand2.status == STATUS_DONE

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT status, verdict FROM scheduler_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
    assert row[0] == "done"
    assert row[1] == VERDICT_WEAK_VALIDATION
