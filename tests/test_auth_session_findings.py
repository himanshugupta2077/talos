"""
Tests: auth-session Phase 4 findings bridge + creator integration.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import talos.findings.db as findings_db
from talos.auth_session import db as as_db
from talos.auth_session.findings_bridge import (
    build_finding_title,
    maybe_create_auth_session_finding,
)
from talos.auth_session.models import (
    STATUS_APPROVED,
    STATUS_RUNNING,
    VERDICT_SECURE,
    VERDICT_WEAK_VALIDATION,
)
from talos.findings.model import (
    ATTACK_DISPLAY,
    EVIDENCE_TYPE_AUTH_SESSION_RESULT,
    FINDING_STATUS_TRIAGING,
    RELATION_TYPE_LINKED,
    RELATION_TYPE_PRIMARY,
    VERDICT_TRIGGERS,
)
from talos.projects.db import init_project_db
from talos.scheduler.job import AUTH_SESSION_ATTACK, ReplayJob
from talos.scheduler.scheduler import ReplayScheduler
import talos.scheduler.db as sched_db

PROJECT_ID = "proj-find"
EP = "ep-find"
FLOW = "flow-find"
NOW = "2026-01-01T00:00:00+00:00"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
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
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', '{}', '{}', 200,
                    '{}', ?, 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (FLOW, PROJECT_ID, NOW, b'{"ok":true}', EP),
        )
        conn.commit()
    return path


def _seed_replay(db_path: Path) -> str:
    replay_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source, original_flow_id)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', '{}', '{}', 200,
                    '{}', ?, 'application/json', ?, '', '', '[]', 'auto_replay', ?)
            """,
            (replay_id, PROJECT_ID, NOW, b'{"ok":true}', EP, FLOW),
        )
        conn.commit()
    return replay_id


def test_verdict_triggers_and_display() -> None:
    assert VERDICT_TRIGGERS["auth_session"] == frozenset({"WEAK_VALIDATION"})
    assert ATTACK_DISPLAY["auth_session"] == "Authentication & Session Testing"


def test_build_cluster_key_auth_session() -> None:
    key = findings_db.build_cluster_key(
        "auth_session", EP, auth_type="jwt"
    )
    assert key == f"AUTH_SESSION:{EP}:jwt"
    key2 = findings_db.build_cluster_key("auth_session", EP)
    assert key2 == f"AUTH_SESSION:{EP}:unknown"


def test_title_formula() -> None:
    title = build_finding_title(
        test_id="jwt.alg_none", method="GET", path="/api/me"
    )
    assert title == (
        "Authentication & Session Testing — jwt.alg_none on GET /api/me"
    )


def test_maybe_create_finding_weak(db_path: Path) -> None:
    replay_id = _seed_replay(db_path)
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
        title="alg none",
        mutation_summary="alg=none",
        endpoint_id=EP,
        risk_hint="critical",
    )
    as_db.insert_result(
        db_path,
        replay_flow_id=replay_id,
        original_flow_id=FLOW,
        candidate_id=cand.id,
        binding_id=binding.id,
        auth_type="jwt",
        test_id="jwt.alg_none",
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        diff_verdict="SAME",
        mutation_summary="alg=none",
    )

    fid = maybe_create_auth_session_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        original_flow_id=FLOW,
        replayed_flow_id=replay_id,
        test_id="jwt.alg_none",
        auth_type="jwt",
        job_id=None,
        diff_verdict="SAME",
        risk_hint="critical",
        mutation_summary="alg=none",
        candidate_id=cand.id,
        binding_id=binding.id,
    )
    assert fid is not None
    finding = findings_db.get_finding(db_path, fid)
    assert finding is not None
    assert finding["status"] == FINDING_STATUS_TRIAGING
    assert finding["attack_type"] == "auth_session"
    assert finding["verdict"] == VERDICT_WEAK_VALIDATION
    assert finding["relation_type"] == RELATION_TYPE_PRIMARY
    assert finding["cluster_key"] == f"AUTH_SESSION:{EP}:jwt"
    assert finding["title"] == (
        "Authentication & Session Testing — jwt.alg_none on GET /api/me"
    )
    assert "WEAK_VALIDATION (jwt.alg_none)" not in finding["title"]

    evidence = findings_db.list_evidence(db_path, fid)
    types = {e["evidence_type"] for e in evidence}
    assert EVIDENCE_TYPE_AUTH_SESSION_RESULT in types
    assert "original_flow" in types
    assert "replay_flow" in types


def test_maybe_create_finding_secure_noop(db_path: Path) -> None:
    replay_id = _seed_replay(db_path)
    fid = maybe_create_auth_session_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        verdict=VERDICT_SECURE,
        endpoint_id=EP,
        original_flow_id=FLOW,
        replayed_flow_id=replay_id,
        test_id="jwt.alg_none",
        auth_type="jwt",
    )
    assert fid is None
    assert findings_db.list_findings(db_path, PROJECT_ID) == []


def test_cluster_primary_linked(db_path: Path) -> None:
    r1 = _seed_replay(db_path)
    r2 = _seed_replay(db_path)
    f1 = maybe_create_auth_session_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        original_flow_id=FLOW,
        replayed_flow_id=r1,
        test_id="jwt.alg_none",
        auth_type="jwt",
        diff_verdict="SAME",
    )
    f2 = maybe_create_auth_session_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        original_flow_id=FLOW,
        replayed_flow_id=r2,
        test_id="jwt.invalid_signature",
        auth_type="jwt",
        diff_verdict="SAME",
    )
    assert f1 and f2
    p = findings_db.get_finding(db_path, f1)
    c = findings_db.get_finding(db_path, f2)
    assert p["relation_type"] == RELATION_TYPE_PRIMARY
    assert c["relation_type"] == RELATION_TYPE_LINKED
    assert c["parent_finding_id"] == f1
    assert p["cluster_key"] == c["cluster_key"]


def test_scheduler_settle_creates_finding(db_path: Path) -> None:
    from talos.auth_session.models import AuthSessionOutcome

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
        risk_hint="critical",
    )
    as_db.mark_candidate_running(db_path, cand.id)
    replay_id = _seed_replay(db_path)
    as_db.insert_result(
        db_path,
        replay_flow_id=replay_id,
        original_flow_id=FLOW,
        candidate_id=cand.id,
        binding_id=binding.id,
        auth_type="jwt",
        test_id="jwt.alg_none",
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        diff_verdict="SAME",
    )

    project = SimpleNamespace(id=PROJECT_ID, db_path=db_path)
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
        replayed_flow_id=replay_id,
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
    assert cand2.status == "done"
    findings = findings_db.list_findings(db_path, PROJECT_ID)
    assert len(findings) == 1
    assert findings[0]["verdict"] == VERDICT_WEAK_VALIDATION
    assert findings[0]["attack_type"] == "auth_session"


def test_report_includes_auth_session_result(db_path: Path) -> None:
    from talos.findings.report import generate_finding_report

    replay_id = _seed_replay(db_path)
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
        mutation_summary="alg=none strip sig",
        endpoint_id=EP,
    )
    as_db.insert_result(
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
        mutation_summary="alg=none strip sig",
        diff_verdict="SAME",
    )
    fid = maybe_create_auth_session_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        verdict=VERDICT_WEAK_VALIDATION,
        endpoint_id=EP,
        original_flow_id=FLOW,
        replayed_flow_id=replay_id,
        test_id="jwt.alg_none",
        auth_type="jwt",
        diff_verdict="SAME",
    )
    assert fid
    report = generate_finding_report(db_path, fid)
    assert "Authentication & Session Testing" in report
    assert "jwt.alg_none" in report
    assert "WEAK_VALIDATION" in report
