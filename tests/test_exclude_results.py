"""Exclude-results purge + scheduler resume skip of excluded endpoints."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.burp.snapshot import finding_record_id, load_records, record_request
from talos.burp.trace import ENGINE_UNAUTH, BurpTrace
from talos.findings.db import add_evidence, create_finding, get_finding
from talos.projects.db import init_project_db
from talos.projects.exclude_results import (
    ExcludeResultsError,
    exclude_and_purge,
    skip_excluded_queue_jobs,
)
from talos.projects.policy import get_effective_policy, set_excluded, set_path_rule
from talos.scheduler import db as sched_db
from talos.scheduler.cli import cmd_resume
from talos.scheduler.job import REPLAY_ENDPOINT, REPLAY_FLOW, STATUS_PAUSED, STATUS_PENDING

PROJECT_ID = "proj-excl"
EP_USERS = "ep-users"
EP_STATIC = "ep-static"
EP_OTHER = "ep-other"
FLOW_USERS = "flow-users"
FLOW_STATIC = "flow-static"
NOW = "2026-01-01T00:00:00+00:00"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


@pytest.fixture()
def project(db_path: Path) -> SimpleNamespace:
    return SimpleNamespace(db_path=db_path, id=PROJECT_ID)


def _seed(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.executemany(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, 'application/json', 1, '[]', ?, ?)
            """,
            [
                (EP_USERS, PROJECT_ID, "GET", "https://api.example.com",
                 "/api/users", "/api/users", NOW, NOW),
                (EP_STATIC, PROJECT_ID, "GET", "https://api.example.com",
                 "/static/app.js", "/static/app.js", NOW, NOW),
                (EP_OTHER, PROJECT_ID, "POST", "https://api.example.com",
                 "/api/orders", "/api/orders", NOW, NOW),
            ],
        )
        for eid in (EP_USERS, EP_STATIC, EP_OTHER):
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, auto_breakdown,
                     excluded, dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', 40, '{}', 0, 0, 0, 1, 'flow_2xx', NULL, 200, ?)
                """,
                (eid, NOW),
            )
        for fid, path, eid in (
            (FLOW_USERS, "/api/users", EP_USERS),
            (FLOW_STATIC, "/static/app.js", EP_STATIC),
        ):
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source)
                VALUES (?, ?, ?, 'GET', ?, 'api.example.com', ?, '', '{}', 200,
                        ?, ?, ?, '[]', 'proxy_capture')
                """,
                (
                    fid, PROJECT_ID, NOW,
                    f"https://api.example.com{path}", path, eid, role, module,
                ),
            )
        conn.commit()


def _enqueue(
    db_path: Path,
    *,
    endpoint_id: str | None = None,
    flow_id: str | None = None,
    status: str = STATUS_PENDING,
    job_type: str = REPLAY_ENDPOINT,
) -> str:
    jid = str(uuid.uuid4())
    sched_db.enqueue_job(
        db_path,
        jid,
        job_type,
        PROJECT_ID,
        endpoint_id=endpoint_id,
        flow_id=flow_id,
    )
    if status != STATUS_PENDING:
        with sched_db._connect_rw(db_path) as conn:
            conn.execute(
                "UPDATE scheduler_jobs SET status = ? WHERE job_id = ?",
                (status, jid),
            )
            conn.commit()
    return jid


def _trace(project_id: str, path: str, record_id: str, endpoint_id: str) -> BurpTrace:
    return BurpTrace(
        engine=ENGINE_UNAUTH,
        group="endpoints",
        endpoint_label=f"GET {path}",
        host="api.example.com",
        endpoint_id=endpoint_id,
        extras={},
        project_id=project_id,
        project_name=project_id,
        record_id=record_id,
    )


# ------------------------------------------------------------------ #
# Resume skip                                                          #
# ------------------------------------------------------------------ #


def test_skip_excluded_queue_jobs_endpoint_flag(db_path: Path) -> None:
    keep = _enqueue(db_path, endpoint_id=EP_OTHER)
    drop = _enqueue(db_path, endpoint_id=EP_USERS, status=STATUS_PAUSED)
    set_excluded(db_path, EP_USERS, True)
    skipped = skip_excluded_queue_jobs(db_path, PROJECT_ID)
    assert skipped == 1
    dropped = sched_db.get_job(db_path, PROJECT_ID, drop)
    kept = sched_db.get_job(db_path, PROJECT_ID, keep)
    assert dropped is not None and dropped.status == "skipped"
    assert dropped.failure_reason == "endpoint_excluded"
    assert kept is not None and kept.status == STATUS_PENDING


def test_skip_excluded_queue_jobs_path_rule(db_path: Path) -> None:
    drop = _enqueue(db_path, endpoint_id=EP_STATIC)
    keep = _enqueue(db_path, endpoint_id=EP_USERS)
    set_path_rule(db_path, PROJECT_ID, "/static/*", excluded=True)
    skipped = skip_excluded_queue_jobs(db_path, PROJECT_ID)
    assert skipped == 1
    assert sched_db.get_job(db_path, PROJECT_ID, drop).status == "skipped"
    assert sched_db.get_job(db_path, PROJECT_ID, keep).status == STATUS_PENDING


def test_skip_excluded_via_flow_id_only(db_path: Path) -> None:
    drop = _enqueue(
        db_path, flow_id=FLOW_USERS, endpoint_id=None, job_type=REPLAY_FLOW
    )
    set_excluded(db_path, EP_USERS, True)
    assert skip_excluded_queue_jobs(db_path, PROJECT_ID) == 1
    assert sched_db.get_job(db_path, PROJECT_ID, drop).status == "skipped"


def test_resume_skips_excluded_then_resumes_rest(
    project: SimpleNamespace, db_path: Path
) -> None:
    drop = _enqueue(db_path, endpoint_id=EP_USERS, status=STATUS_PAUSED)
    keep = _enqueue(db_path, endpoint_id=EP_OTHER, status=STATUS_PAUSED)
    set_excluded(db_path, EP_USERS, True)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_resume(project)
    out = buf.getvalue()
    assert "Scheduler resumed." in out
    assert "Excluded jobs skipped    : 1" in out
    assert "Jobs returned to pending : 1" in out
    assert sched_db.get_job(db_path, PROJECT_ID, drop).status == "skipped"
    assert sched_db.get_job(db_path, PROJECT_ID, keep).status == STATUS_PENDING
    assert sched_db.get_scheduler_state(db_path) == sched_db.SCHED_STATE_RUNNING


# ------------------------------------------------------------------ #
# exclude_and_purge                                                    #
# ------------------------------------------------------------------ #


def test_exclude_results_endpoint_purges_jobs_findings_burp(
    db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    job = _enqueue(db_path, endpoint_id=EP_USERS)
    keep_job = _enqueue(db_path, endpoint_id=EP_OTHER)
    fid = create_finding(
        db_path, PROJECT_ID, "unauth", "BYPASS", EP_USERS, "users bypass"
    )
    keep_fid = create_finding(
        db_path, PROJECT_ID, "unauth", "BYPASS", EP_OTHER, "orders bypass"
    )
    add_evidence(db_path, fid, "original_flow", FLOW_USERS, "orig")
    record_request(
        _trace(PROJECT_ID, "/api/users", "rec-users", EP_USERS),
        method="GET",
        host="api.example.com",
        path="/api/users",
        url="https://api.example.com/api/users",
    )
    record_request(
        _trace(PROJECT_ID, "/api/orders", "rec-orders", EP_OTHER),
        method="POST",
        host="api.example.com",
        path="/api/orders",
        url="https://api.example.com/api/orders",
    )
    record_request(
        _trace(PROJECT_ID, "/api/users", finding_record_id(fid), "unauth"),
        method="GET",
        host="api.example.com",
        path="/api/users",
        url="https://api.example.com/api/users",
    )

    outcome = exclude_and_purge(db_path, PROJECT_ID, "endpoint", EP_USERS)
    assert outcome.endpoints_excluded == 1
    assert outcome.jobs_skipped == 1
    assert outcome.findings_deleted == 1
    assert outcome.burp_records_removed >= 1
    policy = get_effective_policy(db_path, PROJECT_ID, EP_USERS, "/api/users")
    assert policy.excluded is True
    assert sched_db.get_job(db_path, PROJECT_ID, job).status == "skipped"
    assert sched_db.get_job(db_path, PROJECT_ID, keep_job).status == STATUS_PENDING
    assert get_finding(db_path, fid) is None
    assert get_finding(db_path, keep_fid) is not None
    remaining = {r["record_id"] for r in load_records(PROJECT_ID)}
    assert "rec-users" not in remaining
    assert "rec-orders" in remaining
    assert finding_record_id(fid) not in remaining


def test_exclude_results_path_adds_rule_and_purges(db_path: Path) -> None:
    job = _enqueue(db_path, endpoint_id=EP_STATIC)
    keep = _enqueue(db_path, endpoint_id=EP_USERS)
    fid = create_finding(
        db_path, PROJECT_ID, "xss", "XSS", EP_STATIC, "static xss"
    )
    outcome = exclude_and_purge(db_path, PROJECT_ID, "path", "/static/*")
    assert outcome.path_rule_id
    assert outcome.jobs_skipped == 1
    assert outcome.findings_deleted == 1
    assert get_effective_policy(
        db_path, PROJECT_ID, EP_STATIC, "/static/app.js"
    ).excluded is True
    assert get_effective_policy(
        db_path, PROJECT_ID, EP_USERS, "/api/users"
    ).excluded is False
    assert sched_db.get_job(db_path, PROJECT_ID, job).status == "skipped"
    assert sched_db.get_job(db_path, PROJECT_ID, keep).status == STATUS_PENDING
    assert get_finding(db_path, fid) is None


def test_exclude_results_regex(db_path: Path) -> None:
    job = _enqueue(db_path, endpoint_id=EP_STATIC)
    outcome = exclude_and_purge(db_path, PROJECT_ID, "regex", r"^/static/")
    assert EP_STATIC in outcome.endpoint_ids
    assert EP_USERS not in outcome.endpoint_ids
    assert outcome.jobs_skipped == 1
    assert sched_db.get_job(db_path, PROJECT_ID, job).status == "skipped"


CHUNK_RE = r'https?:\/\/[^\s"\'<>]*\/chunk-[A-Z0-9]+\.js'
EP_CHUNK = "ep-chunk"
EP_CHUNK_DOT = "ep-chunk-dot"


def _seed_chunk_endpoints(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', ?, ?, ?, 'application/javascript', 0, '[]', ?, ?)
            """,
            [
                (EP_CHUNK, PROJECT_ID, "https://uat-1-tap.charter.com",
                 "/tap-ui/chunk-ZOPPBF22.js", "/tap-ui/chunk-ZOPPBF22.js",
                 NOW, NOW),
                (EP_CHUNK_DOT, PROJECT_ID, "https://uat-1-tap.charter.com",
                 "/tap-ui/./chunk-GO5FZXLI.js", "/tap-ui/./chunk-GO5FZXLI.js",
                 NOW, NOW),
            ],
        )
        for eid in (EP_CHUNK, EP_CHUNK_DOT):
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, auto_breakdown,
                     excluded, dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'LOW', 0, '{}', 0, 0, 0, 1, 'flow_2xx', NULL, 200, ?)
                """,
                (eid, NOW),
            )
        conn.commit()


def test_exclude_results_url_regex_matches_chunk_js(
    db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """URL-shaped regex must match path-only endpoints and ./chunk URLs."""
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    _seed_chunk_endpoints(db_path)
    fid = create_finding(
        db_path, PROJECT_ID, "passive", "SECRET", EP_CHUNK, "chunk secret"
    )
    fid_dot = create_finding(
        db_path, PROJECT_ID, "passive", "SECRET", EP_CHUNK_DOT, "dot chunk"
    )
    keep = create_finding(
        db_path, PROJECT_ID, "unauth", "BYPASS", EP_USERS, "keep me"
    )
    add_evidence(
        db_path, fid, "source_occurrence", None, "occ",
        {"url": "https://uat-1-tap.charter.com/tap-ui/chunk-ZOPPBF22.js"},
    )
    record_request(
        _trace(PROJECT_ID, "/tap-ui/chunk-ZOPPBF22.js", "rec-chunk", EP_CHUNK),
        method="GET",
        host="uat-1-tap.charter.com",
        path="/tap-ui/chunk-ZOPPBF22.js",
        url="https://uat-1-tap.charter.com/tap-ui/chunk-ZOPPBF22.js",
    )
    record_request(
        _trace(PROJECT_ID, "/tap-ui/./chunk-GO5FZXLI.js", "rec-dot", EP_CHUNK_DOT),
        method="GET",
        host="uat-1-tap.charter.com",
        path="/tap-ui/./chunk-GO5FZXLI.js",
        url="https://uat-1-tap.charter.com/tap-ui/./chunk-GO5FZXLI.js",
    )
    record_request(
        _trace(PROJECT_ID, "/api/users", "rec-keep", EP_USERS),
        method="GET",
        host="api.example.com",
        path="/api/users",
        url="https://api.example.com/api/users",
    )

    outcome = exclude_and_purge(db_path, PROJECT_ID, "regex", CHUNK_RE)
    assert EP_CHUNK in outcome.endpoint_ids
    assert EP_CHUNK_DOT in outcome.endpoint_ids
    assert EP_USERS not in outcome.endpoint_ids
    assert outcome.findings_deleted >= 2
    assert get_finding(db_path, fid) is None
    assert get_finding(db_path, fid_dot) is None
    assert get_finding(db_path, keep) is not None
    remaining = {r["record_id"] for r in load_records(PROJECT_ID)}
    assert "rec-chunk" not in remaining
    assert "rec-dot" not in remaining
    assert "rec-keep" in remaining


def test_exclude_results_url_regex_matches_evidence_url_only(db_path: Path) -> None:
    """Passive findings with a URL in evidence and no matching endpoint path."""
    fid = create_finding(
        db_path, PROJECT_ID, "passive", "SECRET", None, "orphan chunk"
    )
    add_evidence(
        db_path, fid, "source_occurrence", None, "occ",
        {"url": "https://uat-1-tap.charter.com/tap-ui/chunk-AAAA1111.js"},
    )
    keep = create_finding(
        db_path, PROJECT_ID, "unauth", "BYPASS", EP_USERS, "keep"
    )
    outcome = exclude_and_purge(db_path, PROJECT_ID, "regex", CHUNK_RE)
    assert outcome.findings_deleted == 1
    assert get_finding(db_path, fid) is None
    assert get_finding(db_path, keep) is not None


def test_exclude_results_flow(db_path: Path) -> None:
    job = _enqueue(db_path, flow_id=FLOW_USERS, job_type=REPLAY_FLOW)
    fid = create_finding(
        db_path, PROJECT_ID, "unauth", "BYPASS", EP_USERS, "via flow"
    )
    add_evidence(db_path, fid, "original_flow", FLOW_USERS, "orig")
    outcome = exclude_and_purge(db_path, PROJECT_ID, "flow", FLOW_USERS)
    assert EP_USERS in outcome.endpoint_ids
    assert outcome.jobs_skipped == 1
    assert outcome.findings_deleted == 1
    assert get_finding(db_path, fid) is None


def test_exclude_results_unknown_flow(db_path: Path) -> None:
    with pytest.raises(ExcludeResultsError, match="not found"):
        exclude_and_purge(db_path, PROJECT_ID, "flow", "missing-flow")


def test_exclude_results_bad_regex(db_path: Path) -> None:
    with pytest.raises(ExcludeResultsError, match="Invalid regex"):
        exclude_and_purge(db_path, PROJECT_ID, "regex", "[")


def test_cli_exclude_results_json(project: SimpleNamespace, db_path: Path) -> None:
    from talos.projects.endpoint_cli import cmd_exclude_results

    _enqueue(db_path, endpoint_id=EP_USERS)
    args = argparse.Namespace(
        excl_results_target="endpoint",
        endpoint_ids=[EP_USERS],
        force=True,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_exclude_results(project, args)
    data = json.loads(buf.getvalue())
    assert data["action"] == "exclude-results"
    assert data["kind"] == "endpoint"
    assert data["jobs_skipped"] == 1
    assert data["endpoints_excluded"] == 1


def test_cli_exclude_results_parser(project: SimpleNamespace, db_path: Path) -> None:
    from talos.projects.endpoint_cli import run_endpoint_cli

    manager = MagicMock()
    manager.active.return_value = project
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_endpoint_cli(
            manager,
            ["exclude-results", "path", "/static/*", "--force", "--format", "json"],
        )
    data = json.loads(buf.getvalue())
    assert data["kind"] == "path"
    assert data["path_rule_id"]
