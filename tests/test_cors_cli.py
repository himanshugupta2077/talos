"""CLI tests for talos attack cors (enqueue unique jobs, no HTTP)."""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.cors.cli import cmd_run, cmd_techniques
from talos.projects.db import init_project_db
from talos.scheduler.job import CORS_ATTACK

PROJECT_ID = "proj-cli"
EP = "ep-cli"
FLOW = "flow-cli"
NOW = "2026-01-01T00:00:00+00:00"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'https://app.example.com', '/ok', '/ok',
                    'application/json', 0, '[]', ?, ?)
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
                 query, request_headers, status_code, endpoint_id,
                 role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://app.example.com/ok',
                    'app.example.com', '/ok', '', '{}', 200, ?,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (FLOW, PROJECT_ID, NOW, EP, role, module),
        )
        conn.commit()
    return path


def _manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(
        db_path=db_path,
        id=PROJECT_ID,
        scope=["https://app.example.com"],
    )
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def test_techniques_json() -> None:
    manager = MagicMock()
    args = SimpleNamespace(output_format="json")
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_techniques(manager, args)
    data = json.loads(buf.getvalue())
    names = {row["name"] for row in data}
    assert "arbitrary_https" in names
    assert "preflight" in names


def test_run_enqueues_one_job_per_technique(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="arbitrary_https",
        limit=10,
        endpoint=None,
        host=None,
        right_now=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["mode"] == "enqueue"
    assert payload["jobs_enqueued"] == 1
    assert payload["jobs"][0]["technique"] == "arbitrary_https"
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT job_type, flow_id, meta FROM scheduler_jobs"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == CORS_ATTACK
    assert rows[0][1] == FLOW
    meta = json.loads(rows[0][2])
    assert meta["origin_sent"].endswith(".invalid")
    assert meta["attacker_controlled"] is True


def test_run_explicit_flow_only(db_path: Path) -> None:
    extra = "flow-other"
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, status_code, endpoint_id,
                 role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'POST', 'https://app.example.com/other',
                    'app.example.com', '/other', '', '{}', 200, NULL,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (extra, PROJECT_ID, NOW, role, module),
        )
        conn.commit()
    args = SimpleNamespace(
        technique="arbitrary_https",
        limit=10,
        endpoint=None,
        host=None,
        flows=[extra],
        right_now=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["candidates"] == 1
    assert payload["jobs"][0]["flow_id"] == extra
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute("SELECT flow_id FROM scheduler_jobs").fetchall()
    assert [r[0] for r in rows] == [extra]


def test_run_unknown_flow_exits(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="arbitrary_https",
        limit=10,
        endpoint=None,
        host=None,
        flows=["missing-flow"],
        right_now=False,
        output_format="json",
    )
    with pytest.raises(SystemExit):
        cmd_run(_manager(db_path), args)


def test_run_dedups_pending(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="null_origin",
        limit=10,
        endpoint=None,
        host=None,
        right_now=False,
        output_format="json",
    )
    manager = _manager(db_path)
    with redirect_stdout(io.StringIO()):
        cmd_run(manager, args)
        cmd_run(manager, args)
    with sqlite3.connect(str(db_path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM scheduler_jobs WHERE job_type = ?",
            (CORS_ATTACK,),
        ).fetchone()[0]
    assert n == 1
