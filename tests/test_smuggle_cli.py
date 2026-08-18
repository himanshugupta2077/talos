"""CLI tests for talos attack smuggle (enqueue unique jobs, no HTTP)."""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.scheduler.job import JOB_TYPES, SMUGGLE_ATTACK
from talos.smuggle.cli import cmd_run, cmd_techniques
from talos.smuggle.models import TECHNIQUE_NAMES

PROJECT_ID = "proj-smuggle-cli"
EP = "ep-smuggle-cli"
FLOW = "flow-smuggle-cli"
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
                    'text/html', 0, '[]', ?, ?)
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


def test_job_type_registered() -> None:
    assert SMUGGLE_ATTACK == "smuggle_attack"
    assert SMUGGLE_ATTACK in JOB_TYPES


def test_techniques_json() -> None:
    manager = MagicMock()
    args = SimpleNamespace(output_format="json")
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_techniques(manager, args)
    data = json.loads(buf.getvalue())
    names = {row["name"] for row in data}
    assert "cl_te" in names
    assert "te_cl" in names
    assert "cl_cl" in names
    assert names == set(TECHNIQUE_NAMES)


def test_run_requires_flow(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="cl_te",
        flows=None,
        right_now=False,
        output_format="json",
    )
    with pytest.raises(SystemExit):
        cmd_run(_manager(db_path), args)


def test_run_enqueues_one_job_per_technique(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="cl_te",
        flows=[FLOW],
        right_now=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["mode"] == "enqueue"
    assert payload["jobs_enqueued"] == 1
    assert payload["jobs"][0]["technique"] == "cl_te"
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT job_type, flow_id, meta FROM scheduler_jobs"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == SMUGGLE_ATTACK
    assert rows[0][1] == FLOW
    meta = json.loads(rows[0][2])
    assert meta["technique"] == "cl_te"
    assert meta["canary_path"].startswith("/talos-hrs-")


def test_run_all_techniques(db_path: Path) -> None:
    args = SimpleNamespace(
        technique=None,
        flows=[FLOW],
        right_now=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["jobs_enqueued"] == len(TECHNIQUE_NAMES)
