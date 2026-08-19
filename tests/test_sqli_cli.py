"""CLI tests for talos attack sqli (enqueue unique jobs, no HTTP)."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.scheduler.db import enqueue_job, get_next_pending
from talos.scheduler.job import CORS_ATTACK, PRIORITY_HIGH, PRIORITY_MANUAL, SQLI_ATTACK
from talos.sqli.cli import build_sqli_parser, cmd_run, cmd_techniques

PROJECT_ID = "proj-sqli-cli"
EP = "ep-sqli-cli"
FLOW = "flow-sqli-cli"
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
            VALUES (?, ?, 'POST', 'https://app.example.com', '/api/n', '/api/n',
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
                 query, request_headers, request_body, status_code,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'POST',
                    'https://app.example.com/api/n',
                    'app.example.com', '/api/n', '', ?, ?, 200, ?,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Content-Type": "application/json"}),
                b'["test","test","info","111111-11-11T11:11"]',
                EP,
                role,
                module,
            ),
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


def test_run_parser_accepts_db_and_param() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_sqli_parser(sub)
    args = parser.parse_args(
        [
            "sqli",
            "run",
            "--flow",
            FLOW,
            "--db",
            "mssql",
            "--param",
            "id",
            "--parameter",
            "body:user.id",
        ]
    )
    assert args.db == "mssql"
    assert args.params == ["id", "body:user.id"]


def test_techniques_json() -> None:
    manager = MagicMock()
    args = SimpleNamespace(output_format="json")
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_techniques(manager, args)
    data = json.loads(buf.getvalue())
    names = {row["name"] for row in data}
    assert "quote_single" in names
    assert "mssql_waitfor" in names
    assert "union_1" in names


def test_run_requires_flow(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=None,
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    with pytest.raises(SystemExit):
        cmd_run(_manager(db_path), args)


def test_run_enqueues_one_job_per_point(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["mode"] == "enqueue"
    assert payload["entry_points"] == 4
    # unknown --technique quote_single expands to raw + 3 encodings
    assert payload["jobs_enqueued"] == 16
    assert payload["priority"] == PRIORITY_HIGH
    assert payload["high_priority"] is True
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT job_type, flow_id, meta, priority FROM scheduler_jobs ORDER BY created_at"
        ).fetchall()
    assert len(rows) == 16
    assert {r[0] for r in rows} == {SQLI_ATTACK}
    assert {r[1] for r in rows} == {FLOW}
    assert {r[3] for r in rows} == {PRIORITY_HIGH}
    params = {json.loads(r[2])["param_name"] for r in rows}
    assert params == {"[0]", "[1]", "[2]", "[3]"}
    techs = {json.loads(r[2])["technique"] for r in rows}
    assert techs == {
        "quote_single",
        "quote_single__url",
        "quote_single__double_url",
        "quote_single__unicode",
    }
    raw = next(
        json.loads(r[2]) for r in rows if json.loads(r[2])["technique"] == "quote_single"
    )
    assert raw["payload_sent"] == "'"


def test_run_unknown_flow_exits(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=["missing-flow"],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    with pytest.raises(SystemExit):
        cmd_run(_manager(db_path), args)


def test_run_dedups_pending(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    manager = _manager(db_path)
    with redirect_stdout(io.StringIO()):
        cmd_run(manager, args)
        cmd_run(manager, args)
    with sqlite3.connect(str(db_path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM scheduler_jobs WHERE job_type = ?",
            (SQLI_ATTACK,),
        ).fetchone()[0]
    assert n == 16


def test_run_no_high_priority_uses_manual(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=[FLOW],
        right_now=False,
        high_priority=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["priority"] == PRIORITY_MANUAL
    assert payload["high_priority"] is False
    with sqlite3.connect(str(db_path)) as conn:
        prios = {
            row[0]
            for row in conn.execute("SELECT priority FROM scheduler_jobs")
        }
    assert prios == {PRIORITY_MANUAL}


def test_high_priority_sqli_runs_before_older_manual_jobs(db_path: Path) -> None:
    enqueue_job(
        db_path=db_path,
        job_id="old-cors",
        job_type=CORS_ATTACK,
        project_id=PROJECT_ID,
        flow_id=FLOW,
        priority=PRIORITY_MANUAL,
        meta="{}",
    )
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    with redirect_stdout(io.StringIO()):
        cmd_run(_manager(db_path), args)
    nxt = get_next_pending(db_path, PROJECT_ID)
    assert nxt is not None
    assert nxt.job_type == SQLI_ATTACK
    assert nxt.priority == PRIORITY_HIGH
    assert nxt.job_id != "old-cors"


def test_run_param_restricts_entry_points(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        db="mssql",
        params=["[3]"],
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["entry_points"] == 1
    assert payload["jobs_enqueued"] == 1
    assert payload["params"] == ["[3]"]
    with sqlite3.connect(str(db_path)) as conn:
        metas = [
            json.loads(row[0])
            for row in conn.execute("SELECT meta FROM scheduler_jobs")
        ]
    assert [row["param_name"] for row in metas] == ["[3]"]


def test_run_missing_param_exits(db_path: Path) -> None:
    args = SimpleNamespace(
        technique="quote_single",
        family=None,
        db="unknown",
        params=["not-a-field"],
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    with pytest.raises(SystemExit):
        cmd_run(_manager(db_path), args)


def test_run_db_mssql_skips_mysql_payloads(db_path: Path) -> None:
    args = SimpleNamespace(
        technique=None,
        family="time",
        db="mssql",
        params=None,
        flows=[FLOW],
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(_manager(db_path), args)
    payload = json.loads(buf.getvalue())
    assert payload["db"] == "mssql"
    assert payload["entry_points"] == 4
    techs = {job["technique"] for job in payload["jobs"]}
    assert "mssql_waitfor" in techs
    assert "mssql_waitfor_if" in techs
    assert "mysql_sleep" not in techs
    assert "pg_sleep" not in techs
