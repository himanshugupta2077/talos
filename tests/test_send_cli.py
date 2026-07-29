"""
Light CLI tests for talos send (from / once / history / diff / show).
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

from talos.projects.db import init_project_db
from talos.send.cli import run_send_cli


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id="proj")
    m = MagicMock()
    m.active.return_value = project
    return m


def _insert_capture(db_path: Path) -> str:
    fid = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                role_id, module_id, source
            ) VALUES (
                ?, 'proj', '2020-01-01T00:00:00+00:00',
                'GET', 'https://ex.test/a', 'ex.test', '/a', '',
                ?, '{}', NULL, 0, 200, '{}', ?, 0, 'text/plain',
                ?, ?, 'proxy_capture'
            )
            """,
            (
                fid,
                json.dumps({"Host": "ex.test", "Accept": "*/*"}),
                b"hello",
                role,
                mod,
            ),
        )
        conn.commit()
    return fid


def test_send_from_writes_raw_file(manager: MagicMock, db_path: Path, tmp_path: Path) -> None:
    fid = _insert_capture(db_path)
    out = tmp_path / "req.http"
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(manager, ["from", fid, "--raw-out", str(out), "--format", "json"])
    data = json.loads(buf.getvalue())
    assert data["parent_flow_id"] == fid
    assert out.is_file()
    raw = out.read_bytes()
    assert raw.startswith(b"GET /a HTTP/1.1") or b"GET /a" in raw
    assert b"Host:" in raw or b"Host: " in raw


def test_send_once_json_and_history(
    manager: MagicMock, db_path: Path
) -> None:
    fid = _insert_capture(db_path)

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {"content-type": "text/plain"}
        client.request = AsyncMock(return_value=resp)
        client_cls.return_value = client

        buf = io.StringIO()
        with redirect_stdout(buf):
            run_send_cli(
                manager,
                [
                    "once",
                    fid,
                    "--header",
                    "X-Test: 1",
                    "--format",
                    "json",
                ],
            )
        once = json.loads(buf.getvalue())
        assert once["parent_flow_id"] == fid
        assert once["original_flow_id"] == fid
        assert once["execution_flow_id"]
        assert once["status_code"] == 200

        # Second send for history
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            run_send_cli(
                manager,
                ["once", once["execution_flow_id"], "--source", "ai_send", "--format", "json"],
            )
        once2 = json.loads(buf2.getvalue())
        assert once2["original_flow_id"] == fid

    buf_h = io.StringIO()
    with redirect_stdout(buf_h):
        run_send_cli(
            manager,
            ["history", "--from", fid, "--format", "json"],
        )
    hist = json.loads(buf_h.getvalue())
    assert hist["count"] == 2
    assert hist["original_flow_id"] == fid


def test_send_diff_json(manager: MagicMock, db_path: Path) -> None:
    a = _insert_capture(db_path)
    # Insert a second flow with different status via engine mock.
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        resp = MagicMock()
        resp.status_code = 500
        resp.content = b"err"
        resp.headers = {"content-type": "text/plain"}
        client.request = AsyncMock(return_value=resp)
        client_cls.return_value = client

        buf = io.StringIO()
        with redirect_stdout(buf):
            run_send_cli(manager, ["once", a, "--format", "json"])
        once = json.loads(buf.getvalue())

    buf_d = io.StringIO()
    with redirect_stdout(buf_d):
        run_send_cli(
            manager,
            ["diff", a, once["execution_flow_id"], "--format", "json"],
        )
    diff = json.loads(buf_d.getvalue())
    assert diff["verdict"] == "DIFFERENT"
    assert diff["status_b"] == 500


def test_send_show(manager: MagicMock, db_path: Path) -> None:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(manager, ["show", fid, "--format", "json"])
    data = json.loads(buf.getvalue())
    assert data["id"] == fid
    assert data["method"] == "GET"
