"""
Light CLI tests for talos send (Phase 1 + Phase 2 verbs).
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
from talos.send.raw_http import parse_request


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


def _mock_httpx(status: int = 200, body: bytes = b"ok") -> MagicMock:
    client_cls = MagicMock()
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = {"content-type": "text/plain"}
    client.request = AsyncMock(return_value=resp)
    client_cls.return_value = client
    return client_cls


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
    assert "request" in diff
    assert "response" in diff
    assert diff["side"] == "both"


def test_send_show(manager: MagicMock, db_path: Path) -> None:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(manager, ["show", fid, "--format", "json"])
    data = json.loads(buf.getvalue())
    assert data["id"] == fid
    assert data["method"] == "GET"


def test_send_dup_and_session_history(manager: MagicMock, db_path: Path) -> None:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(manager, ["dup", fid, "--format", "json"])
    dup = json.loads(buf.getvalue())
    assert dup["session_id"]
    assert dup["parent_flow_id"] == fid
    assert dup["original_flow_id"] == fid

    with patch("talos.send.engine.httpx.AsyncClient", _mock_httpx()):
        # patch returns MagicMock instance but we need class - fix
        pass

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

        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            run_send_cli(
                manager,
                [
                    "once",
                    fid,
                    "--session",
                    dup["session_id"],
                    "--note",
                    "forked",
                    "--format",
                    "json",
                ],
            )
        once = json.loads(buf2.getvalue())
        assert once["session_id"] == dup["session_id"]

    buf_h = io.StringIO()
    with redirect_stdout(buf_h):
        run_send_cli(
            manager,
            [
                "history",
                "--from",
                fid,
                "--session",
                dup["session_id"],
                "--format",
                "json",
            ],
        )
    hist = json.loads(buf_h.getvalue())
    assert hist["count"] == 1
    assert hist["executions"][0]["session_id"] == dup["session_id"]
    assert hist["executions"][0]["note"] == "forked"


def test_send_export_cli(manager: MagicMock, db_path: Path, tmp_path: Path) -> None:
    fid = _insert_capture(db_path)
    out = tmp_path / "exp"
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(
            manager,
            ["export", fid, "--out", str(out), "--format", "json"],
        )
    data = json.loads(buf.getvalue())
    req = Path(data["request_path"])
    assert req.is_file()
    parsed = parse_request(req.read_bytes(), default_scheme="https")
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/a"


def test_send_repeat_cli(manager: MagicMock, db_path: Path) -> None:
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
                ["once", fid, "--repeat", "3", "--format", "json"],
            )
        data = json.loads(buf.getvalue())
    assert data["profile"] == "repeat"
    assert data["profile_count"] == 3
    assert len(data["execution_flow_ids"]) == 3


def test_send_note_cli(manager: MagicMock, db_path: Path) -> None:
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
            run_send_cli(manager, ["once", fid, "--format", "json"])
        once = json.loads(buf.getvalue())

    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        run_send_cli(
            manager,
            ["note", once["execution_flow_id"], "--text", "later", "--format", "json"],
        )
    note = json.loads(buf2.getvalue())
    assert note["note"] == "later"
    assert note["updated"] is True

    # Reject note on capture
    with pytest.raises(SystemExit):
        run_send_cli(manager, ["note", fid, "--text", "nope", "--format", "json"])


def test_send_show_full_body(manager: MagicMock, db_path: Path) -> None:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(
            manager,
            ["show", fid, "--body", "response", "--full", "--format", "json"],
        )
    data = json.loads(buf.getvalue())
    assert data.get("response_body") == "hello"


def test_send_redo_cli(manager: MagicMock, db_path: Path) -> None:
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
            run_send_cli(manager, ["once", fid, "--format", "json"])
        once = json.loads(buf.getvalue())

        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            run_send_cli(
                manager,
                ["redo", once["execution_flow_id"], "--format", "json"],
            )
        redo = json.loads(buf2.getvalue())
    assert redo["parent_flow_id"] == once["execution_flow_id"]
    assert redo["original_flow_id"] == fid
    assert redo["execution_flow_id"]


def test_send_tab_open_list_reuse_touch_close(
    manager: MagicMock, db_path: Path
) -> None:
    """Persistent tab archive: open, list, reuse, touch after send, close."""
    fid = _insert_capture(db_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_send_cli(manager, ["tab", "open", fid, "--format", "json"])
    opened = json.loads(buf.getvalue())
    assert opened["created"] is True
    assert opened["reused"] is False
    tab = opened["tab"]
    assert tab["parent_flow_id"] == fid
    assert tab["original_flow_id"] == fid
    assert tab["title"].startswith("GET ")
    tab_id = tab["id"]

    # Same parent reuses the existing tab.
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        run_send_cli(manager, ["tab", "open", fid, "--format", "json"])
    reused = json.loads(buf2.getvalue())
    assert reused["reused"] is True
    assert reused["created"] is False
    assert reused["tab"]["id"] == tab_id

    # Force a second tab for the same parent.
    buf3 = io.StringIO()
    with redirect_stdout(buf3):
        run_send_cli(
            manager,
            ["tab", "open", fid, "--force-new", "--title", "extra", "--format", "json"],
        )
    forced = json.loads(buf3.getvalue())
    assert forced["created"] is True
    assert forced["tab"]["id"] != tab_id
    assert forced["tab"]["title"] == "extra"

    buf_list = io.StringIO()
    with redirect_stdout(buf_list):
        run_send_cli(manager, ["tab", "list", "--format", "json"])
    listed = json.loads(buf_list.getvalue())
    assert listed["count"] == 2
    assert {t["id"] for t in listed["tabs"]} == {tab_id, forced["tab"]["id"]}

    # After a send, touch last_execution on the first tab.
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

        buf_once = io.StringIO()
        with redirect_stdout(buf_once):
            run_send_cli(manager, ["once", fid, "--format", "json"])
        once = json.loads(buf_once.getvalue())

    buf_touch = io.StringIO()
    with redirect_stdout(buf_touch):
        run_send_cli(
            manager,
            [
                "tab",
                "touch",
                tab_id,
                "--last-execution",
                once["execution_flow_id"],
                "--format",
                "json",
            ],
        )
    touched = json.loads(buf_touch.getvalue())
    assert touched["tab"]["last_execution_id"] == once["execution_flow_id"]

    buf_close = io.StringIO()
    with redirect_stdout(buf_close):
        run_send_cli(
            manager,
            ["tab", "close", forced["tab"]["id"], "--format", "json"],
        )
    closed = json.loads(buf_close.getvalue())
    assert closed["closed"] is True

    buf_list2 = io.StringIO()
    with redirect_stdout(buf_list2):
        run_send_cli(manager, ["tab", "list", "--format", "json"])
    listed2 = json.loads(buf_list2.getvalue())
    assert listed2["count"] == 1
    assert listed2["tabs"][0]["id"] == tab_id

    # Clear archive; send history is independent of tabs.
    buf_clear = io.StringIO()
    with redirect_stdout(buf_clear):
        run_send_cli(manager, ["tab", "clear", "--format", "json"])
    cleared = json.loads(buf_clear.getvalue())
    assert cleared["cleared"] == 1

    buf_h = io.StringIO()
    with redirect_stdout(buf_h):
        run_send_cli(manager, ["history", "--from", fid, "--format", "json"])
    hist = json.loads(buf_h.getvalue())
    assert hist["count"] >= 1
