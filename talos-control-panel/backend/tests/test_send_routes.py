"""
Control Panel Repeater (`/api/send`) route tests.

Covers draft/history/diff reads, once/redo/dup/note/export mutations,
steps envelope on 2xx, 409 logout, 400 non-raw edit.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
MONOREPO = Path(__file__).resolve().parents[3]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(MONOREPO) not in sys.path:
    sys.path.insert(0, str(MONOREPO))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    talos_home = tmp_path / "talos-home"
    talos_home.mkdir()
    projects = talos_home / "projects"
    projects.mkdir()
    registry = projects / "registry.json"
    monkeypatch.setenv("TALOS_HOME", str(talos_home))
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(cfg, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(cfg, "REGISTRY_PATH", registry)
    monkeypatch.setattr(cfg, "TALOS_ROOT", MONOREPO)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _role_module(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT id FROM roles WHERE name = 'global'").fetchone()
        role_id = row[0] if row else "global"
        row = conn.execute("SELECT id FROM modules WHERE name = 'global'").fetchone()
        module_id = row[0] if row else "global"
    return role_id, module_id


def _insert_capture(
    db_path: Path,
    *,
    flow_id: str | None = None,
    method: str = "POST",
    url: str = "https://api.example.com/v1/item",
    host: str = "api.example.com",
    path: str = "/v1/item",
    headers: dict | None = None,
    body: bytes | None = b'{"a":1}',
    status_code: int = 200,
    response_body: bytes = b'{"ok":true}',
    endpoint_id: str | None = "ep-send-1",
    response_end: str | None = "2020-01-01T00:00:00.100+00:00",
) -> str:
    from talos.projects.db import init_project_db

    init_project_db(db_path)
    fid = flow_id or str(uuid.uuid4())
    role_id, module_id = _role_module(db_path)
    hdrs = headers or {
        "Host": host,
        "Content-Type": "application/json",
        "Content-Length": "7",
        "Cookie": "sid=orig",
    }
    if endpoint_id:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO endpoints (
                    id, project_id, method, host, path, normalized_path,
                    first_seen, last_seen
                ) VALUES (?, 'proj1', ?, ?, ?, ?, '2020-01-01T00:00:00+00:00',
                          '2020-01-01T00:00:00+00:00')
                """,
                (endpoint_id, method, f"https://{host}", path, path),
            )
            conn.commit()

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end, method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source, original_flow_id
            ) VALUES (
                ?, 'proj1', '2020-01-01T00:00:00+00:00', ?,
                ?, ?, ?, ?, '',
                ?, '{"sid":"orig"}', ?, 0, ?, '{}', ?, 0, 'application/json',
                ?, ?, ?, 'proxy_capture', NULL
            )
            """,
            (
                fid,
                response_end,
                method,
                url,
                host,
                path,
                json.dumps(hdrs),
                body,
                status_code,
                response_body,
                endpoint_id,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return fid


@pytest.fixture()
def client(home):
    talos_home, projects, registry = home
    pid = "proj1"
    data_dir = projects / pid
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    flow_id = _insert_capture(db_path)
    _write_registry(
        registry,
        {
            pid: {
                "id": pid,
                "name": "proj1",
                "status": "active",
                "data_dir": str(data_dir),
            }
        },
    )
    from talos_ui.main import app

    return TestClient(app), pid, flow_id, db_path


def test_draft_materialize(client):
    tc, pid, flow_id, _db = client
    r = tc.get(f"/api/send/draft/{flow_id}", params={"project_id": pid})
    assert r.status_code == 200
    data = r.json()
    assert data["parent_flow_id"] == flow_id
    assert data["original_flow_id"] == flow_id
    assert data["method"] == "POST"
    assert data["path"] == "/v1/item"
    assert data["request_body"] == '{"a":1}' or data["request_body"] is not None
    assert data["raw_encoding"] in ("utf8", "base64")
    assert data["raw"] or data["raw_base64"]
    assert isinstance(data["endpoint_annotations"], list)


def test_draft_404(client):
    tc, pid, _fid, _db = client
    r = tc.get("/api/send/draft/missing-id", params={"project_id": pid})
    assert r.status_code == 404


def test_history_empty(client):
    tc, pid, flow_id, _db = client
    r = tc.get(
        "/api/send/history",
        params={"project_id": pid, "from": flow_id},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["original_flow_id"] == flow_id
    assert data["count"] == 0
    assert data["executions"] == []


def test_history_with_duration(client):
    tc, pid, flow_id, db_path = client
    # Insert a fake send row with timestamps for duration
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
        sid = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end, method, url, host, path,
                query, request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source, original_flow_id, flow_meta
            ) VALUES (
                ?, 'proj1', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00.250+00:00',
                'POST', 'https://api.example.com/v1/item', 'api.example.com', '/v1/item',
                '', '{}', '{}', NULL, 0, 201, '{}', '{}', 0, 'application/json',
                NULL, ?, ?, 'manual_send', ?, ?
            )
            """,
            (
                sid,
                role,
                mod,
                flow_id,
                json.dumps(
                    {
                        "parent_flow_id": flow_id,
                        "verdict": "DIFFERENT",
                        "profile": "once",
                    }
                ),
            ),
        )
        conn.commit()

    r = tc.get(
        "/api/send/history",
        params={"project_id": pid, "from": flow_id},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    row = data["executions"][0]
    assert row["id"] == sid
    assert row["duration_ms"] == 250
    assert row["verdict"] == "DIFFERENT"


def test_tree_and_diff(client):
    tc, pid, flow_id, db_path = client
    # Second capture for diff
    other = _insert_capture(
        db_path,
        flow_id=str(uuid.uuid4()),
        body=b'{"a":2}',
        endpoint_id="ep-send-2",
    )
    r = tc.get(
        "/api/send/tree",
        params={"project_id": pid, "from": flow_id},
    )
    assert r.status_code == 200
    assert "nodes" in r.json()
    assert "lines" in r.json()

    r2 = tc.get(
        "/api/send/diff",
        params={"project_id": pid, "a": flow_id, "b": other, "side": "request"},
    )
    assert r2.status_code == 200
    assert "request" in r2.json()


def test_show(client):
    tc, pid, flow_id, _db = client
    r = tc.get(f"/api/send/show/{flow_id}", params={"project_id": pid})
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == flow_id
    assert data["duration_ms"] == 100


def test_once_requires_raw(client):
    tc, pid, flow_id, _db = client
    r = tc.post(
        "/api/send/once",
        params={"project_id": pid},
        json={
            "parent_flow_id": flow_id,
            "edit": {"headers": {"X-Test": "1"}},
            "profile": {"type": "once"},
        },
    )
    assert r.status_code == 400
    assert "raw" in r.json()["detail"].lower()


def test_once_success_steps_envelope(client):
    tc, pid, flow_id, db_path = client

    from talos.send.engine import SendOutcome

    fake = SendOutcome(
        execution_flow_id=str(uuid.uuid4()),
        parent_flow_id=flow_id,
        original_flow_id=flow_id,
        status_code=200,
        success=True,
        failure_reason=None,
        verdict="SAME",
        request_body_len=7,
        response_body_len=11,
        source="manual_send",
        session_id=None,
        profile="once",
        profile_index=0,
        profile_count=1,
        note=None,
    )

    # Store a minimal flow so hydrate works
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end, method, url, host, path,
                query, request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source, original_flow_id, flow_meta
            ) VALUES (
                ?, 'proj1', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00.050+00:00',
                'POST', 'https://api.example.com/v1/item', 'api.example.com', '/v1/item',
                '', '{}', '{}', ?, 0, 200, '{}', ?, 0, 'application/json',
                NULL, ?, ?, 'manual_send', ?, ?
            )
            """,
            (
                fake.execution_flow_id,
                b'{"a":1}',
                b'{"ok":true}',
                role,
                mod,
                flow_id,
                json.dumps(
                    {
                        "parent_flow_id": flow_id,
                        "verdict": "SAME",
                        "normalizers": ["content_length"],
                        "profile": "once",
                    }
                ),
            ),
        )
        conn.commit()

    raw = (
        b"POST /v1/item HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"a":1}'
    )
    raw_b64 = base64.b64encode(raw).decode("ascii")

    with patch(
        "talos.send.engine.send_once",
        new=AsyncMock(return_value=fake),
    ):
        r = tc.post(
            "/api/send/once",
            params={"project_id": pid},
            json={
                "parent_flow_id": flow_id,
                "source": "manual_send",
                "update_content_length": True,
                "edit": {"raw_base64": raw_b64},
                "profile": {"type": "once"},
            },
        )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "steps" in data
    assert data["steps"][0]["ok"] is True
    assert data["result"]["profile"] == "once"
    assert len(data["result"]["outcomes"]) == 1
    outcome = data["result"]["outcomes"][0]
    assert outcome["execution_flow_id"] == fake.execution_flow_id
    assert outcome["verdict"] == "SAME"
    assert "content_length" in (outcome.get("normalizers") or [])


def test_once_logout_409(client):
    tc, pid, flow_id, _db = client
    from talos.send.engine import SendOutcome

    fake = SendOutcome(
        execution_flow_id=None,
        parent_flow_id=flow_id,
        original_flow_id=flow_id,
        status_code=None,
        success=False,
        failure_reason="endpoint_annotated_logout",
        verdict=None,
        source="manual_send",
    )
    raw_b64 = base64.b64encode(
        b"POST /v1/item HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    ).decode("ascii")

    with patch(
        "talos.send.engine.send_once",
        new=AsyncMock(return_value=fake),
    ):
        r = tc.post(
            "/api/send/once",
            params={"project_id": pid},
            json={
                "parent_flow_id": flow_id,
                "edit": {"raw_base64": raw_b64},
                "profile": {"type": "once"},
            },
        )
    assert r.status_code == 409
    body = r.json()
    assert "detail" in body
    assert "steps" not in body


def test_dup_and_note_and_export(client):
    tc, pid, flow_id, db_path = client

    r = tc.post(f"/api/send/dup/{flow_id}", params={"project_id": pid})
    assert r.status_code == 200
    data = r.json()
    assert data["steps"][0]["ok"] is True
    assert data["result"]["session_id"]
    assert data["result"]["parent_flow_id"] == flow_id

    # note only on send sources
    r2 = tc.post(
        f"/api/send/note/{flow_id}",
        params={"project_id": pid},
        json={"note": "should fail on capture"},
    )
    assert r2.status_code == 400

    # insert a send row then note
    send_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path,
                query, request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source, original_flow_id, flow_meta
            ) VALUES (
                ?, 'proj1', '2020-01-01T00:00:00+00:00',
                'POST', 'https://api.example.com/v1/item', 'api.example.com', '/v1/item',
                '', '{}', '{}', NULL, 0, 200, '{}', NULL, 0, '',
                NULL, ?, ?, 'manual_send', ?, '{}'
            )
            """,
            (send_id, role, mod, flow_id),
        )
        conn.commit()

    r3 = tc.post(
        f"/api/send/note/{send_id}",
        params={"project_id": pid},
        json={"note": "interesting"},
    )
    assert r3.status_code == 200
    assert r3.json()["result"]["ok"] is True

    r4 = tc.post(f"/api/send/export/{flow_id}", params={"project_id": pid})
    assert r4.status_code == 200
    exp = r4.json()["result"]
    assert exp["request_http_base64"]
    assert exp["response_http_base64"]
    assert exp["request_bytes"] > 0


def test_redo(client):
    tc, pid, flow_id, db_path = client
    from talos.send.engine import SendOutcome

    exec_id = str(uuid.uuid4())
    new_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
        for fid, parent in ((exec_id, flow_id), (new_id, exec_id)):
            conn.execute(
                """
                INSERT INTO flows (
                    id, project_id, captured_at, response_end, method, url, host, path,
                    query, request_headers, request_cookies, request_body,
                    request_body_truncated, status_code, response_headers,
                    response_body, response_body_truncated, content_type,
                    endpoint_id, role_id, module_id, source, original_flow_id, flow_meta
                ) VALUES (
                    ?, 'proj1', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00.040+00:00',
                    'POST', 'https://api.example.com/v1/item', 'api.example.com', '/v1/item',
                    '', '{}', '{}', NULL, 0, 200, '{}', ?, 0, '',
                    NULL, ?, ?, 'manual_send', ?, ?
                )
                """,
                (
                    fid,
                    b"{}",
                    role,
                    mod,
                    flow_id,
                    json.dumps({"parent_flow_id": parent, "verdict": "SAME"}),
                ),
            )
        conn.commit()

    fake = SendOutcome(
        execution_flow_id=new_id,
        parent_flow_id=exec_id,
        original_flow_id=flow_id,
        status_code=200,
        success=True,
        failure_reason=None,
        verdict="SAME",
        source="manual_send",
    )
    with patch(
        "talos.send.engine.redo_send",
        new=AsyncMock(return_value=fake),
    ):
        r = tc.post(f"/api/send/redo/{exec_id}", params={"project_id": pid}, json={})
    assert r.status_code == 200
    assert r.json()["steps"][0]["ok"] is True
    assert r.json()["result"]["outcomes"][0]["execution_flow_id"] == new_id


def test_send_engine_importable_without_talos_venv():
    """POST /api/send/once imports the engine in this process (issue #4)."""
    import httpx
    from talos.send.engine import send_once, send_parallel, send_repeat, redo_send

    assert httpx.Timeout is not None
    assert callable(send_once)
    assert callable(send_parallel)
    assert callable(send_repeat)
    assert callable(redo_send)


def test_talos_venv_site_packages_unix_layout(tmp_path, monkeypatch):
    """Repeater Send must see httpx from the Talos venv, not backend/.venv."""
    from talos_ui.routers import send as send_router

    venv = tmp_path / ".venv"
    py = venv / "bin" / "python"
    site_pkg = venv / "lib" / "python3.12" / "site-packages"
    site_pkg.mkdir(parents=True)
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("", encoding="utf-8")
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    monkeypatch.setattr(send_router.config, "TALOS_PYTHON", str(py))
    monkeypatch.setattr(send_router.sys, "platform", "linux")
    found = send_router._talos_venv_site_packages()
    assert str(site_pkg) in found


def test_talos_venv_site_packages_windows_layout(tmp_path, monkeypatch):
    from talos_ui.routers import send as send_router

    venv = tmp_path / ".venv"
    py = venv / "Scripts" / "python.exe"
    site_pkg = venv / "Lib" / "site-packages"
    site_pkg.mkdir(parents=True)
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("", encoding="utf-8")
    (venv / "pyvenv.cfg").write_text("home = C:\\Python\n", encoding="utf-8")
    monkeypatch.setattr(send_router.config, "TALOS_PYTHON", str(py))
    monkeypatch.setattr(send_router.sys, "platform", "win32")
    found = send_router._talos_venv_site_packages()
    assert found == [str(site_pkg)]


def test_talos_venv_site_packages_ignores_python_symlink(tmp_path, monkeypatch):
    """``.venv/bin/python`` is a symlink; must not walk it to /usr/lib."""
    from talos_ui.routers import send as send_router

    system_py = tmp_path / "usr" / "bin" / "python3"
    system_py.parent.mkdir(parents=True)
    system_py.write_text("", encoding="utf-8")
    (tmp_path / "usr" / "lib" / "python3.14" / "site-packages").mkdir(parents=True)

    venv = tmp_path / ".venv"
    bindir = venv / "bin"
    bindir.mkdir(parents=True)
    py = bindir / "python"
    py.symlink_to(system_py)
    site_pkg = venv / "lib" / "python3.14" / "site-packages"
    site_pkg.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")

    monkeypatch.setattr(send_router.config, "TALOS_PYTHON", str(py))
    monkeypatch.setattr(send_router.sys, "platform", "linux")
    found = send_router._talos_venv_site_packages()
    assert found == [str(site_pkg)]
    assert not any(p.startswith(str(tmp_path / "usr")) for p in found)


def test_import_send_engine_uses_talos_site_packages():
    from talos_ui.routers import send as send_router

    send_once, send_parallel, send_repeat, redo_send = send_router._import_send_engine()
    assert callable(send_once)
    assert callable(send_parallel)
    assert callable(send_repeat)
    assert callable(redo_send)


def test_tabs_open_list_reuse_touch_close(client):
    """Persistent Repeater tab archive API (metadata only)."""
    tc, pid, flow_id, _db = client

    r0 = tc.get("/api/send/tabs", params={"project_id": pid})
    assert r0.status_code == 200
    assert r0.json()["count"] == 0

    r = tc.post(
        "/api/send/tabs",
        params={"project_id": pid},
        json={"flow_id": flow_id},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["steps"][0]["ok"] is True
    assert body["result"]["created"] is True
    tab = body["result"]["tab"]
    assert tab["parent_flow_id"] == flow_id
    assert tab["original_flow_id"] == flow_id
    tab_id = tab["id"]

    # Reuse same parent
    r2 = tc.post(
        "/api/send/tabs",
        params={"project_id": pid},
        json={"flow_id": flow_id},
    )
    assert r2.status_code == 200
    assert r2.json()["result"]["reused"] is True
    assert r2.json()["result"]["tab"]["id"] == tab_id

    # List
    r3 = tc.get("/api/send/tabs", params={"project_id": pid})
    assert r3.status_code == 200
    assert r3.json()["count"] == 1

    # Touch last execution
    exec_id = str(uuid.uuid4())
    r4 = tc.post(
        f"/api/send/tabs/{tab_id}/touch",
        params={"project_id": pid},
        json={"last_execution_id": exec_id},
    )
    assert r4.status_code == 200
    assert r4.json()["result"]["tab"]["last_execution_id"] == exec_id

    # Rename
    r5 = tc.post(
        f"/api/send/tabs/{tab_id}/rename",
        params={"project_id": pid},
        json={"title": "probe item"},
    )
    assert r5.status_code == 200
    assert r5.json()["result"]["tab"]["title"] == "probe item"

    # Close
    r6 = tc.delete(f"/api/send/tabs/{tab_id}", params={"project_id": pid})
    assert r6.status_code == 200
    assert r6.json()["result"]["closed"] is True

    r7 = tc.get("/api/send/tabs", params={"project_id": pid})
    assert r7.json()["count"] == 0


def test_tabs_open_missing_flow(client):
    tc, pid, _fid, _db = client
    r = tc.post(
        "/api/send/tabs",
        params={"project_id": pid},
        json={"flow_id": "does-not-exist"},
    )
    assert r.status_code == 404
