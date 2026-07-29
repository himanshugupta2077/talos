"""
Tests for talos.send.engine and history.

Covers:
    - Immutability of parent after send
    - New row source/lineage
    - Structured edit reflected in stored request
    - Content-Length default vs --no-update
    - Diff DIFFERENT on status change
    - History lists two sends from same root
    - Logout annotation blocks send
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.projects.annotations import add_annotation
from talos.projects.db import init_project_db
from talos.replay import db as replay_db
from talos.send import db as send_db
from talos.send.engine import send_once


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _role_module(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT id FROM roles WHERE name = 'global'"
        ).fetchone()
        role_id = row[0] if row else "global"
        row = conn.execute(
            "SELECT id FROM modules WHERE name = 'global'"
        ).fetchone()
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
    query: str = "",
    headers: dict | None = None,
    body: bytes | None = b'{"a":1}',
    status_code: int = 200,
    response_body: bytes = b'{"ok":true}',
    endpoint_id: str | None = "ep-send-1",
    original_flow_id: str | None = None,
    source: str = "proxy_capture",
) -> str:
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
                ) VALUES (?, 'proj', ?, ?, ?, ?, '2020-01-01T00:00:00+00:00',
                          '2020-01-01T00:00:00+00:00')
                """,
                (endpoint_id, method, f"https://{host}", path, path),
            )
            conn.commit()

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source, original_flow_id
            ) VALUES (
                ?, 'proj', '2020-01-01T00:00:00+00:00',
                ?, ?, ?, ?, ?,
                ?, '{}', ?, 0, ?, '{}', ?, 0, 'application/json',
                ?, ?, ?, ?, ?
            )
            """,
            (
                fid,
                method,
                url,
                host,
                path,
                query,
                json.dumps(hdrs),
                body,
                status_code,
                response_body,
                endpoint_id,
                role_id,
                module_id,
                source,
                original_flow_id,
            ),
        )
        conn.commit()
    return fid


def _mock_response(
    status_code: int = 200,
    body: bytes = b"resp",
    headers: dict | None = None,
):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body
    resp.headers = headers or {"content-type": "application/json"}
    return resp


def _patch_httpx(response=None):
    """Context manager factory: mock httpx.AsyncClient.request."""
    response = response or _mock_response()
    return patch("talos.send.engine.httpx.AsyncClient"), response


def _run_send(client_cls, response, *args, **kwargs):
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.request = AsyncMock(return_value=response)
    client_cls.return_value = client
    outcome = asyncio.run(send_once(*args, **kwargs))
    return outcome, client


# ------------------------------------------------------------------ #
# Engine                                                               #
# ------------------------------------------------------------------ #

def test_send_immutability_and_new_row(db_path: Path) -> None:
    parent_id = _insert_capture(db_path, body=b'{"a":1}')
    parent_before = send_db.get_flow_for_send(db_path, parent_id)
    assert parent_before is not None
    parent_headers_before = parent_before["request_headers"]
    parent_body_before = parent_before["request_body"]

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        outcome, _client = _run_send(
            client_cls,
            _mock_response(201, b"created"),
            parent_id,
            db_path,
            "proj",
            headers=[("X-Test", "1")],
            body=b'{"a":2}',
            body_set=True,
            source="manual_send",
            reason="manual_probe",
        )

    assert outcome.success
    assert outcome.execution_flow_id
    assert outcome.parent_flow_id == parent_id
    assert outcome.original_flow_id == parent_id
    assert outcome.status_code == 201
    assert outcome.source == "manual_send"

    parent_after = send_db.get_flow_for_send(db_path, parent_id)
    assert parent_after is not None
    assert parent_after["request_headers"] == parent_headers_before
    assert parent_after["request_body"] == parent_body_before
    assert parent_after["source"] == "proxy_capture"

    new_flow = send_db.get_flow_for_send(db_path, outcome.execution_flow_id)
    assert new_flow is not None
    assert new_flow["source"] == "manual_send"
    assert new_flow["original_flow_id"] == parent_id
    assert new_flow["status_code"] == 201
    stored_headers = (
        json.loads(new_flow["request_headers"])
        if isinstance(new_flow["request_headers"], str)
        else new_flow["request_headers"]
    )
    assert stored_headers["X-Test"] == "1"
    assert new_flow["request_body"] == b'{"a":2}'
    meta = new_flow.get("flow_meta") or {}
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta.get("kind") == "send"
    assert meta.get("parent_flow_id") == parent_id
    assert meta.get("update_content_length") is True


def test_content_length_default_matches_body(db_path: Path) -> None:
    parent_id = _insert_capture(
        db_path,
        headers={
            "Host": "api.example.com",
            "Content-Type": "application/json",
            "Content-Length": "999",
        },
        body=b"old",
    )
    new_body = b"new-body-bytes!!"

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        outcome, client = _run_send(
            client_cls,
            _mock_response(),
            parent_id,
            db_path,
            "proj",
            body=new_body,
            body_set=True,
            update_content_length=True,
        )

    assert outcome.success
    new_flow = send_db.get_flow_for_send(db_path, outcome.execution_flow_id)  # type: ignore[arg-type]
    assert new_flow is not None
    headers = (
        json.loads(new_flow["request_headers"])
        if isinstance(new_flow["request_headers"], str)
        else new_flow["request_headers"]
    )
    cl_keys = [k for k in headers if k.lower() == "content-length"]
    assert len(cl_keys) == 1
    assert headers[cl_keys[0]] == str(len(new_body))

    call_kwargs = client.request.await_args.kwargs
    wire_headers = call_kwargs["headers"]
    wire_cl = [k for k in wire_headers if k.lower() == "content-length"]
    assert wire_headers[wire_cl[0]] == str(len(new_body))


def test_no_update_content_length_preserves_stale_cl(db_path: Path) -> None:
    parent_id = _insert_capture(
        db_path,
        headers={
            "Host": "api.example.com",
            "Content-Length": "1",
        },
        body=b"x",
    )

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        outcome, client = _run_send(
            client_cls,
            _mock_response(),
            parent_id,
            db_path,
            "proj",
            body=b"longer-body",
            body_set=True,
            update_content_length=False,
        )

    assert outcome.execution_flow_id
    call_kwargs = client.request.await_args.kwargs
    wire_headers = call_kwargs["headers"]
    cl_vals = [
        wire_headers[k] for k in wire_headers if k.lower() == "content-length"
    ]
    assert cl_vals == ["1"] or "1" in cl_vals


def test_diff_status_change_different(db_path: Path) -> None:
    parent_id = _insert_capture(db_path, status_code=200, response_body=b"ok")

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        outcome, _ = _run_send(
            client_cls,
            _mock_response(403, b"denied"),
            parent_id,
            db_path,
            "proj",
        )

    assert outcome.verdict == "DIFFERENT"
    assert outcome.status_code == 403


def test_history_two_sends(db_path: Path) -> None:
    root = _insert_capture(db_path)

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        o1, _ = _run_send(
            client_cls,
            _mock_response(),
            root,
            db_path,
            "proj",
            reason="probe1",
        )
        o2, _ = _run_send(
            client_cls,
            _mock_response(),
            o1.execution_flow_id,  # type: ignore[arg-type]
            db_path,
            "proj",
            headers=[("X-Second", "1")],
            reason="probe2",
            source="ai_send",
        )

    assert o1.original_flow_id == root
    assert o2.original_flow_id == root
    assert o2.parent_flow_id == o1.execution_flow_id

    hist = send_db.list_send_history(db_path, root)
    assert len(hist) == 2
    ids = {h["id"] for h in hist}
    assert o1.execution_flow_id in ids
    assert o2.execution_flow_id in ids
    sources = {h["source"] for h in hist}
    assert sources == {"manual_send", "ai_send"}


def test_logout_blocks_send(db_path: Path) -> None:
    parent_id = _insert_capture(db_path, endpoint_id="ep-logout")
    add_annotation(db_path, "ep-logout", "logout")

    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.request = AsyncMock(return_value=_mock_response())
        client_cls.return_value = client

        outcome = asyncio.run(send_once(parent_id, db_path, "proj"))

    assert not outcome.success
    assert outcome.failure_reason == "endpoint_annotated_logout"
    assert outcome.execution_flow_id is None
    client.request.assert_not_awaited()


def test_flow_not_found(db_path: Path) -> None:
    outcome = asyncio.run(send_once("missing-id", db_path, "proj"))
    assert not outcome.success
    assert outcome.failure_reason == "flow_not_found"


def test_baseline_selection_still_proxy_capture_only(db_path: Path) -> None:
    """Send flows must not become best baseline for endpoint replay."""
    ep = "ep-base"
    capture = _insert_capture(
        db_path,
        endpoint_id=ep,
        status_code=200,
        body=b"cap",
        response_body=b"cap-resp",
    )
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        _run_send(
            client_cls,
            _mock_response(200, b"send-resp"),
            capture,
            db_path,
            "proj",
            body=b"mutated",
            body_set=True,
        )

    best = replay_db.get_best_flow_for_endpoint(db_path, ep)
    assert best is not None
    assert best["id"] == capture
    assert best["source"] == "proxy_capture"
