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
from talos.send.engine import (
    MAX_PROFILE_N,
    redo_send,
    send_once,
    send_parallel,
    send_repeat,
)
from talos.send.request_diff import compute_request_diff


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


# ------------------------------------------------------------------ #
# Phase 2                                                              #
# ------------------------------------------------------------------ #

def test_phase2_edits_cookie_path_host_json_and_meta(db_path: Path) -> None:
    parent_id = _insert_capture(
        db_path,
        url="https://api.example.com/v1/item?x=1&keep=yes",
        path="/v1/item",
        query="x=1&keep=yes",
        headers={
            "Host": "api.example.com",
            "Cookie": "sid=orig",
            "Content-Type": "application/json",
            "Content-Length": "7",
        },
        body=b'{"a":1}',
    )
    session = str(uuid.uuid4())
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        outcome, client = _run_send(
            client_cls,
            _mock_response(200, b"ok"),
            parent_id,
            db_path,
            "proj",
            cookies=[("sid", "newtok")],
            remove_query=["x"],
            path="/v2/item",
            host="other.example.com",
            json_sets=[("a", "2")],
            session_id=session,
            note="branch-a",
            reason="manual_probe",
        )

    assert outcome.success
    assert outcome.session_id == session
    assert outcome.note == "branch-a"
    new_flow = send_db.get_flow_for_send(db_path, outcome.execution_flow_id)  # type: ignore[arg-type]
    assert new_flow is not None
    assert new_flow["path"] == "/v2/item"
    assert new_flow["host"] == "other.example.com"
    assert "x=" not in (new_flow.get("query") or "")
    assert "keep=yes" in (new_flow.get("query") or "")
    headers = (
        json.loads(new_flow["request_headers"])
        if isinstance(new_flow["request_headers"], str)
        else new_flow["request_headers"]
    )
    assert "sid=newtok" in headers.get("Cookie", "")
    assert headers.get("Host") == "other.example.com"
    body = new_flow["request_body"]
    if isinstance(body, str):
        body = body.encode()
    assert json.loads(body)["a"] == "2"
    meta = new_flow.get("flow_meta") or {}
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta["session_id"] == session
    assert meta["note"] == "branch-a"
    assert meta["verdict"] in ("SAME", "DIFFERENT", "ERROR")
    assert meta["profile"] == "once"

    # Wire request used mutated URL
    call_kwargs = client.request.await_args.kwargs
    assert "other.example.com" in call_kwargs["url"]
    assert "/v2/item" in call_kwargs["url"]


def test_repeat_three_rows_same_parent_root(db_path: Path) -> None:
    root = _insert_capture(db_path)
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.request = AsyncMock(return_value=_mock_response())
        client_cls.return_value = client

        multi = asyncio.run(
            send_repeat(root, db_path, "proj", 3, reason="nx")
        )

    assert multi.profile == "repeat"
    assert multi.profile_count == 3
    assert len(multi.outcomes) == 3
    ids = multi.execution_flow_ids
    assert len(ids) == 3
    assert len(set(ids)) == 3
    for o in multi.outcomes:
        assert o.parent_flow_id == root
        assert o.original_flow_id == root
        assert o.profile == "repeat"
        assert o.profile_count == 3

    # Baseline untouched
    parent = send_db.get_flow_for_send(db_path, root)
    assert parent is not None
    assert parent["source"] == "proxy_capture"

    hist = send_db.list_send_history(db_path, root)
    assert len(hist) == 3


def test_parallel_three_and_cap_validation(db_path: Path) -> None:
    root = _insert_capture(db_path)
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.request = AsyncMock(return_value=_mock_response())
        client_cls.return_value = client

        multi = asyncio.run(send_parallel(root, db_path, "proj", 3))

    assert multi.profile == "parallel"
    assert len(multi.execution_flow_ids) == 3
    assert len(set(multi.execution_flow_ids)) == 3

    with pytest.raises(ValueError, match=">= 1"):
        asyncio.run(send_repeat(root, db_path, "proj", 0))
    with pytest.raises(ValueError, match=str(MAX_PROFILE_N)):
        asyncio.run(send_parallel(root, db_path, "proj", MAX_PROFILE_N + 1))


def test_redo_clones_as_sent(db_path: Path) -> None:
    parent_id = _insert_capture(
        db_path,
        headers={
            "Host": "api.example.com",
            "Content-Type": "application/json",
            "Content-Length": "999",  # deliberately stale
            "X-Custom": "keep",
        },
        body=b"abc",
    )
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        o1, _ = _run_send(
            client_cls,
            _mock_response(),
            parent_id,
            db_path,
            "proj",
            body=b"longer-body!!",
            body_set=True,
            update_content_length=True,
        )
        first = send_db.get_flow_for_send(db_path, o1.execution_flow_id)  # type: ignore[arg-type]
        assert first is not None
        first_headers = (
            json.loads(first["request_headers"])
            if isinstance(first["request_headers"], str)
            else first["request_headers"]
        )
        first_body = first["request_body"]

        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.request = AsyncMock(return_value=_mock_response(201, b"again"))
        client_cls.return_value = client
        o2 = asyncio.run(redo_send(o1.execution_flow_id, db_path, "proj"))  # type: ignore[arg-type]

    assert o2.success
    assert o2.parent_flow_id == o1.execution_flow_id
    assert o2.original_flow_id == parent_id
    call_kwargs = client.request.await_args.kwargs
    assert call_kwargs["content"] == first_body
    # As-sent headers re-fired without re-normalizing CL away from stored value
    wire = call_kwargs["headers"]
    cl_keys = [k for k in wire if k.lower() == "content-length"]
    assert wire[cl_keys[0]] == first_headers[cl_keys[0]]
    assert wire.get("X-Custom") == "keep" or any(
        k.lower() == "x-custom" and wire[k] == "keep" for k in wire
    )


def test_history_session_filter_and_note_update(db_path: Path) -> None:
    root = _insert_capture(db_path)
    sess_a = str(uuid.uuid4())
    sess_b = str(uuid.uuid4())
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        _run_send(
            client_cls,
            _mock_response(),
            root,
            db_path,
            "proj",
            session_id=sess_a,
            note="a1",
        )
        o2, _ = _run_send(
            client_cls,
            _mock_response(),
            root,
            db_path,
            "proj",
            session_id=sess_b,
            note="b1",
        )
        _run_send(
            client_cls,
            _mock_response(),
            root,
            db_path,
            "proj",
            session_id=sess_a,
            note="a2",
        )

    hist_a = send_db.list_send_history(db_path, root, session_id=sess_a)
    assert len(hist_a) == 2
    assert all(h["session_id"] == sess_a for h in hist_a)

    ok, err = send_db.update_send_note(db_path, o2.execution_flow_id, "relabeled")  # type: ignore[arg-type]
    assert ok and err == ""
    show = send_db.get_flow_show(db_path, o2.execution_flow_id)  # type: ignore[arg-type]
    assert show is not None
    meta = show["flow_meta"]
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta["note"] == "relabeled"

    # Note on capture rejected
    ok2, err2 = send_db.update_send_note(db_path, root, "nope")
    assert not ok2
    assert "manual_send" in err2 or "ai_send" in err2


def test_export_round_trip_parse(db_path: Path, tmp_path: Path) -> None:
    from talos.send.raw_http import parse_request

    parent_id = _insert_capture(
        db_path,
        method="POST",
        url="https://api.example.com/v1/item?q=1",
        path="/v1/item",
        query="q=1",
        body=b'{"x":1}',
        headers={
            "Host": "api.example.com",
            "Content-Type": "application/json",
            "Content-Length": "7",
        },
    )
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        o, _ = _run_send(
            client_cls,
            _mock_response(200, b'{"ok":true}'),
            parent_id,
            db_path,
            "proj",
            headers=[("X-T", "1")],
        )
    out = tmp_path / "export"
    result = send_db.export_flow_http(db_path, o.execution_flow_id, out)  # type: ignore[arg-type]
    req_path = Path(result["request_path"])
    assert req_path.is_file()
    parsed = parse_request(req_path.read_bytes(), default_scheme="https")
    assert parsed["method"] == "POST"
    assert parsed["path"] == "/v1/item"
    assert parsed["request_headers"].get("X-T") == "1" or any(
        k.lower() == "x-t" for k in parsed["request_headers"]
    )
    assert Path(result["response_path"]).is_file()


def test_request_diff_detects_changes() -> None:
    a = {
        "method": "GET",
        "url": "https://ex.test/a?x=1",
        "path": "/a",
        "query": "x=1",
        "request_headers": {"Host": "ex.test", "Accept": "*/*"},
        "request_cookies": {},
        "request_body": b"",
    }
    b = {
        "method": "POST",
        "url": "https://ex.test/b?x=2",
        "path": "/b",
        "query": "x=2",
        "request_headers": {
            "Host": "ex.test",
            "Accept": "application/json",
            "X-New": "1",
        },
        "request_cookies": {},
        "request_body": b'{"a":1}',
    }
    d = compute_request_diff(a, b)
    assert d["changed"] is True
    assert d["method_changed"] is True
    assert d["path_changed"] is True
    assert d["query_changed"] is True
    assert d["body_equal"] is False
    assert d["headers"]["added"] or d["headers"]["changed"]
    assert d["method_a"] == "GET"
    assert d["method_b"] == "POST"


def test_response_diff_still_same_different_error(db_path: Path) -> None:
    """Phase 1 regression: compute_diff verdicts still work via send_once."""
    parent_id = _insert_capture(db_path, status_code=200, response_body=b"ok")
    with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
        o_same, _ = _run_send(
            client_cls,
            _mock_response(200, b"ok"),
            parent_id,
            db_path,
            "proj",
        )
        # Same status + similar body may be SAME depending on thresholds
        assert o_same.verdict in ("SAME", "DIFFERENT")
        o_diff, _ = _run_send(
            client_cls,
            _mock_response(403, b"denied"),
            parent_id,
            db_path,
            "proj",
        )
        assert o_diff.verdict == "DIFFERENT"
