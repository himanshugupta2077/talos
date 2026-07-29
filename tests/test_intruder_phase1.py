"""
Phase 1 Intruder tests: schema, template, generators, strategies, match,
timing, engine segment, CLI surface, scheduler job type.
"""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.projects.db import SCHEMA_VERSION, init_project_db
from talos.intruder import db as idb
from talos.intruder.config_schema import ValidationError, default_config, validate_config
from talos.intruder.generators import build_generator
from talos.intruder.match import evaluate_match_rules
from talos.intruder.models import (
    ERR_PATH_INJECT_UNAVAILABLE,
    TemplateVariable,
)
from talos.intruder.strategies import build_strategy
from talos.intruder.template import render_attempt, validate_path_inject
from talos.intruder.timing import TimingController
from talos.intruder.cli import run_intruder_cli
from talos.scheduler.job import INTRUDER_SESSION, JOB_TYPES, PRIORITY_AUTO, PRIORITY_MANUAL


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id="proj", scope=[])
    m = MagicMock()
    m.active.return_value = project
    return m


def _insert_capture(
    db_path: Path,
    *,
    url: str = "https://ex.test/users/42/orders",
    method: str = "GET",
    body: bytes | None = None,
    headers: dict | None = None,
    endpoint_id: str | None = None,
) -> str:
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
                role_id, module_id, source, endpoint_id
            ) VALUES (
                ?, 'proj', '2020-01-01T00:00:00+00:00',
                ?, ?, 'ex.test', '/users/42/orders', '',
                ?, '{}', ?, 0, 200, '{}', ?, 0, 'application/json',
                ?, ?, 'proxy_capture', ?
            )
            """,
            (
                fid,
                method,
                url,
                json.dumps(headers or {"Host": "ex.test", "Accept": "application/json"}),
                body,
                b'{"ok":true}',
                role,
                mod,
                endpoint_id,
            ),
        )
        conn.commit()
    return fid


def _insert_endpoint(db_path: Path, normalized_path: str = "/users/{user_id}/orders") -> str:
    eid = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints (
                id, project_id, method, host, path, normalized_path,
                first_seen, last_seen
            ) VALUES (?, 'proj', 'GET', 'https://ex.test', '/users/42/orders', ?,
                      '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')
            """,
            (eid, normalized_path),
        )
        conn.commit()
    return eid


# ------------------------------------------------------------------ #
# Schema                                                               #
# ------------------------------------------------------------------ #

def test_schema_version_46_has_intruder_tables(db_path: Path) -> None:
    assert SCHEMA_VERSION >= 46
    with sqlite3.connect(str(db_path)) as conn:
        ver = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert ver >= 46
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "intruder_sessions" in tables
    assert "intruder_results" in tables


def test_session_crud_and_batch_insert(db_path: Path) -> None:
    sess = idb.create_session(db_path, "proj", name="t1", config={"schema_version": 1})
    assert sess["status"] == "draft"
    n = idb.insert_results_batch(
        db_path,
        sess["id"],
        [
            {
                "attempt_index": 0,
                "variables": {"x": "1"},
                "status_code": 200,
                "success": True,
                "duration_ms": 10.0,
                "body_length": 5,
                "interesting": True,
                "match_tags": ["m0"],
            }
        ],
        checkpoint={"attempt_index": 0},
        progress={"sent": 1},
    )
    assert n == 1
    # Idempotent re-insert
    n2 = idb.insert_results_batch(
        db_path,
        sess["id"],
        [
            {
                "attempt_index": 0,
                "variables": {"x": "1"},
                "status_code": 200,
                "success": True,
            }
        ],
        checkpoint={"attempt_index": 0},
        progress={"sent": 1},
    )
    assert n2 == 0
    rows = idb.list_results(db_path, sess["id"])
    assert len(rows) == 1
    assert rows[0]["interesting"] is True


# ------------------------------------------------------------------ #
# Template                                                             #
# ------------------------------------------------------------------ #

def test_render_query_and_json_body() -> None:
    baseline = {
        "method": "POST",
        "url": "https://ex.test/api?q=old",
        "headers": {"Content-Type": "application/json", "Content-Length": "99"},
        "body": b'{"user":"a","id":1}',
    }
    vars_ = [
        TemplateVariable(name="q", location="query", path="q"),
        TemplateVariable(name="user", location="body", path="user"),
    ]
    spec = render_attempt(baseline, vars_, {"q": "new", "user": "bob"}, attempt_index=0)
    assert "q=new" in spec.url
    assert b"bob" in (spec.body or b"")
    assert not any(k.lower() == "content-length" for k in spec.headers)


def test_render_raw_multi_occurrence() -> None:
    baseline = {
        "method": "GET",
        "url": "https://ex.test/{{x}}/{{x}}",
        "headers": {"X-T": "{{x}}"},
        "body": None,
    }
    vars_ = [TemplateVariable(name="x", location="raw")]
    spec = render_attempt(baseline, vars_, {"x": "ZZ"}, attempt_index=1)
    assert spec.url == "https://ex.test/ZZ/ZZ"
    assert spec.headers["X-T"] == "ZZ"


def test_path_inject_gate() -> None:
    vars_ = [TemplateVariable(name="user_id", location="path")]
    err = validate_path_inject(vars_, "/users/42/orders")
    assert err == ERR_PATH_INJECT_UNAVAILABLE
    err2 = validate_path_inject(vars_, "/users/{user_id}/orders")
    assert err2 is None


def test_path_render_with_normalized_path() -> None:
    baseline = {
        "method": "GET",
        "url": "https://ex.test/users/42/orders",
        "headers": {},
        "body": None,
    }
    vars_ = [TemplateVariable(name="user_id", location="path")]
    spec = render_attempt(
        baseline,
        vars_,
        {"user_id": "99"},
        normalized_path="/users/{user_id}/orders",
    )
    assert "/users/99/orders" in spec.url


# ------------------------------------------------------------------ #
# Generators / strategies                                              #
# ------------------------------------------------------------------ #

def test_numbers_generator_checkpoint() -> None:
    gen = build_generator("numbers", {"start": 1, "end": 5, "step": 1})
    assert gen.estimate_count() == 5
    it = iter(gen)
    assert next(it) == "1"
    assert next(it) == "2"
    cp = gen.checkpoint()
    gen2 = build_generator("numbers", {"start": 1, "end": 5, "step": 1})
    gen2.restore(cp)
    assert list(gen2) == ["3", "4", "5"]


def test_wordlist_generator(tmp_path: Path) -> None:
    wl = tmp_path / "words.txt"
    wl.write_text("a\n\nb\n", encoding="utf-8")
    gen = build_generator("wordlist", {"path": str(wl)})
    assert list(gen) == ["a", "b"]


def test_single_strategy() -> None:
    gen = build_generator("static", {"values": ["x", "y"]})
    strat = build_strategy("single", ["id"], {"id": gen}, options={"primary": "id"})
    assert strat.next() == {"id": "x"}
    assert strat.next() == {"id": "y"}
    assert strat.next() is None


def test_sniper_strategy() -> None:
    gen = build_generator("static", {"values": ["1", "2"]})
    strat = build_strategy(
        "sniper",
        ["a", "b"],
        {"payloads": gen},
        options={"payload_set": "payloads", "targets": ["a", "b"]},
    )
    seen = []
    while True:
        n = strat.next()
        if n is None:
            break
        seen.append(n)
    assert seen == [{"a": "1"}, {"a": "2"}, {"b": "1"}, {"b": "2"}]
    assert strat.progress()["total_estimate"] == 4


# ------------------------------------------------------------------ #
# Match / timing                                                       #
# ------------------------------------------------------------------ #

def test_match_rules() -> None:
    metrics = {
        "status_code": 200,
        "body_text": "hello world",
        "body_length": 200,
        "duration_ms": 150.0,
    }
    baseline = {"body_length": 100}
    tags = evaluate_match_rules(
        metrics,
        [
            {"tag": "s200", "status": 200},
            {"tag": "len", "length_delta_gt": 50},
            {"tag": "slow", "time_gt_ms": 100},
            {"tag": "miss", "status": 404},
        ],
        baseline=baseline,
    )
    assert "s200" in tags
    assert "len" in tags
    assert "slow" in tags
    assert "miss" not in tags


def test_timing_acquire_rate() -> None:
    async def _run() -> None:
        tc = TimingController(mode="fixed", rps=100.0, max_concurrency=1)
        await tc.acquire()
        tc.release()
        await tc.acquire()
        tc.release()

    asyncio.run(_run())


# ------------------------------------------------------------------ #
# Config validation                                                    #
# ------------------------------------------------------------------ #

def test_validate_config_path_gate() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/users/42"
    cfg["template"]["normalized_path"] = "/users/42"
    cfg["template"]["variables"] = [
        {"name": "user_id", "location": "path"},
    ]
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 3}},
    }
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg)
    assert ei.value.code == ERR_PATH_INJECT_UNAVAILABLE


def test_validate_numbers_ok() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?id=1"
    cfg["template"]["variables"] = [
        {"name": "id", "location": "query", "path": "id"},
    ]
    cfg["payload_sets"] = {
        "id": {"generator": "numbers", "options": {"start": 1, "end": 10}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "id"}}
    out, est = validate_config(cfg)
    assert est == 10
    assert out["strategy"]["type"] == "single"


# ------------------------------------------------------------------ #
# Engine segment (mocked HTTP)                                         #
# ------------------------------------------------------------------ #

def test_engine_segment_right_now(db_path: Path, tmp_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)
    from talos.intruder.session import create_session_from_flow, run_session
    from talos.intruder.engine import run_session_segment

    sess = create_session_from_flow(db_path, "proj", fid, name="enum")
    cfg = sess["config"]
    cfg["template"]["variables"] = [
        {"name": "user_id", "location": "path"},
    ]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 3}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "user_id"}}
    cfg["timing"] = {"mode": "unlimited", "rps": 0, "max_concurrency": 1, "timeout_s": 5}
    cfg["slice"] = {"max_attempts": 100, "max_wall_s": 60}
    cfg["match"] = [{"tag": "ok", "status": 200}]
    cfg["safety"]["require_in_scope"] = False
    idb.update_session(db_path, sess["id"], config=cfg, status="configured")

    client_cls = MagicMock()
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b'{"ok":1}'
    resp.headers = {"content-type": "application/json"}
    client.request = AsyncMock(return_value=resp)
    client_cls.return_value = client

    with patch("talos.intruder.engine.httpx.AsyncClient", client_cls):
        with patch("talos.intruder.engine.get_upstream_url", return_value=None):
            outcome = asyncio.run(
                run_session_segment(sess["id"], db_path, "proj", job_id=None)
            )

    assert outcome.reason == "completed"
    assert outcome.attempts_this_segment == 3
    final = idb.get_session(db_path, sess["id"])
    assert final["status"] == "completed"
    assert final["progress"]["sent"] == 3
    assert idb.count_results(db_path, sess["id"]) == 3
    assert client.request.await_count == 3


def test_engine_pause_via_control_flag(db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)
    from talos.intruder.session import create_session_from_flow
    from talos.intruder.engine import run_session_segment

    sess = create_session_from_flow(db_path, "proj", fid, name="p")
    cfg = sess["config"]
    cfg["template"]["variables"] = [{"name": "user_id", "location": "path"}]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 100}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "user_id"}}
    cfg["timing"] = {"mode": "unlimited", "rps": 0, "max_concurrency": 1, "timeout_s": 5}
    cfg["slice"] = {"max_attempts": 100, "max_wall_s": 60}
    idb.update_session(db_path, sess["id"], config=cfg, status="configured")
    idb.set_control_flag(db_path, sess["id"], "pause")

    client_cls = MagicMock()
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.request = AsyncMock()
    client_cls.return_value = client

    with patch("talos.intruder.engine.httpx.AsyncClient", client_cls):
        with patch("talos.intruder.engine.get_upstream_url", return_value=None):
            outcome = asyncio.run(
                run_session_segment(sess["id"], db_path, "proj")
            )

    assert outcome.reason == "paused"
    assert outcome.attempts_this_segment == 0
    final = idb.get_session(db_path, sess["id"])
    assert final["status"] == "paused"


def test_time_slice_continue(db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)
    from talos.intruder.session import create_session_from_flow
    from talos.intruder.engine import run_session_segment

    sess = create_session_from_flow(db_path, "proj", fid, name="slice")
    cfg = sess["config"]
    cfg["template"]["variables"] = [{"name": "user_id", "location": "path"}]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 50}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "user_id"}}
    cfg["timing"] = {"mode": "unlimited", "rps": 0, "max_concurrency": 1, "timeout_s": 5}
    cfg["slice"] = {"max_attempts": 5, "max_wall_s": 60}
    idb.update_session(db_path, sess["id"], config=cfg, status="configured")

    client_cls = MagicMock()
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"ok"
    resp.headers = {}
    client.request = AsyncMock(return_value=resp)
    client_cls.return_value = client

    with patch("talos.intruder.engine.httpx.AsyncClient", client_cls):
        with patch("talos.intruder.engine.get_upstream_url", return_value=None):
            outcome = asyncio.run(
                run_session_segment(sess["id"], db_path, "proj")
            )

    assert outcome.reason == "continue"
    assert outcome.attempts_this_segment == 5
    final = idb.get_session(db_path, sess["id"])
    assert final["status"] == "running"
    assert final["progress"]["sent"] == 5
    # Checkpoint allows resume without unique violation
    with patch("talos.intruder.engine.httpx.AsyncClient", client_cls):
        with patch("talos.intruder.engine.get_upstream_url", return_value=None):
            outcome2 = asyncio.run(
                run_session_segment(sess["id"], db_path, "proj")
            )
    assert outcome2.attempts_this_segment == 5
    assert idb.count_results(db_path, sess["id"]) == 10


# ------------------------------------------------------------------ #
# CLI                                                                  #
# ------------------------------------------------------------------ #

def test_cli_create_configure_run_enqueue(manager: MagicMock, db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["session", "create", "--from", fid, "--name", "t", "--format", "json"])
    created = json.loads(buf.getvalue())
    sid = created["session_id"]

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "template", "set-var", sid,
                "--name", "user_id", "--location", "path",
                "--format", "json",
            ],
        )
    # Fix normalized_path on config
    sess = idb.get_session(db_path, sid)
    cfg = sess["config"]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    idb.update_session(db_path, sid, config=cfg)

    with redirect_stdout(io.StringIO()):
        run_intruder_cli(
            manager,
            [
                "payload", "set", sid,
                "--var", "user_id",
                "--generator", "numbers",
                "--start", "1",
                "--end", "5",
                "--format", "json",
            ],
        )
        run_intruder_cli(
            manager,
            ["strategy", "set", sid, "--type", "single", "--primary", "user_id", "--format", "json"],
        )
        run_intruder_cli(
            manager,
            ["timing", "set", sid, "--mode", "fixed", "--rps", "5", "--concurrency", "1", "--format", "json"],
        )
        run_intruder_cli(
            manager,
            ["match", "add", sid, "--status", "200", "--tag", "ok", "--format", "json"],
        )

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["session", "run", sid, "--format", "json", "--force"])
    ack = json.loads(buf.getvalue())
    assert ack["status"] == "queued"
    assert ack["job_id"]
    assert ack["execution_mode"] == "scheduler"

    # Job enqueued as intruder_session PRIORITY_MANUAL
    import talos.scheduler.db as sched_db
    job = sched_db.get_job(db_path, "proj", ack["job_id"])
    assert job is not None
    assert job.job_type == INTRUDER_SESSION
    assert job.priority == PRIORITY_MANUAL


def test_cli_export(manager: MagicMock, db_path: Path, tmp_path: Path) -> None:
    sess = idb.create_session(db_path, "proj", name="e")
    idb.insert_results_batch(
        db_path,
        sess["id"],
        [
            {
                "attempt_index": 0,
                "variables": {"a": "1"},
                "status_code": 200,
                "success": True,
                "duration_ms": 1.0,
                "interesting": True,
                "match_tags": ["t"],
            }
        ],
    )
    out = tmp_path / "export"
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["results", "export", sess["id"], "--out", str(out), "--jsonl", "--csv", "--format", "json"],
        )
    data = json.loads(buf.getvalue())
    assert data["exported"] == 1
    assert Path(data["jsonl"]).is_file()
    assert Path(data["csv"]).is_file()


def test_intruder_job_type_registered() -> None:
    assert INTRUDER_SESSION in JOB_TYPES
    assert PRIORITY_AUTO == 10
    assert PRIORITY_MANUAL == 100


def test_talos_helper_documents_intruder() -> None:
    from talos.__main__ import _print_usage
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert "intruder" in text
    assert "session create" in text
    assert "sniper" in text


def test_interesting_flow_skips_error_intel(db_path: Path) -> None:
    """insert_intruder_flow must not call error_intel hooks."""
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()[0]
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()[0]
    fid = str(uuid.uuid4())
    with patch("talos.replay.db._maybe_error_intel_on_replay") as hook:
        idb.insert_intruder_flow(
            db_path,
            {
                "id": fid,
                "project_id": "proj",
                "captured_at": "2020-01-01T00:00:00+00:00",
                "method": "GET",
                "url": "https://ex.test/",
                "host": "ex.test",
                "path": "/",
                "query": "",
                "request_headers": {},
                "request_cookies": {},
                "request_body": None,
                "status_code": 200,
                "response_headers": {},
                "response_body": b"x",
                "content_type": "text/plain",
                "role_id": role,
                "module_id": mod,
                "original_flow_id": None,
                "flow_meta": {"generated_by": "intruder"},
            },
        )
        hook.assert_not_called()
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT source FROM flows WHERE id = ?", (fid,)).fetchone()
    assert row[0] == "intruder"
