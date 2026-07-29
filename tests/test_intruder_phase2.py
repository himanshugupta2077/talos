"""
Phase 2 Intruder tests: multi-set strategies, processors, storage modes,
session clone, host concurrency caps, CLI surface.
"""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.intruder import db as idb
from talos.intruder.cli import run_intruder_cli
from talos.intruder.config_schema import ValidationError, default_config, validate_config
from talos.intruder.generators import build_generator
from talos.intruder.models import (
    ERR_UNBOUND_VARIABLE,
    STORAGE_ALL_FLOWS,
    STORAGE_SAMPLE_FLOWS,
)
from talos.intruder.processors import apply_processors, build_processor, is_known_processor
from talos.intruder.strategies import build_strategy
from talos.intruder.timing import TimingController
from talos.projects.db import init_project_db


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
# Strategies                                                           #
# ------------------------------------------------------------------ #

def test_pitchfork_strategy_lockstep() -> None:
    a = build_generator("static", {"values": ["1", "2", "3"]})
    b = build_generator("static", {"values": ["x", "y"]})
    strat = build_strategy(
        "pitchfork",
        ["a", "b"],
        {"a": a, "b": b},
        options={"sets": ["a", "b"]},
    )
    seen = []
    while True:
        n = strat.next()
        if n is None:
            break
        seen.append(n)
    # Stops at shortest set length (2)
    assert seen == [{"a": "1", "b": "x"}, {"a": "2", "b": "y"}]
    assert strat.progress()["total_estimate"] == 2


def test_zip_alias_of_pitchfork() -> None:
    a = build_generator("static", {"values": ["1", "2"]})
    b = build_generator("static", {"values": ["x", "y"]})
    strat = build_strategy("zip", ["a", "b"], {"a": a, "b": b}, options={"sets": ["a", "b"]})
    assert strat.next() == {"a": "1", "b": "x"}
    assert strat.next() == {"a": "2", "b": "y"}
    assert strat.next() is None


def test_cluster_bomb_cartesian() -> None:
    a = build_generator("static", {"values": ["1", "2"]})
    b = build_generator("static", {"values": ["x", "y"]})
    strat = build_strategy(
        "cluster_bomb",
        ["a", "b"],
        {"a": a, "b": b},
        options={"sets": ["a", "b"]},
    )
    seen = []
    while True:
        n = strat.next()
        if n is None:
            break
        seen.append(n)
    assert seen == [
        {"a": "1", "b": "x"},
        {"a": "1", "b": "y"},
        {"a": "2", "b": "x"},
        {"a": "2", "b": "y"},
    ]
    assert strat.progress()["total_estimate"] == 4


def test_cluster_bomb_checkpoint_restore() -> None:
    a = build_generator("static", {"values": ["1", "2"]})
    b = build_generator("static", {"values": ["x", "y"]})
    strat = build_strategy(
        "cluster_bomb",
        ["a", "b"],
        {"a": a, "b": b},
        options={"sets": ["a", "b"]},
    )
    assert strat.next() == {"a": "1", "b": "x"}
    cp = strat.checkpoint()
    # Rebuild and restore
    a2 = build_generator("static", {"values": ["1", "2"]})
    b2 = build_generator("static", {"values": ["x", "y"]})
    strat2 = build_strategy(
        "cluster_bomb",
        ["a", "b"],
        {"a": a2, "b": b2},
        options={"sets": ["a", "b"]},
    )
    strat2.restore(cp)
    rest = []
    while True:
        n = strat2.next()
        if n is None:
            break
        rest.append(n)
    assert rest == [
        {"a": "1", "b": "y"},
        {"a": "2", "b": "x"},
        {"a": "2", "b": "y"},
    ]


def test_pitchfork_checkpoint_restore() -> None:
    a = build_generator("numbers", {"start": 1, "end": 5})
    b = build_generator("static", {"values": ["x", "y", "z"]})
    strat = build_strategy(
        "pitchfork",
        ["a", "b"],
        {"a": a, "b": b},
        options={"sets": ["a", "b"]},
    )
    assert strat.next() == {"a": "1", "b": "x"}
    cp = strat.checkpoint()
    a2 = build_generator("numbers", {"start": 1, "end": 5})
    b2 = build_generator("static", {"values": ["x", "y", "z"]})
    strat2 = build_strategy(
        "pitchfork",
        ["a", "b"],
        {"a": a2, "b": b2},
        options={"sets": ["a", "b"]},
    )
    strat2.restore(cp)
    assert strat2.next() == {"a": "2", "b": "y"}


# ------------------------------------------------------------------ #
# Processors                                                           #
# ------------------------------------------------------------------ #

def test_phase2_processors() -> None:
    assert build_processor("url_decode").process("%61%62") == "ab"
    assert build_processor("to_upper").process("ab") == "AB"
    assert build_processor("to_lower").process("AB") == "ab"
    assert build_processor("strip").process("  x  ") == "x"
    assert build_processor("html_encode").process("<a>") == "&lt;a&gt;"
    assert len(build_processor("md5").process("hi")) == 32
    assert len(build_processor("sha256").process("hi")) == 64
    assert build_processor("prefix:pre-").process("x") == "pre-x"
    assert build_processor("suffix:-suf").process("x") == "x-suf"
    b64 = build_processor("base64_encode").process("hi")
    assert build_processor("base64_decode").process(b64) == "hi"
    chain = apply_processors("Ab ", ["strip", "to_lower", "prefix:p:"])
    assert chain == "p:ab"
    assert is_known_processor("prefix:foo")
    assert is_known_processor("sha1")
    assert not is_known_processor("not_a_real_proc")


# ------------------------------------------------------------------ #
# Config validation                                                    #
# ------------------------------------------------------------------ #

def test_validate_cluster_bomb_estimate() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?a=1&b=2"
    cfg["template"]["variables"] = [
        {"name": "a", "location": "query", "path": "a"},
        {"name": "b", "location": "query", "path": "b"},
    ]
    cfg["payload_sets"] = {
        "a": {"generator": "static", "options": {"values": ["1", "2", "3"]}},
        "b": {"generator": "static", "options": {"values": ["x", "y"]}},
    }
    cfg["strategy"] = {"type": "cluster_bomb", "options": {"sets": ["a", "b"]}}
    out, est = validate_config(cfg)
    assert est == 6
    assert out["strategy"]["type"] == "cluster_bomb"


def test_validate_pitchfork_estimate_min() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?a=1&b=2"
    cfg["template"]["variables"] = [
        {"name": "a", "location": "query", "path": "a"},
        {"name": "b", "location": "query", "path": "b"},
    ]
    cfg["payload_sets"] = {
        "a": {"generator": "numbers", "options": {"start": 1, "end": 10}},
        "b": {"generator": "static", "options": {"values": ["x", "y"]}},
    }
    cfg["strategy"] = {"type": "pitchfork"}
    out, est = validate_config(cfg)
    assert est == 2
    assert out["strategy"]["options"]["sets"] == ["a", "b"]


def test_validate_cartesian_alias() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?a=1&b=2"
    cfg["template"]["variables"] = [
        {"name": "a", "location": "query", "path": "a"},
        {"name": "b", "location": "query", "path": "b"},
    ]
    cfg["payload_sets"] = {
        "a": {"generator": "static", "options": {"values": ["1"]}},
        "b": {"generator": "static", "options": {"values": ["x"]}},
    }
    cfg["strategy"] = {"type": "cartesian"}
    out, est = validate_config(cfg)
    assert out["strategy"]["type"] == "cluster_bomb"
    assert est == 1


def test_validate_storage_modes() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?id=1"
    cfg["template"]["variables"] = [{"name": "id", "location": "query", "path": "id"}]
    cfg["payload_sets"] = {
        "id": {"generator": "static", "options": {"values": ["1"]}},
    }
    cfg["storage"] = {"mode": "all_flows", "sample_rate": 0.5}
    out, _ = validate_config(cfg)
    assert out["storage"]["mode"] == STORAGE_ALL_FLOWS

    cfg["storage"] = {"mode": "bogus"}
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg)
    assert ei.value.code == "invalid_storage_mode"


def test_validate_multiset_missing_var() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/?a=1"
    cfg["template"]["variables"] = [{"name": "a", "location": "query", "path": "a"}]
    cfg["payload_sets"] = {
        "a": {"generator": "static", "options": {"values": ["1"]}},
        "missing": {"generator": "static", "options": {"values": ["x"]}},
    }
    cfg["strategy"] = {"type": "pitchfork", "options": {"sets": ["a", "missing"]}}
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg)
    assert ei.value.code == ERR_UNBOUND_VARIABLE


# ------------------------------------------------------------------ #
# Engine storage modes                                                 #
# ------------------------------------------------------------------ #

def test_engine_all_flows_storage(db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)
    from talos.intruder.session import create_session_from_flow
    from talos.intruder.engine import run_session_segment

    sess = create_session_from_flow(db_path, "proj", fid, name="all")
    cfg = sess["config"]
    cfg["template"]["variables"] = [{"name": "user_id", "location": "path"}]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 3}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "user_id"}}
    cfg["timing"] = {"mode": "unlimited", "rps": 0, "max_concurrency": 1, "timeout_s": 5}
    cfg["storage"] = {
        "mode": STORAGE_ALL_FLOWS,
        "store_interesting_bodies": False,
        "max_body_bytes": 65536,
        "max_results": 10000,
    }
    cfg["match"] = []  # no interesting tags
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
            outcome = asyncio.run(run_session_segment(sess["id"], db_path, "proj"))

    assert outcome.reason == "completed"
    results = idb.list_results(db_path, sess["id"])
    assert len(results) == 3
    assert all(r.get("flow_id") for r in results)
    with sqlite3.connect(str(db_path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE source = 'intruder'"
        ).fetchone()[0]
    assert n == 3


def test_engine_pitchfork_segment(db_path: Path) -> None:
    eid = _insert_endpoint(db_path, normalized_path="/users/{user_id}/orders")
    fid = _insert_capture(
        db_path,
        url="https://ex.test/users/42/orders?role=admin",
        endpoint_id=eid,
    )
    from talos.intruder.session import create_session_from_flow
    from talos.intruder.engine import run_session_segment

    sess = create_session_from_flow(db_path, "proj", fid, name="pf")
    cfg = sess["config"]
    cfg["template"]["variables"] = [
        {"name": "user_id", "location": "path"},
        {"name": "role", "location": "query", "path": "role"},
    ]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    cfg["payload_sets"] = {
        "user_id": {"generator": "static", "options": {"values": ["1", "2"]}},
        "role": {"generator": "static", "options": {"values": ["a", "b"]}},
    }
    cfg["strategy"] = {"type": "pitchfork", "options": {"sets": ["user_id", "role"]}}
    cfg["timing"] = {"mode": "unlimited", "rps": 0, "max_concurrency": 1, "timeout_s": 5}
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
            outcome = asyncio.run(run_session_segment(sess["id"], db_path, "proj"))

    assert outcome.reason == "completed"
    assert outcome.attempts_this_segment == 2
    results = idb.list_results(db_path, sess["id"])
    assert results[0]["variables"] == {"user_id": "1", "role": "a"}
    assert results[1]["variables"] == {"user_id": "2", "role": "b"}


# ------------------------------------------------------------------ #
# Timing host cap                                                      #
# ------------------------------------------------------------------ #

def test_timing_per_host_cap() -> None:
    async def _run() -> None:
        tc = TimingController(
            mode="unlimited",
            rps=0,
            max_concurrency=4,
            max_concurrency_per_host=1,
        )
        await tc.acquire(host="a.example")
        # Same host should block if we don't release — use timeout via wait_for
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(tc.acquire(host="a.example"), timeout=0.05)
        # Different host OK
        await tc.acquire(host="b.example")
        tc.release(host="b.example")
        tc.release(host="a.example")
        await tc.acquire(host="a.example")
        tc.release(host="a.example")

    asyncio.run(_run())


# ------------------------------------------------------------------ #
# Session clone + CLI                                                  #
# ------------------------------------------------------------------ #

def test_session_clone(db_path: Path) -> None:
    from talos.intruder.session import clone_session, create_session_from_flow

    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)
    sess = create_session_from_flow(db_path, "proj", fid, name="orig")
    cfg = sess["config"]
    cfg["payload_sets"] = {
        "user_id": {"generator": "numbers", "options": {"start": 1, "end": 5}},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "user_id"}}
    idb.update_session(db_path, sess["id"], config=cfg, status="configured")
    idb.insert_results_batch(
        db_path,
        sess["id"],
        [{"attempt_index": 0, "variables": {"user_id": "1"}, "status_code": 200, "success": True}],
        checkpoint={"attempt_index": 0},
        progress={"sent": 1},
    )

    cloned = clone_session(db_path, "proj", sess["id"], name="copy")
    assert cloned["id"] != sess["id"]
    assert cloned["status"] == "draft"
    assert cloned["name"] == "copy"
    assert cloned["base_flow_id"] == fid
    assert (cloned["config"].get("payload_sets") or {}).get("user_id")
    assert idb.count_results(db_path, cloned["id"]) == 0
    assert idb.count_results(db_path, sess["id"]) == 1


def test_cli_strategy_storage_clone(manager: MagicMock, db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    fid = _insert_capture(db_path, endpoint_id=eid)

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["session", "create", "--from", fid, "--name", "p2", "--format", "json"],
        )
    sid = json.loads(buf.getvalue())["session_id"]

    sess = idb.get_session(db_path, sid)
    cfg = sess["config"]
    cfg["template"]["variables"] = [
        {"name": "user_id", "location": "path"},
        {"name": "role", "location": "query", "path": "role"},
    ]
    cfg["template"]["normalized_path"] = "/users/{user_id}/orders"
    idb.update_session(db_path, sid, config=cfg)

    with redirect_stdout(io.StringIO()):
        run_intruder_cli(
            manager,
            [
                "payload", "set", sid,
                "--var", "user_id",
                "--generator", "static",
                "--value", "1", "--value", "2",
                "--processor", "to_upper",
                "--format", "json",
            ],
        )
        run_intruder_cli(
            manager,
            [
                "payload", "set", sid,
                "--var", "role",
                "--generator", "static",
                "--value", "a", "--value", "b",
                "--processor", "prefix:r-",
                "--format", "json",
            ],
        )
        run_intruder_cli(
            manager,
            [
                "strategy", "set", sid,
                "--type", "cluster_bomb",
                "--set", "user_id", "--set", "role",
                "--format", "json",
            ],
        )
        run_intruder_cli(
            manager,
            [
                "storage", "set", sid,
                "--mode", "sample_flows",
                "--sample-rate", "0.25",
                "--format", "json",
            ],
        )
        run_intruder_cli(
            manager,
            [
                "timing", "set", sid,
                "--mode", "fixed",
                "--rps", "5",
                "--concurrency", "2",
                "--concurrency-per-host", "1",
                "--format", "json",
            ],
        )

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["session", "validate", sid, "--format", "json", "--force"])
    val = json.loads(buf.getvalue())
    assert val["valid"] is True
    assert val["estimate_attempts"] == 4

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["session", "clone", sid, "--name", "p2-clone", "--format", "json"],
        )
    cloned = json.loads(buf.getvalue())
    assert cloned["name"] == "p2-clone"
    assert cloned["status"] == "draft"

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["generators", "list", "--format", "json"])
    inv = json.loads(buf.getvalue())
    assert "cluster_bomb" in inv["strategies"]
    assert "pitchfork" in inv["strategies"]
    assert STORAGE_SAMPLE_FLOWS in inv["storage_modes"]
    assert "md5" in inv["processors"]


def test_talos_helper_documents_phase2() -> None:
    from talos.__main__ import _print_usage

    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert "cluster_bomb" in text
    assert "pitchfork" in text
    assert "clone" in text
    assert "storage" in text
