"""
Phase 4 Intruder tests: adaptive/token_bucket timing, dates/bruteforce/
random/pattern generators, AI suggest CLI.
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
from unittest.mock import MagicMock

import pytest

from talos.intruder import db as idb
from talos.intruder.cli import run_intruder_cli
from talos.intruder.config_schema import ValidationError, default_config, validate_config
from talos.intruder.generators import build_generator
from talos.intruder.models import (
    ERR_BRUTEFORCE_TOO_LARGE,
    ERR_INVALID_DATES,
    ERR_INVALID_PATTERN,
    ERR_INVALID_TIMING,
    GEN_BRUTEFORCE,
    GEN_DATES,
    GEN_PATTERN,
    GEN_RANDOM,
    KNOWN_GENERATORS,
    KNOWN_TIMING_MODES,
    PHASE4_GENERATORS,
    AttemptResult,
)
from talos.intruder.suggest import apply_suggestions, build_suggestions
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
    url: str = "https://ex.test/api/users/42",
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
                'GET', ?, 'ex.test', '/api/users/42', '',
                '{}', '{}', NULL, 0, 200, '{}', ?, 0, 'application/json',
                ?, ?, 'proxy_capture', ?
            )
            """,
            (fid, url, b'{"ok":true,"token":"abc"}', role, mod, endpoint_id),
        )
        conn.commit()
    return fid


def _create_session(manager, db_path: Path) -> str:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["session", "create", "--from", fid, "--name", "p4", "--format", "json"],
        )
    out = json.loads(buf.getvalue())
    return out["session_id"]


# ------------------------------------------------------------------ #
# Generators                                                           #
# ------------------------------------------------------------------ #


def test_phase4_generators_registered() -> None:
    for g in PHASE4_GENERATORS:
        assert g in KNOWN_GENERATORS


def test_dates_generator() -> None:
    gen = build_generator(
        GEN_DATES,
        {"start": "2020-01-01", "end": "2020-01-03", "format": "%Y/%m/%d"},
    )
    assert list(gen) == ["2020/01/01", "2020/01/02", "2020/01/03"]
    assert gen.estimate_count() == 3


def test_dates_checkpoint_restore() -> None:
    gen = build_generator(GEN_DATES, {"start": "2020-01-01", "end": "2020-01-05"})
    it = iter(gen)
    assert next(it) == "2020-01-01"
    ck = gen.checkpoint()
    gen2 = build_generator(GEN_DATES, {"start": "2020-01-01", "end": "2020-01-05"})
    gen2.restore(ck)
    assert list(gen2) == ["2020-01-02", "2020-01-03", "2020-01-04", "2020-01-05"]


def test_dates_invalid_range() -> None:
    with pytest.raises(ValueError, match=ERR_INVALID_DATES):
        build_generator(GEN_DATES, {"start": "2020-02-01", "end": "2020-01-01"})


def test_bruteforce_generator() -> None:
    gen = build_generator(
        GEN_BRUTEFORCE,
        {"charset": "ab", "min_len": 1, "max_len": 2},
    )
    vals = list(gen)
    assert vals == ["a", "b", "aa", "ab", "ba", "bb"]
    assert gen.estimate_count() == 6


def test_bruteforce_too_large_without_force() -> None:
    with pytest.raises(ValueError, match=ERR_BRUTEFORCE_TOO_LARGE):
        build_generator(
            GEN_BRUTEFORCE,
            {"charset": "0123456789abcdef", "min_len": 1, "max_len": 5},
        )


def test_random_seeded_reproducible() -> None:
    a = list(build_generator(GEN_RANDOM, {"count": 5, "length": 6, "seed": 42}))
    b = list(build_generator(GEN_RANDOM, {"count": 5, "length": 6, "seed": 42}))
    c = list(build_generator(GEN_RANDOM, {"count": 5, "length": 6, "seed": 99}))
    assert a == b
    assert a != c
    assert all(len(x) == 6 for x in a)


def test_random_checkpoint_restore() -> None:
    gen = build_generator(GEN_RANDOM, {"count": 4, "length": 3, "seed": 7})
    it = iter(gen)
    first = next(it)
    ck = gen.checkpoint()
    gen2 = build_generator(GEN_RANDOM, {"count": 1, "length": 1, "seed": 0})
    gen2.restore(ck)
    rest = list(gen2)
    full = list(build_generator(GEN_RANDOM, {"count": 4, "length": 3, "seed": 7}))
    assert [first] + rest == full


def test_pattern_generator_formats() -> None:
    gen = build_generator(
        GEN_PATTERN,
        {"pattern": "user{n:03d}-{hex}", "start": 10, "end": 12},
    )
    assert list(gen) == ["user010-a", "user011-b", "user012-c"]


def test_pattern_static_no_placeholder() -> None:
    gen = build_generator(GEN_PATTERN, {"pattern": "fixed-value"})
    assert list(gen) == ["fixed-value"]


def test_pattern_bad_step() -> None:
    with pytest.raises(ValueError, match=ERR_INVALID_PATTERN):
        build_generator(GEN_PATTERN, {"pattern": "x{n}", "start": 1, "end": 5, "step": 0})


# ------------------------------------------------------------------ #
# Timing                                                               #
# ------------------------------------------------------------------ #


def test_known_timing_modes() -> None:
    assert "fixed" in KNOWN_TIMING_MODES
    assert "unlimited" in KNOWN_TIMING_MODES
    assert "token_bucket" in KNOWN_TIMING_MODES
    assert "adaptive" in KNOWN_TIMING_MODES


def test_token_bucket_burst() -> None:
    async def run() -> None:
        tc = TimingController(mode="token_bucket", rps=1.0, burst_size=3, jitter_ms=0)
        t0 = asyncio.get_event_loop().time()
        for _ in range(3):
            await tc.acquire()
            tc.release()
        elapsed = asyncio.get_event_loop().time() - t0
        # Burst of 3 should complete quickly without waiting full 1s intervals
        assert elapsed < 0.5

    asyncio.run(run())


def test_adaptive_slows_on_errors() -> None:
    async def run() -> None:
        tc = TimingController(
            mode="adaptive",
            rps=4.0,
            min_rps=0.5,
            max_rps=10.0,
            adaptive_window=4,
            down_factor=0.5,
            up_factor=1.2,
            slow_ms=1000,
            jitter_ms=0,
        )
        start = tc.effective_rps
        for i in range(4):
            await tc.acquire()
            tc.release()
            tc.note_response(
                AttemptResult(
                    attempt_index=i,
                    variables={},
                    status_code=429,
                    success=True,
                    failure_reason=None,
                    duration_ms=50.0,
                )
            )
        assert tc.effective_rps < start
        assert tc.effective_rps >= 0.5

    asyncio.run(run())


def test_adaptive_speeds_on_healthy() -> None:
    async def run() -> None:
        tc = TimingController(
            mode="adaptive",
            rps=1.0,
            min_rps=0.5,
            max_rps=5.0,
            adaptive_window=3,
            up_factor=1.5,
            down_factor=0.5,
            slow_ms=5000,
            jitter_ms=0,
        )
        # Force effective down first
        tc._effective_rps = 1.0
        for i in range(3):
            await tc.acquire()
            tc.release()
            tc.note_response(
                AttemptResult(
                    attempt_index=i,
                    variables={},
                    status_code=200,
                    success=True,
                    failure_reason=None,
                    duration_ms=10.0,
                )
            )
        assert tc.effective_rps > 1.0

    asyncio.run(run())


def test_timing_snapshot() -> None:
    tc = TimingController(mode="adaptive", rps=2.0, min_rps=0.5, max_rps=8.0)
    snap = tc.snapshot()
    assert snap["mode"] == "adaptive"
    assert snap["rps"] == 2.0
    assert "effective_rps" in snap


def test_validate_unknown_timing_mode() -> None:
    cfg = default_config()
    cfg["template"] = {
        "method": "GET",
        "url": "https://ex.test/x",
        "headers": {},
        "body": None,
        "variables": [{"name": "q", "location": "query", "path": "q"}],
        "normalized_path": "",
    }
    cfg["payload_sets"] = {
        "q": {"generator": "static", "options": {"values": ["a"]}, "processors": []},
    }
    cfg["timing"]["mode"] = "warp_drive"
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg, open_generators=True)
    assert ei.value.code == ERR_INVALID_TIMING


# ------------------------------------------------------------------ #
# Suggest                                                              #
# ------------------------------------------------------------------ #


def test_suggest_for_numeric_id(db_path: Path) -> None:
    cfg = default_config()
    cfg["template"] = {
        "method": "GET",
        "url": "https://ex.test/api/users/{{user_id}}",
        "headers": {},
        "body": None,
        "variables": [
            {
                "name": "user_id",
                "location": "path",
                "path": "user_id",
                "original_value": "42",
                "semantic_type": "integer",
            }
        ],
        "normalized_path": "/api/users/{user_id}",
    }
    session = {"id": "sess-1", "project_id": "proj", "config": cfg}
    sug = build_suggestions(session, cfg, db_path=db_path, project_id="proj")
    assert sug["schema"] == "intruder_suggest/v1"
    assert sug["strategy"]["type"] == "single"
    assert sug["timing"]["mode"] in ("adaptive", "fixed")
    payloads = {p["var"]: p for p in sug["payloads"]}
    assert payloads["user_id"]["payload_set"]["generator"] == "numbers"
    assert any("payload set" in c for c in sug["commands"])


def test_suggest_sniper_multi_var(db_path: Path) -> None:
    cfg = default_config()
    cfg["template"] = {
        "method": "GET",
        "url": "https://ex.test/x",
        "headers": {},
        "body": None,
        "variables": [
            {"name": "a", "location": "query", "path": "a"},
            {"name": "b", "location": "query", "path": "b"},
        ],
        "normalized_path": "",
    }
    sug = build_suggestions(
        {"id": "s", "project_id": "proj"},
        cfg,
        db_path=db_path,
        project_id="proj",
    )
    assert sug["strategy"]["type"] == "sniper"
    assert len(sug["payloads"]) == 2


def test_apply_suggestions_mutates_config(db_path: Path) -> None:
    cfg = default_config()
    cfg["template"] = {
        "method": "GET",
        "url": "https://ex.test/api/x",
        "headers": {},
        "body": None,
        "variables": [
            {"name": "pin", "location": "query", "path": "pin", "original_value": "1234"},
        ],
        "normalized_path": "",
    }
    sug = build_suggestions({"id": "s", "project_id": "p"}, cfg, db_path=db_path, project_id="p")
    out = apply_suggestions(cfg, sug, replace_payloads=True)
    assert out["strategy"]["type"] in ("single", "sniper")
    assert "pin" in out["payload_sets"]
    assert out["timing"]["mode"] in KNOWN_TIMING_MODES
    assert len(out["match"]) >= 1


# ------------------------------------------------------------------ #
# CLI                                                                  #
# ------------------------------------------------------------------ #


def test_cli_payload_dates(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "template", "set-var", sid,
                "--name", "d", "--location", "query", "--path", "d",
                "--format", "json",
            ],
        )
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "payload", "set", sid,
                "--var", "d",
                "--generator", "dates",
                "--start-date", "2020-01-01",
                "--end-date", "2020-01-02",
                "--format", "json",
            ],
        )
    out = json.loads(buf.getvalue())
    assert out["payload_set"]["generator"] == "dates"
    assert out["payload_set"]["options"]["start"] == "2020-01-01"


def test_cli_payload_bruteforce_pattern_random(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    for args in (
        [
            "payload", "set", sid, "--var", "bf", "--generator", "bruteforce",
            "--charset", "01", "--min-len", "1", "--max-len", "2", "--format", "json",
        ],
        [
            "payload", "set", sid, "--var", "pat", "--generator", "pattern",
            "--pattern", "u{n}", "--start", "1", "--end", "3", "--format", "json",
        ],
        [
            "payload", "set", sid, "--var", "rnd", "--generator", "random",
            "--count", "5", "--length", "4", "--seed", "1", "--format", "json",
        ],
    ):
        # need template vars for completeness (payload set alone is ok)
        var = args[args.index("--var") + 1]
        with redirect_stdout(io.StringIO()):
            run_intruder_cli(
                manager,
                [
                    "template", "set-var", sid,
                    "--name", var, "--location", "query", "--path", var,
                    "--format", "json",
                ],
            )
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_intruder_cli(manager, args)
        out = json.loads(buf.getvalue())
        assert out["payload_set"]["generator"] in PHASE4_GENERATORS


def test_cli_timing_adaptive(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "timing", "set", sid,
                "--mode", "adaptive",
                "--rps", "2",
                "--min-rps", "0.5",
                "--max-rps", "8",
                "--slow-ms", "1500",
                "--burst-size", "2",
                "--format", "json",
            ],
        )
    out = json.loads(buf.getvalue())
    assert out["timing"]["mode"] == "adaptive"
    assert out["timing"]["min_rps"] == 0.5
    assert out["timing"]["max_rps"] == 8.0
    assert out["timing"]["slow_ms"] == 1500.0
    assert out["timing"]["burst_size"] == 2


def test_cli_suggest_and_apply(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    with redirect_stdout(io.StringIO()):
        run_intruder_cli(
            manager,
            [
                "template", "set-var", sid,
                "--name", "user_id", "--location", "query", "--path", "user_id",
                "--format", "json",
            ],
        )
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["suggest", sid, "--format", "json"])
    sug = json.loads(buf.getvalue())
    assert sug["schema"] == "intruder_suggest/v1"
    assert sug["applied"] is False
    assert "user_id" in sug["injectable_variables"]

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["suggest", sid, "--apply", "--replace-payloads", "--format", "json"],
        )
    applied = json.loads(buf.getvalue())
    assert applied["applied"] is True

    sess = idb.get_session(db_path, sid)
    assert sess is not None
    cfg = sess["config"]
    assert "user_id" in (cfg.get("payload_sets") or {})
    assert (cfg.get("strategy") or {}).get("type") in ("single", "sniper")


def test_cli_generators_list_phase4(manager) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["generators", "list", "--format", "json"])
    out = json.loads(buf.getvalue())
    for g in PHASE4_GENERATORS:
        assert g in out["generators"]
    assert "adaptive" in out["timing_modes"]
    assert out["phase4"]["suggest"] is True


def test_validate_dates_payload(db_path: Path) -> None:
    cfg = default_config()
    cfg["template"] = {
        "method": "GET",
        "url": "https://ex.test/?d=1",
        "headers": {},
        "body": None,
        "variables": [{"name": "d", "location": "query", "path": "d"}],
        "normalized_path": "",
    }
    cfg["payload_sets"] = {
        "d": {
            "generator": "dates",
            "options": {"start": "2020-01-01", "end": "2020-01-02"},
            "processors": [],
        },
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "d"}}
    cfg["timing"]["mode"] = "token_bucket"
    cfg["timing"]["burst_size"] = 5
    norm, estimate = validate_config(cfg, open_generators=True, db_path=db_path, project_id="proj")
    assert estimate == 2
    assert norm["timing"]["mode"] == "token_bucket"
