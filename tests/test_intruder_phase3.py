"""
Phase 3 Intruder tests: grep extract, pools, uuid/csv/json/example_values
generators, template from-params, schema v47.
"""

from __future__ import annotations

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
from talos.intruder.grep import evaluate_grep_rules, rules_to_pool, validate_grep_rule
from talos.intruder.models import (
    ERR_INVALID_GREP,
    ERR_POOL_NOT_FOUND,
    GEN_CSV,
    GEN_EXAMPLE_VALUES,
    GEN_JSON,
    GEN_POOL,
    GEN_UUID,
    KNOWN_GENERATORS,
)
from talos.projects.db import SCHEMA_VERSION, init_project_db


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


def _insert_endpoint(db_path: Path, normalized_path: str = "/users/{user_id}") -> str:
    eid = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints (
                id, project_id, method, host, path, normalized_path,
                first_seen, last_seen
            ) VALUES (?, 'proj', 'GET', 'https://ex.test', '/users/42', ?,
                      '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')
            """,
            (eid, normalized_path),
        )
        conn.commit()
    return eid


def _insert_param(
    db_path: Path,
    endpoint_id: str,
    *,
    name: str = "user_id",
    location: str = "path",
    examples: list | None = None,
) -> str:
    pid = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO parameters (
                id, endpoint_id, name, location, param_type, semantic_type,
                example_values, seen_count
            ) VALUES (?, ?, ?, ?, 'string', 'integer', ?, 3)
            """,
            (pid, endpoint_id, name, location, json.dumps(examples or ["1", "2", "42"])),
        )
        conn.commit()
    return pid


def _insert_capture(
    db_path: Path,
    *,
    url: str = "https://ex.test/users/42",
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
                'GET', ?, 'ex.test', '/users/42', '',
                '{}', '{}', NULL, 0, 200, '{}', ?, 0, 'application/json',
                ?, ?, 'proxy_capture', ?
            )
            """,
            (fid, url, b'{"ok":true}', role, mod, endpoint_id),
        )
        conn.commit()
    return fid


# ------------------------------------------------------------------ #
# Schema                                                               #
# ------------------------------------------------------------------ #


def test_schema_version_47_has_intruder_pools(db_path: Path) -> None:
    assert SCHEMA_VERSION >= 47
    with sqlite3.connect(str(db_path)) as conn:
        ver = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert ver >= 47
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "intruder_pools" in tables


# ------------------------------------------------------------------ #
# Grep                                                                 #
# ------------------------------------------------------------------ #


def test_evaluate_grep_rules_body_and_header() -> None:
    metrics = {
        "body_text": '{"token":"abc-123","other":1} and also "token":"abc-123"',
        "status_code": 200,
    }
    headers = {"X-Request-Id": "req-99", "Content-Type": "application/json"}
    rules = [
        {
            "name": "token",
            "regex": r'"token"\s*:\s*"([^"]+)"',
            "group": 1,
            "tag_interesting": True,
        },
        {
            "name": "rid",
            "regex": r"req-\d+",
            "group": 0,
            "source": "header:X-Request-Id",
        },
    ]
    grepped, tags = evaluate_grep_rules(metrics, rules, response_headers=headers)
    assert grepped["token"] == ["abc-123"]  # unique captures only
    assert grepped["rid"] == ["req-99"]
    assert tags == ["token"]
    pools = rules_to_pool(grepped, rules)
    assert "token" in pools and "rid" in pools


def test_validate_grep_rule_rejects_bad_regex() -> None:
    with pytest.raises(ValueError) as ei:
        validate_grep_rule({"name": "x", "regex": "("})
    assert str(ei.value).startswith(ERR_INVALID_GREP)


# ------------------------------------------------------------------ #
# Generators                                                           #
# ------------------------------------------------------------------ #


def test_uuid_generator_count() -> None:
    gen = build_generator(GEN_UUID, {"count": 5})
    vals = list(gen)
    assert len(vals) == 5
    assert gen.estimate_count() == 5
    # all unique UUID-shaped
    assert len(set(vals)) == 5
    for v in vals:
        uuid.UUID(v)


def test_csv_generator(tmp_path: Path) -> None:
    p = tmp_path / "ids.csv"
    p.write_text("id,name\n10,alice\n20,bob\n", encoding="utf-8")
    gen = build_generator(GEN_CSV, {"path": str(p), "column": "id"})
    assert list(gen) == ["10", "20"]

    gen2 = build_generator(GEN_CSV, {"path": str(p), "column": 1, "has_header": True})
    assert list(gen2) == ["alice", "bob"]


def test_json_generator_paths(tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    p.write_text(
        json.dumps({"ids": [1, 2], "users": [{"id": "a"}, {"id": "b"}]}),
        encoding="utf-8",
    )
    gen = build_generator(GEN_JSON, {"path": str(p), "json_path": "ids"})
    assert list(gen) == ["1", "2"]
    gen2 = build_generator(GEN_JSON, {"path": str(p), "json_path": "users[].id"})
    assert list(gen2) == ["a", "b"]


def test_example_values_generator(db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    pid = _insert_param(db_path, eid, examples=["aa", "bb"])
    gen = build_generator(
        GEN_EXAMPLE_VALUES,
        {"param_id": pid, "db_path": str(db_path)},
    )
    assert list(gen) == ["aa", "bb"]


def test_pool_generator_roundtrip(db_path: Path) -> None:
    idb.upsert_pool_values(db_path, "proj", "tokens", ["t1", "t2", "t1"])
    pool = idb.get_pool(db_path, "proj", "tokens")
    assert pool is not None
    assert pool["values"] == ["t1", "t2"]
    assert pool["count"] == 2

    gen = build_generator(
        GEN_POOL,
        {"name": "tokens", "db_path": str(db_path), "project_id": "proj"},
    )
    assert list(gen) == ["t1", "t2"]


def test_pool_generator_missing(db_path: Path) -> None:
    with pytest.raises(ValueError) as ei:
        build_generator(
            GEN_POOL,
            {"name": "nope", "db_path": str(db_path), "project_id": "proj"},
        )
    assert ERR_POOL_NOT_FOUND in str(ei.value)


def test_known_generators_include_phase3() -> None:
    for g in (GEN_UUID, GEN_CSV, GEN_JSON, GEN_EXAMPLE_VALUES, GEN_POOL):
        assert g in KNOWN_GENERATORS


# ------------------------------------------------------------------ #
# Config validation                                                    #
# ------------------------------------------------------------------ #


def test_validate_config_with_uuid_generator(db_path: Path) -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/x?q={{q}}"
    cfg["template"]["variables"] = [{"name": "q", "location": "query", "path": "q"}]
    cfg["payload_sets"] = {
        "q": {"generator": "uuid", "options": {"count": 3}, "processors": []},
    }
    cfg["strategy"] = {"type": "single", "options": {"primary": "q"}}
    out, estimate = validate_config(cfg, open_generators=True, db_path=db_path, project_id="proj")
    assert estimate == 3
    assert out["strategy"]["type"] == "single"


def test_validate_grep_in_config() -> None:
    cfg = default_config()
    cfg["template"]["method"] = "GET"
    cfg["template"]["url"] = "https://ex.test/"
    cfg["template"]["variables"] = [{"name": "q", "location": "query"}]
    cfg["payload_sets"] = {
        "q": {"generator": "static", "options": {"values": ["a"]}, "processors": []},
    }
    cfg["grep"] = [{"name": "tok", "regex": r"x(y)"}]
    out, _ = validate_config(cfg, open_generators=True)
    assert len(out["grep"]) == 1

    cfg["grep"] = [{"name": "", "regex": "a"}]
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg, open_generators=True)
    assert ei.value.code == ERR_INVALID_GREP


# ------------------------------------------------------------------ #
# CLI                                                                  #
# ------------------------------------------------------------------ #


def _create_session(manager: MagicMock, fid: str) -> str:
    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["session", "create", "--from", fid, "--format", "json"])
    return json.loads(out.getvalue())["session_id"]


def test_cli_grep_and_pool(manager: MagicMock, db_path: Path) -> None:
    fid = _insert_capture(db_path)
    sid = _create_session(manager, fid)

    run_intruder_cli(
        manager,
        [
            "grep", "add", sid,
            "--name", "token",
            "--regex", r'"token"\s*:\s*"([^"]+)"',
            "--tag-interesting",
            "--format", "json",
        ],
    )
    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["grep", "list", sid, "--format", "json"])
    data = json.loads(out.getvalue())
    assert len(data["grep"]) == 1
    assert data["grep"][0]["name"] == "token"

    idb.upsert_pool_values(db_path, "proj", "token", ["a", "b"])
    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["pool", "list", "--format", "json"])
    pools = json.loads(out.getvalue())
    assert any(p["name"] == "token" for p in pools)

    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["pool", "show", "token", "--format", "json"])
    shown = json.loads(out.getvalue())
    assert shown["values"] == ["a", "b"]


def test_cli_template_from_params(manager: MagicMock, db_path: Path) -> None:
    eid = _insert_endpoint(db_path)
    _insert_param(db_path, eid, name="user_id", location="path", examples=["9"])
    _insert_param(db_path, eid, name="role", location="query", examples=["admin"])
    fid = _insert_capture(db_path, endpoint_id=eid)
    sid = _create_session(manager, fid)

    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(
            manager,
            ["template", "from-params", sid, "--set-payloads", "--format", "json"],
        )
    result = json.loads(out.getvalue())
    assert result["added"] >= 2

    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["template", "show", sid, "--format", "json"])
    tmpl = json.loads(out.getvalue())
    names = {v["name"] for v in tmpl["variables"]}
    assert "user_id" in names
    assert "role" in names

    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["payload", "list", sid, "--format", "json"])
    payloads = json.loads(out.getvalue())
    assert payloads["payload_sets"]["user_id"]["generator"] == "example_values"


def test_cli_payload_uuid_csv_json(manager: MagicMock, db_path: Path, tmp_path: Path) -> None:
    fid = _insert_capture(db_path)
    sid = _create_session(manager, fid)

    run_intruder_cli(
        manager,
        ["template", "set-var", sid, "--name", "q", "--location", "query", "--format", "json"],
    )
    run_intruder_cli(
        manager,
        ["payload", "set", sid, "--var", "q", "--generator", "uuid", "--count", "3", "--format", "json"],
    )

    csv_path = tmp_path / "c.csv"
    csv_path.write_text("v\nx\ny\n", encoding="utf-8")
    run_intruder_cli(
        manager,
        [
            "payload", "set", sid, "--var", "q", "--generator", "csv",
            "--file", str(csv_path), "--column", "v", "--format", "json",
        ],
    )
    json_path = tmp_path / "j.json"
    json_path.write_text(json.dumps(["p", "q"]), encoding="utf-8")
    run_intruder_cli(
        manager,
        [
            "payload", "set", sid, "--var", "q", "--generator", "json",
            "--file", str(json_path), "--format", "json",
        ],
    )
    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["payload", "list", sid, "--format", "json"])
    data = json.loads(out.getvalue())
    assert data["payload_sets"]["q"]["generator"] == "json"


def test_cli_generators_list_phase3(manager: MagicMock) -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        run_intruder_cli(manager, ["generators", "list", "--format", "json"])
    data = json.loads(out.getvalue())
    assert "uuid" in data["generators"]
    assert "pool" in data["generators"]
    assert data["phase3"]["grep"] is True
