"""
Phase 5 Intruder tests: optional findings promote, hardening, schema 48.
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
from unittest.mock import MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.findings.model import ATTACK_DISPLAY, EVIDENCE_TYPE_INTRUDER_RESULT
from talos.intruder import db as idb
from talos.intruder.cli import run_intruder_cli
from talos.intruder.config_schema import ValidationError, default_config, validate_config
from talos.intruder.engine import run_session_segment
from talos.intruder.findings_bridge import (
    build_intruder_cluster_key,
    findings_config_from,
    promote_session_results,
    result_eligible,
)
from talos.intruder.models import (
    DEFAULT_FINDINGS_MAX,
    DEFAULT_FINDINGS_PROMOTE,
    ERR_FINDINGS_NO_MATCH,
    ERR_INVALID_FINDINGS,
    VERDICT_INTRUDER_MATCH,
)
from talos.projects.db import SCHEMA_VERSION, init_project_db, migrate_project_db


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
    body: bytes = b'{"ok":true}',
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
            (fid, url, body, role, mod, endpoint_id),
        )
        conn.commit()
    return fid


def _create_session(manager, db_path: Path, name: str = "p5") -> str:
    fid = _insert_capture(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["session", "create", "--from", fid, "--name", name, "--format", "json"],
        )
    out = json.loads(buf.getvalue())
    return out["session_id"]


def _configure_basic(manager, sid: str, *, with_match: bool = True) -> None:
    run_intruder_cli(
        manager,
        [
            "template", "set-var", sid,
            "--name", "q", "--location", "query", "--path", "q",
        ],
    )
    run_intruder_cli(
        manager,
        [
            "payload", "set", sid,
            "--var", "q", "--generator", "static",
            "--value", "a", "--value", "b", "--value", "c",
        ],
    )
    run_intruder_cli(manager, ["strategy", "set", sid, "--type", "single"])
    if with_match:
        run_intruder_cli(
            manager,
            ["match", "add", sid, "--status", "200", "--tag", "ok"],
        )


# ------------------------------------------------------------------ #
# Schema / defaults                                                    #
# ------------------------------------------------------------------ #


def test_schema_version_48_has_finding_id(db_path: Path) -> None:
    assert SCHEMA_VERSION >= 48
    with sqlite3.connect(str(db_path)) as conn:
        ver = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert ver >= 48
        cols = {r[1] for r in conn.execute("PRAGMA table_info(intruder_results)")}
    assert "finding_id" in cols


def test_migrate_adds_finding_id(tmp_path: Path) -> None:
    """Upgrading an older-shaped table gets finding_id via v48 migration path."""
    path = tmp_path / "old.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (47);
            CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, is_active INTEGER);
            CREATE TABLE modules (
                id TEXT PRIMARY KEY, name TEXT, description TEXT, is_active INTEGER
            );
            CREATE TABLE intruder_sessions (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                status TEXT,
                base_flow_id TEXT,
                endpoint_id TEXT,
                config_json TEXT,
                checkpoint_json TEXT,
                progress_json TEXT,
                job_id TEXT,
                control_flag TEXT,
                created_at TEXT,
                updated_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                failure_reason TEXT,
                schema_version INTEGER
            );
            CREATE TABLE intruder_results (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                attempt_index INTEGER,
                variables_json TEXT,
                status_code INTEGER,
                success INTEGER,
                failure_reason TEXT,
                duration_ms REAL,
                body_length INTEGER,
                word_count INTEGER,
                line_count INTEGER,
                body_hash TEXT,
                fingerprint_json TEXT,
                metrics_json TEXT,
                interesting INTEGER,
                match_tags_json TEXT,
                grepped_json TEXT,
                flow_id TEXT,
                created_at TEXT,
                UNIQUE (session_id, attempt_index)
            );
            """
        )
    migrate_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        ver = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        cols = {r[1] for r in conn.execute("PRAGMA table_info(intruder_results)")}
    assert ver >= 48
    assert "finding_id" in cols


def test_default_findings_promote_off() -> None:
    cfg = default_config()
    assert cfg["findings"]["promote"] is False
    assert cfg["findings"]["max_findings"] == DEFAULT_FINDINGS_MAX
    assert DEFAULT_FINDINGS_PROMOTE is False
    fcfg = findings_config_from(cfg)
    assert fcfg["promote"] is False


def test_attack_display_intruder() -> None:
    assert ATTACK_DISPLAY.get("intruder") == "Intruder Match"
    assert EVIDENCE_TYPE_INTRUDER_RESULT == "intruder_result"


# ------------------------------------------------------------------ #
# Validation / hardening                                               #
# ------------------------------------------------------------------ #


def test_promote_requires_match_or_tag_grep() -> None:
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
    cfg["strategy"] = {"type": "single", "options": {"primary": "q"}}
    cfg["findings"] = {"promote": True, "max_findings": 5}
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg, open_generators=True, force=True)
    assert ei.value.code == ERR_FINDINGS_NO_MATCH


def test_promote_ok_with_match_rule() -> None:
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
    cfg["strategy"] = {"type": "single", "options": {"primary": "q"}}
    cfg["match"] = [{"status": 200, "tag": "ok"}]
    cfg["findings"] = {"promote": True, "max_findings": 5}
    out, _ = validate_config(cfg, open_generators=True, force=True)
    assert out["findings"]["promote"] is True
    assert out["findings"]["max_findings"] == 5


def test_max_findings_over_1000_needs_force() -> None:
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
    cfg["strategy"] = {"type": "single", "options": {"primary": "q"}}
    cfg["match"] = [{"status": 200, "tag": "ok"}]
    cfg["findings"] = {"promote": True, "max_findings": 1001}
    with pytest.raises(ValidationError) as ei:
        validate_config(cfg, open_generators=True, force=False)
    assert ei.value.code == ERR_INVALID_FINDINGS
    out, _ = validate_config(cfg, open_generators=True, force=True)
    assert out["findings"]["max_findings"] == 1001


def test_cluster_key_modes() -> None:
    sid = "sess-1"
    assert build_intruder_cluster_key(session_id=sid) == f"INTRUDER:{sid}"
    assert (
        build_intruder_cluster_key(
            session_id=sid, endpoint_id="ep-9", cluster_by="endpoint"
        )
        == "INTRUDER:ep-9"
    )
    # endpoint mode without endpoint falls back to session
    assert (
        build_intruder_cluster_key(
            session_id=sid, endpoint_id=None, cluster_by="endpoint"
        )
        == f"INTRUDER:{sid}"
    )


def test_result_eligible_rules() -> None:
    fcfg = {
        "promote": True,
        "on": "interesting",
        "only_success": True,
        "max_findings": 10,
    }
    assert not result_eligible(
        {"success": True, "interesting": False, "match_tags": []}, fcfg
    )
    assert result_eligible(
        {"success": True, "interesting": True, "match_tags": ["ok"]}, fcfg
    )
    assert not result_eligible(
        {"success": False, "interesting": True, "match_tags": ["ok"]}, fcfg
    )
    assert not result_eligible(
        {
            "success": True,
            "interesting": True,
            "match_tags": ["ok"],
            "finding_id": "already",
        },
        fcfg,
    )


# ------------------------------------------------------------------ #
# CLI findings set / show / promote                                    #
# ------------------------------------------------------------------ #


def test_cli_findings_set_and_show(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    _configure_basic(manager, sid, with_match=True)

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "findings", "set", sid,
                "--promote", "on",
                "--max", "10",
                "--cluster-by", "session",
                "--format", "json",
            ],
        )
    out = json.loads(buf.getvalue())
    assert out["findings"]["promote"] is True
    assert out["findings"]["max_findings"] == 10

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            ["findings", "show", sid, "--format", "json"],
        )
    show = json.loads(buf.getvalue())
    assert show["findings"]["promote"] is True
    assert show["results_promoted"] == 0


def test_cli_findings_set_promote_without_match_fails(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    _configure_basic(manager, sid, with_match=False)
    with pytest.raises(SystemExit) as ei:
        run_intruder_cli(
            manager,
            ["findings", "set", sid, "--promote", "on", "--format", "json"],
        )
    assert ei.value.code != 0


# ------------------------------------------------------------------ #
# Online + offline promote                                             #
# ------------------------------------------------------------------ #


def test_engine_promotes_interesting_when_enabled(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    _configure_basic(manager, sid, with_match=True)
    run_intruder_cli(
        manager,
        [
            "findings", "set", sid, "--promote", "on", "--max", "5",
            "--format", "json",
        ],
    )
    # Lower caps so segment completes quickly
    sess = idb.get_session(db_path, sid)
    assert sess is not None
    cfg = sess["config"]
    cfg.setdefault("safety", {})["max_attempts"] = 10
    cfg.setdefault("slice", {})["max_attempts"] = 10
    cfg.setdefault("timing", {})["mode"] = "unlimited"
    idb.update_session(db_path, sid, config=cfg)

    class _FakeResp:
        status_code = 200
        content = b'{"ok":true}'
        headers = {"content-type": "application/json"}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, **kwargs):
            return _FakeResp()

    with patch("talos.intruder.engine.httpx.AsyncClient", _FakeClient):
        outcome = asyncio.run(
            run_session_segment(sid, db_path, "proj", force=True)
        )
    assert outcome.reason in ("completed", "continue")
    sess = idb.get_session(db_path, sid)
    assert sess is not None
    progress = sess.get("progress") or {}
    assert int(progress.get("findings_promoted") or 0) >= 1

    results = idb.list_results(db_path, sid, interesting_only=True, limit=50)
    promoted = [r for r in results if r.get("finding_id")]
    assert len(promoted) >= 1

    finding = findings_db.get_finding(db_path, promoted[0]["finding_id"])
    assert finding is not None
    assert finding["attack_type"] == "intruder"
    assert finding["verdict"] == VERDICT_INTRUDER_MATCH
    assert finding["status"] == "TRIAGING"


def test_offline_promote_idempotent(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    _configure_basic(manager, sid, with_match=True)
    # Insert synthetic interesting results without findings
    for i in range(3):
        idb.insert_results_batch(
            db_path,
            sid,
            [
                {
                    "attempt_index": i,
                    "variables": {"q": f"v{i}"},
                    "status_code": 200,
                    "success": True,
                    "interesting": True,
                    "match_tags": ["ok"],
                    "metrics": {},
                    "fingerprint": {},
                }
            ],
        )

    sess = idb.get_session(db_path, sid)
    assert sess is not None
    cfg = sess["config"]
    cfg["findings"] = {
        "promote": True,
        "on": "interesting",
        "max_findings": 2,
        "only_success": True,
        "cluster_by": "session",
    }
    idb.update_session(db_path, sid, config=cfg)
    sess = idb.get_session(db_path, sid)
    assert sess is not None

    first = promote_session_results(db_path, "proj", sess, force_enable=True)
    assert first["promoted"] == 2
    assert first["capped"] is True or first["promoted"] == 2

    second = promote_session_results(db_path, "proj", sess, force_enable=True)
    # Already at max_findings
    assert second["promoted"] == 0

    findings = findings_db.list_findings(db_path, "proj")
    assert len(findings) == 2
    # PRIMARY + LINKED cluster
    relations = {f["relation_type"] for f in findings}
    assert "PRIMARY" in relations
    assert "LINKED" in relations or len(findings) == 1


def test_cli_offline_promote_with_enable(manager, db_path: Path) -> None:
    sid = _create_session(manager, db_path)
    _configure_basic(manager, sid, with_match=True)
    idb.insert_results_batch(
        db_path,
        sid,
        [
            {
                "attempt_index": 0,
                "variables": {"q": "x"},
                "status_code": 200,
                "success": True,
                "interesting": True,
                "match_tags": ["ok"],
                "metrics": {},
                "fingerprint": {},
            }
        ],
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "findings", "promote", sid,
                "--enable", "--force", "--format", "json",
            ],
        )
    out = json.loads(buf.getvalue())
    assert out["promoted"] == 1
    row = idb.get_result(db_path, sid, 0)
    assert row is not None
    assert row.get("finding_id")


def test_export_includes_finding_id(manager, db_path: Path, tmp_path: Path) -> None:
    sid = _create_session(manager, db_path)
    idb.insert_results_batch(
        db_path,
        sid,
        [
            {
                "attempt_index": 0,
                "variables": {"q": "x"},
                "status_code": 200,
                "success": True,
                "interesting": True,
                "match_tags": ["ok"],
                "finding_id": "fid-test",
                "metrics": {},
                "fingerprint": {},
            }
        ],
    )
    out_dir = tmp_path / "exp"
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(
            manager,
            [
                "results", "export", sid,
                "--out", str(out_dir),
                "--csv", "--jsonl",
                "--format", "json",
            ],
        )
    csv_files = list(out_dir.glob("*.csv"))
    assert csv_files
    text = csv_files[0].read_text(encoding="utf-8")
    assert "finding_id" in text
    assert "fid-test" in text


def test_generators_list_phase5(manager) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_intruder_cli(manager, ["generators", "list", "--format", "json"])
    out = json.loads(buf.getvalue())
    assert out["phase5"]["findings_promote"] is True
    assert out["phase5"]["default_promote"] is False
