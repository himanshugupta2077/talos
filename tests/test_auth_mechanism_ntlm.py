"""
Platform NTLM as a first-class auth mechanism for IV / unauth / auth-test.

Covers:
    - resolve_auth_mechanism (artifacts vs credentialed NTLM)
    - hostname matching against canonical endpoint origins
    - IV pre-check: NTLM ready (including leftover cookie names); missing both; uncovered host
    - session health skip when platform NTLM is configured
    - httpx client_kwargs(platform_auth=False) drops NTLM
    - unauth CLI: fail without a mechanism; NTLM-only enqueues baseline only
    - auth show mentions platform NTLM
"""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.configuration.model import PlatformAuthEntry
from talos.input_validation.engine import verify_auth_for_iv_scan
from talos.projects.auth import set_auth_fields
from talos.projects.auth_cli import cmd_auth_show
from talos.projects.auth_mechanism import (
    hostname_for_auth_match,
    missing_auth_error,
    platform_ntlm_covers_host,
    resolve_auth_mechanism,
    uncovered_ntlm_hosts,
)
from talos.projects.db import init_project_db
from talos.projects.proxy_config import add_platform_auth_entry
from talos.projects.session_health import ensure_healthy
from talos.projects.unauth.cli import cmd_unauth_run
from talos.projects.unauth.recipes import UNAUTH_RECIPES
from talos.proxy.http_client import client_kwargs
from talos.scheduler.job import UNAUTH_ATTACK

PROJECT_ID = "proj-ntlm"
EP = "ep-ntlm"
FLOW = "flow-ntlm"
NOW = "2026-08-17T00:00:00+00:00"
ORIGIN = "https://foresight-uat.chartercom.com"
HOST = "foresight-uat.chartercom.com"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _add_ntlm(
    db_path: Path,
    host: str = HOST,
    username: str = "P3307757",
    password: str = "secret",
) -> None:
    add_platform_auth_entry(
        db_path,
        PlatformAuthEntry(
            host=host,
            auth_type="ntlmv2",
            username=username,
            password=password,
            domain_hostname=host,
        ),
    )


def _seed_flow(db_path: Path, *, origin: str = ORIGIN) -> str:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'POST', ?, '/api/get_broadcast_notifications',
                    '/api/get_broadcast_notifications',
                    'application/json', 1, '[]', ?, ?)
            """,
            (EP, PROJECT_ID, origin, NOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
            """,
            (EP, FLOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, status_code, endpoint_id,
                 role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'POST', ?, ?,
                    '/api/get_broadcast_notifications', '', '{}', 200, ?,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                f"{origin}/api/get_broadcast_notifications",
                HOST,
                EP,
                role,
                module,
            ),
        )
        conn.commit()
        return role


def _manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id=PROJECT_ID)
    manager = MagicMock()
    manager.active.return_value = project
    return manager


class TestResolveMechanism:
    def test_empty(self, db_path: Path) -> None:
        mech = resolve_auth_mechanism(db_path)
        assert mech.has_artifacts is False
        assert mech.has_platform_ntlm is False
        assert mech.ntlm_only is False
        assert mech.ready is False

    def test_artifacts_only(self, db_path: Path) -> None:
        set_auth_fields(db_path, cookies=["session"], headers=[])
        mech = resolve_auth_mechanism(db_path)
        assert mech.has_artifacts is True
        assert mech.ntlm_only is False
        assert mech.ready is True

    def test_ntlm_only(self, db_path: Path) -> None:
        _add_ntlm(db_path)
        mech = resolve_auth_mechanism(db_path)
        assert mech.has_artifacts is False
        assert mech.has_platform_ntlm is True
        assert mech.ntlm_only is True
        assert mech.ready is True
        assert mech.platform_profiles[0].host == HOST
        assert mech.platform_profiles[0].username == "P3307757"

    def test_strip_only_profile_is_not_a_session(self, db_path: Path) -> None:
        add_platform_auth_entry(
            db_path,
            PlatformAuthEntry(host=HOST, username="", password=""),
        )
        mech = resolve_auth_mechanism(db_path)
        assert mech.has_platform_ntlm is False
        assert mech.ready is False

    def test_origin_matches_bare_host(self, db_path: Path) -> None:
        _add_ntlm(db_path)
        mech = resolve_auth_mechanism(db_path)
        assert hostname_for_auth_match(ORIGIN) == HOST
        assert platform_ntlm_covers_host(mech, ORIGIN) is True
        assert uncovered_ntlm_hosts(mech, [ORIGIN]) == []
        assert uncovered_ntlm_hosts(mech, ["https://other.example"]) == [
            "https://other.example"
        ]


class TestIvPrecheck:
    def test_neither_mechanism_mentions_ntlm(self, db_path: Path) -> None:
        _seed_flow(db_path)
        errors = verify_auth_for_iv_scan(db_path, PROJECT_ID)
        assert errors
        assert "NTLM" in errors[0]
        assert "proxy auth add" in errors[0]
        assert "invent" in errors[0].lower()

    def test_ntlm_only_is_ready(self, db_path: Path) -> None:
        _seed_flow(db_path)
        _add_ntlm(db_path)
        assert verify_auth_for_iv_scan(db_path, PROJECT_ID) == []

    def test_ntlm_wrong_host(self, db_path: Path) -> None:
        _seed_flow(db_path)
        _add_ntlm(db_path, host="other.example.com")
        errors = verify_auth_for_iv_scan(db_path, PROJECT_ID)
        assert errors
        assert "no credentialed profile" in errors[0]
        assert ORIGIN in errors[0] or HOST in errors[0]

    def test_artifacts_without_session_still_fail(self, db_path: Path) -> None:
        _seed_flow(db_path)
        set_auth_fields(db_path, cookies=["session"], headers=[])
        errors = verify_auth_for_iv_scan(db_path, PROJECT_ID)
        assert errors
        assert any("No login flows" in e or "No manual session" in e for e in errors)

    def test_ntlm_plus_leftover_artifacts_skips_session(self, db_path: Path) -> None:
        _seed_flow(db_path)
        set_auth_fields(db_path, cookies=["ASP.NET_SessionId"], headers=[])
        _add_ntlm(db_path)
        assert verify_auth_for_iv_scan(db_path, PROJECT_ID) == []


class TestSessionHealth:
    def test_ntlm_only_ensure_healthy(self, db_path: Path) -> None:
        role_id = _seed_flow(db_path)
        _add_ntlm(db_path)
        assert ensure_healthy(db_path, role_id, PROJECT_ID) is True

    def test_ntlm_plus_leftover_artifacts_skips_refresh(self, db_path: Path) -> None:
        role_id = _seed_flow(db_path)
        set_auth_fields(db_path, cookies=["ASP.NET_SessionId"], headers=[])
        _add_ntlm(db_path)
        assert ensure_healthy(db_path, role_id, PROJECT_ID) is True


class TestHttpClient:
    def test_platform_auth_false_drops_ntlm(self, db_path: Path) -> None:
        _add_ntlm(db_path)
        on = client_kwargs(db_path, timeout=5.0)
        off = client_kwargs(db_path, timeout=5.0, platform_auth=False)
        assert "auth" in on
        assert "auth" not in off
        assert "mounts" not in off


class TestUnauthCli:
    def test_refuses_without_mechanism(self, db_path: Path) -> None:
        _seed_flow(db_path)
        with pytest.raises(SystemExit):
            cmd_unauth_run(_manager(db_path), SimpleNamespace(technique=None, flows=None))

    def test_ntlm_only_enqueues_baseline_only(self, db_path: Path) -> None:
        _seed_flow(db_path)
        _add_ntlm(db_path)
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_unauth_run(
                _manager(db_path), SimpleNamespace(technique=None, flows=None)
            )
        text = out.getvalue()
        assert "Platform NTLM" in text
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT meta FROM scheduler_jobs WHERE job_type = ?",
                (UNAUTH_ATTACK,),
            ).fetchall()
        techniques = {json.loads(r[0])["technique"] for r in rows}
        assert techniques == {"baseline"}
        expected = sum(1 for rec in UNAUTH_RECIPES if rec["technique"] == "baseline")
        assert len(rows) == expected

    def test_ntlm_rejects_header_technique(self, db_path: Path) -> None:
        _seed_flow(db_path)
        _add_ntlm(db_path)
        with pytest.raises(SystemExit):
            cmd_unauth_run(
                _manager(db_path),
                SimpleNamespace(technique="empty_auth", flows=None),
            )


class TestAuthShow:
    def test_empty_mentions_ntlm_path(self, db_path: Path) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_auth_show(SimpleNamespace(db_path=db_path), None)
        text = out.getvalue()
        assert "empty" in text.lower()
        assert "proxy auth add" in text

    def test_ntlm_listed(self, db_path: Path) -> None:
        _add_ntlm(db_path)
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_auth_show(SimpleNamespace(db_path=db_path), None)
        text = out.getvalue()
        assert HOST in text
        assert "P3307757" in text
        assert "Authorization header" in text

    def test_json_includes_platform_ntlm(self, db_path: Path) -> None:
        _add_ntlm(db_path)
        out = io.StringIO()
        args = SimpleNamespace(output_format="json")
        with redirect_stdout(out):
            cmd_auth_show(SimpleNamespace(db_path=db_path), args)
        payload = json.loads(out.getvalue())
        assert payload["cookies"] == []
        assert payload["headers"] == []
        assert payload["platform_ntlm"]["enabled"] is True
        assert payload["platform_ntlm"]["profiles"][0]["host"] == HOST


def test_missing_auth_error_lists_hosts() -> None:
    text = missing_auth_error([ORIGIN])
    assert ORIGIN in text
    assert "proxy auth add" in text
