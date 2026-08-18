"""
NTLM / platform-auth BAC path — kept separate from cookie/header BAC.

Covers:
    - auth.mode stored vs inferred (NTLM-only → platform_ntlm)
    - leftover cookie names do not flip an artifacts project to NTLM
    - role → profile bind / unbind
    - BAC prereqs: NTLM needs a bound profile; artifacts still need tokens
    - session-swap null/whitespace variants are dropped on NTLM
    - engine fails with no_ntlm_profile when unbound
    - engine strips Authorization and uses only the attacker profile
    - Burp snapshot extras include auth_mode + ntlm_profile
    - artifacts BAC still fails on empty auth_config
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from talos.configuration.model import PlatformAuthEntry
from talos.projects.auth import set_auth_fields
from talos.projects.auth_mode import (
    AUTH_MODE_ARTIFACTS,
    AUTH_MODE_PLATFORM_NTLM,
    get_stored_auth_mode,
    resolve_auth_mode,
    set_auth_mode,
)
from talos.projects.bac.auth_prereq import check_auth_prereqs
from talos.projects.bac.engine import execute_bac_job
from talos.projects.bac.variants import (
    SESSION_SWAP_VARIANTS,
    variants_for_auth_mode,
)
from talos.projects.db import init_project_db
from talos.projects.proxy_config import add_platform_auth_entry
from talos.projects.role_ntlm import (
    RoleNtlmError,
    bind_role_ntlm,
    get_role_ntlm_profile,
    list_role_ntlm_bindings,
    resolve_attacker_profile,
    unbind_role_ntlm,
)
from talos.proxy.http_client import client_kwargs
from talos.scheduler.job import BAC_SESSION_SWAP

PROJECT_ID = "proj-ntlm-bac"
ROLE_PRIV = "role-priv"
ROLE_UNPRIV = "role-unpriv"
MODULE_ADMIN = "mod-admin"
EP = "ep-admin"
FLOW = "flow-admin"
HOST = "foresight-uat.chartercom.com"
NOW = "2026-08-18T00:00:00+00:00"


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "talos-data"
    d.mkdir()
    (d / "projects").mkdir()
    monkeypatch.setenv("TALOS_DATA_DIR", str(d))
    return d


@pytest.fixture
def db_path(data_dir: Path) -> Path:
    pdir = data_dir / "projects" / PROJECT_ID
    pdir.mkdir()
    path = pdir / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


def _seed(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            [(ROLE_PRIV, "priv"), (ROLE_UNPRIV, "unpriv")],
        )
        conn.execute(
            "INSERT INTO modules (id, name) VALUES (?, ?)",
            (MODULE_ADMIN, "admin-panel"),
        )
        conn.executemany(
            """
            INSERT INTO access_map (role_id, module_id, client_allowed, server_expected)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ROLE_PRIV, MODULE_ADMIN, "ALLOW", "ALLOW"),
                (ROLE_UNPRIV, MODULE_ADMIN, "DENY", "DENY"),
            ],
        )
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', ?, '/admin', '/admin',
                    'text/html', 1, '[]', ?, ?)
            """,
            (EP, PROJECT_ID, f"https://{HOST}", NOW, NOW),
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
        headers = json.dumps(
            {
                "Host": HOST,
                "Authorization": "NTLM TlRMTVNTUAABAAA=",
                "Cookie": "ASP.NET_SessionId=stale",
            }
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, status_code, endpoint_id,
                 role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', ?, ?, '/admin', '', ?, 200, ?,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                f"https://{HOST}/admin",
                HOST,
                headers,
                EP,
                ROLE_PRIV,
                MODULE_ADMIN,
            ),
        )
        conn.commit()


def _add_profile(
    db_path: Path,
    *,
    profile_id: str,
    username: str,
    name: str = "",
    host: str = HOST,
) -> PlatformAuthEntry:
    return add_platform_auth_entry(
        db_path,
        PlatformAuthEntry(
            id=profile_id,
            name=name or profile_id,
            host=host,
            auth_type="ntlmv2",
            username=username,
            password=f"{username}-secret",
            domain_hostname=host,
        ),
    )


class TestAuthMode:
    def test_default_is_artifacts(self, db_path: Path) -> None:
        assert get_stored_auth_mode(db_path) == AUTH_MODE_ARTIFACTS
        assert resolve_auth_mode(db_path) == AUTH_MODE_ARTIFACTS

    def test_ntlm_only_infers_platform_mode(self, db_path: Path) -> None:
        _add_profile(db_path, profile_id="priv-acct", username="PRIV")
        assert get_stored_auth_mode(db_path) == AUTH_MODE_ARTIFACTS
        assert resolve_auth_mode(db_path) == AUTH_MODE_PLATFORM_NTLM

    def test_leftover_cookies_stay_artifacts(self, db_path: Path) -> None:
        set_auth_fields(db_path, cookies=["ASP.NET_SessionId"], headers=[])
        _add_profile(db_path, profile_id="priv-acct", username="PRIV")
        assert resolve_auth_mode(db_path) == AUTH_MODE_ARTIFACTS

    def test_explicit_platform_wins_over_leftover_cookies(self, db_path: Path) -> None:
        set_auth_fields(db_path, cookies=["ASP.NET_SessionId"], headers=[])
        _add_profile(db_path, profile_id="priv-acct", username="PRIV")
        set_auth_mode(db_path, AUTH_MODE_PLATFORM_NTLM)
        assert get_stored_auth_mode(db_path) == AUTH_MODE_PLATFORM_NTLM
        assert resolve_auth_mode(db_path) == AUTH_MODE_PLATFORM_NTLM


class TestRoleBinding:
    def test_bind_and_resolve(self, db_path: Path) -> None:
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV", name="low")
        bound = bind_role_ntlm(db_path, ROLE_UNPRIV, "low")
        assert bound.id == "unpriv-acct"
        loaded = get_role_ntlm_profile(db_path, ROLE_UNPRIV)
        assert loaded is not None
        assert loaded.username == "UNPRIV"
        attacker = resolve_attacker_profile(db_path, ROLE_UNPRIV, host=HOST)
        assert attacker is not None
        assert attacker.id == "unpriv-acct"

    def test_host_mismatch_returns_none(self, db_path: Path) -> None:
        _add_profile(
            db_path, profile_id="other", username="U", host="other.example"
        )
        bind_role_ntlm(db_path, ROLE_UNPRIV, "other")
        assert resolve_attacker_profile(db_path, ROLE_UNPRIV, host=HOST) is None

    def test_unbind(self, db_path: Path) -> None:
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV")
        bind_role_ntlm(db_path, ROLE_UNPRIV, "unpriv-acct")
        assert unbind_role_ntlm(db_path, ROLE_UNPRIV) is True
        assert get_role_ntlm_profile(db_path, ROLE_UNPRIV) is None

    def test_strip_only_cannot_bind(self, db_path: Path) -> None:
        add_platform_auth_entry(
            db_path,
            PlatformAuthEntry(id="strip", host=HOST, username="", password=""),
        )
        with pytest.raises(RoleNtlmError):
            bind_role_ntlm(db_path, ROLE_UNPRIV, "strip")

    def test_list_bindings(self, db_path: Path) -> None:
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV")
        bind_role_ntlm(db_path, ROLE_UNPRIV, "unpriv-acct")
        rows = list_role_ntlm_bindings(db_path)
        assert len(rows) == 1
        assert rows[0]["role_name"] == "unpriv"
        assert rows[0]["username"] == "UNPRIV"


class TestPrereqsAndVariants:
    def test_ntlm_prereq_requires_binding(self, db_path: Path) -> None:
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV")
        set_auth_mode(db_path, AUTH_MODE_PLATFORM_NTLM)
        failed = check_auth_prereqs(
            db_path, PROJECT_ID, ROLE_UNPRIV, "unpriv"
        )
        assert failed.passed is False
        assert "bind-ntlm" in failed.errors[0]
        bind_role_ntlm(db_path, ROLE_UNPRIV, "unpriv-acct")
        ok = check_auth_prereqs(db_path, PROJECT_ID, ROLE_UNPRIV, "unpriv")
        assert ok.passed is True
        assert ok.auth_state == {"ntlm_profile": "unpriv-acct"}

    def test_artifacts_prereq_still_requires_tokens(self, db_path: Path) -> None:
        result = check_auth_prereqs(
            db_path, PROJECT_ID, ROLE_UNPRIV, "unpriv"
        )
        assert result.passed is False
        assert any("Auth requirements" in e for e in result.errors)

    def test_ntlm_drops_header_override_variants(self) -> None:
        names = {v["name"] for v in SESSION_SWAP_VARIANTS}
        assert "authorization_null" in names
        ntlm = variants_for_auth_mode(BAC_SESSION_SWAP, AUTH_MODE_PLATFORM_NTLM)
        assert [v["name"] for v in ntlm] == ["session_swap"]
        artifacts = variants_for_auth_mode(BAC_SESSION_SWAP, AUTH_MODE_ARTIFACTS)
        assert {v["name"] for v in artifacts} == names


class TestEngine:
    def test_ntlm_job_fails_without_binding(self, db_path: Path) -> None:
        set_auth_mode(db_path, AUTH_MODE_PLATFORM_NTLM)
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV")
        outcome = _run_job(db_path)
        assert outcome.failure_reason == "no_ntlm_profile"

    def test_artifacts_job_fails_without_session(self, db_path: Path) -> None:
        # Artifacts path — not NTLM. No tokens / no cookie names → no handshake.
        outcome = _run_job(db_path)
        assert outcome.failure_reason in ("no_active_token", "auth_config_empty")
        assert outcome.failure_reason != "no_ntlm_profile"

    def test_ntlm_strips_authorization_and_uses_attacker_profile(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        set_auth_mode(db_path, AUTH_MODE_PLATFORM_NTLM)
        _add_profile(db_path, profile_id="priv-acct", username="PRIV", name="high")
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV", name="low")
        bind_role_ntlm(db_path, ROLE_UNPRIV, "unpriv-acct")
        bind_role_ntlm(db_path, ROLE_PRIV, "priv-acct")

        captured: dict = {}

        class _Resp:
            status_code = 403
            headers = {"content-type": "text/html"}
            content = b"denied"
            reason_phrase = "Forbidden"

        async_client = MagicMock()
        async_client.request = AsyncMock(return_value=_Resp())
        async_client.__aenter__ = AsyncMock(return_value=async_client)
        async_client.__aexit__ = AsyncMock(return_value=None)

        def _factory(*_a, **kwargs):
            captured["kwargs"] = kwargs
            return async_client

        monkeypatch.setattr(
            "talos.projects.bac.engine.create_async_client", _factory
        )
        outcome = _run_job(db_path)
        assert outcome.failure_reason is None
        assert outcome.replay_status == 403
        entries = captured["kwargs"].get("platform_auth_entries") or []
        assert len(entries) == 1
        assert entries[0].id == "unpriv-acct"
        assert entries[0].username == "UNPRIV"
        sent_headers = async_client.request.await_args.kwargs["headers"]
        assert not any(str(k).lower() == "authorization" for k in sent_headers)

    def test_burp_snapshot_has_ntlm_extras(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        set_auth_mode(db_path, AUTH_MODE_PLATFORM_NTLM)
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV", name="low")
        bind_role_ntlm(db_path, ROLE_UNPRIV, "unpriv-acct")

        class _Resp:
            status_code = 200
            headers = {"content-type": "text/html"}
            content = b"<html>admin</html>"
            reason_phrase = "OK"

        async_client = MagicMock()
        async_client.request = AsyncMock(return_value=_Resp())
        async_client.__aenter__ = AsyncMock(return_value=async_client)
        async_client.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(
            "talos.projects.bac.engine.create_async_client",
            lambda *_a, **_k: async_client,
        )
        _run_job(db_path)
        from talos.burp.snapshot import load_records

        rows = load_records(PROJECT_ID)
        assert rows, "BAC must write a Burp JSONL record"
        row = rows[-1]
        assert row.get("engine") == "bac"
        assert "session_swap" in (row.get("variant") or row.get("technique") or "")
        assert "low" in (row.get("detail") or "")
        assert row.get("auth_mode") == "platform_ntlm"
        assert row.get("ntlm_profile") == "low"


def _run_job(db_path: Path):
    import asyncio

    return asyncio.run(
        execute_bac_job(
            FLOW,
            {
                "attacker_role_id": ROLE_UNPRIV,
                "target_role_id": ROLE_PRIV,
                "module_id": MODULE_ADMIN,
                "variant": "session_swap",
            },
            BAC_SESSION_SWAP,
            db_path,
            PROJECT_ID,
        )
    )


class TestClientOverride:
    def test_platform_auth_entries_override_project_list(self, db_path: Path) -> None:
        priv = _add_profile(db_path, profile_id="priv-acct", username="PRIV")
        _add_profile(db_path, profile_id="unpriv-acct", username="UNPRIV")
        kwargs = client_kwargs(
            db_path,
            timeout=5.0,
            platform_auth_entries=[priv],
        )
        from talos.proxy.platform_auth import match_platform_auth

        hit = match_platform_auth(kwargs["auth"].entries, HOST)
        assert hit is not None
        assert hit.username == "PRIV"
        assert hit.id == "priv-acct"
