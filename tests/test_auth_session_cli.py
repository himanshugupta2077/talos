"""
Tests: auth-session CLI (Phases 2–5).

Covers:
  - bind requires auth_config field
  - generate via CLI creates pending candidates
  - approve --all-pending / reject
  - suite list includes core rows; --alg expands full degradation matrix
  - status overview + --format json on action paths
  - Talos Helper documents auth-session surface
  - attack_cli dispatches auth-session
"""

from __future__ import annotations

import io
import json
import re
import sqlite3
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.__main__ import _print_usage
from talos.auth_session import db as as_db
from talos.auth_session.cli import (
    build_auth_session_parser,
    run_auth_session_cli,
)
from talos.auth_session.jwt_codec import encode_jwt
from talos.auth_session.models import STATUS_APPROVED, STATUS_PENDING
from talos.projects.attack_cli import run_attack_cli
from talos.projects.auth import set_auth_fields
from talos.projects.db import init_project_db

PROJECT_ID = "proj-cli"
EP = "ep-1"
FLOW = "flow-1"
NOW = "2026-01-01T00:00:00+00:00"


def _jwt() -> str:
    return encode_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "u1", "role": "user", "exp": 9999999999},
        "sig",
    )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    bearer = f"Bearer {_jwt()}"
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/me', '/api/me',
                    'application/json', 1, '[]', ?, ?)
            """,
            (EP, PROJECT_ID, NOW, NOW),
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
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', ?, '{}', 200,
                    '{}', 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Authorization": bearer}),
                EP,
            ),
        )
        conn.commit()
    set_auth_fields(path, cookies=[], headers=["Authorization"])
    return path


@pytest.fixture()
def manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id=PROJECT_ID)
    m = MagicMock()
    m.active.return_value = project
    return m


def _parse_as(argv: list[str]):
    import argparse

    parser = argparse.ArgumentParser(prog="talos attack")
    sub = parser.add_subparsers(dest="attack_type")
    build_auth_session_parser(sub)
    return parser.parse_args(["auth-session"] + argv)


def test_bind_requires_auth_config(manager: MagicMock, db_path: Path) -> None:
    # Clear auth config and try bind cookie not configured
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("DELETE FROM auth_config")
        conn.commit()
    args = _parse_as(["bind", "--type", "jwt", "--header", "Authorization"])
    with pytest.raises(SystemExit) as exc:
        run_auth_session_cli(manager, args)
    assert exc.value.code == 3  # precondition


def test_bind_generate_approve_reject_flow(manager: MagicMock, db_path: Path) -> None:
    # bind
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["bind", "--type", "jwt", "--header", "Authorization"])
        )
    text = out.getvalue()
    assert "Bound" in text
    bindings = as_db.list_bindings(db_path)
    assert len(bindings) == 1

    # generate
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["generate", "--endpoint", EP])
        )
    assert "Created" in out.getvalue()
    pending = as_db.list_candidates(db_path, status=STATUS_PENDING)
    assert len(pending) > 0

    # candidates list
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["candidates", "list", "--status", "pending"])
        )
    assert "jwt.alg_none" in out.getvalue() or "alg" in out.getvalue().lower()

    # approve all pending
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["approve", "--all-pending"])
        )
    assert "Approved" in out.getvalue()
    approved = as_db.list_candidates(db_path, status=STATUS_APPROVED)
    assert len(approved) == len(pending)

    # re-bind path for reject: generate new binding+candidates is heavy;
    # insert fresh pending and reject
    b = bindings[0]
    c = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="other-flow",
        auth_type="jwt",
        test_id="jwt.alg_unknown",
        test_family="algorithm",
        title="x",
        mutation_summary="m",
    )
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["reject", c.id, "--reason", "nope"])
        )
    assert "Rejected" in out.getvalue()
    assert as_db.get_candidate(db_path, c.id).status == "rejected"


def test_suite_list_core_and_degrade(manager: MagicMock) -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["suite", "list", "--type", "jwt"])
        )
    text = out.getvalue()
    assert "jwt.alg_none" in text

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["suite", "list", "--type", "jwt", "--alg", "RS256"]),
        )
    text = out.getvalue()
    assert "jwt.alg_degrade.rs256_to_hs256" in text
    # Phase 5 full matrix cross-family edges.
    assert "jwt.alg_degrade.rs256_to_es256" in text
    assert "jwt.alg_degrade.rs256_to_ps256" in text
    assert "jwt.alg_degrade.rs256_to_none" not in text


def test_suite_list_json(manager: MagicMock) -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["suite", "list", "--format", "json"])
        )
    data = json.loads(out.getvalue())
    assert isinstance(data, list)
    assert any(r["test_id"] == "jwt.alg_none" for r in data)


def test_attack_cli_dispatch(manager: MagicMock, db_path: Path) -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        run_attack_cli(
            manager,
            ["auth-session", "bind", "--type", "jwt", "--header", "Authorization"],
        )
    assert "Bound" in out.getvalue()


def test_talos_helper_documents_auth_session() -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert re.search(r"^\s+auth-session bind\|unbind\|show-bindings", text, re.M)
    assert "auth-session generate" in text
    assert "auth-session candidates" in text
    assert "auth-session approve|reject|unapprove" in text
    assert "auth-session run" in text
    assert "auth-session results" in text
    assert "auth-session status" in text
    assert "auth-session filter" in text
    assert "auth-session suite list" in text
    assert "full alg-degradation matrix" in text


def test_filter_init_show_validate(manager: MagicMock, db_path: Path) -> None:
    from talos.auth_session.decision_filter import FILTER_FILENAME

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["filter", "init"]))
    assert "Created:" in out.getvalue()
    assert (db_path.parent / FILTER_FILENAME).exists()

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["filter", "init"]))
    assert "Already exists" in out.getvalue()

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["filter", "validate"]))
    text = out.getvalue()
    assert "OK" in text
    assert "passed_detection" in text

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["filter", "show"]))
    assert "version:" in out.getvalue()


def test_bind_normalizes_header_case(manager: MagicMock, db_path: Path) -> None:
    """auth_config has Authorization; bind --header authorization stores canonical."""
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["bind", "--type", "jwt", "--header", "authorization"]),
        )
    bindings = as_db.list_bindings(db_path)
    assert len(bindings) == 1
    assert bindings[0].name == "Authorization"


def test_unapprove_cli_and_unbind_path(manager: MagicMock, db_path: Path) -> None:
    run_auth_session_cli(
        manager, _parse_as(["bind", "--type", "jwt", "--header", "Authorization"])
    )
    run_auth_session_cli(manager, _parse_as(["generate", "--endpoint", EP]))
    run_auth_session_cli(manager, _parse_as(["approve", "--all-pending"]))
    approved = as_db.list_candidates(db_path, status=STATUS_APPROVED)
    assert approved

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["unapprove", "--all-approved"])
        )
    assert "Unapproved" in out.getvalue()
    assert as_db.list_candidates(db_path, status=STATUS_APPROVED) == []
    pending = as_db.list_candidates(db_path, status=STATUS_PENDING)
    assert len(pending) == len(approved)

    # Now unbind --force works (pending only)
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["unbind", "--header", "Authorization", "--force"]),
        )
    assert "Unbound" in out.getvalue()
    assert as_db.list_bindings(db_path) == []


def test_show_bindings_json(manager: MagicMock, db_path: Path) -> None:
    as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["show-bindings", "--format", "json"])
        )
    data = json.loads(out.getvalue())
    assert len(data) == 1
    assert data[0]["name"] == "Authorization"


def test_status_and_json_actions(manager: MagicMock, db_path: Path) -> None:
    """Phase 5: status overview + --format json on generate / approve / status."""
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as([
                "bind", "--type", "jwt", "--header", "Authorization",
                "--format", "json",
            ]),
        )
    bind_data = json.loads(out.getvalue())
    assert bind_data["name"] == "Authorization"
    assert bind_data["auth_type"] == "jwt"

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["generate", "--endpoint", EP, "--format", "json"]),
        )
    gen = json.loads(out.getvalue())
    assert gen["created"] > 0
    assert "bindings_processed" in gen
    # Full Phase 5 matrix for RS256 includes cross-family edges.
    pending = as_db.list_candidates(db_path, status=STATUS_PENDING)
    degrade_ids = {c.test_id for c in pending if c.test_id.startswith("jwt.alg_degrade.")}
    assert "jwt.alg_degrade.rs256_to_es256" in degrade_ids
    assert "jwt.alg_degrade.rs256_to_ps256" in degrade_ids

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["status", "--format", "json"]),
        )
    st = json.loads(out.getvalue())
    assert st["bindings"] == 1
    assert st["candidates_total"] == gen["created"]
    assert st["candidates_by_status"].get("pending", 0) == gen["created"]

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager,
            _parse_as(["approve", "--all-pending", "--format", "json"]),
        )
    ap = json.loads(out.getvalue())
    assert ap["approved_count"] == gen["created"]

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["status"]))
    text = out.getvalue()
    assert "Auth-session status" in text
    assert "approved" in text.lower()
    assert str(gen["created"]) in text


def test_unknown_family_rejected_on_approve(manager: MagicMock, db_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        run_auth_session_cli(
            manager,
            _parse_as(["approve", "--all-pending", "--family", "not_a_family"]),
        )
    assert exc.value.code == 2  # usage


def test_unapprove_blocked_when_job_pending(
    manager: MagicMock, db_path: Path
) -> None:
    """Unapprove refuses while auth_session_attack job is still queued."""
    run_auth_session_cli(
        manager, _parse_as(["bind", "--type", "jwt", "--header", "Authorization"])
    )
    run_auth_session_cli(
        manager,
        _parse_as([
            "generate", "--endpoint", EP,
            "--test-id", "jwt.alg_degrade.rs256_to_es256",
        ]),
    )
    run_auth_session_cli(manager, _parse_as(["approve", "--all-pending"]))
    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(manager, _parse_as(["run", "--format", "json"]))
    run_data = json.loads(out.getvalue())
    assert run_data["jobs_enqueued"] == 1

    out = io.StringIO()
    with redirect_stdout(out):
        run_auth_session_cli(
            manager, _parse_as(["unapprove", "--all-approved", "--format", "json"])
        )
    u = json.loads(out.getvalue())
    assert u["unapproved_count"] == 0
    assert u["blocked_active_job_count"] == 1
    # Still approved (not stuck pending with a live job).
    approved = as_db.list_candidates(db_path, status=STATUS_APPROVED)
    assert len(approved) == 1
