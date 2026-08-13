"""CORS engine: unique replay flows + reflection verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.cors.candidates import (
    DEFAULT_CANDIDATE_LIMIT,
    normalize_flow_ids,
    select_cors_candidates,
    select_cors_candidates_for_flows,
)
from talos.cors.db import list_cors_results
from talos.cors.engine import execute_cors_job
from talos.cors.findings_bridge import maybe_create_cors_finding
from talos.cors.models import VERDICT_CORS_MISCONFIG, VERDICT_SECURE
from talos.findings import db as findings_db
from talos.projects.db import init_project_db

PROJECT_ID = "proj-cors"
EP = "ep-cors"
FLOW = "flow-cors"
NOW = "2026-01-01T00:00:00+00:00"


def _context_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
    return role, module


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    role_id, module_id = _context_ids(path)
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'POST', 'https://app.example.com', '/api/items',
                    '/api/items', 'application/json', 1, '[]', ?, ?)
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
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'POST', 'https://app.example.com/api/items',
                    'app.example.com', '/api/items', '', ?, '{}', 200,
                    ?, ?, 'application/json', ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Origin": "https://spa.example.com", "Content-Type": "application/json"}),
                json.dumps({"Content-Type": "application/json"}),
                b'{"ok":true}',
                EP,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return path


def _mock_response(headers: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers
    resp.content = b'{"ok":true}'
    return resp


def _patch_httpx(headers: dict, status: int = 200):
    """Purpose: AsyncClient context whose request() returns headers."""
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(headers, status)
    return patch("talos.cors.engine.httpx.AsyncClient", return_value=client)


def test_select_prefers_post_with_origin(db_path: Path) -> None:
    rows = select_cors_candidates(
        db_path,
        in_scope_prefixes=["https://app.example.com"],
    )
    assert len(rows) == 1
    assert rows[0].method == "POST"
    assert rows[0].origin_was_present is True
    assert rows[0].baseline_origin == "https://spa.example.com"
    assert rows[0].flow_id == FLOW


def test_select_default_cap_is_five(db_path: Path) -> None:
    role_id, module_id = _context_ids(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        for i in range(7):
            ep = f"ep-extra-{i}"
            flow = f"flow-extra-{i}"
            conn.execute(
                """
                INSERT INTO endpoints
                    (id, project_id, method, host, path, normalized_path,
                     content_type, auth_required, roles_seen, first_seen, last_seen)
                VALUES (?, ?, 'GET', 'https://app.example.com', ?, ?,
                        'application/json', 0, '[]', ?, ?)
                """,
                (ep, PROJECT_ID, f"/extra/{i}", f"/extra/{i}", NOW, NOW),
            )
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, excluded,
                     dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'LOW', 10, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
                """,
                (ep, flow, NOW),
            )
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source)
                VALUES (?, ?, ?, 'GET', ?, 'app.example.com', ?,
                        '', '{}', 200, ?, ?, ?, '[]', 'proxy_capture')
                """,
                (
                    flow,
                    PROJECT_ID,
                    NOW,
                    f"https://app.example.com/extra/{i}",
                    f"/extra/{i}",
                    ep,
                    role_id,
                    module_id,
                ),
            )
        conn.commit()

    defaulted = select_cors_candidates(
        db_path,
        in_scope_prefixes=["https://app.example.com"],
    )
    uncapped = select_cors_candidates(
        db_path,
        in_scope_prefixes=["https://app.example.com"],
        limit=20,
    )
    assert DEFAULT_CANDIDATE_LIMIT == 5
    assert len(defaulted) == 5
    assert len(uncapped) == 8
    assert defaulted[0].method == "POST"
    assert {row.flow_id for row in defaulted}.issubset(
        {row.flow_id for row in uncapped}
    )


def test_normalize_flow_ids_splits_and_dedupes() -> None:
    assert normalize_flow_ids(["a,b", "b", "c"]) == ["a", "b", "c"]
    assert normalize_flow_ids(None) == []


def test_select_explicit_flows_preserves_order(db_path: Path) -> None:
    role_id, module_id = _context_ids(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, status_code, endpoint_id,
                 role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://app.example.com/second',
                    'app.example.com', '/second', '', '{}', 404, NULL,
                    ?, ?, '[]', 'proxy_capture')
            """,
            ("flow-second", PROJECT_ID, NOW, role_id, module_id),
        )
        conn.commit()
    rows, missing = select_cors_candidates_for_flows(
        db_path,
        in_scope_prefixes=["https://app.example.com"],
        flow_ids=["flow-second", FLOW],
    )
    assert missing == []
    assert [r.flow_id for r in rows] == ["flow-second", FLOW]
    assert rows[0].status_code == 404


def test_select_explicit_unknown_ids(db_path: Path) -> None:
    rows, missing = select_cors_candidates_for_flows(
        db_path,
        in_scope_prefixes=["https://app.example.com"],
        flow_ids=["nope", FLOW],
    )
    assert missing == ["nope"]
    assert [r.flow_id for r in rows] == [FLOW]


def test_engine_writes_unique_flow_not_baseline(db_path: Path) -> None:
    headers = {
        "Access-Control-Allow-Origin": "https://talos-cors-aa.invalid",
        "Content-Type": "application/json",
    }
    with _patch_httpx(headers):
        outcome = asyncio.run(
            execute_cors_job(
                FLOW,
                {
                    "technique": "arbitrary_https",
                    "technique_family": "arbitrary_origin",
                    "origin_sent": "https://talos-cors-aa.invalid",
                    "attacker_controlled": True,
                    "baseline_origin": "https://spa.example.com",
                },
                db_path,
                PROJECT_ID,
            )
        )

    assert outcome.verdict == VERDICT_CORS_MISCONFIG
    assert outcome.replayed_flow_id
    assert outcome.replayed_flow_id != FLOW
    assert outcome.original_flow_id == FLOW
    assert outcome.reflected is True

    with sqlite3.connect(str(db_path)) as conn:
        baseline = conn.execute(
            "SELECT source, original_flow_id FROM flows WHERE id = ?",
            (FLOW,),
        ).fetchone()
        replay = conn.execute(
            "SELECT source, original_flow_id, replay_reason, request_headers "
            "FROM flows WHERE id = ?",
            (outcome.replayed_flow_id,),
        ).fetchone()
        count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    assert baseline[0] == "proxy_capture"
    assert baseline[1] is None
    assert replay[0] == "auto_replay"
    assert replay[1] == FLOW
    assert replay[2] == "cors_attack"
    req = json.loads(replay[3])
    assert req["Origin"] == "https://talos-cors-aa.invalid"
    assert count == 2

    stored = list_cors_results(db_path)
    assert len(stored) == 1
    assert stored[0]["replay_flow_id"] == outcome.replayed_flow_id
    assert stored[0]["verdict"] == VERDICT_CORS_MISCONFIG


def test_engine_wildcard_is_secure(db_path: Path) -> None:
    with _patch_httpx({"Access-Control-Allow-Origin": "*"}):
        outcome = asyncio.run(
            execute_cors_job(
                FLOW,
                {
                    "technique": "arbitrary_https",
                    "origin_sent": "https://talos-cors-aa.invalid",
                    "attacker_controlled": True,
                },
                db_path,
                PROJECT_ID,
            )
        )
    assert outcome.verdict == VERDICT_SECURE
    assert outcome.wildcard is True
    assert outcome.reflected is False


def test_findings_cluster_one_primary(db_path: Path) -> None:
    first = SimpleNamespace(
        verdict=VERDICT_CORS_MISCONFIG,
        replayed_flow_id="replay-1",
        original_flow_id=FLOW,
        endpoint_id=EP,
        host="https://app.example.com",
        technique="arbitrary_https",
        technique_family="arbitrary_origin",
        origin_sent="https://evil.invalid",
        acao="https://evil.invalid",
        acac="true",
        reflected=True,
        credentials=True,
        wildcard=False,
        risk_hint="credentials",
    )
    second = SimpleNamespace(
        verdict=VERDICT_CORS_MISCONFIG,
        replayed_flow_id="replay-2",
        original_flow_id=FLOW,
        endpoint_id=EP,
        host="https://app.example.com",
        technique="subdomain_of_target",
        technique_family="subdomain_reflection",
        origin_sent="https://x.app.example.com",
        acao="https://x.app.example.com",
        acac=None,
        reflected=True,
        credentials=False,
        wildcard=False,
        risk_hint="reflected_origin",
    )
    # Findings require the replay flow rows for evidence; insert stubs.
    role_id, module_id = _context_ids(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        for rid in ("replay-1", "replay-2"):
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source, original_flow_id,
                     replay_reason)
                VALUES (?, ?, ?, 'POST', 'https://app.example.com/api/items',
                        'app.example.com', '/api/items', '', '{}', 200, ?,
                        ?, ?, '[]', 'auto_replay', ?, 'cors_attack')
                """,
                (rid, PROJECT_ID, NOW, EP, role_id, module_id, FLOW),
            )
        conn.commit()

    a = maybe_create_cors_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=first,  # type: ignore[arg-type]
        method="POST", path="/api/items",
    )
    b = maybe_create_cors_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=second,  # type: ignore[arg-type]
        method="POST", path="/api/items",
    )
    assert a and b and a != b
    fa = findings_db.get_finding(db_path, a)
    fb = findings_db.get_finding(db_path, b)
    assert fa["relation_type"] == "PRIMARY"
    assert fb["relation_type"] == "LINKED"
    assert fb["parent_finding_id"] == a
    assert fa["cluster_key"] == "CORS:https://app.example.com"
    assert fa["cluster_key"] == fb["cluster_key"]
    assert fa["attack_type"] == "cors"
