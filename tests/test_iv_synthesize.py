"""
Unit tests for Input Validation Module 3 — Synthesis from existing probes.

Covers:
    - Offline synthesize_param_profile from fixture probe rows (no network)
    - Conflicting reflection → state conflicting + reduced confidence
    - Partial data does not crash; partial flag set
    - Acceptance / taxonomy / tested / capabilities populated
    - DB round-trip via upsert_param_profile
    - analysis_probes_ready wait vs ready
    - char_to_taxonomy_classes + multiprobe extension hook
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.db import (
    get_param_profile,
    get_parameter_profile,
    make_param_uuid,
    upsert_probe_result,
)
from talos.input_validation.profile import (
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_REFLECTIVE_INPUT,
    STATE_CONFLICTING,
)
from talos.input_validation.synthesize import (
    analysis_probes_ready,
    char_to_taxonomy_classes,
    detect_payload_reflection,
    format_profile_summary_lines,
    list_param_uuids_with_probes,
    synthesize_many,
    synthesize_param_profile,
)
from talos.projects.db import init_project_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _global_role_module(conn: sqlite3.Connection) -> tuple[str, str]:
    """Return (role_id, module_id) for seeded global context."""
    role = conn.execute(
        "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
    ).fetchone()
    mod = conn.execute(
        "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
    ).fetchone()
    role_id = role[0] if role else "global-role"
    module_id = mod[0] if mod else "global-module"
    if not role:
        conn.execute(
            "INSERT OR IGNORE INTO roles (id, name, is_active) VALUES (?, 'global', 1)",
            (role_id,),
        )
    if not mod:
        conn.execute(
            "INSERT OR IGNORE INTO modules (id, name, description, is_active) "
            "VALUES (?, 'global', '', 1)",
            (module_id,),
        )
    return role_id, module_id


def _insert_flow(
    db_path: Path,
    *,
    status_code: int = 200,
    content_type: str = "application/json",
    body: str = '{"ok":true}',
    host: str = "https://api.example.com",
    path: str = "/v1/items",
) -> str:
    """Insert a minimal flows row and return its id."""
    flow_id = str(uuid.uuid4())
    headers = json.dumps({"Content-Type": content_type})
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _global_role_module(conn)
        ep_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, 'proj', ?, 'GET', ?, ?, datetime('now'), datetime('now'))
            """,
            (ep_id, host, path, path),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path, query,
                 request_headers, request_cookies, status_code, response_headers,
                 response_body, content_type, endpoint_id, role_id, module_id,
                 tags, source, flow_meta)
            VALUES (?, 'proj', '2024-01-01T00:00:00+00:00', 'GET', ?, ?, ?, '',
                    '{}', '{}', ?, ?, ?, ?, ?, ?, ?, '[]', 'auto_replay', '{}')
            """,
            (
                flow_id,
                f"{host}{path}?q=1",
                host,
                path,
                status_code,
                headers,
                body.encode("utf-8") if isinstance(body, str) else body,
                content_type,
                ep_id,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return flow_id


def _seed_probe(
    db_path: Path,
    *,
    param_uuid: str,
    host: str,
    location: str,
    param_name: str,
    analysis: str,
    payload: str | None,
    payload_type: str,
    payload_index: int,
    status_code: int,
    body: str,
    content_type: str = "application/json",
    endpoint_id: str | None = None,
) -> str:
    flow_id = _insert_flow(
        db_path,
        status_code=status_code,
        content_type=content_type,
        body=body,
        host=host,
    )
    upsert_probe_result(
        db_path,
        param_uuid,
        endpoint_id,
        host,
        location,
        param_name,
        analysis,
        payload,
        payload_type,
        payload_index,
        flow_id,
        "completed",
    )
    return flow_id


def _seed_basic_param(db_path: Path) -> tuple[str, str, str, str]:
    """
    Seed baseline + identifier + characters for a reflected query param.
    Returns (param_uuid, host, location, name).
    """
    host = "https://api.example.com"
    location = "query"
    name = "q"
    param_uuid = make_param_uuid(host, location, name)

    # Baseline — value not in body
    _seed_probe(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        analysis="baseline",
        payload=None,
        payload_type="baseline",
        payload_index=0,
        status_code=200,
        body='{"result":"hello"}',
    )
    # Identifier probes reflected in JSON body
    for i, payload in enumerate(["123456", "abcdef", "AbCdEf"]):
        _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="identifier",
            payload=payload,
            payload_type="identifier",
            payload_index=i,
            status_code=200,
            body=json.dumps({"result": f"echo {payload}"}),
        )
    # Characters: quote rejected (400), alpha accepted + reflected
    _seed_probe(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        analysis="characters",
        payload="a",
        payload_type="character",
        payload_index=0,
        status_code=200,
        body='{"result":"a"}',
    )
    _seed_probe(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        analysis="characters",
        payload="'",
        payload_type="character",
        payload_index=1,
        status_code=400,
        body='{"error":"invalid character"}',
    )
    # Length samples
    for i, n in enumerate([1, 16, 128]):
        _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="length",
            payload="a" * n,
            payload_type="length",
            payload_index=i,
            status_code=200 if n <= 16 else 400,
            body='{"ok":true}' if n <= 16 else '{"error":"too long"}',
        )
    # Types
    _seed_probe(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        analysis="types",
        payload="42",
        payload_type="integer",
        payload_index=0,
        status_code=200,
        body='{"result":42}',
    )
    # Validation null_byte rejected
    _seed_probe(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        analysis="validation",
        payload="\x00",
        payload_type="null_byte",
        payload_index=0,
        status_code=400,
        body='{"error":"bad"}',
    )
    return param_uuid, host, location, name


# ---------------------------------------------------------------------------
# Taxonomy helpers
# ---------------------------------------------------------------------------

class TestCharTaxonomy:
    def test_known_chars(self) -> None:
        assert "quote" in char_to_taxonomy_classes("'")
        assert "alpha" in char_to_taxonomy_classes("a")
        assert "digit" in char_to_taxonomy_classes("1")
        assert "markup" in char_to_taxonomy_classes("<")
        assert "null" in char_to_taxonomy_classes("\x00")

    def test_empty_for_multipart_payload(self) -> None:
        assert char_to_taxonomy_classes("ab") == []


class TestDetectReflection:
    def test_raw_and_html_encoded(self) -> None:
        r = detect_payload_reflection("abc", "xx abc yy", "text/html")
        assert r["reflected"] is True
        assert r["encoding"] == "raw"
        assert r["location"] == "html"

        r2 = detect_payload_reflection("<x>", "xx &lt;x&gt; yy", "text/html")
        assert r2["reflected"] is True
        assert r2["encoding"] == "html_encoded"


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------

class TestSynthesizeParamProfile:
    def test_produces_nonempty_profile_offline(self, db_path: Path) -> None:
        param_uuid, host, location, name = _seed_basic_param(db_path)
        profile = synthesize_param_profile(
            db_path, param_uuid, persist=True, bump_version=True,
        )

        assert profile["schema_version"] == 1
        assert profile["param_uuid"] == param_uuid
        assert profile["host"] == host
        assert profile["location"] == location
        assert profile["name"] == name
        assert profile["requests_used"] > 0
        assert profile["observed"]["baseline_fingerprint"]
        assert profile["observed"]["baseline_fingerprint"].get("status_code") == 200

        # Reflection observed
        refl = profile["observed"]["reflection"]
        assert refl["state"] == "reflected"
        assert refl["confidence"] >= 60
        assert CAPABILITY_REFLECTIVE_INPUT in profile["capabilities"]
        assert CAPABILITY_JSON_PARSER in profile["capabilities"] or CAPABILITY_JSON_CONTEXT in profile["capabilities"]

        # Acceptance classes
        classes = profile["observed"]["acceptance"]["classes"]
        assert "alpha" in classes or "a" in profile["observed"]["acceptance"]["chars"]
        if "quote" in classes:
            assert classes["quote"]["outcome"] == "rejected"

        # Length
        length = profile["observed"]["length"]
        assert length.get("max_accepted") in (1, 16)
        assert length["state"] in ("bounded", "open", "all_rejected")

        # Types + tested
        assert "integer" in profile["observed"]["types"]
        assert "null" in profile["tested"] or "null_byte" in profile["tested"]

        # Attempts bounded mutation history
        assert isinstance(profile["attempts"], list)
        assert len(profile["attempts"]) > 0

        # Persisted
        loaded = get_param_profile(db_path, param_uuid)
        assert loaded is not None
        assert loaded["profile_version"] >= 1
        assert loaded["observed"]["reflection"]["state"] == "reflected"

    def test_conflicting_reflection(self, db_path: Path) -> None:
        host = "https://api.example.com"
        location = "query"
        name = "mixed"
        param_uuid = make_param_uuid(host, location, name)

        _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="baseline",
            payload=None,
            payload_type="baseline",
            payload_index=0,
            status_code=200,
            body='{"ok":true}',
        )
        # Half reflected, half not (same analysis=identifier)
        for i, (payload, reflect) in enumerate([
            ("111111", True),
            ("222222", False),
            ("333333", True),
            ("444444", False),
        ]):
            body = json.dumps({"echo": payload}) if reflect else '{"ok":true}'
            _seed_probe(
                db_path,
                param_uuid=param_uuid,
                host=host,
                location=location,
                param_name=name,
                analysis="identifier",
                payload=payload,
                payload_type="identifier",
                payload_index=i,
                status_code=200,
                body=body,
            )

        profile = synthesize_param_profile(
            db_path, param_uuid, persist=False, bump_version=False,
        )
        refl = profile["observed"]["reflection"]
        assert refl["state"] == STATE_CONFLICTING
        assert refl["confidence"] < 60
        assert refl["uncertainty"] in ("high", "low")
        synth = profile["inferred"]["synthesis"]
        assert synth["partial"] is True
        assert any("conflict" in n for n in synth.get("notes") or [])

    def test_partial_without_crash(self, db_path: Path) -> None:
        host = "https://api.example.com"
        location = "body"
        name = "only_base"
        param_uuid = make_param_uuid(host, location, name)
        _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="baseline",
            payload=None,
            payload_type="baseline",
            payload_index=0,
            status_code=200,
            body='{"ok":true}',
        )
        profile = synthesize_param_profile(db_path, param_uuid, persist=True)
        assert profile["schema_version"] == 1
        assert isinstance(profile["observed"], dict)
        assert isinstance(profile["inferred"], dict)
        assert profile["inferred"]["synthesis"]["partial"] is True
        # Baseline alone is incomplete; multiprobe (or legacy identifier) missing.
        missing = profile["inferred"]["synthesis"]["missing_analyses"]
        assert "multiprobe" in missing or "identifier" in missing

    def test_empty_probes_skeleton(self, db_path: Path) -> None:
        uid = "0" * 32
        profile = synthesize_param_profile(db_path, uid, persist=False)
        assert profile["schema_version"] == 1
        assert profile["inferred"]["synthesis"]["completed_probe_count"] == 0
        assert profile["inferred"]["synthesis"]["partial"] is True

    def test_multiprobe_extension_hook(self, db_path: Path) -> None:
        """M4 multiprobe_classes on a probe row fold into acceptance.classes."""
        host = "https://api.example.com"
        location = "query"
        name = "mp"
        param_uuid = make_param_uuid(host, location, name)
        _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="baseline",
            payload=None,
            payload_type="baseline",
            payload_index=0,
            status_code=200,
            body='{"ok":true}',
        )
        # Self-describing multiprobe payload (M4 grammar) rejected by server.
        from talos.input_validation.multiprobe import build_multiprobe_payload

        plan = build_multiprobe_payload(canary="TLhook000000000001")
        flow_id = _seed_probe(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            analysis="multiprobe",
            payload=plan.payload,
            payload_type="multiprobe",
            payload_index=0,
            status_code=400,
            body='{"error":"no"}',
        )
        profile = synthesize_param_profile(db_path, param_uuid, persist=False)
        classes = profile["observed"]["acceptance"]["classes"]
        # No reflection → classes may be rejected/unknown from fingerprint, but
        # multiprobe still records taxonomy keys from the plan.
        assert classes, "multiprobe should populate acceptance.classes"
        assert any(
            (v.get("source") == "multiprobe") for v in classes.values()
        )
        assert flow_id


class TestAnalysisRace:
    def test_ready_when_probes_complete_no_pending(self, db_path: Path) -> None:
        param_uuid, *_ = _seed_basic_param(db_path)
        ready = analysis_probes_ready(db_path, param_uuid)
        assert ready["wait"] is False
        assert ready["ready"] is True
        assert ready["completed_probe_count"] > 0
        assert "baseline" in ready["completed_analyses"]

    def test_wait_when_pending_scan_jobs(self, db_path: Path) -> None:
        param_uuid, host, location, name = _seed_basic_param(db_path)
        with sqlite3.connect(str(db_path)) as conn:
            # Ensure scheduler_jobs table exists (from init)
            conn.execute(
                """
                INSERT INTO scheduler_jobs
                    (job_id, endpoint_id, job_type, priority, status, created_at, meta)
                VALUES (?, NULL, 'iv_characters', 50, 'pending', datetime('now'), ?)
                """,
                (
                    str(uuid.uuid4()),
                    json.dumps({
                        "parameter_uuid": param_uuid,
                        "host": host,
                        "location": location,
                        "parameter_name": name,
                    }),
                ),
            )
            conn.commit()
        ready = analysis_probes_ready(db_path, param_uuid)
        assert ready["wait"] is True
        assert ready["ready"] is False
        assert ready["pending_scan_jobs"] >= 1


class TestSynthesizeManyAndShow:
    def test_synthesize_many_and_list(self, db_path: Path) -> None:
        p1, host, *_ = _seed_basic_param(db_path)
        # second param
        host2 = host
        loc2 = "header"
        name2 = "X-Token"
        p2 = make_param_uuid(host2, loc2, name2)
        _seed_probe(
            db_path,
            param_uuid=p2,
            host=host2,
            location=loc2,
            param_name=name2,
            analysis="baseline",
            payload=None,
            payload_type="baseline",
            payload_index=0,
            status_code=200,
            body="ok",
            content_type="text/plain",
        )
        uuids = list_param_uuids_with_probes(db_path)
        assert p1 in uuids and p2 in uuids

        summary = synthesize_many(db_path, host=host, persist=True)
        assert summary["requested"] >= 2
        assert summary["synthesized"] + summary["empty"] >= 1
        assert get_param_profile(db_path, p1) is not None

    def test_format_summary_lines(self, db_path: Path) -> None:
        param_uuid, *_ = _seed_basic_param(db_path)
        profile = synthesize_param_profile(db_path, param_uuid, persist=False)
        lines = format_profile_summary_lines(profile)
        assert lines
        joined = "\n".join(lines)
        assert "Reflection" in joined or "reflection" in joined.lower() or "state=" in joined

    def test_get_parameter_profile_attaches_intelligence(self, db_path: Path) -> None:
        """When parameters table row exists, intelligence_profile is attached."""
        host = "https://api.example.com"
        location = "query"
        name = "q"
        param_uuid, *_ = _seed_basic_param(db_path)
        synthesize_param_profile(db_path, param_uuid, persist=True)

        param_id = str(uuid.uuid4())
        with sqlite3.connect(str(db_path)) as conn:
            # Reuse endpoint created by flow seeding (unique on host/method/path).
            ep_row = conn.execute(
                """
                SELECT id FROM endpoints
                WHERE project_id = 'proj' AND host = ? AND method = 'GET'
                  AND normalized_path = '/v1/items'
                LIMIT 1
                """,
                (host,),
            ).fetchone()
            if ep_row:
                ep_id = ep_row[0]
            else:
                ep_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO endpoints
                        (id, project_id, host, method, path, normalized_path,
                         first_seen, last_seen)
                    VALUES (?, 'proj', ?, 'GET', '/v1/items', '/v1/items',
                            datetime('now'), datetime('now'))
                    """,
                    (ep_id, host),
                )
            cols = {r[1] for r in conn.execute("PRAGMA table_info(parameters)").fetchall()}
            row = {
                "id": param_id,
                "endpoint_id": ep_id,
                "name": name,
                "location": location,
                "param_type": "string",
                "semantic_type": "unknown",
                "example_values": "[]",
                "seen_count": 1,
                "appears_in_roles": "[]",
                "appears_in_modules": "[]",
                "is_reflected": 0,
                "reflection_count": 0,
                "reflection_locations": "[]",
                "reflection_encoding": "[]",
            }
            use = {k: v for k, v in row.items() if k in cols}
            conn.execute(
                f"INSERT INTO parameters ({', '.join(use)}) VALUES ({', '.join('?' for _ in use)})",
                tuple(use.values()),
            )
            conn.commit()

        profile = get_parameter_profile(db_path, param_id)
        assert profile is not None
        assert profile.get("intelligence_profile") is not None
        assert profile["intelligence_profile"]["observed"]["reflection"]["state"] == "reflected"
