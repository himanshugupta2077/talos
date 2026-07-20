"""
Unit tests for Input Validation Module 4 — Canaries & Multiprobe.

Covers:
    - High-entropy canary generation and collision avoidance
    - Multiprobe payload grammar (self-describing, parse round-trip)
    - Analyzer: reflection + multiple taxonomy outcomes from one body
    - Analyzer: no-reflection path (lower confidence / unknown classes)
    - HTML / URL encoding detection for canary and samples
    - Identifier strategy: standard uses canaries; exhaustive keeps weak list
    - Engine scheduling: standard strategy enqueues multiprobe, skips chars
    - Evidence: multiprobe meta structure on job payload
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from talos.input_validation.config import IVConfig, IVAnalysesConfig, save_config, load_config
from talos.input_validation.engine import (
    _probes_for_phase,
    _strategy_skips_characters,
    _strategy_skips_identifier,
    make_param_uuid,
    schedule_endpoint,
)
from talos.input_validation.multiprobe import (
    DEFAULT_CANARY_PREFIX,
    LEGACY_WEAK_IDENTIFIERS,
    MULTIPROBE_SEPARATOR,
    analyze_multiprobe_response,
    build_canary_identifier_probes,
    build_multiprobe_payload,
    canary_collides,
    generate_canary,
    identifier_probes_for_strategy,
    parse_multiprobe_payload,
)
from talos.input_validation.synthesize import synthesize_param_profile
from talos.input_validation.db import upsert_probe_result
from talos.projects.db import init_project_db
from talos.scheduler.job import IV_CHARACTERS, IV_IDENTIFIER, IV_MULTIPROBE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _seed_endpoint_param(
    db_path: Path,
    *,
    host: str = "api.example.com",
    path: str = "/v1/items",
    param_name: str = "q",
    location: str = "query",
) -> tuple[str, str]:
    """Insert qualified endpoint + parameter; return (endpoint_id, param_uuid)."""
    ep_id = str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, param_name)
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()
        role_id = role[0] if role else "r1"
        module_id = mod[0] if mod else "m1"
        if not role:
            conn.execute(
                "INSERT INTO roles (id, name, is_active) VALUES (?, 'global', 1)",
                (role_id,),
            )
        if not mod:
            conn.execute(
                "INSERT INTO modules (id, name, description, is_active) "
                "VALUES (?, 'global', '', 1)",
                (module_id,),
            )
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, 'proj', ?, 'GET', ?, ?, datetime('now'), datetime('now'))
            """,
            (ep_id, host, path, path),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, qualified, excluded, updated_at)
            VALUES (?, 1, 0, datetime('now'))
            """,
            (ep_id,),
        )
        conn.execute(
            """
            INSERT INTO parameters (id, endpoint_id, name, location, param_type)
            VALUES (?, ?, ?, ?, 'string')
            """,
            (str(uuid.uuid4()), ep_id, param_name, location),
        )
        conn.commit()
    return ep_id, param_uuid


def _seed_flow_body(
    db_path: Path,
    *,
    body: str,
    host: str = "api.example.com",
    status_code: int = 200,
    content_type: str = "text/html",
) -> str:
    flow_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()
        mod = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()
        role_id = role[0] if role else "r1"
        module_id = mod[0] if mod else "m1"
        ep = conn.execute("SELECT id FROM endpoints LIMIT 1").fetchone()
        ep_id = ep[0] if ep else str(uuid.uuid4())
        if not ep:
            conn.execute(
                """
                INSERT INTO endpoints
                    (id, project_id, host, method, path, normalized_path,
                     first_seen, last_seen)
                VALUES (?, 'proj', ?, 'GET', '/', '/', datetime('now'), datetime('now'))
                """,
                (ep_id, host),
            )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path, query,
                 request_headers, request_cookies, status_code, response_headers,
                 response_body, content_type, endpoint_id, role_id, module_id,
                 tags, source, flow_meta)
            VALUES (?, 'proj', '2024-01-01T00:00:00+00:00', 'GET', ?, ?, '/', '',
                    '{}', '{}', ?, ?, ?, ?, ?, ?, ?, '[]', 'auto_replay', '{}')
            """,
            (
                flow_id,
                f"https://{host}/",
                host,
                status_code,
                json.dumps({"Content-Type": content_type}),
                body.encode("utf-8"),
                content_type,
                ep_id,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return flow_id


# ---------------------------------------------------------------------------
# Canaries
# ---------------------------------------------------------------------------

class TestCanaries:
    def test_generate_canary_prefix_and_entropy(self) -> None:
        c = generate_canary(prefix="TL", hex_len=16)
        assert c.startswith("TL")
        assert len(c) == 2 + 16
        # High entropy: hex only after prefix
        assert all(ch in "0123456789abcdef" for ch in c[2:])

    def test_unique_canaries(self) -> None:
        batch = {generate_canary() for _ in range(40)}
        assert len(batch) == 40

    def test_avoid_static_collision(self) -> None:
        static = "Welcome to our site. Contact support."
        c = generate_canary(avoid_in=static)
        assert not canary_collides(c, static)
        # Common weak tokens are NOT our canaries
        assert c not in ("123456", "abcdef")

    def test_canary_collides(self) -> None:
        assert canary_collides("TLabc", "foo TLabc bar") is True
        assert canary_collides("TLabc", "no match") is False


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

class TestMultiprobePayload:
    def test_build_and_parse_roundtrip(self) -> None:
        plan = build_multiprobe_payload(canary="TLdeadbeefcafef00d")
        assert plan.canary == "TLdeadbeefcafef00d"
        assert plan.payload.startswith(plan.canary)
        assert plan.payload.endswith(plan.canary)
        assert MULTIPROBE_SEPARATOR in plan.payload
        assert len(plan.fragments) >= 8

        parsed = parse_multiprobe_payload(plan.payload)
        assert parsed is not None
        assert parsed.canary == plan.canary
        names = [f.class_name for f in parsed.fragments]
        assert "quote" in names
        assert "markup" in names
        assert "digit" in names

    def test_separator_not_in_samples(self) -> None:
        plan = build_multiprobe_payload()
        for frag in plan.fragments:
            assert MULTIPROBE_SEPARATOR not in frag.sample

    def test_to_dict_for_flow_meta(self) -> None:
        plan = build_multiprobe_payload(canary="TLmeta000000000001")
        d = plan.to_dict()
        assert d["canary"] == "TLmeta000000000001"
        assert "fragments" in d
        assert "classes" in d


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class TestMultiprobeAnalyzer:
    def test_one_request_reflection_and_classes(self) -> None:
        plan = build_multiprobe_payload(canary="TLreflect000000001")
        # Body reflects canary + most samples raw
        samples = "".join(f.sample for f in plan.fragments if f.sample != "\x00")
        body = f"<div>echo {plan.canary} {samples}</div>"
        result = analyze_multiprobe_response(plan, body, "text/html")

        assert result.canary_reflected is True
        assert result.canary_encoding == "raw"
        assert result.confidence_reflection >= 85
        assert result.location == "html"
        # Multiple taxonomy outcomes from one body
        assert len(result.multiprobe_classes) >= 5
        assert "quote" in result.class_outcomes
        assert result.class_outcomes["quote"]["outcome"] in (
            "accepted", "encoded", "normalized",
        )
        assert result.class_outcomes["quote"]["confidence"] >= 80

    def test_html_encoded_canary(self) -> None:
        plan = build_multiprobe_payload(
            canary="TLhtmlenc000000001",
            class_samples=(("markup", "<"), ("quote", "'")),
        )
        # HTML-encode canary is unusual; encode the markup sample
        body = f"ok {plan.canary} &lt; &#x27;"
        result = analyze_multiprobe_response(plan, body, "text/html")
        assert result.canary_reflected is True
        assert result.class_outcomes["markup"]["outcome"] == "encoded"
        assert result.class_outcomes["markup"]["encoding"] == "html_encoded"

    def test_filtered_class_when_canary_present(self) -> None:
        plan = build_multiprobe_payload(
            canary="TLfilter0000000001",
            class_samples=(("quote", "'"), ("markup", "<"), ("digit", "7")),
        )
        # Reflect canary + digit only; strip quotes and markup
        body = f"value={plan.canary}-7-safe"
        result = analyze_multiprobe_response(plan, body, "application/json")
        assert result.canary_reflected is True
        assert result.class_outcomes["digit"]["survived"] is True
        assert result.class_outcomes["quote"]["outcome"] == "rejected"
        assert result.class_outcomes["markup"]["outcome"] == "rejected"

    def test_no_reflection_lower_confidence(self) -> None:
        plan = build_multiprobe_payload(canary="TLnoreflect0000001")
        body = '{"error":"invalid input","ok":false}'
        result = analyze_multiprobe_response(
            plan,
            body,
            "application/json",
            fingerprint_outcome="rejected",
            fingerprint_confidence=80,
        )
        assert result.canary_reflected is False
        assert result.multiprobe_classes == []
        for cls, entry in result.class_outcomes.items():
            assert entry["outcome"] in ("rejected", "unknown")
            assert entry["confidence"] < 60

    def test_parse_payload_string_path(self) -> None:
        plan = build_multiprobe_payload(canary="TLparse00000000001")
        body = f"x={plan.canary} and a and 7"
        result = analyze_multiprobe_response(plan.payload, body, "text/plain")
        assert result.canary_reflected is True

    def test_canary_not_in_common_static(self) -> None:
        """Unique canaries do not collide with common static content."""
        static_pages = [
            "<html><body>Login</body></html>",
            '{"status":"ok","version":"1.2.3"}',
            "123456 abcdef ABCDEF error page not found",
            "Copyright 2024 Example Corp. All rights reserved.",
        ]
        for page in static_pages:
            c = generate_canary(avoid_in=page)
            assert c not in page
            assert not canary_collides(c, page)


# ---------------------------------------------------------------------------
# Identifier strategy
# ---------------------------------------------------------------------------

class TestIdentifierStrategy:
    def test_standard_uses_canaries_not_weak(self) -> None:
        probes = identifier_probes_for_strategy("standard")
        assert len(probes) >= 1
        for p in probes:
            assert p.startswith(DEFAULT_CANARY_PREFIX)
            assert p not in LEGACY_WEAK_IDENTIFIERS

    def test_exhaustive_includes_legacy_weak(self) -> None:
        probes = identifier_probes_for_strategy("exhaustive")
        for weak in LEGACY_WEAK_IDENTIFIERS:
            assert weak in probes
        # Plus at least one canary
        assert any(p.startswith(DEFAULT_CANARY_PREFIX) for p in probes)

    def test_strategy_skips(self) -> None:
        assert _strategy_skips_identifier("standard", True) is True
        assert _strategy_skips_characters("standard", True) is True
        assert _strategy_skips_identifier("exhaustive", True) is False
        assert _strategy_skips_characters("deep", True) is False
        assert _strategy_skips_characters("standard", False) is False


# ---------------------------------------------------------------------------
# Engine scheduling
# ---------------------------------------------------------------------------

class TestEngineScheduling:
    def test_standard_multiprobe_probes(self) -> None:
        cfg = IVConfig(probe_strategy="standard")
        probes = _probes_for_phase(IV_MULTIPROBE, cfg)
        assert len(probes) == 1
        ptype, payload = probes[0]
        assert ptype == "multiprobe"
        assert MULTIPROBE_SEPARATOR in payload
        assert parse_multiprobe_payload(payload) is not None

    def test_standard_skips_chars_and_identifier_when_multiprobe(self) -> None:
        cfg = IVConfig(
            probe_strategy="standard",
            analyses=IVAnalysesConfig(multiprobe=True),
        )
        assert _probes_for_phase(IV_IDENTIFIER, cfg) == []
        assert _probes_for_phase(IV_CHARACTERS, cfg) == []

    def test_exhaustive_keeps_chars_and_weak_ids(self) -> None:
        cfg = IVConfig(
            probe_strategy="exhaustive",
            analyses=IVAnalysesConfig(multiprobe=True),
        )
        ids = _probes_for_phase(IV_IDENTIFIER, cfg)
        chars = _probes_for_phase(IV_CHARACTERS, cfg)
        assert len(ids) >= len(LEGACY_WEAK_IDENTIFIERS)
        assert any(p[1] in LEGACY_WEAK_IDENTIFIERS for p in ids)
        # Module 6: exhaustive uses extended taxonomy list (legacy + structure).
        from talos.input_validation.phases import IV_TEST_CHARS
        from talos.input_validation.taxonomy import EXHAUSTIVE_TEST_CHARS
        assert len(chars) == len(EXHAUSTIVE_TEST_CHARS)
        for c in IV_TEST_CHARS:
            assert any(p[1] == c for p in chars)

    def test_schedule_endpoint_enqueues_baseline_first(
        self, db_path: Path
    ) -> None:
        """
        Module 5 planner: standard run enqueues only the first wave (baseline),
        not the full matrix. Multiprobe follows after baseline completes.
        """
        save_config(
            db_path,
            IVConfig(
                enabled=True,
                probe_strategy="standard",
                analyses=IVAnalysesConfig(
                    multiprobe=True,
                    length=False,
                    types=False,
                    validation=False,
                    transformations=False,
                    reflection=False,
                    identifier=True,
                    characters=True,
                ),
            ),
        )
        ep_id, _ = _seed_endpoint_param(db_path)
        n = schedule_endpoint(
            db_path, "proj", ep_id, phase_filter=None, ignore_cache=True
        )
        # Planner: first wave is baseline only (not ~70 jobs, not even multiprobe yet)
        assert n == 1
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, meta FROM scheduler_jobs ORDER BY created_at"
            ).fetchall()
        types = [r[0] for r in rows]
        assert types == ["iv_baseline"]
        assert "iv_identifier" not in types
        assert "iv_characters" not in types
        assert "iv_length" not in types

    def test_phase_filter_multiprobe_still_direct(
        self, db_path: Path
    ) -> None:
        """Phase CLI shortcut bypasses planner and enqueues multiprobe jobs."""
        save_config(
            db_path,
            IVConfig(
                enabled=True,
                probe_strategy="standard",
                analyses=IVAnalysesConfig(multiprobe=True),
            ),
        )
        ep_id, _ = _seed_endpoint_param(db_path)
        n = schedule_endpoint(
            db_path, "proj", ep_id, phase_filter=IV_MULTIPROBE, ignore_cache=True
        )
        assert n == 1
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, meta FROM scheduler_jobs"
            ).fetchall()
        assert rows[0][0] == "iv_multiprobe"
        meta = json.loads(rows[0][1])
        assert meta["analysis"] == "multiprobe"
        assert meta.get("multiprobe")
        assert meta["multiprobe"]["canary"]
        assert meta["payload_type"] == "multiprobe"


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

class TestConfigStrategy:
    def test_save_load_probe_strategy(self, db_path: Path) -> None:
        save_config(
            db_path,
            IVConfig(enabled=True, probe_strategy="deep"),
        )
        cfg = load_config(db_path)
        assert cfg.probe_strategy == "deep"
        assert cfg.analyses.multiprobe is True


# ---------------------------------------------------------------------------
# Synthesis from multiprobe (offline)
# ---------------------------------------------------------------------------

class TestSynthesizeMultiprobe:
    def test_multiprobe_sets_reflection_and_classes(self, db_path: Path) -> None:
        host = "api.example.com"
        location = "query"
        name = "q"
        param_uuid = make_param_uuid(host, location, name)
        plan = build_multiprobe_payload(canary="TLsynth00000000001")
        samples = "".join(
            f.sample for f in plan.fragments if f.sample not in ("\x00",)
        )
        body = f"<html>echo:{plan.canary}:{samples}</html>"

        base_flow = _seed_flow_body(
            db_path, body='{"ok":true}', content_type="application/json"
        )
        mp_flow = _seed_flow_body(
            db_path, body=body, content_type="text/html"
        )
        upsert_probe_result(
            db_path, param_uuid, None, host, location, name,
            "baseline", None, "baseline", 0, base_flow, "completed",
        )
        upsert_probe_result(
            db_path, param_uuid, None, host, location, name,
            "multiprobe", plan.payload, "multiprobe", 0, mp_flow, "completed",
        )

        profile = synthesize_param_profile(db_path, param_uuid, persist=False)
        refl = profile["observed"]["reflection"]
        assert refl["state"] == "reflected"
        classes = profile["observed"]["acceptance"]["classes"]
        assert len(classes) >= 3
        # At least one accepted class from multiprobe
        accepted = [
            k for k, v in classes.items()
            if v.get("outcome") in ("accepted", "encoded", "normalized", "modified")
        ]
        assert accepted
        assert any(
            (v.get("source") == "multiprobe")
            for v in classes.values()
        )


class TestBuildCanaryProbes:
    def test_count_bounds(self) -> None:
        assert len(build_canary_identifier_probes(3)) == 3
        assert len(build_canary_identifier_probes(1)) == 1
