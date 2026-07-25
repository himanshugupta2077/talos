"""
Tests: Module 8 — Normalization pipeline & parser fingerprinting.

Coverage:
    - Duplicate-query first_wins / last_wins / join / reject
    - JSON null / empty / omit measurable and stored
    - Normalization pipeline non-empty when reflection shows trim/decode
    - Deep tier includes unicode / double-encode; quick skips most probes
    - Negative evidence when parser rejects duplicates
    - Planner emits parser_probes (not FUTURE stub) on standard/deep
    - Engine expands parser_probes with injection_mode
    - Structural inject: dup query, JSON null, JSON omit, JSON dup key
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import pytest

from talos.input_validation.config import IVConfig
from talos.input_validation.engine import (
    _enqueue_parser_probes,
    make_param_uuid,
)
from talos.input_validation.outcomes import OUTCOME_ACCEPTED, OUTCOME_REJECTED
from talos.input_validation.parser_intel import (
    DUP_FIRST_WINS,
    DUP_JOIN,
    DUP_LAST_WINS,
    DUP_REJECT,
    MODE_DUP_QUERY,
    MODE_JSON_DUP_KEY,
    MODE_JSON_NULL,
    MODE_JSON_OMIT,
    SENTINEL_FIRST,
    SENTINEL_LAST,
    apply_parser_injection,
    apply_parser_synthesis_to_profile,
    detect_duplicate_behavior,
    detect_normalization_stages_from_reflection,
    estimated_parser_probe_count,
    injection_mode_for_payload_type,
    merge_normalization_pipeline,
    pack_dup_payload,
    select_normalization_probes,
    select_parser_fingerprint_probes,
    select_parser_probes,
    synthesize_parser_state,
    unpack_dup_payload,
)
from talos.input_validation.phases import prepare_iv_probe
from talos.input_validation.planner import (
    ACTION_PARSER_PROBES,
    FUTURE_ACTION_TOKENS,
    M8_ACTION_TOKENS,
    PlanAction,
    PlanContext,
    plan_next,
)
from talos.input_validation.profile import (
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_JSON_PARSER,
    empty_param_profile,
)
from talos.scheduler.job import IV_PARSER


# ---------------------------------------------------------------------------
# Pure detection
# ---------------------------------------------------------------------------

class TestDuplicateBehavior:
    def test_first_wins(self) -> None:
        body = f"value={SENTINEL_FIRST} ok"
        behavior, conf = detect_duplicate_behavior(body)
        assert behavior == DUP_FIRST_WINS
        assert conf >= 90

    def test_last_wins(self) -> None:
        body = f"got {SENTINEL_LAST}"
        behavior, conf = detect_duplicate_behavior(body)
        assert behavior == DUP_LAST_WINS
        assert conf >= 90

    def test_join(self) -> None:
        body = f"{SENTINEL_FIRST},{SENTINEL_LAST}"
        behavior, conf = detect_duplicate_behavior(body)
        assert behavior == DUP_JOIN
        assert conf >= 90

    def test_reject_on_error_outcome(self) -> None:
        behavior, conf = detect_duplicate_behavior(
            "error: bad request",
            outcome=OUTCOME_REJECTED,
            status_code=400,
        )
        assert behavior == DUP_REJECT
        assert conf >= 80


class TestNormalizationStages:
    def test_trim_detected(self) -> None:
        canary = "TlNormabc123"
        payload = f"  {canary}  "
        stages = detect_normalization_stages_from_reflection(
            payload, "norm:trim", f"echo:{canary}",
        )
        names = [s.stage for s in stages]
        assert "trim" in names
        assert stages[0].confidence >= 80

    def test_url_decode_detected(self) -> None:
        canary = "TlNormxyz"
        payload = f"%41{canary}"
        body = f"A{canary}"
        stages = detect_normalization_stages_from_reflection(
            payload, "norm:url_decode", body,
        )
        assert any(s.stage == "url_decode" and s.confidence >= 80 for s in stages)

    def test_case_lower(self) -> None:
        payload = "AbCdEf"
        stages = detect_normalization_stages_from_reflection(
            payload, "norm:case", "abcdef",
        )
        assert any(s.stage == "case_fold" and s.confidence >= 80 for s in stages)

    def test_pipeline_merge_ordered(self) -> None:
        trim = detect_normalization_stages_from_reflection(
            "  x  ", "norm:trim", "x",
        )
        decode = detect_normalization_stages_from_reflection(
            "%41rest", "norm:url_decode", "Arest",
        )
        pipeline = merge_normalization_pipeline([trim, decode])
        assert pipeline
        stages = [p["stage"] for p in pipeline]
        # url_decode before trim in STAGE_ORDER
        if "url_decode" in stages and "trim" in stages:
            assert stages.index("url_decode") < stages.index("trim")
        assert "reflect" in stages


# ---------------------------------------------------------------------------
# Probe selection by tier / location
# ---------------------------------------------------------------------------

class TestProbeSelection:
    def test_quick_skips_most(self) -> None:
        plan = select_parser_probes(location="query", strategy="quick")
        assert plan.probes == ()
        assert estimated_parser_probe_count("quick") == 0

    def test_standard_query_has_dup(self) -> None:
        plan = select_parser_probes(
            location="query",
            strategy="standard",
            reflection_state="reflected",
        )
        types = [p.payload_type for p in plan.probes]
        assert "parser:dup_query" in types
        assert len(plan.probes) <= 5
        assert any(t.startswith("norm:") for t in types)

    def test_standard_json_null_empty(self) -> None:
        plan = select_parser_probes(
            location="body",
            content_type="application/json",
            strategy="standard",
            reflection_state="not_reflected",
        )
        types = [p.payload_type for p in plan.probes]
        assert "parser:json_null" in types
        assert "parser:json_empty" in types
        # not_reflected → no norm probes
        assert not any(t.startswith("norm:") for t in types)

    def test_deep_extra_unicode_and_double_encode(self) -> None:
        norms = select_normalization_probes(
            strategy="deep", reflection_state="reflected",
        )
        types = [p.payload_type for p in norms]
        assert "norm:double_encode" in types
        assert "norm:unicode" in types

        parsers = select_parser_fingerprint_probes(
            location="query", strategy="deep",
        )
        ptypes = [p.payload_type for p in parsers]
        assert "parser:array_dot" in ptypes or "parser:array_bracket" in ptypes

    def test_standard_norm_no_unicode(self) -> None:
        norms = select_normalization_probes(
            strategy="standard", reflection_state="reflected",
        )
        types = [p.payload_type for p in norms]
        assert "norm:double_encode" not in types
        assert "norm:unicode" not in types
        assert "norm:trim" in types

    def test_header_norm_trim_is_transport_legal(self) -> None:
        """Leading/trailing spaces are illegal as header field-values."""
        from talos.input_validation.surface import is_http_header_value_legal

        norms = select_normalization_probes(
            strategy="standard",
            reflection_state="reflected",
            location="header",
        )
        trim = next(p for p in norms if p.payload_type == "norm:trim")
        assert is_http_header_value_legal(trim.payload)
        assert not trim.payload.startswith(" ")
        assert not trim.payload.endswith(" ")
        assert "  " in trim.payload  # internal pad still present
        assert trim.hypothesis == "norm.trim_internal_space"

        query_trim = next(
            p
            for p in select_normalization_probes(
                strategy="standard",
                reflection_state="reflected",
                location="query",
            )
            if p.payload_type == "norm:trim"
        )
        assert query_trim.payload.startswith("  ")

    def test_injection_mode_map(self) -> None:
        assert injection_mode_for_payload_type("parser:dup_query") == MODE_DUP_QUERY
        assert injection_mode_for_payload_type("parser:json_null") == MODE_JSON_NULL
        assert injection_mode_for_payload_type("norm:trim") == "value"


# ---------------------------------------------------------------------------
# Structural injection
# ---------------------------------------------------------------------------

class TestStructuralInjection:
    def test_dup_query_two_keys(self) -> None:
        url = "https://api.example.com/x?id=1&other=z"
        packed = pack_dup_payload()
        new_url, _, _ = apply_parser_injection(
            injection_mode=MODE_DUP_QUERY,
            location="query",
            name="id",
            payload=packed,
            url=url,
            headers={},
            body=None,
        )
        pairs = parse_qsl(urlparse(new_url).query, keep_blank_values=True)
        id_vals = [v for k, v in pairs if k == "id"]
        assert id_vals == [SENTINEL_FIRST, SENTINEL_LAST]
        assert ("other", "z") in pairs

    def test_json_null(self) -> None:
        body = b'{"name":"alice","age":1}'
        _, _, new_body = apply_parser_injection(
            injection_mode=MODE_JSON_NULL,
            location="body",
            name="name",
            payload="null",
            url="https://x/",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        parsed = json.loads(new_body.decode())
        assert parsed["name"] is None
        assert parsed["age"] == 1

    def test_json_omit(self) -> None:
        body = b'{"name":"alice","age":1}'
        _, _, new_body = apply_parser_injection(
            injection_mode=MODE_JSON_OMIT,
            location="body",
            name="name",
            payload="",
            url="https://x/",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        parsed = json.loads(new_body.decode())
        assert "name" not in parsed
        assert parsed["age"] == 1

    def test_json_dup_key_raw(self) -> None:
        body = b'{"keep":true}'
        packed = pack_dup_payload()
        _, _, new_body = apply_parser_injection(
            injection_mode=MODE_JSON_DUP_KEY,
            location="body",
            name="id",
            payload=packed,
            url="https://x/",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        raw = new_body.decode()
        # Both keys present as text (json.loads would collapse).
        assert raw.count('"id"') == 2
        assert SENTINEL_FIRST in raw
        assert SENTINEL_LAST in raw
        assert "keep" in raw

    def test_prepare_iv_probe_uses_mode(self) -> None:
        flow = {
            "method": "GET",
            "url": "https://api.example.com/search?q=old",
            "request_headers": "{}",
            "request_body": None,
        }
        mutations = prepare_iv_probe(
            "parser",
            flow,
            "q",
            "query",
            pack_dup_payload(),
            payload_type="parser:dup_query",
        )
        assert "url" in mutations
        pairs = parse_qsl(urlparse(mutations["url"]).query, keep_blank_values=True)
        assert [v for k, v in pairs if k == "q"] == [SENTINEL_FIRST, SENTINEL_LAST]


# ---------------------------------------------------------------------------
# Synthesis + negative evidence
# ---------------------------------------------------------------------------

class TestParserSynthesis:
    def test_dup_query_stored_with_capability(self) -> None:
        rows = [{
            "payload_type": "parser:dup_query",
            "payload": pack_dup_payload(),
            "outcome": OUTCOME_ACCEPTED,
            "confidence": 80,
            "body": f"echo {SENTINEL_LAST}",
            "status_code": 200,
            "flow_id": "f1",
        }]
        synth = synthesize_parser_state(rows, location="query")
        assert "duplicate_query" in synth.parser
        assert synth.parser["duplicate_query"]["state"] == DUP_LAST_WINS
        assert CAPABILITY_DUPLICATE_PARAMETER in synth.capabilities

        profile = empty_param_profile(
            param_uuid="u", host="h", location="query", name="q",
        )
        apply_parser_synthesis_to_profile(profile, synth)
        assert profile["observed"]["parser"]["duplicate_query"]["behavior"] == DUP_LAST_WINS
        assert CAPABILITY_DUPLICATE_PARAMETER in profile["capabilities"]

    def test_json_null_empty_stored(self) -> None:
        rows = [
            {
                "payload_type": "parser:json_null",
                "payload": "null",
                "outcome": OUTCOME_ACCEPTED,
                "confidence": 85,
                "body": "{}",
                "status_code": 200,
                "flow_id": "f1",
            },
            {
                "payload_type": "parser:json_empty",
                "payload": "",
                "outcome": OUTCOME_REJECTED,
                "confidence": 90,
                "body": "error",
                "status_code": 400,
                "flow_id": "f2",
            },
        ]
        synth = synthesize_parser_state(rows, location="body")
        assert "json_null" in synth.parser
        assert "json_empty" in synth.parser
        assert synth.parser["json_empty"]["state"] == OUTCOME_REJECTED
        assert CAPABILITY_JSON_PARSER in synth.capabilities

    def test_rejected_duplicate_in_tested(self) -> None:
        rows = [{
            "payload_type": "parser:dup_query",
            "payload": pack_dup_payload(),
            "outcome": OUTCOME_REJECTED,
            "confidence": 88,
            "body": "Bad Request",
            "status_code": 400,
            "flow_id": "f1",
        }]
        synth = synthesize_parser_state(rows, location="query")
        assert "parser:duplicate" in synth.tested_updates
        assert synth.tested_updates["parser:duplicate"]["outcome"] == OUTCOME_REJECTED
        assert synth.tested_updates["parser:duplicate"]["confidence"] >= 80

        profile = empty_param_profile(
            param_uuid="u", host="h", location="query", name="q",
        )
        apply_parser_synthesis_to_profile(profile, synth)
        assert profile["tested"]["parser:duplicate"]["outcome"] == OUTCOME_REJECTED

    def test_normalization_pipeline_non_empty(self) -> None:
        canary = "TlNormpipe01"
        rows = [
            {
                "payload_type": "norm:trim",
                "payload": f"  {canary}  ",
                "outcome": OUTCOME_ACCEPTED,
                "confidence": 80,
                "body": f"out={canary}",
                "status_code": 200,
                "flow_id": "f1",
            },
            {
                "payload_type": "norm:url_decode",
                "payload": f"%41{canary}",
                "outcome": OUTCOME_ACCEPTED,
                "confidence": 80,
                "body": f"A{canary}",
                "status_code": 200,
                "flow_id": "f2",
            },
        ]
        synth = synthesize_parser_state(rows, location="query")
        assert synth.normalization_pipeline
        stages = [s["stage"] for s in synth.normalization_pipeline]
        assert "trim" in stages or "url_decode" in stages


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class TestPlannerM8:
    def test_m8_token_not_future_stub(self) -> None:
        assert ACTION_PARSER_PROBES in M8_ACTION_TOKENS
        assert ACTION_PARSER_PROBES not in FUTURE_ACTION_TOKENS

    def test_quick_does_not_emit_parser_probes(self) -> None:
        ctx = PlanContext(
            budget_tier="quick",
            max_requests=8,
            requests_used=2,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            reflection_state="reflected",
            reflection_confidence=95,
            reflection_uncertainty="none",
            acceptance_class_count=3,
        )
        result = plan_next(ctx)
        actions = [a.action for a in result.actions]
        assert ACTION_PARSER_PROBES not in actions

    def test_deep_emits_parser_probes(self) -> None:
        ctx = PlanContext(
            budget_tier="deep",
            max_requests=40,
            requests_used=6,
            completed_analyses=frozenset({
                "baseline", "multiprobe", "identifier", "characters",
                "length", "types", "validation",
            }),
            multiprobe_completed_count=1,
            identifier_completed_count=1,
            characters_completed_count=1,
            length_completed_count=3,
            types_completed_count=2,
            validation_completed_count=3,
            parser_completed_count=0,
            reflection_state="reflected",
            reflection_confidence=80,
            reflection_uncertainty="low",
            length_state="bounded",
            length_confidence=90,
            length_uncertainty="low",
            types_known=True,
            location="query",
        )
        result = plan_next(ctx)
        actions = [a.action for a in result.actions]
        assert ACTION_PARSER_PROBES in actions
        pa = next(a for a in result.actions if a.action == ACTION_PARSER_PROBES)
        assert pa.estimated_requests >= 1
        assert pa.estimated_requests <= 10

    def test_standard_emits_when_not_early_stop(self) -> None:
        # Low reflection confidence → no early stop → parser can be scheduled.
        ctx = PlanContext(
            budget_tier="standard",
            max_requests=18,
            requests_used=4,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=2,  # no more multiprobe retries
            reflection_state="unknown",
            reflection_confidence=40,
            reflection_uncertainty="high",
            acceptance_class_count=0,
            types_completed_count=0,
            types_known=False,
            validation_completed_count=0,
            parser_completed_count=0,
            location="query",
        )
        result = plan_next(ctx)
        actions = [a.action for a in result.actions]
        # May include type/semantic/parser depending on budget; parser is eligible.
        # At least one follow-up HTTP action expected.
        assert result.state == "EVALUATE" or ACTION_PARSER_PROBES in actions or any(
            a in actions for a in (
                "type_confirm", "semantic_rules", "length_binary", "parser_probes",
            )
        )


# ---------------------------------------------------------------------------
# Engine expansion
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "proj.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE endpoints (
                id TEXT PRIMARY KEY,
                host TEXT,
                method TEXT,
                path TEXT,
                project_id TEXT,
                normalized_path TEXT
            );
            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT,
                name TEXT,
                location TEXT,
                host TEXT,
                semantic_type TEXT DEFAULT 'unknown',
                example_values TEXT DEFAULT '[]',
                seen_count INTEGER DEFAULT 1
            );
            CREATE TABLE scheduler_jobs (
                job_id TEXT PRIMARY KEY,
                endpoint_id TEXT,
                job_type TEXT,
                priority INTEGER,
                status TEXT,
                created_at TEXT,
                meta TEXT
            );
            CREATE TABLE iv_param_profiles (
                param_uuid TEXT PRIMARY KEY,
                host TEXT,
                location TEXT,
                param_name TEXT,
                profile_json TEXT,
                profile_version INTEGER DEFAULT 1,
                updated_at TEXT
            );
            CREATE TABLE iv_probe_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                param_uuid TEXT,
                host TEXT,
                location TEXT,
                param_name TEXT,
                analysis TEXT,
                payload TEXT,
                payload_type TEXT,
                payload_index INTEGER,
                status TEXT,
                flow_id TEXT,
                status_code INTEGER,
                created_at TEXT,
                UNIQUE(param_uuid, analysis, payload_type, payload_index)
            );
            """
        )
    return path


class TestEngineParserExpansion:
    def test_enqueue_parser_jobs_with_injection_mode(self, db_path: Path) -> None:
        host = "api.example.com"
        location = "query"
        name = "q"
        param_uuid = make_param_uuid(host, location, name)
        ep_id = str(uuid.uuid4())
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO endpoints (id, host, method, path, project_id, normalized_path) "
                "VALUES (?, ?, 'GET', '/s', 'p', '/s')",
                (ep_id, host),
            )
            conn.execute(
                "INSERT INTO parameters "
                "(id, endpoint_id, name, location, host, semantic_type, example_values) "
                "VALUES (?, ?, ?, ?, ?, 'string', '[]')",
                (str(uuid.uuid4()), ep_id, name, location, host),
            )

        action = PlanAction(
            action=ACTION_PARSER_PROBES,
            hypothesis="parser.fingerprint_standard",
            estimated_requests=5,
            meta={
                "tier": "standard",
                "location": location,
                "content_type": "",
                "reflection_state": "reflected",
            },
        )
        config = IVConfig()
        # Ensure analyses default on
        n = _enqueue_parser_probes(
            db_path,
            "p",
            host,
            location,
            name,
            param_uuid,
            ep_id,
            config,
            action,
            ignore_cache=True,
        )
        assert n >= 1
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, meta FROM scheduler_jobs WHERE job_type = ?",
                (IV_PARSER,),
            ).fetchall()
        assert len(rows) == n
        metas = [json.loads(r[1]) for r in rows]
        assert all(m.get("analysis") == "parser" for m in metas)
        assert any(m.get("injection_mode") == MODE_DUP_QUERY for m in metas)
        assert any(
            str(m.get("payload_type", "")).startswith("parser:")
            or str(m.get("payload_type", "")).startswith("norm:")
            for m in metas
        )


# ---------------------------------------------------------------------------
# Pack helpers
# ---------------------------------------------------------------------------

class TestPackHelpers:
    def test_pack_unpack_roundtrip(self) -> None:
        packed = pack_dup_payload("aa", "bb")
        assert unpack_dup_payload(packed) == ("aa", "bb")
