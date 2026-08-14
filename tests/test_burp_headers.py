"""
Tests for Burp Suite metadata headers (talos.burp) and the burp config section.

Covers:
    - Header contract / sanitization
    - IV trace attachment + flow_meta round-trip
    - maybe_apply_burp_headers policy (disabled / no upstream / no trace)
    - Layered config registration (defaults, schema, EffectiveConfig)
    - Replay engine attaches headers only when upstream + enabled
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from talos.burp.config import (
    BurpRuntimeConfig,
    burp_config_from_effective,
    reset_process_burp_config,
    set_process_burp_config,
)
from talos.burp.ingest import reset_ingest_state
from talos.burp.headers import (
    HEADER_ANALYSIS,
    HEADER_DETAIL,
    HEADER_ENDPOINT,
    HEADER_ENDPOINT_ID,
    HEADER_ENGINE,
    HEADER_GROUP,
    HEADER_HOST,
    HEADER_LOCATION,
    HEADER_PARAM,
    HEADER_PAYLOAD_TYPE,
    HEADER_PROJECT,
    HEADER_RECORD_ID,
    HEADER_TECHNIQUE,
    apply_overlay,
    apply_trace_headers,
    build_headers,
    maybe_apply_burp_headers,
    sanitize_header_value,
    sanitize_prefix,
)
from talos.burp.trace import (
    ENGINE_AUTH_SESSION,
    ENGINE_BAC,
    ENGINE_CORS,
    ENGINE_INPUT_VALIDATION,
    ENGINE_INTRUDER,
    ENGINE_UNAUTH,
    GROUP_ENDPOINTS,
    BurpTrace,
    attach_burp_trace,
    attach_iv_burp_trace,
    endpoint_label,
    normalize_host,
    trace_from_flow_meta,
)
from talos.configuration.defaults import (
    BUILTIN_DEFAULTS,
    CONFIG_SECTIONS,
    KNOWN_LEAF_PATHS,
    SECTION_META,
    SETTING_SCHEMA,
)
from talos.configuration.manager import ConfigurationManager
from talos.projects.db import init_project_db


@pytest.fixture(autouse=True)
def _reset_burp_cache() -> None:
    reset_process_burp_config()
    reset_ingest_state()
    yield
    reset_process_burp_config()
    reset_ingest_state()


@pytest.fixture(autouse=True)
def _ingest_down_by_default() -> None:
    """Unit tests assume the extension is not loaded unless they patch it."""
    with patch("talos.burp.headers.offer_trace", return_value=False):
        yield


# ------------------------------------------------------------------ #
# Header helpers                                                       #
# ------------------------------------------------------------------ #


def test_sanitize_header_value_strips_controls_and_truncates() -> None:
    dirty = "GET /a\r\nInjected: 1\x00/path"
    cleaned = sanitize_header_value(dirty)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\x00" not in cleaned
    assert "Injected:" in cleaned
    long = "A" * 800
    assert len(sanitize_header_value(long)) == 512


def test_sanitize_prefix_falls_back() -> None:
    assert sanitize_prefix("X-Talos") == "X-Talos"
    assert sanitize_prefix(" X-Custom! ") == "X-Custom"
    assert sanitize_prefix("@@@") == "X-Talos"


def test_build_headers_iv_contract() -> None:
    trace = BurpTrace(
        engine=ENGINE_INPUT_VALIDATION,
        group=GROUP_ENDPOINTS,
        endpoint_label="GET /api/users/{id}",
        host="api.example.com",
        endpoint_id="ep-1",
        extras={
            "param": "username",
            "location": "body",
            "analysis": "types",
            "payload_type": "type:int",
        },
    )
    headers = build_headers(trace)
    assert headers[HEADER_ENGINE] == "input-validation"
    assert headers[HEADER_GROUP] == "endpoints"
    assert headers[HEADER_ENDPOINT] == "GET /api/users/{id}"
    assert headers[HEADER_ENDPOINT_ID] == "ep-1"
    assert headers[HEADER_HOST] == "api.example.com"
    assert headers[HEADER_PARAM] == "username"
    assert headers[HEADER_LOCATION] == "body"
    assert headers[HEADER_ANALYSIS] == "types"
    assert headers[HEADER_PAYLOAD_TYPE] == "type:int"


def test_build_headers_includes_project_and_record() -> None:
    trace = BurpTrace(
        engine=ENGINE_INPUT_VALIDATION,
        group=GROUP_ENDPOINTS,
        endpoint_label="GET /x",
        project_id="acme",
        project_name="Acme",
        record_id="rec-9",
    )
    headers = build_headers(trace)
    assert headers[HEADER_PROJECT] == "acme"
    assert headers[HEADER_RECORD_ID] == "rec-9"


def test_build_headers_custom_prefix() -> None:
    trace = BurpTrace(
        engine="input-validation",
        group="endpoints",
        endpoint_label="POST /login",
    )
    headers = build_headers(trace, prefix="X-Custom")
    assert "X-Custom-Engine" in headers
    assert HEADER_ENGINE not in headers


def test_apply_trace_headers_replaces_same_name_any_case() -> None:
    trace = BurpTrace(
        engine="input-validation",
        group="endpoints",
        endpoint_label="GET /x",
    )
    merged = apply_trace_headers(
        {"Accept": "*/*", "x-talos-engine": "stale"},
        trace,
    )
    assert merged["Accept"] == "*/*"
    assert merged[HEADER_ENGINE] == "input-validation"
    assert "x-talos-engine" not in merged


def test_maybe_apply_skips_without_upstream() -> None:
    trace = BurpTrace(
        engine="input-validation",
        group="endpoints",
        endpoint_label="GET /x",
    )
    out = maybe_apply_burp_headers(
        {"Accept": "*/*"},
        {"burp": trace.to_dict()},
        has_upstream=False,
        config=BurpRuntimeConfig(enabled=True),
    )
    assert HEADER_ENGINE not in out
    assert out["Accept"] == "*/*"


def test_maybe_apply_skips_when_disabled() -> None:
    trace = BurpTrace(
        engine="input-validation",
        group="endpoints",
        endpoint_label="GET /x",
    )
    out = maybe_apply_burp_headers(
        {"Accept": "*/*"},
        {"burp": trace.to_dict()},
        has_upstream=True,
        config=BurpRuntimeConfig(enabled=False),
    )
    assert HEADER_ENGINE not in out


def test_maybe_apply_skips_without_trace() -> None:
    out = maybe_apply_burp_headers(
        {"Accept": "*/*"},
        {"generated_by": "input_validation"},
        has_upstream=True,
        config=BurpRuntimeConfig(enabled=True),
    )
    assert HEADER_ENGINE not in out


def test_maybe_apply_attaches_when_enabled_and_upstream() -> None:
    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    meta: dict = {}
    attach_iv_burp_trace(
        meta,
        flow={"method": "POST", "normalized_path": "/v1/item", "host": "api.example.com", "endpoint_id": "ep-9"},
        endpoint_id="ep-9",
        host="api.example.com",
        parameter_name="qty",
        location="body",
        analysis="baseline",
        payload_type="baseline",
    )
    out = maybe_apply_burp_headers(
        {"Accept": "*/*"},
        meta,
        has_upstream=True,
    )
    assert out[HEADER_ENGINE] == "input-validation"
    assert out[HEADER_GROUP] == "endpoints"
    assert out[HEADER_ENDPOINT] == "POST /v1/item"
    assert out[HEADER_PARAM] == "qty"


def test_maybe_apply_skips_headers_when_ingest_accepts() -> None:
    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    meta: dict = {}
    attach_iv_burp_trace(
        meta,
        flow={"method": "POST", "normalized_path": "/v1/item", "host": "api.example.com"},
        endpoint_id="ep-9",
        host="api.example.com",
    )
    with patch("talos.burp.headers.offer_trace", return_value=True) as offer:
        out = maybe_apply_burp_headers(
            {"Accept": "*/*"},
            meta,
            has_upstream=True,
            method="POST",
            host="api.example.com",
            path="/v1/item",
        )
    assert HEADER_ENGINE not in out
    assert out["Accept"] == "*/*"
    offer.assert_called_once()


# ------------------------------------------------------------------ #
# Trace                                                                #
# ------------------------------------------------------------------ #


def test_endpoint_label_normalizes() -> None:
    assert endpoint_label("get", "api/users") == "GET /api/users"
    assert endpoint_label("", "") == "GET /"


def test_attach_and_parse_iv_trace() -> None:
    meta: dict = {"generated_by": "input_validation"}
    attach_iv_burp_trace(
        meta,
        flow={
            "method": "GET",
            "path": "/users/5",
            "normalized_path": "/users/{id}",
            "host": "ex.test",
            "endpoint_id": "ep-a",
        },
        parameter_name="id",
        location="path",
        analysis="characters",
        payload_type="char:slash",
    )
    parsed = trace_from_flow_meta(meta)
    assert parsed is not None
    assert parsed.engine == ENGINE_INPUT_VALIDATION
    assert parsed.group == GROUP_ENDPOINTS
    assert parsed.endpoint_label == "GET /users/{id}"
    assert parsed.endpoint_id == "ep-a"
    assert parsed.extras["param"] == "id"
    assert parsed.engine_label == "Input Validation"
    assert parsed.group_label == "Endpoints"


def test_trace_from_flow_meta_rejects_incomplete() -> None:
    assert trace_from_flow_meta(None) is None
    assert trace_from_flow_meta({}) is None
    assert trace_from_flow_meta({"burp": {"engine": "input-validation"}}) is None


def test_normalize_host_strips_scheme() -> None:
    assert normalize_host("http://myapp.local:3000") == "myapp.local:3000"
    assert normalize_host("myapp.local:3000") == "myapp.local:3000"
    assert normalize_host("https://api.example.com/path") == "api.example.com"


def test_attach_other_engines() -> None:
    flow = {"method": "POST", "path": "/login", "host": "http://myapp.local:3000"}
    cases = (
        (ENGINE_UNAUTH, "Unauthenticated Execution", {"technique": "strip_cookies"}),
        (ENGINE_BAC, "BAC", {"technique": "bac_session_swap", "variant": "v1"}),
        (ENGINE_AUTH_SESSION, "Auth-Session Testing", {"technique": "jwt", "variant": "alg_none"}),
        (ENGINE_CORS, "CORS Misconfiguration", {"technique": "reflected", "origin": "https://evil.test"}),
        (ENGINE_INTRUDER, "Intruder", {"attempt": "12", "variant": "user=admin"}),
    )
    for token, label, extras in cases:
        meta: dict = {}
        attach_burp_trace(meta, engine=token, flow=flow, extras=extras)
        parsed = trace_from_flow_meta(meta)
        assert parsed is not None
        assert parsed.engine == token
        assert parsed.engine_label == label
        assert parsed.host == "myapp.local:3000"
        assert parsed.endpoint_label == "POST /login"
        headers = build_headers(parsed)
        assert headers[HEADER_ENGINE] == token
        assert HEADER_DETAIL in headers


def test_apply_overlay_on_header_list() -> None:
    out = apply_overlay(
        [("Accept", "*/*"), ("X-Talos-Engine", "stale")],
        {HEADER_ENGINE: "cors"},
    )
    assert out == [("Accept", "*/*"), (HEADER_ENGINE, "cors")]


# ------------------------------------------------------------------ #
# Layered config                                                       #
# ------------------------------------------------------------------ #


def test_burp_in_builtin_defaults() -> None:
    assert "burp" in BUILTIN_DEFAULTS
    assert BUILTIN_DEFAULTS["burp"]["enabled"] is True
    assert BUILTIN_DEFAULTS["burp"]["header_prefix"] == "X-Talos"
    assert "burp" in CONFIG_SECTIONS
    assert "burp" in SECTION_META
    assert "burp.enabled" in KNOWN_LEAF_PATHS
    assert "burp.header_prefix" in KNOWN_LEAF_PATHS
    schema_keys = {e["key"] for e in SETTING_SCHEMA if e["section"] == "burp"}
    assert schema_keys == {"burp.enabled", "burp.header_prefix"}


def test_effective_config_has_burp(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "projects").mkdir()
    mgr = ConfigurationManager(data_dir)
    eff = mgr.load()
    assert eff.burp.enabled is True
    assert eff.burp.header_prefix == "X-Talos"
    assert burp_config_from_effective(eff).enabled is True


def test_project_can_disable_burp(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    projects = data_dir / "projects"
    projects.mkdir()
    pdir = projects / "demo"
    pdir.mkdir()
    (pdir / "project.yaml").write_text("burp:\n  enabled: false\n  header_prefix: X-Custom\n")
    mgr = ConfigurationManager(data_dir)
    eff = mgr.load(project_data_dir=pdir)
    assert eff.burp.enabled is False
    assert eff.burp.header_prefix == "X-Custom"


# ------------------------------------------------------------------ #
# Replay engine                                                        #
# ------------------------------------------------------------------ #


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _role_module(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name = 'global'").fetchone()
        module = conn.execute("SELECT id FROM modules WHERE name = 'global'").fetchone()
    return role[0], module[0]


def _base_flow(db_path: Path) -> dict:
    role_id, module_id = _role_module(db_path)
    return {
        "id": str(uuid.uuid4()),
        "method": "GET",
        "url": "https://api.example.com/v1/item",
        "host": "api.example.com",
        "path": "/v1/item",
        "query": "",
        "request_headers": json.dumps({"Host": "api.example.com", "Accept": "*/*"}),
        "request_cookies": "{}",
        "request_body": None,
        "request_body_truncated": 0,
        "role_id": role_id,
        "module_id": module_id,
        "endpoint_id": "ep-iv-1",
    }


def test_replay_adds_headers_when_upstream_enabled(db_path: Path) -> None:
    from talos.replay.engine import replay_with_mutation

    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    flow = _base_flow(db_path)
    meta: dict = {"generated_by": "input_validation"}
    attach_iv_burp_trace(
        meta,
        flow={**flow, "normalized_path": "/v1/item"},
        endpoint_id="ep-iv-1",
        host="api.example.com",
        parameter_name="id",
        location="query",
        analysis="types",
        payload_type="type:int",
    )

    sent: dict = {}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def request(self, **kwargs):
            sent.update(kwargs)
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"{}"
            resp.headers = {"content-type": "application/json"}
            return resp

    with patch("talos.replay.engine.get_upstream_url", return_value="http://127.0.0.1:8081"), patch(
        "talos.replay.engine.httpx.AsyncClient", return_value=_Client()
    ):
        outcome = asyncio.run(
            replay_with_mutation(
                original_flow=flow,
                mutations={},
                db_path=db_path,
                project_id="proj",
                source="auto_replay",
                replay_reason="input_validation",
                flow_meta=meta,
            )
        )

    assert outcome.success
    headers = sent["headers"]
    assert headers[HEADER_ENGINE] == "input-validation"
    assert headers[HEADER_GROUP] == "endpoints"
    assert headers[HEADER_ENDPOINT] == "GET /v1/item"
    assert headers[HEADER_PARAM] == "id"


def test_replay_omits_headers_in_direct_mode(db_path: Path) -> None:
    from talos.replay.engine import replay_with_mutation

    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    flow = _base_flow(db_path)
    meta: dict = {}
    attach_iv_burp_trace(
        meta,
        flow=flow,
        endpoint_id="ep-iv-1",
        host="api.example.com",
        parameter_name="id",
        location="query",
        analysis="types",
        payload_type="type:int",
    )
    sent: dict = {}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def request(self, **kwargs):
            sent.update(kwargs)
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"{}"
            resp.headers = {}
            return resp

    with patch("talos.replay.engine.get_upstream_url", return_value=None), patch(
        "talos.replay.engine.httpx.AsyncClient", return_value=_Client()
    ):
        asyncio.run(
            replay_with_mutation(
                original_flow=flow,
                mutations={},
                db_path=db_path,
                project_id="proj",
                source="auto_replay",
                replay_reason="input_validation",
                flow_meta=meta,
            )
        )

    assert HEADER_ENGINE not in sent["headers"]
