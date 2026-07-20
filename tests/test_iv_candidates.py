"""
Unit tests for Input Validation Module 11 — Capabilities & Attack Candidates.

Covers pure scoring fixtures (no network):
    - Reflected HTML + markup accepted → high XSS score with reasons
    - redirect name + URL type → open_redirect / SSRF candidates
    - Rejected quotes reduce SQLi score; negative evidence referenced
    - Stable consumer API get_param_intelligence / list_candidates
    - Capability derivation centralization
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.capabilities import (
    apply_capabilities,
    derive_capabilities,
    has_capability,
)
from talos.input_validation.candidates import (
    ATTACK_HEADER_INJECTION,
    ATTACK_HPP,
    ATTACK_OPEN_REDIRECT,
    ATTACK_SQLI,
    ATTACK_SSRF,
    ATTACK_XSS,
    enrich_profile_capabilities_and_candidates,
    get_param_intelligence,
    list_candidates,
    score_candidates,
)
from talos.input_validation.db import (
    get_param_profile,
    make_param_uuid,
    upsert_param_profile,
)
from talos.input_validation.profile import (
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_URL_LIKE_VALUE,
    empty_param_profile,
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


def _profile(**kwargs) -> dict:
    p = empty_param_profile(
        param_uuid=kwargs.pop("param_uuid", "abc123"),
        host=kwargs.pop("host", "api.example.com"),
        location=kwargs.pop("location", "query"),
        name=kwargs.pop("name", "q"),
    )
    for k, v in kwargs.items():
        p[k] = v
    return p


def _cand(cands: list[dict], attack: str) -> dict | None:
    for c in cands:
        if c.get("attack") == attack:
            return c
    return None


# ---------------------------------------------------------------------------
# Capability derivation
# ---------------------------------------------------------------------------

def test_derive_reflective_html_capabilities():
    profile = _profile()
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 90,
        "uncertainty": "none",
        "contexts": ["html"],
        "evidence_flow_ids": ["flow-1"],
    }
    profile["observed"]["baseline_fingerprint"] = {"content_type": "html"}
    caps = derive_capabilities(profile)
    assert CAPABILITY_REFLECTIVE_INPUT in caps
    assert CAPABILITY_HTML_CONTEXT in caps


def test_derive_url_like_and_header_surface():
    profile = _profile(location="header", name="X-Forwarded-Host")
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 80},
    }
    profile["observed"]["baseline_fingerprint"] = {"redirect": True}
    caps = derive_capabilities(profile)
    assert CAPABILITY_URL_LIKE_VALUE in caps
    assert CAPABILITY_HEADER_INJECTION_SURFACE in caps
    assert "redirect_like" in caps


def test_apply_capabilities_overwrites_list():
    profile = _profile()
    profile["capabilities"] = ["stale_flag_unknown"]
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "contexts": ["json"],
        "confidence": 70,
        "uncertainty": "low",
    }
    profile["observed"]["baseline_fingerprint"] = {"content_type": "json"}
    apply_capabilities(profile)
    assert CAPABILITY_REFLECTIVE_INPUT in profile["capabilities"]
    assert "json_context" in profile["capabilities"] or "json_parser" in profile["capabilities"]


# ---------------------------------------------------------------------------
# XSS scoring
# ---------------------------------------------------------------------------

def test_xss_high_when_reflected_html_and_markup_accepted():
    profile = _profile(name="comment")
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 95,
        "uncertainty": "none",
        "contexts": ["html"],
        "evidence_flow_ids": ["f-html"],
    }
    profile["observed"]["acceptance"] = {
        "classes": {
            "markup": {
                "outcome": "accepted",
                "confidence": 90,
                "evidence_flow_ids": ["f-markup"],
            },
            "quote": {
                "outcome": "accepted",
                "confidence": 85,
                "evidence_flow_ids": ["f-quote"],
            },
        },
        "chars": {},
    }
    enrich_profile_capabilities_and_candidates(profile)
    xss = _cand(profile["candidates"], ATTACK_XSS)
    assert xss is not None
    assert xss["score"] >= 85
    assert xss["confidence"] >= 50
    reasons = " ".join(xss["reasons"]).lower()
    assert "markup" in reasons or "html" in reasons
    assert "f-html" in xss["evidence_flow_ids"] or "f-markup" in xss["evidence_flow_ids"]
    assert has_capability(profile, CAPABILITY_REFLECTIVE_INPUT)
    assert has_capability(profile, CAPABILITY_HTML_CONTEXT)


def test_xss_absent_without_reflection():
    profile = _profile()
    profile["observed"]["acceptance"] = {
        "classes": {
            "markup": {"outcome": "accepted", "confidence": 90},
        },
        "chars": {},
    }
    cands = score_candidates(profile)
    assert _cand(cands, ATTACK_XSS) is None


# ---------------------------------------------------------------------------
# Open redirect / SSRF
# ---------------------------------------------------------------------------

def test_redirect_name_and_url_type_scores_open_redirect_and_ssrf():
    profile = _profile(name="redirect_url")
    profile["observed"]["types"] = {
        "url": {
            "outcome": "accepted",
            "confidence": 88,
            "evidence_flow_ids": ["f-url"],
        },
        "_summary": {"primary": "url", "passive": "url"},
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_URL_LIKE_VALUE in profile["capabilities"]

    redir = _cand(profile["candidates"], ATTACK_OPEN_REDIRECT)
    assert redir is not None
    assert redir["score"] >= 70
    assert any("redirect" in r.lower() or "url" in r.lower() for r in redir["reasons"])

    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    assert ssrf is not None
    assert ssrf["score"] >= 50
    assert any("url" in r.lower() for r in ssrf["reasons"])


def test_webhook_name_biases_ssrf():
    profile = _profile(name="webhook")
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 90},
    }
    cands = score_candidates(apply_capabilities(profile))
    ssrf = _cand(cands, ATTACK_SSRF)
    assert ssrf is not None
    assert ssrf["score"] >= 70
    assert any("webhook" in r.lower() or "ssrf" in r.lower() or "url" in r.lower()
               for r in ssrf["reasons"])


# ---------------------------------------------------------------------------
# SQLi negative evidence
# ---------------------------------------------------------------------------

def test_rejected_quotes_reduce_sqli_score():
    base = _profile(name="search")
    base["observed"]["types"] = {
        "_summary": {"primary": "string"},
    }
    base["observed"]["acceptance"] = {
        "classes": {
            "quote": {"outcome": "accepted", "confidence": 80},
            "operator": {"outcome": "accepted", "confidence": 75},
            "comment": {"outcome": "accepted", "confidence": 70},
        },
        "chars": {},
    }
    high = score_candidates(apply_capabilities(dict(base)))
    high_sqli = _cand(high, ATTACK_SQLI)
    assert high_sqli is not None
    assert high_sqli["score"] >= 60

    rejected = _profile(name="search")
    rejected["observed"]["types"] = {"_summary": {"primary": "string"}}
    rejected["observed"]["acceptance"] = {
        "classes": {
            "quote": {
                "outcome": "rejected",
                "confidence": 95,
                "evidence_flow_ids": ["f-quote-rej"],
            },
            "operator": {"outcome": "accepted", "confidence": 75},
            "comment": {"outcome": "accepted", "confidence": 70},
        },
        "chars": {},
    }
    rejected["tested"] = {
        "quote": {"outcome": "rejected", "confidence": 95, "evidence_flow_ids": ["f-quote-rej"]},
    }
    low = score_candidates(apply_capabilities(rejected))
    low_sqli = _cand(low, ATTACK_SQLI)

    # Either absent (below emit threshold) or clearly lower than accepted case.
    if low_sqli is None:
        assert high_sqli["score"] >= 60
    else:
        assert low_sqli["score"] < high_sqli["score"]
        reasons = " ".join(low_sqli["reasons"]).lower()
        assert "negative" in reasons or "reject" in reasons


# ---------------------------------------------------------------------------
# HPP / header
# ---------------------------------------------------------------------------

def test_hpp_from_duplicate_parser_behavior():
    profile = _profile(location="query", name="id")
    profile["observed"]["parser"] = {
        "duplicate_query": {
            "behavior": "last_wins",
            "confidence": 90,
            "evidence_flow_ids": ["f-dup"],
        },
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_DUPLICATE_PARAMETER in profile["capabilities"]
    hpp = _cand(profile["candidates"], ATTACK_HPP)
    assert hpp is not None
    assert hpp["score"] >= 50
    assert "f-dup" in hpp["evidence_flow_ids"]


def test_header_injection_surface():
    profile = _profile(location="header", name="X-Custom")
    profile["observed"]["acceptance"] = {
        "classes": {
            "control": {"outcome": "accepted", "confidence": 70},
        },
        "chars": {},
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_HEADER_INJECTION_SURFACE in profile["capabilities"]
    hdr = _cand(profile["candidates"], ATTACK_HEADER_INJECTION)
    assert hdr is not None
    assert hdr["score"] >= 40


# ---------------------------------------------------------------------------
# Consumer API
# ---------------------------------------------------------------------------

def test_get_param_intelligence_by_param_uuid(db_path: Path):
    host, loc, name = "api.example.com", "query", "redirect"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 90},
    }
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 80,
        "uncertainty": "low",
        "contexts": [],
    }
    enrich_profile_capabilities_and_candidates(profile)
    upsert_param_profile(
        db_path,
        param_uuid=uid,
        host=host,
        location=loc,
        param_name=name,
        profile=profile,
        bump_version=False,
    )

    intel = get_param_intelligence(db_path, uid)
    assert intel is not None
    assert intel["param_uuid"] == uid
    assert intel["name"] == name
    assert isinstance(intel["capabilities"], list)
    assert isinstance(intel["candidates"], list)
    assert any(c.get("attack") in (ATTACK_OPEN_REDIRECT, ATTACK_SSRF)
               for c in intel["candidates"])
    # Stable shape for attack modules — no need to parse probe tables.
    assert "profile" in intel
    assert "observed" in intel
    assert "tested" in intel


def test_get_param_intelligence_by_parameter_row_id(db_path: Path):
    host, loc, name = "api.example.com", "query", "q"
    param_id = str(uuid.uuid4())
    ep_id = str(uuid.uuid4())
    uid = make_param_uuid(host, loc, name)

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, 'proj', ?, 'GET', '/search', '/search',
                    datetime('now'), datetime('now'))
            """,
            (ep_id, host),
        )
        cols = {r[1] for r in conn.execute("PRAGMA table_info(parameters)").fetchall()}
        row = {
            "id": param_id,
            "endpoint_id": ep_id,
            "name": name,
            "location": loc,
            "param_type": "string",
            "semantic_type": "string",
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
            f"INSERT INTO parameters ({', '.join(use)}) VALUES "
            f"({', '.join('?' for _ in use)})",
            tuple(use.values()),
        )
        conn.commit()

    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 90,
        "contexts": ["html"],
        "uncertainty": "none",
        "evidence_flow_ids": ["f1"],
    }
    profile["observed"]["acceptance"] = {
        "classes": {
            "markup": {"outcome": "accepted", "confidence": 90, "evidence_flow_ids": ["f2"]},
        },
        "chars": {},
    }
    enrich_profile_capabilities_and_candidates(profile)
    upsert_param_profile(
        db_path,
        param_uuid=uid,
        host=host,
        location=loc,
        param_name=name,
        profile=profile,
    )

    intel = get_param_intelligence(db_path, param_id)
    assert intel is not None
    assert intel["param_uuid"] == uid
    xss = _cand(intel["candidates"], ATTACK_XSS)
    assert xss is not None
    assert xss["score"] >= 85


def test_list_candidates_filters(db_path: Path):
    for name, attack_setup in (
        ("redirect", "url"),
        ("comment", "xss"),
    ):
        host, loc = "api.example.com", "query"
        uid = make_param_uuid(host, loc, name)
        profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
        if attack_setup == "url":
            profile["observed"]["types"] = {
                "url": {"outcome": "accepted", "confidence": 90},
            }
        else:
            profile["observed"]["reflection"] = {
                "state": "reflected",
                "confidence": 90,
                "contexts": ["html"],
                "uncertainty": "none",
            }
            profile["observed"]["acceptance"] = {
                "classes": {
                    "markup": {"outcome": "accepted", "confidence": 90},
                },
                "chars": {},
            }
        enrich_profile_capabilities_and_candidates(profile)
        upsert_param_profile(
            db_path,
            param_uuid=uid,
            host=host,
            location=loc,
            param_name=name,
            profile=profile,
        )

    all_rows = list_candidates(db_path, host="api.example.com", min_score=25)
    assert len(all_rows) >= 2
    assert all("attack" in r and "score" in r and "param_uuid" in r for r in all_rows)

    xss_only = list_candidates(db_path, attack=ATTACK_XSS, min_score=50)
    assert xss_only
    assert all(r["attack"] == ATTACK_XSS for r in xss_only)

    high = list_candidates(db_path, min_score=90)
    assert all(r["score"] >= 90 for r in high)


def test_candidate_shape_contract():
    profile = _profile(name="next")
    profile["observed"]["types"] = {"url": {"outcome": "accepted", "confidence": 80}}
    for c in score_candidates(apply_capabilities(profile)):
        assert set(c.keys()) >= {
            "attack", "score", "confidence", "reasons", "evidence_flow_ids",
        }
        assert 0 <= c["score"] <= 100
        assert 0 <= c["confidence"] <= 100
        assert isinstance(c["reasons"], list)
        assert isinstance(c["evidence_flow_ids"], list)


def test_stored_profile_round_trip_includes_candidates(db_path: Path):
    host, loc, name = "h.test", "query", "q"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 90,
        "contexts": ["html"],
        "uncertainty": "none",
    }
    profile["observed"]["acceptance"] = {
        "classes": {"markup": {"outcome": "accepted", "confidence": 90}},
        "chars": {},
    }
    enrich_profile_capabilities_and_candidates(profile)
    upsert_param_profile(
        db_path, param_uuid=uid, host=host, location=loc, param_name=name, profile=profile,
    )
    loaded = get_param_profile(db_path, uid)
    assert loaded is not None
    assert loaded.get("candidates")
    assert any(c.get("attack") == ATTACK_XSS for c in loaded["candidates"])
