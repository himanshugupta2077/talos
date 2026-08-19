"""
Unit tests for Input Validation Module 11 — Capabilities & Attack Candidates.

Covers pure scoring fixtures (no network):
    - Reflected HTML + markup accepted → high XSS score with reasons
    - redirect name + URL type → open_redirect / SSRF candidates
    - Rejected quotes reduce SQLi score; negative evidence referenced
    - Stable consumer API get_param_intelligence / list_candidates
    - Capability derivation centralization
    - URL Sink Discovery Phase 4: network_resource_sink, value-first SSRF,
      webhook_abuse / oauth_redirect, redirect_behavior reweight
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
    ATTACK_OAUTH_REDIRECT,
    ATTACK_OPEN_REDIRECT,
    ATTACK_PATH_TRAVERSAL,
    ATTACK_SQLI,
    ATTACK_SSRF,
    ATTACK_WEBHOOK_ABUSE,
    ATTACK_XSS,
    KNOWN_ATTACKS,
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
    CAPABILITY_FETCH_SINK,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_NETWORK_RESOURCE_SINK,
    CAPABILITY_REDIRECT_SINK,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_WEBHOOK_SINK,
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
# URL Sink Discovery Phase 4 — capabilities + value-first candidates
# ---------------------------------------------------------------------------

def test_known_attacks_includes_webhook_and_oauth():
    assert ATTACK_WEBHOOK_ABUSE in KNOWN_ATTACKS
    assert ATTACK_OAUTH_REDIRECT in KNOWN_ATTACKS


def test_network_resource_sink_from_type_url_and_alias():
    """type url soft-accept → network_resource_sink + url_like_value alias."""
    profile = _profile(name="abc")
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 90},
        "_summary": {"primary": "url"},
    }
    caps = derive_capabilities(profile)
    assert CAPABILITY_NETWORK_RESOURCE_SINK in caps
    assert CAPABILITY_URL_LIKE_VALUE in caps  # compat alias


def test_network_resource_sink_from_passive_url_features_value_first():
    """Random name + high url_features.score → network_resource_sink without catalog."""
    profile = _profile(name="abc")
    profile["observed"]["url_features"] = {
        "possible_url_value": True,
        "possible_network_resource": True,
        "score": 95,
        "name_category": None,
        "name_categories": [],
        "evidence": ["value_scheme:https"],
    }
    caps = derive_capabilities(profile)
    assert CAPABILITY_NETWORK_RESOURCE_SINK in caps
    assert CAPABILITY_URL_LIKE_VALUE in caps  # alias when confidence ≥ 45


def test_value_first_ssrf_without_name_tokens():
    """abc=https://… style: high passive score + URL accept → ssrf candidate."""
    profile = _profile(name="abc")
    profile["observed"]["url_features"] = {
        "possible_url_value": True,
        "possible_network_resource": True,
        "score": 95,
        "name_category": None,
        "name_categories": [],
        "evidence": ["value_scheme:https"],
    }
    profile["observed"]["types"] = {
        "url": {
            "outcome": "accepted",
            "confidence": 88,
            "evidence_flow_ids": ["f-url"],
        },
        "_summary": {"primary": "url"},
    }
    enrich_profile_capabilities_and_candidates(profile)
    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    assert ssrf is not None
    assert ssrf["score"] >= 50
    reasons = " ".join(ssrf["reasons"]).lower()
    assert "value-first" in reasons or "url" in reasons or "network_resource" in reasons
    # No name-token requirement
    assert CAPABILITY_NETWORK_RESOURCE_SINK in profile["capabilities"]
    # QA-USD-13: pure URL-accept without redirect signal is not open_redirect noise
    assert _cand(profile["candidates"], ATTACK_OPEN_REDIRECT) is None


def test_url_sink_fetch_raises_ssrf_and_fetch_sink():
    profile = _profile(name="resource")
    profile["observed"]["url_features"] = {
        "score": 60,
        "possible_network_resource": True,
        "name_category": "remote_fetch",
        "name_categories": ["remote_fetch"],
    }
    profile["observed"]["url_sink"] = {
        "confidence": 80,
        "accepts_url": True,
        "fetch_behavior": True,
        "dns_resolution_detected": True,
        "error_classes": ["timeout"],
        "accepted_protocols": ["https"],
        "accepts_protocol": True,
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_NETWORK_RESOURCE_SINK in profile["capabilities"]
    assert CAPABILITY_FETCH_SINK in profile["capabilities"]
    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    assert ssrf is not None
    assert ssrf["score"] >= 70
    reasons = " ".join(ssrf["reasons"]).lower()
    assert "fetch" in reasons or "dns" in reasons or "network" in reasons


def test_redirect_behavior_elevates_open_redirect():
    profile = _profile(name="returnTo")
    profile["observed"]["url_features"] = {
        "score": 30,
        "name_category": "redirect",
        "name_categories": ["redirect"],
        "possible_network_resource": False,
    }
    profile["observed"]["url_sink"] = {
        "confidence": 85,
        "accepts_url": True,
        "redirect_behavior": True,
        "fetch_behavior": False,
    }
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 80},
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_REDIRECT_SINK in profile["capabilities"]
    redir = _cand(profile["candidates"], ATTACK_OPEN_REDIRECT)
    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    assert redir is not None
    assert redir["score"] >= 70
    # Redirect-only: open_redirect should rank at least as high as ssrf.
    if ssrf is not None:
        assert redir["score"] >= ssrf["score"] - 5


def test_webhook_abuse_candidate():
    profile = _profile(name="callback_url")
    profile["observed"]["url_features"] = {
        "score": 40,
        "name_category": "webhook",
        "name_categories": ["webhook", "remote_fetch"],
    }
    profile["observed"]["url_sink"] = {
        "confidence": 75,
        "accepts_url": True,
        "fetch_behavior": True,
    }
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 85},
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_WEBHOOK_SINK in profile["capabilities"]
    wh = _cand(profile["candidates"], ATTACK_WEBHOOK_ABUSE)
    assert wh is not None
    assert wh["score"] >= 60
    assert any("webhook" in r.lower() or "callback" in r.lower() for r in wh["reasons"])


def test_oauth_redirect_candidate():
    profile = _profile(name="redirect_uri")
    profile["observed"]["url_features"] = {
        "score": 30,
        "name_category": "oauth",
        "name_categories": ["oauth", "redirect"],
    }
    profile["observed"]["url_sink"] = {
        "confidence": 70,
        "accepts_url": True,
        "redirect_behavior": True,
    }
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 80},
    }
    enrich_profile_capabilities_and_candidates(profile)
    oauth = _cand(profile["candidates"], ATTACK_OAUTH_REDIRECT)
    assert oauth is not None
    assert oauth["score"] >= 60
    assert any("oauth" in r.lower() or "redirect" in r.lower() for r in oauth["reasons"])


def test_name_only_weak_does_not_spam_ssrf_without_value():
    """Bare short name without URL evidence should not invent high SSRF spam."""
    profile = _profile(name="q")
    # No types, no url_features network resource, no url_sink.
    cands = score_candidates(apply_capabilities(profile))
    assert _cand(cands, ATTACK_SSRF) is None
    assert _cand(cands, ATTACK_OPEN_REDIRECT) is None


def test_name_only_catalog_hits_do_not_spam_candidates_or_sink_caps():
    """
    Phase 4 QA: go/to/next/webhook/redirect_uri name alone must not invent
    sink capabilities or candidates (plan: name-only weak hits do not spam).
    """
    for name in ("go", "to", "next", "from", "webhook", "redirect_uri", "redirect_url"):
        profile = _profile(name=name)
        enrich_profile_capabilities_and_candidates(profile)
        assert CAPABILITY_NETWORK_RESOURCE_SINK not in profile["capabilities"]
        assert CAPABILITY_REDIRECT_SINK not in profile["capabilities"]
        assert CAPABILITY_WEBHOOK_SINK not in profile["capabilities"]
        assert profile["candidates"] == [], (
            f"name-only {name!r} emitted candidates: {profile['candidates']}"
        )


def test_stale_network_resource_sink_not_sticky_on_rederive():
    """Prior known caps must not survive re-derive without observed evidence."""
    profile = _profile(name="q")
    profile["capabilities"] = [
        CAPABILITY_NETWORK_RESOURCE_SINK,
        CAPABILITY_URL_LIKE_VALUE,
        CAPABILITY_REDIRECT_SINK,
        CAPABILITY_FETCH_SINK,
        CAPABILITY_WEBHOOK_SINK,
    ]
    caps = derive_capabilities(profile)
    assert CAPABILITY_NETWORK_RESOURCE_SINK not in caps
    assert CAPABILITY_URL_LIKE_VALUE not in caps
    assert CAPABILITY_REDIRECT_SINK not in caps
    assert CAPABILITY_FETCH_SINK not in caps
    assert CAPABILITY_WEBHOOK_SINK not in caps


def test_passive_value_first_does_not_claim_type_accept():
    """High url_features.score alone → NRS + SSRF, not false 'accepts URL' reason."""
    profile = _profile(name="abc")
    profile["observed"]["url_features"] = {
        "possible_url_value": True,
        "possible_network_resource": True,
        "score": 95,
        "name_category": None,
        "name_categories": [],
    }
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_NETWORK_RESOURCE_SINK in profile["capabilities"]
    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    assert ssrf is not None
    assert ssrf["score"] >= 45
    assert not any("accepts URL-shaped input" in r for r in ssrf["reasons"])
    assert any("value-first" in r.lower() or "network_resource" in r.lower()
               for r in ssrf["reasons"])


def test_url_type_rejected_does_not_apply_high_priority_floor():
    """High-priority max() must not undo type-url rejection penalty."""
    profile = _profile(name="resource")
    profile["observed"]["url_features"] = {
        "score": 90,
        "possible_network_resource": True,
        "name_category": "remote_fetch",
        "name_categories": ["remote_fetch"],
    }
    profile["observed"]["types"] = {
        "url": {"outcome": "rejected", "confidence": 95},
    }
    enrich_profile_capabilities_and_candidates(profile)
    # fetch_sink must not invent from name+NRS without active fetch signals
    assert CAPABILITY_FETCH_SINK not in profile["capabilities"]
    ssrf = _cand(profile["candidates"], ATTACK_SSRF)
    if ssrf is not None:
        assert "negative evidence: URL type rejected" in " ".join(ssrf["reasons"])
        assert not any(r.startswith("high-priority:") for r in ssrf["reasons"])
        # With rejection, score should stay modest (no 78 floor)
        assert ssrf["score"] < 78


def test_redirect_sink_requires_behavior_or_accept_not_name_alone():
    profile = _profile(name="returnTo")
    # Name only
    caps = derive_capabilities(profile)
    assert CAPABILITY_REDIRECT_SINK not in caps
    # With redirect behavior + accept
    profile["observed"]["url_sink"] = {
        "redirect_behavior": True,
        "accepts_url": True,
        "confidence": 80,
    }
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 85},
    }
    caps = derive_capabilities(profile)
    assert CAPABILITY_REDIRECT_SINK in caps
    assert CAPABILITY_NETWORK_RESOURCE_SINK in caps


def test_list_candidates_filters_new_attacks(db_path: Path):
    pu = make_param_uuid("api.example.com", "query", "webhook")
    profile = empty_param_profile(
        param_uuid=pu, host="api.example.com", location="query", name="webhook",
    )
    profile["observed"]["types"] = {
        "url": {"outcome": "accepted", "confidence": 90},
    }
    profile["observed"]["url_sink"] = {
        "confidence": 70,
        "accepts_url": True,
        "fetch_behavior": True,
    }
    enrich_profile_capabilities_and_candidates(profile)
    upsert_param_profile(
        db_path,
        param_uuid=pu,
        host="api.example.com",
        location="query",
        param_name="webhook",
        profile=profile,
        bump_version=False,
    )
    rows = list_candidates(db_path, attack=ATTACK_WEBHOOK_ABUSE, min_score=25)
    assert any(r.get("attack") == ATTACK_WEBHOOK_ABUSE for r in rows)


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


# ---------------------------------------------------------------------------
# PR5 / PR6 — Stored / cross-flow reflection
# ---------------------------------------------------------------------------

from talos.input_validation.candidates import (  # noqa: E402
    empty_candidate,
    load_and_merge_cross_flow,
)
from talos.input_validation.profile import (  # noqa: E402
    CAPABILITY_STORED_REFLECTION,
)
from talos.projects.value_reflection import (  # noqa: E402
    CrossFlowConfig,
    merge_cross_flow_reflection,
    set_process_cross_flow_config,
    reset_process_cross_flow_config,
)


@pytest.fixture(autouse=True)
def _cross_flow_feed_iv_defaults():
    """Ensure feed_iv=True for merge tests; reset process cache after each test."""
    set_process_cross_flow_config(CrossFlowConfig(enabled=False, feed_iv=True))
    yield
    reset_process_cross_flow_config()


def _stored_only_profile(**kwargs) -> dict:
    """Multiprobe not_reflected + nested cross_flow reflected (post-merge shape)."""
    p = _profile(name=kwargs.pop("name", "username"), **kwargs)
    p["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 80,
        "uncertainty": "low",
        "contexts": ["html"],
        "encoding": "raw",
        "evidence_flow_ids": ["src-flow", "sink-flow"],
        "modes": ["same_request", "cross_flow"],
        "same_request": {
            "state": "not_reflected",
            "confidence": 88,
            "uncertainty": "none",
            "evidence_flow_ids": ["probe-flow"],
            "contexts": [],
            "encoding": "",
        },
        "cross_flow": {
            "state": "reflected",
            "confidence": 80,
            "uncertainty": "low",
            "link_count": 1,
            "contexts": ["html"],
            "encoding": "raw",
            "evidence_flow_ids": ["src-flow", "sink-flow"],
            "sinks": [
                {
                    "sink_method": "GET",
                    "sink_path": "/profile",
                    "sink_endpoint_id": "ep-sink",
                    "sink_flow_id": "sink-flow",
                    "context": "html",
                    "encoding": "raw",
                    "confidence": 80,
                    "detection_mode": "passive",
                    "reason": (
                        "value from username@POST /register reflected on "
                        "GET /profile (html, raw)"
                    ),
                }
            ],
        },
    }
    return p


def _insert_cross_flow_link(
    db_path: Path,
    *,
    param_uuid: str,
    host: str = "https://app.example.com",
    source_param_name: str = "username",
    source_method: str = "POST",
    source_path: str = "/register",
    sink_method: str = "GET",
    sink_path: str = "/profile",
    sink_context: str = "html",
    confidence: int = 80,
) -> None:
    link_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO cross_flow_reflections (
                id, project_id, host,
                source_flow_id, first_source_flow_id,
                source_endpoint_id, source_param_id, source_param_uuid,
                source_param_name, source_location, source_method, source_path,
                source_role_id,
                sink_flow_id, sink_endpoint_id, sink_method, sink_path,
                sink_content_type, sink_context, sink_role_id,
                encoding, transforms,
                value_hash, value_len, match_kind, confidence, detection_mode,
                first_seen_at, last_seen_at, observation_count
            ) VALUES (
                ?, 'proj', ?,
                'src-flow', 'src-flow',
                NULL, NULL, ?,
                ?, 'body', ?, ?,
                NULL,
                'sink-flow', NULL, ?, ?,
                'text/html', ?, NULL,
                'raw', '[]',
                'deadbeef', 9, 'exact', ?, 'passive',
                '2026-01-01T00:00:00+00:00', '2026-01-01T00:01:00+00:00', 1
            )
            """,
            (
                link_id,
                host,
                param_uuid,
                source_param_name,
                source_method,
                source_path,
                sink_method,
                sink_path,
                sink_context,
                confidence,
            ),
        )
        conn.commit()


def test_derive_stored_reflection_capability():
    profile = _stored_only_profile()
    caps = derive_capabilities(profile)
    assert CAPABILITY_REFLECTIVE_INPUT in caps
    assert CAPABILITY_STORED_REFLECTION in caps
    assert CAPABILITY_HTML_CONTEXT in caps
    # Order: stored_reflection immediately after reflective_input
    assert caps.index(CAPABILITY_STORED_REFLECTION) == caps.index(
        CAPABILITY_REFLECTIVE_INPUT
    ) + 1


def test_derive_stored_only_from_nested_without_top_level():
    """Stale profile: only nested cross_flow reflected, top-level not yet merged."""
    profile = _profile(name="username")
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "contexts": [],
        "cross_flow": {
            "state": "reflected",
            "confidence": 80,
            "contexts": ["html"],
            "sinks": [{"context": "html", "sink_method": "GET", "sink_path": "/p"}],
        },
    }
    caps = derive_capabilities(profile)
    assert CAPABILITY_STORED_REFLECTION in caps
    assert CAPABILITY_REFLECTIVE_INPUT in caps
    assert CAPABILITY_HTML_CONTEXT in caps


def test_xss_stored_only_passes_gate_and_reasons():
    profile = _stored_only_profile()
    enrich_profile_capabilities_and_candidates(profile)
    xss = _cand(profile["candidates"], ATTACK_XSS)
    assert xss is not None
    # +30 reflected +12 stored +25 html = 67; floor 55 for stored+html
    assert xss["score"] >= 55
    assert xss["score"] == 67  # 30+12+25, no markup
    assert "cross_flow" in (xss.get("reflection_modes") or [])
    assert xss["reasons"][0].startswith("value from username@POST /register")
    assert "GET /profile" in xss["reasons"][0]
    assert "input is reflected in responses" in xss["reasons"]
    assert xss.get("stored_reflection") is not None
    assert xss["stored_reflection"]["link_count"] == 1
    assert xss["stored_reflection"]["sinks"][0]["path"] == "/profile"
    assert "src-flow" in xss["evidence_flow_ids"]
    assert "sink-flow" in xss["evidence_flow_ids"]
    # Confidence from positive contributors only (stored link + context),
    # not multiprobe same_request not_reflected conf (88).
    assert 70 <= xss["confidence"] <= 80
    assert xss["confidence"] != 88


def test_xss_stored_html_without_markup_floor_55():
    profile = _stored_only_profile()
    # Only json context → lower; override to html for floor test already html
    cands = score_candidates(apply_capabilities(profile))
    xss = _cand(cands, ATTACK_XSS)
    assert xss is not None
    assert xss["score"] >= 55


def test_xss_stored_json_emits_with_lower_relevance():
    profile = _stored_only_profile()
    profile["observed"]["reflection"]["contexts"] = ["json"]
    profile["observed"]["reflection"]["cross_flow"]["contexts"] = ["json"]
    profile["observed"]["reflection"]["cross_flow"]["sinks"][0]["context"] = "json"
    profile["observed"]["reflection"]["cross_flow"]["sinks"][0]["reason"] = (
        "value from username@POST /register reflected on GET /profile (json, raw)"
    )
    enrich_profile_capabilities_and_candidates(profile)
    xss = _cand(profile["candidates"], ATTACK_XSS)
    assert xss is not None
    # 30 + 12 + 5 json = 47
    assert xss["score"] == 47
    reasons = " ".join(xss["reasons"]).lower()
    assert "json" in reasons


def test_xss_high_priority_keeps_stored_reason_not_always_first():
    profile = _stored_only_profile()
    profile["observed"]["acceptance"] = {
        "classes": {
            "markup": {"outcome": "accepted", "confidence": 90},
        },
        "chars": {},
    }
    # Also same-request reflected so high-priority pattern applies cleanly
    profile["observed"]["reflection"]["same_request"]["state"] = "reflected"
    profile["observed"]["reflection"]["same_request"]["contexts"] = ["html"]
    enrich_profile_capabilities_and_candidates(profile)
    xss = _cand(profile["candidates"], ATTACK_XSS)
    assert xss is not None
    assert xss["score"] >= 85
    assert xss["reasons"][0].startswith("high-priority:")
    assert any("username@POST /register" in r for r in xss["reasons"])


def test_empty_candidate_extras():
    c = empty_candidate(
        ATTACK_XSS,
        score=67,
        confidence=78,
        reasons=["value from username@POST /register reflected on GET /profile (html, raw)"],
        evidence_flow_ids=["a", "b"],
        reflection_modes=["cross_flow"],
        stored_reflection={"link_count": 1, "sinks": []},
    )
    assert c["reflection_modes"] == ["cross_flow"]
    assert c["stored_reflection"]["link_count"] == 1
    # Without extras, keys absent
    bare = empty_candidate(ATTACK_XSS, score=10)
    assert "reflection_modes" not in bare
    assert "stored_reflection" not in bare


def test_load_and_merge_cross_flow_from_db(db_path: Path):
    host = "https://app.example.com"
    loc, name = "body", "username"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "uncertainty": "none",
        "contexts": [],
        "encoding": "",
        "evidence_flow_ids": ["probe-flow"],
    }
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    out = load_and_merge_cross_flow(db_path, profile, persist=False, score=True)
    refl = out["observed"]["reflection"]
    assert refl["same_request"]["state"] == "not_reflected"
    assert refl["cross_flow"]["state"] == "reflected"
    assert refl["state"] == "reflected"
    assert refl["confidence"] == 80
    assert CAPABILITY_STORED_REFLECTION in out["capabilities"]
    assert CAPABILITY_REFLECTIVE_INPUT in out["capabilities"]
    xss = _cand(out["candidates"], ATTACK_XSS)
    assert xss is not None
    assert xss["reasons"][0].startswith("value from username@POST /register")


def test_load_and_merge_respects_feed_iv_false(db_path: Path):
    set_process_cross_flow_config(CrossFlowConfig(enabled=True, feed_iv=False))
    host = "https://app.example.com"
    uid = make_param_uuid(host, "body", "username")
    profile = empty_param_profile(
        param_uuid=uid, host=host, location="body", name="username",
    )
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "contexts": [],
        "evidence_flow_ids": [],
    }
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)
    load_and_merge_cross_flow(db_path, profile, persist=False, score=True)
    refl = profile["observed"]["reflection"]
    assert "cross_flow" not in refl or refl.get("cross_flow") is None or (
        refl.get("state") == "not_reflected"
    )
    assert CAPABILITY_STORED_REFLECTION not in (profile.get("capabilities") or [])


def test_load_and_merge_respects_project_yaml_feed_iv_false(db_path: Path):
    """
    Issue 2 regression: project.yaml feed_iv=false is honored on consume path
    via ensure_process_cross_flow_config (not just process cache set by tests).
    """
    from talos.projects.value_reflection import (
        ensure_process_cross_flow_config,
        load_cross_flow_config_for_project,
        reset_process_cross_flow_config,
    )

    # Clear process cache so load_and_merge must load project YAML.
    reset_process_cross_flow_config()
    project_dir = db_path.parent
    (project_dir / "project.yaml").write_text(
        "parameter_intel:\n"
        "  cross_flow:\n"
        "    enabled: true\n"
        "    feed_iv: false\n",
        encoding="utf-8",
    )

    loaded = load_cross_flow_config_for_project(project_dir)
    assert loaded.feed_iv is False
    assert loaded.enabled is True

    reset_process_cross_flow_config()
    host = "https://app.example.com"
    uid = make_param_uuid(host, "body", "username")
    profile = empty_param_profile(
        param_uuid=uid, host=host, location="body", name="username",
    )
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "contexts": [],
        "evidence_flow_ids": [],
    }
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    load_and_merge_cross_flow(db_path, profile, persist=False, score=True)
    # ensure_process should have installed feed_iv=false from YAML
    cfg = ensure_process_cross_flow_config(project_dir)
    assert cfg.feed_iv is False
    refl = profile["observed"]["reflection"]
    assert refl.get("state") == "not_reflected"
    assert CAPABILITY_STORED_REFLECTION not in (profile.get("capabilities") or [])


def test_get_param_intelligence_recompute_merges_links(db_path: Path):
    host = "https://app.example.com"
    loc, name = "body", "username"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    # Stored profile: multiprobe only, no cross_flow yet
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "uncertainty": "none",
        "contexts": [],
        "evidence_flow_ids": ["probe"],
    }
    profile["capabilities"] = []
    profile["candidates"] = []
    upsert_param_profile(
        db_path, param_uuid=uid, host=host, location=loc, param_name=name, profile=profile,
    )
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    intel = get_param_intelligence(db_path, uid, recompute=True)
    assert intel is not None
    assert CAPABILITY_STORED_REFLECTION in intel["capabilities"]
    xss = _cand(intel["candidates"], ATTACK_XSS)
    assert xss is not None
    assert "username@POST /register" in xss["reasons"][0]
    assert intel["profile"]["observed"]["reflection"]["state"] == "reflected"


def test_get_param_intelligence_default_path_merges_live_links(db_path: Path):
    """
    Issue 1 regression: recompute=False with non-empty caps/candidates still
    live-merges when cross_flow links exist (parity with list_candidates).
    """
    host = "https://app.example.com"
    loc, name = "body", "username"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    # Profile synthesized *before* proxy traffic created links — stale
    # multiprobe-only reflection, but capabilities/candidates already filled
    # (the condition that previously skipped merge on get_param_intelligence).
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "uncertainty": "none",
        "contexts": [],
        "evidence_flow_ids": ["probe"],
    }
    profile["capabilities"] = ["strict_length"]
    profile["candidates"] = [
        {
            "attack": "ssrf",
            "score": 30,
            "confidence": 50,
            "reasons": ["placeholder"],
            "evidence_flow_ids": [],
        }
    ]
    upsert_param_profile(
        db_path, param_uuid=uid, host=host, location=loc, param_name=name, profile=profile,
    )
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    # list_candidates already merged live links without recompute
    rows = list_candidates(db_path, attack=ATTACK_XSS, min_score=40, recompute=False)
    assert rows, "list_candidates should surface stored XSS from live links"

    # get_param_intelligence must match (was: still strict_length / not_reflected)
    intel = get_param_intelligence(db_path, uid, recompute=False)
    assert intel is not None
    assert CAPABILITY_STORED_REFLECTION in intel["capabilities"]
    assert intel["profile"]["observed"]["reflection"]["state"] == "reflected"
    xss = _cand(intel["candidates"], ATTACK_XSS)
    assert xss is not None
    assert "username@POST /register" in xss["reasons"][0]
    assert "cross_flow" in (xss.get("reflection_modes") or [])


def test_list_candidates_batched_pass_through(db_path: Path):
    host = "https://app.example.com"
    loc, name = "body", "username"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "uncertainty": "none",
        "contexts": [],
        "evidence_flow_ids": ["probe"],
    }
    # Persist without candidates so list path re-scores after merge
    profile["capabilities"] = []
    profile["candidates"] = []
    upsert_param_profile(
        db_path, param_uuid=uid, host=host, location=loc, param_name=name, profile=profile,
    )
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    rows = list_candidates(
        db_path, attack=ATTACK_XSS, min_score=40, recompute=True,
    )
    assert rows
    row = rows[0]
    assert row["param_uuid"] == uid
    assert "reflection_modes" in row
    assert "cross_flow" in (row["reflection_modes"] or [])
    assert row.get("stored_reflection") is not None
    assert row["reasons"][0].startswith("value from username@POST /register")
    assert CAPABILITY_STORED_REFLECTION in row["capabilities"]

    # Capability filter
    by_cap = list_candidates(
        db_path, capability=CAPABILITY_STORED_REFLECTION, recompute=True,
    )
    assert any(r["param_uuid"] == uid for r in by_cap)


def test_list_candidates_default_path_merges_live_links(db_path: Path):
    """recompute=False still merges when batched links exist (stale profile)."""
    host = "https://app.example.com"
    loc, name = "body", "username"
    uid = make_param_uuid(host, loc, name)
    profile = empty_param_profile(param_uuid=uid, host=host, location=loc, name=name)
    # Old stored JSON: not reflected, has empty candidates that would skip re-score
    # without link-aware merge.
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "contexts": [],
        "evidence_flow_ids": [],
    }
    # Give it a non-XSS candidate so capabilities/candidates are non-empty
    profile["capabilities"] = ["url_like_value"]
    profile["candidates"] = [
        {
            "attack": "ssrf",
            "score": 30,
            "confidence": 50,
            "reasons": ["placeholder"],
            "evidence_flow_ids": [],
        }
    ]
    upsert_param_profile(
        db_path, param_uuid=uid, host=host, location=loc, param_name=name, profile=profile,
    )
    _insert_cross_flow_link(db_path, param_uuid=uid, host=host)

    rows = list_candidates(db_path, attack=ATTACK_XSS, min_score=40, recompute=False)
    assert rows, "live links should merge into stale profile without recompute flag"
    assert rows[0]["reasons"][0].startswith("value from username@POST /register")


def test_merge_then_score_pure_path():
    """Pure merge_cross_flow_reflection + score without DB."""
    profile = _profile(name="username")
    profile["observed"]["reflection"] = {
        "state": "not_reflected",
        "confidence": 88,
        "uncertainty": "none",
        "contexts": [],
        "encoding": "",
        "evidence_flow_ids": ["probe-flow"],
    }
    links = [{
        "source_param_name": "username",
        "source_method": "POST",
        "source_path": "/register",
        "source_flow_id": "src-flow",
        "first_source_flow_id": "src-flow",
        "sink_flow_id": "sink-flow",
        "sink_method": "GET",
        "sink_path": "/profile",
        "sink_context": "html",
        "encoding": "raw",
        "confidence": 80,
        "detection_mode": "passive",
    }]
    merge_cross_flow_reflection(profile, links)
    enrich_profile_capabilities_and_candidates(profile)
    assert CAPABILITY_STORED_REFLECTION in profile["capabilities"]
    xss = _cand(profile["candidates"], ATTACK_XSS)
    assert xss is not None
    assert xss["score"] == 67


def test_format_candidates_lines_includes_stored_sinks():
    from talos.input_validation.candidates import format_candidates_lines

    lines = format_candidates_lines([
        {
            "attack": "xss",
            "score": 67,
            "confidence": 78,
            "reasons": [
                "value from username@POST /register reflected on GET /profile (html, raw)",
            ],
            "reflection_modes": ["cross_flow"],
            "stored_reflection": {
                "link_count": 1,
                "sinks": [
                    {
                        "reason": (
                            "value from username@POST /register reflected "
                            "on GET /profile (html, raw)"
                        ),
                    },
                ],
            },
        },
    ])
    joined = "\n".join(lines)
    assert "modes=cross_flow" in joined
    assert "stored:" in joined
    assert "POST /register" in joined


def test_format_profile_summary_dual_reflection_modes():
    from talos.input_validation.synthesize import format_profile_summary_lines

    profile = {
        "schema_version": 2,
        "profile_version": 1,
        "requests_used": 1,
        "observed": {
            "reflection": {
                "state": "reflected",
                "confidence": 80,
                "uncertainty": "low",
                "encoding": "raw",
                "contexts": ["html"],
                "modes": ["cross_flow"],
                "same_request": {
                    "state": "not_reflected",
                    "confidence": 88,
                    "contexts": [],
                },
                "cross_flow": {
                    "state": "reflected",
                    "confidence": 80,
                    "link_count": 1,
                    "contexts": ["html"],
                    "sinks": [
                        {
                            "reason": (
                                "value from username@POST /register reflected "
                                "on GET /profile (html, raw)"
                            ),
                        },
                    ],
                },
            },
        },
        "capabilities": ["reflective_input", "stored_reflection"],
        "candidates": [],
    }
    joined = "\n".join(format_profile_summary_lines(profile))
    assert "modes=cross_flow" in joined
    assert "same_request:" in joined
    assert "cross_flow:" in joined
    assert "sink:" in joined
    assert "data-flow prioritization evidence" in joined


# ---------------------------------------------------------------------------
# Path traversal / LFI candidate ranking
# ---------------------------------------------------------------------------


def test_path_traversal_name_and_path_class():
    profile = _profile(name="file", location="query")
    profile["observed"]["acceptance"] = {
        "classes": {
            "path": {"outcome": "accepted", "confidence": 80, "evidence_flow_ids": ["f1"]},
        }
    }
    cands = score_candidates(apply_capabilities(profile))
    pt = _cand(cands, ATTACK_PATH_TRAVERSAL)
    assert pt is not None
    assert pt["score"] >= 45
    reasons = " ".join(pt["reasons"]).lower()
    assert "path/file" in reasons
    assert "path characters" in reasons


def test_path_traversal_value_first_without_name_gate():
    profile = _profile(name="q", location="query")
    profile["inferred"] = {
        "passive": {
            "semantic_type": "string",
            "examples": ["../../templates/home.html"],
        }
    }
    cands = score_candidates(apply_capabilities(profile))
    pt = _cand(cands, ATTACK_PATH_TRAVERSAL)
    assert pt is not None
    reasons = " ".join(pt["reasons"]).lower()
    assert "file path" in reasons or "dot-dot" in reasons


def test_path_traversal_multipart_filename_surface():
    profile = _profile(name="upload", location="body")
    profile["capabilities"] = ["multipart_filename"]
    cands = score_candidates(profile)
    pt = _cand(cands, ATTACK_PATH_TRAVERSAL)
    assert pt is not None
    assert "multipart filename" in " ".join(pt["reasons"]).lower()


def test_path_traversal_plain_string_is_not_a_candidate():
    profile = _profile(name="q", location="query")
    cands = score_candidates(apply_capabilities(profile))
    assert _cand(cands, ATTACK_PATH_TRAVERSAL) is None
