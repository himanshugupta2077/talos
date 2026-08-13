"""Unit tests for CORS Origin payload generation and verdict analysis."""

from __future__ import annotations

from talos.cors.engine import analyze_cors_response
from talos.cors.models import TECHNIQUE_NAMES, VERDICT_CORS_MISCONFIG, VERDICT_SECURE
from talos.cors.payloads import (
    generate_cors_payloads,
    request_origin_from_url,
    resolve_baseline_origin,
    target_origin_key,
)


def test_synthesize_origin_from_url() -> None:
    assert (
        request_origin_from_url("https://app.example.com:8443/api/items")
        == "https://app.example.com:8443"
    )


def test_resolve_uses_captured_origin() -> None:
    origin, present = resolve_baseline_origin(
        "https://app.example.com/x",
        {"Origin": "https://spa.example.com"},
    )
    assert present is True
    assert origin == "https://spa.example.com"


def test_resolve_synthesizes_when_missing() -> None:
    origin, present = resolve_baseline_origin(
        "https://app.example.com/x",
        {"Accept": "application/json"},
    )
    assert present is False
    assert origin == "https://app.example.com"


def test_target_origin_key() -> None:
    assert (
        target_origin_key("https://API.Example.com:443/v1")
        == "https://api.example.com:443"
    )


def test_payloads_include_arbitrary_and_subdomain() -> None:
    payloads = generate_cors_payloads(
        baseline_origin="https://app.example.com",
        request_method="POST",
        nonce="deadbeef",
    )
    by_name = {p.technique: p for p in payloads}
    assert by_name["baseline_origin"].origin == "https://app.example.com"
    assert by_name["baseline_origin"].attacker_controlled is False
    assert by_name["arbitrary_https"].origin == "https://talos-cors-deadbeef.invalid"
    assert by_name["arbitrary_https"].attacker_controlled is True
    assert by_name["subdomain_of_target"].origin == (
        "https://talos-cors-deadbeef.app.example.com"
    )
    assert by_name["prefix_bypass"].origin.endswith(".talos-cors-deadbeef.invalid")
    assert by_name["null_origin"].origin == "null"
    assert by_name["wildcard_origin"].attacker_controlled is False
    assert by_name["preflight"].method_override == "OPTIONS"
    assert by_name["preflight"].acr_method == "POST"
    assert {p.technique for p in payloads} <= set(TECHNIQUE_NAMES)


def test_technique_filter() -> None:
    payloads = generate_cors_payloads(
        baseline_origin="https://app.example.com",
        nonce="aa",
        techniques=["arbitrary_https", "null_origin"],
    )
    assert [p.technique for p in payloads] == ["arbitrary_https", "null_origin"]


def test_analyze_reflected_attacker_origin_is_issue() -> None:
    reflected, creds, wild, acao, acac, verdict, hint = analyze_cors_response(
        origin_sent="https://talos-cors-aa.invalid",
        response_headers={
            "Access-Control-Allow-Origin": "https://talos-cors-aa.invalid",
        },
        attacker_controlled=True,
    )
    assert reflected is True
    assert creds is False
    assert wild is False
    assert verdict == VERDICT_CORS_MISCONFIG
    assert hint == "reflected_origin"
    assert acao == "https://talos-cors-aa.invalid"
    assert acac is None


def test_analyze_reflected_with_credentials_is_same_issue() -> None:
    reflected, creds, _wild, _acao, _acac, verdict, hint = analyze_cors_response(
        origin_sent="https://evil.invalid",
        response_headers={
            "Access-Control-Allow-Origin": "https://evil.invalid",
            "Access-Control-Allow-Credentials": "true",
        },
        attacker_controlled=True,
    )
    assert reflected is True
    assert creds is True
    assert verdict == VERDICT_CORS_MISCONFIG
    assert hint == "credentials"


def test_analyze_wildcard_alone_is_not_issue() -> None:
    reflected, _creds, wild, _acao, _acac, verdict, hint = analyze_cors_response(
        origin_sent="https://talos-cors-aa.invalid",
        response_headers={"Access-Control-Allow-Origin": "*"},
        attacker_controlled=True,
    )
    assert reflected is False
    assert wild is True
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_analyze_credentials_without_reflection_is_not_issue() -> None:
    reflected, creds, _wild, _acao, _acac, verdict, _hint = analyze_cors_response(
        origin_sent="https://talos-cors-aa.invalid",
        response_headers={
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
        attacker_controlled=True,
    )
    assert reflected is False
    assert creds is True
    assert verdict == VERDICT_SECURE


def test_analyze_wildcard_plus_credentials_is_not_issue() -> None:
    reflected, creds, wild, _acao, _acac, verdict, _hint = analyze_cors_response(
        origin_sent="https://talos-cors-aa.invalid",
        response_headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        attacker_controlled=True,
    )
    assert reflected is False
    assert creds is True
    assert wild is True
    assert verdict == VERDICT_SECURE


def test_analyze_baseline_echo_is_not_issue() -> None:
    _ref, _c, _w, _ao, _ac, verdict, _h = analyze_cors_response(
        origin_sent="https://app.example.com",
        response_headers={
            "Access-Control-Allow-Origin": "https://app.example.com",
        },
        attacker_controlled=False,
    )
    assert verdict == VERDICT_SECURE


def test_analyze_null_reflection_is_issue() -> None:
    reflected, _c, _w, _ao, _ac, verdict, hint = analyze_cors_response(
        origin_sent="null",
        response_headers={"Access-Control-Allow-Origin": "null"},
        attacker_controlled=True,
    )
    assert reflected is True
    assert verdict == VERDICT_CORS_MISCONFIG
    assert hint == "null_origin"
