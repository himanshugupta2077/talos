"""XSS entry-point extraction, append inject, catalogue coverage."""

from talos.xss.inject import (
    apply_payload,
    extract_injection_points,
    match_injection_points,
)
from talos.xss.models import CANARY, FAMILIES
from talos.xss.payloads import generate_xss_payloads, render_payload


def test_catalogue_covers_all_families() -> None:
    payloads = generate_xss_payloads()
    families = {p.family for p in payloads}
    assert families == set(FAMILIES)
    names = {p.technique for p in payloads}
    assert "script_alert" in names
    assert "img_onerror" in names
    assert "h1_tag" in names
    assert "dq_img_break" in names
    assert "js_sq_break" in names
    assert "enc_url_script" in names
    assert "bypass_case" in names
    assert "poly_onclick" in names
    assert all(CANARY in p.payload for p in payloads)
    assert len(payloads) >= 60


def test_family_filter() -> None:
    tags = generate_xss_payloads(families=["html_tag"])
    assert {p.family for p in tags} == {"html_tag"}
    assert any("<script>" in p.payload for p in tags)


def test_extracts_query_json_and_path_param() -> None:
    points = extract_injection_points(
        url="https://app.example.com/search/home?q=hello",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"comment":"hi"}',
        normalized_path="/search/{term}",
    )
    by_key = {(p.location, p.name): p for p in points}
    assert ("query", "q") in by_key
    assert ("body", "comment") in by_key
    assert ("path", "term") in by_key
    assert by_key[("query", "q")].original == "hello"


def test_append_payload_on_query() -> None:
    points = extract_injection_points(
        url="https://app.example.com/search?q=hello",
    )
    q_pt = next(p for p in points if p.name == "q")
    payloads = generate_xss_payloads(techniques=["script_alert"])
    sent = render_payload(payloads[0], q_pt.original)
    assert sent.startswith("hello")
    assert "<script>" in sent
    url, _headers, _body = apply_payload(
        q_pt,
        sent,
        url="https://app.example.com/search?q=hello",
        request_headers={},
        request_body=None,
    )
    assert "hello" in url
    assert "script" in url.lower() or "%3c" in url.lower()


def test_match_param_filter() -> None:
    points = extract_injection_points(
        url="https://app.example.com/x?q=a&id=1",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"q":"b"}',
    )
    matched, missing = match_injection_points(points, ["query:q"])
    assert missing == []
    assert len(matched) == 1
    assert matched[0].location == "query"
    assert matched[0].name == "q"


def test_match_iv_array_schema_path() -> None:
    points = extract_injection_points(
        url="https://app.example.com/forecast",
        request_headers={"Content-Type": "application/json"},
        request_body=b'[{"Expense Type":"opex"}]',
    )
    matched, missing = match_injection_points(points, ["body:[].Expense Type"])
    assert missing == []
    assert [p.name for p in matched] == ["[0].Expense Type"]
