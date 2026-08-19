"""SSRF entry-point matching: IV array schema + requested headers."""

from talos.ssrf.inject import (
    apply_payload,
    extract_injection_points,
    match_injection_points,
)


def test_match_iv_array_schema_path() -> None:
    points = extract_injection_points(
        url="https://app.example.com/hook",
        request_headers={"Content-Type": "application/json"},
        request_body=b'[{"url":"https://cdn.example/x"}]',
    )
    matched, missing = match_injection_points(points, ["body:[].url"])
    assert missing == []
    assert [p.name for p in matched] == ["[0].url"]


def test_requested_headers_are_entry_points() -> None:
    points = extract_injection_points(
        url="https://app.example.com/admin.js",
        request_headers={"Host": "app.example.com", "Origin": "https://app.example.com"},
        request_body=None,
        header_names=["host", "origin", "referer", "authorization"],
    )
    by_key = {(p.location, p.name.lower()): p for p in points}
    assert ("header", "host") in by_key
    assert ("header", "origin") in by_key
    assert ("header", "referer") in by_key
    assert ("header", "authorization") not in by_key
    matched, missing = match_injection_points(points, ["header:origin"])
    assert missing == []
    assert matched[0].name == "Origin"

    _url, headers, _body = apply_payload(
        matched[0],
        "http://127.0.0.1/",
        url="https://app.example.com/admin.js",
        request_headers={"Host": "app.example.com", "Origin": "https://app.example.com"},
        request_body=None,
    )
    assert headers["Origin"] == "http://127.0.0.1/"
    assert headers["Host"] == "app.example.com"
