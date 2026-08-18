"""SQLi entry-point extraction and JSON-array injection."""

import json

from talos.sqli.inject import apply_payload, extract_injection_points
from talos.sqli.payloads import generate_sqli_payloads


def test_extracts_json_array_indexes() -> None:
    points = extract_injection_points(
        url="https://app.example.com/api/send_broadcast_notification",
        request_headers={"Content-Type": "application/json"},
        request_body=b'["test","test","info","111111-11-11T11:11"]',
    )
    names = [p.name for p in points]
    assert names == ["[0]", "[1]", "[2]", "[3]"]
    assert points[3].original == "111111-11-11T11:11"
    assert all(p.location == "body" for p in points)


def test_extracts_query_and_json_object() -> None:
    points = extract_injection_points(
        url="https://app.example.com/search?q=hello&page=1",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"user":{"id":7},"q":"x"}',
    )
    by_key = {(p.location, p.name): p for p in points}
    assert ("query", "q") in by_key
    assert ("query", "page") in by_key
    assert ("body", "user.id") in by_key
    assert ("body", "q") in by_key
    assert by_key[("body", "user.id")].original == "7"


def test_append_payload_to_json_array_element() -> None:
    points = extract_injection_points(
        url="https://app.example.com/n",
        request_headers={"Content-Type": "application/json"},
        request_body=b'["test","test","info","111111-11-11T11:11"]',
    )
    date = next(p for p in points if p.name == "[3]")
    _url, _headers, body = apply_payload(
        date,
        "'",
        url="https://app.example.com/n",
        request_headers={"Content-Type": "application/json"},
        request_body=b'["test","test","info","111111-11-11T11:11"]',
    )
    parsed = json.loads(body)
    assert parsed[3] == "111111-11-11T11:11'"
    assert parsed[0] == "test"


def test_catalogue_covers_error_union_boolean_time() -> None:
    payloads = generate_sqli_payloads()
    families = {p.family for p in payloads}
    assert families == {"error", "union", "boolean", "time"}
    names = {p.technique for p in payloads}
    assert "quote_single" in names
    assert "mssql_convert" in names
    assert "union_3" in names
    assert "mssql_waitfor" in names
    only_error = generate_sqli_payloads(families=["error"])
    assert {p.family for p in only_error} == {"error"}
