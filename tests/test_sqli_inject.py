"""SQLi entry-point extraction and JSON-array injection."""

import json

from talos.sqli.inject import (
    apply_payload,
    extract_injection_points,
    match_injection_points,
)
from talos.sqli.models import normalize_db_type
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


def test_unknown_db_includes_vendor_and_encodings() -> None:
    payloads = generate_sqli_payloads(db_type="unknown")
    names = {p.technique for p in payloads}
    vendors = {p.dbms for p in payloads}
    assert {"generic", "mssql", "mysql", "postgresql", "oracle", "sqlite"} <= vendors
    assert "mysql_sleep" in names
    assert "pg_cast" in names
    assert "oracle_pipe" in names
    assert "sqlite_error" in names
    assert "quote_single__url" in names
    assert "quote_single__double_url" in names
    assert "quote_single__unicode" in names
    url = next(p for p in payloads if p.technique == "quote_single__url")
    assert url.payload == "%27"
    assert url.base_technique == "quote_single"
    taut = next(p for p in payloads if p.technique == "tautology__url")
    assert "%27" in taut.payload


def test_mssql_db_is_sql_server_only() -> None:
    payloads = generate_sqli_payloads(db_type="mssql")
    names = {p.technique for p in payloads}
    vendors = {p.dbms for p in payloads}
    assert vendors <= {"generic", "mssql"}
    assert "mssql_convert" in names
    assert "mssql_cast" in names
    assert "mssql_waitfor_if" in names
    assert "mssql_char_or" in names
    assert "mysql_sleep" not in names
    assert "pg_sleep" not in names
    assert "oracle_pipe" not in names
    assert not any(p.encoding != "raw" for p in payloads)


def test_technique_filter_expands_unknown_encodings() -> None:
    payloads = generate_sqli_payloads(db_type="unknown", techniques=["quote_single"])
    assert {p.technique for p in payloads} == {
        "quote_single",
        "quote_single__url",
        "quote_single__double_url",
        "quote_single__unicode",
    }
    mssql_only = generate_sqli_payloads(db_type="mssql", techniques=["quote_single"])
    assert [p.technique for p in mssql_only] == ["quote_single"]


def test_match_injection_points_by_name_and_location() -> None:
    points = extract_injection_points(
        url="https://app.example.com/search?q=hello&page=1",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"q":"x","user":{"id":7}}',
    )
    by_name, missing = match_injection_points(points, ["q"])
    assert missing == []
    assert {p.location for p in by_name} == {"query", "body"}
    body_only, missing_body = match_injection_points(points, ["body:q"])
    assert missing_body == []
    assert [p.location for p in body_only] == ["body"]
    nested, _ = match_injection_points(points, ["user.id"])
    assert [p.name for p in nested] == ["user.id"]
    _, gone = match_injection_points(points, ["nope"])
    assert gone == ["nope"]


def test_normalize_db_type_aliases() -> None:
    assert normalize_db_type(None) == "unknown"
    assert normalize_db_type("Unknown") == "unknown"
    assert normalize_db_type("sqlserver") == "mssql"
    assert normalize_db_type("Microsoft SQL Server") == "mssql"
    try:
        normalize_db_type("oracle")
    except ValueError as exc:
        assert "unknown SQLi database" in str(exc)
    else:
        raise AssertionError("expected ValueError for oracle")
