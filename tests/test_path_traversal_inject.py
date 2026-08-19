"""Path-traversal entry-point extraction, replace inject, catalogue coverage."""

import json

from talos.path_traversal.inject import (
    apply_payload,
    extract_injection_points,
    match_injection_points,
)
from talos.path_traversal.payloads import generate_path_traversal_payloads, render_payload
from talos.path_traversal.models import FAMILIES


def test_catalogue_covers_all_families() -> None:
    payloads = generate_path_traversal_payloads()
    families = {p.family for p in payloads}
    assert families == set(FAMILIES)
    names = {p.technique for p in payloads}
    assert "unix_passwd" in names
    assert "win_ini" in names
    assert "dd_unix_8" in names
    assert "enc_double_url" in names
    assert "php_filter_passwd" in names
    assert "null_passwd_jpg" in names
    assert "bypass_semicolon" in names
    assert len(payloads) >= 40


def test_family_filter() -> None:
    unix = generate_path_traversal_payloads(families=["unix"])
    assert {p.family for p in unix} == {"unix"}
    assert any(p.payload == "/etc/passwd" for p in unix)


def test_extracts_query_json_and_path_param() -> None:
    points = extract_injection_points(
        url="https://app.example.com/files/report.pdf?file=avatar.png",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"path":"docs/a.txt"}',
        normalized_path="/files/{name}",
    )
    by_key = {(p.location, p.name): p for p in points}
    assert ("query", "file") in by_key
    assert ("body", "path") in by_key
    assert ("path", "name") in by_key
    assert by_key[("query", "file")].original == "avatar.png"
    assert by_key[("path", "name")].original == "report.pdf"


def test_replace_payload_on_query() -> None:
    points = extract_injection_points(
        url="https://app.example.com/view?file=home.html",
    )
    file_pt = next(p for p in points if p.name == "file")
    url, _headers, _body = apply_payload(
        file_pt,
        "/etc/passwd",
        url="https://app.example.com/view?file=home.html",
        request_headers={},
        request_body=None,
    )
    assert "file=/etc/passwd" in url or "file=%2Fetc%2Fpasswd" in url
    assert "home.html" not in url.split("?", 1)[-1]


def test_match_param_filter() -> None:
    points = extract_injection_points(
        url="https://app.example.com/x?file=a&id=1",
        request_headers={"Content-Type": "application/json"},
        request_body=b'{"file":"b"}',
    )
    matched, missing = match_injection_points(points, ["query:file"])
    assert missing == []
    assert len(matched) == 1
    assert matched[0].location == "query"
    assert matched[0].name == "file"


def test_suffix_render_joins_original() -> None:
    payloads = generate_path_traversal_payloads(techniques=["dd_suffix_unix"])
    assert len(payloads) == 1
    sent = render_payload(payloads[0], "uploads/a.txt")
    assert sent.startswith("uploads/a.txt/")
    assert sent.endswith("etc/passwd")


def test_multipart_filename_point() -> None:
    body = (
        b"--xyz\r\nContent-Disposition: form-data; name=\"doc\"; "
        b"filename=\"report.pdf\"\r\n\r\nxx\r\n--xyz--\r\n"
    )
    points = extract_injection_points(
        url="https://app.example.com/upload",
        request_headers={"Content-Type": "multipart/form-data; boundary=xyz"},
        request_body=body,
    )
    names = [(p.location, p.name, p.surface_kind) for p in points]
    assert ("body", "doc", "multipart_filename") in names
    doc = next(p for p in points if p.name == "doc")
    assert doc.original == "report.pdf"
