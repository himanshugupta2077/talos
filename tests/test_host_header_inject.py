"""Host-header extraction, header replace, catalogue coverage."""

from talos.host_header.inject import (
    apply_payload,
    extract_injection_points,
    match_injection_points,
)
from talos.host_header.models import CANARY_HOST, FAMILIES
from talos.host_header.payloads import (
    generate_host_header_payloads,
    payload_applies,
    render_payload,
)


def test_catalogue_covers_all_families() -> None:
    payloads = generate_host_header_payloads()
    families = {p.family for p in payloads}
    assert families == set(FAMILIES)
    names = {p.technique for p in payloads}
    assert "abs_canary" in names
    assert "port_canary_443" in names
    assert "amb_colon" in names
    assert "url_https" in names
    assert "enc_percent_dot" in names
    assert "bypass_sub_poison" in names
    assert "crlf_xfh" in names
    assert len(payloads) >= 35


def test_family_filter() -> None:
    rows = generate_host_header_payloads(families=["absolute"])
    assert {p.family for p in rows} == {"absolute"}
    assert any(p.technique == "abs_canary" for p in rows)


def test_extracts_host_and_overrides() -> None:
    points = extract_injection_points(
        url="https://app.example.com/reset",
        request_headers={"Host": "app.example.com", "Accept": "text/html"},
    )
    names = [p.name for p in points]
    assert names[0] == "Host"
    assert "X-Forwarded-Host" in names
    assert "Forwarded" in names
    host = next(p for p in points if p.name == "Host")
    assert host.original == "app.example.com"
    assert host.location == "header"
    xfh = next(p for p in points if p.name == "X-Forwarded-Host")
    assert xfh.original == ""


def test_apply_payload_keeps_url_changes_host() -> None:
    points = extract_injection_points(
        url="https://app.example.com/reset",
        request_headers={"Host": "app.example.com"},
    )
    host = next(p for p in points if p.name == "Host")
    url, headers, _body = apply_payload(
        host,
        CANARY_HOST,
        url="https://app.example.com/reset",
        request_headers={"Host": "app.example.com"},
        request_body=None,
    )
    assert url == "https://app.example.com/reset"
    assert headers["Host"] == CANARY_HOST


def test_apply_override_keeps_original_host() -> None:
    points = extract_injection_points(
        url="https://app.example.com/reset",
        request_headers={"Host": "app.example.com"},
    )
    xfh = next(p for p in points if p.name == "X-Forwarded-Host")
    url, headers, _body = apply_payload(
        xfh,
        CANARY_HOST,
        url="https://app.example.com/reset",
        request_headers={"Host": "app.example.com"},
        request_body=None,
    )
    assert url == "https://app.example.com/reset"
    assert headers["Host"] == "app.example.com"
    assert headers["X-Forwarded-Host"] == CANARY_HOST


def test_match_header_filter() -> None:
    points = extract_injection_points(url="https://app.example.com/")
    matched, missing = match_injection_points(points, ["Host", "header:X-Forwarded-Host"])
    assert missing == []
    assert [p.name for p in matched] == ["Host", "X-Forwarded-Host"]


def test_render_forwarded_wraps_host() -> None:
    payloads = generate_host_header_payloads(techniques=["abs_canary"])
    sent = render_payload(
        payloads[0],
        "app.example.com",
        url="https://app.example.com/",
        header_name="Forwarded",
    )
    assert sent == f"host={CANARY_HOST}"


def test_crlf_payload_host_only() -> None:
    payloads = generate_host_header_payloads(techniques=["crlf_xfh"])
    assert len(payloads) == 1
    assert payload_applies(payloads[0], "Host")
    assert not payload_applies(payloads[0], "X-Forwarded-Host")
