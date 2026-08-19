"""Host-header detector: URL-shaped canary sinks vs baseline."""

from talos.host_header.detect import analyze_host_header_response, host_matches_needle
from talos.host_header.models import CANARY_HOST, VERDICT_HOST_HEADER, VERDICT_SECURE


def test_new_location_canary_is_finding() -> None:
    verdict, hint, url, evidence = analyze_host_header_response(
        baseline_headers={"Location": "https://app.example.com/login"},
        probe_headers={"Location": f"https://{CANARY_HOST}/login"},
        baseline_body=b"ok",
        probe_body=b"ok",
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_HOST_HEADER
    assert hint == "location"
    assert CANARY_HOST in url
    assert "location" in evidence


def test_same_baseline_location_is_secure() -> None:
    loc = f"https://{CANARY_HOST}/already"
    verdict, hint, _, _ = analyze_host_header_response(
        baseline_headers={"Location": loc},
        probe_headers={"Location": loc},
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_html_href_canary_is_finding() -> None:
    verdict, hint, url, _ = analyze_host_header_response(
        baseline_headers={"Content-Type": "text/html"},
        probe_headers={"Content-Type": "text/html"},
        baseline_body=b'<a href="https://app.example.com/reset">reset</a>',
        probe_body=(
            f'<a href="https://{CANARY_HOST}/reset?tok=1">reset</a>'.encode()
        ),
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_HOST_HEADER
    assert hint == "html_url"
    assert CANARY_HOST in url


def test_plain_echo_without_url_is_not_finding() -> None:
    verdict, hint, _, _ = analyze_host_header_response(
        baseline_headers={},
        probe_headers={"Content-Type": "text/html"},
        baseline_body=b"<html>ok</html>",
        probe_body=f"<html>invalid host {CANARY_HOST}</html>".encode(),
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_acao_canary_is_finding() -> None:
    verdict, hint, url, _ = analyze_host_header_response(
        baseline_headers={"Access-Control-Allow-Origin": "https://app.example.com"},
        probe_headers={"Access-Control-Allow-Origin": f"https://{CANARY_HOST}"},
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_HOST_HEADER
    assert hint == "acao"
    assert CANARY_HOST in url


def test_cache_html_sets_cache_hint() -> None:
    verdict, hint, _, _ = analyze_host_header_response(
        baseline_headers={},
        probe_headers={
            "Content-Type": "text/html",
            "X-Cache": "HIT",
            "Age": "12",
        },
        baseline_body=b"<html>ok</html>",
        probe_body=f'<link rel="canonical" href="https://{CANARY_HOST}/page">'.encode(),
        payload_sent=CANARY_HOST,
    )
    assert verdict == VERDICT_HOST_HEADER
    assert hint == "cache"


def test_localhost_payload_in_location_is_finding() -> None:
    verdict, hint, url, _ = analyze_host_header_response(
        baseline_headers={"Location": "https://app.example.com/x"},
        probe_headers={"Location": "https://localhost/x"},
        payload_sent="localhost",
    )
    assert verdict == VERDICT_HOST_HEADER
    assert hint == "location"
    assert "localhost" in url


def test_host_matches_subdomain_poison() -> None:
    assert host_matches_needle(
        "https://app.example.com.talos-hhi.invalid/reset",
        CANARY_HOST,
    )
    assert host_matches_needle(
        f"https://{CANARY_HOST}.app.example.com/reset",
        CANARY_HOST,
    )
    assert not host_matches_needle("https://app.example.com/", CANARY_HOST)
