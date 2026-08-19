"""Open-redirect detector: new Location / JS / meta to the canary."""

from talos.open_redirect.detect import analyze_open_redirect_response, host_matches_canary
from talos.open_redirect.models import CANARY_HOST, VERDICT_OPEN_REDIRECT, VERDICT_SECURE


def test_new_location_to_canary_is_open_redirect() -> None:
    verdict, hint, url, evidence = analyze_open_redirect_response(
        baseline_headers={"Location": "https://app.example.com/login"},
        probe_headers={"Location": f"https://{CANARY_HOST}/"},
        baseline_body=b"",
        probe_body=b"",
        payload_sent=f"https://{CANARY_HOST}/",
    )
    assert verdict == VERDICT_OPEN_REDIRECT
    assert hint == "location"
    assert CANARY_HOST in url
    assert "location" in evidence


def test_same_baseline_location_is_secure() -> None:
    loc = f"https://{CANARY_HOST}/"
    verdict, hint, _, _ = analyze_open_redirect_response(
        baseline_headers={"Location": loc},
        probe_headers={"Location": loc},
        payload_sent=loc,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_echoed_payload_in_html_is_not_open_redirect() -> None:
    payload = f"https://{CANARY_HOST}/"
    verdict, _, _, _ = analyze_open_redirect_response(
        baseline_headers={"Content-Type": "text/html"},
        probe_headers={"Content-Type": "text/html"},
        baseline_body=b"<html>ok</html>",
        probe_body=f"<html>next={payload}</html>".encode(),
        payload_sent=payload,
    )
    assert verdict == VERDICT_SECURE


def test_js_location_assignment_is_open_redirect() -> None:
    body = f"<script>window.location='https://{CANARY_HOST}/'</script>".encode()
    verdict, hint, url, _ = analyze_open_redirect_response(
        baseline_headers={},
        probe_headers={"Content-Type": "text/html"},
        baseline_body=b"<html></html>",
        probe_body=body,
        payload_sent=f"https://{CANARY_HOST}/",
    )
    assert verdict == VERDICT_OPEN_REDIRECT
    assert hint == "js_location"
    assert CANARY_HOST in url


def test_javascript_location_header_is_open_redirect() -> None:
    verdict, hint, url, _ = analyze_open_redirect_response(
        baseline_headers={},
        probe_headers={"Location": "javascript:alert(1)"},
        payload_sent="javascript:alert(1)",
    )
    assert verdict == VERDICT_OPEN_REDIRECT
    assert hint == "javascript"
    assert url.startswith("javascript:")


def test_host_matches_canary_subdomain() -> None:
    assert host_matches_canary(f"https://x.{CANARY_HOST}/", CANARY_HOST)
    assert not host_matches_canary(f"https://{CANARY_HOST}.evil.com/", CANARY_HOST)
    assert host_matches_canary(f"//{CANARY_HOST}/", CANARY_HOST)
