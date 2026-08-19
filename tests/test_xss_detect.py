"""XSS detector: canary + unencoded sink vs encoded / baseline."""

from talos.xss.detect import analyze_xss_response, collect_canary_hits
from talos.xss.models import CANARY, VERDICT_HTMLI, VERDICT_SECURE, VERDICT_XSS


def test_collects_canary() -> None:
    hits = collect_canary_hits(f"<p>hello {CANARY}</p>")
    assert hits
    assert CANARY in hits[0]


def test_raw_script_is_xss() -> None:
    verdict, hint, ctx, enc, evidence = analyze_xss_response(
        baseline_body=b"<html>search</html>",
        probe_body=f"<html>search<script>alert('{CANARY}')</script></html>".encode(),
        content_type="text/html",
    )
    assert verdict == VERDICT_XSS
    assert hint == "xss_sink"
    assert enc == "raw"
    assert CANARY in evidence


def test_img_onerror_is_xss() -> None:
    verdict, hint, _, _, _ = analyze_xss_response(
        baseline_body=b"<html>ok</html>",
        probe_body=f"<html><img src=x onerror=alert('{CANARY}')></html>".encode(),
        content_type="text/html",
    )
    assert verdict == VERDICT_XSS
    assert hint == "xss_sink"


def test_h1_is_htmli() -> None:
    verdict, hint, _, enc, evidence = analyze_xss_response(
        baseline_body=b"<html>ok</html>",
        probe_body=f"<html><h1>{CANARY}</h1></html>".encode(),
        content_type="text/html",
        risk_class="htmli",
    )
    assert verdict == VERDICT_HTMLI
    assert hint == "html_tag"
    assert enc == "raw"
    assert CANARY in evidence


def test_html_encoded_script_is_secure() -> None:
    verdict, hint, _, enc, _ = analyze_xss_response(
        baseline_body=b"<html>ok</html>",
        probe_body=f"<html>&lt;script&gt;alert('{CANARY}')&lt;/script&gt;</html>".encode(),
        content_type="text/html",
    )
    assert verdict == VERDICT_SECURE
    assert enc == "html_entity"
    assert hint == "encoded"


def test_same_baseline_canary_is_not_a_finding() -> None:
    body = f"<html><script>alert('{CANARY}')</script></html>".encode()
    verdict, hint, _, _, _ = analyze_xss_response(
        baseline_body=body,
        probe_body=body,
        content_type="text/html",
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_missing_canary_is_secure() -> None:
    verdict, _, _, _, _ = analyze_xss_response(
        baseline_body=b"<html>ok</html>",
        probe_body=b"<html><script>alert(1)</script></html>",
        content_type="text/html",
    )
    assert verdict == VERDICT_SECURE


def test_js_breakout_alert_is_xss() -> None:
    verdict, hint, _, _, _ = analyze_xss_response(
        baseline_body=b"var q='x';",
        probe_body=f"var q='x';alert('{CANARY}')//';".encode(),
        content_type="application/javascript",
    )
    assert verdict == VERDICT_XSS
    assert hint == "xss_sink"
