"""
Phase 6 tests: suppression vocabulary and edge cases.
"""

from __future__ import annotations

from talos.passive.models import RawMatch
from talos.passive.suppress import is_public_test_token, should_suppress


def test_empty_and_nullish():
    for v in ("", "  ", "null", "undefined", "None", "nil"):
        assert should_suppress(v)[0] is True


def test_placeholder_vocabulary():
    for v in (
        "example",
        "changeme",
        "placeholder",
        "YOUR_API_KEY",
        "password",
        "xxx",
        "aaaa",
    ):
        suppressed, reason = should_suppress(v)
        assert suppressed, v
        assert reason


def test_template_and_env():
    assert should_suppress("${SECRET}")[0]
    assert should_suppress("{{password}}")[0]
    assert should_suppress("process.env.API_KEY")[0]
    assert should_suppress("import.meta.env.VITE_KEY")[0]


def test_env_assignment_context():
    # Value that is not itself a placeholder token — only the env assignment
    # context should suppress it.
    raw = RawMatch(
        detector_id="contextual_assignment",
        detector_family="contextual",
        category="secret",
        secret_type="generic_assignment",
        matched_key="key",
        raw_value="MYAPP_TOKEN",
        match_start=10,
        match_end=21,
        context_before="const key = process.env.",
        context_after=";",
    )
    suppressed, reason = should_suppress(
        "MYAPP_TOKEN",
        detector_family="contextual",
        raw_match=raw,
    )
    assert suppressed
    assert reason == "env_var_assignment"


def test_public_test_tokens():
    assert is_public_test_token("AKIAIOSFODNN7EXAMPLE")
    assert should_suppress("AKIAIOSFODNN7EXAMPLE")[0]


def test_low_entropy_generic():
    suppressed, reason = should_suppress(
        "aaaaaa",
        detector_family="contextual",
    )
    assert suppressed
    assert reason in ("low_entropy", "placeholder", "placeholder_vocabulary")


def test_good_secret_not_suppressed():
    suppressed, _ = should_suppress(
        "SuperSecret123!xyzAB",
        detector_family="contextual",
        matched_key="password",
    )
    assert not suppressed


def test_url_and_hostpath_suppressed():
    for v in (
        "https://api.github.com/user",
        "//api.github.com/user",
        "api.github.com/user",
        "https://example.com/v1/keys",
    ):
        suppressed, reason = should_suppress(v, detector_family="entropy")
        assert suppressed, v
        assert reason == "url_or_hostpath"


def test_connection_string_uris_not_suppressed_as_urls():
    """DB URIs and HTTP userinfo URLs are secrets, not URL noise."""
    for v in (
        "postgres://user:s3cret@db.internal:5432/app",
        "mysql://root:pass@localhost:3306/db",
        "https://user:pass@example.com/path",
    ):
        suppressed, reason = should_suppress(v, detector_family="entropy")
        assert not suppressed, (v, reason)


def test_angle_placeholder_suppressed():
    for v in ("<secret>", "<YOUR_API_KEY>", "<token>"):
        suppressed, reason = should_suppress(v, detector_family="contextual")
        assert suppressed, v
        assert reason == "angle_placeholder"


def test_credentials_mode_and_code_expression_suppressed():
    from talos.passive.suppress import looks_like_code_expression

    assert looks_like_code_expression("()=>get[e")
    assert looks_like_code_expression("{...token")
    assert looks_like_code_expression("!!r.withCredentials)")
    assert looks_like_code_expression("Object.defineProperty")
    assert looks_like_code_expression("n=Object.getOwnPropertyDescriptor")

    for v, family in (
        ("same-origin", "contextual"),
        ("include", "contextual"),
        ("omit", "contextual"),
        ("true", "contextual"),
        ("{fontFamily:x}", "contextual"),
    ):
        suppressed, reason = should_suppress(v, detector_family=family)
        assert suppressed, (v, reason)


def test_non_secret_key_suppressed():
    suppressed, reason = should_suppress(
        "whatevervalue12",
        detector_family="contextual",
        matched_key="withCredentials",
    )
    assert suppressed
    assert reason == "non_secret_key"
