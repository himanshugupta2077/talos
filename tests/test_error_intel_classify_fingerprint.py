"""
Golden / unit tests for Error Intelligence Phases 3–4:

  - normalize_error_text (line numbers, UUIDs, request IDs)
  - compute_fingerprint stability (same error, different volatiles → one fp)
  - classify_error category / severity bands
"""

from __future__ import annotations

from talos.error_intel import (
    CATEGORY_DATABASE,
    CATEGORY_FRAMEWORK,
    CATEGORY_HTTP,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_SECURITY,
    CATEGORY_STACK_TRACE,
    CATEGORY_VALIDATION,
    ERROR_INTEL_VERSION,
    LANG_JAVA,
    LANG_PYTHON,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    ClassifiedError,
    classify_error,
    classify_from_detect,
    compute_fingerprint,
    detect_errors,
    normalize_error_text,
    normalize_stack_line_numbers,
    severity_from_score,
)
from talos.error_intel.config import merge_config

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

JAVA_SQL_A = """\
HTTP Status 500 – Internal Server Error
java.sql.SQLSyntaxErrorException: You have an error in your SQL syntax; check the manual
\tat com.example.UserService.load(UserService.java:142)
\tat com.example.UserController.get(UserController.java:58)
Caused by: java.sql.SQLException: syntax error at or near "'"
request_id=abc-123-def-456-xyz
"""

JAVA_SQL_B = """\
HTTP Status 500 – Internal Server Error
java.sql.SQLSyntaxErrorException: You have an error in your SQL syntax; check the manual
\tat com.example.UserService.load(UserService.java:999)
\tat com.example.UserController.get(UserController.java:12)
Caused by: java.sql.SQLException: syntax error at or near "'"
request_id=zzzz-yyyy-xxxx-wwww
"""

JAVA_HIBERNATE = """\
org.hibernate.exception.SQLGrammarException: could not extract ResultSet
\tat org.hibernate.exception.internal.SQLStateConversionDelegate.convert(SQLStateConversionDelegate.java:112)
\tat com.example.repo.OrderRepository.find(OrderRepository.java:44)
Caused by: java.sql.SQLSyntaxErrorException: Unknown column 'usr_id' in 'field list'
"""

PYTHON_TRACE = """\
Traceback (most recent call last):
  File "/app/views.py", line 42, in handler
    raise ValueError("bad input")
ValueError: bad input
"""

INVALID_EMAIL = '{"error": "Invalid email", "message": "Invalid email address"}'

WHITELABEL = """\
Whitelabel Error Page
This application has no explicit mapping for /error
"""

JWT_ERR = "JWT decode failed: invalid signature"


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def test_normalize_java_line_numbers() -> None:
    a = normalize_stack_line_numbers(
        "at com.example.UserService.load(UserService.java:142)"
    )
    b = normalize_stack_line_numbers(
        "at com.example.UserService.load(UserService.java:999)"
    )
    assert a == b
    assert "<LINE>" in a
    assert "142" not in a
    assert "999" not in a


def test_normalize_strips_uuid_and_ts() -> None:
    raw = (
        "error id=550e8400-e29b-41d4-a716-446655440000 "
        "at 2024-06-01T12:34:56Z path=/home/alice/app/x.py"
    )
    norm = normalize_error_text(raw)
    assert "550e8400" not in norm
    assert "<UUID>" in norm
    assert "<TS>" in norm
    assert "/home/<USER>/" in norm
    assert "alice" not in norm


def test_normalize_request_id_kv() -> None:
    norm = normalize_error_text("request_id=abc123xyz789 and trace_id=deadbeefcafe01")
    assert "abc123xyz789" not in norm
    assert "<REQID>" in norm


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

def test_same_java_exception_different_lines_same_fingerprint() -> None:
    c1 = classify_error(JAVA_SQL_A, status_code=500, content_type="text/plain")
    c2 = classify_error(JAVA_SQL_B, status_code=500, content_type="text/plain")
    assert c1 is not None and c2 is not None
    assert c1.fingerprint == c2.fingerprint
    assert c1.exception_type and "SQLSyntaxErrorException" in c1.exception_type
    assert c1.category == CATEGORY_STACK_TRACE
    assert c1.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)
    assert c1.language == LANG_JAVA


def test_fingerprint_excludes_endpoint_identity() -> None:
    """Fingerprint is independent of call site — only identity tuple fields."""
    fp1 = compute_fingerprint(
        status_bucket="5xx",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type="java.sql.SQLSyntaxErrorException",
        framework="spring",
        database="mysql",
        normalized_stack="at com.example.UserService.load(UserService.java:<LINE>)",
        normalized_message="You have an error in your SQL syntax",
        server="tomcat",
    )
    fp2 = compute_fingerprint(
        status_bucket="5xx",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type="java.sql.SQLSyntaxErrorException",
        framework="spring",
        database="mysql",
        normalized_stack="at com.example.UserService.load(UserService.java:<LINE>)",
        normalized_message="You have an error in your SQL syntax",
        server="tomcat",
    )
    assert fp1 == fp2
    assert len(fp1) == 64


def test_different_exception_types_fork_fingerprint() -> None:
    fp1 = compute_fingerprint(
        status_bucket="5xx",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type="java.lang.NullPointerException",
        normalized_stack="",
        normalized_message="npe",
    )
    fp2 = compute_fingerprint(
        status_bucket="5xx",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type="java.sql.SQLSyntaxErrorException",
        normalized_stack="",
        normalized_message="npe",
    )
    assert fp1 != fp2


def test_short_and_fqcn_exception_same_fingerprint() -> None:
    """BUG-04: NullPointerException and java.lang.NullPointerException merge."""
    from talos.error_intel.detectors.base import normalize_exception_type

    short = normalize_exception_type("NullPointerException")
    fqcn = normalize_exception_type("java.lang.NullPointerException")
    assert short == fqcn == "java.lang.NullPointerException"

    fp1 = compute_fingerprint(
        status_bucket="none",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type=short,
        normalized_stack="at com.example.X.run(X.java:<LINE>)",
        normalized_message="null",
    )
    fp2 = compute_fingerprint(
        status_bucket="none",
        category=CATEGORY_STACK_TRACE,
        language=LANG_JAVA,
        exception_type=fqcn,
        normalized_stack="at com.example.X.run(X.java:<LINE>)",
        normalized_message="null",
    )
    assert fp1 == fp2

    # Short CLR name expands to System.*
    assert (
        normalize_exception_type("NullReferenceException")
        == "System.NullReferenceException"
    )


# ---------------------------------------------------------------------------
# Classify
# ---------------------------------------------------------------------------

def test_classify_java_sql_stack_high_or_critical() -> None:
    c = classify_error(JAVA_SQL_A, status_code=500)
    assert c is not None
    assert c.category == CATEGORY_STACK_TRACE
    assert c.has_stack_trace is True
    assert c.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)
    assert c.severity_score >= 70
    assert c.confidence >= 70
    assert c.fingerprint
    assert c.scanner_version == ERROR_INTEL_VERSION


def test_classify_hibernate_has_database_tech() -> None:
    c = classify_error(JAVA_HIBERNATE, status_code=500)
    assert c is not None
    assert c.category == CATEGORY_STACK_TRACE
    # DB or hibernate should appear in technologies / database
    techs = set(c.technologies or [])
    assert c.database or "hibernate" in techs or c.framework == "hibernate"
    assert c.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)


def test_classify_python_traceback() -> None:
    c = classify_error(PYTHON_TRACE, status_code=500)
    assert c is not None
    assert c.category == CATEGORY_STACK_TRACE
    assert c.language == LANG_PYTHON
    assert c.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)


def test_classify_stack_on_http_200() -> None:
    c = classify_error(JAVA_SQL_A, status_code=200, content_type="text/plain")
    assert c is not None
    assert c.category == CATEGORY_STACK_TRACE
    assert c.status_bucket == "2xx_error_body"
    assert c.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)


def test_same_exception_merges_across_status_buckets() -> None:
    """BUG-01: proxy 500 + IV 400 + BAC 200 → one fingerprint."""
    body = JAVA_SQL_A
    c_proxy = classify_error(body, status_code=500, content_type="text/plain")
    c_iv = classify_error(body, status_code=400, content_type="text/plain")
    c_bac = classify_error(body, status_code=200, content_type="text/plain")
    assert c_proxy is not None and c_iv is not None and c_bac is not None
    assert c_proxy.fingerprint == c_iv.fingerprint == c_bac.fingerprint
    # Display buckets still reflect the observation status
    assert c_proxy.status_bucket == "5xx"
    assert c_iv.status_bucket == "4xx"
    assert c_bac.status_bucket == "2xx_error_body"


def test_classify_invalid_email_low_or_skipped_by_stage_g() -> None:
    # Default: store_generic_http_errors=false and 4xx → Stage G may not fire
    c = classify_error(
        INVALID_EMAIL,
        status_code=400,
        content_type="application/json",
    )
    # Either no classification (gate of Stage G) or low validation
    if c is None:
        return
    assert c.category in (CATEGORY_VALIDATION, CATEGORY_HTTP)
    assert c.severity in (SEVERITY_LOW, SEVERITY_MEDIUM)
    assert c.severity_score < 70


def test_classify_invalid_email_with_generic_store() -> None:
    cfg = merge_config(overrides={"store_generic_http_errors": True})
    c = classify_error(
        INVALID_EMAIL,
        status_code=400,
        content_type="application/json",
        config=cfg,
    )
    assert c is not None
    assert c.category in (CATEGORY_VALIDATION, CATEGORY_HTTP)
    assert c.severity in (SEVERITY_LOW, SEVERITY_MEDIUM)


def test_classify_jwt_security() -> None:
    c = classify_error(JWT_ERR, status_code=401)
    assert c is not None
    assert c.category == CATEGORY_SECURITY
    assert c.severity in (SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_LOW)


def test_classify_whitelabel_framework() -> None:
    c = classify_error(WHITELABEL, status_code=500)
    assert c is not None
    assert c.category in (CATEGORY_FRAMEWORK, CATEGORY_STACK_TRACE)
    assert c.framework == "spring" or "spring" in (c.technologies or [])


def test_severity_from_score_bands() -> None:
    assert severity_from_score(95) == SEVERITY_CRITICAL
    assert severity_from_score(75) == SEVERITY_HIGH
    assert severity_from_score(50) == SEVERITY_MEDIUM
    assert severity_from_score(10) == SEVERITY_LOW


def test_classify_from_detect_empty() -> None:
    result = detect_errors("hello world ok", status_code=200)
    c = classify_from_detect(result, status_code=200)
    assert c is None


def test_classified_error_to_dict() -> None:
    c = classify_error(PYTHON_TRACE, status_code=500)
    assert c is not None
    d = c.to_dict()
    assert d["category"] == CATEGORY_STACK_TRACE
    assert d["fingerprint"] == c.fingerprint


def test_evidence_snippet_redacts_password_and_jdbc() -> None:
    """BUG-12: stored evidence must not retain cleartext secrets."""
    body = (
        "java.sql.SQLException: login failed\n"
        "password=SuperSecret123!\n"
        "jdbc:mysql://db.internal:3306/app?user=root&password=hunter2\n"
        "\tat com.example.Db.connect(Db.java:10)\n"
    )
    c = classify_error(body, status_code=500)
    assert c is not None
    # Critical severity still applies (detection saw secrets)
    assert c.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)
    snip = c.evidence_snippet or ""
    assert "SuperSecret123" not in snip
    assert "hunter2" not in snip
    assert "****" in snip
