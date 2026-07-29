"""
Golden / unit tests for talos.error_intel detectors (Phase 2).

Stages A–G via detect_errors / ErrorDetectorOrchestrator.
No DB, no queue, no FlowWorker.
"""

from __future__ import annotations

import pytest

from talos.error_intel import (
    CATEGORY_DATABASE,
    CATEGORY_DISCLOSURE,
    CATEGORY_FRAMEWORK,
    CATEGORY_HTTP,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_SECURITY,
    CATEGORY_STACK_TRACE,
    CATEGORY_VALIDATION,
    CONFIDENCE_CONFIRMED_PATTERN,
    DETECTOR_FAMILY_DATABASE,
    DETECTOR_FAMILY_DISCLOSURE,
    DETECTOR_FAMILY_FRAMEWORK,
    DETECTOR_FAMILY_HTTP,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_SECURITY,
    DETECTOR_FAMILY_STACK,
    LANG_CSHARP,
    LANG_GO,
    LANG_JAVA,
    LANG_JAVASCRIPT,
    LANG_PHP,
    LANG_PYTHON,
    LANG_RUBY,
    LANG_RUST,
    ErrorDetectResult,
    detect_errors,
    pick_primary_match,
)
from talos.error_intel.config import default_config, merge_config
from talos.error_intel.detectors.base import decode_body_text, extract_snippet
from talos.error_intel.detectors.database import DatabaseErrorDetector
from talos.error_intel.detectors.stack_trace import StackTraceDetector
from talos.error_intel.models import RawErrorMatch

# ---------------------------------------------------------------------------
# Fixtures (realistic error bodies)
# ---------------------------------------------------------------------------

JAVA_SQL_STACK = """\
HTTP Status 500 – Internal Server Error
java.sql.SQLSyntaxErrorException: You have an error in your SQL syntax; check the manual
\tat com.example.UserService.load(UserService.java:142)
\tat com.example.UserController.get(UserController.java:58)
\tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)
Caused by: java.sql.SQLException: syntax error at or near "'"
\tat com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:120)
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
  File "/usr/local/lib/python3.11/site-packages/django/core/handlers/base.py", line 197, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
ValueError: bad input
"""

DOTNET_STACK = """\
System.NullReferenceException: Object reference not set to an instance of an object.
   at MyApp.Services.UserService.Load(Int32 id) in C:\\src\\UserService.cs:line 88
   at MyApp.Controllers.UsersController.Get(Int32 id) in C:\\src\\UsersController.cs:line 40
StackTrace:
"""

NODE_STACK = """\
TypeError: Cannot read properties of undefined (reading 'id')
    at Object.getUser (/app/routes/user.js:12:15)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/app/node_modules/express/lib/router/route.js:144:13)
"""

PHP_FATAL = """\
Fatal error: Uncaught Error: Call to undefined function foo() in /var/www/html/index.php:15
Stack trace:
#0 /var/www/html/index.php(15): foo()
#1 {main}
  thrown in /var/www/html/index.php on line 15
"""

RUBY_ERROR = """\
NoMethodError (undefined method `name' for nil:NilClass):
  from app/controllers/users_controller.rb:22:in `show'
  from actionpack (7.0.0) lib/action_controller/metal/basic_implicit_render.rb:6:in `send_action'
Action Controller: Exception caught
"""

GO_PANIC = """\
panic: runtime error: invalid memory address or nil pointer dereference
goroutine 1 [running]:
main.(*Server).Handle(0xc0000140a0, 0xc00010a000)
\t/app/server.go:55 +0x65
"""

RUST_PANIC = """\
thread 'main' panicked at 'index out of bounds: the len is 0 but the index is 0', src/main.rs:10:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
"""

SQLSTATE_BODY = """\
SQLSTATE[42P01]: Undefined table: 7 ERROR:  relation "users" does not exist
LINE 1: SELECT * FROM users
"""

ORA_BODY = "ORA-00942: table or view does not exist"

MYSQL_BODY = "ERROR 1064 (42000): You have an error in your SQL syntax near 'SELCT'"

WHITELABEL = """\
<html><body><h1>Whitelabel Error Page</h1>
<p>This application has no explicit mapping for /error</p>
</body></html>
"""

NGINX_502 = """\
<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
"""

CLOUDFLARE_1020 = """\
<!DOCTYPE html>
<html>
<head><title>Access denied | Cloudflare</title></head>
<body>
<h1>Error code 1020</h1>
<p>Access denied. Contact the site owner.</p>
<!-- cf-ray: 7a1b2c3d4e5f6g7h-SJC -->
</body>
</html>
"""

JWT_ERROR_JSON = '{"error":"invalid_token","error_description":"JWT decode failed: signature verification failed"}'

CSRF_HTML = "<html><body>CSRF token validation failed. Forbidden (CSRF).</body></html>"

JSON_VALIDATION_400 = '{"message":"Invalid email","code":"validation_error"}'

PROBLEM_JSON = """\
{
  "type": "https://example.com/probs/out-of-credit",
  "title": "You do not have enough credit.",
  "detail": "Your current balance is 30, but that costs 50.",
  "status": 403
}
"""

PATH_LEAK_5XX = """\
Internal Server Error
File "/home/deploy/app/services/billing.py", line 99, in charge
Connection refused to db.internal:5432 (10.0.1.15)
OpenJDK Runtime Environment 17.0.2
"""

HEALTHY_JSON = '{"ok": true, "data": {"id": 1}}'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _families(result: ErrorDetectResult) -> set[str]:
    return {m.family for m in result.matches}


def _ids(result: ErrorDetectResult) -> set[str]:
    return {m.detector_id for m in result.matches}


# ---------------------------------------------------------------------------
# Stage A — stack traces
# ---------------------------------------------------------------------------

def test_java_sql_stack_primary() -> None:
    r = detect_errors(JAVA_SQL_STACK, status_code=500, content_type="text/plain")
    assert r.strong_hit
    assert DETECTOR_FAMILY_STACK in _families(r)
    assert r.primary is not None
    assert r.primary.family == DETECTOR_FAMILY_STACK
    assert r.primary.language == LANG_JAVA
    assert r.primary.exception_type is not None
    assert "SQLSyntaxErrorException" in r.primary.exception_type
    assert r.primary.confidence == CONFIDENCE_CONFIRMED_PATTERN
    assert r.primary.raw_snippet
    # DB stage should also fire (SQLException / mysql)
    assert DETECTOR_FAMILY_DATABASE in _families(r) or any(
        "sql" in (m.exception_type or "").lower() for m in r.matches
    )


def test_java_hibernate_and_database() -> None:
    r = detect_errors(JAVA_HIBERNATE, status_code=500)
    stack = [m for m in r.matches if m.family == DETECTOR_FAMILY_STACK]
    db = [m for m in r.matches if m.family == DETECTOR_FAMILY_DATABASE]
    assert stack
    assert any("SQL" in (m.exception_type or "") or "Hibernate" in (m.exception_type or "") for m in stack + db)
    assert r.primary is not None
    # Stack or DB both high value; primary should not be http_generic
    assert r.primary.family in (DETECTOR_FAMILY_STACK, DETECTOR_FAMILY_DATABASE)


def test_python_traceback() -> None:
    r = detect_errors(PYTHON_TRACE, status_code=500)
    assert r.primary is not None
    assert r.primary.language == LANG_PYTHON
    assert r.primary.exception_type == "ValueError"
    assert r.primary.metadata.get("has_stack_trace") is True
    frames = r.primary.metadata.get("frames") or []
    assert frames
    assert any("views.py" in (f.get("file") or "") for f in frames)
    assert "django" in (r.primary.metadata.get("technologies") or [])


def test_dotnet_null_reference() -> None:
    r = detect_errors(DOTNET_STACK, status_code=500)
    assert r.primary is not None
    assert r.primary.language == LANG_CSHARP
    assert "NullReferenceException" in (r.primary.exception_type or "")


def test_javascript_typeerror() -> None:
    r = detect_errors(NODE_STACK, status_code=500)
    assert r.primary is not None
    assert r.primary.language == LANG_JAVASCRIPT
    assert r.primary.exception_type == "TypeError"
    assert r.primary.metadata.get("has_stack_trace") is True
    techs = r.primary.metadata.get("technologies") or []
    assert "express" in techs


def test_php_fatal() -> None:
    r = detect_errors(PHP_FATAL, status_code=500)
    assert any(m.language == LANG_PHP for m in r.matches)
    assert any(m.family == DETECTOR_FAMILY_STACK for m in r.matches)
    # path disclosure on 5xx
    assert any(a.kind == "path" for a in r.artifacts) or DETECTOR_FAMILY_DISCLOSURE in _families(r)


def test_ruby_nomethod() -> None:
    r = detect_errors(RUBY_ERROR, status_code=500)
    assert any(m.language == LANG_RUBY for m in r.matches)
    assert any("NoMethodError" in (m.exception_type or "") for m in r.matches)
    # Rails framework chrome may also fire
    assert DETECTOR_FAMILY_STACK in _families(r) or DETECTOR_FAMILY_FRAMEWORK in _families(r)


def test_go_panic() -> None:
    r = detect_errors(GO_PANIC, status_code=500)
    assert r.primary is not None
    assert r.primary.language == LANG_GO
    assert r.primary.exception_type == "panic"


def test_rust_panic() -> None:
    r = detect_errors(RUST_PANIC, status_code=500)
    assert any(m.language == LANG_RUST for m in r.matches)
    assert any(m.exception_type == "panic" for m in r.matches)


def test_stack_detector_direct_java_frames_metadata() -> None:
    det = StackTraceDetector()
    hits = det.detect(JAVA_SQL_STACK)
    assert hits
    assert hits[0].metadata.get("frames")
    assert hits[0].metadata.get("caused_by")


# ---------------------------------------------------------------------------
# Stage B — database
# ---------------------------------------------------------------------------

def test_sqlstate_postgresql() -> None:
    r = detect_errors(SQLSTATE_BODY, status_code=500)
    db = [m for m in r.matches if m.family == DETECTOR_FAMILY_DATABASE]
    assert db
    assert any(
        (m.metadata or {}).get("sqlstate") == "42P01"
        or "42P01" in (m.exception_type or "")
        for m in db
    )
    assert any((m.metadata or {}).get("vendor") == "postgresql" or (m.metadata or {}).get("database") == "postgresql" for m in db)


def test_sqlstate_only_maps_postgresql_vendor() -> None:
    """BUG-11: pure SQLSTATE[42P01] without 'postgresql' text still tags vendor."""
    body = "SQLSTATE[42P01]: ERROR:  relation does not exist"
    r = detect_errors(body, status_code=500)
    db = [m for m in r.matches if m.family == DETECTOR_FAMILY_DATABASE]
    assert db
    assert any(
        (m.metadata or {}).get("vendor") == "postgresql"
        or (m.metadata or {}).get("database") == "postgresql"
        for m in db
    )
    from talos.error_intel import classify_error

    c = classify_error(body, status_code=500)
    assert c is not None
    assert c.database == "postgresql"


def test_ora_code() -> None:
    r = detect_errors(ORA_BODY, status_code=500)
    db = [m for m in r.matches if m.family == DETECTOR_FAMILY_DATABASE]
    assert db
    assert any("ORA-00942" in (m.exception_type or "") or (m.metadata or {}).get("error_code") == "ORA-00942" for m in db)


def test_mysql_error_number() -> None:
    det = DatabaseErrorDetector()
    hits = det.detect(MYSQL_BODY)
    assert hits
    assert any(m.detector_id == "db_mysql" for m in hits)


# ---------------------------------------------------------------------------
# Stage C — framework
# ---------------------------------------------------------------------------

def test_spring_whitelabel() -> None:
    r = detect_errors(WHITELABEL, status_code=500, content_type="text/html")
    assert DETECTOR_FAMILY_FRAMEWORK in _families(r)
    assert any(m.detector_id == "fw_spring_whitelabel" for m in r.matches)
    assert r.primary is not None
    assert r.primary.category_hint == CATEGORY_FRAMEWORK


def test_werkzeug_debugger() -> None:
    body = "Werkzeug Debugger\nTraceback (most recent call last):\n  File \"app.py\", line 1\nZeroDivisionError: division by zero"
    r = detect_errors(body, status_code=500)
    assert any("werkzeug" in (m.detector_id or "") or (m.metadata or {}).get("framework") == "werkzeug" for m in r.matches)
    # Python stack also present
    assert DETECTOR_FAMILY_STACK in _families(r)


# ---------------------------------------------------------------------------
# Stage D — infrastructure
# ---------------------------------------------------------------------------

def test_nginx_502() -> None:
    r = detect_errors(NGINX_502, status_code=502, content_type="text/html")
    assert DETECTOR_FAMILY_INFRA in _families(r) or any(
        (m.metadata or {}).get("server") == "nginx" for m in r.matches
    )


# Bare default 404 pages (BUG-02) — gated like Stage G under default config
NGINX_404 = """\
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
"""

APACHE_404 = """\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at example.com Port 443</address>
</body></html>
"""

TOMCAT_404 = """\
<!doctype html><html><head><title>HTTP Status 404 – Not Found</title></head>
<body>
<h1>HTTP Status 404 – Not Found</h1>
<hr class="line" />
<p><b>Type</b> Status Report</p>
<p><b>Message</b> The requested resource is not available.</p>
<p><b>Description</b> The origin server did not find a current representation.</p>
<hr class="line" />
<h3>Apache Tomcat/9.0.65</h3>
</body></html>
"""


def test_nginx_apache_tomcat_404_not_stored_when_generic_disabled() -> None:
    """BUG-02: bare default 404 chrome must not fire as strong under default config."""
    for body, status in (
        (NGINX_404, 404),
        (APACHE_404, 404),
        (TOMCAT_404, 404),
    ):
        r = detect_errors(body, status_code=status, content_type="text/html")
        assert r.matches == [], f"expected no matches for default {status} page"
        assert r.strong_hit is False
        assert r.primary is None


def test_nginx_apache_tomcat_404_kept_when_store_generic_enabled() -> None:
    cfg = merge_config(default_config(), {"store_generic_http_errors": True})
    r_nginx = detect_errors(NGINX_404, status_code=404, content_type="text/html", config=cfg)
    r_apache = detect_errors(APACHE_404, status_code=404, content_type="text/html", config=cfg)
    r_tomcat = detect_errors(TOMCAT_404, status_code=404, content_type="text/html", config=cfg)
    assert any((m.metadata or {}).get("server") == "nginx" for m in r_nginx.matches)
    assert any((m.metadata or {}).get("server") == "apache" for m in r_apache.matches)
    assert any(
        m.detector_id == "fw_tomcat" or (m.metadata or {}).get("framework") == "tomcat"
        for m in r_tomcat.matches
    )


def test_default_page_kept_when_stack_also_present() -> None:
    """Deeper signal (stack) keeps default-page matches as secondary tags."""
    body = JAVA_SQL_STACK + "\n<hr><center>nginx/1.18.0</center>\n"
    r = detect_errors(body, status_code=404, content_type="text/html")
    assert r.strong_hit
    assert DETECTOR_FAMILY_STACK in _families(r)


def test_cloudflare_error_page() -> None:
    r = detect_errors(CLOUDFLARE_1020, status_code=403, content_type="text/html")
    assert any(
        m.family == DETECTOR_FAMILY_INFRA and "cloudflare" in m.detector_id
        for m in r.matches
    )


def test_envoy_upstream_error() -> None:
    body = "upstream connect error or disconnect/reset before headers. reset reason: connection failure"
    r = detect_errors(body, status_code=503)
    assert any(m.detector_id == "infra_envoy" for m in r.matches)


# ---------------------------------------------------------------------------
# Stage E — security
# ---------------------------------------------------------------------------

def test_jwt_error_json() -> None:
    r = detect_errors(JWT_ERROR_JSON, status_code=401, content_type="application/json")
    assert DETECTOR_FAMILY_SECURITY in _families(r)
    assert any(m.detector_id == "sec_jwt" for m in r.matches)
    # Strong security hit → not flooded with generic only
    assert r.strong_hit


def test_csrf_error() -> None:
    r = detect_errors(CSRF_HTML, status_code=403, content_type="text/html")
    assert any(m.detector_id == "sec_csrf" for m in r.matches)


def test_www_authenticate_header() -> None:
    r = detect_errors(
        "",
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="api", error="invalid_token"'},
    )
    # empty body — security header path
    assert any(m.family == DETECTOR_FAMILY_SECURITY for m in r.matches) or r.matches == []
    # With empty body, security detector may still use headers
    r2 = detect_errors(
        "Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )
    assert any(m.family == DETECTOR_FAMILY_SECURITY for m in r2.matches)


# ---------------------------------------------------------------------------
# Stage F — disclosure
# ---------------------------------------------------------------------------

def test_path_host_version_disclosure_on_5xx() -> None:
    r = detect_errors(PATH_LEAK_5XX, status_code=500)
    kinds = {a.kind for a in r.artifacts}
    assert "path" in kinds
    assert "host" in kinds or any(
        a.kind == "host" for a in r.artifacts
    )
    # version OpenJDK
    assert "version" in kinds or DETECTOR_FAMILY_DISCLOSURE in _families(r)
    assert any(a.kind == "path" and "/home/" in a.value for a in r.artifacts)


def test_disclosure_not_forced_on_healthy_2xx() -> None:
    r = detect_errors(HEALTHY_JSON, status_code=200, content_type="application/json")
    # No strong error, not 5xx → no disclosure forced; no generic (store off)
    assert r.matches == []
    assert r.artifacts == []


# ---------------------------------------------------------------------------
# Stage G — generic HTTP (policy)
# ---------------------------------------------------------------------------

def test_generic_400_suppressed_by_default() -> None:
    r = detect_errors(
        JSON_VALIDATION_400,
        status_code=400,
        content_type="application/json",
    )
    # No strong stage → Stage G gated by store_generic_http_errors=false
    assert not any(m.family == DETECTOR_FAMILY_HTTP for m in r.matches)
    assert r.primary is None or r.primary.family != DETECTOR_FAMILY_HTTP


def test_generic_400_when_store_enabled() -> None:
    cfg = merge_config(default_config(), {"store_generic_http_errors": True})
    r = detect_errors(
        JSON_VALIDATION_400,
        status_code=400,
        content_type="application/json",
        config=cfg,
    )
    assert any(m.family == DETECTOR_FAMILY_HTTP for m in r.matches)
    assert r.primary is not None
    assert r.primary.category_hint in (CATEGORY_VALIDATION, CATEGORY_HTTP)


def test_generic_5xx_plain_allowed() -> None:
    r = detect_errors("Internal Server Error", status_code=500, content_type="text/plain")
    assert r.matches
    assert any(m.family == DETECTOR_FAMILY_HTTP for m in r.matches)


def test_problem_json_when_store_enabled() -> None:
    cfg = merge_config(default_config(), {"store_generic_http_errors": True})
    r = detect_errors(
        PROBLEM_JSON,
        status_code=403,
        content_type="application/problem+json",
        config=cfg,
    )
    assert any(m.detector_id == "http_problem_json" for m in r.matches)


# ---------------------------------------------------------------------------
# Orchestrator / primary selection / multi-match
# ---------------------------------------------------------------------------

def test_primary_prefers_stack_over_http() -> None:
    # Body has stack; even with store generic, primary is stack
    cfg = merge_config(default_config(), {"store_generic_http_errors": True})
    r = detect_errors(JAVA_SQL_STACK, status_code=500, config=cfg)
    assert r.primary is not None
    assert r.primary.family == DETECTOR_FAMILY_STACK


def test_pick_primary_ranking() -> None:
    matches = [
        RawErrorMatch(
            detector_id="http_json_error",
            family=DETECTOR_FAMILY_HTTP,
            confidence="WEAK",
            category_hint=CATEGORY_HTTP,
        ),
        RawErrorMatch(
            detector_id="stack_java",
            family=DETECTOR_FAMILY_STACK,
            exception_type="java.lang.NullPointerException",
            confidence=CONFIDENCE_CONFIRMED_PATTERN,
            category_hint=CATEGORY_STACK_TRACE,
            language=LANG_JAVA,
        ),
        RawErrorMatch(
            detector_id="db_sqlstate",
            family=DETECTOR_FAMILY_DATABASE,
            exception_type="SQLSTATE:42000",
            confidence="HIGH",
            category_hint=CATEGORY_DATABASE,
        ),
    ]
    primary = pick_primary_match(matches)
    assert primary is not None
    assert primary.detector_id == "stack_java"


def test_stack_on_200_json() -> None:
    """Success criterion: stack on HTTP 200 still detected."""
    body = (
        '{"error":"internal","trace":"'
        "Traceback (most recent call last):\\n"
        '  File \\"/app/x.py\\", line 1, in <module>\\n'
        'ValueError: boom'
        '"}'
    )
    # Also plain body form
    plain = (
        "Traceback (most recent call last):\n"
        '  File "/app/x.py", line 1, in <module>\n'
        "ValueError: boom\n"
    )
    r = detect_errors(plain, status_code=200, content_type="application/json")
    assert r.strong_hit
    assert r.primary is not None
    assert r.primary.language == LANG_PYTHON


def test_empty_body_no_crash() -> None:
    r = detect_errors(b"", status_code=500)
    # 5xx empty may yield status-only generic
    assert isinstance(r, ErrorDetectResult)


def test_binary_rejected_by_decode() -> None:
    text = decode_body_text(b"\x00" * 100 + b"\xff\xd8\xff")
    assert text == ""


def test_snippet_bounded() -> None:
    huge = "x" * 50_000
    snip = extract_snippet(huge, 100, 200, max_chars=1000)
    assert len(snip) <= 1100


def test_detectors_fired_list() -> None:
    r = detect_errors(JAVA_SQL_STACK, status_code=500)
    assert r.detectors_fired
    assert "stack_java" in r.detectors_fired or any("java" in d for d in r.detectors_fired)


def test_to_dict_debug() -> None:
    r = detect_errors(PYTHON_TRACE, status_code=500)
    d = r.to_dict()
    assert d["strong_hit"] is True
    assert d["match_count"] >= 1
    assert d["primary_family"] == DETECTOR_FAMILY_STACK


@pytest.mark.parametrize(
    "body,status,lang",
    [
        (JAVA_SQL_STACK, 500, LANG_JAVA),
        (PYTHON_TRACE, 500, LANG_PYTHON),
        (DOTNET_STACK, 500, LANG_CSHARP),
        (NODE_STACK, 500, LANG_JAVASCRIPT),
        (GO_PANIC, 500, LANG_GO),
    ],
)
def test_language_param_matrix(body: str, status: int, lang: str) -> None:
    r = detect_errors(body, status_code=status)
    assert any(m.language == lang for m in r.matches), f"expected {lang} in {[m.language for m in r.matches]}"


# ---------------------------------------------------------------------------
# BUG-05 / BUG-15 — false-positive tightening
# ---------------------------------------------------------------------------

def test_laravel_marketing_copy_not_whoops() -> None:
    """BUG-15: bare 'Laravel Framework' is not a Whoops error page."""
    body = "Laravel Framework documentation — build amazing apps."
    r = detect_errors(body, status_code=200, content_type="text/html")
    assert not any(m.detector_id == "fw_laravel_whoops" for m in r.matches)


def test_laravel_whoops_still_detected() -> None:
    body = "Whoops! Something went wrong.\n/vendor/filp/whoops/src/Whoops/Run.php"
    r = detect_errors(body, status_code=500, content_type="text/html")
    assert any(m.detector_id == "fw_laravel_whoops" for m in r.matches)


def test_jwt_docs_text_not_security_hit() -> None:
    """BUG-05: tutorial copy on 200 must not fire sec_jwt HIGH."""
    body = "How to handle invalid token errors in JWT authentication guides."
    r = detect_errors(body, status_code=200, content_type="text/html")
    assert not any(m.detector_id == "sec_jwt" for m in r.matches)


def test_jwt_real_error_still_detected() -> None:
    r = detect_errors(JWT_ERROR_JSON, status_code=401, content_type="application/json")
    assert any(m.detector_id == "sec_jwt" for m in r.matches)


def test_access_denied_without_oauth_vocab_not_oauth() -> None:
    """BUG-05: bare access_denied is not enough for sec_oauth."""
    body = '{"status":"access_denied"}'
    r = detect_errors(body, status_code=403, content_type="application/json")
    assert not any(m.detector_id == "sec_oauth" for m in r.matches)


def test_oauth_access_denied_with_vocab_detected() -> None:
    body = '{"error":"access_denied","error_description":"User denied OAuth consent"}'
    r = detect_errors(body, status_code=400, content_type="application/json")
    assert any(m.detector_id == "sec_oauth" for m in r.matches)


def test_cdnjs_cloudflare_not_infra_hit() -> None:
    """BUG-05: CDN asset hostname alone is not a Cloudflare edge error."""
    body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>'
    r = detect_errors(body, status_code=500, content_type="text/html")
    assert not any(
        m.family == DETECTOR_FAMILY_INFRA and "cloudflare" in m.detector_id
        for m in r.matches
    )


def test_amazon_s3_success_copy_not_infra() -> None:
    """BUG-05: success messaging mentioning S3 is not an AWS error page."""
    body = "File uploaded to Amazon S3 successfully."
    r = detect_errors(body, status_code=403, content_type="text/plain")
    assert not any(m.detector_id == "infra_aws" for m in r.matches)


def test_amazon_s3_access_denied_still_detected() -> None:
    body = (
        "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code>"
        "<Message>Access Denied</Message></Error>"
    )
    r = detect_errors(body, status_code=403, content_type="application/xml")
    assert any(m.detector_id == "infra_aws" for m in r.matches)
