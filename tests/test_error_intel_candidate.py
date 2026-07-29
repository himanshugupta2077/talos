"""
Golden tests for talos.error_intel.candidate.is_error_candidate (Phase 1).

Status class, body markers, error headers, media rejects, 2xx stack traces,
empty body edge cases.  No FlowWorker wiring / DB.
"""

from __future__ import annotations

import pytest

from talos.error_intel.candidate import (
    is_error_candidate,
    is_error_candidate_from_flow,
    status_bucket,
)
from talos.error_intel.constants import (
    STATUS_BUCKET_2XX_ERROR_BODY,
    STATUS_BUCKET_4XX,
    STATUS_BUCKET_5XX,
    STATUS_BUCKET_NONE,
)
from talos.error_intel.observe import observe_error
from talos.error_intel.config import default_config, merge_config

# Minimal real magic prefixes (not full files)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
PDF = b"%PDF-1.4\n%" + b"\x00" * 16
WASM = b"\x00asm" + b"\x01\x00\x00\x00"
EMPTY = b""

JAVA_STACK = b"""\
HTTP Status 500 - Internal Server Error
java.sql.SQLSyntaxErrorException: You have an error in your SQL syntax
\tat com.example.UserService.load(UserService.java:142)
Caused by: java.sql.SQLException: ...
"""

PYTHON_TRACE = b"""\
Traceback (most recent call last):
  File "/app/views.py", line 42, in handler
    raise ValueError("bad")
ValueError: bad
"""

JSON_ERROR_200 = b'{"error": "invalid_token", "message": "JWT decode failed"}'
JSON_OK = b'{"ok": true, "data": {"id": 1}}\n'
HTML_APP = b"<!DOCTYPE html><html><body><div id=root></div></body></html>"
HTML_WHITELABEL = b"<h1>Whitelabel Error Page</h1><div>There was an unexpected error</div>"
INVALID_EMAIL = b'{"message": "Invalid email"}'
NGINX_404 = b"<html><head><title>404 Not Found</title></head><body>nginx</body></html>"


# ---------------------------------------------------------------------------
# Status class 4xx/5xx
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 500, 502, 503])
def test_error_status_with_body_is_candidate(status: int) -> None:
    assert is_error_candidate(
        status_code=status,
        content_type="application/json",
        body=INVALID_EMAIL,
    )


def test_500_plain_text_no_source_ct() -> None:
    """Unlike passive, plain text 500 does not need source-like CT."""
    assert is_error_candidate(
        status_code=500,
        content_type="text/plain",
        body=b"Internal Server Error\n",
    )


def test_500_json_is_candidate() -> None:
    assert is_error_candidate(
        status_code=500,
        content_type="application/json",
        body=b'{"error":"boom"}',
    )


def test_404_html_is_candidate_gate_not_store_policy() -> None:
    """Gate accepts; store_generic_http_errors is a later store decision."""
    assert is_error_candidate(
        status_code=404,
        content_type="text/html",
        body=NGINX_404,
    )


def test_400_invalid_email_is_candidate() -> None:
    assert is_error_candidate(
        status_code=400,
        content_type="application/json",
        body=INVALID_EMAIL,
    )


# ---------------------------------------------------------------------------
# 2xx with error-shaped body
# ---------------------------------------------------------------------------

def test_200_json_error_keys() -> None:
    assert is_error_candidate(
        status_code=200,
        content_type="application/json",
        body=JSON_ERROR_200,
    )


def test_200_java_stack_in_json() -> None:
    body = b'{"status":200,"exception":"java.lang.NullPointerException","trace":"at com.x.Y"}'
    assert is_error_candidate(
        status_code=200,
        content_type="application/json",
        body=body,
    )


def test_200_python_traceback() -> None:
    assert is_error_candidate(
        status_code=200,
        content_type="text/html",
        body=PYTHON_TRACE,
    )


def test_200_ok_json_not_candidate() -> None:
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            body=JSON_OK,
        )
        is False
    )


def test_200_json_with_message_only_not_candidate() -> None:
    """Bare 'message' is common on success payloads — not enough alone."""
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            body=b'{"ok": true, "message": "welcome"}',
        )
        is False
    )


def test_200_html_app_shell_not_candidate() -> None:
    assert (
        is_error_candidate(
            status_code=200,
            content_type="text/html",
            body=HTML_APP,
        )
        is False
    )


def test_none_status_with_stack_is_candidate() -> None:
    assert is_error_candidate(
        status_code=None,
        content_type="text/plain",
        body=JAVA_STACK,
    )


# ---------------------------------------------------------------------------
# Framework chrome
# ---------------------------------------------------------------------------

def test_whitelabel_error_page() -> None:
    assert is_error_candidate(
        status_code=200,
        content_type="text/html",
        body=HTML_WHITELABEL,
    )


def test_werkzeug_debugger() -> None:
    body = b"<title>Werkzeug Debugger</title><div class=traceback>"
    assert is_error_candidate(status_code=500, content_type="text/html", body=body)


# ---------------------------------------------------------------------------
# Error headers
# ---------------------------------------------------------------------------

def test_x_exception_header_empty_body() -> None:
    assert is_error_candidate(
        status_code=200,
        content_type="text/plain",
        headers={"X-Exception": "NullPointerException"},
        body=EMPTY,
    )


def test_x_exception_header_no_body() -> None:
    assert is_error_candidate(
        status_code=500,
        headers={"x-exception": "boom"},
        body=None,
    )


def test_normal_headers_no_signal() -> None:
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            headers={"Content-Type": "application/json", "X-Request-Id": "abc"},
            body=JSON_OK,
        )
        is False
    )


def test_raw_header_string() -> None:
    raw = "HTTP/1.1 500 OK\r\nX-Error-Message: fail\r\nContent-Type: text/plain\r\n"
    assert is_error_candidate(
        status_code=200,
        headers=raw,
        body=EMPTY,
    )


# ---------------------------------------------------------------------------
# Hard rejects: empty, binary, media
# ---------------------------------------------------------------------------

def test_empty_body_success_no_headers() -> None:
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            body=EMPTY,
        )
        is False
    )


def test_empty_body_500_no_headers() -> None:
    """BUG-03: empty BLOB (b"") is treated like deferred body for error status."""
    assert is_error_candidate(
        status_code=500,
        content_type="text/html",
        body=EMPTY,
    )


def test_empty_body_502_matches_none_body() -> None:
    """BUG-03: b'' and None must not disagree on 5xx gate."""
    kwargs = dict(status_code=502, content_type="text/plain", path="/api/x")
    assert is_error_candidate(body=b"", **kwargs) is True
    assert is_error_candidate(body=None, **kwargs) is True
    assert is_error_candidate(body=b"", status_code=200, content_type="text/plain") is False


@pytest.mark.parametrize(
    "content_type",
    [
        "image/png",
        "image/jpeg",
        "video/mp4",
        "audio/mpeg",
        "font/woff2",
        "application/pdf",
        "application/zip",
        "application/wasm",
        "multipart/form-data",
    ],
)
def test_reject_media_content_types(content_type: str) -> None:
    assert (
        is_error_candidate(
            status_code=500,
            content_type=content_type,
            body=JAVA_STACK,
        )
        is False
    )


@pytest.mark.parametrize(
    "label,body",
    [
        ("png", PNG),
        ("jpeg", JPEG),
        ("pdf", PDF),
        ("wasm", WASM),
    ],
)
def test_reject_magic_binary_despite_text_ct(label: str, body: bytes) -> None:
    assert (
        is_error_candidate(
            status_code=500,
            content_type="text/plain",
            body=body,
            path=f"/file.{label}",
        )
        is False
    )


# ---------------------------------------------------------------------------
# Body deferred (None) — cheap enqueue path
# ---------------------------------------------------------------------------

def test_body_none_4xx_enqueues() -> None:
    assert is_error_candidate(
        status_code=404,
        content_type="text/html",
        body=None,
        path="/api/users",
    )


def test_body_none_200_without_headers_rejects() -> None:
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            body=None,
            path="/api/ok",
        )
        is False
    )


def test_body_none_png_path_4xx_rejects() -> None:
    assert (
        is_error_candidate(
            status_code=404,
            content_type=None,
            body=None,
            path="/static/logo.png",
        )
        is False
    )


# ---------------------------------------------------------------------------
# from_flow + status_bucket + observe_error stub
# ---------------------------------------------------------------------------

def test_from_flow_string_status() -> None:
    assert is_error_candidate_from_flow(
        status_code="500",
        content_type="application/json",
        body=b'{"error":"x"}',
    )
    assert (
        is_error_candidate_from_flow(
            status_code="200",
            content_type="application/json",
            body=JSON_OK,
        )
        is False
    )


def test_status_bucket_mapping() -> None:
    assert status_bucket(500) == STATUS_BUCKET_5XX
    assert status_bucket(404) == STATUS_BUCKET_4XX
    assert status_bucket(200, body_error_shaped=True) == STATUS_BUCKET_2XX_ERROR_BODY
    assert status_bucket(None) == STATUS_BUCKET_NONE


def test_observe_error_without_db_returns_empty() -> None:
    """Gate may pass but without db_path nothing is stored (returns [])."""
    out = observe_error(
        project_id="p1",
        flow_id="f1",
        response_status=500,
        response_body=JAVA_STACK,
        content_type="text/plain",
        attack_type="proxy",
    )
    assert out == []


def test_observe_error_disabled() -> None:
    cfg = merge_config(default_config(), {"enabled": False})
    out = observe_error(
        project_id="p1",
        flow_id="f1",
        response_status=500,
        response_body=JAVA_STACK,
        config=cfg,
    )
    assert out == []


def test_observe_error_gate_reject() -> None:
    out = observe_error(
        project_id="p1",
        flow_id="f1",
        response_status=200,
        response_body=JSON_OK,
        content_type="application/json",
    )
    assert out == []


def test_observe_error_missing_ids() -> None:
    assert observe_error(project_id="", flow_id="f1") == []
    assert observe_error(project_id="p1", flow_id="") == []


def test_config_defaults() -> None:
    cfg = default_config()
    assert cfg.enabled is True
    assert cfg.store_generic_http_errors is False
    assert "x-exception" in cfg.error_header_names


def test_error_null_json_not_candidate_on_2xx() -> None:
    """BUG-14: {\"error\":null} must not enqueue on healthy 2xx."""
    assert (
        is_error_candidate(
            status_code=200,
            content_type="application/json",
            body=b'{"error":null,"data":{}}',
        )
        is False
    )


def test_laravel_word_alone_not_candidate_on_2xx() -> None:
    """BUG-14: bare product word on 200 is gate noise."""
    assert (
        is_error_candidate(
            status_code=200,
            content_type="text/html",
            body=b"Built with Laravel and love.",
        )
        is False
    )


def test_whitelabel_still_candidate_on_2xx() -> None:
    assert is_error_candidate(
        status_code=200,
        content_type="text/html",
        body=HTML_WHITELABEL,
    )
