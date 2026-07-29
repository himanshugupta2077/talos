"""
Tests for talos.send.normalize Content-Length policy.
"""

from __future__ import annotations

from talos.send.normalize import apply_content_length, strip_content_length


class TestContentLengthNormalizer:
    def test_default_sets_cl_to_body_len(self) -> None:
        headers = {"Content-Type": "text/plain", "Content-Length": "999"}
        body = b"hello world"
        ran = apply_content_length(headers, body, enabled=True)
        assert ran == ["content_length"]
        assert headers["Content-Length"] == str(len(body))
        assert headers["Content-Type"] == "text/plain"

    def test_default_removes_stale_cl_case_insensitive(self) -> None:
        headers = {"content-length": "1", "X-A": "1"}
        body = b"abcd"
        apply_content_length(headers, body, enabled=True)
        # Only one CL key, correct value.
        cl_keys = [k for k in headers if k.lower() == "content-length"]
        assert len(cl_keys) == 1
        assert headers[cl_keys[0]] == "4"

    def test_empty_body_drops_cl(self) -> None:
        headers = {"Content-Length": "10", "Host": "x"}
        ran = apply_content_length(headers, None, enabled=True)
        assert ran == ["content_length"]
        assert not any(k.lower() == "content-length" for k in headers)

    def test_disabled_leaves_headers_untouched(self) -> None:
        headers = {"Content-Length": "1", "X-A": "z"}
        body = b"longerbodynotmatching"
        ran = apply_content_length(headers, body, enabled=False)
        assert ran == []
        assert headers["Content-Length"] == "1"
        assert headers["X-A"] == "z"

    def test_strip_helper(self) -> None:
        headers = {"Content-Length": "3", "Host": "h", "content-length": "9"}
        out = strip_content_length(headers)
        assert "Host" in out
        assert not any(k.lower() == "content-length" for k in out)
