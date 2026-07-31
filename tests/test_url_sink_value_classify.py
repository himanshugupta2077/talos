"""
Tests: talos.url_sink.value_classify

Purpose:
    Table-driven coverage of pure value classification for URL Sink Discovery
    Phase 1: schemes, protocol-relative, IPv4/IPv6, UNC, paths, hostnames,
    host:port, email ignore, and score bands.
"""

from __future__ import annotations

import pytest

from talos.url_sink.value_classify import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    classify_value,
)


# ---------------------------------------------------------------------------
# Absolute URLs / schemes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,scheme",
    [
        ("https://cdn.example.com/x.png", "https"),
        ("http://example.com/", "http"),
        ("ftp://files.example/a", "ftp"),
        ("ftps://secure.example/a", "ftps"),
        ("gopher://g.example/1", "gopher"),
        ("ws://chat.example/socket", "ws"),
        ("wss://chat.example/socket", "wss"),
        ("file:///etc/passwd", "file"),
        ("ldap://dc.example/cn=user", "ldap"),
        ("sftp://files.example/path", "sftp"),
    ],
)
def test_scheme_urls_high_score(value: str, scheme: str) -> None:
    feat = classify_value(value)
    assert feat.possible_url_value is True
    assert feat.possible_protocol is True
    assert scheme in feat.protocols_seen
    assert feat.score >= 90
    assert feat.possible_network_resource is True
    assert f"value_scheme:{scheme}" in feat.evidence
    assert "url" in feat.looks_like


def test_random_name_https_value_is_network_resource() -> None:
    """Success metric: abc=https://… scores high without name context."""
    feat = classify_value("https://cdn.example/x")
    assert feat.score >= 90
    assert feat.possible_network_resource is True


def test_protocol_relative() -> None:
    feat = classify_value("//cdn.example.com/lib.js")
    assert feat.possible_url_value is True
    assert "protocol_relative" in feat.looks_like
    assert feat.score >= 80
    assert feat.possible_network_resource is True


def test_mailto_low_weight() -> None:
    feat = classify_value("mailto:user@example.com")
    assert feat.possible_protocol is True
    assert "mailto" in feat.protocols_seen
    assert feat.score < NETWORK_RESOURCE_SCORE_THRESHOLD
    assert feat.possible_network_resource is False


def test_data_and_blob_low_weight() -> None:
    for value in ("data:text/plain,hello", "blob:https://example.com/uuid"):
        feat = classify_value(value)
        assert feat.score < NETWORK_RESOURCE_SCORE_THRESHOLD
        assert feat.possible_network_resource is False


# ---------------------------------------------------------------------------
# Email ignore
# ---------------------------------------------------------------------------

def test_email_ignored() -> None:
    feat = classify_value("user@example.com")
    assert feat.is_email is True
    assert feat.possible_network_resource is False
    assert feat.score == 0
    assert "email_ignored" in feat.evidence
    assert "email" in feat.looks_like


# ---------------------------------------------------------------------------
# IP literals
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "169.254.1.1",
        "8.8.8.8",
    ],
)
def test_ipv4_literal(value: str) -> None:
    feat = classify_value(value)
    assert feat.possible_ip is True
    assert "ipv4" in feat.looks_like
    assert 70 <= feat.score <= 85
    assert feat.possible_network_resource is True


def test_ipv4_with_port() -> None:
    feat = classify_value("127.0.0.1:8080")
    assert feat.possible_ip is True
    assert feat.possible_network_resource is True


@pytest.mark.parametrize(
    "value",
    [
        "::1",
        "fe80::1",
        "2001:db8::1",
        "[2001:db8::1]",
        "[::1]:443",
    ],
)
def test_ipv6_literal(value: str) -> None:
    feat = classify_value(value)
    assert feat.possible_ip is True
    assert "ipv6" in feat.looks_like
    assert feat.score >= 70
    assert feat.possible_network_resource is True


# ---------------------------------------------------------------------------
# UNC / paths
# ---------------------------------------------------------------------------

def test_unc_backslash() -> None:
    feat = classify_value(r"\\fileserver\share\docs")
    assert feat.possible_unc is True
    assert "unc" in feat.looks_like
    assert 40 <= feat.score <= 65
    assert feat.possible_network_resource is True


def test_windows_path() -> None:
    feat = classify_value(r"C:\Windows\System32\drivers")
    assert feat.possible_path is True
    assert "path" in feat.looks_like
    assert feat.score >= 40


def test_unix_sensitive_path() -> None:
    feat = classify_value("/etc/passwd")
    assert feat.possible_path is True
    assert feat.score >= 45
    assert feat.possible_network_resource is True


def test_path_query_fragment() -> None:
    feat = classify_value("/callback?next=1")
    assert feat.possible_path is True
    assert feat.score >= 40


# ---------------------------------------------------------------------------
# Hostnames
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "cdn.example.com",
        "foo.internal",
        "app.local",
        "api.corp",
    ],
)
def test_hostname_domain(value: str) -> None:
    feat = classify_value(value)
    assert feat.possible_hostname is True
    assert feat.possible_domain is True
    assert 55 <= feat.score <= 75
    assert feat.possible_network_resource is True


def test_localhost() -> None:
    feat = classify_value("localhost")
    assert feat.possible_hostname is True
    assert feat.score >= 55


def test_host_port() -> None:
    feat = classify_value("api.example.com:8443")
    assert feat.possible_hostname or "host_port" in feat.looks_like
    assert feat.score >= 55
    assert feat.possible_network_resource is True


def test_hostname_with_path() -> None:
    feat = classify_value("cdn.example.com/assets/x.js")
    assert feat.possible_hostname is True
    assert feat.possible_network_resource is True


# ---------------------------------------------------------------------------
# Empty / unrelated
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", "   ", "hello", "true", "42"])
def test_unrelated_low_or_zero(value) -> None:
    feat = classify_value(value)
    assert feat.score < NETWORK_RESOURCE_SCORE_THRESHOLD
    assert feat.possible_network_resource is False


def test_empty_features_defaults() -> None:
    feat = classify_value("")
    d = feat.to_dict()
    assert d["score"] == 0
    assert d["protocols_seen"] == []
    assert d["possible_network_resource"] is False


def test_url_enriches_hostname_flags() -> None:
    feat = classify_value("https://192.168.0.1/admin")
    assert feat.possible_url_value is True
    assert feat.possible_ip is True
    assert feat.score >= 90


# ---------------------------------------------------------------------------
# Filename vs hostname (QA regression)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "report.pdf",
        "photo.png",
        "script.js",
        "style.css",
        "data.json",
        "index.html",
        "archive.zip",
        "jquery.min.js",
        "bundle.min.css",
    ],
)
def test_filenames_are_not_hostnames(value: str) -> None:
    """Common basenames must not score as domains (TLD/extension collision)."""
    feat = classify_value(value)
    assert feat.possible_hostname is False
    assert feat.possible_domain is False
    assert feat.possible_network_resource is False
    assert feat.score < NETWORK_RESOURCE_SCORE_THRESHOLD


def test_real_hostname_still_detected() -> None:
    feat = classify_value("cdn.example.com")
    assert feat.possible_hostname is True
    assert feat.possible_network_resource is True
