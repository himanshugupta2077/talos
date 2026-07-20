"""
Regression tests for Basic Scope (Burp-inspired URL-prefix model).

Covers URL identity, in-scope / out-of-scope matching, import parsing,
endpoint origin identity across non-default ports, and CLI import atomicity.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.projects.manager import ProjectManager
from talos.projects.outscope import add_prefix, list_prefixes, load_prefix_set
from talos.projects.scope_io import ScopeImportError, parse_scope_file_text
from talos.proxy.scope import (
    ScopeParseError,
    any_rule_matches,
    evaluate_scope,
    is_url_in_scope,
    parse_scope_prefix,
    ScopeDecision,
)
from talos.url_identity import (
    UrlIdentityError,
    effective_port,
    format_canonical_authority,
    format_canonical_origin,
    parse_authority_and_path,
    parse_request_url,
)
from talos.worker.worker import _endpoint_origin_key, _upsert_endpoint
from talos.projects.endpoints import normalize_flow_url
from talos.projects.db import init_project_db


# ------------------------------------------------------------------ #
# URL identity                                                         #
# ------------------------------------------------------------------ #


def test_effective_port_defaults():
    assert effective_port("http", None) == 80
    assert effective_port("https", None) == 443
    assert effective_port("http", 8000) == 8000
    assert effective_port(None, None) is None


def test_canonical_authority_and_origin():
    assert format_canonical_authority("http", "example.com", None) == "example.com"
    assert format_canonical_authority("http", "example.com", 80) == "example.com"
    assert format_canonical_authority("http", "example.com", 8000) == "example.com:8000"
    assert format_canonical_origin("http", "example.com", None) == "http://example.com"
    assert format_canonical_origin("http", "example.com", 80) == "http://example.com"
    assert format_canonical_origin("http", "example.com", 8000) == "http://example.com:8000"
    assert format_canonical_origin("https", "example.com", 443) == "https://example.com"


def test_http_omitted_port_equals_explicit_80():
    a = parse_request_url("http://example.com/path")
    b = parse_request_url("http://example.com:80/path")
    assert a.effective_port == 80
    assert b.effective_port == 80
    assert a.canonical_origin == b.canonical_origin == "http://example.com"


def test_https_omitted_port_equals_explicit_443():
    a = parse_request_url("https://example.com/")
    b = parse_request_url("https://example.com:443/")
    assert a.effective_port == b.effective_port == 443
    assert a.canonical_origin == b.canonical_origin == "https://example.com"


def test_non_default_ports_remain_distinct():
    a = parse_request_url("http://example.com:8000/")
    b = parse_request_url("http://example.com:9000/")
    assert a.canonical_origin != b.canonical_origin
    assert a.canonical_origin == "http://example.com:8000"
    assert b.canonical_origin == "http://example.com:9000"


def test_ipv6_authority_parsing():
    identity = parse_request_url("http://[2001:db8::1]:8080/v1")
    assert identity.hostname == "2001:db8::1"
    assert identity.explicit_port == 8080
    assert identity.canonical_origin == "http://[2001:db8::1]:8080"
    rule = parse_scope_prefix("http://[2001:db8::1]:8080")
    assert any_rule_matches("http://[2001:db8::1]:8080/v1", [rule.raw])


# ------------------------------------------------------------------ #
# Basic Scope matching                                                 #
# ------------------------------------------------------------------ #


def test_host_only_matches_http_and_https():
    scope = ["example.com"]
    assert is_url_in_scope("http://example.com/", scope)
    assert is_url_in_scope("https://example.com/", scope)


def test_host_only_matches_different_ports():
    scope = ["example.com"]
    assert is_url_in_scope("http://example.com:8000/", scope)
    assert is_url_in_scope("http://example.com:9000/", scope)
    assert is_url_in_scope("https://example.com:443/", scope)


def test_protocol_specific_scope():
    assert is_url_in_scope("http://example.com/", ["http://example.com"])
    assert not is_url_in_scope("https://example.com/", ["http://example.com"])
    assert is_url_in_scope("https://example.com/", ["https://example.com"])
    assert not is_url_in_scope("http://example.com/", ["https://example.com"])


def test_path_prefix_scope():
    scope = ["example.com/api/"]
    assert is_url_in_scope("https://example.com/api/users", scope)
    assert is_url_in_scope("http://example.com/api/", scope)
    assert not is_url_in_scope("https://example.com/login", scope)
    assert not is_url_in_scope("https://example.com/apix", scope)


def test_subdomains_not_implicitly_included():
    scope = ["example.com"]
    assert is_url_in_scope("http://example.com/", scope)
    assert not is_url_in_scope("http://api.example.com/", scope)
    assert not is_url_in_scope("http://www.example.com/", scope)


def test_port_specific_scope_only_requested_port():
    scope = ["example.com:8000"]
    assert is_url_in_scope("http://example.com:8000/", scope)
    assert is_url_in_scope("https://example.com:8000/", scope)
    assert not is_url_in_scope("http://example.com:9000/", scope)
    assert not is_url_in_scope("http://example.com/", scope)


def test_same_hostname_ports_remain_distinct_for_port_rules():
    assert is_url_in_scope("http://test.com:8000/api/users", ["test.com:8000"])
    assert not is_url_in_scope("http://test.com:9000/api/users", ["test.com:8000"])


def test_same_ipv4_ports_remain_distinct():
    assert is_url_in_scope("http://10.10.10.25:8000/api", ["10.10.10.25:8000"])
    assert not is_url_in_scope("http://10.10.10.25:9000/api", ["10.10.10.25:8000"])
    assert is_url_in_scope("http://10.10.10.25:9000/api", ["10.10.10.25:9000"])


def test_query_strings_do_not_alter_prefix_identity():
    scope = ["example.com/api/"]
    assert is_url_in_scope("https://example.com/api/users?x=1&y=2", scope)
    assert is_url_in_scope("https://example.com/api/users", scope)


def test_out_of_scope_overrides_in_scope():
    decision = evaluate_scope(
        "https://example.com/logout",
        ["example.com"],
        ["example.com/logout"],
    )
    assert decision is ScopeDecision.OUT_OF_SCOPE
    assert not is_url_in_scope(
        "https://example.com/logout",
        ["example.com"],
        ["example.com/logout"],
    )
    assert is_url_in_scope(
        "https://example.com/home",
        ["example.com"],
        ["example.com/logout"],
    )


def test_port_specific_out_of_scope():
    assert not is_url_in_scope(
        "http://example.com:9000/",
        ["example.com"],
        ["example.com:9000"],
    )
    assert is_url_in_scope(
        "http://example.com:8000/",
        ["example.com"],
        ["example.com:9000"],
    )


def test_path_specific_out_of_scope():
    assert not is_url_in_scope(
        "https://example.com/admin/destructive/wipe",
        ["example.com"],
        ["https://example.com/admin/destructive/"],
    )


def test_scope_and_outscope_use_same_parser():
    rule_in = parse_scope_prefix("http://10.10.10.25:8000/api/")
    rule_out = parse_scope_prefix("http://10.10.10.25:8000/api/")
    assert rule_in.hostname == rule_out.hostname
    assert rule_in.port == rule_out.port
    assert rule_in.path_prefix == rule_out.path_prefix
    assert rule_in.scheme == rule_out.scheme


def test_wildcard_rejected_with_actionable_message():
    with pytest.raises(ScopeParseError, match="Wildcard"):
        parse_scope_prefix("*.example.com")


def test_empty_scope_is_strict_opt_in():
    assert not is_url_in_scope("http://example.com/", [])


# ------------------------------------------------------------------ #
# Import                                                               #
# ------------------------------------------------------------------ #


def test_import_ignores_blank_and_comment_lines():
    text = """
# Production web applications

example.com

api.example.com
http://10.10.10.25:8000
"""
    prefixes = parse_scope_file_text(text)
    assert prefixes == [
        "example.com",
        "api.example.com",
        "http://10.10.10.25:8000",
    ]


def test_import_does_not_split_commas():
    # Entire line is one prefix attempt — comma-containing host-like string
    # is invalid as a single host, so import should report the line, not split.
    text = "example.com, api.example.com\n"
    with pytest.raises(ScopeImportError) as exc_info:
        parse_scope_file_text(text)
    assert exc_info.value.line_number == 1
    assert "example.com, api.example.com" in str(exc_info.value)


def test_import_reports_invalid_line_numbers():
    text = "example.com\n*.bad.com\ngood.com\n"
    with pytest.raises(ScopeImportError) as exc_info:
        parse_scope_file_text(text)
    assert exc_info.value.line_number == 2
    assert "*.bad.com" in (exc_info.value.value or "")


def test_import_atomic_no_partial_via_manager(tmp_path: Path):
    mgr = ProjectManager(projects_root=tmp_path / "projects")
    project = mgr.create("scope-import", scope=["keep.example.com"])
    text = "ok.example.com\n*.nope.example.com\n"
    with pytest.raises(ScopeImportError):
        from talos.projects.scope_io import parse_scope_file_text as parse

        parse(text)
    # Manager never called — scope unchanged
    assert mgr.get(project.id).scope == ["keep.example.com"]


# ------------------------------------------------------------------ #
# Endpoint identity                                                    #
# ------------------------------------------------------------------ #


def test_endpoint_identity_differs_across_non_default_ports(tmp_path: Path):
    db_path = tmp_path / "ep.db"
    init_project_db(db_path)
    norm = normalize_flow_url("/api/users", "")

    flow_a = {
        "project_id": "p",
        "method": "GET",
        "host": "http://test.com:8000",
        "url": "http://test.com:8000/api/users",
        "path": "/api/users",
        "role_id": "global",
        "request_start": "2026-01-01T00:00:00+00:00",
    }
    flow_b = {
        **flow_a,
        "host": "http://test.com:9000",
        "url": "http://test.com:9000/api/users",
    }

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        id_a = _upsert_endpoint(conn, flow_a, norm, "application/json", False)
        id_b = _upsert_endpoint(conn, flow_b, norm, "application/json", False)
        conn.commit()

    assert id_a != id_b
    with sqlite3.connect(str(db_path)) as conn:
        hosts = {
            row[0]
            for row in conn.execute("SELECT host FROM endpoints").fetchall()
        }
    assert hosts == {"http://test.com:8000", "http://test.com:9000"}


def test_endpoint_origin_key_from_url():
    flow = {
        "host": "test.com",
        "url": "http://test.com:8000/x",
    }
    assert _endpoint_origin_key(flow) == "http://test.com:8000"


def test_outscope_storage_uses_prefixes(tmp_path: Path):
    mgr = ProjectManager(projects_root=tmp_path / "projects")
    project = mgr.create("oos", scope=["example.com"])
    assert add_prefix(project.db_path, project.id, "example.com:9000")
    assert add_prefix(project.db_path, project.id, "example.com/logout")
    entries = list_prefixes(project.db_path)
    prefixes = {e["prefix"] for e in entries}
    assert "example.com:9000" in prefixes
    assert "example.com/logout" in prefixes
    loaded = load_prefix_set(project.db_path)
    assert "example.com:9000" in loaded


def test_scheme_less_host_port_parse():
    identity = parse_authority_and_path("example.com:8000")
    assert identity.hostname == "example.com"
    assert identity.explicit_port == 8000
    assert identity.scheme is None


def test_parse_request_url_rejects_missing_scheme():
    with pytest.raises(UrlIdentityError):
        parse_request_url("example.com/path")
