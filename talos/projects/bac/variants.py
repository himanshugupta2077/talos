"""
Module: talos.projects.bac.variants

Purpose:
    Static mutation variant definitions for each BAC attack type.
    Each variant is a plain dict describing the mutation to apply.
    The BAC engine reads these dicts at execution time to construct
    the modified HTTP request.

    Variant dict always contains:
        name            (str) — unique identifier used as job meta['variant'].
        description     (str) — human-readable label for display/logging.
        mutation_family (str) — high-level family name (e.g. 'method-fuzz').
        mutation        (str) — specific mutation label (e.g. 'GET→POST').
    Additional keys are attack-type-specific (documented per section).

Dependencies: None
Side effects: None (pure data definitions).
"""

from typing import Any


# ------------------------------------------------------------------ #
# Session Swap                                                         #
# ------------------------------------------------------------------ #
# Replays the target-role flow with the attacker role's session token.
# No additional mutation beyond the token injection.
# Extra variants inject null/whitespace auth values to probe middleware
# that fails to validate absent-but-present credential values.

SESSION_SWAP_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "session_swap",
        "description": "Replace target-role session with attacker-role session token",
        "mutation_family": "session-swap",
        "mutation": "session_swap",
        "auth_override": None,  # standard session swap — inject attacker credentials
    },
    {
        "name": "authorization_null",
        "description": "Set Authorization header/cookies to literal 'null' value",
        "mutation_family": "session-swap",
        "mutation": "authorization_null",
        "auth_override": "null",  # engine sets auth fields to string 'null'
    },
    {
        "name": "authorization_whitespace",
        "description": "Set Authorization header/cookies to whitespace string",
        "mutation_family": "session-swap",
        "mutation": "authorization_whitespace",
        "auth_override": " ",  # engine sets auth fields to single space
    },
]

# ------------------------------------------------------------------ #
# HTTP Method Manipulation                                             #
# ------------------------------------------------------------------ #
# Direct verb changes and X-HTTP-Method-Override header injection.
# Additional keys:
#   from_method     (str|None)  — original method this variant targets; None = any.
#   to_method       (str|None)  — replacement method; None for override-only variants.
#   override_header (bool)      — True when injecting X-HTTP-Method-Override.
#   override_value  (str)       — value for the override header (only when override_header=True).

_METHOD_TRANSITIONS: list[tuple[str, str]] = [
    ("GET",  "POST"),
    ("GET",  "PUT"),
    ("GET",  "HEAD"),
    ("POST", "GET"),
    ("POST", "PUT"),
    ("POST", "PATCH"),
    ("PUT",  "PATCH"),
]

METHOD_FUZZ_VARIANTS: list[dict[str, Any]] = [
    {
        "name": f"{src}_to_{dst}",
        "description": f"Change HTTP method from {src} to {dst}",
        "mutation_family": "method-fuzz",
        "mutation": f"{src}→{dst}",
        "from_method": src,
        "to_method": dst,
        "override_header": False,
    }
    for src, dst in _METHOD_TRANSITIONS
] + [
    {
        "name": f"override_{verb}",
        "description": f"Inject X-HTTP-Method-Override: {verb} (method unchanged)",
        "mutation_family": "method-fuzz",
        "mutation": f"X-HTTP-Method-Override:{verb}",
        "from_method": None,
        "to_method": None,
        "override_header": True,
        "override_value": verb,
    }
    for verb in ("PUT", "DELETE")
]

# ------------------------------------------------------------------ #
# Content-Type Confusion                                               #
# ------------------------------------------------------------------ #
# Additional keys:
#   from_ct (str|None) — source content-type substring to match; None = apply to all.
#   to_ct   (str)      — replacement content-type value.

CONTENT_TYPE_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "json_to_form",
        "description": "Change Content-Type: application/json → application/x-www-form-urlencoded",
        "mutation_family": "content-type",
        "mutation": "json→form",
        "from_ct": "application/json",
        "to_ct": "application/x-www-form-urlencoded",
    },
    {
        "name": "json_to_multipart",
        "description": "Change Content-Type: application/json → multipart/form-data",
        "mutation_family": "content-type",
        "mutation": "json→multipart",
        "from_ct": "application/json",
        "to_ct": "multipart/form-data",
    },
    {
        "name": "form_to_json",
        "description": "Change Content-Type: application/x-www-form-urlencoded → application/json",
        "mutation_family": "content-type",
        "mutation": "form→json",
        "from_ct": "application/x-www-form-urlencoded",
        "to_ct": "application/json",
    },
    {
        "name": "xml_to_json",
        "description": "Change Content-Type: application/xml → application/json",
        "mutation_family": "content-type",
        "mutation": "xml→json",
        "from_ct": "application/xml",
        "to_ct": "application/json",
    },
    {
        "name": "invalid_content_type",
        "description": "Set Content-Type: application/octet-stream (invalid for typical APIs)",
        "mutation_family": "content-type",
        "mutation": "→octet-stream",
        "from_ct": None,
        "to_ct": "application/octet-stream",
    },
]

# ------------------------------------------------------------------ #
# URL Manipulation                                                      #
# ------------------------------------------------------------------ #
# Additional keys:
#   transform (str) — transformation identifier consumed by engine._mutate_url.
#
# Transforms:
#   trailing_slash   — /admin → /admin/
#   double_slash     — /admin/users → /admin//users
#   dot_segment      — /admin/users → /admin/./users
#   dot_segment_back — /admin/users → /admin/../admin/users
#   encoded_path     — first char of first segment percent-encoded (%61dmin)
#   mixed_case       — first segment capitalised (/Admin)

URL_FUZZ_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "trailing_slash",
        "description": "Append trailing slash to path: /admin → /admin/",
        "mutation_family": "url-fuzz",
        "mutation": "trailing_slash",
        "transform": "trailing_slash",
    },
    {
        "name": "double_slash",
        "description": "Insert double slash after first segment: /admin/users → /admin//users",
        "mutation_family": "url-fuzz",
        "mutation": "double_slash",
        "transform": "double_slash",
    },
    {
        "name": "dot_segment",
        "description": "Insert dot segment: /admin/users → /admin/./users",
        "mutation_family": "url-fuzz",
        "mutation": "dot_segment",
        "transform": "dot_segment",
    },
    {
        "name": "dot_segment_back",
        "description": "Back-traversal dot segment: /admin/users → /admin/../admin/users",
        "mutation_family": "url-fuzz",
        "mutation": "dot_segment_back",
        "transform": "dot_segment_back",
    },
    {
        "name": "encoded_path",
        "description": "Percent-encode first char of path: /admin → /%61dmin",
        "mutation_family": "url-fuzz",
        "mutation": "encoded_path",
        "transform": "encoded_path",
    },
    {
        "name": "mixed_case",
        "description": "Capitalise first segment: /admin → /Admin",
        "mutation_family": "url-fuzz",
        "mutation": "mixed_case",
        "transform": "mixed_case",
    },
]

# ------------------------------------------------------------------ #
# Header Manipulation                                                  #
# ------------------------------------------------------------------ #
# Additional keys:
#   header       (str) — header name to inject.
#   value_source (str) — 'path' (use request path) or 'static' (use value field).
#   value        (str) — static value (only when value_source='static').

HEADER_INJECT_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "x_original_url",
        "description": "Inject X-Original-URL: <request-path>",
        "mutation_family": "header-inject",
        "mutation": "X-Original-URL",
        "header": "X-Original-URL",
        "value_source": "path",
    },
    {
        "name": "x_rewrite_url",
        "description": "Inject X-Rewrite-URL: <request-path>",
        "mutation_family": "header-inject",
        "mutation": "X-Rewrite-URL",
        "header": "X-Rewrite-URL",
        "value_source": "path",
    },
    {
        "name": "x_forwarded_for",
        "description": "Inject X-Forwarded-For: 127.0.0.1",
        "mutation_family": "header-inject",
        "mutation": "X-Forwarded-For",
        "header": "X-Forwarded-For",
        "value_source": "static",
        "value": "127.0.0.1",
    },
    {
        "name": "x_forwarded_host",
        "description": "Inject X-Forwarded-Host: localhost",
        "mutation_family": "header-inject",
        "mutation": "X-Forwarded-Host",
        "header": "X-Forwarded-Host",
        "value_source": "static",
        "value": "localhost",
    },
    {
        "name": "x_forwarded_proto",
        "description": "Inject X-Forwarded-Proto: https",
        "mutation_family": "header-inject",
        "mutation": "X-Forwarded-Proto",
        "header": "X-Forwarded-Proto",
        "value_source": "static",
        "value": "https",
    },
    {
        "name": "x_real_ip",
        "description": "Inject X-Real-IP: 127.0.0.1",
        "mutation_family": "header-inject",
        "mutation": "X-Real-IP",
        "header": "X-Real-IP",
        "value_source": "static",
        "value": "127.0.0.1",
    },
]

# ------------------------------------------------------------------ #
# Host Header                                                          #
# ------------------------------------------------------------------ #
# Additional keys:
#   host (str) — replacement Host header value.

HOST_FUZZ_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "host_example_com",
        "description": "Change Host header to example.com",
        "mutation_family": "host-fuzz",
        "mutation": "example.com",
        "host": "example.com",
    },
    {
        "name": "host_localhost",
        "description": "Change Host header to localhost",
        "mutation_family": "host-fuzz",
        "mutation": "localhost",
        "host": "localhost",
    },
    {
        "name": "host_127_0_0_1",
        "description": "Change Host header to 127.0.0.1",
        "mutation_family": "host-fuzz",
        "mutation": "127.0.0.1",
        "host": "127.0.0.1",
    },
]

# ------------------------------------------------------------------ #
# Role Parameter Injection                                            #
# ------------------------------------------------------------------ #
# Additional keys:
#   inject_type (str)       — 'query_param' | 'query_param_duplicate' | 'header'.
#   key         (str)       — parameter/header name.
#   value       (str)       — value (single injection).
#   values      (list[str]) — values list (duplicate injection only).

ROLE_INJECT_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "param_isAdmin",
        "description": "Inject isAdmin=true as query parameter",
        "mutation_family": "role-inject",
        "mutation": "isAdmin=true",
        "inject_type": "query_param",
        "key": "isAdmin",
        "value": "true",
    },
    {
        "name": "param_role_admin",
        "description": "Inject role=admin as query parameter",
        "mutation_family": "role-inject",
        "mutation": "role=admin",
        "inject_type": "query_param",
        "key": "role",
        "value": "admin",
    },
    {
        "name": "param_admin_1",
        "description": "Inject admin=1 as query parameter",
        "mutation_family": "role-inject",
        "mutation": "admin=1",
        "inject_type": "query_param",
        "key": "admin",
        "value": "1",
    },
    {
        "name": "param_access_level",
        "description": "Inject access_level=999 as query parameter",
        "mutation_family": "role-inject",
        "mutation": "access_level=999",
        "inject_type": "query_param",
        "key": "access_level",
        "value": "999",
    },
    {
        "name": "param_permissions",
        "description": 'Inject permissions=["admin"] as query parameter',
        "mutation_family": "role-inject",
        "mutation": 'permissions=["admin"]',
        "inject_type": "query_param",
        "key": "permissions",
        "value": '["admin"]',
    },
    {
        "name": "param_duplicate_role",
        "description": "Inject duplicate role parameter: role=user&role=admin",
        "mutation_family": "role-inject",
        "mutation": "role=user&role=admin",
        "inject_type": "query_param_duplicate",
        "key": "role",
        "values": ["user", "admin"],
    },
    {
        "name": "header_x_role_admin",
        "description": "Inject X-Role: admin header",
        "mutation_family": "role-inject",
        "mutation": "X-Role:admin",
        "inject_type": "header",
        "key": "X-Role",
        "value": "admin",
    },
    {
        "name": "header_x_admin_true",
        "description": "Inject X-Admin: true header",
        "mutation_family": "role-inject",
        "mutation": "X-Admin:true",
        "inject_type": "header",
        "key": "X-Admin",
        "value": "true",
    },
]

# ------------------------------------------------------------------ #
# Parser Confusion                                                     #
# ------------------------------------------------------------------ #
# Exploits parser discrepancies between proxies, API gateways, and
# backend frameworks.  Each variant introduces ambiguity in how the
# request is parsed.
#
# Additional keys:
#   confuse_type (str) — identifies which confusion technique to apply:
#     duplicate_param      — duplicate a key query parameter (first vs last wins)
#     hpp                  — HTTP Parameter Pollution (param=val1&param=val2)
#     duplicate_header     — inject a duplicate of a common header
#     duplicate_content_type — inject a second Content-Type header
#     te_cl_conflict       — inject conflicting Transfer-Encoding + Content-Length

PARSER_CONFUSE_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "duplicate_id_param",
        "description": "Duplicate the first query parameter (first vs last wins ambiguity)",
        "mutation_family": "parser-confusion",
        "mutation": "duplicate_param",
        "confuse_type": "duplicate_param",
    },
    {
        "name": "hpp_id_param",
        "description": "HTTP Parameter Pollution: inject id=0 alongside existing id value",
        "mutation_family": "parser-confusion",
        "mutation": "hpp",
        "confuse_type": "hpp",
        "hpp_key": "id",
        "hpp_value": "0",
    },
    {
        "name": "duplicate_accept",
        "description": "Inject duplicate Accept header",
        "mutation_family": "parser-confusion",
        "mutation": "duplicate_header:Accept",
        "confuse_type": "duplicate_header",
        "dup_header": "Accept",
        "dup_value": "*/*",
    },
    {
        "name": "duplicate_content_type",
        "description": "Inject duplicate Content-Type: text/plain",
        "mutation_family": "parser-confusion",
        "mutation": "duplicate_content_type",
        "confuse_type": "duplicate_content_type",
        "extra_ct": "text/plain",
    },
    {
        "name": "te_cl_conflict",
        "description": "Inject conflicting Transfer-Encoding: chunked alongside Content-Length",
        "mutation_family": "parser-confusion",
        "mutation": "TE-CL-conflict",
        "confuse_type": "te_cl_conflict",
    },
]

# ------------------------------------------------------------------ #
# Registry — maps job type constant → variant list                     #
# ------------------------------------------------------------------ #

VARIANTS_BY_ATTACK: dict[str, list[dict[str, Any]]] = {
    "bac_session_swap":    SESSION_SWAP_VARIANTS,
    "bac_method_fuzz":     METHOD_FUZZ_VARIANTS,
    "bac_content_type":    CONTENT_TYPE_VARIANTS,
    "bac_url_fuzz":        URL_FUZZ_VARIANTS,
    "bac_header_inject":   HEADER_INJECT_VARIANTS,
    "bac_host_fuzz":       HOST_FUZZ_VARIANTS,
    "bac_role_inject":     ROLE_INJECT_VARIANTS,
    "bac_parser_confuse":  PARSER_CONFUSE_VARIANTS,
}
