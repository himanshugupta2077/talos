"""
Module: talos.projects.unauth.recipes

Purpose:
    Defines Unauth execution recipes.

    Mandatory authentication removal is performed by engine.py before every
    recipe is applied.

Architecture:
    mandatory auth removal
        +
    unauth technique
        +
    optional request mutation
"""


UNAUTH_RECIPES = [
    # -------------------------------------------------------------- #
    # Core Unauth techniques                                         #
    # -------------------------------------------------------------- #

    {
        "technique": "baseline",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "empty_auth",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "malformed_auth",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "auth_null",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "auth_whitespace",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "duplicate_empty_header",
        "request_mutation": None,
        "request_type": None,
    },
    {
        "technique": "duplicate_malformed_header",
        "request_mutation": None,
        "request_type": None,
    },

    # -------------------------------------------------------------- #
    # High-value Unauth + request mutation combinations               #
    # -------------------------------------------------------------- #

    {
        "technique": "baseline",
        "request_mutation": "override_PUT",
        "request_type": "bac_method_fuzz",
    },
    {
        "technique": "baseline",
        "request_mutation": "override_DELETE",
        "request_type": "bac_method_fuzz",
    },
    {
        "technique": "baseline",
        "request_mutation": "x_original_url",
        "request_type": "bac_header_inject",
    },
    {
        "technique": "baseline",
        "request_mutation": "x_rewrite_url",
        "request_type": "bac_header_inject",
    },
    {
        "technique": "baseline",
        "request_mutation": "encoded_path",
        "request_type": "bac_url_fuzz",
    },
    {
        "technique": "baseline",
        "request_mutation": "trailing_slash",
        "request_type": "bac_url_fuzz",
    },
    {
        "technique": "baseline",
        "request_mutation": "dot_segment",
        "request_type": "bac_url_fuzz",
    },
    {
        "technique": "baseline",
        "request_mutation": "x_forwarded_for_localhost",
        "request_type": "bac_header_inject",
    },
    {
        "technique": "baseline",
        "request_mutation": "x_real_ip_localhost",
        "request_type": "bac_header_inject",
    },
    {
        "technique": "baseline",
        "request_mutation": "x_forwarded_host",
        "request_type": "bac_header_inject",
    },
]