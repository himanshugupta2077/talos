"""
Module: talos.projects.unauth.variants

Purpose:
    Defines Unauth techniques.

    Authentication removal is NOT a technique.

    Every Unauth request is first passed through the mandatory canonical
    auth stripping stage in engine.py.  A technique is then optionally
    applied to the fully unauthenticated request.

Pipeline:
    baseline flow
        -> strip all configured auth
        -> apply unauth technique
        -> optional request mutation
        -> replay
"""

from typing import Any


UNAUTH_TECHNIQUES: list[dict[str, Any]] = [
    {
        "name": "baseline",
        "description": "Replay with all configured authentication removed",
        "mutation_family": "remove-auth",
        "mutation": "baseline",
        "technique_action": "none",
    },
    {
        "name": "empty_auth",
        "description": "Re-add configured auth fields with empty values",
        "mutation_family": "empty-auth",
        "mutation": "empty_auth",
        "technique_action": "empty",
    },
    {
        "name": "malformed_auth",
        "description": (
            "Re-add configured auth headers with a malformed credential "
            "matching the original authentication scheme when detectable"
        ),
        "mutation_family": "malformed-auth",
        "mutation": "malformed_auth",
        "technique_action": "malformed",
    },
    {
        "name": "auth_null",
        "description": "Re-add configured auth fields with literal string 'null'",
        "mutation_family": "null-auth",
        "mutation": "auth_null",
        "technique_action": "null",
    },
    {
        "name": "auth_whitespace",
        "description": "Re-add configured auth fields with a single whitespace value",
        "mutation_family": "whitespace-auth",
        "mutation": "auth_whitespace",
        "technique_action": "whitespace",
    },
    {
        "name": "duplicate_empty_header",
        "description": (
            "Send two instances of each configured auth header, both without "
            "valid authentication; first empty and second empty"
        ),
        "mutation_family": "duplicate-auth",
        "mutation": "duplicate_empty_header",
        "technique_action": "duplicate_empty",
    },
    {
        "name": "duplicate_malformed_header",
        "description": (
            "Send two instances of each configured auth header, both without "
            "valid authentication; one malformed and one empty"
        ),
        "mutation_family": "duplicate-auth",
        "mutation": "duplicate_malformed_header",
        "technique_action": "duplicate_malformed",
    },
]


UNAUTH_TECHNIQUE_BY_NAME: dict[str, dict[str, Any]] = {
    technique["name"]: technique
    for technique in UNAUTH_TECHNIQUES
}
