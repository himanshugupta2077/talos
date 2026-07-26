"""
Unit tests for talos.passive.redaction — fingerprint stability and redaction.

Synthetic secrets only; never live credentials.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from talos.passive.redaction import (
    canonicalize_secret,
    fingerprint_secret,
    looks_like_placeholder,
    redact_secret,
)


# ---------------------------------------------------------------------------
# canonicalize_secret
# ---------------------------------------------------------------------------


def test_canonicalize_strips_whitespace() -> None:
    assert canonicalize_secret("  secret-value  ", case_sensitive=True) == "secret-value"


def test_canonicalize_case_fold_for_provider_family() -> None:
    assert canonicalize_secret("AbCd", family="provider") == "abcd"
    assert canonicalize_secret("AbCd", family="pem", case_sensitive=None) == "AbCd"


def test_canonicalize_explicit_case_sensitive() -> None:
    assert canonicalize_secret("AbCd", case_sensitive=True) == "AbCd"
    assert canonicalize_secret("AbCd", case_sensitive=False) == "abcd"


def test_canonicalize_none_is_empty() -> None:
    assert canonicalize_secret(None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# fingerprint_secret — contract
# ---------------------------------------------------------------------------


def test_fingerprint_matches_documented_formula() -> None:
    family = "provider"
    value = "AKIAIOSFODNN7EXAMPLE"
    canonical = canonicalize_secret(value, family=family)
    expected = hashlib.sha256(f"{family}\0{canonical}".encode("utf-8")).hexdigest()
    assert fingerprint_secret(family, value) == expected


def test_fingerprint_is_stable_across_calls() -> None:
    a = fingerprint_secret("provider", "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    b = fingerprint_secret("provider", "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert a == b
    assert re.fullmatch(r"[0-9a-f]{64}", a)


def test_fingerprint_whitespace_does_not_split_clusters() -> None:
    left = fingerprint_secret("provider", "  tokenvalue  ")
    right = fingerprint_secret("provider", "tokenvalue")
    assert left == right


def test_fingerprint_case_fold_for_provider() -> None:
    lower = fingerprint_secret("provider", "abcdef12")
    upper = fingerprint_secret("provider", "ABCDEF12")
    assert lower == upper


def test_fingerprint_case_sensitive_for_pem() -> None:
    # PEM family defaults to case-sensitive (not in fold set)
    a = fingerprint_secret("pem", "BEGIN-MARKER")
    b = fingerprint_secret("pem", "begin-marker")
    assert a != b


def test_fingerprint_different_families_differ() -> None:
    value = "same-secret-material"
    a = fingerprint_secret("provider", value)
    b = fingerprint_secret("generic", value)
    assert a != b


def test_fingerprint_empty_family_still_hashes() -> None:
    fp = fingerprint_secret("", "x")
    assert re.fullmatch(r"[0-9a-f]{64}", fp)


# ---------------------------------------------------------------------------
# redact_secret
# ---------------------------------------------------------------------------


def test_redact_long_secret_shows_prefix_and_suffix() -> None:
    # Synthetic AWS-shaped id (example pattern from AWS docs — not live)
    value = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(value)
    assert redacted == "AKIA****MPLE"
    assert "IOSFODNN7EXA" not in redacted


def test_redact_short_secret_is_full_mask() -> None:
    assert redact_secret("short") == "****"
    assert redact_secret("12345678") == "****"  # exactly prefix+suffix


def test_redact_empty_and_whitespace() -> None:
    assert redact_secret("") == ""
    assert redact_secret("   ") == ""
    assert redact_secret(None) == ""  # type: ignore[arg-type]


def test_redact_custom_windows() -> None:
    value = "abcdefghijklmnop"
    assert redact_secret(value, prefix=2, suffix=2, mask="XX") == "abXXop"


# ---------------------------------------------------------------------------
# looks_like_placeholder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "null",
        "undefined",
        "example",
        "changeme",
        "placeholder",
        "YOUR_API_KEY",
        "${API_KEY}",
        "{{secret}}",
        "process.env.SECRET",
        "import.meta.env.VITE_KEY",
        "aaaaaaaa",
    ],
)
def test_placeholder_true(value: str) -> None:
    assert looks_like_placeholder(value) is True


def test_placeholder_false_for_realistic_shapes() -> None:
    # Build vendor-shaped strings at runtime (avoid static secret scanners).
    samples = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + ("A" * 36),
        "sk_" + "live_" + "not_a_real_key_but_shaped",
    ]
    for value in samples:
        assert looks_like_placeholder(value) is False
