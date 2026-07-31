"""
Tests: talos.url_sink.name_classify + catalog

Purpose:
    Cover name normalization (camelCase/snake/kebab), multi-category matches,
    nested leaf extraction, and catalog membership for the product name list.
"""

from __future__ import annotations

import pytest

from talos.url_sink.catalog import (
    ALL_CATEGORY_NAMES,
    CATEGORY_IMPORT_METADATA,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_OAUTH,
    CATEGORY_PATH_LIKE,
    CATEGORY_REDIRECT,
    CATEGORY_REMOTE_ASSET,
    CATEGORY_REMOTE_FETCH,
    CATEGORY_WEBHOOK,
    NAME_CATEGORIES,
    primary_category,
)
from talos.url_sink.name_classify import (
    classify_name,
    leaf_param_name,
    normalize_param_name,
)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("returnUrl", "return_url"),
        ("ReturnURL", "return_url"),
        ("callback_url", "callback_url"),
        ("callback-url", "callback_url"),
        ("RelayState", "relay_state"),
        ("redirect_uri", "redirect_uri"),
        ("imageUrl", "image_url"),
        ("API_URL", "api_url"),
        ("baseUri", "base_uri"),
        ("postLogin", "post_login"),
    ],
)
def test_normalize_param_name(raw: str, expected: str) -> None:
    assert normalize_param_name(raw) == expected


@pytest.mark.parametrize(
    "raw,leaf",
    [
        ("config.oauth.metadata", "metadata"),
        ("variables.user.avatar_url", "avatar_url"),
        ("items[].url", "url"),
        ("callback", "callback"),
        ("a.b.c.d", "d"),
    ],
)
def test_leaf_param_name(raw: str, leaf: str) -> None:
    assert leaf_param_name(raw) == leaf


# ---------------------------------------------------------------------------
# Category matches
# ---------------------------------------------------------------------------

def test_callback_url_multi_match() -> None:
    """callback_url → webhook (+ possibly remote_fetch)."""
    c = classify_name("callback_url")
    assert CATEGORY_WEBHOOK in c.name_categories
    assert c.name_category in (CATEGORY_WEBHOOK, CATEGORY_REMOTE_FETCH)
    assert c.score_hint >= 15
    assert any(e.startswith("name:") for e in c.evidence)


def test_nested_metadata_leaf() -> None:
    c = classify_name("config.oauth.metadata")
    assert c.leaf_name == "metadata"
    assert CATEGORY_IMPORT_METADATA in c.name_categories or (
        CATEGORY_REMOTE_FETCH in c.name_categories
    )


def test_redirect_url_primary_is_redirect_not_oauth() -> None:
    """QA-USD-16: classic redirect_url primary category is redirect, not oauth."""
    c = classify_name("redirect_url")
    assert c.name_category == CATEGORY_REDIRECT
    assert CATEGORY_REDIRECT in (c.name_categories or [])


def test_redirect_uri_oauth_primary() -> None:
    c = classify_name("redirect_uri")
    assert CATEGORY_OAUTH in c.name_categories
    # OAuth outranks generic redirect when both match.
    assert c.name_category == CATEGORY_OAUTH


def test_return_url_camel() -> None:
    c = classify_name("returnUrl")
    assert CATEGORY_REDIRECT in c.name_categories or CATEGORY_OAUTH in c.name_categories
    assert c.score_hint >= 15


def test_avatar_remote_asset() -> None:
    c = classify_name("avatar")
    assert CATEGORY_REMOTE_ASSET in c.name_categories


def test_webhook_name() -> None:
    c = classify_name("webhook")
    assert CATEGORY_WEBHOOK in c.name_categories
    assert c.name_category == CATEGORY_WEBHOOK


def test_backend_url_infrastructure() -> None:
    c = classify_name("backend_url")
    assert (
        CATEGORY_INFRASTRUCTURE in c.name_categories
        or CATEGORY_REMOTE_FETCH in c.name_categories
    )


def test_filepath_path_like() -> None:
    c = classify_name("filepath")
    assert CATEGORY_PATH_LIKE in c.name_categories


def test_unknown_name_empty() -> None:
    c = classify_name("q")
    assert c.name_category is None
    assert c.name_categories == ()
    assert c.score_hint == 0


def test_empty_name() -> None:
    c = classify_name("")
    assert c.name_category is None
    assert c.normalized == ""


# ---------------------------------------------------------------------------
# Catalog completeness (product list samples)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name,expected_cat",
    [
        ("redirect", CATEGORY_REDIRECT),
        ("goto", CATEGORY_REDIRECT),
        ("next", CATEGORY_REDIRECT),
        ("RelayState", CATEGORY_REDIRECT),
        ("success_url", CATEGORY_REDIRECT),
        ("failure_url", CATEGORY_REDIRECT),
        ("post_login", CATEGORY_REDIRECT),
        ("callback", CATEGORY_WEBHOOK),
        ("hook_url", CATEGORY_WEBHOOK),
        ("notify", CATEGORY_WEBHOOK),
        ("url", CATEGORY_REMOTE_FETCH),
        ("uri", CATEGORY_REMOTE_FETCH),
        ("endpoint", CATEGORY_REMOTE_FETCH),
        ("api_url", CATEGORY_REMOTE_FETCH),
        ("base_url", CATEGORY_REMOTE_FETCH),
        ("fetch", CATEGORY_REMOTE_FETCH),
        ("avatar", CATEGORY_REMOTE_ASSET),
        ("image_url", CATEGORY_REMOTE_ASSET),
        ("logo", CATEGORY_REMOTE_ASSET),
        ("thumbnail", CATEGORY_REMOTE_ASSET),
        ("favicon", CATEGORY_REMOTE_ASSET),
        ("wsdl", CATEGORY_IMPORT_METADATA),
        ("openapi", CATEGORY_IMPORT_METADATA),
        ("rss", CATEGORY_IMPORT_METADATA),
        ("proxy", CATEGORY_INFRASTRUCTURE),
        ("gateway", CATEGORY_INFRASTRUCTURE),
        ("upstream", CATEGORY_INFRASTRUCTURE),
        ("hostname", CATEGORY_INFRASTRUCTURE),
        ("healthcheck", "network_probe"),
        ("probe", "network_probe"),
        ("dns", "network_probe"),
        ("download_url", CATEGORY_PATH_LIKE),
        ("upload", CATEGORY_PATH_LIKE),
        ("redirect_uri", CATEGORY_OAUTH),
    ],
)
def test_catalog_samples(name: str, expected_cat: str) -> None:
    c = classify_name(name)
    assert expected_cat in c.name_categories, (
        f"{name!r} expected category {expected_cat}, got {c.name_categories}"
    )


def test_all_categories_nonempty() -> None:
    for cat in ALL_CATEGORY_NAMES:
        assert cat in NAME_CATEGORIES
        assert len(NAME_CATEGORIES[cat]) > 0


def test_primary_category_priority() -> None:
    assert primary_category(["remote_fetch", "oauth", "redirect"]) == "oauth"
    assert primary_category(["remote_fetch", "webhook"]) == "webhook"
    assert primary_category([]) is None


def test_to_dict_shape() -> None:
    d = classify_name("callbackUrl").to_dict()
    assert "name_category" in d
    assert "name_categories" in d
    assert "normalized" in d
    assert isinstance(d["name_categories"], list)


def test_multi_word_token_match_redirect() -> None:
    """https_redirect / HTTPSRedirect should hit redirect via token membership."""
    c = classify_name("HTTPSRedirect")
    assert CATEGORY_REDIRECT in c.name_categories


@pytest.mark.parametrize("name", ["preview", "preview_url", "reset", "previewUrl"])
def test_preview_reset_in_catalog(name: str) -> None:
    c = classify_name(name)
    assert c.name_categories, f"{name!r} should match a catalog category"
