"""
Package: talos.url_sink

Purpose:
    URL Sink Discovery — passive characterization of parameters that look like
    network resources (URLs, hostnames, IPs, paths, UNC) or whose names suggest
    sink categories (redirect, webhook, remote_fetch, remote_asset, …).

    This is **characterization and prioritization**, not exploit confirmation.
    No OAST chains, no Findings, no freeform shell.

Architecture (Phase 1 — passive core):
    Endpoint Intelligence (parameters.py)
        → value_classify  (does the value look like a network resource?)
        → name_classify   (does the name suggest a sink category?)
        → features.compose_url_features  → parameters.url_features JSON
        → improved semantic_type=url for URL-shaped values

    Later phases (not in Phase 1):
        structure discovery, IV URL probes, capabilities, candidate rewrite.

Public exports (Phase 1):
    classify_value, UrlValueFeatures
    classify_name, NameClassification
    compose_url_features, NETWORK_RESOURCE_SCORE_THRESHOLD
    NAME_CATEGORIES, all catalog category constants

Dependencies: stdlib only (re, dataclasses, ipaddress, urllib.parse)
Data flow: raw name/value → pure classifiers → url_features dict → parameters table
Side effects: None in pure classifiers; DB write only when wired by parameters.upsert.
"""

from __future__ import annotations

from talos.url_sink.catalog import (
    CATEGORY_IMPORT_METADATA,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_NETWORK_PROBE,
    CATEGORY_OAUTH,
    CATEGORY_PATH_LIKE,
    CATEGORY_REDIRECT,
    CATEGORY_REMOTE_ASSET,
    CATEGORY_REMOTE_FETCH,
    CATEGORY_WEBHOOK,
    NAME_CATEGORIES,
    ALL_CATEGORY_NAMES,
)
from talos.url_sink.features import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    compose_url_features,
    empty_url_features,
)
from talos.url_sink.name_classify import (
    NameClassification,
    classify_name,
    leaf_param_name,
    normalize_param_name,
)
from talos.url_sink.value_classify import (
    UrlValueFeatures,
    classify_value,
)

__all__ = [
    # Value
    "UrlValueFeatures",
    "classify_value",
    # Name
    "NameClassification",
    "classify_name",
    "leaf_param_name",
    "normalize_param_name",
    # Catalog
    "CATEGORY_REDIRECT",
    "CATEGORY_WEBHOOK",
    "CATEGORY_REMOTE_FETCH",
    "CATEGORY_REMOTE_ASSET",
    "CATEGORY_IMPORT_METADATA",
    "CATEGORY_INFRASTRUCTURE",
    "CATEGORY_NETWORK_PROBE",
    "CATEGORY_PATH_LIKE",
    "CATEGORY_OAUTH",
    "NAME_CATEGORIES",
    "ALL_CATEGORY_NAMES",
    # Features
    "compose_url_features",
    "empty_url_features",
    "NETWORK_RESOURCE_SCORE_THRESHOLD",
]
