"""
Module: talos.url_sink.features

Purpose:
    Compose the stable ``url_features`` document stored on parameter inventory
    rows by merging value classification + name classification.

    Rules (Phase 1):
        - Value dominates name for score (e.g. abc=https://… ≈ 90–100).
        - Email addresses stay non-network-resource.
        - Name alone can set category + modest score (15–35), never invents
          a confirmed sink.
        - possible_network_resource = score >= NETWORK_RESOURCE_SCORE_THRESHOLD.

Dependencies: talos.url_sink.value_classify, talos.url_sink.name_classify
Data flow: name + sample_value → url_features dict
Side effects: None.
"""

from __future__ import annotations

from typing import Any

from talos.url_sink.name_classify import NameClassification, classify_name
from talos.url_sink.value_classify import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    UrlValueFeatures,
    classify_value,
)

# Re-export threshold for consumers / tests.
__all__ = [
    "NETWORK_RESOURCE_SCORE_THRESHOLD",
    "compose_url_features",
    "empty_url_features",
    "url_features_to_json_dict",
]


def empty_url_features() -> dict[str, Any]:
    """
    Purpose:
        Return a zeroed url_features document (stable keys for consumers).
    Output:
        dict with all Phase-1 keys at default values.
    Side effects: None.
    """
    return {
        "possible_url_value": False,
        "possible_hostname": False,
        "possible_ip": False,
        "possible_path": False,
        "possible_domain": False,
        "possible_unc": False,
        "possible_protocol": False,
        "protocols_seen": [],
        "looks_like": [],
        "name_category": None,
        "name_categories": [],
        "score": 0,
        "possible_network_resource": False,
        "evidence": [],
    }


def compose_url_features(
    name: str | None = None,
    value: str | None = None,
    *,
    value_features: UrlValueFeatures | None = None,
    name_features: NameClassification | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Merge value + name classification into one url_features document.
    Input:
        name / value — raw parameter name and sample value (optional if
                       precomputed features are passed).
        value_features / name_features — optional precomputed classifications
                                         (avoids double work).
    Output:
        url_features dict (JSON-serializable).
    Side effects: None.
    """
    vf = value_features if value_features is not None else classify_value(value)
    nf = name_features if name_features is not None else classify_name(name)

    # Email: keep name categories for operator context but score stays 0.
    if vf.is_email:
        doc = empty_url_features()
        doc["looks_like"] = list(vf.looks_like)
        doc["name_category"] = nf.name_category
        doc["name_categories"] = list(nf.name_categories)
        evidence = list(vf.evidence)
        evidence.extend(nf.evidence)
        doc["evidence"] = list(dict.fromkeys(evidence))
        doc["score"] = 0
        doc["possible_network_resource"] = False
        return doc

    value_score = int(vf.score or 0)
    name_score = int(nf.score_hint or 0)

    # Value dominates: take max, with a small name boost when value is weak.
    if value_score >= 55:
        score = value_score
        # Tiny boost when name also matches (cap 100).
        if name_score and score < 100:
            score = min(100, score + min(5, name_score // 6))
    elif value_score > 0:
        # Modest value + name: blend toward the stronger signal.
        score = max(value_score, name_score)
        if name_score and value_score:
            score = min(100, max(value_score, name_score) + 5)
    else:
        # Name only.
        score = name_score

    score = max(0, min(100, score))

    evidence: list[str] = list(vf.evidence)
    evidence.extend(nf.evidence)
    # De-dupe preserve order.
    evidence = list(dict.fromkeys(evidence))

    looks = list(vf.looks_like)
    if nf.name_category and "name_hint" not in looks and nf.name_categories:
        looks.append("name_hint")

    return {
        "possible_url_value": bool(vf.possible_url_value),
        "possible_hostname": bool(vf.possible_hostname),
        "possible_ip": bool(vf.possible_ip),
        "possible_path": bool(vf.possible_path),
        "possible_domain": bool(vf.possible_domain),
        "possible_unc": bool(vf.possible_unc),
        "possible_protocol": bool(vf.possible_protocol),
        "protocols_seen": list(vf.protocols_seen),
        "looks_like": looks,
        "name_category": nf.name_category,
        "name_categories": list(nf.name_categories),
        "score": score,
        "possible_network_resource": score >= NETWORK_RESOURCE_SCORE_THRESHOLD,
        "evidence": evidence,
    }


def url_features_to_json_dict(features: dict[str, Any] | None) -> dict[str, Any]:
    """
    Purpose:
        Normalize an arbitrary mapping into a full url_features document.
    Input:
        features — partial or full dict, or None.
    Output:
        Complete url_features dict.
    Side effects: None.
    """
    base = empty_url_features()
    if not features or not isinstance(features, dict):
        return base
    for key in base:
        if key in features:
            base[key] = features[key]
    return base
