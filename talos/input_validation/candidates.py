"""
Module: talos.input_validation.candidates

Purpose:
    Module 11 — **attack candidate scoring** and the stable consumer API
    for attack modules (XSS, SQLi, SSRF, open redirect, HPP, header issues).

    Candidates are **prioritization hints**, not confirmed vulnerabilities.
    Attack modules must still verify; IV only ranks where to look first.

What this module does
    - score_candidates(profile) → list of candidate dicts
    - apply_candidates(profile) → write onto profile["candidates"]
    - get_param_intelligence(db, param_id|uuid) — single stable import
    - list_candidates(db, filters) — project-wide prioritization

What this module does **not** do
    - Create findings
    - Run exploit payloads
    - Change BAC engines (document-only handoff)

Candidate shape (code-as-truth)::

    {
      "attack": "xss" | "sqli" | "open_redirect" | "ssrf" | "hpp" |
                "header_injection" | "path_traversal" | "mass_assignment",
      "score": 0-100,           # prioritization strength
      "confidence": 0-100,      # evidence quality for this score
      "reasons": ["..."],
      "evidence_flow_ids": ["..."]
    }

Dependencies:
    talos.input_validation.profile (capability constants)
    talos.input_validation.capabilities (derive/has)
    talos.input_validation.db (profile CRUD for consumer API)
    talos.input_validation.outcomes (outcome labels)
Data flow:
    profile → score_candidates → candidates[]
    db → get_param_intelligence / list_candidates
Side effects: apply_* mutates profile; consumer API is read-only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from talos.input_validation.capabilities import (
    derive_capabilities,
    has_capability,
)
from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_ENCODED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    OUTCOME_REJECTED,
)
from talos.input_validation.profile import (
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_XML_BODY,
)

# ---------------------------------------------------------------------------
# Attack vocabulary (stable consumer contract)
# ---------------------------------------------------------------------------

ATTACK_XSS = "xss"
ATTACK_SQLI = "sqli"
ATTACK_OPEN_REDIRECT = "open_redirect"
ATTACK_SSRF = "ssrf"
ATTACK_HPP = "hpp"
ATTACK_HEADER_INJECTION = "header_injection"
ATTACK_PATH_TRAVERSAL = "path_traversal"
ATTACK_MASS_ASSIGNMENT = "mass_assignment"

KNOWN_ATTACKS: frozenset[str] = frozenset({
    ATTACK_XSS,
    ATTACK_SQLI,
    ATTACK_OPEN_REDIRECT,
    ATTACK_SSRF,
    ATTACK_HPP,
    ATTACK_HEADER_INJECTION,
    ATTACK_PATH_TRAVERSAL,
    ATTACK_MASS_ASSIGNMENT,
})

# Soft-accept outcomes for class/type evidence.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_ENCODED,
    OUTCOME_NORMALIZED,
})

# Parameter name tokens → open redirect / URL surface.
_REDIRECT_NAME_TOKENS: tuple[str, ...] = (
    "redirect", "return_url", "returnurl", "return_to", "returnto",
    "next", "continue", "goto", "dest", "destination", "callback",
    "url", "uri", "target", "redir", "rurl", "relay",
)

# Name tokens that bias toward SSRF (server-side fetch / webhook style).
_SSRF_NAME_TOKENS: tuple[str, ...] = (
    "webhook", "callback", "fetch", "proxy", "url", "uri", "endpoint",
    "host", "target", "feed", "avatar", "image_url", "img", "media",
    "remote", "src", "source", "link",
)

# Minimum score to include a candidate in the default list (avoid noise).
MIN_EMIT_SCORE = 25


# ---------------------------------------------------------------------------
# Candidate object helpers
# ---------------------------------------------------------------------------

def empty_candidate(
    attack: str,
    *,
    score: int = 0,
    confidence: int = 0,
    reasons: list[str] | None = None,
    evidence_flow_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Purpose: Build one candidate dict with clamped score/confidence.
    Side effects: None.
    """
    return {
        "attack": attack,
        "score": _clamp(score),
        "confidence": _clamp(confidence),
        "reasons": list(reasons or []),
        "evidence_flow_ids": list(evidence_flow_ids or []),
    }


def score_candidates(profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    """
    Purpose:
        Pure scorer: derive attack candidates from a parameter profile
        (capabilities + observed acceptance/types/reflection/tested).

    Input:
        profile — intelligence document (capabilities preferred; re-derived
                  if missing).

    Output:
        List of candidate dicts with score ≥ MIN_EMIT_SCORE, sorted by
        score desc then attack name. Empty list when profile is empty.

    Side effects: None (does not mutate profile).
    """
    if not profile or not isinstance(profile, dict):
        return []

    # Work on a shallow view: ensure capabilities present for rules.
    caps = profile.get("capabilities")
    if not isinstance(caps, list) or not caps:
        caps = derive_capabilities(profile)
    view = dict(profile)
    view["capabilities"] = list(caps)

    ctx = _ProfileView(view)
    scored: list[dict[str, Any]] = []

    for builder in (
        _score_xss,
        _score_sqli,
        _score_open_redirect,
        _score_ssrf,
        _score_hpp,
        _score_header_injection,
        _score_path_traversal,
        _score_mass_assignment,
    ):
        cand = builder(ctx)
        if cand is not None and int(cand.get("score") or 0) >= MIN_EMIT_SCORE:
            scored.append(cand)

    scored.sort(key=lambda c: (-int(c.get("score") or 0), str(c.get("attack") or "")))
    return scored


def apply_candidates(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Recompute capabilities (if empty) and write ``profile["candidates"]``.

    Input/Output: mutable profile document.
    Side effects: May fill capabilities when empty; overwrites candidates.
    """
    if not isinstance(profile, dict):
        return profile
    caps = profile.get("capabilities")
    if not isinstance(caps, list) or not caps:
        from talos.input_validation.capabilities import apply_capabilities
        apply_capabilities(profile)
    profile["candidates"] = score_candidates(profile)
    return profile


def enrich_profile_capabilities_and_candidates(
    profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Purpose:
        Full Module 11 post-synthesis pass: re-derive capabilities then score
        candidates. Preferred single entry from synthesizer.

    Side effects: Mutates profile capabilities + candidates.
    """
    from talos.input_validation.capabilities import apply_capabilities

    apply_capabilities(profile)
    profile["candidates"] = score_candidates(profile)
    return profile


# ---------------------------------------------------------------------------
# Stable consumer API (attack modules import these)
# ---------------------------------------------------------------------------

def get_param_intelligence(
    db_path: Path | str,
    param_id_or_uuid: str,
    *,
    recompute: bool = False,
) -> dict[str, Any] | None:
    """
    Purpose:
        **Stable single import** for attack modules. Load parameter
        intelligence (profile + capabilities + candidates) without parsing
        ``iv_probe_results`` or phase caches.

    Input:
        db_path          — project SQLite path.
        param_id_or_uuid — ``parameters.id`` row UUID **or** param_uuid
                           (sha256 host|location|name).
        recompute        — when True, re-run capability + candidate scoring
                           on the loaded profile (does not persist).

    Output:
        dict with keys::

            param_uuid, host, location, name, level,
            profile,              # full shaped profile (or None)
            capabilities,         # list[str]
            candidates,           # list[candidate]
            observed, inferred, tested,  # convenience slices
            endpoint_id?,         # when resolved via parameters table
            passive?              # optional passive parameter fields

        None when neither parameters row nor iv_param_profiles match.

    Side effects: Read-only DB.
    """
    from talos.input_validation import db as iv_db
    from talos.input_validation.profile import ensure_profile_shape

    path = Path(db_path)
    key = (param_id_or_uuid or "").strip()
    if not key:
        return None

    # 1) Prefer parameters table id (passive inventory).
    passive = iv_db.get_parameter_profile(path, key)
    profile: dict[str, Any] | None = None
    endpoint_id: str | None = None
    host = location = name = param_uuid = ""

    if passive is not None:
        host = str(passive.get("host") or "")
        location = str(passive.get("location") or "")
        name = str(passive.get("name") or "")
        param_uuid = str(passive.get("param_uuid") or "")
        profile = passive.get("intelligence_profile")
        # endpoint path is available; id may not be in passive dict.
        endpoint_id = passive.get("endpoint_id")  # type: ignore[assignment]
        if not endpoint_id:
            # Recover endpoint_id from probe rows when possible.
            for rec in iv_db.get_probe_results_for_param(path, param_uuid)[:5]:
                if rec.get("endpoint_id"):
                    endpoint_id = str(rec["endpoint_id"])
                    break
    else:
        # 2) Treat key as param_uuid.
        profile = iv_db.get_param_profile(path, key)
        if profile is None:
            return None
        param_uuid = str(profile.get("param_uuid") or key)
        host = str(profile.get("host") or "")
        location = str(profile.get("location") or "")
        name = str(profile.get("name") or "")

    if profile is None:
        # Passive row exists but no synthesized profile yet.
        profile = {
            "param_uuid": param_uuid,
            "host": host,
            "location": location,
            "name": name,
            "capabilities": [],
            "candidates": [],
            "observed": {},
            "inferred": {},
            "tested": {},
        }
    else:
        profile = ensure_profile_shape(dict(profile))

    if recompute or not profile.get("candidates") or not profile.get("capabilities"):
        enrich_profile_capabilities_and_candidates(profile)

    return {
        "param_uuid": param_uuid or str(profile.get("param_uuid") or ""),
        "host": host or str(profile.get("host") or ""),
        "location": location or str(profile.get("location") or ""),
        "name": name or str(profile.get("name") or ""),
        "level": profile.get("level") or "parameter",
        "endpoint_id": endpoint_id,
        "profile": profile,
        "capabilities": list(profile.get("capabilities") or []),
        "candidates": list(profile.get("candidates") or []),
        "observed": profile.get("observed") or {},
        "inferred": profile.get("inferred") or {},
        "tested": profile.get("tested") or {},
        "passive": {
            "param_type": (passive or {}).get("param_type"),
            "semantic_type": (passive or {}).get("semantic_type"),
            "is_reflected": (passive or {}).get("is_reflected"),
            "examples": (passive or {}).get("examples"),
        } if passive else None,
    }


def list_candidates(
    db_path: Path | str,
    *,
    attack: str | None = None,
    min_score: int = 0,
    min_confidence: int = 0,
    host: str | None = None,
    capability: str | None = None,
    limit: int = 500,
    recompute: bool = False,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Project-wide candidate listing for operators and future attack
        prioritization UIs. Flattens profile.candidates with identity.

    Input filters:
        attack         — exact attack name (e.g. ``xss``).
        min_score      — inclusive score floor (0–100).
        min_confidence — inclusive confidence floor.
        host           — exact host filter.
        capability     — require this capability flag on the profile.
        limit          — max flattened rows (default 500).
        recompute      — re-score each profile in memory (not persisted).

    Output:
        List of dicts::

            {
              param_uuid, host, location, name,
              attack, score, confidence, reasons, evidence_flow_ids,
              capabilities  # full flag list for the param
            }

        Sorted by score desc, then confidence desc, then param_uuid.

    Side effects: Read-only DB.
    """
    from talos.input_validation import db as iv_db

    path = Path(db_path)
    profiles = iv_db.list_param_profiles(path, host=host, limit=max(limit * 2, 500))
    attack_filter = (attack or "").strip().lower() or None
    cap_filter = (capability or "").strip() or None
    rows: list[dict[str, Any]] = []

    for prof in profiles:
        work = dict(prof) if recompute else prof
        if recompute or not work.get("candidates") or not work.get("capabilities"):
            work = dict(prof)
            enrich_profile_capabilities_and_candidates(work)

        caps = list(work.get("capabilities") or [])
        if cap_filter and cap_filter not in caps:
            continue

        for cand in work.get("candidates") or []:
            if not isinstance(cand, dict):
                continue
            atk = str(cand.get("attack") or "")
            if attack_filter and atk.lower() != attack_filter:
                continue
            score = _clamp(cand.get("score") or 0)
            conf = _clamp(cand.get("confidence") or 0)
            if score < int(min_score):
                continue
            if conf < int(min_confidence):
                continue
            rows.append({
                "param_uuid": work.get("param_uuid") or "",
                "host": work.get("host") or "",
                "location": work.get("location") or "",
                "name": work.get("name") or "",
                "attack": atk,
                "score": score,
                "confidence": conf,
                "reasons": list(cand.get("reasons") or []),
                "evidence_flow_ids": list(cand.get("evidence_flow_ids") or []),
                "capabilities": caps,
            })
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break

    rows.sort(
        key=lambda r: (
            -int(r.get("score") or 0),
            -int(r.get("confidence") or 0),
            str(r.get("param_uuid") or ""),
            str(r.get("attack") or ""),
        )
    )
    return rows[:limit]


def format_candidates_lines(candidates: list[dict[str, Any]] | None) -> list[str]:
    """
    Purpose: Human-readable candidate lines for CLI show / export.
    Side effects: None.
    """
    if not candidates:
        return []
    lines: list[str] = []
    for c in candidates:
        if not isinstance(c, dict):
            continue
        reasons = c.get("reasons") or []
        reason_txt = "; ".join(str(r) for r in reasons[:4])
        if len(reasons) > 4:
            reason_txt += f"; +{len(reasons) - 4} more"
        lines.append(
            f"{c.get('attack', '?')}: score={c.get('score', 0)}  "
            f"confidence={c.get('confidence', 0)}"
            + (f"  — {reason_txt}" if reason_txt else "")
        )
    return lines


# ---------------------------------------------------------------------------
# Internal scoring context
# ---------------------------------------------------------------------------

class _ProfileView:
    """Read-only helpers over a profile for scorer functions."""

    __slots__ = (
        "profile", "caps", "obs", "tested", "name", "location",
        "acceptance", "types", "refl", "parser", "semantic",
    )

    def __init__(self, profile: dict[str, Any]) -> None:
        self.profile = profile
        self.caps = set(profile.get("capabilities") or [])
        self.obs = profile.get("observed") or {}
        if not isinstance(self.obs, dict):
            self.obs = {}
        self.tested = profile.get("tested") or {}
        if not isinstance(self.tested, dict):
            self.tested = {}
        self.name = str(profile.get("name") or "")
        self.location = str(profile.get("location") or "").lower()
        acc = self.obs.get("acceptance") or {}
        self.acceptance = (acc.get("classes") or {}) if isinstance(acc, dict) else {}
        if not isinstance(self.acceptance, dict):
            self.acceptance = {}
        self.types = self.obs.get("types") or {}
        if not isinstance(self.types, dict):
            self.types = {}
        self.refl = self.obs.get("reflection") or {}
        if not isinstance(self.refl, dict):
            self.refl = {}
        self.parser = self.obs.get("parser") or profile.get("parser") or {}
        if not isinstance(self.parser, dict):
            self.parser = {}
        self.semantic = _resolve_semantic(profile, self.types)

    def has(self, cap: str) -> bool:
        return cap in self.caps

    def class_outcome(self, cls: str) -> str | None:
        entry = self.acceptance.get(cls)
        if isinstance(entry, dict):
            return str(entry.get("outcome") or "").lower() or None
        # Fall back to tested taxonomy keys.
        t = self.tested.get(cls)
        if isinstance(t, dict):
            return str(t.get("outcome") or "").lower() or None
        return None

    def class_soft_accept(self, cls: str) -> bool:
        o = self.class_outcome(cls)
        return o in _SOFT_ACCEPT if o else False

    def class_rejected(self, cls: str) -> bool:
        o = self.class_outcome(cls)
        return o == OUTCOME_REJECTED if o else False

    def type_soft_accept(self, tname: str) -> bool:
        entry = self.types.get(tname)
        if isinstance(entry, dict):
            return str(entry.get("outcome") or "").lower() in _SOFT_ACCEPT
        return False

    def type_rejected(self, tname: str) -> bool:
        entry = self.types.get(tname)
        if isinstance(entry, dict):
            return str(entry.get("outcome") or "").lower() == OUTCOME_REJECTED
        key = f"type:{tname}"
        t = self.tested.get(key) or self.tested.get(tname)
        if isinstance(t, dict):
            return str(t.get("outcome") or "").lower() == OUTCOME_REJECTED
        return False

    def flows_from(self, *entries: Any) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for fid in entry.get("evidence_flow_ids") or []:
                s = str(fid)
                if s and s not in seen:
                    seen.add(s)
                    ids.append(s)
        # Also pull from reflection / classes when passed as raw keys.
        return ids

    def flows_for_classes(self, *classes: str) -> list[str]:
        entries = []
        for c in classes:
            e = self.acceptance.get(c)
            if isinstance(e, dict):
                entries.append(e)
            t = self.tested.get(c)
            if isinstance(t, dict):
                entries.append(t)
        return self.flows_from(*entries, self.refl)


def _resolve_semantic(profile: dict[str, Any], types: dict[str, Any]) -> str:
    summary = types.get("_summary")
    if isinstance(summary, dict):
        for k in ("passive", "semantic", "primary", "semantic_type"):
            v = summary.get(k)
            if v:
                return str(v).lower()
    inferred = profile.get("inferred") or {}
    if isinstance(inferred, dict):
        passive = inferred.get("passive") or {}
        if isinstance(passive, dict) and passive.get("semantic_type"):
            return str(passive["semantic_type"]).lower()
    return ""


def _name_tokens_match(name: str, tokens: tuple[str, ...]) -> list[str]:
    n = (name or "").lower().replace("-", "_")
    return [t for t in tokens if t in n]


def _clamp(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _avg_conf(*values: int) -> int:
    nums = [v for v in values if v > 0]
    if not nums:
        return 50
    return _clamp(sum(nums) // len(nums))


def _entry_conf(entry: Any, default: int = 60) -> int:
    if isinstance(entry, dict):
        return _clamp(entry.get("confidence") or default)
    return default


# ---------------------------------------------------------------------------
# Per-attack scorers
# ---------------------------------------------------------------------------

def _score_xss(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    XSS candidate: reflection + HTML/JS/attr context + markup/quote accepted.
    High when reflected HTML and ``<>`` (markup) soft-accepted.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows = ctx.flows_for_classes("markup", "quote")

    reflected = ctx.has(CAPABILITY_REFLECTIVE_INPUT) or (
        str(ctx.refl.get("state") or "").lower() == "reflected"
    )
    if reflected:
        score += 30
        reasons.append("input is reflected in responses")
        confs.append(_entry_conf(ctx.refl, 70))
        flows = list(dict.fromkeys(flows + list(ctx.refl.get("evidence_flow_ids") or [])))

    if ctx.has(CAPABILITY_HTML_CONTEXT):
        score += 25
        reasons.append("reflection context includes html")
        confs.append(75)
    if ctx.has(CAPABILITY_JS_CONTEXT):
        score += 22
        reasons.append("reflection context includes javascript")
        confs.append(75)
    if ctx.has(CAPABILITY_URL_CONTEXT) and reflected:
        score += 8
        reasons.append("reflection in url context")
    if ctx.has(CAPABILITY_JSON_CONTEXT) and reflected:
        score += 5
        reasons.append("reflection in json context (lower XSS relevance)")

    markup_ok = ctx.class_soft_accept("markup")
    quote_ok = ctx.class_soft_accept("quote")
    if markup_ok:
        score += 28
        reasons.append("markup characters (e.g. <>) accepted")
        confs.append(_entry_conf(ctx.acceptance.get("markup"), 80))
    if quote_ok:
        score += 12
        reasons.append("quote characters accepted")
        confs.append(_entry_conf(ctx.acceptance.get("quote"), 75))

    if ctx.class_rejected("markup"):
        score -= 20
        reasons.append("negative evidence: markup rejected")
        confs.append(_entry_conf(ctx.acceptance.get("markup") or ctx.tested.get("markup"), 85))
    if ctx.class_rejected("quote"):
        score -= 8
        reasons.append("negative evidence: quotes rejected")

    # Strong pattern: reflected HTML + accepts <>
    if reflected and ctx.has(CAPABILITY_HTML_CONTEXT) and markup_ok:
        score = max(score, 85)
        if "high-priority: reflected HTML with markup accepted" not in reasons:
            reasons.append("high-priority: reflected HTML with markup accepted")

    if not reflected and score < 40:
        # Without reflection, XSS candidate is weak noise.
        return None

    return empty_candidate(
        ATTACK_XSS,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_sqli(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    SQLi candidate (characterization only): quote/operator/comment classes +
    string-like type. Rejected quotes strongly reduce score.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows = ctx.flows_for_classes("quote", "operator", "comment")

    # Name / type baseline — most params are string-like; avoid flooding.
    primary = ""
    summary = ctx.types.get("_summary")
    if isinstance(summary, dict):
        primary = str(summary.get("primary") or summary.get("passive") or "").lower()
    if primary in ("string", "unknown", "") or ctx.semantic in ("string", "text", ""):
        score += 15
        reasons.append("string-like parameter type")
    if primary in ("integer", "int", "boolean", "bool", "float"):
        score -= 15
        reasons.append(f"primary type {primary} reduces classic SQLi priority")

    quote_ok = ctx.class_soft_accept("quote")
    op_ok = ctx.class_soft_accept("operator")
    comment_ok = ctx.class_soft_accept("comment")

    if quote_ok:
        score += 30
        reasons.append("quote class accepted")
        confs.append(_entry_conf(ctx.acceptance.get("quote"), 80))
    if op_ok:
        score += 20
        reasons.append("operator class accepted")
        confs.append(_entry_conf(ctx.acceptance.get("operator"), 75))
    if comment_ok:
        score += 18
        reasons.append("comment class accepted")
        confs.append(_entry_conf(ctx.acceptance.get("comment"), 75))

    if ctx.class_rejected("quote"):
        score -= 35
        reasons.append("negative evidence: quotes rejected (reduces SQLi priority)")
        confs.append(_entry_conf(ctx.acceptance.get("quote") or ctx.tested.get("quote"), 90))
    if ctx.class_rejected("comment"):
        score -= 10
        reasons.append("negative evidence: comment markers rejected")
    if ctx.class_rejected("operator"):
        score -= 10
        reasons.append("negative evidence: operator characters rejected")

    # Tested family keys from validation (Module 7).
    for key in ("quote", "class:quote"):
        t = ctx.tested.get(key)
        if isinstance(t, dict) and str(t.get("outcome") or "").lower() == OUTCOME_REJECTED:
            if "negative evidence: quotes rejected" not in " ".join(reasons):
                score -= 20
                reasons.append("negative evidence: tested quotes rejected")
                confs.append(_entry_conf(t, 90))
                flows = list(dict.fromkeys(flows + list(t.get("evidence_flow_ids") or [])))

    if quote_ok and op_ok and comment_ok:
        score = max(score, 70)
        reasons.append("quote+operator+comment classes all accepted")

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_SQLI,
        score=score,
        confidence=_avg_conf(*confs) if confs else 50,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_open_redirect(ctx: _ProfileView) -> dict[str, Any] | None:
    """open_redirect: name signals + url type + url-like / redirect capabilities."""
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []

    name_hits = _name_tokens_match(ctx.name, _REDIRECT_NAME_TOKENS)
    if name_hits:
        score += 35
        reasons.append(f"parameter name suggests redirect/URL ({', '.join(name_hits[:4])})")
        confs.append(70)

    if ctx.has(CAPABILITY_REDIRECT_LIKE):
        score += 30
        reasons.append("baseline response is redirect-like")
        confs.append(80)
        fp = ctx.obs.get("baseline_fingerprint") or {}
        if isinstance(fp, dict):
            flows = ctx.flows_from(fp)

    if ctx.has(CAPABILITY_URL_LIKE_VALUE) or ctx.type_soft_accept("url"):
        score += 28
        reasons.append("accepts URL-shaped input")
        confs.append(_entry_conf(ctx.types.get("url"), 80))
        if isinstance(ctx.types.get("url"), dict):
            flows = list(dict.fromkeys(
                flows + list((ctx.types.get("url") or {}).get("evidence_flow_ids") or [])
            ))

    if ctx.semantic in ("url", "uri", "redirect"):
        score += 15
        reasons.append(f"semantic_type={ctx.semantic}")
        confs.append(75)

    if ctx.type_rejected("url"):
        score -= 25
        reasons.append("negative evidence: URL type rejected")
        confs.append(85)

    if score < MIN_EMIT_SCORE:
        return None

    # Name + URL type is the classic high-priority pattern.
    if name_hits and (ctx.has(CAPABILITY_URL_LIKE_VALUE) or ctx.type_soft_accept("url")):
        score = max(score, 80)
        reasons.append("high-priority: redirect-like name + URL type accepted")

    return empty_candidate(
        ATTACK_OPEN_REDIRECT,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_ssrf(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    SSRF candidate: URL-shaped acceptance + server-side name hints.
    Overlaps open_redirect signals but biases webhook/fetch-style names.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []

    ssrf_hits = _name_tokens_match(ctx.name, _SSRF_NAME_TOKENS)
    redir_hits = _name_tokens_match(ctx.name, _REDIRECT_NAME_TOKENS)

    if ssrf_hits:
        score += 32
        reasons.append(f"parameter name suggests server-side URL fetch ({', '.join(ssrf_hits[:4])})")
        confs.append(70)

    if ctx.has(CAPABILITY_URL_LIKE_VALUE) or ctx.type_soft_accept("url"):
        score += 30
        reasons.append("accepts URL-shaped input")
        confs.append(_entry_conf(ctx.types.get("url"), 80))
        if isinstance(ctx.types.get("url"), dict):
            flows = list((ctx.types.get("url") or {}).get("evidence_flow_ids") or [])

    if ctx.semantic in ("url", "uri", "callback", "webhook"):
        score += 15
        reasons.append(f"semantic_type={ctx.semantic}")

    # Open-redirect-only names without URL acceptance: weaker SSRF signal.
    if redir_hits and not ssrf_hits and not (
        ctx.has(CAPABILITY_URL_LIKE_VALUE) or ctx.type_soft_accept("url")
    ):
        score += 10
        reasons.append("redirect-like name without confirmed URL acceptance")

    if ctx.type_rejected("url"):
        score -= 30
        reasons.append("negative evidence: URL type rejected")
        confs.append(90)

    # Path params rarely SSRF surfaces unless named url-like.
    if ctx.location == "path" and not ssrf_hits:
        score -= 10

    if score < MIN_EMIT_SCORE:
        return None

    if ssrf_hits and (ctx.has(CAPABILITY_URL_LIKE_VALUE) or ctx.type_soft_accept("url")):
        score = max(score, 78)
        reasons.append("high-priority: SSRF-ish name + URL type accepted")

    return empty_candidate(
        ATTACK_SSRF,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_hpp(ctx: _ProfileView) -> dict[str, Any] | None:
    """HPP / duplicate-parameter behaviour from parser fingerprint."""
    if not ctx.has(CAPABILITY_DUPLICATE_PARAMETER):
        # Check parser block even if capability list stale.
        found = False
        for key in ("duplicate_query", "duplicate_form", "array_repeat"):
            entry = ctx.parser.get(key) or {}
            if isinstance(entry, dict):
                behavior = str(entry.get("behavior") or entry.get("state") or "")
                if behavior in ("first_wins", "last_wins", "join"):
                    found = True
                    break
        if not found:
            return None

    score = 55
    reasons = ["parser accepts or distinguishes duplicate parameters"]
    confs = [75]
    flows: list[str] = []
    for key in ("duplicate_query", "duplicate_form", "array_repeat"):
        entry = ctx.parser.get(key) or {}
        if isinstance(entry, dict):
            behavior = str(entry.get("behavior") or entry.get("state") or "")
            if behavior in ("first_wins", "last_wins", "join"):
                score += 15
                reasons.append(f"{key} behavior={behavior}")
                confs.append(_entry_conf(entry, 80))
                flows = list(dict.fromkeys(
                    flows + list(entry.get("evidence_flow_ids") or [])
                ))

    if ctx.location in ("query", "body"):
        score += 5
        reasons.append(f"location={ctx.location} is HPP-relevant")

    return empty_candidate(
        ATTACK_HPP,
        score=score,
        confidence=_avg_conf(*confs),
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_header_injection(ctx: _ProfileView) -> dict[str, Any] | None:
    """Header-based issues: header location / capability + control/CRLF accept."""
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows = ctx.flows_for_classes("control")

    if ctx.has(CAPABILITY_HEADER_INJECTION_SURFACE) or ctx.location == "header":
        score += 40
        reasons.append("parameter is a header injection surface")
        confs.append(85)
    else:
        return None

    if ctx.class_soft_accept("control"):
        score += 30
        reasons.append("control characters accepted in header value")
        confs.append(_entry_conf(ctx.acceptance.get("control"), 80))
    if ctx.class_rejected("control"):
        score -= 20
        reasons.append("negative evidence: control characters rejected")
        confs.append(90)

    # CRLF family keys from validation (Module 7).
    for key in ("crlf", "validation:crlf", "header_crlf"):
        t = ctx.tested.get(key)
        if isinstance(t, dict):
            o = str(t.get("outcome") or "").lower()
            if o in _SOFT_ACCEPT:
                score += 25
                reasons.append(f"CRLF-related probe soft-accepted ({key})")
                confs.append(_entry_conf(t, 80))
                flows = list(dict.fromkeys(flows + list(t.get("evidence_flow_ids") or [])))
            elif o == OUTCOME_REJECTED:
                score -= 15
                reasons.append(f"negative evidence: {key} rejected")
                confs.append(_entry_conf(t, 85))

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_HEADER_INJECTION,
        score=score,
        confidence=_avg_conf(*confs) if confs else 60,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_path_traversal(ctx: _ProfileView) -> dict[str, Any] | None:
    """Path param + path/separator classes accepted."""
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows = ctx.flows_for_classes("path", "separator")

    if ctx.has(CAPABILITY_PATH_PARAMETER) or ctx.location == "path":
        score += 35
        reasons.append("path parameter surface")
        confs.append(85)
    else:
        # Non-path params can still be file-path-like.
        name_hits = _name_tokens_match(
            ctx.name,
            ("path", "file", "filename", "filepath", "dir", "directory", "template"),
        )
        if not name_hits:
            return None
        score += 20
        reasons.append(f"name suggests path/file ({', '.join(name_hits[:3])})")
        confs.append(60)

    if ctx.class_soft_accept("path"):
        score += 25
        reasons.append("path characters (./\\) soft-accepted")
        confs.append(_entry_conf(ctx.acceptance.get("path"), 80))
    if ctx.class_soft_accept("separator"):
        score += 10
        reasons.append("separator characters accepted")

    if ctx.class_rejected("path"):
        score -= 25
        reasons.append("negative evidence: path characters rejected")
        confs.append(90)

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_PATH_TRAVERSAL,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_mass_assignment(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    Mass-assignment-ish: JSON body + duplicate key / extra field parser quirks.
    Lightweight prioritization only.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []

    if ctx.location != "body" and not ctx.has(CAPABILITY_JSON_PARSER):
        return None
    if not (
        ctx.has(CAPABILITY_JSON_PARSER)
        or ctx.has(CAPABILITY_JSON_CONTEXT)
        or ctx.has(CAPABILITY_GRAPHQL_VARIABLE)
    ):
        return None

    score += 20
    reasons.append("JSON/body surface may accept unexpected fields")
    confs.append(50)

    dup = ctx.parser.get("json_duplicate_key") or {}
    if isinstance(dup, dict) and (dup.get("behavior") or dup.get("state")):
        score += 30
        reasons.append(
            f"json_duplicate_key behavior={dup.get('behavior') or dup.get('state')}"
        )
        confs.append(_entry_conf(dup, 75))
        flows = list(dup.get("evidence_flow_ids") or [])

    if ctx.has(CAPABILITY_DUPLICATE_PARAMETER):
        score += 15
        reasons.append("duplicate parameter handling observed")

    name_hits = _name_tokens_match(
        ctx.name,
        ("role", "is_admin", "admin", "privilege", "permission", "user_type"),
    )
    if name_hits:
        score += 25
        reasons.append(f"sensitive-looking field name ({', '.join(name_hits[:3])})")
        confs.append(65)

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_MASS_ASSIGNMENT,
        score=score,
        confidence=_avg_conf(*confs) if confs else 45,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


# Re-export has_capability for consumers that only import candidates.
__all__ = [
    "ATTACK_XSS",
    "ATTACK_SQLI",
    "ATTACK_OPEN_REDIRECT",
    "ATTACK_SSRF",
    "ATTACK_HPP",
    "ATTACK_HEADER_INJECTION",
    "ATTACK_PATH_TRAVERSAL",
    "ATTACK_MASS_ASSIGNMENT",
    "KNOWN_ATTACKS",
    "MIN_EMIT_SCORE",
    "empty_candidate",
    "score_candidates",
    "apply_candidates",
    "enrich_profile_capabilities_and_candidates",
    "get_param_intelligence",
    "list_candidates",
    "format_candidates_lines",
    "has_capability",
]
