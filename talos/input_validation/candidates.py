"""
Module: talos.input_validation.candidates

Purpose:
    Module 11 — **attack candidate scoring** and the stable consumer API
    for attack modules (XSS, SQLi, SSRF, open redirect, webhook abuse,
    OAuth redirect, HPP, header issues).

    Candidates are **prioritization hints**, not confirmed vulnerabilities.
    Attack modules must still verify; IV only ranks where to look first.

    URL Sink Discovery Phase 4 (PR-9): value-first scoring from
    ``url_features`` + ``observed.url_sink`` + capabilities
    (``network_resource_sink`` / redirect_sink / fetch_sink / webhook_sink).
    Flat name-token lists are replaced by the categorized catalog.

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
      "attack": "xss" | "sqli" | "open_redirect" | "ssrf" | "webhook_abuse" |
                "oauth_redirect" | "hpp" | "header_injection" |
                "path_traversal" | "mass_assignment",
      "score": 0-100,           # prioritization strength
      "confidence": 0-100,      # evidence quality for this score
      "reasons": ["..."],
      "evidence_flow_ids": ["..."]
    }

Dependencies:
    talos.input_validation.profile (capability constants)
    talos.input_validation.capabilities (derive/has, url_features resolvers)
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
    resolve_url_features,
    resolve_url_sink,
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
    CAPABILITY_FETCH_SINK,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_NETWORK_RESOURCE_SINK,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_REDIRECT_SINK,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_STORED_REFLECTION,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_WEBHOOK_SINK,
    CAPABILITY_XML_BODY,
)

# ---------------------------------------------------------------------------
# Attack vocabulary (stable consumer contract)
# ---------------------------------------------------------------------------

ATTACK_XSS = "xss"
ATTACK_SQLI = "sqli"
ATTACK_OPEN_REDIRECT = "open_redirect"
ATTACK_SSRF = "ssrf"
ATTACK_WEBHOOK_ABUSE = "webhook_abuse"
ATTACK_OAUTH_REDIRECT = "oauth_redirect"
ATTACK_HPP = "hpp"
ATTACK_HEADER_INJECTION = "header_injection"
ATTACK_PATH_TRAVERSAL = "path_traversal"
ATTACK_MASS_ASSIGNMENT = "mass_assignment"

KNOWN_ATTACKS: frozenset[str] = frozenset({
    ATTACK_XSS,
    ATTACK_SQLI,
    ATTACK_OPEN_REDIRECT,
    ATTACK_SSRF,
    ATTACK_WEBHOOK_ABUSE,
    ATTACK_OAUTH_REDIRECT,
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

# Catalog categories → attack family bias (value still dominates).
_REDIRECT_CATEGORIES: frozenset[str] = frozenset({"redirect"})
_OAUTH_CATEGORIES: frozenset[str] = frozenset({"oauth"})
_WEBHOOK_CATEGORIES: frozenset[str] = frozenset({"webhook"})
_SSRF_CATEGORIES: frozenset[str] = frozenset({
    "remote_fetch",
    "remote_asset",
    "import_metadata",
    "infrastructure",
    "network_probe",
    "webhook",  # webhook also elevates SSRF; dedicated attack is separate
})
# Error classes that imply server-side network processing.
_NETWORK_ERROR_CLASSES: frozenset[str] = frozenset({
    "timeout",
    "connection_refused",
    "dns_lookup_failed",
    "unable_to_fetch",
    "host_unreachable",
})

# Minimum score to include a candidate in the default list (avoid noise).
MIN_EMIT_SCORE = 25

# Parameter-name tokens that often reflect into HTML / JS (XSS / HTMLI).
# Avoid tokens that are substrings of common auth fields (e.g. "name" in username).
_XSS_NAME_TOKENS: tuple[str, ...] = (
    "q",
    "query",
    "search",
    "keyword",
    "comment",
    "message",
    "content",
    "title",
    "html",
    "callback",
    "jsonp",
    "template",
    "caption",
    "bio",
    "about",
    "term",
    "preview",
    "note",
    "slogan",
    "headline",
    "markup",
)

# Parameter-name tokens that often feed a filesystem include / download / template.
_PATH_TRAVERSAL_NAME_TOKENS: tuple[str, ...] = (
    "path",
    "file",
    "filename",
    "filepath",
    "file_path",
    "pathname",
    "dir",
    "directory",
    "folder",
    "template",
    "tpl",
    "layout",
    "include",
    "require",
    "page",
    "document",
    "attachment",
    "download",
    "upload",
    "image",
    "img",
    "asset",
    "resource",
    "content",
    "view",
    "partial",
    "theme",
    "catalog",
    "basepath",
    "docroot",
    "document_root",
    "include_path",
    "static",
)

_PATH_TRAVERSAL_SEMANTIC: frozenset[str] = frozenset({
    "filename",
    "filepath",
    "path",
    "file",
})

_FILE_EXTENSIONS: tuple[str, ...] = (
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phar",
    ".html", ".htm", ".jsp", ".jspx", ".asp", ".aspx", ".ashx",
    ".cfm", ".cgi", ".pl", ".py", ".rb", ".js", ".ts",
    ".css", ".xml", ".json", ".yml", ".yaml", ".ini", ".conf",
    ".config", ".txt", ".log", ".bak", ".old", ".orig",
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".tpl", ".twig", ".ejs", ".hbs", ".mustache", ".erb",
    ".env", ".htaccess", ".htpasswd",
)


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
    reflection_modes: list[str] | None = None,
    stored_reflection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Purpose: Build one candidate dict with clamped score/confidence.
    Side effects: None.

    Optional cross-flow extras (XSS):
        reflection_modes  — e.g. ["same_request", "cross_flow"]
        stored_reflection — sink summary dict for CP/CLI expand
    """
    out: dict[str, Any] = {
        "attack": attack,
        "score": _clamp(score),
        "confidence": _clamp(confidence),
        "reasons": list(reasons or []),
        "evidence_flow_ids": list(evidence_flow_ids or []),
    }
    if reflection_modes is not None:
        out["reflection_modes"] = list(reflection_modes)
    if stored_reflection is not None:
        out["stored_reflection"] = stored_reflection
    return out


def load_and_merge_cross_flow(
    db_path: Path | str,
    profile: dict[str, Any],
    *,
    persist: bool = False,
    links: list[dict[str, Any]] | None = None,
    score: bool = True,
) -> dict[str, Any]:
    """
    Purpose:
        Load ``cross_flow_reflections`` for ``profile['param_uuid']``, merge
        into ``observed.reflection`` (nested same_request / cross_flow), then
        optionally re-derive capabilities + candidates.

    Input:
        db_path  — project SQLite path.
        profile  — mutable param intelligence document.
        persist  — when True, write profile back via ``upsert_param_profile``.
        links    — pre-loaded link rows (skip DB when provided, including []).
        score    — when True (default), apply_capabilities + score_candidates.

    Output:
        The same profile dict (mutated).

    Side effects:
        Mutates profile reflection / capabilities / candidates.
        When persist=True, writes iv_param_profiles.
    """
    if not isinstance(profile, dict):
        return profile

    from talos.projects.value_reflection import (
        ensure_process_cross_flow_config,
        list_cross_flow_reflections,
        merge_cross_flow_reflection,
    )

    path = Path(db_path)
    # Consume-path: install project YAML knobs once (feed_iv, etc.).
    # Ingest paths (worker/replay) already call ensure/set; this is idempotent.
    cfg = ensure_process_cross_flow_config(path.parent)
    # feed_iv gates IV consumption; when False, leave profile unchanged.
    if not cfg.feed_iv:
        if score:
            enrich_profile_capabilities_and_candidates(profile)
        return profile

    param_uuid = str(profile.get("param_uuid") or "").strip()
    resolved_links: list[dict[str, Any]]
    if links is not None:
        resolved_links = list(links)
    elif param_uuid:
        resolved_links = list_cross_flow_reflections(
            path, param_uuid=param_uuid, limit=50,
        )
    else:
        resolved_links = []

    # Merge even with empty links so nested cross_flow block is explicit
    # after recompute (same_request snapshot preserved).
    merge_cross_flow_reflection(profile, resolved_links)

    if score:
        enrich_profile_capabilities_and_candidates(profile)

    if persist and param_uuid:
        from talos.input_validation import db as iv_db

        path = Path(db_path)
        host = str(profile.get("host") or "")
        location = str(profile.get("location") or "")
        name = str(profile.get("name") or "")
        if host and location and name:
            from talos.input_validation.profile import ensure_profile_shape

            iv_db.upsert_param_profile(
                path,
                param_uuid=param_uuid,
                host=host,
                location=location,
                param_name=name,
                profile=ensure_profile_shape(profile),
                bump_version=False,
            )

    return profile


def _should_merge_cross_flow(
    *,
    recompute: bool,
    links: list[dict[str, Any]] | None,
) -> bool:
    """
    Decide whether list/get paths should run load_and_merge_cross_flow.

    - recompute=True → always merge (explicit empty cross_flow when no links).
    - live links present → merge so default CP/list path is not stale after
      proxy-only traffic with an older profile JSON.
    """
    if recompute:
        return True
    return bool(links)


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
        _score_webhook_abuse,
        _score_oauth_redirect,
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
        recompute        — when True, always re-merge cross-flow links and
                           re-score capabilities/candidates (does not persist).
                           When False, still live-merges if cross_flow links
                           exist (parity with list_candidates) so stored
                           reflection is not stale after late proxy traffic.

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

    Side effects: Read-only DB (in-memory merge only; never persists).
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

    # Product decision (§6.3): XSS candidates from stored reflection require
    # an existing iv_param_profiles document. No soft stubs on first link.
    had_profile_doc = profile is not None
    passive_uf = (passive or {}).get("url_features") if passive else None
    if not isinstance(passive_uf, dict):
        passive_uf = {}
    if profile is None:
        # Passive row exists but no synthesized profile yet.
        profile = {
            "param_uuid": param_uuid,
            "host": host,
            "location": location,
            "name": name,
            "capabilities": [],
            "candidates": [],
            "observed": {"url_features": dict(passive_uf)} if passive_uf else {},
            "inferred": {},
            "tested": {},
        }
    else:
        profile = ensure_profile_shape(dict(profile))
        # Inject passive url_features when profile lacks them (Phase 4).
        if passive_uf:
            obs = profile.setdefault("observed", {})
            if not isinstance(obs, dict):
                profile["observed"] = {}
                obs = profile["observed"]
            existing_uf = obs.get("url_features")
            if not isinstance(existing_uf, dict) or not existing_uf:
                obs["url_features"] = dict(passive_uf)

    # Cross-flow merge (P1): only on real profile docs. Parity with
    # list_candidates: merge when recompute=True OR live links exist, so a
    # profile synthesized before proxy traffic still surfaces stored_reflection
    # without requiring recompute/re-synthesize. persist=False (memory only).
    param_uuid = param_uuid or str(profile.get("param_uuid") or "")
    links: list[dict[str, Any]] | None = None
    if had_profile_doc and param_uuid:
        from talos.projects.value_reflection import list_cross_flow_reflections

        links = list_cross_flow_reflections(
            path, param_uuid=param_uuid, limit=50,
        )
    needs_score = (
        recompute
        or not profile.get("candidates")
        or not profile.get("capabilities")
    )
    if had_profile_doc and param_uuid and _should_merge_cross_flow(
        recompute=recompute, links=links,
    ):
        load_and_merge_cross_flow(
            path,
            profile,
            persist=False,
            links=links,
            score=True,
        )
    elif needs_score:
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
            "url_features": (passive or {}).get("url_features") or {},
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

    Side effects: Read-only DB (in-memory merge only; never persists).
    """
    from talos.input_validation import db as iv_db
    from talos.projects.value_reflection import batch_list_cross_flow_reflections

    path = Path(db_path)
    profiles = iv_db.list_param_profiles(path, host=host, limit=max(limit * 2, 500))
    attack_filter = (attack or "").strip().lower() or None
    cap_filter = (capability or "").strip() or None
    rows: list[dict[str, Any]] = []

    # Batched link load (avoid N+1) — design §6.2.
    uuids = [
        str(p.get("param_uuid") or "")
        for p in profiles
        if p.get("param_uuid")
    ]
    links_by_uuid = batch_list_cross_flow_reflections(
        path, uuids, limit_per_param=50,
    ) if uuids else {}

    for prof in profiles:
        work = dict(prof)
        pu = str(work.get("param_uuid") or "")
        links = links_by_uuid.get(pu) or []
        needs_score = (
            recompute
            or not work.get("candidates")
            or not work.get("capabilities")
        )
        if _should_merge_cross_flow(recompute=recompute, links=links):
            load_and_merge_cross_flow(
                path,
                work,
                persist=False,
                links=links,
                score=True,
            )
        elif needs_score:
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
                # Explicit pass-through for CP/CLI stored-reflection UX.
                "reflection_modes": list(cand.get("reflection_modes") or []),
                "stored_reflection": cand.get("stored_reflection"),
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
    Includes reflection_modes and stored sink reasons when present.
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
        modes = c.get("reflection_modes") or []
        mode_suffix = f"  modes={','.join(modes)}" if modes else ""
        lines.append(
            f"{c.get('attack', '?')}: score={c.get('score', 0)}  "
            f"confidence={c.get('confidence', 0)}"
            + mode_suffix
            + (f"  — {reason_txt}" if reason_txt else "")
        )
        stored = c.get("stored_reflection")
        if isinstance(stored, dict):
            sinks = stored.get("sinks") or []
            if isinstance(sinks, list):
                for sink in sinks[:3]:
                    if not isinstance(sink, dict):
                        continue
                    rsn = sink.get("reason")
                    if rsn:
                        lines.append(f"    stored: {rsn}")
                    else:
                        method = sink.get("method") or ""
                        path = sink.get("path") or ""
                        ctx = sink.get("context") or "other"
                        enc = sink.get("encoding") or "raw"
                        lines.append(
                            f"    stored: sink {method} {path} ({ctx}, {enc})".strip()
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
        "url_features", "url_sink", "name_categories",
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
        # URL Sink Discovery Phase 4 — passive + active context for scorers.
        self.url_features = resolve_url_features(profile)
        self.url_sink = resolve_url_sink(profile)
        self.name_categories = _categories_from_features(
            self.url_features, name=self.name,
        )

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


def _profile_example_values(ctx: _ProfileView) -> list[str]:
    """Purpose: Collect observed / passive example strings for value-first scoring."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(raw: object) -> None:
        if raw is None:
            return
        if isinstance(raw, (list, tuple, set)):
            for item in raw:
                _add(item)
            return
        text = str(raw).strip()
        if not text or text in seen:
            return
        seen.add(text)
        out.append(text)

    inferred = ctx.profile.get("inferred") or {}
    if isinstance(inferred, dict):
        passive = inferred.get("passive") or {}
        if isinstance(passive, dict):
            _add(passive.get("examples"))
            _add(passive.get("example_values"))
            _add(passive.get("sample"))
    _add(ctx.obs.get("examples"))
    _add(ctx.obs.get("example_values"))
    _add(ctx.obs.get("values"))
    return out


def _filesystem_path_reasons(values: list[str]) -> list[str]:
    """
    Purpose:
        Describe why captured values look like filesystem / LFI inputs.
    Output:
        Reason tokens (empty when nothing looks path-like).
    """
    reasons: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = (value or "").strip()
        if not text:
            continue
        lower = text.lower()
        hits: list[str] = []
        if ".." in text and ("/" in text or "\\" in text):
            hits.append("dot-dot traversal")
        if lower.startswith("file:"):
            hits.append("file:// URI")
        if lower.startswith("php://") or lower.startswith("zip://") or lower.startswith("phar://"):
            hits.append("PHP wrapper")
        if len(text) >= 3 and (text[1:3] in (":\\", ":/") or text.startswith("\\\\")):
            hits.append("windows path")
        if text.startswith("/") and ("/" in text[1:] or any(lower.endswith(ext) for ext in _FILE_EXTENSIONS)):
            hits.append("unix-style path")
        if any(
            lower.endswith(ext) or f"{ext}?" in lower or f"{ext}#" in lower
            for ext in _FILE_EXTENSIONS
        ):
            hits.append("file extension")
        if any(
            token in lower
            for token in (
                "/etc/",
                "/proc/",
                "/var/www",
                "/windows/",
                "\\windows\\",
                "win.ini",
                "web.config",
                "inetpub",
            )
        ):
            hits.append("well-known filesystem prefix")
        for hit in hits:
            if hit not in seen:
                seen.add(hit)
                reasons.append(hit)
    return reasons


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


def _categories_from_features(
    url_features: dict[str, Any],
    *,
    name: str = "",
) -> set[str]:
    """
    Purpose: Collect name_category / name_categories; fall back to classify_name.
    Side effects: None.
    """
    cats: set[str] = set()
    primary = url_features.get("name_category") if isinstance(url_features, dict) else None
    if primary:
        cats.add(str(primary).lower())
    for c in (url_features.get("name_categories") or []) if isinstance(url_features, dict) else []:
        if c:
            cats.add(str(c).lower())
    if name and not cats:
        try:
            from talos.url_sink.name_classify import classify_name

            nf = classify_name(name)
            if nf.name_category:
                cats.add(str(nf.name_category).lower())
            for c in nf.name_categories or ():
                cats.add(str(c).lower())
        except Exception:
            pass
    return cats


def _passive_url_score(url_features: dict[str, Any] | None) -> int:
    if not isinstance(url_features, dict):
        return 0
    try:
        return max(0, min(100, int(url_features.get("score") or 0)))
    except (TypeError, ValueError):
        return 0


def _has_url_evidence(ctx: _ProfileView) -> bool:
    """
    Purpose:
        True when there is value/behavior/accept evidence beyond bare name.
        Used to gate spam and to bias value-first scoring.

        Does **not** treat name-derived capabilities alone as evidence
        (redirect_sink / webhook_sink require measured signals now).
    """
    us = ctx.url_sink
    uf = ctx.url_features
    if ctx.type_soft_accept("url"):
        return True
    # Primary type url from synthesis (measured or passive-confirmed).
    summary = ctx.types.get("_summary") if isinstance(ctx.types, dict) else None
    if isinstance(summary, dict) and str(summary.get("primary") or "").lower() == "url":
        return True
    if any(
        us.get(k) is True
        for k in (
            "accepts_url",
            "accepts_hostname",
            "accepts_ip",
            "accepts_protocol",
            "redirect_behavior",
            "fetch_behavior",
            "dns_resolution_detected",
        )
    ):
        return True
    if ctx.has(CAPABILITY_FETCH_SINK):
        return True
    if uf.get("possible_network_resource") is True:
        return True
    if _passive_url_score(uf) >= 45:
        return True
    # Measured baseline redirect only counts with other signals handled above;
    # bare redirect_like alone is weak — still allow with redirect_behavior.
    if ctx.has(CAPABILITY_REDIRECT_LIKE) and (
        us.get("redirect_behavior") is True
        or ctx.type_soft_accept("url")
        or _passive_url_score(uf) >= 45
    ):
        return True
    if ctx.semantic in ("url", "uri"):
        return True
    return False


def _url_type_accepted(ctx: _ProfileView) -> bool:
    """True when type probe soft-accepted URL or url_sink accepts absolute URL form."""
    if ctx.type_soft_accept("url"):
        return True
    if ctx.url_sink.get("accepts_url") is True:
        return True
    return False


def _url_accept_boost(
    ctx: _ProfileView,
    reasons: list[str],
    confs: list[int],
) -> int:
    """
    Purpose:
        Shared +score for **measured** URL acceptance only (type soft-accept
        or url_sink accepts_*). Does **not** treat passive url_like_value alias
        / NRS as acceptance — those use value-first / NRS score paths instead.
    Output: score delta (0 if none).
    """
    us = ctx.url_sink
    boost = 0
    if ctx.type_soft_accept("url"):
        boost = max(boost, 28)
        if "accepts URL-shaped input" not in reasons:
            reasons.append("accepts URL-shaped input")
        confs.append(_entry_conf(ctx.types.get("url"), 80))
    if us.get("accepts_url") is True:
        boost = max(boost, 30)
        if "url_sink accepts_url" not in " ".join(reasons):
            reasons.append("url_sink accepts_url (canary form accepted)")
        confs.append(_clamp(us.get("confidence") or 80))
    elif us.get("accepts_hostname") is True or us.get("accepts_ip") is True:
        boost = max(boost, 22)
        form = "hostname" if us.get("accepts_hostname") else "ip"
        reasons.append(f"url_sink accepts_{form}")
        confs.append(_clamp(us.get("confidence") or 75))
    return boost


def _url_flows(ctx: _ProfileView) -> list[str]:
    """Collect evidence_flow_ids from type url + url_sink per_probe."""
    flows: list[str] = []
    url_entry = ctx.types.get("url")
    if isinstance(url_entry, dict):
        for fid in url_entry.get("evidence_flow_ids") or []:
            s = str(fid)
            if s and s not in flows:
                flows.append(s)
    us = ctx.url_sink
    per = us.get("per_probe") if isinstance(us, dict) else None
    if isinstance(per, dict):
        for entry in per.values():
            if not isinstance(entry, dict):
                continue
            for fid in entry.get("evidence_flow_ids") or []:
                s = str(fid)
                if s and s not in flows:
                    flows.append(s)
            fid = entry.get("flow_id")
            if fid:
                s = str(fid)
                if s and s not in flows:
                    flows.append(s)
    return flows


# ---------------------------------------------------------------------------
# Per-attack scorers
# ---------------------------------------------------------------------------

def _score_xss(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    XSS candidate: reflection (same-request and/or cross-flow/stored) +
    HTML/JS/attr context + markup/quote accepted.

    Stored / cross-page evidence satisfies the reflection gate and contributes
    ordered reasons naming source and sink endpoints. Prioritization only —
    not XSS confirmation (that is ``talos attack xss``).
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []  # positive contributing confidences only
    flows = ctx.flows_for_classes("markup", "quote")

    cross = ctx.refl.get("cross_flow") if isinstance(ctx.refl.get("cross_flow"), dict) else {}
    same = ctx.refl.get("same_request") if isinstance(ctx.refl.get("same_request"), dict) else {}
    modes = list(ctx.refl.get("modes") or [])

    cross_state = str(cross.get("state") or "").lower()
    same_state = str(same.get("state") or "").lower()
    top_state = str(ctx.refl.get("state") or "").lower()

    stored = (
        ctx.has(CAPABILITY_STORED_REFLECTION)
        or cross_state == "reflected"
    )
    reflected = (
        ctx.has(CAPABILITY_REFLECTIVE_INPUT)
        or top_state == "reflected"
        or same_state == "reflected"
        or stored
    )

    # Build stored sink reasons (canonical format) — max 2 for reasons[0..].
    stored_reasons: list[str] = []
    stored_sinks_out: list[dict[str, Any]] = []
    if stored:
        sinks = list(cross.get("sinks") or [])
        for sink in sinks[:2]:
            if not isinstance(sink, dict):
                continue
            reason = str(sink.get("reason") or "").strip()
            if not reason:
                from talos.projects.value_reflection import format_cross_flow_reason

                # Sink shape may use sink_* keys from profile merge.
                reason = format_cross_flow_reason({
                    "source_param_name": ctx.name or "param",
                    "source_method": sink.get("source_method") or "",
                    "source_path": sink.get("source_path") or "",
                    "source_location": ctx.location or "",
                    "sink_method": sink.get("sink_method") or sink.get("method") or "",
                    "sink_path": sink.get("sink_path") or sink.get("path") or "",
                    "sink_context": sink.get("context") or sink.get("sink_context") or "other",
                    "encoding": sink.get("encoding") or "raw",
                })
            if reason:
                stored_reasons.append(reason)
            stored_sinks_out.append({
                "method": sink.get("sink_method") or sink.get("method") or "",
                "path": sink.get("sink_path") or sink.get("path") or "",
                "endpoint_id": sink.get("sink_endpoint_id") or sink.get("endpoint_id"),
                "flow_id": sink.get("sink_flow_id") or sink.get("flow_id"),
                "context": sink.get("context") or sink.get("sink_context") or "other",
                "encoding": sink.get("encoding") or "raw",
                "reason": reason,
            })
        # Evidence from cross_flow / top-level.
        for fid in list(cross.get("evidence_flow_ids") or []) + list(
            ctx.refl.get("evidence_flow_ids") or []
        ):
            s = str(fid)
            if s and s not in flows:
                flows.append(s)
        cross_conf = _clamp(cross.get("confidence") or 0)
        if cross_conf > 0:
            confs.append(cross_conf)
        elif stored:
            confs.append(70)

    # Reflection modes for candidate extras.
    reflection_modes: list[str] = list(modes)
    if not reflection_modes:
        if same_state in ("reflected", "not_reflected", "conflicting"):
            reflection_modes.append("same_request")
        if cross_state in ("reflected", "not_reflected", "conflicting"):
            reflection_modes.append("cross_flow")
        if reflected and not reflection_modes:
            # Legacy profiles without nested modes: same-request only.
            reflection_modes.append("same_request")

    # --- Score components ------------------------------------------------
    if reflected:
        score += 30
        # Confidence: prefer stored link conf when top-level is stored-only;
        # do not average multiprobe "not_reflected" confidence.
        if stored and same_state != "reflected":
            # confs already has cross conf above
            pass
        else:
            confs.append(_entry_conf(ctx.refl, 70))
        flows = list(dict.fromkeys(
            flows + list(ctx.refl.get("evidence_flow_ids") or [])
        ))

    if stored:
        score += 12  # once per candidate

    if ctx.has(CAPABILITY_HTML_CONTEXT):
        score += 25
        confs.append(75)
    if ctx.has(CAPABILITY_JS_CONTEXT):
        score += 22
        confs.append(75)

    name_hits = _name_tokens_match(ctx.name, _XSS_NAME_TOKENS)
    if name_hits:
        score += 10
        confs.append(60)

    contexts: list[str] = []
    for blob in (ctx.refl, same, cross):
        if isinstance(blob, dict):
            contexts.extend(str(item).lower() for item in (blob.get("contexts") or []))
    if any(item in ("attr", "attribute", "html_attr", "event") for item in contexts):
        score += 12
        confs.append(70)
    if ctx.has(CAPABILITY_URL_CONTEXT) and reflected:
        score += 8
    if ctx.has(CAPABILITY_JSON_CONTEXT) and reflected:
        score += 5

    markup_ok = ctx.class_soft_accept("markup")
    quote_ok = ctx.class_soft_accept("quote")
    if markup_ok:
        score += 28
        confs.append(_entry_conf(ctx.acceptance.get("markup"), 80))
    if quote_ok:
        score += 12
        confs.append(_entry_conf(ctx.acceptance.get("quote"), 75))

    if ctx.class_rejected("markup"):
        score -= 20
        # Negative evidence is not a positive conf contributor.
    if ctx.class_rejected("quote"):
        score -= 8

    # Strong pattern: reflected HTML + accepts <>
    high_priority = False
    if reflected and ctx.has(CAPABILITY_HTML_CONTEXT) and markup_ok:
        score = max(score, 85)
        high_priority = True

    # Stored + html without markup tests → prioritization floor.
    if stored and ctx.has(CAPABILITY_HTML_CONTEXT) and not markup_ok:
        score = max(score, 55)

    if not reflected and score < 40:
        # Without reflection, XSS candidate is weak noise.
        return None

    # --- Reason ordering (CP uses reasons[0]) ----------------------------
    # 1. Stored canonical reasons first (stored-only default), unless
    #    high-priority same-request pattern takes index 0.
    # 2. "input is reflected in responses"
    # 3. Context reasons
    # 4. Acceptance
    # 5. Negative evidence
    ordered: list[str] = []

    if high_priority:
        ordered.append("high-priority: reflected HTML with markup accepted")
        for r in stored_reasons:
            if r not in ordered:
                ordered.append(r)
    else:
        for r in stored_reasons:
            ordered.append(r)

    if reflected:
        ordered.append("input is reflected in responses")

    if ctx.has(CAPABILITY_HTML_CONTEXT):
        ordered.append("reflection context includes html")
    if ctx.has(CAPABILITY_JS_CONTEXT):
        ordered.append("reflection context includes javascript")
    if name_hits:
        ordered.append(f"name suggests reflected HTML ({', '.join(name_hits[:3])})")
    if any(item in ("attr", "attribute", "html_attr", "event") for item in contexts):
        ordered.append("reflection context includes html attribute / event")
    if ctx.has(CAPABILITY_URL_CONTEXT) and reflected:
        ordered.append("reflection in url context")
    if ctx.has(CAPABILITY_JSON_CONTEXT) and reflected:
        ordered.append("reflection in json context (lower XSS relevance)")

    if markup_ok:
        ordered.append("markup characters (e.g. <>) accepted")
    if quote_ok:
        ordered.append("quote characters accepted")
    if ctx.class_rejected("markup"):
        ordered.append("negative evidence: markup rejected")
    if ctx.class_rejected("quote"):
        ordered.append("negative evidence: quotes rejected")

    # When reflective_input is solely via cross_flow, at least one stored
    # reason is required (design §7).
    if stored and same_state != "reflected" and not stored_reasons:
        # Fallback generic stored reason if sinks missing reason text.
        ordered.insert(0, "stored/cross-page reflection observed")

    stored_block: dict[str, Any] | None = None
    if stored:
        stored_block = {
            "link_count": int(cross.get("link_count") or len(stored_sinks_out) or 0),
            "sinks": stored_sinks_out,
        }

    return empty_candidate(
        ATTACK_XSS,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=ordered,
        evidence_flow_ids=flows[:20],
        reflection_modes=reflection_modes,
        stored_reflection=stored_block,
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
    """
    open_redirect: requires a redirect-shaped signal (name category redirect/
    oauth, redirect_behavior, or baseline redirect_like) **plus** network
    resource evidence. Pure URL-accept params without redirect signals go to
    SSRF / network_resource_sink instead (QA-USD-13 noise reduction).
    Name-only catalog hits (go/to/next) do **not** emit without URL evidence.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []

    cats = ctx.name_categories
    redir_cat = bool(cats & _REDIRECT_CATEGORIES)
    oauth_cat = bool(cats & _OAUTH_CATEGORIES)
    url_ev = _has_url_evidence(ctx)
    us = ctx.url_sink
    uf = ctx.url_features
    type_rejected = ctx.type_rejected("url")

    # Spam gate: require value/behavior/accept evidence (not bare name).
    if not url_ev:
        return None

    # Redirect-signal gate: do not emit open_redirect for every URL-accept param.
    has_redirect_signal = (
        redir_cat
        or oauth_cat
        or us.get("redirect_behavior") is True
        or ctx.has(CAPABILITY_REDIRECT_LIKE)
        or ctx.has(CAPABILITY_REDIRECT_SINK)
    )
    if not has_redirect_signal:
        return None

    if redir_cat:
        score += 35
        reasons.append(
            f"name category suggests redirect ({', '.join(sorted(cats & _REDIRECT_CATEGORIES))})"
        )
        confs.append(70)
    elif oauth_cat:
        # OAuth params also redirect-shaped; dedicated attack is separate.
        score += 18
        reasons.append("oauth name category (also open-redirect relevant)")
        confs.append(65)

    if ctx.has(CAPABILITY_REDIRECT_SINK):
        score += 18
        reasons.append("capability redirect_sink")
        confs.append(75)

    if ctx.has(CAPABILITY_REDIRECT_LIKE) or us.get("redirect_behavior") is True:
        score += 30
        if us.get("redirect_behavior") is True:
            reasons.append("URL sink redirect_behavior (Location/canary)")
            confs.append(85)
        else:
            reasons.append("baseline response is redirect-like")
            confs.append(80)
        fp = ctx.obs.get("baseline_fingerprint") or {}
        if isinstance(fp, dict):
            flows = list(dict.fromkeys(flows + ctx.flows_from(fp)))

    url_accept = _url_accept_boost(ctx, reasons, confs)
    score += url_accept
    flows = list(dict.fromkeys(flows + _url_flows(ctx)))

    # Value-first: high passive URL score without name catalog hit.
    passive_score = _passive_url_score(uf)
    if passive_score >= 45 and not redir_cat:
        boost = 22 if passive_score >= 90 else 15
        score += boost
        reasons.append(
            f"value-first url_features.score={passive_score} (no redirect name required)"
        )
        confs.append(min(90, passive_score))

    if ctx.semantic in ("url", "uri", "redirect"):
        score += 12
        reasons.append(f"semantic_type={ctx.semantic}")
        confs.append(75)

    if type_rejected:
        score -= 25
        reasons.append("negative evidence: URL type rejected")
        confs.append(85)

    # High-priority only when measured accept and not hard-rejected.
    if (
        not type_rejected
        and redir_cat
        and _url_type_accepted(ctx)
    ):
        score = max(score, 80)
        reasons.append("high-priority: redirect category + URL acceptance")

    # Redirect-only behavior should beat generic SSRF when both present.
    if (
        not type_rejected
        and us.get("redirect_behavior") is True
        and us.get("fetch_behavior") is not True
    ):
        score = min(100, score + 5)
        if "redirect-biased over fetch" not in " ".join(reasons):
            reasons.append("redirect-biased: Location behavior without fetch")

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_OPEN_REDIRECT,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_ssrf(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    SSRF candidate: network_resource_sink + fetch/DNS/timeout **or** strong
    remote name category + URL accept. Value-first: random name + URL value.
    Name-only catalog hits do **not** emit without URL/value/behavior evidence.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []

    cats = ctx.name_categories
    ssrf_cats = cats & _SSRF_CATEGORIES
    redir_cat = bool(cats & _REDIRECT_CATEGORIES)
    us = ctx.url_sink
    uf = ctx.url_features
    url_ev = _has_url_evidence(ctx)
    type_rejected = ctx.type_rejected("url")
    passive_score = _passive_url_score(uf)

    # Spam gate: bare name categories (webhook, url, …) without value/accept.
    if not url_ev:
        return None

    if ssrf_cats:
        score += 32
        reasons.append(
            f"name category suggests server-side URL sink ({', '.join(sorted(ssrf_cats)[:4])})"
        )
        confs.append(70)

    if ctx.has(CAPABILITY_NETWORK_RESOURCE_SINK):
        score += 20
        reasons.append("capability network_resource_sink")
        confs.append(80)

    if ctx.has(CAPABILITY_FETCH_SINK) or us.get("fetch_behavior") is True:
        score += 28
        reasons.append("fetch_behavior / fetch_sink (server-side processing)")
        confs.append(85)
    if us.get("dns_resolution_detected") is True:
        score += 18
        reasons.append("dns_resolution_detected on URL canary")
        confs.append(80)
    err = {str(e).lower() for e in (us.get("error_classes") or []) if e}
    net_errs = err & _NETWORK_ERROR_CLASSES
    if net_errs:
        score += 15
        reasons.append(f"network error classes: {', '.join(sorted(net_errs)[:4])}")
        confs.append(75)

    url_accept = _url_accept_boost(ctx, reasons, confs)
    score += url_accept
    flows = list(dict.fromkeys(flows + _url_flows(ctx)))

    # Value-first: high passive URL score without name catalog hit.
    if passive_score >= 45 and not ssrf_cats:
        boost = 30 if passive_score >= 90 else 20
        score += boost
        reasons.append(
            f"value-first url_features.score={passive_score} (name-independent SSRF priority)"
        )
        confs.append(min(92, passive_score))
    elif passive_score >= 90 and ssrf_cats:
        score += 8
        reasons.append(f"strong URL-shaped value (score={passive_score})")
        confs.append(85)

    if ctx.semantic in ("url", "uri", "callback", "webhook"):
        score += 12
        reasons.append(f"semantic_type={ctx.semantic}")

    # When redirect_behavior dominates and no fetch/DNS, soft-downweight SSRF
    # so open_redirect ranks higher for pure redirect sinks.
    if (
        us.get("redirect_behavior") is True
        and us.get("fetch_behavior") is not True
        and not net_errs
        and not us.get("dns_resolution_detected")
        and redir_cat
        and not ssrf_cats
    ):
        score -= 12
        reasons.append("redirect-only behavior: SSRF priority reduced")

    if type_rejected:
        score -= 30
        reasons.append("negative evidence: URL type rejected")
        confs.append(90)

    # Path params rarely SSRF surfaces unless named fetch-like / network resource.
    if ctx.location == "path" and not ssrf_cats and not ctx.has(CAPABILITY_NETWORK_RESOURCE_SINK):
        score -= 10

    # High-priority floors only when measured accept and not hard-rejected
    # (must not undo rejection penalty).
    if not type_rejected:
        if ssrf_cats and _url_type_accepted(ctx):
            score = max(score, 78)
            reasons.append("high-priority: SSRF category + URL type accepted")

        # network_resource_sink + fetch/DNS without name → strong value-first floor.
        if ctx.has(CAPABILITY_NETWORK_RESOURCE_SINK) and (
            ctx.has(CAPABILITY_FETCH_SINK)
            or us.get("fetch_behavior") is True
            or us.get("dns_resolution_detected") is True
            or net_errs
        ):
            score = max(score, 72)
            if "high-priority: network_resource_sink + fetch/DNS" not in reasons:
                reasons.append("high-priority: network_resource_sink + fetch/DNS evidence")

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_SSRF,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_webhook_abuse(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    webhook_abuse: callback/webhook category + fetch_behavior (or URL accept).
    Name alone does not emit.
    """
    cats = ctx.name_categories
    if not (cats & _WEBHOOK_CATEGORIES) and not ctx.has(CAPABILITY_WEBHOOK_SINK):
        return None

    # Require URL/value/fetch evidence — name-only webhook is not enough.
    if not _has_url_evidence(ctx) and not ctx.has(CAPABILITY_FETCH_SINK):
        return None

    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []
    us = ctx.url_sink
    type_rejected = ctx.type_rejected("url")

    if cats & _WEBHOOK_CATEGORIES:
        score += 35
        reasons.append(
            f"webhook/callback name category ({', '.join(sorted(cats & _WEBHOOK_CATEGORIES))})"
        )
        confs.append(75)
    if ctx.has(CAPABILITY_WEBHOOK_SINK):
        score += 15
        reasons.append("capability webhook_sink")
        confs.append(80)

    if us.get("fetch_behavior") is True or ctx.has(CAPABILITY_FETCH_SINK):
        score += 30
        reasons.append("fetch_behavior suggests server-side callback delivery")
        confs.append(85)
    else:
        # Without fetch, still score when URL is accepted (soft webhook surface).
        url_accept = _url_accept_boost(ctx, reasons, confs)
        score += url_accept
        if url_accept == 0 and _passive_url_score(ctx.url_features) < 45:
            # Category + weak passive only — do not spam.
            return None

    flows = list(dict.fromkeys(flows + _url_flows(ctx)))

    if ctx.has(CAPABILITY_NETWORK_RESOURCE_SINK):
        score += 10
        reasons.append("network_resource_sink present")

    if type_rejected:
        score -= 20
        reasons.append("negative evidence: URL type rejected")

    if (
        not type_rejected
        and (cats & _WEBHOOK_CATEGORIES)
        and (us.get("fetch_behavior") is True or ctx.has(CAPABILITY_FETCH_SINK))
    ):
        score = max(score, 75)
        reasons.append("high-priority: webhook category + fetch_behavior")

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_WEBHOOK_ABUSE,
        score=score,
        confidence=_avg_conf(*confs) if confs else 55,
        reasons=reasons,
        evidence_flow_ids=flows[:20],
    )


def _score_oauth_redirect(ctx: _ProfileView) -> dict[str, Any] | None:
    """
    oauth_redirect: oauth / redirect_uri-like name + redirect/URL evidence.
    Name alone does not emit.
    """
    cats = ctx.name_categories
    us = ctx.url_sink
    oauth = bool(cats & _OAUTH_CATEGORIES)
    # Also treat redirect_uri-style leaf names via category; catalog owns aliases.
    if not oauth and not (
        "redirect_uri" in ctx.name.lower().replace("-", "_")
        or "return_uri" in ctx.name.lower().replace("-", "_")
    ):
        return None
    if not oauth:
        oauth = True  # name substring matched

    # Require measured URL/redirect evidence.
    if not _has_url_evidence(ctx):
        return None

    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows: list[str] = []
    type_rejected = ctx.type_rejected("url")

    score += 35
    reasons.append("oauth / redirect_uri-like parameter name")
    confs.append(75)

    if us.get("redirect_behavior") is True or ctx.has(CAPABILITY_REDIRECT_SINK):
        score += 30
        reasons.append("redirect_behavior / redirect_sink on OAuth-like param")
        confs.append(85)
    elif ctx.has(CAPABILITY_REDIRECT_LIKE):
        score += 22
        reasons.append("baseline redirect-like response")
        confs.append(75)

    url_accept = _url_accept_boost(ctx, reasons, confs)
    score += url_accept
    flows = list(dict.fromkeys(flows + _url_flows(ctx)))

    if type_rejected:
        score -= 20
        reasons.append("negative evidence: URL type rejected")

    if not type_rejected and oauth and (
        us.get("redirect_behavior") is True
        or _url_type_accepted(ctx)
    ):
        score = max(score, 78)
        reasons.append("high-priority: oauth name + redirect/URL acceptance")

    if score < MIN_EMIT_SCORE:
        return None

    return empty_candidate(
        ATTACK_OAUTH_REDIRECT,
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
    """
    Rank LFI / path-traversal surfaces.

    Gates (any one is enough to continue):
        path parameter / location=path, multipart filename, LFI-ish name,
        filename semantic type, or an observed value that looks like a
        filesystem path. Confirmation is the path-traversal attack module;
        IV only ranks where to look.
    """
    score = 0
    reasons: list[str] = []
    confs: list[int] = []
    flows = ctx.flows_for_classes("path", "separator", "null")
    gated = False

    if ctx.has(CAPABILITY_PATH_PARAMETER) or ctx.location == "path":
        score += 35
        reasons.append("path parameter surface")
        confs.append(85)
        gated = True

    if ctx.has(CAPABILITY_MULTIPART_FILENAME):
        score += 35
        reasons.append("multipart filename surface")
        confs.append(80)
        gated = True

    name_hits = _name_tokens_match(ctx.name, _PATH_TRAVERSAL_NAME_TOKENS)
    if name_hits:
        score += 20
        reasons.append(f"name suggests path/file ({', '.join(name_hits[:3])})")
        confs.append(60)
        gated = True

    if ctx.semantic in _PATH_TRAVERSAL_SEMANTIC:
        score += 20
        reasons.append(f"semantic type {ctx.semantic} is file-path-like")
        confs.append(65)
        gated = True

    value_hits = _filesystem_path_reasons(_profile_example_values(ctx))
    if value_hits:
        score += 25
        reasons.append(f"value looks like a file path ({value_hits[0]})")
        confs.append(70)
        gated = True

    if not gated:
        return None

    if ctx.class_soft_accept("path"):
        score += 25
        reasons.append("path characters (./\\) soft-accepted")
        confs.append(_entry_conf(ctx.acceptance.get("path"), 80))
    if ctx.class_soft_accept("separator"):
        score += 10
        reasons.append("separator characters accepted")
    if ctx.class_soft_accept("null"):
        score += 10
        reasons.append("null byte soft-accepted (classic LFI truncation)")
        confs.append(_entry_conf(ctx.acceptance.get("null"), 70))

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
    "ATTACK_WEBHOOK_ABUSE",
    "ATTACK_OAUTH_REDIRECT",
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
    "load_and_merge_cross_flow",
    "get_param_intelligence",
    "list_candidates",
    "format_candidates_lines",
    "has_capability",
]
