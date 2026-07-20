"""
Module: talos.projects.policy_score

Purpose:
    Compute an automatic priority score for an endpoint based on security-impact
    heuristics.  The score estimates: "if this endpoint is vulnerable, how
    valuable is that finding?"  This deliberately favours impact over
    exploitability so that high-value targets — payment flows, admin endpoints,
    permission management — rank ahead of low-value assets like static files
    and health checks.

    Scoring is additive: every signal contributes a signed integer delta.
    The final raw score maps to a named priority level:
        CRITICAL  — score >= CRITICAL_THRESHOLD  (default 100)
        HIGH      — score >= HIGH_THRESHOLD       (default 70)
        NORMAL    — score >= NORMAL_THRESHOLD     (default 40)
        LOW       — anything below NORMAL

    Every scoring decision is recorded in a contributors dict so the result is
    fully explainable.  Example output:

        Auto Priority: HIGH (Score: 92)

        Contributors:
          +60  DELETE method
          +15  UUID path parameter
          +30  /admin path keyword
          +15  Authorization header observed
          -28  normalisation floor
        Final Score: 92

    Score config can be customised per project via policy_score.json in the
    project directory.  If the file is absent the built-in defaults are used.

    Input to compute_auto_priority():
        method                — HTTP method string (e.g. "DELETE").
        normalized_path       — canonical path (e.g. "/users/{id}/role").
        response_content_type — value of the response Content-Type header.
        auth_required         — True when request carried auth material.
        roles_seen_count      — number of distinct roles that have hit this endpoint.
        total_roles           — total roles defined in the project.
        parameter_names       — list of observed query/body parameter names.
        request_content_type  — request Content-Type (for body type scoring).

    Output:
        tuple(score: int, level: str, contributors: dict[str, int])

Dependencies: re, json, pathlib
Data flow:
    policy.py → compute_auto_priority() → (score, level, contributors dict)
    worker.py → compute_auto_priority() → stored in endpoint_policy
Side effects: None — pure functions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# ------------------------------------------------------------------ #
# Default score thresholds                                             #
# ------------------------------------------------------------------ #

DEFAULT_CRITICAL_THRESHOLD: int = 100
DEFAULT_HIGH_THRESHOLD: int = 70
DEFAULT_NORMAL_THRESHOLD: int = 40

# ------------------------------------------------------------------ #
# HTTP method scores                                                   #
# ------------------------------------------------------------------ #

_METHOD_SCORES: dict[str, int] = {
    "DELETE":  60,
    "PATCH":   50,
    "PUT":     45,
    "POST":    35,
    "GET":     15,
    "HEAD":     5,
    "OPTIONS":  0,
}

# ------------------------------------------------------------------ #
# Sensitive path keyword scores                                        #
# Each keyword is matched as a path segment or segment prefix.        #
# ------------------------------------------------------------------ #

_PATH_KEYWORD_SCORES: dict[str, int] = {
    "admin":          50,
    "user":           30,
    "users":          30,
    "account":        30,
    "profile":        20,
    "role":           40,
    "roles":          40,
    "permission":     45,
    "permissions":    45,
    "group":          25,
    "groups":         25,
    "payment":        50,
    "payments":       50,
    "billing":        45,
    "invoice":        35,
    "invoices":       35,
    "transfer":       60,
    "bank":           60,
    "wallet":         55,
    "order":          35,
    "orders":         35,
    "customer":       30,
    "customers":      30,
    "export":         50,
    "import":         45,
    "reset-password": 60,
    "password":       50,
    "session":        40,
    "sessions":       40,
    "token":          40,
    "tokens":         40,
    "oauth":          40,
    "api-key":        50,
    "api_key":        50,
    "key":            30,
    "webhook":        35,
    "webhooks":       35,
    "graphql":        25,
}

# ------------------------------------------------------------------ #
# Endpoint naming keywords — action verbs in path segments            #
# ------------------------------------------------------------------ #

_ENDPOINT_NAMING_SCORES: dict[str, int] = {
    "create":     20,
    "update":     20,
    "delete":     30,
    "remove":     30,
    "approve":    40,
    "reject":     35,
    "assign":     25,
    "invite":     30,
    "promote":    40,
    "demote":     40,
    "grant":      50,
    "revoke":     50,
    "activate":   25,
    "deactivate": 30,
    "disable":    25,
    "enable":     20,
    "merge":      25,
    "clone":      15,
    "copy":       15,
}

# ------------------------------------------------------------------ #
# Business operation keywords                                          #
# ------------------------------------------------------------------ #

_BUSINESS_KEYWORD_SCORES: dict[str, int] = {
    "checkout": 50,
    "purchase": 50,
    "refund":   55,
    "payroll":  60,
    "salary":   60,
    "employee": 35,
    "finance":  45,
    "report":   35,
    "audit":    35,
}

# ------------------------------------------------------------------ #
# Low-priority path signals (subtracted)                              #
# ------------------------------------------------------------------ #

_LOW_PRIORITY_PATH_SIGNALS: dict[str, int] = {
    "favicon":    -80,
    "robots.txt": -80,
    "health":     -80,
    "ping":       -70,
    "status":     -70,
    "version":    -40,
    "theme":      -50,
    "assets":     -70,
    "static":     -70,
    "css":        -70,
    "js":         -70,
    "font":       -70,
    "fonts":      -70,
    "image":      -70,
    "images":     -70,
    "logo":       -70,
    "avatar":     -40,
    "analytics":  -40,
    "telemetry":  -40,
    "metrics":    -60,
    "swagger":    -40,
    "openapi":    -40,
    "docs":       -30,
}

# ------------------------------------------------------------------ #
# Static file extension scores (subtracted)                           #
# ------------------------------------------------------------------ #

_STATIC_EXTENSION_SCORES: dict[str, int] = {
    ".css":  -80,
    ".js":   -80,
    ".png":  -80,
    ".jpg":  -80,
    ".jpeg": -80,
    ".gif":  -80,
    ".svg":  -80,
    ".ico":  -80,
    ".woff": -80,
    ".woff2": -80,
    ".ttf":  -80,
    ".map":  -60,
}

# ------------------------------------------------------------------ #
# Response content-type scores                                         #
# ------------------------------------------------------------------ #

_RESPONSE_CONTENT_TYPE_SCORES: dict[str, int] = {
    "application/json":   10,
    "application/octet-stream": 15,
    "text/csv":           35,
    "application/pdf":    30,
    "application/zip":    40,
    "application/vnd.openxmlformats-officedocument": 30,  # xlsx, docx
}

_RESPONSE_CONTENT_TYPE_PENALTIES: dict[str, int] = {
    "text/css":             -70,
    "image/":               -70,  # prefix match
    "font/":                -70,  # prefix match
    "application/javascript": -70,
    "text/javascript":      -70,
}

# ------------------------------------------------------------------ #
# File download / export response signal                               #
# ------------------------------------------------------------------ #

_RESPONSE_DOWNLOAD_SCORE: int = 35  # applied when response suggests file download

# ------------------------------------------------------------------ #
# Authentication signals                                               #
# ------------------------------------------------------------------ #

_AUTH_SCORE: int = 15  # applied when auth_required is True

# ------------------------------------------------------------------ #
# Role visibility scores                                               #
# ------------------------------------------------------------------ #

_MULTI_ROLE_SCORE: int = 15   # seen by multiple roles
_ADMIN_ONLY_SCORE: int = 35   # seen only by the admin role (heuristic)

# ------------------------------------------------------------------ #
# Sensitive parameter name scores                                      #
# ------------------------------------------------------------------ #

_PARAMETER_NAME_SCORES: dict[str, int] = {
    "id":               10,
    "user_id":          25,
    "account_id":       25,
    "tenant_id":        35,
    "organization_id":  35,
    "company_id":       30,
    "customer_id":      30,
    "role":             35,
    "permission":       35,
    "group":            25,
    "owner":            20,
    "email":            15,
    "username":         15,
    "token":            25,
    "api_key":          40,
    "secret":           50,
}

# ------------------------------------------------------------------ #
# Path parameter type scores                                           #
# ------------------------------------------------------------------ #

# Patterns to detect typed path parameters embedded in normalised paths.
# The normaliser wraps path params in braces: /users/{id} — we inspect segment text.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MONGO_OBJECTID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
_SEQUENTIAL_INT_RE = re.compile(r"^\d+$")
_GENERIC_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

_PATH_PARAM_TYPE_SCORES: dict[str, int] = {
    "uuid":       15,
    "integer_id": 10,
    "objectid":   15,
    "hash":       10,
    "sequential": 15,
}

# ------------------------------------------------------------------ #
# Request body type scores                                             #
# ------------------------------------------------------------------ #

_REQUEST_BODY_SCORES: dict[str, int] = {
    "multipart/form-data": 30,
    "application/json":    15,
    "application/xml":     20,
    "text/xml":            20,
}

# ------------------------------------------------------------------ #
# Score floor / normalisation                                          #
# Applied after all signals to prevent extreme negative scores.        #
# ------------------------------------------------------------------ #

_SCORE_FLOOR: int = -200


# ------------------------------------------------------------------ #
# Config loading                                                       #
# ------------------------------------------------------------------ #

def load_score_config(project_data_dir: Path | None = None) -> dict:
    """
    Purpose:
        Load per-project scoring configuration from policy_score.json.
        Falls back to built-in defaults if the file is absent or invalid.
    Input:
        project_data_dir — Path to the project's data directory.
                           None returns built-in defaults.
    Output:
        Config dict with 'thresholds' sub-dict.
    Side effects: None beyond file read.
    """
    defaults = {
        "thresholds": {
            "CRITICAL": DEFAULT_CRITICAL_THRESHOLD,
            "HIGH":     DEFAULT_HIGH_THRESHOLD,
            "NORMAL":   DEFAULT_NORMAL_THRESHOLD,
        }
    }

    if project_data_dir is None:
        return defaults

    config_path = project_data_dir / "policy_score.json"
    if not config_path.exists():
        return defaults

    try:
        raw = config_path.read_text(encoding="utf-8")
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            return defaults
        # Merge — only override keys that are present and valid.
        thresholds = loaded.get("thresholds", {})
        if isinstance(thresholds, dict):
            for key in ("CRITICAL", "HIGH", "NORMAL"):
                val = thresholds.get(key)
                if isinstance(val, int):
                    defaults["thresholds"][key] = val
        return defaults
    except Exception:
        # Corrupted or unreadable config — silently fall back to defaults.
        return defaults


def write_default_score_config(project_data_dir: Path) -> None:
    """
    Purpose:
        Write the default policy_score.json to a project directory.
        No-op if the file already exists (preserves tester edits).
    Input:
        project_data_dir — Path to the project's data directory.
    Side effects:
        Creates policy_score.json when absent.
    """
    config_path = project_data_dir / "policy_score.json"
    if config_path.exists():
        return

    config = {
        "thresholds": {
            "CRITICAL": DEFAULT_CRITICAL_THRESHOLD,
            "HIGH":     DEFAULT_HIGH_THRESHOLD,
            "NORMAL":   DEFAULT_NORMAL_THRESHOLD,
        },
        "_note": (
            "Adjust thresholds to change what score maps to CRITICAL/HIGH/NORMAL. "
            "Anything below NORMAL threshold is LOW. "
            "Scores are additive — method + path signals + parameter signals + auth."
        ),
    }
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


# ------------------------------------------------------------------ #
# Core scoring function                                                #
# ------------------------------------------------------------------ #

def compute_auto_priority(
    method: str,
    normalized_path: str,
    response_content_type: str,
    auth_required: bool,
    roles_seen_count: int,
    total_roles: int,
    parameter_names: list[str],
    request_content_type: str,
    config: dict | None = None,
) -> tuple[int, str, dict[str, int]]:
    """
    Purpose:
        Compute an automatic priority score for one endpoint.
    Input:
        method                — HTTP method string.
        normalized_path       — canonical path (path params may be in braces).
        response_content_type — response Content-Type header value.
        auth_required         — True when the request carried auth material.
        roles_seen_count      — number of distinct project roles that accessed this endpoint.
        total_roles           — total roles defined in the project.
        parameter_names       — list of observed query/body parameter names.
        request_content_type  — request Content-Type header value.
        config                — optional scoring config dict from load_score_config().
                                Uses built-in defaults when None.
    Output:
        (score, level, contributors)
        score        — raw integer score.
        level        — 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW'.
        contributors — ordered dict mapping contributor label → signed delta.
    Side effects: None.
    """
    if config is None:
        config = load_score_config(None)

    thresholds = config.get("thresholds", {})
    critical_t = thresholds.get("CRITICAL", DEFAULT_CRITICAL_THRESHOLD)
    high_t     = thresholds.get("HIGH",     DEFAULT_HIGH_THRESHOLD)
    normal_t   = thresholds.get("NORMAL",   DEFAULT_NORMAL_THRESHOLD)

    contributors: dict[str, int] = {}
    score = 0

    def _add(label: str, delta: int) -> None:
        """Record a non-zero contribution."""
        if delta == 0:
            return
        contributors[label] = delta

    # ---- Method ----
    method_up = method.upper()
    method_score = _METHOD_SCORES.get(method_up, 0)
    _add(f"{method_up} method", method_score)
    score += method_score

    # ---- Path analysis ----
    path_lower = normalized_path.lower()
    segments = [s for s in path_lower.split("/") if s]

    # Check for low-priority signals first — they dominate static assets.
    low_priority_applied: set[str] = set()
    for segment in segments:
        for signal, delta in _LOW_PRIORITY_PATH_SIGNALS.items():
            if signal in segment and signal not in low_priority_applied:
                _add(f"low-priority path: /{signal}", delta)
                score += delta
                low_priority_applied.add(signal)

    # Also check full path for signals like robots.txt
    for signal, delta in _LOW_PRIORITY_PATH_SIGNALS.items():
        if signal in path_lower and signal not in low_priority_applied:
            _add(f"low-priority path: /{signal}", delta)
            score += delta
            low_priority_applied.add(signal)

    # Static file extension check on the last segment.
    if segments:
        last_seg = segments[-1]
        for ext, delta in _STATIC_EXTENSION_SCORES.items():
            if last_seg.endswith(ext):
                _add(f"static file extension: {ext}", delta)
                score += delta
                break  # Only apply the first matching extension.

    # Sensitive path keywords.
    applied_kw: set[str] = set()
    for segment in segments:
        # Strip brace-wrapped path params: {id} → skip, /users → match.
        clean_seg = re.sub(r"\{[^}]+\}", "", segment).strip("-_")
        for keyword, delta in _PATH_KEYWORD_SCORES.items():
            if keyword == clean_seg and keyword not in applied_kw:
                _add(f"path keyword: /{keyword}", delta)
                score += delta
                applied_kw.add(keyword)
        # Also check business operation verbs.
        for verb, delta in _ENDPOINT_NAMING_SCORES.items():
            if verb == clean_seg and f"verb:{verb}" not in applied_kw:
                _add(f"endpoint action: {verb}", delta)
                score += delta
                applied_kw.add(f"verb:{verb}")
        # Business keywords.
        for biz, delta in _BUSINESS_KEYWORD_SCORES.items():
            if biz == clean_seg and f"biz:{biz}" not in applied_kw:
                _add(f"business keyword: {biz}", delta)
                score += delta
                applied_kw.add(f"biz:{biz}")

    # Path parameter type detection.
    path_param_labels = _detect_path_param_types(segments)
    for label, delta in path_param_labels:
        _add(label, delta)
        score += delta

    # ---- Authentication ----
    if auth_required:
        _add("Authorization / session cookie observed", _AUTH_SCORE)
        score += _AUTH_SCORE

    # ---- Role visibility ----
    if roles_seen_count >= 2 and total_roles > 1:
        _add("seen by multiple roles", _MULTI_ROLE_SCORE)
        score += _MULTI_ROLE_SCORE

    # ---- Response content-type ----
    resp_ct = response_content_type.lower()

    # Check penalties first (CSS, images, fonts, JS).
    ct_penalty_applied = False
    for ct_prefix, delta in _RESPONSE_CONTENT_TYPE_PENALTIES.items():
        if resp_ct.startswith(ct_prefix):
            _add(f"response content-type penalty: {ct_prefix}", delta)
            score += delta
            ct_penalty_applied = True
            break

    if not ct_penalty_applied and resp_ct:
        for ct, delta in _RESPONSE_CONTENT_TYPE_SCORES.items():
            if resp_ct.startswith(ct):
                _add(f"response content-type: {ct}", delta)
                score += delta
                break

    # File download signal from content-disposition or known download types.
    if (
        "attachment" in resp_ct
        or resp_ct in ("text/csv", "application/zip", "application/pdf")
        or "octet-stream" in resp_ct
    ):
        _add("file download response", _RESPONSE_DOWNLOAD_SCORE)
        score += _RESPONSE_DOWNLOAD_SCORE

    # ---- Request body type ----
    req_ct = request_content_type.lower()
    for ct, delta in _REQUEST_BODY_SCORES.items():
        if req_ct.startswith(ct):
            _add(f"request body: {ct}", delta)
            score += delta
            break

    # ---- Parameter names ----
    applied_params: set[str] = set()
    for param_name in parameter_names:
        name_lower = param_name.lower()
        if name_lower in _PARAMETER_NAME_SCORES and name_lower not in applied_params:
            delta = _PARAMETER_NAME_SCORES[name_lower]
            _add(f"sensitive parameter: {param_name}", delta)
            score += delta
            applied_params.add(name_lower)

    # Clamp score to floor to prevent absurd negative values.
    score = max(score, _SCORE_FLOOR)

    # ---- Priority level mapping ----
    if score >= critical_t:
        level = "CRITICAL"
    elif score >= high_t:
        level = "HIGH"
    elif score >= normal_t:
        level = "NORMAL"
    else:
        level = "LOW"

    return score, level, contributors


# ------------------------------------------------------------------ #
# Path parameter type detection                                        #
# ------------------------------------------------------------------ #

def _detect_path_param_types(segments: list[str]) -> list[tuple[str, int]]:
    """
    Purpose:
        Detect typed path parameters (UUID, integer, Mongo ObjectId, hash, etc.)
        in path segments and return scoring contributions.
    Input:
        segments — path segments split by '/' with braces intact.
    Output:
        List of (label, delta) pairs for each detected parameter type.
    Side effects: None.
    """
    results: list[tuple[str, int]] = []
    types_seen: set[str] = set()

    for segment in segments:
        # Brace-wrapped placeholder from normalisation: {id}, {uuid}, etc.
        if segment.startswith("{") and segment.endswith("}"):
            inner = segment[1:-1].lower()
            if "uuid" in inner and "uuid" not in types_seen:
                results.append(("UUID path parameter", _PATH_PARAM_TYPE_SCORES["uuid"]))
                types_seen.add("uuid")
            elif "id" in inner and "uuid" not in types_seen and "int" not in types_seen:
                results.append(("integer/ID path parameter", _PATH_PARAM_TYPE_SCORES["integer_id"]))
                types_seen.add("int")
            continue

        # Bare values (raw path — normaliser may not have replaced them).
        if _UUID_RE.match(segment) and "uuid" not in types_seen:
            results.append(("UUID path parameter", _PATH_PARAM_TYPE_SCORES["uuid"]))
            types_seen.add("uuid")
        elif _MONGO_OBJECTID_RE.match(segment) and "objectid" not in types_seen:
            results.append(("Mongo ObjectId path parameter", _PATH_PARAM_TYPE_SCORES["objectid"]))
            types_seen.add("objectid")
        elif _SEQUENTIAL_INT_RE.match(segment) and "seq" not in types_seen:
            if len(segment) <= 12:  # reasonable integer ID length
                results.append(("sequential integer ID in path", _PATH_PARAM_TYPE_SCORES["sequential"]))
                types_seen.add("seq")
        elif _GENERIC_HASH_RE.match(segment) and "hash" not in types_seen and len(segment) >= 32:
            results.append(("hash/token in path", _PATH_PARAM_TYPE_SCORES["hash"]))
            types_seen.add("hash")

    return results


# ------------------------------------------------------------------ #
# Formatting helpers                                                   #
# ------------------------------------------------------------------ #

def format_score_breakdown(
    score: int,
    level: str,
    contributors: dict[str, int],
) -> str:
    """
    Purpose:
        Format a score breakdown as a human-readable multi-line string.
    Input:
        score        — final integer score.
        level        — priority level string.
        contributors — mapping of contributor label → signed delta.
    Output:
        Multi-line string suitable for CLI display.
    Side effects: None.
    """
    lines = [f"  Auto Priority : {level} (Score: {score})"]

    if contributors:
        lines.append("  Contributors  :")
        for label, delta in contributors.items():
            sign = "+" if delta >= 0 else ""
            lines.append(f"    {sign}{delta:>4}  {label}")

    return "\n".join(lines)
