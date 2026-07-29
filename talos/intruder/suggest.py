"""
Module: talos.intruder.suggest

Purpose:
    Phase 4 "AI suggest" — deterministic, offline heuristics that propose
    Intruder session configuration for operators and AI agents.

    Inputs: session config (baseline template, variables, optional param
    intel / pools). Outputs: structured suggestion document (JSON-stable)
    with recommended strategy, timing, payload generators, match rules,
    and optional grep extract.

    Does **not** call external LLMs. Suggestions are pure functions of
    session + project intel so agents can apply them without network.

Dependencies: json, typing; optional DB for pools/param examples
Data flow:
    CLI suggest → build_suggestions(session, config, db) → dict
    optional apply_suggestions → mutated config
Side effects: none (apply is caller-owned config mutation).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from talos.intruder import db as intruder_db
from talos.intruder.config_schema import merge_defaults
from talos.intruder.models import (
    GEN_BRUTEFORCE,
    GEN_DATES,
    GEN_EXAMPLE_VALUES,
    GEN_NUMBERS,
    GEN_PATTERN,
    GEN_POOL,
    GEN_RANDOM,
    GEN_STATIC,
    GEN_UUID,
    GEN_WORDLIST,
    LOCATION_HEADER,
    LOCATION_PATH,
    STRATEGY_SINGLE,
    STRATEGY_SNIPER,
    TIMING_ADAPTIVE,
    TIMING_FIXED,
    TemplateVariable,
)
from talos.intruder.template import variables_from_config


# Semantic type → preferred generator sketch
_SEMANTIC_GENERATOR: dict[str, dict[str, Any]] = {
    "integer": {
        "generator": GEN_NUMBERS,
        "options": {"start": 1, "end": 100, "step": 1},
        "reason": "semantic_type=integer → numbers range",
    },
    "int": {
        "generator": GEN_NUMBERS,
        "options": {"start": 1, "end": 100, "step": 1},
        "reason": "semantic_type=int → numbers range",
    },
    "uuid": {
        "generator": GEN_UUID,
        "options": {"count": 50},
        "reason": "semantic_type=uuid → uuid generator",
    },
    "email": {
        "generator": GEN_PATTERN,
        "options": {"pattern": "user{n}@example.com", "start": 1, "end": 50},
        "reason": "semantic_type=email → pattern emails",
    },
    "boolean": {
        "generator": GEN_STATIC,
        "options": {"values": ["true", "false", "1", "0", "yes", "no"]},
        "reason": "semantic_type=boolean → static truthy/falsy",
    },
    "bool": {
        "generator": GEN_STATIC,
        "options": {"values": ["true", "false", "1", "0"]},
        "reason": "semantic_type=bool → static truthy/falsy",
    },
    "date": {
        "generator": GEN_DATES,
        "options": {
            "start": "2020-01-01",
            "end": "2020-01-31",
            "step_days": 1,
            "format": "%Y-%m-%d",
        },
        "reason": "semantic_type=date → dates range",
    },
    "datetime": {
        "generator": GEN_DATES,
        "options": {
            "start": "2020-01-01",
            "end": "2020-01-14",
            "step_days": 1,
            "format": "%Y-%m-%dT00:00:00Z",
        },
        "reason": "semantic_type=datetime → dates range",
    },
    "token": {
        "generator": GEN_RANDOM,
        "options": {"count": 50, "length": 32, "charset": "abcdef0123456789"},
        "reason": "semantic_type=token → random hex-ish strings",
    },
    "password": {
        "generator": GEN_WORDLIST,
        "options": {"path": "./wordlists/passwords.txt"},
        "reason": "semantic_type=password → wordlist (provide path)",
        "needs_file": True,
    },
    "enum": {
        "generator": GEN_STATIC,
        "options": {"values": []},
        "reason": "semantic_type=enum → static from example_values when present",
    },
}


def _guess_from_name(name: str) -> Optional[dict[str, Any]]:
    key = (name or "").lower()
    if key in ("id", "user_id", "userid", "uid", "account_id", "order_id"):
        return {
            "generator": GEN_NUMBERS,
            "options": {"start": 1, "end": 200, "step": 1},
            "reason": f"name '{name}' looks numeric id → numbers 1..200",
        }
    if "uuid" in key or key.endswith("_id") and "guid" in key:
        return {
            "generator": GEN_UUID,
            "options": {"count": 50},
            "reason": f"name '{name}' looks like uuid → uuid generator",
        }
    if any(x in key for x in ("token", "jwt", "session", "auth")):
        return {
            "generator": GEN_RANDOM,
            "options": {"count": 30, "length": 24},
            "reason": f"name '{name}' looks like token → random strings",
        }
    if any(x in key for x in ("email", "mail")):
        return {
            "generator": GEN_PATTERN,
            "options": {"pattern": "user{n}@test.local", "start": 1, "end": 50},
            "reason": f"name '{name}' looks like email → pattern",
        }
    if any(x in key for x in ("date", "day", "dob", "birth")):
        return {
            "generator": GEN_DATES,
            "options": {
                "start": "1990-01-01",
                "end": "1990-12-31",
                "step_days": 7,
                "format": "%Y-%m-%d",
            },
            "reason": f"name '{name}' looks like date → weekly dates",
        }
    if any(x in key for x in ("role", "type", "status", "state", "mode")):
        return {
            "generator": GEN_STATIC,
            "options": {"values": ["admin", "user", "guest", "true", "false"]},
            "reason": f"name '{name}' looks like enum → static common values",
        }
    if any(x in key for x in ("pin", "otp", "code")) and "postal" not in key:
        return {
            "generator": GEN_BRUTEFORCE,
            "options": {"charset": "0123456789", "min_len": 4, "max_len": 4},
            "reason": f"name '{name}' looks like PIN/OTP → 4-digit bruteforce",
        }
    return None


def _payload_for_variable(
    var: TemplateVariable,
    *,
    pools: list[dict[str, Any]],
    existing_set: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build one payload suggestion for a template variable."""
    if existing_set:
        return {
            "var": var.name,
            "action": "keep",
            "payload_set": existing_set,
            "reason": "payload set already configured",
        }

    # Prefer project pool when name matches
    pool_names = {p.get("name") for p in pools}
    if var.name in pool_names:
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": GEN_POOL,
                "options": {"name": var.name},
                "processors": [],
            },
            "reason": f"project pool '{var.name}' exists → reuse via pool generator",
        }

    # Param-intel example_values
    if var.param_id:
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": GEN_EXAMPLE_VALUES,
                "options": {"param_id": var.param_id},
                "processors": [],
            },
            "reason": "param_id present → example_values from Parameter Intelligence",
        }

    semantic = (var.semantic_type or "").strip().lower()
    if semantic in _SEMANTIC_GENERATOR:
        sketch = _SEMANTIC_GENERATOR[semantic]
        # enum with original_value → static single + common flips
        if semantic == "enum" and var.original_value:
            return {
                "var": var.name,
                "action": "set",
                "payload_set": {
                    "generator": GEN_STATIC,
                    "options": {
                        "values": list(dict.fromkeys([
                            str(var.original_value),
                            "admin",
                            "user",
                            "true",
                            "false",
                        ])),
                    },
                    "processors": [],
                },
                "reason": sketch["reason"],
            }
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": sketch["generator"],
                "options": dict(sketch["options"]),
                "processors": [],
            },
            "reason": sketch["reason"],
            "needs_file": sketch.get("needs_file", False),
        }

    guessed = _guess_from_name(var.name)
    if guessed:
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": guessed["generator"],
                "options": dict(guessed["options"]),
                "processors": [],
            },
            "reason": guessed["reason"],
        }

    # Fallbacks from original_value shape
    ov = var.original_value
    if ov is not None:
        s = str(ov)
        if s.isdigit():
            base = int(s)
            start = max(0, base - 50)
            end = base + 50
            return {
                "var": var.name,
                "action": "set",
                "payload_set": {
                    "generator": GEN_NUMBERS,
                    "options": {"start": start, "end": end, "step": 1},
                    "processors": [],
                },
                "reason": f"original_value '{s}' is numeric → numbers around baseline",
            }
        if len(s) == 36 and s.count("-") == 4:
            return {
                "var": var.name,
                "action": "set",
                "payload_set": {
                    "generator": GEN_UUID,
                    "options": {"count": 50},
                    "processors": [],
                },
                "reason": "original_value looks like UUID → uuid generator",
            }

    # Location-aware defaults
    if var.location == LOCATION_PATH:
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": GEN_NUMBERS,
                "options": {"start": 1, "end": 50, "step": 1},
                "processors": [],
            },
            "reason": "path variable without intel → numbers 1..50",
        }
    if var.location == LOCATION_HEADER and (var.path or var.name).lower() in (
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    ):
        return {
            "var": var.name,
            "action": "set",
            "payload_set": {
                "generator": GEN_RANDOM,
                "options": {"count": 20, "length": 32},
                "processors": (
                    ["prefix:Bearer "]
                    if (var.path or var.name).lower() == "authorization"
                    else []
                ),
            },
            "reason": "auth-like header → random tokens (Bearer prefix when Authorization)",
        }

    return {
        "var": var.name,
        "action": "set",
        "payload_set": {
            "generator": GEN_STATIC,
            "options": {
                "values": [
                    str(ov) if ov is not None else "test",
                    "",
                    "1",
                    "admin",
                    "../",
                    "'\"<>",
                ],
            },
            "processors": [],
        },
        "reason": "generic fallback → small static probe list",
    }


def build_suggestions(
    session: dict[str, Any],
    config: Optional[dict[str, Any]] = None,
    *,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a full suggestion document for a session.

    Stable JSON shape for AI agents:

        {
          "schema": "intruder_suggest/v1",
          "session_id": "...",
          "summary": "...",
          "strategy": {...},
          "timing": {...},
          "payloads": [...],
          "match": [...],
          "grep": [...],
          "notes": [...],
          "commands": ["talos intruder ...", ...]
        }
    """
    cfg = merge_defaults(config if config is not None else (session.get("config") or {}))
    variables = variables_from_config(cfg)
    injectable = [v for v in variables if not v.is_fixed()]
    existing_sets = dict(cfg.get("payload_sets") or {})
    pid = project_id or (cfg.get("session") or {}).get("project_id") or session.get("project_id")

    pools: list[dict[str, Any]] = []
    if db_path is not None and pid:
        try:
            pools = list(intruder_db.list_pools(db_path, str(pid)) or [])
        except Exception:  # noqa: BLE001
            pools = []

    # Strategy suggestion
    if len(injectable) <= 1:
        strategy_sugg = {
            "type": STRATEGY_SINGLE,
            "options": {"primary": injectable[0].name} if injectable else {},
            "reason": "single injectable variable → single strategy",
        }
    else:
        strategy_sugg = {
            "type": STRATEGY_SNIPER,
            "options": {"targets": [v.name for v in injectable]},
            "reason": f"{len(injectable)} injectables → sniper (one set across positions)",
        }

    # Timing: prefer adaptive for unknown surfaces, fixed stealth for small enums
    timing_sugg = {
        "mode": TIMING_ADAPTIVE,
        "rps": 2.0,
        "min_rps": 0.5,
        "max_rps": 5.0,
        "max_concurrency": 1,
        "jitter_ms": 50,
        "slow_ms": 2000,
        "reason": "adaptive timing with stealth concurrency 1 (Phase 4 default suggest)",
    }
    # If only a tiny static attack likely, fixed is fine
    if len(injectable) == 1 and injectable[0].semantic_type in ("boolean", "bool", "enum"):
        timing_sugg = {
            "mode": TIMING_FIXED,
            "rps": 2.0,
            "max_concurrency": 1,
            "jitter_ms": 0,
            "reason": "small enum/boolean surface → fixed 2 RPS",
        }

    # Payloads
    payloads: list[dict[str, Any]] = []
    for var in injectable:
        payloads.append(
            _payload_for_variable(
                var,
                pools=pools,
                existing_set=existing_sets.get(var.name),
            )
        )

    # Match rules from baseline method
    method = str((cfg.get("template") or {}).get("method") or "GET").upper()
    match_rules: list[dict[str, Any]] = [
        {
            "tag": "ok",
            "status": 200,
            "reason": "flag successful 200 responses",
        },
        {
            "tag": "auth_fail",
            "status": 401,
            "reason": "flag unauthorized",
        },
        {
            "tag": "forbidden",
            "status": 403,
            "reason": "flag forbidden (possible authz difference)",
        },
        {
            "tag": "slow",
            "time_gt_ms": 2000,
            "reason": "flag slow responses (timing side-channel)",
        },
    ]
    if method in ("POST", "PUT", "PATCH"):
        match_rules.append({
            "tag": "created",
            "status": 201,
            "reason": f"{method} may create resources → flag 201",
        })

    # Grep: JSON-ish token extract when body/API-like
    url = str((cfg.get("template") or {}).get("url") or "")
    grep_rules: list[dict[str, Any]] = []
    if any(x in url for x in ("/api", "/v1", "/v2", "graphql")) or "json" in url.lower():
        grep_rules.append({
            "name": "token",
            "regex": r'"token"\s*:\s*"([^"]+)"',
            "group": 1,
            "source": "body",
            "to_pool": True,
            "tag_interesting": True,
            "reason": "API-ish URL → extract JSON token into pool",
        })
        grep_rules.append({
            "name": "id",
            "regex": r'"id"\s*:\s*"?([0-9a-fA-F-]{6,})"?',
            "group": 1,
            "source": "body",
            "to_pool": True,
            "tag_interesting": False,
            "reason": "API-ish URL → extract id values into pool",
        })

    notes: list[str] = [
        "Suggestions are heuristics for operators/AI agents; review before run.",
        "Apply with: talos intruder suggest <id> --apply [--force]",
        "Large bruteforce/cartesian still requires --force at run when estimate > 1000.",
        "Findings auto-promote remains Phase 5 / opt-in (not applied here).",
    ]
    if not injectable:
        notes.append(
            "No non-fixed template variables — add with template set-var or "
            "template from-params before payloads are useful."
        )
    if not existing_sets and injectable:
        notes.append("No payload sets yet; suggested payloads cover all injectables.")

    # CLI command sketches (session id filled by caller when known)
    sid = session.get("id") or "<session_id>"
    commands: list[str] = [
        f"talos intruder strategy set {sid} --type {strategy_sugg['type']}",
        (
            f"talos intruder timing set {sid} --mode {timing_sugg['mode']} "
            f"--rps {timing_sugg.get('rps', 2)}"
            + (
                f" --min-rps {timing_sugg['min_rps']} --max-rps {timing_sugg['max_rps']}"
                if timing_sugg.get("mode") == TIMING_ADAPTIVE
                else ""
            )
            + f" --concurrency {timing_sugg.get('max_concurrency', 1)}"
        ),
    ]
    for p in payloads:
        if p.get("action") != "set":
            continue
        ps = p["payload_set"]
        gen = ps["generator"]
        opts = ps.get("options") or {}
        parts = [
            f"talos intruder payload set {sid} --var {p['var']} --generator {gen}",
        ]
        if gen == GEN_NUMBERS:
            parts.append(f"--start {opts.get('start', 1)} --end {opts.get('end', 100)}")
            if opts.get("step", 1) != 1:
                parts.append(f"--step {opts['step']}")
        elif gen == GEN_UUID:
            parts.append(f"--count {opts.get('count', 50)}")
        elif gen == GEN_STATIC:
            for v in opts.get("values") or []:
                parts.append(f"--value {v!s}")
        elif gen == GEN_POOL:
            parts.append(f"--pool {opts.get('name') or opts.get('pool')}")
        elif gen == GEN_EXAMPLE_VALUES:
            parts.append(f"--param-id {opts.get('param_id')}")
        elif gen == GEN_DATES:
            parts.append(f"--start-date {opts.get('start')} --end-date {opts.get('end')}")
            if opts.get("format"):
                parts.append(f"--date-format {opts['format']}")
        elif gen == GEN_BRUTEFORCE:
            parts.append(f"--charset {opts.get('charset', '0123456789')}")
            parts.append(f"--min-len {opts.get('min_len', 1)}")
            parts.append(f"--max-len {opts.get('max_len', 3)}")
        elif gen == GEN_RANDOM:
            parts.append(f"--count {opts.get('count', 50)}")
            parts.append(f"--length {opts.get('length', 8)}")
        elif gen == GEN_PATTERN:
            parts.append(f"--pattern {opts.get('pattern')!s}")
            parts.append(f"--start {opts.get('start', 0)} --end {opts.get('end', 99)}")
        elif gen == GEN_WORDLIST:
            parts.append(f"--file {opts.get('path', './wordlist.txt')}")
        for proc in ps.get("processors") or []:
            parts.append(f"--processor {proc}")
        commands.append(" ".join(str(x) for x in parts))

    for rule in match_rules[:3]:
        bits = [f"talos intruder match add {sid}"]
        if rule.get("tag"):
            bits.append(f"--tag {rule['tag']}")
        if "status" in rule:
            bits.append(f"--status {rule['status']}")
        if "time_gt_ms" in rule:
            bits.append(f"--time-gt-ms {rule['time_gt_ms']}")
        commands.append(" ".join(bits))

    for gr in grep_rules:
        commands.append(
            f"talos intruder grep add {sid} --name {gr['name']} "
            f"--regex {gr['regex']!r}"
            + (" --tag-interesting" if gr.get("tag_interesting") else "")
        )

    summary_bits = [
        f"{len(injectable)} injectable var(s)",
        f"strategy={strategy_sugg['type']}",
        f"timing={timing_sugg['mode']}",
        f"{sum(1 for p in payloads if p.get('action') == 'set')} payload suggestion(s)",
    ]

    return {
        "schema": "intruder_suggest/v1",
        "session_id": session.get("id"),
        "summary": "; ".join(summary_bits),
        "strategy": strategy_sugg,
        "timing": timing_sugg,
        "payloads": payloads,
        "match": match_rules,
        "grep": grep_rules,
        "notes": notes,
        "commands": commands,
        "pools_available": [p.get("name") for p in pools],
        "injectable_variables": [v.name for v in injectable],
        "fixed_variables": [v.name for v in variables if v.is_fixed()],
    }


def apply_suggestions(
    config: dict[str, Any],
    suggestions: dict[str, Any],
    *,
    replace_payloads: bool = False,
    apply_match: bool = True,
    apply_grep: bool = True,
) -> dict[str, Any]:
    """
    Mutate a config dict from a suggestions document.
    Returns the updated config (same object after merge_defaults-style keys).
    """
    cfg = merge_defaults(config)

    st = suggestions.get("strategy") or {}
    if st.get("type"):
        cfg["strategy"] = {
            "type": st["type"],
            "options": dict(st.get("options") or {}),
        }

    tm = suggestions.get("timing") or {}
    if tm:
        timing = dict(cfg.get("timing") or {})
        for key in (
            "mode",
            "rps",
            "min_rps",
            "max_rps",
            "max_concurrency",
            "jitter_ms",
            "slow_ms",
            "burst_size",
            "timeout_s",
        ):
            if key in tm and tm[key] is not None:
                timing[key] = tm[key]
        cfg["timing"] = timing

    if replace_payloads:
        cfg["payload_sets"] = {}
    psets = dict(cfg.get("payload_sets") or {})
    for p in suggestions.get("payloads") or []:
        if p.get("action") == "set" and p.get("var") and p.get("payload_set"):
            if replace_payloads or p["var"] not in psets:
                # Skip suggestions that need external files unless path set
                if p.get("needs_file"):
                    continue
                psets[p["var"]] = dict(p["payload_set"])
    cfg["payload_sets"] = psets

    if apply_match and suggestions.get("match"):
        # Convert suggest match sketches to engine rule shape
        rules = list(cfg.get("match") or [])
        existing_tags = {r.get("tag") for r in rules if isinstance(r, dict)}
        for m in suggestions["match"]:
            tag = m.get("tag")
            if tag and tag in existing_tags:
                continue
            rule: dict[str, Any] = {}
            if tag:
                rule["tag"] = tag
            for k in ("status", "body_contains", "regex", "length_delta_gt", "time_gt_ms"):
                if k in m:
                    rule[k] = m[k]
            if rule:
                rules.append(rule)
        cfg["match"] = rules

    if apply_grep and suggestions.get("grep"):
        greps = list(cfg.get("grep") or [])
        existing_names = {g.get("name") for g in greps if isinstance(g, dict)}
        for g in suggestions["grep"]:
            name = g.get("name")
            if name and name in existing_names:
                continue
            rule = {
                "name": name,
                "regex": g.get("regex"),
                "group": g.get("group", 1),
                "source": g.get("source", "body"),
                "to_pool": g.get("to_pool", True),
                "tag_interesting": g.get("tag_interesting", False),
            }
            if rule.get("regex"):
                greps.append(rule)
        cfg["grep"] = greps

    return cfg
