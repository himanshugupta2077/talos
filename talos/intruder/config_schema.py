"""
Module: talos.intruder.config_schema

Purpose:
    Load, default, and validate Intruder session config documents
    (schema_version 1 only in Phase 1).
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional

from talos.intruder.generators import build_generator
from talos.intruder.models import (
    CONFIG_SCHEMA_VERSION,
    DEFAULT_AUTH_FAIL_THRESHOLD,
    DEFAULT_CONFIRM_THRESHOLD,
    DEFAULT_JITTER_MS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_MAX_DURATION_S,
    DEFAULT_MAX_RESULTS,
    DEFAULT_RPS,
    DEFAULT_SLICE_MAX_ATTEMPTS,
    DEFAULT_SLICE_MAX_WALL_S,
    DEFAULT_TIMEOUT_S,
    ERR_EMPTY_GENERATOR,
    ERR_INVALID_NUMBERS,
    ERR_MISSING_BASELINE,
    ERR_NO_VARIABLES,
    ERR_PATH_INJECT_UNAVAILABLE,
    ERR_SNIPER_NO_TARGETS,
    ERR_UNBOUND_VARIABLE,
    ERR_UNKNOWN_PLUGIN,
    ERR_UNSUPPORTED_CONFIG_VERSION,
    ERR_WORDLIST_TOO_LARGE,
    LOCATION_PATH,
    PHASE1_GENERATORS,
    PHASE1_PROCESSORS,
    PHASE1_STRATEGIES,
    STRATEGY_SINGLE,
    STRATEGY_SNIPER,
)
from talos.intruder.processors import build_processor
from talos.intruder.template import path_has_brace, variables_from_config


def default_config() -> dict[str, Any]:
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "session": {},
        "template": {
            "method": "GET",
            "url": "",
            "headers": {},
            "body": None,
            "variables": [],
            "normalized_path": "",
        },
        "payload_sets": {},
        "strategy": {"type": STRATEGY_SINGLE, "options": {}},
        "timing": {
            "mode": "fixed",
            "rps": DEFAULT_RPS,
            "max_concurrency": DEFAULT_MAX_CONCURRENCY,
            "jitter_ms": DEFAULT_JITTER_MS,
            "timeout_s": DEFAULT_TIMEOUT_S,
        },
        "slice": {
            "max_attempts": DEFAULT_SLICE_MAX_ATTEMPTS,
            "max_wall_s": DEFAULT_SLICE_MAX_WALL_S,
        },
        "storage": {
            "mode": "metrics_only",
            "sample_rate": 0.0,
            "store_interesting_bodies": True,
            "max_body_bytes": 65536,
            "max_results": DEFAULT_MAX_RESULTS,
        },
        "match": [],
        "grep": [],
        "safety": {
            "respect_logout": True,
            "respect_dangerous": True,
            "require_in_scope": True,
            "skip_auth_artifacts": False,
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "max_duration_s": DEFAULT_MAX_DURATION_S,
            "auth_fail_threshold": DEFAULT_AUTH_FAIL_THRESHOLD,
        },
    }


def merge_defaults(config: dict[str, Any]) -> dict[str, Any]:
    base = default_config()
    return _deep_merge(base, config or {})


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(a)
    for k, v in (b or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


class ValidationError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def validate_config(
    config: dict[str, Any],
    *,
    open_generators: bool = True,
    force: bool = False,
) -> tuple[dict[str, Any], Optional[int]]:
    """
    Validate and normalize config.
    Returns (normalized_config, estimate_attempts).
    Raises ValidationError with stable code.
    """
    cfg = merge_defaults(config)
    ver = cfg.get("schema_version")
    if ver is None or int(ver) != CONFIG_SCHEMA_VERSION:
        raise ValidationError(
            ERR_UNSUPPORTED_CONFIG_VERSION,
            f"unsupported config schema_version={ver!r}; Phase 1 requires {CONFIG_SCHEMA_VERSION}",
        )

    tmpl = cfg.get("template") or {}
    if not tmpl.get("method") or not tmpl.get("url"):
        raise ValidationError(ERR_MISSING_BASELINE, "template method/url required")

    variables = variables_from_config(cfg)
    injectable = [v for v in variables if not v.is_fixed()]
    strategy = cfg.get("strategy") or {}
    stype = str(strategy.get("type") or STRATEGY_SINGLE).lower()
    if stype not in PHASE1_STRATEGIES:
        raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown strategy: {stype}")

    if stype in (STRATEGY_SINGLE, STRATEGY_SNIPER) and not injectable and not variables:
        raise ValidationError(ERR_NO_VARIABLES, "strategy requires template variables")

    if stype == STRATEGY_SNIPER:
        targets = (strategy.get("options") or {}).get("targets")
        if targets is not None and len(targets) == 0:
            raise ValidationError(ERR_SNIPER_NO_TARGETS)
        if not injectable and not targets:
            # All fixed → sniper has no targets
            raise ValidationError(ERR_SNIPER_NO_TARGETS, "sniper needs non-fixed variables")

    # Path inject gate
    norm_path = str(tmpl.get("normalized_path") or "")
    for var in variables:
        if var.location == LOCATION_PATH:
            name = var.inject_name()
            if not path_has_brace(norm_path, name):
                raise ValidationError(
                    ERR_PATH_INJECT_UNAVAILABLE,
                    f"path variable '{var.name}' requires '{{{name}}}' in normalized_path",
                )

    payload_sets = cfg.get("payload_sets") or {}
    if not isinstance(payload_sets, dict) or not payload_sets:
        if stype in (STRATEGY_SINGLE, STRATEGY_SNIPER):
            raise ValidationError(ERR_UNBOUND_VARIABLE, "payload_sets required")

    estimate: Optional[int] = None
    for set_name, pset in payload_sets.items():
        if not isinstance(pset, dict):
            raise ValidationError(ERR_UNKNOWN_PLUGIN, f"bad payload set {set_name}")
        gen_name = str(pset.get("generator") or "").lower()
        if gen_name not in PHASE1_GENERATORS:
            raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown generator: {gen_name}")
        for proc in pset.get("processors") or []:
            pname = str(proc).lower()
            if pname not in PHASE1_PROCESSORS:
                raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown processor: {pname}")
            build_processor(pname)

        opts = dict(pset.get("options") or {})
        if force:
            opts["force"] = True
        if not open_generators:
            continue
        try:
            gen = build_generator(gen_name, opts)
        except ValueError as exc:
            msg = str(exc)
            if msg.startswith(ERR_WORDLIST_TOO_LARGE):
                raise ValidationError(ERR_WORDLIST_TOO_LARGE, msg) from exc
            if msg.startswith(ERR_EMPTY_GENERATOR) or "empty" in msg:
                raise ValidationError(ERR_EMPTY_GENERATOR, msg) from exc
            if msg.startswith(ERR_INVALID_NUMBERS) or "invalid_numbers" in msg:
                raise ValidationError(ERR_INVALID_NUMBERS, msg) from exc
            raise ValidationError(ERR_UNKNOWN_PLUGIN, msg) from exc
        count = gen.estimate_count()
        if count is not None and count == 0:
            raise ValidationError(ERR_EMPTY_GENERATOR, f"payload set {set_name} empty")
        if estimate is None:
            estimate = count
        elif count is not None and stype == STRATEGY_SNIPER:
            # sniper total = payloads * targets
            pass
        elif count is not None:
            estimate = count

    # Estimate for sniper
    if open_generators and stype == STRATEGY_SNIPER:
        targets = (strategy.get("options") or {}).get("targets")
        n_targets = len(targets) if targets else len(injectable)
        # Re-open first set for count
        first = next(iter(payload_sets.values()), None)
        if first:
            opts = dict(first.get("options") or {})
            if force:
                opts["force"] = True
            gen = build_generator(str(first.get("generator")), opts)
            pc = gen.estimate_count() or 0
            estimate = pc * max(1, n_targets)
    elif open_generators and stype == STRATEGY_SINGLE and estimate is None:
        first = next(iter(payload_sets.values()), None)
        if first:
            opts = dict(first.get("options") or {})
            if force:
                opts["force"] = True
            gen = build_generator(str(first.get("generator")), opts)
            estimate = gen.estimate_count()

    # Bind strategy primary var for single
    if stype == STRATEGY_SINGLE and injectable:
        opts = strategy.setdefault("options", {})
        if not opts.get("primary") and not opts.get("var"):
            # Prefer matching payload set name
            for v in injectable:
                if v.name in payload_sets:
                    opts["primary"] = v.name
                    break
            if not opts.get("primary"):
                opts["primary"] = injectable[0].name
        primary = opts.get("primary") or opts.get("var")
        if primary and primary not in {v.name for v in variables}:
            raise ValidationError(ERR_UNBOUND_VARIABLE, f"primary var {primary} not in template")
        if primary and primary not in payload_sets and len(payload_sets) != 1:
            raise ValidationError(ERR_UNBOUND_VARIABLE, f"no payload set for {primary}")

    if stype == STRATEGY_SNIPER and injectable:
        opts = strategy.setdefault("options", {})
        if not opts.get("targets"):
            opts["targets"] = [v.name for v in injectable]

    cfg["strategy"] = strategy
    cfg["strategy"]["type"] = stype
    return cfg, estimate


def estimate_requires_confirm(estimate: Optional[int]) -> bool:
    return estimate is not None and estimate > DEFAULT_CONFIRM_THRESHOLD
