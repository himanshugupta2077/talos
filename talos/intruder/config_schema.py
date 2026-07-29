"""
Module: talos.intruder.config_schema

Purpose:
    Load, default, and validate Intruder session config documents
    (schema_version 1; Phase 1–3 plugins).
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from talos.intruder.generators import build_generator
from talos.intruder.grep import validate_grep_rule
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
    ERR_INVALID_FILE_GENERATOR,
    ERR_INVALID_GREP,
    ERR_INVALID_NUMBERS,
    ERR_INVALID_STORAGE_MODE,
    ERR_MISSING_BASELINE,
    ERR_MULTISET_UNBOUND,
    ERR_NO_VARIABLES,
    ERR_PARAM_NOT_FOUND,
    ERR_PATH_INJECT_UNAVAILABLE,
    ERR_POOL_NOT_FOUND,
    ERR_SNIPER_NO_TARGETS,
    ERR_UNBOUND_VARIABLE,
    ERR_UNKNOWN_PLUGIN,
    ERR_UNSUPPORTED_CONFIG_VERSION,
    ERR_WORDLIST_TOO_LARGE,
    GEN_CSV,
    GEN_EXAMPLE_VALUES,
    GEN_JSON,
    GEN_POOL,
    KNOWN_GENERATORS,
    KNOWN_STORAGE_MODES,
    KNOWN_STRATEGIES,
    LOCATION_PATH,
    MULTI_SET_STRATEGIES,
    STORAGE_METRICS_ONLY,
    STRATEGY_CARTESIAN,
    STRATEGY_CLUSTER_BOMB,
    STRATEGY_PITCHFORK,
    STRATEGY_SINGLE,
    STRATEGY_SNIPER,
    STRATEGY_ZIP,
)
from talos.intruder.processors import build_processor, is_known_processor
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
            "max_concurrency_per_host": None,
            "jitter_ms": DEFAULT_JITTER_MS,
            "timeout_s": DEFAULT_TIMEOUT_S,
        },
        "slice": {
            "max_attempts": DEFAULT_SLICE_MAX_ATTEMPTS,
            "max_wall_s": DEFAULT_SLICE_MAX_WALL_S,
        },
        "storage": {
            "mode": STORAGE_METRICS_ONLY,
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


def _normalize_strategy_type(stype: str) -> str:
    key = (stype or "").strip().lower()
    if key == STRATEGY_CARTESIAN:
        return STRATEGY_CLUSTER_BOMB
    return key


def _inject_runtime_opts(
    opts: dict[str, Any],
    *,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
) -> dict[str, Any]:
    """Attach db_path / project_id for generators that need project data."""
    open_opts = dict(opts)
    if db_path is not None:
        open_opts.setdefault("db_path", str(db_path))
    if project_id is not None:
        open_opts.setdefault("project_id", project_id)
    return open_opts


def _open_generator(
    gen_name: str,
    opts: dict[str, Any],
    *,
    force: bool,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
) -> Any:
    open_opts = _inject_runtime_opts(opts, db_path=db_path, project_id=project_id)
    if force:
        open_opts["force"] = True
    try:
        return build_generator(gen_name, open_opts)
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith(ERR_WORDLIST_TOO_LARGE):
            raise ValidationError(ERR_WORDLIST_TOO_LARGE, msg) from exc
        if msg.startswith(ERR_EMPTY_GENERATOR) or "empty" in msg:
            raise ValidationError(ERR_EMPTY_GENERATOR, msg) from exc
        if msg.startswith(ERR_INVALID_NUMBERS) or "invalid_numbers" in msg:
            raise ValidationError(ERR_INVALID_NUMBERS, msg) from exc
        if msg.startswith(ERR_POOL_NOT_FOUND):
            raise ValidationError(ERR_POOL_NOT_FOUND, msg) from exc
        if msg.startswith(ERR_PARAM_NOT_FOUND):
            raise ValidationError(ERR_PARAM_NOT_FOUND, msg) from exc
        if msg.startswith(ERR_INVALID_FILE_GENERATOR):
            raise ValidationError(ERR_INVALID_FILE_GENERATOR, msg) from exc
        raise ValidationError(ERR_UNKNOWN_PLUGIN, msg) from exc


def _estimate_multiset(
    stype: str,
    set_names: list[str],
    payload_sets: dict[str, Any],
    *,
    force: bool,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
) -> Optional[int]:
    counts: list[int] = []
    for name in set_names:
        pset = payload_sets[name]
        gen = _open_generator(
            str(pset.get("generator")),
            dict(pset.get("options") or {}),
            force=force,
            db_path=db_path,
            project_id=project_id,
        )
        c = gen.estimate_count()
        if c is None:
            return None
        if c == 0:
            raise ValidationError(ERR_EMPTY_GENERATOR, f"payload set {name} empty")
        counts.append(c)
    if not counts:
        return 0
    if stype in (STRATEGY_PITCHFORK, STRATEGY_ZIP):
        return min(counts)
    # cluster_bomb / cartesian
    total = 1
    for c in counts:
        total *= c
    return total


def validate_config(
    config: dict[str, Any],
    *,
    open_generators: bool = True,
    force: bool = False,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
) -> tuple[dict[str, Any], Optional[int]]:
    """
    Validate and normalize config.
    Returns (normalized_config, estimate_attempts).
    Raises ValidationError with stable code.

    db_path / project_id are required when opening pool or example_values generators.
    """
    cfg = merge_defaults(config)
    ver = cfg.get("schema_version")
    if ver is None or int(ver) != CONFIG_SCHEMA_VERSION:
        raise ValidationError(
            ERR_UNSUPPORTED_CONFIG_VERSION,
            f"unsupported config schema_version={ver!r}; requires {CONFIG_SCHEMA_VERSION}",
        )

    tmpl = cfg.get("template") or {}
    if not tmpl.get("method") or not tmpl.get("url"):
        raise ValidationError(ERR_MISSING_BASELINE, "template method/url required")

    # Storage mode
    storage = cfg.get("storage") or {}
    mode = str(storage.get("mode") or STORAGE_METRICS_ONLY).lower()
    if mode not in KNOWN_STORAGE_MODES:
        raise ValidationError(ERR_INVALID_STORAGE_MODE, f"unknown storage mode: {mode}")
    storage["mode"] = mode
    try:
        sample_rate = float(storage.get("sample_rate") or 0.0)
    except (TypeError, ValueError) as exc:
        raise ValidationError(ERR_INVALID_STORAGE_MODE, "sample_rate must be a number") from exc
    if sample_rate < 0.0 or sample_rate > 1.0:
        raise ValidationError(ERR_INVALID_STORAGE_MODE, "sample_rate must be in [0, 1]")
    storage["sample_rate"] = sample_rate
    cfg["storage"] = storage

    # Timing: optional host concurrency cap
    timing = cfg.get("timing") or {}
    per_host = timing.get("max_concurrency_per_host")
    if per_host is not None and per_host != "":
        try:
            per_host_i = int(per_host)
        except (TypeError, ValueError) as exc:
            raise ValidationError(ERR_UNKNOWN_PLUGIN, "max_concurrency_per_host must be int") from exc
        if per_host_i < 1:
            raise ValidationError(ERR_UNKNOWN_PLUGIN, "max_concurrency_per_host must be >= 1")
        timing["max_concurrency_per_host"] = per_host_i
    else:
        timing["max_concurrency_per_host"] = None
    cfg["timing"] = timing

    variables = variables_from_config(cfg)
    injectable = [v for v in variables if not v.is_fixed()]
    strategy = cfg.get("strategy") or {}
    stype = _normalize_strategy_type(str(strategy.get("type") or STRATEGY_SINGLE))
    if stype not in KNOWN_STRATEGIES:
        raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown strategy: {stype}")

    if stype in (STRATEGY_SINGLE, STRATEGY_SNIPER) and not injectable and not variables:
        raise ValidationError(ERR_NO_VARIABLES, "strategy requires template variables")

    if stype == STRATEGY_SNIPER:
        targets = (strategy.get("options") or {}).get("targets")
        if targets is not None and len(targets) == 0:
            raise ValidationError(ERR_SNIPER_NO_TARGETS)
        if not injectable and not targets:
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
        if stype in (STRATEGY_SINGLE, STRATEGY_SNIPER) or stype in MULTI_SET_STRATEGIES:
            raise ValidationError(ERR_UNBOUND_VARIABLE, "payload_sets required")

    # Resolve project_id from session block when not passed
    sess_block = cfg.get("session") or {}
    if project_id is None:
        project_id = sess_block.get("project_id")

    # Validate generators / processors
    for set_name, pset in payload_sets.items():
        if not isinstance(pset, dict):
            raise ValidationError(ERR_UNKNOWN_PLUGIN, f"bad payload set {set_name}")
        gen_name = str(pset.get("generator") or "").lower()
        if gen_name not in KNOWN_GENERATORS:
            raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown generator: {gen_name}")
        # Structural checks for Phase 3 generators that need runtime context
        opts = dict(pset.get("options") or {})
        if gen_name in (GEN_POOL, GEN_EXAMPLE_VALUES) and open_generators:
            if db_path is None:
                raise ValidationError(
                    ERR_UNKNOWN_PLUGIN,
                    f"{gen_name} generator requires db_path at validate/run",
                )
        if gen_name == GEN_POOL and not (
            opts.get("name") or opts.get("pool") or opts.get("pool_name")
        ):
            raise ValidationError(ERR_POOL_NOT_FOUND, f"pool set {set_name}: missing pool name")
        if gen_name == GEN_EXAMPLE_VALUES:
            if not opts.get("param_id") and not (
                opts.get("endpoint_id") and opts.get("name") and opts.get("location")
            ):
                raise ValidationError(
                    ERR_PARAM_NOT_FOUND,
                    f"example_values set {set_name}: need param_id or endpoint_id+name+location",
                )
        if gen_name in (GEN_CSV, GEN_JSON) and not (opts.get("path") or opts.get("file")):
            raise ValidationError(
                ERR_INVALID_FILE_GENERATOR,
                f"{gen_name} set {set_name}: missing path/file",
            )
        for proc in pset.get("processors") or []:
            pname = str(proc)
            if not is_known_processor(pname):
                raise ValidationError(ERR_UNKNOWN_PLUGIN, f"unknown processor: {pname}")
            build_processor(pname)

        if open_generators:
            gen = _open_generator(
                gen_name,
                opts,
                force=force,
                db_path=db_path,
                project_id=project_id,
            )
            count = gen.estimate_count()
            if count is not None and count == 0:
                raise ValidationError(ERR_EMPTY_GENERATOR, f"payload set {set_name} empty")

    # Grep rules
    grep_rules = cfg.get("grep") or []
    if not isinstance(grep_rules, list):
        raise ValidationError(ERR_INVALID_GREP, "grep must be a list")
    for rule in grep_rules:
        try:
            validate_grep_rule(rule)
        except ValueError as exc:
            raise ValidationError(ERR_INVALID_GREP, str(exc)) from exc
    cfg["grep"] = grep_rules

    estimate: Optional[int] = None

    # Multi-set strategies: resolve ordered set names and estimate
    if stype in MULTI_SET_STRATEGIES:
        opts = strategy.setdefault("options", {})
        ordered = opts.get("sets") or opts.get("variables")
        if ordered:
            set_names = [str(s) for s in ordered]
        else:
            matched = [v.name for v in injectable if v.name in payload_sets]
            set_names = matched if matched else list(payload_sets.keys())
        if not set_names:
            raise ValidationError(ERR_MULTISET_UNBOUND, "multi-set strategy needs payload sets")
        for name in set_names:
            if name not in payload_sets:
                raise ValidationError(ERR_UNBOUND_VARIABLE, f"no payload set for {name}")
            # Variable should exist on template (or will be treated as raw-style binding name)
            var_names = {v.name for v in variables}
            if name not in var_names:
                raise ValidationError(
                    ERR_UNBOUND_VARIABLE,
                    f"payload set '{name}' has no matching template variable",
                )
        opts["sets"] = set_names
        if open_generators:
            estimate = _estimate_multiset(
                stype,
                set_names,
                payload_sets,
                force=force,
                db_path=db_path,
                project_id=project_id,
            )

    # Estimate for sniper
    if open_generators and stype == STRATEGY_SNIPER:
        targets = (strategy.get("options") or {}).get("targets")
        n_targets = len(targets) if targets else len(injectable)
        first = next(iter(payload_sets.values()), None)
        if first:
            gen = _open_generator(
                str(first.get("generator")),
                dict(first.get("options") or {}),
                force=force,
                db_path=db_path,
                project_id=project_id,
            )
            pc = gen.estimate_count() or 0
            estimate = pc * max(1, n_targets)
    elif open_generators and stype == STRATEGY_SINGLE:
        first_name = None
        opts = strategy.setdefault("options", {})
        primary = opts.get("primary") or opts.get("var")
        if primary and primary in payload_sets:
            first_name = primary
        elif len(payload_sets) == 1:
            first_name = next(iter(payload_sets.keys()))
        if first_name:
            pset = payload_sets[first_name]
            gen = _open_generator(
                str(pset.get("generator")),
                dict(pset.get("options") or {}),
                force=force,
                db_path=db_path,
                project_id=project_id,
            )
            estimate = gen.estimate_count()

    # Bind strategy primary var for single
    if stype == STRATEGY_SINGLE and injectable:
        opts = strategy.setdefault("options", {})
        if not opts.get("primary") and not opts.get("var"):
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


def storage_requires_confirm(config: dict[str, Any]) -> bool:
    """all_flows storage needs operator confirm / --force."""
    mode = str(((config or {}).get("storage") or {}).get("mode") or "").lower()
    return mode == "all_flows"
