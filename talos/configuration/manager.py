"""
Module: talos.configuration.manager

Purpose:
    Configuration Manager — single authority for layered configuration.

    Precedence (highest last):
        1. Built-in defaults
        2. Global config.yaml (~/.talos/config.yaml)
        3. Legacy project stores (SQLite / headers_drop.txt / constraints)
        4. Project project.yaml
        5. CLI one-shot overrides

    Exactly one EffectiveConfig is produced per load. Subsystems should not
    re-open config files for values covered by this model.

Dependencies:
    pathlib, talos.config.TalosConfig, talos.configuration.*
Data flow:
    CLI / proxy addon / helpers → ConfigurationManager.load → EffectiveConfig
Side effects:
    set / unset write YAML files; optional dual-write to legacy SQLite tables.
"""

from __future__ import annotations

import logging
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from talos.configuration.defaults import BUILTIN_DEFAULTS, CONFIG_SECTIONS
from talos.configuration.io import (
    ConfigIOError,
    global_config_path,
    load_yaml_file,
    project_config_path,
    save_yaml_file,
)
from talos.configuration.legacy import (
    load_legacy_project_layer,
    mirror_attack_to_legacy,
    mirror_proxy_to_legacy,
    mirror_scheduler_to_legacy,
)
from talos.configuration.merge import (
    deep_merge,
    flatten_leaves,
    get_path,
    path_exists,
    set_path,
    unset_path,
)
from talos.configuration.http_rules import parse_rules, sort_rules
from talos.configuration.model import (
    AttackConfigSection,
    AuthConfigSection,
    BurpConfigSection,
    CaptureConfigSection,
    CrossFlowConfigSection,
    EffectiveConfig,
    HttpConfigSection,
    ParameterIntelConfigSection,
    PlatformAuthEntry,
    PlatformAuthSection,
    ProxyConfigSection,
    SchedulerConfigSection,
    UrlSinkConfigSection,
    ValueSource,
)

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """
    Purpose:
        Configuration operation failure (bad path, I/O, validation).
        CLI maps to EXIT_USAGE or EXIT_FAILURE.
    """


class ConfigurationManager:
    """
    Purpose:
        Load, merge, query, and mutate layered configuration.

    Fields:
        data_dir — Talos root data directory (global config lives here).
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir: Path = Path(data_dir)
        self.global_path: Path = global_config_path(self.data_dir)

    @classmethod
    def from_env(cls) -> "ConfigurationManager":
        """
        Purpose:
            Build a manager using TalosConfig.from_env() data_dir.
        Side effects: Reads TALOS_DATA_DIR when set.
        """
        from talos.config import TalosConfig

        return cls(TalosConfig.from_env().data_dir)

    # ------------------------------------------------------------------ #
    # Load                                                                 #
    # ------------------------------------------------------------------ #

    def load(
        self,
        *,
        project_data_dir: Optional[Path] = None,
        store_bodies: Optional[bool] = None,
        max_body_size: Optional[int] = None,
        cli_overrides: Optional[dict] = None,
    ) -> EffectiveConfig:
        """
        Purpose:
            Build the immutable EffectiveConfig for the current context.
        Input:
            project_data_dir — when set, project + legacy layers apply.
            store_bodies / max_body_size — registry constraints (legacy).
            cli_overrides — partial tree applied last (one-shot flags).
        Output:
            EffectiveConfig with raw tree + source map.
        Side effects: Reads YAML / legacy files when present.
        """
        defaults = deepcopy(BUILTIN_DEFAULTS)
        try:
            global_layer = load_yaml_file(self.global_path)
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc

        legacy_layer: dict = {}
        project_layer: dict = {}
        project_path: Optional[Path] = None

        if project_data_dir is not None:
            pdir = Path(project_data_dir)
            project_path = project_config_path(pdir)
            # Global config only applies to projects stored under this
            # manager's data_dir/projects. Isolated test trees and ad-hoc
            # paths skip global so ~/.talos never leaks into pytest.
            if not self._is_managed_project(pdir):
                global_layer = {}
            legacy_layer = load_legacy_project_layer(
                pdir,
                store_bodies=store_bodies,
                max_body_size=max_body_size,
            )
            try:
                project_layer = load_yaml_file(project_path)
            except ConfigIOError as exc:
                raise ConfigError(str(exc)) from exc

        cli_layer = cli_overrides or {}

        # Merge: defaults ← global ← legacy ← project ← cli
        # http.rules are concatenated across layers (not replaced) so global
        # and project rules both apply. Other keys use standard deep_merge.
        merged = deep_merge(defaults, global_layer)
        merged = deep_merge(merged, legacy_layer)
        merged = deep_merge(merged, project_layer)
        merged = deep_merge(merged, cli_layer)

        effective_rules = self._concatenate_http_rules(
            defaults=defaults,
            global_layer=global_layer,
            legacy_layer=legacy_layer,
            project_layer=project_layer,
            cli_layer=cli_layer,
        )
        http_section = merged.get("http")
        if not isinstance(http_section, dict):
            http_section = {}
            merged["http"] = http_section
        http_section["rules"] = effective_rules

        sources = self._build_source_map(
            defaults=defaults,
            global_layer=global_layer,
            legacy_layer=legacy_layer,
            project_layer=project_layer,
            cli_layer=cli_layer,
            merged=merged,
        )

        return self._to_effective(
            merged,
            sources=sources,
            project_path=str(project_path) if project_path else None,
        )

    def load_for_project(self, project: Any, *, cli_overrides: Optional[dict] = None) -> EffectiveConfig:
        """
        Purpose:
            Convenience load from a Project instance (or duck-typed object).
        Input:
            project — object with data_dir and constraints attributes.
            cli_overrides — optional one-shot tree.
        Output:
            EffectiveConfig.
        Side effects: Same as load().
        """
        constraints = getattr(project, "constraints", None)
        store_bodies = getattr(constraints, "store_bodies", None) if constraints else None
        max_body_size = getattr(constraints, "max_body_size", None) if constraints else None
        return self.load(
            project_data_dir=Path(project.data_dir),
            store_bodies=store_bodies,
            max_body_size=max_body_size,
            cli_overrides=cli_overrides,
        )

    # ------------------------------------------------------------------ #
    # Mutation (write)                                                     #
    # ------------------------------------------------------------------ #

    def get_layer(self, *, global_scope: bool, project_data_dir: Optional[Path]) -> dict:
        """
        Purpose:
            Return the raw YAML layer for global or project scope.
        Side effects: Reads the target file when present.
        """
        path = self._target_path(global_scope=global_scope, project_data_dir=project_data_dir)
        try:
            return load_yaml_file(path)
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc

    def set_value(
        self,
        path: str,
        value: Any,
        *,
        global_scope: bool = False,
        project_data_dir: Optional[Path] = None,
        project_db_path: Optional[Path] = None,
    ) -> Path:
        """
        Purpose:
            Set a dotted key in global or project YAML and dual-write legacy
            stores when applicable.
        Input:
            path             — dotted key (e.g. "scheduler.min_delay").
            value            — new value.
            global_scope     — write ~/.talos/config.yaml when True.
            project_data_dir — required when global_scope is False.
            project_db_path  — optional; enables SQLite dual-write.
        Output:
            Path of the file written.
        Side effects:
            Writes YAML; may write SQLite for proxy/scheduler/attack keys.
        """
        path = self._normalize_path(path)
        target = self._target_path(
            global_scope=global_scope, project_data_dir=project_data_dir
        )
        try:
            current = load_yaml_file(target)
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc

        updated = set_path(current, path, value)
        save_yaml_file(target, updated)
        self._maybe_mirror_legacy(
            path, value, project_db_path=project_db_path, layer=updated
        )
        return target

    def unset_value(
        self,
        path: str,
        *,
        global_scope: bool = False,
        project_data_dir: Optional[Path] = None,
        project_db_path: Optional[Path] = None,
    ) -> tuple[Path, bool]:
        """
        Purpose:
            Remove a dotted key from global or project YAML so the lower
            layer (global or defaults) is inherited again.
        Output:
            (file_path, removed) — removed is False when the key was absent.
        Side effects:
            Writes YAML when removed; may dual-write legacy after re-merge.
        """
        path = self._normalize_path(path)
        target = self._target_path(
            global_scope=global_scope, project_data_dir=project_data_dir
        )
        try:
            current = load_yaml_file(target)
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc

        updated, removed = unset_path(current, path)
        if removed:
            save_yaml_file(target, updated)
            # After unset, re-load effective project view for dual-write of
            # remaining values is handled by callers when needed; for proxy
            # unset, clear legacy if project no longer sets upstream.
            if not global_scope and project_db_path is not None:
                self._mirror_after_project_change(
                    project_data_dir=project_data_dir,
                    project_db_path=project_db_path,
                )
        return target, removed

    # ------------------------------------------------------------------ #
    # Internals                                                            #
    # ------------------------------------------------------------------ #

    def _target_path(
        self, *, global_scope: bool, project_data_dir: Optional[Path]
    ) -> Path:
        if global_scope:
            return self.global_path
        if project_data_dir is None:
            raise ConfigError(
                "Project configuration requires a bound project. "
                "Run 'talos project open <id>', pass --project <id>, "
                "or use --global."
            )
        return project_config_path(Path(project_data_dir))

    def _is_managed_project(self, project_data_dir: Path) -> bool:
        """
        Purpose:
            Return True when project_data_dir lives under data_dir/projects.
        Side effects: None.
        """
        try:
            project_data_dir.resolve().relative_to(
                (self.data_dir / "projects").resolve()
            )
            return True
        except ValueError:
            return False

    @staticmethod
    def _normalize_path(path: str) -> str:
        cleaned = path.strip().lstrip(".")
        if not cleaned or ".." in cleaned.split("."):
            raise ConfigError(f"Invalid config path: {path!r}")
        # Reject empty segments
        parts = cleaned.split(".")
        if any(not p for p in parts):
            raise ConfigError(f"Invalid config path: {path!r}")
        return cleaned

    def _build_source_map(
        self,
        *,
        defaults: dict,
        global_layer: dict,
        legacy_layer: dict,
        project_layer: dict,
        cli_layer: dict,
        merged: dict,
    ) -> dict[str, ValueSource]:
        """
        Purpose:
            For each leaf in the merged tree, record which layer won.
        Side effects: None.
        """
        sources: dict[str, ValueSource] = {}
        for leaf_path in flatten_leaves(merged):
            if path_exists(cli_layer, leaf_path):
                sources[leaf_path] = ValueSource.CLI
            elif path_exists(project_layer, leaf_path):
                sources[leaf_path] = ValueSource.PROJECT
            elif path_exists(global_layer, leaf_path) and path_exists(
                legacy_layer, leaf_path
            ):
                # Dual-write mirrors the YAML merge into SQLite. When legacy
                # merely echoes the global value, attribute to global; when
                # it differs, legacy is the true override.
                if get_path(legacy_layer, leaf_path) == get_path(
                    global_layer, leaf_path
                ):
                    sources[leaf_path] = ValueSource.GLOBAL
                else:
                    sources[leaf_path] = ValueSource.LEGACY
            elif path_exists(legacy_layer, leaf_path):
                legacy_val = get_path(legacy_layer, leaf_path)
                default_val = get_path(defaults, leaf_path)
                if legacy_val == default_val:
                    sources[leaf_path] = ValueSource.DEFAULT
                else:
                    sources[leaf_path] = ValueSource.LEGACY
            elif path_exists(global_layer, leaf_path):
                sources[leaf_path] = ValueSource.GLOBAL
            else:
                sources[leaf_path] = ValueSource.DEFAULT
        return sources

    @staticmethod
    def _concatenate_http_rules(
        *,
        defaults: dict,
        global_layer: dict,
        legacy_layer: dict,
        project_layer: dict,
        cli_layer: dict,
    ) -> list[dict]:
        """
        Purpose:
            Build the effective http.rules list by concatenating every layer.
            Unlike other config leaves (which replace), rules accumulate so
            operators can keep global defaults and add project-scoped rules.
        Output:
            Sorted list of normalized rule dicts with ``source`` stamped.
        Side effects: None.
        """
        combined: list[dict] = []
        for source_label, layer in (
            ("default", defaults),
            ("global", global_layer),
            ("legacy", legacy_layer),
            ("project", project_layer),
            ("cli", cli_layer),
        ):
            raw = get_path(layer, "http.rules", None)
            if not raw:
                continue
            try:
                parsed = parse_rules(raw, source=source_label)
            except ValueError as exc:
                logger.warning("Skipping invalid http.rules in %s layer: %s", source_label, exc)
                continue
            combined.extend(parsed)
        return sort_rules(combined)

    def _to_effective(
        self,
        merged: dict,
        *,
        sources: dict[str, ValueSource],
        project_path: Optional[str],
    ) -> EffectiveConfig:
        proxy_raw = merged.get("proxy") or {}
        upstream = proxy_raw.get("upstream") or {}
        capture_raw = merged.get("capture") or {}
        sched_raw = merged.get("scheduler") or {}
        if not isinstance(sched_raw, dict):
            sched_raw = {}
        tw_raw = sched_raw.get("testing_windows") or {}
        if not isinstance(tw_raw, dict):
            tw_raw = {}
        attack_raw = merged.get("attack") or {}
        http_raw = merged.get("http") or {}

        drop_headers = capture_raw.get("drop_headers") or []
        if not isinstance(drop_headers, list):
            drop_headers = list(drop_headers) if drop_headers else []

        rules_raw = http_raw.get("rules") or []
        if not isinstance(rules_raw, list):
            rules_raw = []
        # Rules may already be normalized (with source) from load().
        try:
            rules = parse_rules(rules_raw) if rules_raw else []
            # Preserve source stamps when already present.
            for i, r in enumerate(rules):
                if i < len(rules_raw) and isinstance(rules_raw[i], dict):
                    src = rules_raw[i].get("source")
                    if src:
                        r["source"] = src
            rules = sort_rules(rules)
        except ValueError as exc:
            logger.warning("Invalid effective http.rules: %s", exc)
            rules = []

        enabled = bool(upstream.get("enabled", False))
        url = upstream.get("url")
        if url is not None:
            url = str(url).strip() or None
        # enabled with empty url is treated as Direct.
        if enabled and not url:
            enabled = False

        pi_raw = merged.get("parameter_intel") or {}
        cf_raw = pi_raw.get("cross_flow") or {} if isinstance(pi_raw, dict) else {}
        if not isinstance(cf_raw, dict):
            cf_raw = {}

        cross_flow = CrossFlowConfigSection(
            enabled=bool(cf_raw.get("enabled", False)),
            feed_iv=bool(cf_raw.get("feed_iv", True)),
            active_sink_probe=bool(cf_raw.get("active_sink_probe", False)),
            value_index_ttl_hours=int(cf_raw.get("value_index_ttl_hours", 72)),
            value_index_max_per_host=int(cf_raw.get("value_index_max_per_host", 50_000)),
            value_index_max_sources_per_value=int(
                cf_raw.get("value_index_max_sources_per_value", 8)
            ),
            min_value_len=int(cf_raw.get("min_value_len", 6)),
            scan_hot_set_k=int(cf_raw.get("scan_hot_set_k", 2000)),
            scan_time_budget_ms=int(cf_raw.get("scan_time_budget_ms", 20)),
            max_body_scan_bytes=int(cf_raw.get("max_body_scan_bytes", 2_000_000)),
            canary_ttl_hours=int(cf_raw.get("canary_ttl_hours", 24)),
        )

        us_raw = merged.get("url_sink") or {}
        if not isinstance(us_raw, dict):
            us_raw = {}
        passive_raw = us_raw.get("passive") or {}
        html_js_raw = us_raw.get("html_js") or {}
        iv_probes_raw = us_raw.get("iv_probes") or {}
        if not isinstance(passive_raw, dict):
            passive_raw = {}
        if not isinstance(html_js_raw, dict):
            html_js_raw = {}
        if not isinstance(iv_probes_raw, dict):
            iv_probes_raw = {}
        try:
            score_threshold = int(us_raw.get("score_threshold", 45))
        except (TypeError, ValueError):
            score_threshold = 45
        score_threshold = max(0, min(100, score_threshold))
        url_sink = UrlSinkConfigSection(
            passive_enabled=bool(passive_raw.get("enabled", True)),
            html_js_enabled=bool(html_js_raw.get("enabled", True)),
            iv_probes_enabled=bool(iv_probes_raw.get("enabled", True)),
            score_threshold=score_threshold,
        )

        burp_raw = merged.get("burp") or {}
        if not isinstance(burp_raw, dict):
            burp_raw = {}
        header_prefix = burp_raw.get("header_prefix", "X-Talos")
        if not isinstance(header_prefix, str) or not header_prefix.strip():
            header_prefix = "X-Talos"
        burp = BurpConfigSection(
            enabled=bool(burp_raw.get("enabled", True)),
            header_prefix=header_prefix.strip(),
        )

        auth_raw = merged.get("auth") or {}
        if not isinstance(auth_raw, dict):
            auth_raw = {}
        auth_mode = str(auth_raw.get("mode") or "artifacts").strip().lower()
        if auth_mode not in ("artifacts", "platform_ntlm"):
            auth_mode = "artifacts"
        auth = AuthConfigSection(mode=auth_mode)

        return EffectiveConfig(
            proxy=ProxyConfigSection(
                upstream_enabled=enabled,
                upstream_url=url,
                http2=_as_bool(proxy_raw.get("http2"), True),
                keep_alive=_as_bool(proxy_raw.get("keep_alive"), True),
                platform_auth=_parse_platform_auth(proxy_raw.get("platform_auth")),
            ),
            capture=CaptureConfigSection(
                store_bodies=bool(capture_raw.get("store_bodies", True)),
                max_body_size=int(capture_raw.get("max_body_size", 1 * 1024 * 1024)),
                drop_headers=tuple(str(h) for h in drop_headers),
            ),
            scheduler=SchedulerConfigSection(
                min_delay=float(sched_raw.get("min_delay", 2.0)),
                max_delay=float(sched_raw.get("max_delay", 6.0)),
                max_queue_size=int(sched_raw.get("max_queue_size", 200)),
                testing_windows_enabled=_as_bool(tw_raw.get("enabled"), False),
                testing_windows=_parse_testing_windows(tw_raw.get("windows")),
            ),
            attack=AttackConfigSection(
                unauth_auto_run=bool(attack_raw.get("unauth_auto_run", False)),
            ),
            http=HttpConfigSection(
                enabled=bool(http_raw.get("enabled", True)),
                rules=tuple(rules),
            ),
            parameter_intel=ParameterIntelConfigSection(cross_flow=cross_flow),
            url_sink=url_sink,
            burp=burp,
            auth=auth,
            raw=merged,
            sources=sources,
            global_path=str(self.global_path),
            project_path=project_path,
        )

    def _maybe_mirror_legacy(
        self,
        path: str,
        value: Any,
        *,
        project_db_path: Optional[Path],
        layer: dict,
    ) -> None:
        """Dual-write selected keys into SQLite when a project DB is available."""
        if project_db_path is None:
            return
        if path.startswith("proxy.upstream") or path == "proxy":
            up = get_path(layer, "proxy.upstream", {}) or {}
            enabled = bool(up.get("enabled", False)) if isinstance(up, dict) else False
            url = up.get("url") if isinstance(up, dict) else None
            if path == "proxy.upstream.enabled":
                enabled = bool(value)
            if path == "proxy.upstream.url":
                url = value
                enabled = bool(url)
            mirror_proxy_to_legacy(project_db_path, enabled, url if url else None)
        elif path.startswith("scheduler.") or path == "scheduler":
            # Re-read full scheduler from layer with defaults.
            from talos.configuration.defaults import BUILTIN_DEFAULTS

            base = deep_merge(BUILTIN_DEFAULTS.get("scheduler", {}), get_path(layer, "scheduler", {}) or {})
            mirror_scheduler_to_legacy(
                project_db_path,
                min_delay=float(base.get("min_delay", 2.0)),
                max_delay=float(base.get("max_delay", 6.0)),
                max_queue_size=int(base.get("max_queue_size", 200)),
            )
        elif path == "attack.unauth_auto_run":
            mirror_attack_to_legacy(project_db_path, bool(value))

    def _mirror_after_project_change(
        self,
        *,
        project_data_dir: Optional[Path],
        project_db_path: Path,
    ) -> None:
        """
        Purpose:
            After unsetting a project key, re-sync legacy SQLite from the
            YAML-only merge (defaults → global → project.yaml), deliberately
            ignoring legacy SQLite so sticky dual-write values cannot defeat
            an unset.
        """
        if project_data_dir is None:
            return
        effective = self._load_yaml_layers_only(Path(project_data_dir))
        mirror_proxy_to_legacy(
            project_db_path,
            effective.proxy.upstream_enabled,
            effective.proxy.upstream_url,
        )
        mirror_scheduler_to_legacy(
            project_db_path,
            min_delay=effective.scheduler.min_delay,
            max_delay=effective.scheduler.max_delay,
            max_queue_size=effective.scheduler.max_queue_size,
        )
        mirror_attack_to_legacy(
            project_db_path, effective.attack.unauth_auto_run
        )

    def _load_yaml_layers_only(self, project_data_dir: Path) -> EffectiveConfig:
        """
        Purpose:
            Merge defaults + global + project.yaml without the legacy bridge.
            Used when dual-writing SQLite after YAML mutations so SQLite
            tracks YAML intent rather than its own previous values.
        Side effects: Reads YAML files only.
        """
        defaults = deepcopy(BUILTIN_DEFAULTS)
        try:
            global_layer = load_yaml_file(self.global_path)
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc
        if not self._is_managed_project(project_data_dir):
            global_layer = {}
        try:
            project_layer = load_yaml_file(project_config_path(project_data_dir))
        except ConfigIOError as exc:
            raise ConfigError(str(exc)) from exc
        merged = deep_merge(defaults, global_layer)
        merged = deep_merge(merged, project_layer)
        effective_rules = self._concatenate_http_rules(
            defaults=defaults,
            global_layer=global_layer,
            legacy_layer={},
            project_layer=project_layer,
            cli_layer={},
        )
        http_section = merged.get("http")
        if not isinstance(http_section, dict):
            http_section = {}
            merged["http"] = http_section
        http_section["rules"] = effective_rules
        return self._to_effective(
            merged,
            sources={},
            project_path=str(project_config_path(project_data_dir)),
        )


def load_effective_config(
    project: Any = None,
    *,
    data_dir: Optional[Path] = None,
    cli_overrides: Optional[dict] = None,
) -> EffectiveConfig:
    """
    Purpose:
        Module-level convenience for subsystems that need EffectiveConfig.
    Input:
        project       — optional Project instance.
        data_dir      — optional Talos data dir (defaults to from_env).
        cli_overrides — optional one-shot overrides.
    Output:
        EffectiveConfig.
    Side effects: Reads config files.
    """
    if data_dir is not None:
        mgr = ConfigurationManager(data_dir)
    else:
        mgr = ConfigurationManager.from_env()
    if project is None:
        return mgr.load(cli_overrides=cli_overrides)
    return mgr.load_for_project(project, cli_overrides=cli_overrides)


def section_names() -> tuple[str, ...]:
    """Return first-class config section names."""
    return CONFIG_SECTIONS


def _as_bool(value: Any, default: bool) -> bool:
    """
    Purpose:
        Coerce YAML/CLI values to bool without treating "false" as True.
    Side effects: None.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off", ""):
            return False
    return bool(value)


def _parse_testing_windows(raw: Any) -> tuple[str, ...]:
    """
    Purpose:
        Canonicalize scheduler.testing_windows.windows; drop invalid entries
        so a typo cannot crash the scheduler load path.
    """
    if raw is None or raw == "":
        return ()
    if isinstance(raw, str):
        items: list[Any] = [raw]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        return ()
    from talos.scheduler.testing_windows import WindowParseError, normalize_windows

    valid: list[str] = []
    for item in items:
        try:
            valid.extend(normalize_windows([item]))
        except WindowParseError as exc:
            logger.warning("Ignoring invalid testing window %r: %s", item, exc)
    try:
        return normalize_windows(valid)
    except WindowParseError:
        return ()


_PROFILE_ID_RE = re.compile(r"[^a-z0-9]+")


def slugify_profile_id(text: str) -> str:
    """
    Purpose:
        Turn a name or host into a stable lowercase profile id.
    Side effects: None.
    """
    cleaned = _PROFILE_ID_RE.sub("-", (text or "").strip().lower()).strip("-")
    return (cleaned[:48] or "profile")


def uniquify_profile_id(base: str, taken: set[str]) -> str:
    """
    Purpose:
        Append -2, -3, … when ``base`` is already used.
    Side effects: None.
    """
    candidate = base or "profile"
    n = 2
    while candidate in taken:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _parse_platform_auth(raw: Any) -> PlatformAuthSection:
    """
    Purpose:
        Build PlatformAuthSection from a merged YAML mapping.
    Side effects: None. Invalid rows are skipped with a warning.
    """
    if not isinstance(raw, dict):
        return PlatformAuthSection()
    entries_raw = raw.get("entries") or []
    if not isinstance(entries_raw, list):
        entries_raw = []
    entries: list[PlatformAuthEntry] = []
    taken: set[str] = set()
    for item in entries_raw:
        try:
            entry = parse_platform_auth_entry(item)
        except ValueError as exc:
            logger.warning("Skipping invalid platform-auth entry: %s", exc)
            continue
        profile_id = uniquify_profile_id(entry.id or slugify_profile_id(entry.host), taken)
        taken.add(profile_id)
        if entry.id != profile_id:
            from dataclasses import replace

            entry = replace(entry, id=profile_id)
        entries.append(entry)
    return PlatformAuthSection(
        enabled=_as_bool(raw.get("enabled"), False),
        entries=tuple(entries),
    )


def parse_platform_auth_entry(raw: Any) -> PlatformAuthEntry:
    """
    Purpose:
        Validate one platform-auth mapping into a PlatformAuthEntry.
    Input:
        raw — dict from YAML / CLI / Control Panel.
    Output:
        Immutable PlatformAuthEntry.
    Side effects: None.
    Raises:
        ValueError when host is missing or auth_type is unknown.
    """
    if not isinstance(raw, dict):
        raise ValueError("platform-auth entry must be a mapping")
    host = str(raw.get("host") or "").strip()
    if not host:
        raise ValueError("platform-auth entry requires host")
    auth_type = str(raw.get("auth_type") or raw.get("type") or "ntlmv2").strip().lower()
    if auth_type not in ("ntlmv2", "ntlm", "negotiate"):
        raise ValueError(
            f"platform-auth type must be ntlmv2, ntlm, or negotiate (got {auth_type!r})"
        )
    negotiate = raw.get("negotiate")
    if negotiate is None:
        negotiate = auth_type == "negotiate"
    name = str(raw.get("name") or "").strip()
    profile_id = str(raw.get("id") or "").strip()
    if not profile_id:
        profile_id = slugify_profile_id(name or host)
    return PlatformAuthEntry(
        host=host,
        auth_type=auth_type,
        username=str(raw.get("username") or "").strip(),
        password=str(raw.get("password") or ""),
        domain=str(raw.get("domain") or "").strip(),
        domain_hostname=str(raw.get("domain_hostname") or "").strip(),
        spnego=_as_bool(raw.get("spnego"), False),
        negotiate=_as_bool(negotiate, False),
        id=profile_id,
        name=name or host,
        enabled=_as_bool(raw.get("enabled"), True),
    )
