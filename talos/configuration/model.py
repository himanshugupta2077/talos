"""
Module: talos.configuration.model

Purpose:
    Immutable effective configuration objects consumed by runtime subsystems.
    Built by ConfigurationManager after merging all layers.

Dependencies: dataclasses, typing
Data flow: ConfigurationManager → EffectiveConfig → proxy / scheduler / attack / …
Side effects: None — pure data containers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ValueSource(str, Enum):
    """
    Purpose:
        Identify which layer supplied an effective value.
        Used by `talos config get` / `effective` for inheritance visibility.
    """

    DEFAULT = "default"
    GLOBAL = "global"
    PROJECT = "project"
    LEGACY = "legacy"
    CLI = "cli"


@dataclass(frozen=True)
class SourceInfo:
    """
    Purpose:
        Pair an effective value with its winning source layer.
    Fields:
        value  — resolved Python value.
        source — layer that won the merge for this path.
    """

    value: Any
    source: ValueSource


@dataclass(frozen=True)
class ProxyConfigSection:
    """
    Purpose:
        Effective proxy settings.
    Fields:
        upstream_enabled — whether Upstream Proxy mode is active.
        upstream_url     — validated URL when enabled; None in Direct mode.
    """

    upstream_enabled: bool = False
    upstream_url: Optional[str] = None


@dataclass(frozen=True)
class CaptureConfigSection:
    """
    Purpose:
        Effective capture / traffic-storage settings.
    Fields:
        store_bodies  — whether request/response bodies are stored.
        max_body_size — truncation bound in bytes.
        drop_headers  — header names excluded from stored capture payloads.
    """

    store_bodies: bool = True
    max_body_size: int = 1 * 1024 * 1024
    drop_headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class SchedulerConfigSection:
    """
    Purpose:
        Effective scheduler rate-limit settings.
    """

    min_delay: float = 2.0
    max_delay: float = 6.0
    max_queue_size: int = 200


@dataclass(frozen=True)
class AttackConfigSection:
    """
    Purpose:
        Effective attack-related toggles that belong in layered config.
    Fields:
        unauth_auto_run — scheduler auto-enqueues auth_test for untested endpoints.
    """

    unauth_auto_run: bool = False


@dataclass(frozen=True)
class HttpConfigSection:
    """
    Purpose:
        HTTP Manipulation Engine settings — the single system for modifying
        requests and responses flowing through the proxy.
    Fields:
        enabled — master switch; when false no rules run.
        rules   — effective rule list (concatenated from all layers, sorted
                  by priority). Each rule is a dict with id, name, enabled,
                  priority, direction, match, actions, and optional source.
    """

    enabled: bool = True
    rules: tuple[dict, ...] = ()


@dataclass(frozen=True)
class CrossFlowConfigSection:
    """
    Purpose:
        Cross-flow / stored reflection knobs under parameter_intel.cross_flow.
        Mirrors talos.projects.value_reflection.CrossFlowConfig defaults.
    """

    enabled: bool = False
    feed_iv: bool = True
    active_sink_probe: bool = False
    value_index_ttl_hours: int = 72
    value_index_max_per_host: int = 50_000
    value_index_max_sources_per_value: int = 8
    min_value_len: int = 6
    scan_hot_set_k: int = 2000
    scan_time_budget_ms: int = 20
    max_body_scan_bytes: int = 2_000_000
    canary_ttl_hours: int = 24


@dataclass(frozen=True)
class ParameterIntelConfigSection:
    """
    Purpose:
        Parameter intelligence settings (cross-flow reflection, etc.).
    """

    cross_flow: CrossFlowConfigSection = field(default_factory=CrossFlowConfigSection)


@dataclass(frozen=True)
class UrlSinkConfigSection:
    """
    Purpose:
        URL Sink Discovery knobs (passive inventory + IV canaries).
        Defaults match BUILTIN_DEFAULTS['url_sink'].
    """

    passive_enabled: bool = True
    html_js_enabled: bool = True
    iv_probes_enabled: bool = True
    score_threshold: int = 45


@dataclass(frozen=True)
class EffectiveConfig:
    """
    Purpose:
        Single immutable configuration object for a Talos invocation.
        Runtime components receive this instead of opening files themselves.

    Fields:
        proxy            — upstream proxy mode.
        capture          — body storage + drop headers.
        scheduler        — job delay / queue size.
        attack           — attack toggles.
        http             — HTTP manipulation engine (rules + master switch).
        parameter_intel  — parameter intelligence (cross-flow reflection).
        url_sink         — URL Sink Discovery kill-switches + score gate.
        raw              — full merged dict tree (for generic get / effective views).
        sources          — dotted path → ValueSource for inheritance display.
        global_path      — path to global config file (may not exist yet).
        project_path     — path to project.yaml (None when no project bound).
    """

    proxy: ProxyConfigSection = field(default_factory=ProxyConfigSection)
    capture: CaptureConfigSection = field(default_factory=CaptureConfigSection)
    scheduler: SchedulerConfigSection = field(default_factory=SchedulerConfigSection)
    attack: AttackConfigSection = field(default_factory=AttackConfigSection)
    http: HttpConfigSection = field(default_factory=HttpConfigSection)
    parameter_intel: ParameterIntelConfigSection = field(
        default_factory=ParameterIntelConfigSection
    )
    url_sink: UrlSinkConfigSection = field(default_factory=UrlSinkConfigSection)
    raw: dict = field(default_factory=dict)
    sources: dict[str, ValueSource] = field(default_factory=dict)
    global_path: Optional[str] = None
    project_path: Optional[str] = None

    def get(self, path: str, default: Any = None) -> Any:
        """
        Purpose:
            Read a dotted path from the merged raw tree.
        Side effects: None.
        """
        from talos.configuration.merge import get_path

        return get_path(self.raw, path, default)

    def source_of(self, path: str) -> Optional[ValueSource]:
        """
        Purpose:
            Return the winning source for a dotted path, if known.
        Side effects: None.
        """
        return self.sources.get(path)

    def upstream_url(self) -> Optional[str]:
        """
        Purpose:
            Convenience: effective upstream URL, or None for Direct mode.
        Side effects: None.
        """
        if not self.proxy.upstream_enabled:
            return None
        url = self.proxy.upstream_url
        if not url:
            return None
        return str(url).strip() or None

    def drop_headers_set(self) -> frozenset[str]:
        """
        Purpose:
            Lowercase frozenset of capture drop-header names for the addon.
        Side effects: None.
        """
        return frozenset(h.lower() for h in self.capture.drop_headers)
