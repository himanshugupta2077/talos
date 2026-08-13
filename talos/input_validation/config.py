"""
Module: talos.input_validation.config

Purpose:
    Read and write the per-project Input Validation Engine configuration.
    Configuration lives in the input_validation_config table and is also
    mirrored to/from a YAML file for user editing.

    Defaults:
        enabled                : False  — tester must explicitly enable
        workers                : 2
        analyses               : all phases enabled (including multiprobe)
        probe_strategy         : exhaustive — full probe set (type-family,
                                 URL sink, chars, validation). Smaller tiers
                                 remain opt-in limiters via --budget.
        max_requests_per_param : 0 — use planner tier default (Module 5)
        include_auth_artifacts : False — skip session cookies / Authorization
                                 unless operator opts in (Module 9)

Dependencies: sqlite3, json, pathlib
Data flow:
    CLI -> load_config() / save_config() -> input_validation_config table
Side effects: DB reads/writes only.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path


# Probe strategy / planner budget tiers (Modules 4–5; same names).
PROBE_STRATEGIES: tuple[str, ...] = (
    "quick",
    "standard",
    "deep",
    "exhaustive",
)
DEFAULT_PROBE_STRATEGY = "exhaustive"


@dataclass
class IVAnalysesConfig:
    """
    Per-phase analysis toggles.
    All phases default to enabled; the tester may disable individual phases.
    """

    baseline: bool = True
    multiprobe: bool = True
    identifier: bool = True
    characters: bool = True
    length: bool = True
    types: bool = True
    transformations: bool = True
    reflection: bool = True
    validation: bool = True


@dataclass
class IVConfig:
    """
    Per-project Input Validation Engine configuration.

    Fields:
        enabled                — Whether IV runs at all. Default False.
        workers                — Concurrent analysis workers. Default 2.
        analyses               — Per-phase toggles.
        probe_strategy         — quick|standard|deep|exhaustive (planner
                                 budget). Default exhaustive = full probe set.
        max_requests_per_param — Hard HTTP cap per parameter; 0 = tier default
                                 (Module 5 planner).
        include_auth_artifacts — When False (default), session cookies and
                                 Authorization-like headers are not probed
                                 (Module 9). Set True or pass
                                 --include-auth-artifacts to probe them.
        excluded_hosts         — Hosts excluded from IV (in addition to policy).
        excluded_endpoints     — Endpoint UUIDs excluded from IV.
    """

    enabled: bool = False
    workers: int = 2
    analyses: IVAnalysesConfig = field(default_factory=IVAnalysesConfig)
    probe_strategy: str = DEFAULT_PROBE_STRATEGY
    max_requests_per_param: int = 0
    include_auth_artifacts: bool = False
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_endpoints: list[str] = field(default_factory=list)


def _row_bool(row: sqlite3.Row, key: str, default: bool = True) -> bool:
    """Read a boolean config column; missing key → default. Side effects: None."""
    try:
        return bool(row[key])
    except (IndexError, KeyError):
        return default


def load_config(db_path: Path) -> IVConfig:
    """
    Purpose:
        Load the Input Validation configuration from the project database.
        Returns the default config if no row exists or the table does not yet
        exist (e.g. project opened before schema was migrated).
    Input:
        db_path — Path to the project SQLite database.
    Output:
        IVConfig populated from the database row.
    Side effects: None (read-only DB access).
    """
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM input_validation_config WHERE id = 'default'"
            ).fetchone()
    except sqlite3.OperationalError:
        # Table doesn't exist yet — return defaults.
        return IVConfig()

    if row is None:
        return IVConfig()

    try:
        excluded_hosts: list[str] = json.loads(row["excluded_hosts"])
    except (json.JSONDecodeError, TypeError, KeyError):
        excluded_hosts = []
    try:
        excluded_endpoints: list[str] = json.loads(row["excluded_endpoints"])
    except (json.JSONDecodeError, TypeError, KeyError):
        excluded_endpoints = []

    try:
        strategy = str(row["probe_strategy"] or DEFAULT_PROBE_STRATEGY).lower()
    except (IndexError, KeyError):
        strategy = DEFAULT_PROBE_STRATEGY
    if strategy not in PROBE_STRATEGIES:
        strategy = DEFAULT_PROBE_STRATEGY

    try:
        max_req = int(row["max_requests_per_param"] or 0)
    except (IndexError, KeyError, TypeError, ValueError):
        max_req = 0
    if max_req < 0:
        max_req = 0

    include_auth = _row_bool(row, "include_auth_artifacts", False)

    analyses = IVAnalysesConfig(
        baseline=_row_bool(row, "analyses_baseline", True),
        multiprobe=_row_bool(row, "analyses_multiprobe", True),
        identifier=_row_bool(row, "analyses_identifier", True),
        characters=_row_bool(row, "analyses_characters", True),
        length=_row_bool(row, "analyses_length", True),
        types=_row_bool(row, "analyses_types", True),
        transformations=_row_bool(row, "analyses_transformations", True),
        reflection=_row_bool(row, "analyses_reflection", True),
        validation=_row_bool(row, "analyses_validation", True),
    )
    return IVConfig(
        enabled=bool(row["enabled"]),
        workers=int(row["workers"]),
        analyses=analyses,
        probe_strategy=strategy,
        max_requests_per_param=max_req,
        include_auth_artifacts=include_auth,
        excluded_hosts=excluded_hosts,
        excluded_endpoints=excluded_endpoints,
    )


def save_config(db_path: Path, config: IVConfig) -> None:
    """
    Purpose:
        Persist the Input Validation configuration to the project database.
    Input:
        db_path — Path to the project SQLite database.
        config  — IVConfig to save.
    Side effects:
        - Inserts or replaces the single 'default' row in input_validation_config.
    """
    a = config.analyses
    strategy = (config.probe_strategy or DEFAULT_PROBE_STRATEGY).lower()
    if strategy not in PROBE_STRATEGIES:
        strategy = DEFAULT_PROBE_STRATEGY
    max_req = int(config.max_requests_per_param or 0)
    if max_req < 0:
        max_req = 0
    # Ensure Module 9 column exists on upgraded DBs.
    try:
        from talos.projects.db import migrate_project_db
        migrate_project_db(db_path)
    except Exception:
        pass
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO input_validation_config (
                id, enabled, workers,
                analyses_baseline, analyses_multiprobe, analyses_identifier,
                analyses_characters,
                analyses_length, analyses_types, analyses_transformations,
                analyses_reflection, analyses_validation,
                probe_strategy, max_requests_per_param,
                include_auth_artifacts,
                excluded_hosts, excluded_endpoints
            ) VALUES (
                'default', ?, ?,
                ?, ?, ?,
                ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?
            )
            """,
            (
                1 if config.enabled else 0,
                config.workers,
                1 if a.baseline else 0,
                1 if a.multiprobe else 0,
                1 if a.identifier else 0,
                1 if a.characters else 0,
                1 if a.length else 0,
                1 if a.types else 0,
                1 if a.transformations else 0,
                1 if a.reflection else 0,
                1 if a.validation else 0,
                strategy,
                max_req,
                1 if config.include_auth_artifacts else 0,
                json.dumps(config.excluded_hosts),
                json.dumps(config.excluded_endpoints),
            ),
        )
        conn.commit()


def ensure_default_config(db_path: Path) -> None:
    """
    Purpose:
        Insert the default config row if it does not already exist.
        Called during project initialization.
    Input:
        db_path — Path to the project SQLite database.
    Side effects:
        - Inserts one row into input_validation_config if absent.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO input_validation_config (id)
            VALUES ('default')
            """
        )
        conn.commit()


def format_config(config: IVConfig) -> str:
    """
    Purpose:
        Render an IVConfig as a human-readable YAML-like string for display.
    Input:
        config — IVConfig instance.
    Output:
        Multi-line formatted string.
    Side effects: None.
    """
    a = config.analyses
    excluded_hosts_display = (
        "\n".join(f"    - {h}" for h in config.excluded_hosts)
        if config.excluded_hosts
        else "    (none)"
    )
    excluded_eps_display = (
        f"    {len(config.excluded_endpoints)} endpoint(s)"
        if config.excluded_endpoints
        else "    (none)"
    )
    max_req = int(config.max_requests_per_param or 0)
    max_req_display = str(max_req) if max_req > 0 else "tier default"
    auth_art = "on (probe session/auth)" if config.include_auth_artifacts else "off (skip auth artifacts)"
    return (
        f"Input Validation Configuration\n"
        f"  Status         : {'Enabled' if config.enabled else 'Disabled'}\n"
        f"  Workers        : {config.workers}\n"
        f"  Probe strategy : {config.probe_strategy}\n"
        f"  Max req/param  : {max_req_display}\n"
        f"  Auth artifacts : {auth_art}\n"
        f"\n"
        f"  Analyses:\n"
        f"    baseline        : {'on' if a.baseline else 'off'}\n"
        f"    multiprobe      : {'on' if a.multiprobe else 'off'}\n"
        f"    identifier      : {'on' if a.identifier else 'off'}\n"
        f"    characters      : {'on' if a.characters else 'off'}\n"
        f"    length          : {'on' if a.length else 'off'}\n"
        f"    types           : {'on' if a.types else 'off'}\n"
        f"    transformations : {'on' if a.transformations else 'off'}\n"
        f"    reflection      : {'on' if a.reflection else 'off'}\n"
        f"    validation      : {'on' if a.validation else 'off'}\n"
        f"\n"
        f"  Excluded Hosts:\n"
        f"{excluded_hosts_display}\n"
        f"\n"
        f"  Excluded Endpoints:\n"
        f"{excluded_eps_display}\n"
        f"\n"
        f"  Surfaces (Module 9):\n"
        f"    path, query, body (JSON/form/multipart/XML/GraphQL),\n"
        f"    header, cookie — first-class inject + profiles\n"
    )
