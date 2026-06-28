"""
Module: talos.input_validation.config

Purpose:
    Read and write the per-project Input Validation Engine configuration.
    Configuration lives in the input_validation_config table and is also
    mirrored to/from a YAML file for user editing.

    Defaults:
        enabled  : False  — tester must explicitly enable
        workers  : 2
        analyses : all phases enabled

Dependencies: sqlite3, yaml (stdlib fallback to json), pathlib
Data flow:
    CLI -> load_config() / save_config() -> input_validation_config table
Side effects: DB reads/writes only.
"""

import json
import sqlite3
import sqlite3
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class IVAnalysesConfig:
    """
    Per-phase analysis toggles.
    All phases default to enabled; the tester may disable individual phases.
    """

    baseline: bool = True
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
        enabled            — Whether IV runs at all. Default False.
        workers            — Concurrent analysis workers. Default 2.
        analyses           — Per-phase toggles.
        excluded_hosts     — Hosts excluded from IV (in addition to endpoint policy).
        excluded_endpoints — Endpoint UUIDs excluded from IV.
    """

    enabled: bool = False
    workers: int = 2
    analyses: IVAnalysesConfig = field(default_factory=IVAnalysesConfig)
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_endpoints: list[str] = field(default_factory=list)


def load_config(db_path: Path) -> IVConfig:
    """
    Purpose:
        Load the Input Validation configuration from the project database.
        Returns the default config if no row exists or the table does not yet
        exist (e.g. project opened before schema was migrated to v25).
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
    except (json.JSONDecodeError, TypeError):
        excluded_hosts = []
    try:
        excluded_endpoints: list[str] = json.loads(row["excluded_endpoints"])
    except (json.JSONDecodeError, TypeError):
        excluded_endpoints = []

    analyses = IVAnalysesConfig(
        baseline=bool(row["analyses_baseline"]),
        identifier=bool(row["analyses_identifier"]),
        characters=bool(row["analyses_characters"]),
        length=bool(row["analyses_length"]),
        types=bool(row["analyses_types"]),
        transformations=bool(row["analyses_transformations"]),
        reflection=bool(row["analyses_reflection"]),
        validation=bool(row["analyses_validation"]),
    )
    return IVConfig(
        enabled=bool(row["enabled"]),
        workers=int(row["workers"]),
        analyses=analyses,
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
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO input_validation_config (
                id, enabled, workers,
                analyses_baseline, analyses_identifier, analyses_characters,
                analyses_length, analyses_types, analyses_transformations,
                analyses_reflection, analyses_validation,
                excluded_hosts, excluded_endpoints
            ) VALUES (
                'default', ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?
            )
            """,
            (
                1 if config.enabled else 0,
                config.workers,
                1 if a.baseline else 0,
                1 if a.identifier else 0,
                1 if a.characters else 0,
                1 if a.length else 0,
                1 if a.types else 0,
                1 if a.transformations else 0,
                1 if a.reflection else 0,
                1 if a.validation else 0,
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
    return (
        f"Input Validation Configuration\n"
        f"  Status       : {'Enabled' if config.enabled else 'Disabled'}\n"
        f"  Workers      : {config.workers}\n"
        f"\n"
        f"  Analyses:\n"
        f"    baseline        : {'on' if a.baseline else 'off'}\n"
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
    )
