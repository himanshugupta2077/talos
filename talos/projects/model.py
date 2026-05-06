"""
Module: talos.projects.model

Purpose:
    Defines the Project data model and its serialization.
    A project is the root isolation unit — all data (traffic, sessions,
    endpoints, attacks) is bound to exactly one project.

Dependencies: dataclasses, datetime, json
Data flow: ProjectManager creates/loads Project instances; serialized to/from JSON for the registry.
Side effects: None — pure data model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

# Default max body size: 1 MB. Prevents memory spikes on large binary responses.
_DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024


class ProjectStatus(str, Enum):
    # Project exists but is not the active capture target.
    INACTIVE = "inactive"
    # Project is currently open — proxy capture routes traffic here.
    ACTIVE = "active"


@dataclass
class ScopeConstraints:
    """
    Per-project capture constraints applied by the proxy layer.

    Fields:
        capture_in_scope_only — If True, only in-scope hosts are captured.
                                Always True for correctness; exposed for clarity.
        store_bodies          — If True, request/response bodies are stored.
                                Set False to reduce storage for recon-heavy sessions.
        max_body_size         — Maximum body size in bytes before truncation.
                                Protects against memory pressure on large responses.

    Invariant:
        Defaults are safe — capture is strict and bodies are bounded.
    """

    capture_in_scope_only: bool = True
    store_bodies: bool = True
    max_body_size: int = _DEFAULT_MAX_BODY_SIZE

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ScopeConstraints:
        return cls(
            capture_in_scope_only=data.get("capture_in_scope_only", True),
            store_bodies=data.get("store_bodies", True),
            max_body_size=data.get("max_body_size", _DEFAULT_MAX_BODY_SIZE),
        )


@dataclass
class Project:
    """
    Root isolation unit for Talos.

    Fields:
        id          — Unique slug, derived from name at creation time.
        name        — Human-readable label.
        description — Optional context note.
        created_at  — UTC ISO-8601 creation timestamp.
        status      — ACTIVE or INACTIVE.
        scope       — List of host patterns defining capture scope.
                      Supports exact domains ("example.com") and
                      wildcard subdomains ("*.api.example.com").
        constraints — Capture behaviour settings (bodies, size limits).
        data_dir    — Absolute path to the project's isolated storage directory.

    Invariants:
        - id must be filesystem-safe (slug form).
        - data_dir always equals <projects_root>/<id>.
        - No two projects share the same id.
        - Empty scope → no traffic captured (strict opt-in).
    """

    id: str
    name: str
    description: str
    created_at: str
    status: ProjectStatus
    scope: list[str]
    data_dir: str  # absolute path, stringified for serialization
    constraints: ScopeConstraints = field(default_factory=ScopeConstraints)

    # ------------------------------------------------------------------ #
    # Paths derived from data_dir — never stored, always computed.        #
    # ------------------------------------------------------------------ #

    @property
    def db_path(self) -> Path:
        """Path to the project's SQLite database file."""
        return Path(self.data_dir) / "talos.db"

    @property
    def archive_dir(self) -> Path:
        """Path to the raw HTTP archive directory."""
        return Path(self.data_dir) / "archive"

    @property
    def headers_drop_path(self) -> Path:
        """
        Path to the per-project header filter file.
        Users edit this file to customize which headers are dropped at capture time.
        Populated from the global template on project creation.
        """
        return Path(self.data_dir) / "headers_drop.txt"

    # ------------------------------------------------------------------ #
    # Serialization                                                        #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Convert project to a JSON-serializable dict."""
        d = asdict(self)
        d["status"] = self.status.value
        # asdict() recurses into ScopeConstraints — already a plain dict.
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Project:
        """Reconstruct a Project from a dict (e.g. loaded from registry)."""
        raw_constraints = data.get("constraints", {})
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            created_at=data["created_at"],
            status=ProjectStatus(data["status"]),
            scope=data.get("scope", []),
            data_dir=data["data_dir"],
            constraints=ScopeConstraints.from_dict(raw_constraints),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, raw: str) -> Project:
        return cls.from_dict(json.loads(raw))


def make_project_id(name: str) -> str:
    """
    Purpose: Convert a human name to a filesystem-safe slug for use as project id.
    Input:   name — arbitrary string
    Output:  lowercase alphanumeric slug with hyphens; e.g. "My App" → "my-app"
    Side effects: None
    """
    import re
    slug = name.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    if not slug:
        raise ValueError(f"Project name '{name}' produces an empty slug.")
    return slug


def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
