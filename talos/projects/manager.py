"""
Module: talos.projects.manager

Purpose:
    Single authority for all project lifecycle operations.
    Maintains a JSON registry of all projects and enforces the
    "exactly one active project at a time" invariant.

Dependencies: json, pathlib, talos.projects.model, talos.projects.db
Data flow:
    CLI → ProjectManager → registry (JSON) + per-project directory + SQLite DB
Side effects:
    - Reads/writes the registry file at <projects_root>/registry.json.
    - Creates per-project directories and databases on disk.
    - Enforces that no two projects are ACTIVE simultaneously.

Registry format (projects_root/registry.json):
    {
      "<project_id>": { ...Project.to_dict() },
      ...
    }
"""

import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from talos.projects.db import init_project_db
from talos.projects.model import (
    Project,
    ProjectStatus,
    ScopeConstraints,
    make_project_id,
    utc_now_iso,
)
from talos.projects.policy_score import write_default_score_config

logger = logging.getLogger(__name__)

_REGISTRY_FILENAME = "registry.json"

# Path to the global headers_drop template shipped with the proxy package.
# Copied into each new project directory so users can override per-project.
_GLOBAL_HEADERS_DROP = (
    Path(__file__).parent.parent / "proxy" / "default_headers_drop.txt"
)


def _copy_headers_drop_template(dest: Path) -> None:
    """
    Purpose:
        Copy the global default_headers_drop.txt into a project's data directory.
        Skips if the destination already exists to avoid overwriting user edits.
    Input:
        dest — target path inside the project's data_dir.
    Side effects:
        - Creates the file if the global template exists and dest is absent.
        - Logs WARNING if the global template is missing (misconfigured install).
    """
    if dest.exists():
        return
    if _GLOBAL_HEADERS_DROP.exists():
        shutil.copy2(_GLOBAL_HEADERS_DROP, dest)
        logger.debug("Copied default headers_drop template to %s", dest)
    else:
        logger.warning(
            "Global headers_drop template not found at %s — project will capture all headers",
            _GLOBAL_HEADERS_DROP,
        )


class ProjectError(Exception):
    """Base error for all project management failures."""


class ProjectNotFound(ProjectError):
    """Raised when a requested project id does not exist in the registry."""


class ProjectAlreadyExists(ProjectError):
    """Raised when creating a project whose id is already registered."""


class NoActiveProject(ProjectError):
    """Raised when an operation requires an active project but none is set."""


class ProjectManager:
    """
    Purpose:
        Manage the full lifecycle of Talos projects.
        Enforces isolation — no active project means no capture.

    Responsibilities:
        - create: register project, create storage, init DB
        - open:   set exactly one project as ACTIVE
        - close:  deactivate the current project
        - delete: remove project from registry (data preserved on disk)
        - list:   enumerate all registered projects
        - get:    retrieve a single project by id
        - active: return the currently active project or None

    Input:
        projects_root — Path to the directory that stores all projects.
                        Created automatically if it does not exist.
    """

    def __init__(self, projects_root: Path) -> None:
        # Why root, not a fixed path: lets callers control storage location
        # (e.g. test isolation, user-configured data dir).
        self._root = projects_root
        self._root.mkdir(parents=True, exist_ok=True)
        self._registry_path = self._root / _REGISTRY_FILENAME

    # ------------------------------------------------------------------ #
    # Registry I/O                                                         #
    # ------------------------------------------------------------------ #

    def _load_registry(self) -> dict[str, dict]:
        """
        Purpose: Load the registry from disk.
        Output:  Dict of project_id → raw project dict.
        Side effects: None (read-only).
        Edge case: Missing registry file is treated as empty registry.
        """
        if not self._registry_path.exists():
            return {}
        try:
            raw = self._registry_path.read_text(encoding="utf-8")
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProjectError(
                f"Registry file is corrupted: {self._registry_path}"
            ) from exc

    def _save_registry(self, registry: dict[str, dict]) -> None:
        """
        Purpose: Persist the registry to disk atomically.
        Input:   registry — full registry dict to write.
        Side effects: Writes to disk; replaces existing file.
        """
        self._registry_path.write_text(
            json.dumps(registry, indent=2),
            encoding="utf-8",
        )

    def _get_registry_entry(self, project_id: str) -> dict:
        """
        Purpose: Retrieve a single registry entry, raising if missing.
        Input:   project_id — slug string.
        Output:  Raw project dict.
        Raises:  ProjectNotFound
        """
        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")
        return registry[project_id]

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def create(
        self,
        name: str,
        description: str = "",
        scope: Optional[list[str]] = None,
    ) -> Project:
        """
        Purpose:
            Register a new project, create its storage directory,
            and initialize its SQLite database.
        Input:
            name        — human label; used to derive the project id slug.
            description — optional context note.
            scope       — list of host/URL patterns (can be set later via edit).
        Output:
            The newly created Project instance.
        Side effects:
            - Writes registry entry.
            - Creates <projects_root>/<id>/ directory.
            - Creates <projects_root>/<id>/talos.db with full schema.
            - Creates <projects_root>/<id>/archive/ directory.
        Raises:
            ProjectAlreadyExists — if the slug is already registered.
            ValueError           — if name produces an empty slug.
        """
        project_id = make_project_id(name)

        registry = self._load_registry()
        if project_id in registry:
            raise ProjectAlreadyExists(
                f"Project '{project_id}' already exists. Choose a different name."
            )

        data_dir = self._root / project_id

        project = Project(
            id=project_id,
            name=name,
            description=description,
            created_at=utc_now_iso(),
            status=ProjectStatus.INACTIVE,
            scope=scope or [],
            data_dir=str(data_dir),
        )

        # Prepare storage before writing registry — if this fails, registry stays clean.
        data_dir.mkdir(parents=True, exist_ok=True)
        project.archive_dir.mkdir(parents=True, exist_ok=True)
        _copy_headers_drop_template(project.headers_drop_path)
        init_project_db(project.db_path)
        write_default_score_config(data_dir)

        registry[project_id] = project.to_dict()
        self._save_registry(registry)

        logger.info("Created project '%s' at %s", project_id, data_dir)
        return project

    def open(self, project_id: str) -> Project:
        """
        Purpose:
            Set a project as the active capture target.
            Exactly one project may be ACTIVE at a time — opening a new one
            deactivates any currently active project first.
        Input:
            project_id — slug of the project to activate.
        Output:
            The now-active Project instance.
        Side effects:
            - Writes registry (deactivates previous active, activates target).
        Raises:
            ProjectNotFound — if project_id is not registered.
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        # Deactivate any currently active project first.
        for pid, data in registry.items():
            if data["status"] == ProjectStatus.ACTIVE.value and pid != project_id:
                data["status"] = ProjectStatus.INACTIVE.value
                logger.info("Deactivated project '%s'", pid)

        registry[project_id]["status"] = ProjectStatus.ACTIVE.value
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Opened project '%s'", project_id)
        return project

    def close(self) -> Optional[Project]:
        """
        Purpose:
            Deactivate the currently active project.
            After this call, no project is active — capture is blocked.
        Output:
            The project that was deactivated, or None if none was active.
        Side effects:
            - Writes registry.
        """
        registry = self._load_registry()
        closed: Optional[Project] = None

        for pid, data in registry.items():
            if data["status"] == ProjectStatus.ACTIVE.value:
                data["status"] = ProjectStatus.INACTIVE.value
                closed = Project.from_dict(data)
                logger.info("Closed project '%s'", pid)
                break

        if closed is not None:
            self._save_registry(registry)

        return closed

    def delete(self, project_id: str) -> Project:
        """
        Purpose:
            Remove a project from the registry.
            Data on disk is NOT deleted — caller is responsible for cleanup
            to avoid accidental data loss.
        Input:
            project_id — slug of the project to remove.
        Output:
            The removed Project instance (for confirmation display).
        Side effects:
            - Removes entry from registry file.
        Raises:
            ProjectNotFound — if project_id is not registered.
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        project = Project.from_dict(registry.pop(project_id))
        self._save_registry(registry)

        logger.info("Deleted project '%s' from registry (data preserved at %s)", project_id, project.data_dir)
        return project

    def get(self, project_id: str) -> Project:
        """
        Purpose: Retrieve a project by id.
        Input:   project_id — slug string.
        Output:  Project instance.
        Raises:  ProjectNotFound
        """
        return Project.from_dict(self._get_registry_entry(project_id))

    def list_all(self) -> list[Project]:
        """
        Purpose: Return all registered projects sorted by creation time.
        Output:  List of Project instances; empty list if none registered.
        Side effects: None.
        """
        registry = self._load_registry()
        projects = [Project.from_dict(data) for data in registry.values()]
        projects.sort(key=lambda p: p.created_at)
        return projects

    def active(self) -> Optional[Project]:
        """
        Purpose: Return the currently active project, or None.
        Output:  Project with status=ACTIVE, or None.
        Side effects: None.
        """
        registry = self._load_registry()
        for data in registry.values():
            if data["status"] == ProjectStatus.ACTIVE.value:
                return Project.from_dict(data)
        return None

    def set_scope(self, project_id: str, scope: list[str]) -> Project:
        """
        Purpose:
            Replace the scope list for a project.
            Scope entries are host patterns: exact ("example.com") or
            wildcard subdomain ("*.api.example.com").
        Input:
            project_id — slug of the target project.
            scope      — new list of scope patterns.
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry.
        Raises:
            ProjectNotFound
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        registry[project_id]["scope"] = scope
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Updated scope for project '%s': %s", project_id, scope)
        return project

    def set_constraints(
        self,
        project_id: str,
        constraints: ScopeConstraints,
    ) -> Project:
        """
        Purpose:
            Replace the capture constraints for a project.
        Input:
            project_id  — slug of the target project.
            constraints — new ScopeConstraints instance.
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry.
        Raises:
            ProjectNotFound
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        registry[project_id]["constraints"] = constraints.to_dict()
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Updated constraints for project '%s'", project_id)
        return project
