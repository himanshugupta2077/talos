"""
Tests for the Authentication Provider architecture.

Covers:
    - auth_provider module: CRUD, session state, file parsing, template formatting
    - DB schema v29 migration: new tables are created correctly
    - session_health integration: MANUAL provider path in should_refresh,
      refresh_auth_state, ensure_healthy
    - scheduler DB: mark_paused, pause_pending_jobs, resume_paused_jobs,
      get/set scheduler state
"""

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from talos.projects.db import init_project_db, migrate_project_db, get_schema_version
from talos.projects.auth_provider import (
    PROVIDER_AUTO,
    PROVIDER_MANUAL,
    SESSION_READY,
    SESSION_EXPIRING,
    SESSION_EXPIRED,
    SESSION_WAITING_FOR_USER,
    get_provider,
    set_provider,
    get_manual_session_config,
    set_manual_session_config,
    clear_manual_session_config,
    get_manual_session_expiry,
    apply_manual_session,
    get_session_display_state,
    parse_session_file,
    format_session_template,
)
from talos.projects.auth import get_role_auth_state, get_auth_config
from talos.scheduler.db import (
    SCHED_STATE_RUNNING,
    SCHED_STATE_PAUSED,
    SCHED_STATE_WAITING_FOR_SESSION,
    get_scheduler_state,
    set_scheduler_state,
    mark_paused,
    pause_pending_jobs,
    resume_paused_jobs,
    enqueue_job,
)
from talos.scheduler.job import (
    STATUS_PAUSED,
    STATUS_PENDING,
    REPLAY_FLOW,
)


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Create a fully-initialised project DB and return its path."""
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def db_with_role(db_path: Path) -> tuple[Path, str]:
    """Create a DB with a test role and return (db_path, role_id)."""
    import uuid
    role_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name, is_active) VALUES (?, 'tester', 0)",
            (role_id,),
        )
        conn.commit()
    return db_path, role_id


# ================================================================== #
# Schema version                                                       #
# ================================================================== #

class TestSchemaVersion:
    def test_new_db_is_current(self, db_path: Path) -> None:
        from talos.projects.db import SCHEMA_VERSION
        assert get_schema_version(db_path) == SCHEMA_VERSION

    def test_new_tables_exist(self, db_path: Path) -> None:
        with sqlite3.connect(str(db_path)) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "role_auth_provider" in tables
        assert "manual_session_config" in tables
        assert "scheduler_state" in tables


# ================================================================== #
# Provider CRUD                                                        #
# ================================================================== #

class TestProviderCRUD:
    def test_default_provider_is_auto(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        assert get_provider(db_path, role_id) == PROVIDER_AUTO

    def test_set_provider_manual(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        assert get_provider(db_path, role_id) == PROVIDER_MANUAL

    def test_set_provider_auto(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        set_provider(db_path, role_id, PROVIDER_AUTO)
        assert get_provider(db_path, role_id) == PROVIDER_AUTO

    def test_set_provider_invalid(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        with pytest.raises(ValueError, match="Unknown provider"):
            set_provider(db_path, role_id, "oauth2")

    def test_provider_upsert(self, db_with_role: tuple) -> None:
        """set_provider can be called multiple times without error."""
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        assert get_provider(db_path, role_id) == PROVIDER_MANUAL


# ================================================================== #
# Manual session config CRUD                                           #
# ================================================================== #

class TestManualSessionConfig:
    def test_no_config_returns_none(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        assert get_manual_session_config(db_path, role_id) is None

    def test_set_and_get_config(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer token123"},
            cookies={"session": "abc"},
            expires_at=None,
            ttl_seconds=3600,
        )
        cfg = get_manual_session_config(db_path, role_id)
        assert cfg is not None
        assert cfg["headers"] == {"Authorization": "Bearer token123"}
        assert cfg["cookies"] == {"session": "abc"}
        assert cfg["ttl_seconds"] == 3600
        assert cfg["expires_at"] is None

    def test_set_config_populates_auth_config(self, db_with_role: tuple) -> None:
        """set_manual_session_config also writes to auth_config for injection."""
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer x"},
            cookies={"session": "y"},
            expires_at=None,
            ttl_seconds=3600,
        )
        auth_cfg = get_auth_config(db_path)
        assert "Authorization" in auth_cfg["headers"]
        assert "session" in auth_cfg["cookies"]

    def test_clear_config(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer x"},
            cookies={},
            expires_at=None,
            ttl_seconds=3600,
        )
        clear_manual_session_config(db_path, role_id)
        assert get_manual_session_config(db_path, role_id) is None

    def test_upsert_overwrites_existing(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer old"},
            cookies={},
            expires_at=None,
            ttl_seconds=3600,
        )
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer new"},
            cookies={"session": "xyz"},
            expires_at=None,
            ttl_seconds=7200,
        )
        cfg = get_manual_session_config(db_path, role_id)
        assert cfg["headers"]["Authorization"] == "Bearer new"
        assert cfg["ttl_seconds"] == 7200


# ================================================================== #
# Manual session expiry computation                                    #
# ================================================================== #

class TestManualSessionExpiry:
    def test_expiry_from_ttl_seconds(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"X-Token": "abc"},
            cookies={},
            expires_at=None,
            ttl_seconds=3600,
        )
        expiry = get_manual_session_expiry(db_path, role_id)
        assert expiry is not None
        now = datetime.now(timezone.utc)
        # Expiry should be approximately now + 3600s
        diff = abs((expiry - now).total_seconds() - 3600)
        assert diff < 5  # within 5 seconds of expected

    def test_expiry_from_expires_at(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        expires_at_str = future.strftime("%Y-%m-%d %H:%M UTC")
        set_manual_session_config(
            db_path, role_id,
            headers={"X-Token": "abc"},
            cookies={},
            expires_at=expires_at_str,
            ttl_seconds=None,
        )
        expiry = get_manual_session_expiry(db_path, role_id)
        assert expiry is not None
        # Within 1 minute of expected (parsing may lose seconds)
        diff = abs((expiry - future).total_seconds())
        assert diff < 120

    def test_no_config_returns_none(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        assert get_manual_session_expiry(db_path, role_id) is None


# ================================================================== #
# Apply manual session                                                 #
# ================================================================== #

class TestApplyManualSession:
    def test_apply_writes_role_auth_state(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer xyz"},
            cookies={"session": "abc123"},
            expires_at=None,
            ttl_seconds=3600,
        )
        result = apply_manual_session(db_path, role_id)
        assert result is True
        state = get_role_auth_state(db_path, role_id)
        assert state["state"]["Authorization"] == "Bearer xyz"
        assert state["state"]["session"] == "abc123"
        assert state["collected_at"] is not None

    def test_apply_fails_when_no_config(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        assert apply_manual_session(db_path, role_id) is False

    def test_apply_fails_when_expired(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        expires_at_str = past.isoformat()
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer old"},
            cookies={},
            expires_at=expires_at_str,
            ttl_seconds=None,
        )
        assert apply_manual_session(db_path, role_id) is False

    def test_apply_fails_when_no_ttl(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer xyz"},
            cookies={},
            expires_at=None,
            ttl_seconds=None,
        )
        assert apply_manual_session(db_path, role_id) is False

    def test_apply_fails_when_empty_artifacts(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path, role_id,
            headers={},
            cookies={},
            expires_at=None,
            ttl_seconds=3600,
        )
        assert apply_manual_session(db_path, role_id) is False


# ================================================================== #
# Session display state                                                #
# ================================================================== #

class TestSessionDisplayState:
    def test_no_config_is_waiting_for_user(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        assert get_session_display_state(db_path, role_id) == SESSION_WAITING_FOR_USER

    def test_valid_session_is_ready(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer xyz"},
            cookies={},
            expires_at=None,
            ttl_seconds=3600,
        )
        apply_manual_session(db_path, role_id)
        state = get_session_display_state(db_path, role_id)
        assert state == SESSION_READY

    def test_expired_session_is_expired(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer old"},
            cookies={},
            expires_at=past,
            ttl_seconds=None,
        )
        state = get_session_display_state(db_path, role_id)
        assert state == SESSION_EXPIRED


# ================================================================== #
# Session file parsing                                                 #
# ================================================================== #

class TestParseSessionFile:
    def test_parse_headers_and_cookies(self) -> None:
        content = """
--header
Authorization
Bearer eyJ123

--cookie
session
abc123
csrf_token
xyz789

ttl_seconds
3600
"""
        parsed = parse_session_file(content)
        assert parsed["headers"] == {"Authorization": "Bearer eyJ123"}
        assert parsed["cookies"] == {"session": "abc123", "csrf_token": "xyz789"}
        assert parsed["ttl_seconds"] == 3600
        assert parsed["expires_at"] is None

    def test_parse_expires_at(self) -> None:
        content = """
--header
X-API-Key
secret123

expires_at
2026-07-03 13:00 UTC
"""
        parsed = parse_session_file(content)
        assert parsed["headers"] == {"X-API-Key": "secret123"}
        assert parsed["expires_at"] == "2026-07-03 13:00 UTC"
        assert parsed["ttl_seconds"] is None

    def test_comments_ignored(self) -> None:
        content = """
# This is a comment
--header
# Authorization
# Bearer xyz

--cookie
session
abc123

ttl_seconds
7200
"""
        parsed = parse_session_file(content)
        # Lines starting with # are treated as comments by being skipped in
        # the key accumulation (they're not blank, but they start with #)
        assert "session" in parsed["cookies"]
        assert parsed["cookies"]["session"] == "abc123"
        assert parsed["ttl_seconds"] == 7200

    def test_empty_content(self) -> None:
        parsed = parse_session_file("")
        assert parsed["headers"] == {}
        assert parsed["cookies"] == {}
        assert parsed["expires_at"] is None
        assert parsed["ttl_seconds"] is None

    def test_only_ttl(self) -> None:
        parsed = parse_session_file("ttl_seconds\n1800\n")
        assert parsed["ttl_seconds"] == 1800

    def test_invalid_ttl_ignored(self) -> None:
        parsed = parse_session_file("ttl_seconds\nnotanumber\n")
        assert parsed["ttl_seconds"] is None


# ================================================================== #
# Session file template                                                #
# ================================================================== #

class TestFormatSessionTemplate:
    def test_template_without_existing(self) -> None:
        template = format_session_template("Admin")
        assert "Admin" in template
        assert "--header" in template
        assert "--cookie" in template

    def test_template_with_existing_ttl(self) -> None:
        existing = {
            "headers": {"Authorization": "Bearer x"},
            "cookies": {"session": "abc"},
            "expires_at": None,
            "ttl_seconds": 3600,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        template = format_session_template("Admin", existing)
        assert "Authorization" in template
        assert "Bearer x" in template
        assert "session" in template
        assert "abc" in template
        assert "3600" in template

    def test_template_with_existing_expires_at(self) -> None:
        existing = {
            "headers": {},
            "cookies": {},
            "expires_at": "2026-07-03 13:00 UTC",
            "ttl_seconds": None,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        template = format_session_template("User", existing)
        assert "2026-07-03 13:00 UTC" in template


# ================================================================== #
# session_health.should_refresh — MANUAL provider                     #
# ================================================================== #

class TestShouldRefreshManual:
    def test_no_config_returns_true(self, db_with_role: tuple) -> None:
        from talos.projects.session_health import should_refresh
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        assert should_refresh(db_path, role_id) is True

    def test_valid_session_not_near_expiry_returns_false(
        self, db_with_role: tuple
    ) -> None:
        from talos.projects.session_health import should_refresh
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer x"},
            cookies={},
            expires_at=None,
            ttl_seconds=7200,  # 2 hours
        )
        # Default refresh_before is 120s; 7200 - 120 = 7080s remaining
        assert should_refresh(db_path, role_id) is False

    def test_expired_session_returns_true(self, db_with_role: tuple) -> None:
        from talos.projects.session_health import should_refresh
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer old"},
            cookies={},
            expires_at=past,
            ttl_seconds=None,
        )
        assert should_refresh(db_path, role_id) is True


# ================================================================== #
# session_health.refresh_auth_state — MANUAL provider                 #
# ================================================================== #

class TestRefreshAuthStateManual:
    def test_manual_refresh_applies_config(self, db_with_role: tuple) -> None:
        from talos.projects.session_health import refresh_auth_state
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        set_manual_session_config(
            db_path, role_id,
            headers={"X-API-Key": "secret"},
            cookies={"session": "tok"},
            expires_at=None,
            ttl_seconds=3600,
        )
        # project_id is unused for MANUAL provider
        result = refresh_auth_state(db_path, role_id, "dummy-project-id")
        assert result is True
        state = get_role_auth_state(db_path, role_id)
        assert state["state"]["X-API-Key"] == "secret"
        assert state["state"]["session"] == "tok"

    def test_manual_refresh_fails_when_no_config(
        self, db_with_role: tuple
    ) -> None:
        from talos.projects.session_health import refresh_auth_state
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        result = refresh_auth_state(db_path, role_id, "dummy-project-id")
        assert result is False

    def test_manual_refresh_fails_when_expired(self, db_with_role: tuple) -> None:
        from talos.projects.session_health import refresh_auth_state
        db_path, role_id = db_with_role
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        set_manual_session_config(
            db_path, role_id,
            headers={"Authorization": "Bearer old"},
            cookies={},
            expires_at=past,
            ttl_seconds=None,
        )
        result = refresh_auth_state(db_path, role_id, "dummy-project-id")
        assert result is False


# ================================================================== #
# Scheduler DB: state and pause/resume                                 #
# ================================================================== #

class TestSchedulerState:
    def test_default_state_is_running(self, db_path: Path) -> None:
        assert get_scheduler_state(db_path) == SCHED_STATE_RUNNING

    def test_set_state_paused(self, db_path: Path) -> None:
        set_scheduler_state(db_path, SCHED_STATE_PAUSED, "manual pause")
        assert get_scheduler_state(db_path) == SCHED_STATE_PAUSED

    def test_set_state_waiting_for_session(self, db_path: Path) -> None:
        set_scheduler_state(db_path, SCHED_STATE_WAITING_FOR_SESSION)
        assert get_scheduler_state(db_path) == SCHED_STATE_WAITING_FOR_SESSION

    def test_set_state_running_clears_pause(self, db_path: Path) -> None:
        set_scheduler_state(db_path, SCHED_STATE_PAUSED)
        set_scheduler_state(db_path, SCHED_STATE_RUNNING)
        assert get_scheduler_state(db_path) == SCHED_STATE_RUNNING

    def test_set_state_upsert(self, db_path: Path) -> None:
        set_scheduler_state(db_path, SCHED_STATE_PAUSED)
        set_scheduler_state(db_path, SCHED_STATE_PAUSED, "reason2")
        assert get_scheduler_state(db_path) == SCHED_STATE_PAUSED


class TestSchedulerPauseResume:
    def _add_jobs(self, db_path: Path, count: int) -> list[str]:
        import uuid
        ids = []
        for _ in range(count):
            jid = str(uuid.uuid4())
            enqueue_job(db_path, jid, REPLAY_FLOW, "proj", flow_id=str(uuid.uuid4()))
            ids.append(jid)
        return ids

    def test_pause_pending_jobs(self, db_path: Path) -> None:
        self._add_jobs(db_path, 3)
        paused = pause_pending_jobs(db_path)
        assert paused == 3
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT status FROM scheduler_jobs"
            ).fetchall()
        assert all(r[0] == STATUS_PAUSED for r in rows)

    def test_resume_paused_jobs(self, db_path: Path) -> None:
        self._add_jobs(db_path, 3)
        pause_pending_jobs(db_path)
        resumed = resume_paused_jobs(db_path)
        assert resumed == 3
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT status FROM scheduler_jobs"
            ).fetchall()
        assert all(r[0] == STATUS_PENDING for r in rows)

    def test_mark_paused_individual_job(self, db_path: Path) -> None:
        job_ids = self._add_jobs(db_path, 2)
        mark_paused(db_path, job_ids[0])
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT status FROM scheduler_jobs WHERE job_id = ?", (job_ids[0],)
            ).fetchone()
        assert row[0] == STATUS_PAUSED

    def test_pause_zero_pending(self, db_path: Path) -> None:
        paused = pause_pending_jobs(db_path)
        assert paused == 0

    def test_resume_zero_paused(self, db_path: Path) -> None:
        resumed = resume_paused_jobs(db_path)
        assert resumed == 0


# ================================================================== #
# Job status constant                                                  #
# ================================================================== #

class TestJobStatusConstants:
    def test_status_paused_defined(self) -> None:
        assert STATUS_PAUSED == "paused"

    def test_status_paused_is_string(self) -> None:
        assert isinstance(STATUS_PAUSED, str)
