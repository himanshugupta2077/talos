"""
Tests for finding PRIMARY / LINKED relationships.

Covers:
  - cluster key construction
  - first finding in a cluster is PRIMARY; subsequent are LINKED
  - concurrent PRIMARY race falls back to LINKED
  - list filters (PRIMARY default / --linked / --all)
  - independent status changes
  - bulk --linked status operations
  - --linked refused on LINKED findings
  - schema migration to v34
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import uuid
from pathlib import Path

import pytest

from talos.projects.db import (
    SCHEMA_VERSION,
    init_project_db,
    migrate_project_db,
    get_schema_version,
)
import talos.findings.db as findings_db
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import (
    FINDING_STATUS_TRIAGING,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_REJECTED,
    RELATION_TYPE_PRIMARY,
    RELATION_TYPE_LINKED,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _create(
    db_path: Path,
    *,
    attack: str = "unauth",
    verdict: str = "BYPASS",
    endpoint_id: str | None = "ep-1",
    title: str = "test",
    cluster_key: str | None = None,
    project_id: str = "proj",
) -> str:
    if cluster_key is None and endpoint_id:
        cluster_key = findings_db.build_cluster_key(attack, endpoint_id)
    return findings_db.create_finding(
        db_path=db_path,
        project_id=project_id,
        attack_type=attack,
        verdict=verdict,
        endpoint_id=endpoint_id,
        title=title,
        cluster_key=cluster_key,
    )


# ------------------------------------------------------------------ #
# Cluster key                                                          #
# ------------------------------------------------------------------ #

def test_build_cluster_key_unauth():
    assert findings_db.build_cluster_key("unauth", "ep-abc") == "UNAUTH:ep-abc"


def test_build_cluster_key_auth_test():
    assert findings_db.build_cluster_key("auth_test", "ep-1") == "AUTH_TEST:ep-1"


def test_build_cluster_key_bac():
    assert (
        findings_db.build_cluster_key("bac", "ep-1", "role-a", "role-t")
        == "BAC:ep-1:role-a:role-t"
    )


def test_build_cluster_key_no_endpoint():
    assert findings_db.build_cluster_key("unauth", None) is None


def test_build_cluster_key_cors_uses_host():
    assert (
        findings_db.build_cluster_key(
            "cors", "ep-1", host="https://app.example.com"
        )
        == "CORS:https://app.example.com"
    )
    assert findings_db.build_cluster_key("cors", "ep-1") == "CORS:ep-1"
    assert findings_db.build_cluster_key("cors", None) is None


# ------------------------------------------------------------------ #
# PRIMARY / LINKED creation                                            #
# ------------------------------------------------------------------ #

def test_first_finding_is_primary(db_path: Path):
    fid = _create(db_path, title="first")
    f = findings_db.get_finding(db_path, fid)
    assert f is not None
    assert f["relation_type"] == RELATION_TYPE_PRIMARY
    assert f["parent_finding_id"] is None
    assert f["cluster_key"] == "UNAUTH:ep-1"
    assert f["status"] == FINDING_STATUS_TRIAGING


def test_second_finding_is_linked(db_path: Path):
    primary_id = _create(db_path, title="primary")
    linked_id = _create(db_path, title="linked")
    primary = findings_db.get_finding(db_path, primary_id)
    linked = findings_db.get_finding(db_path, linked_id)
    assert primary["relation_type"] == RELATION_TYPE_PRIMARY
    assert linked["relation_type"] == RELATION_TYPE_LINKED
    assert linked["parent_finding_id"] == primary_id
    assert linked["cluster_key"] == primary["cluster_key"]


def test_different_endpoints_are_separate_primaries(db_path: Path):
    a = _create(db_path, endpoint_id="ep-a", title="a")
    b = _create(db_path, endpoint_id="ep-b", title="b")
    fa = findings_db.get_finding(db_path, a)
    fb = findings_db.get_finding(db_path, b)
    assert fa["relation_type"] == RELATION_TYPE_PRIMARY
    assert fb["relation_type"] == RELATION_TYPE_PRIMARY
    assert fa["cluster_key"] != fb["cluster_key"]


def test_mutations_do_not_split_unauth_cluster(db_path: Path):
    """Auth/request mutations must not be part of the Unauth cluster key."""
    ids = [
        _create(db_path, title=f"technique-{i}")
        for i in range(5)
    ]
    findings = [findings_db.get_finding(db_path, i) for i in ids]
    primaries = [f for f in findings if f["relation_type"] == RELATION_TYPE_PRIMARY]
    linked = [f for f in findings if f["relation_type"] == RELATION_TYPE_LINKED]
    assert len(primaries) == 1
    assert len(linked) == 4
    assert all(f["parent_finding_id"] == primaries[0]["id"] for f in linked)


def test_no_endpoint_always_primary(db_path: Path):
    a = _create(db_path, endpoint_id=None, title="x")
    b = _create(db_path, endpoint_id=None, title="y")
    assert findings_db.get_finding(db_path, a)["relation_type"] == RELATION_TYPE_PRIMARY
    assert findings_db.get_finding(db_path, b)["relation_type"] == RELATION_TYPE_PRIMARY


def test_unique_primary_constraint(db_path: Path):
    """DB partial unique index allows only one PRIMARY per cluster_key."""
    _create(db_path, title="p1")
    with sqlite3.connect(str(db_path)) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO findings
                    (id, project_id, attack_type, verdict, endpoint_id, status,
                     relation_type, parent_finding_id, cluster_key,
                     created_at, updated_at, title, notes)
                VALUES (?, 'proj', 'unauth', 'BYPASS', 'ep-1', 'TRIAGING',
                        'PRIMARY', NULL, 'UNAUTH:ep-1',
                        't', 't', 'dup', '')
                """,
                (str(uuid.uuid4()),),
            )


def test_concurrent_primary_race_creates_one_primary(db_path: Path):
    """Simulated race: IntegrityError path must produce LINKED under winner."""
    results: list[str] = []
    barrier = threading.Barrier(4)
    errors: list[BaseException] = []

    def worker():
        try:
            barrier.wait(timeout=5)
            fid = _create(db_path, title="race")
            results.append(fid)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"workers failed: {errors}"
    assert len(results) == 4
    findings = [findings_db.get_finding(db_path, i) for i in results]
    primaries = [f for f in findings if f["relation_type"] == RELATION_TYPE_PRIMARY]
    linked = [f for f in findings if f["relation_type"] == RELATION_TYPE_LINKED]
    assert len(primaries) == 1
    assert len(linked) == 3
    parent = primaries[0]["id"]
    assert all(f["parent_finding_id"] == parent for f in linked)


# ------------------------------------------------------------------ #
# List filters                                                         #
# ------------------------------------------------------------------ #

def test_list_default_primary_only(db_path: Path):
    p = _create(db_path, title="p")
    _create(db_path, title="l1")
    _create(db_path, title="l2")
    listed = findings_db.list_findings(
        db_path, "proj", relation_type=RELATION_TYPE_PRIMARY
    )
    assert len(listed) == 1
    assert listed[0]["id"] == p
    assert listed[0]["linked_count"] == 2


def test_list_linked_only(db_path: Path):
    _create(db_path, title="p")
    _create(db_path, title="l1")
    _create(db_path, title="l2")
    listed = findings_db.list_findings(
        db_path, "proj", relation_type=RELATION_TYPE_LINKED
    )
    assert len(listed) == 2
    assert all(f["relation_type"] == RELATION_TYPE_LINKED for f in listed)


def test_list_all(db_path: Path):
    _create(db_path, title="p")
    _create(db_path, title="l1")
    listed = findings_db.list_findings(db_path, "proj", relation_type=None)
    assert len(listed) == 2


def test_list_linked_findings_helper(db_path: Path):
    p = _create(db_path, title="p")
    l1 = _create(db_path, title="l1")
    l2 = _create(db_path, title="l2")
    kids = findings_db.list_linked_findings(db_path, p)
    assert [k["id"] for k in kids] == [l1, l2]
    assert findings_db.count_linked_findings(db_path, p) == 2


# ------------------------------------------------------------------ #
# Status independence                                                  #
# ------------------------------------------------------------------ #

def test_status_change_does_not_propagate(db_path: Path):
    p = _create(db_path, title="p")
    l1 = _create(db_path, title="l1")
    l2 = _create(db_path, title="l2")
    findings_db.update_finding_status(db_path, p, FINDING_STATUS_REJECTED)
    assert findings_db.get_finding(db_path, p)["status"] == FINDING_STATUS_REJECTED
    assert findings_db.get_finding(db_path, l1)["status"] == FINDING_STATUS_TRIAGING
    assert findings_db.get_finding(db_path, l2)["status"] == FINDING_STATUS_TRIAGING


def test_future_linked_after_bulk_starts_triaging(db_path: Path):
    """Bulk reject of existing linked must not affect future linked findings."""
    p = _create(db_path, title="p")
    l1 = _create(db_path, title="l1")
    findings_db.update_finding_status(db_path, p, FINDING_STATUS_REJECTED)
    findings_db.update_finding_status(db_path, l1, FINDING_STATUS_REJECTED)
    l_new = _create(db_path, title="later")
    assert findings_db.get_finding(db_path, l_new)["status"] == FINDING_STATUS_TRIAGING
    assert findings_db.get_finding(db_path, l_new)["parent_finding_id"] == p
    assert findings_db.get_finding(db_path, l_new)["relation_type"] == RELATION_TYPE_LINKED


# ------------------------------------------------------------------ #
# Creator integration                                                  #
# ------------------------------------------------------------------ #

def test_create_finding_from_verdict_clusters_unauth(db_path: Path):
    project_id = "proj"
    ep = "endpoint-uuid-1"
    ids = []
    for i, variant in enumerate(
        ["remove_all_auth", "authorization_null", "malformed_bearer"]
    ):
        fid = create_finding_from_verdict(
            db_path=db_path,
            project_id=project_id,
            attack_module="unauth",
            verdict="BYPASS",
            endpoint_id=ep,
            original_flow_id=None,
            replayed_flow_id=None,
            variant=variant,
        )
        assert fid is not None
        ids.append(fid)

    findings = [findings_db.get_finding(db_path, i) for i in ids]
    primaries = [f for f in findings if f["relation_type"] == RELATION_TYPE_PRIMARY]
    linked = [f for f in findings if f["relation_type"] == RELATION_TYPE_LINKED]
    assert len(primaries) == 1
    assert len(linked) == 2
    assert all(f["cluster_key"] == f"UNAUTH:{ep}" for f in findings)

    # Non-trigger verdict creates nothing.
    none_id = create_finding_from_verdict(
        db_path=db_path,
        project_id=project_id,
        attack_module="unauth",
        verdict="SECURE",
        endpoint_id=ep,
        original_flow_id=None,
        replayed_flow_id=None,
    )
    assert none_id is None


# ------------------------------------------------------------------ #
# Migration                                                            #
# ------------------------------------------------------------------ #

def test_schema_version_is_current(db_path: Path):
    assert get_schema_version(db_path) == SCHEMA_VERSION
    assert SCHEMA_VERSION >= 34


def test_migration_backfills_relationships(tmp_path: Path):
    """Pre-v34 findings sharing unauth+endpoint become PRIMARY + LINKED."""
    path = tmp_path / "old.db"
    # Build a minimal pre-relationship findings table (v33 shape).
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (33);
            CREATE TABLE findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                endpoint_id TEXT,
                status TEXT NOT NULL DEFAULT 'TRIAGING',
                duplicate_of TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO findings VALUES
                ('f1', 'p', 'unauth', 'BYPASS', 'ep-x', 'TRIAGING', NULL,
                 '2020-01-01T00:00:00', '2020-01-01T00:00:00', 'first', ''),
                ('f2', 'p', 'unauth', 'BYPASS', 'ep-x', 'TRIAGING', NULL,
                 '2020-01-02T00:00:00', '2020-01-02T00:00:00', 'second', ''),
                ('f3', 'p', 'unauth', 'BYPASS', 'ep-y', 'TRIAGING', NULL,
                 '2020-01-03T00:00:00', '2020-01-03T00:00:00', 'other', '');
            """
        )
        conn.commit()

    migrate_project_db(path)
    # Lands on current SCHEMA_VERSION (includes v34 relationships + later steps).
    assert get_schema_version(path) == SCHEMA_VERSION
    assert get_schema_version(path) >= 34

    f1 = findings_db.get_finding(path, "f1")
    f2 = findings_db.get_finding(path, "f2")
    f3 = findings_db.get_finding(path, "f3")
    assert f1["relation_type"] == RELATION_TYPE_PRIMARY
    assert f1["cluster_key"] == "UNAUTH:ep-x"
    assert f2["relation_type"] == RELATION_TYPE_LINKED
    assert f2["parent_finding_id"] == "f1"
    assert f3["relation_type"] == RELATION_TYPE_PRIMARY
    assert f3["cluster_key"] == "UNAUTH:ep-y"


def test_fresh_db_has_relationship_columns(db_path: Path):
    with sqlite3.connect(str(db_path)) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    assert "relation_type" in cols
    assert "parent_finding_id" in cols
    assert "cluster_key" in cols
    indexes = {
        row[1]
        for row in conn.execute("PRAGMA index_list(findings)")
    }
    assert "idx_findings_primary_cluster" in indexes
