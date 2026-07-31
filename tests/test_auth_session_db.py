"""
Tests: auth-session Phase 2 DB CRUD (bindings + candidates).

Covers:
  - insert/list/get binding; unique (location, name)
  - candidate insert-if-absent unique key
  - approve pending|failed|done; reject pending only
  - force-refresh pending/rejected only
  - token_fingerprint short form (no full token)
  - unbind guards: RESTRICT / cascade pending
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.auth_session import db as as_db
from talos.auth_session.models import (
    STATUS_APPROVED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_RUNNING,
)
from talos.projects.db import init_project_db


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def test_token_fingerprint_stable_and_short() -> None:
    token = "eyJhbGciOiJSUzI1NiJ9." + ("a" * 80) + ".sig"
    fp1 = as_db.token_fingerprint(token)
    fp2 = as_db.token_fingerprint(token)
    assert fp1 == fp2
    assert "…" in fp1
    assert token not in fp1
    assert len(fp1) < len(token)


def test_insert_and_list_binding(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path,
        location="header",
        name="Authorization",
        auth_type="jwt",
    )
    assert b.id
    assert b.location == "header"
    assert b.name == "Authorization"
    assert b.auth_type == "jwt"

    rows = as_db.list_bindings(db_path)
    assert len(rows) == 1
    assert rows[0].id == b.id

    got = as_db.get_binding_by_field(db_path, "header", "Authorization")
    assert got is not None
    assert got.id == b.id


def test_binding_unique_location_name(db_path: Path) -> None:
    as_db.insert_binding(
        db_path, location="cookie", name="session", auth_type="jwt"
    )
    with pytest.raises(sqlite3.IntegrityError):
        as_db.insert_binding(
            db_path, location="cookie", name="session", auth_type="jwt"
        )


def test_binding_rejects_unknown_type(db_path: Path) -> None:
    with pytest.raises(ValueError, match="auth_type"):
        as_db.insert_binding(
            db_path, location="header", name="X", auth_type="saml"
        )


def test_insert_candidate_and_unique(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    c = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="flow-1",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="alg none",
        mutation_summary="set alg none",
        endpoint_id="ep-1",
        token_fingerprint="abc…deadbeef01",
        risk_hint="critical",
    )
    assert c.status == STATUS_PENDING
    assert c.endpoint_id == "ep-1"

    with pytest.raises(sqlite3.IntegrityError):
        as_db.insert_candidate(
            db_path,
            binding_id=b.id,
            baseline_flow_id="flow-1",
            auth_type="jwt",
            test_id="jwt.alg_none",
            test_family="algorithm",
            title="dup",
            mutation_summary="dup",
        )


def test_approve_pending_failed_done(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    ids = []
    for i, st in enumerate(
        (STATUS_PENDING, STATUS_FAILED, STATUS_DONE, STATUS_RUNNING)
    ):
        c = as_db.insert_candidate(
            db_path,
            binding_id=b.id,
            baseline_flow_id=f"flow-{i}",
            auth_type="jwt",
            test_id=f"jwt.test_{i}",
            test_family="algorithm",
            title=f"t{i}",
            mutation_summary="m",
            status=st if st == STATUS_PENDING else STATUS_PENDING,
        )
        # Force non-pending statuses via set
        if st != STATUS_PENDING:
            as_db.set_candidate_status(
                db_path, c.id, st, allowed_from=None
            )
        ids.append(c.id)

    approved, skipped = as_db.approve_candidates(db_path, ids)
    # pending, failed, done approved; running skipped
    assert len(approved) == 3
    assert len(skipped) == 1
    for cid in approved:
        assert as_db.get_candidate(db_path, cid).status == STATUS_APPROVED


def test_reject_pending_only(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="cookie", name="tok", auth_type="jwt"
    )
    pending = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f1",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
    )
    approved = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f2",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
    )
    as_db.set_candidate_status(
        db_path, approved.id, STATUS_APPROVED, allowed_from=None
    )

    rej, skip = as_db.reject_candidates(
        db_path, [pending.id, approved.id], reason="operator"
    )
    assert rej == [pending.id]
    assert skip == [approved.id]
    got = as_db.get_candidate(db_path, pending.id)
    assert got.status == STATUS_REJECTED
    assert got.reject_reason == "operator"


def test_force_refresh_pending_and_rejected_only(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    pend = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f1",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="old",
        mutation_summary="old-sum",
    )
    as_db.reject_candidates(db_path, [pend.id], reason="nope")
    rej = as_db.get_candidate(db_path, pend.id)
    assert rej.status == STATUS_REJECTED

    refreshed = as_db.force_refresh_candidate(
        db_path,
        pend.id,
        title="new",
        mutation_summary="new-sum",
        risk_hint="high",
        test_family="algorithm",
        meta={"x": 1},
    )
    assert refreshed is not None
    assert refreshed.status == STATUS_PENDING
    assert refreshed.title == "new"
    assert refreshed.reject_reason is None

    # done cannot force-refresh
    done = as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f2",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="d",
        mutation_summary="m",
    )
    as_db.set_candidate_status(db_path, done.id, STATUS_DONE, allowed_from=None)
    assert (
        as_db.force_refresh_candidate(
            db_path,
            done.id,
            title="x",
            mutation_summary="y",
            risk_hint=None,
            test_family="algorithm",
        )
        is None
    )


def test_count_and_delete_binding_without_candidates(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    counts = as_db.count_candidates_for_binding(db_path, b.id)
    assert counts["total"] == 0
    assert as_db.delete_binding(db_path, b.id) is True
    assert as_db.get_binding(db_path, b.id) is None


def test_cascade_reject_and_delete(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f1",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
    )
    n = as_db.cascade_reject_pending_for_binding(db_path, b.id)
    assert n >= 1
    # After cascade delete of pending/rejected, binding can be removed.
    assert as_db.count_candidates_for_binding(db_path, b.id)["total"] == 0
    assert as_db.delete_binding(db_path, b.id) is True


def test_list_candidates_filters(db_path: Path) -> None:
    b = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f1",
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="a",
        mutation_summary="m",
        endpoint_id="ep-1",
    )
    as_db.insert_candidate(
        db_path,
        binding_id=b.id,
        baseline_flow_id="f1",
        auth_type="jwt",
        test_id="jwt.elevate_role",
        test_family="claims",
        title="b",
        mutation_summary="m",
        endpoint_id="ep-2",
    )
    only_ep1 = as_db.list_candidates(db_path, endpoint_id="ep-1")
    assert len(only_ep1) == 1
    only_claims = as_db.list_candidates(db_path, families=["claims"])
    assert len(only_claims) == 1
    assert only_claims[0].test_id == "jwt.elevate_role"
