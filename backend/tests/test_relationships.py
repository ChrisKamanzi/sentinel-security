"""Database relationship, cascade and foreign-key tests.

Note: the test database is built from the current SQLAlchemy models via
create_all(). It therefore does NOT reproduce the schema drift found in the
existing autopentest.db (scans.target_id there lacks ON DELETE CASCADE and its
index). Tests deliberately never open autopentest.db.
"""

import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.models import Finding, Project, Scan, Target

API = "/api/v1"


def _count(session, model):
    return session.scalar(select(func.count()).select_from(model))


@pytest.fixture
def graph(make_target, make_scan, make_finding):
    """One project -> one target -> one scan -> one finding."""
    target = make_target()
    scan = make_scan(target=target)
    finding = make_finding(scan_id=scan["id"])
    return {"target": target, "scan": scan, "finding": finding}


def test_foreign_keys_pragma_enabled(db_session):
    assert db_session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_delete_project_cascades_to_targets_scans_findings(
    client, db_session, graph
):
    project_id = graph["target"]["project_id"]
    assert client.delete(f"{API}/projects/{project_id}").status_code == 204

    assert client.get(f"{API}/targets/{graph['target']['id']}").status_code == 404
    assert client.get(f"{API}/scans/{graph['scan']['id']}").status_code == 404
    assert client.get(f"{API}/findings/{graph['finding']['id']}").status_code == 404
    for model in (Project, Target, Scan, Finding):
        assert _count(db_session, model) == 0, model.__name__


def test_delete_project_leaves_other_projects_intact(
    client, db_session, graph, make_target, make_scan, make_finding
):
    other_target = make_target()
    other_finding = make_finding(scan_id=make_scan(target=other_target)["id"])

    client.delete(f"{API}/projects/{graph['target']['project_id']}")

    assert client.get(f"{API}/targets/{other_target['id']}").status_code == 200
    assert client.get(f"{API}/findings/{other_finding['id']}").status_code == 200
    assert _count(db_session, Project) == 1
    assert _count(db_session, Finding) == 1


def test_delete_target_cascades_to_scans_and_findings(client, db_session, graph):
    """Current behavior: deleting a Target also deletes its scan history."""
    assert client.delete(f"{API}/targets/{graph['target']['id']}").status_code == 204

    assert client.get(f"{API}/scans/{graph['scan']['id']}").status_code == 404
    assert client.get(f"{API}/findings/{graph['finding']['id']}").status_code == 404
    assert _count(db_session, Scan) == 0
    assert _count(db_session, Finding) == 0
    # project survives
    project_id = graph["target"]["project_id"]
    assert client.get(f"{API}/projects/{project_id}").status_code == 200


def test_delete_scan_cascades_to_findings(client, db_session, graph):
    assert client.delete(f"{API}/scans/{graph['scan']['id']}").status_code == 204

    assert client.get(f"{API}/findings/{graph['finding']['id']}").status_code == 404
    assert _count(db_session, Finding) == 0
    assert client.get(f"{API}/targets/{graph['target']['id']}").status_code == 200


def test_db_level_on_delete_cascade(db_session, graph):
    """With foreign_keys=ON, a raw SQL delete (bypassing the ORM) cascades."""
    db_session.execute(text("DELETE FROM projects"))
    db_session.commit()
    for model in (Target, Scan, Finding):
        assert _count(db_session, model) == 0, model.__name__


def test_fk_rejects_target_with_unknown_project(db_session):
    db_session.add(Target(project_id=uuid.uuid4(), name="x", host="example.com"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_fk_rejects_scan_with_unknown_project(db_session):
    db_session.add(Scan(project_id=uuid.uuid4(), target_url="https://example.com"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_fk_rejects_scan_with_unknown_target(db_session, make_project):
    project_id = uuid.UUID(make_project()["id"])
    db_session.add(
        Scan(
            project_id=project_id,
            target_id=uuid.uuid4(),
            target_url="https://example.com",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_fk_rejects_finding_with_unknown_scan(db_session):
    db_session.add(Finding(scan_id=uuid.uuid4(), title="x"))
    with pytest.raises(IntegrityError):
        db_session.commit()
