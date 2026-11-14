"""Characterization tests for Targets (/projects/{id}/targets and /targets/{id})."""

import pytest

API = "/api/v1"


def test_create_target(client, make_project):
    project = make_project()
    resp = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={"name": "Main site", "host": "example.com"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["project_id"] == project["id"]
    assert data["name"] == "Main site"
    assert data["host"] == "example.com"
    assert data["base_url"] is None
    assert data["is_authorized"] is False  # default: not authorized
    assert data["description"] is None
    assert data["created_at"]


def test_create_target_for_missing_project_returns_404(client, missing_id):
    resp = client.post(
        f"{API}/projects/{missing_id}/targets",
        json={"name": "x", "host": "example.com"},
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Project not found"}


def test_create_target_ignores_project_id_in_body(client, make_project):
    """project_id comes from the URL path; a body value is silently ignored."""
    project = make_project()
    other = make_project(name="Other")
    resp = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={"name": "x", "host": "example.com", "project_id": other["id"]},
    )
    assert resp.status_code == 201
    assert resp.json()["project_id"] == project["id"]


def test_list_targets_scoped_to_project(client, make_project, make_target):
    project = make_project()
    other = make_project(name="Other")
    t1 = make_target(project_id=project["id"], name="One")
    t2 = make_target(project_id=project["id"], name="Two")
    make_target(project_id=other["id"], name="Elsewhere")

    resp = client.get(f"{API}/projects/{project['id']}/targets")
    assert resp.status_code == 200
    assert {t["id"] for t in resp.json()} == {t1["id"], t2["id"]}


def test_list_targets_empty(client, make_project):
    project = make_project()
    resp = client.get(f"{API}/projects/{project['id']}/targets")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_targets_for_missing_project_returns_404(client, missing_id):
    resp = client.get(f"{API}/projects/{missing_id}/targets")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Project not found"}


def test_get_target(client, make_target):
    target = make_target()
    resp = client.get(f"{API}/targets/{target['id']}")
    assert resp.status_code == 200
    assert resp.json() == target


def test_update_target(client, make_target):
    target = make_target(is_authorized=False)
    resp = client.patch(
        f"{API}/targets/{target['id']}",
        json={"name": "Renamed", "is_authorized": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Renamed"
    assert data["is_authorized"] is True
    assert data["host"] == target["host"]  # untouched


def test_update_target_cannot_change_project(client, make_target, make_project):
    """project_id is not part of TargetUpdate; the extra field is ignored."""
    target = make_target()
    other = make_project(name="Other")
    resp = client.patch(
        f"{API}/targets/{target['id']}", json={"project_id": other["id"]}
    )
    assert resp.status_code == 200
    assert resp.json()["project_id"] == target["project_id"]


def test_delete_target(client, make_target):
    target = make_target()
    resp = client.delete(f"{API}/targets/{target['id']}")
    assert resp.status_code == 204
    assert client.get(f"{API}/targets/{target['id']}").status_code == 404
    # parent project is unaffected
    assert client.get(f"{API}/projects/{target['project_id']}").status_code == 200


@pytest.mark.parametrize(
    "method, body",
    [("get", None), ("patch", {"name": "x"}), ("delete", None)],
)
def test_missing_target_returns_404(client, missing_id, method, body):
    kwargs = {"json": body} if body is not None else {}
    resp = getattr(client, method)(f"{API}/targets/{missing_id}", **kwargs)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Target not found"}


@pytest.mark.parametrize(
    "body",
    [
        {"host": "example.com"},  # name missing
        {"name": "x"},  # host missing
        {"name": "", "host": "example.com"},
        {"name": "x", "host": ""},
        {"name": "x" * 121, "host": "example.com"},
        {"name": "x", "host": "h" * 256},
        {"name": "x", "host": "example.com", "base_url": "u" * 2049},
        {"name": "x", "host": "example.com", "is_authorized": "maybe"},
    ],
    ids=[
        "missing-name",
        "missing-host",
        "empty-name",
        "empty-host",
        "name-too-long",
        "host-too-long",
        "base-url-too-long",
        "is-authorized-not-bool",
    ],
)
def test_create_target_invalid_body_returns_422(client, make_project, body):
    project = make_project()
    resp = client.post(f"{API}/projects/{project['id']}/targets", json=body)
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "body",
    [{"name": ""}, {"host": ""}, {"is_authorized": "maybe"}],
    ids=["empty-name", "empty-host", "is-authorized-not-bool"],
)
def test_update_target_invalid_body_returns_422(client, make_target, body):
    target = make_target()
    assert client.patch(f"{API}/targets/{target['id']}", json=body).status_code == 422


def test_invalid_target_id_returns_422(client):
    assert client.get(f"{API}/targets/not-a-uuid").status_code == 422
