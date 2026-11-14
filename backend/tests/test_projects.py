"""Characterization tests for /api/v1/projects."""

import uuid

import pytest

API = "/api/v1"


def test_create_project(client):
    resp = client.post(
        f"{API}/projects", json={"name": "Acme", "description": "Web assessment"}
    )
    assert resp.status_code == 201
    data = resp.json()
    uuid.UUID(data["id"])  # valid UUID
    assert data["name"] == "Acme"
    assert data["description"] == "Web assessment"
    assert data["created_at"]


def test_create_project_description_is_optional(client):
    resp = client.post(f"{API}/projects", json={"name": "Acme"})
    assert resp.status_code == 201
    assert resp.json()["description"] is None


def test_list_projects_empty(client):
    resp = client.get(f"{API}/projects")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_projects_returns_all(client, make_project):
    a = make_project(name="A")
    b = make_project(name="B")
    resp = client.get(f"{API}/projects")
    assert resp.status_code == 200
    # Ordering is by created_at (1-second resolution in SQLite), so rows created
    # in the same second have no guaranteed order. Compare as a set.
    assert {p["id"] for p in resp.json()} == {a["id"], b["id"]}


def test_get_project(client, make_project):
    project = make_project()
    resp = client.get(f"{API}/projects/{project['id']}")
    assert resp.status_code == 200
    assert resp.json() == project


def test_update_project_partial(client, make_project):
    project = make_project(name="Old", description="Keep me")
    resp = client.patch(f"{API}/projects/{project['id']}", json={"name": "New"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "New"
    assert data["description"] == "Keep me"  # unset fields untouched
    assert client.get(f"{API}/projects/{project['id']}").json()["name"] == "New"


def test_update_project_nullable_description_to_null(client, make_project):
    project = make_project(description="Something")
    resp = client.patch(f"{API}/projects/{project['id']}", json={"description": None})
    assert resp.status_code == 200
    assert resp.json()["description"] is None


def test_update_project_empty_body_is_noop(client, make_project):
    project = make_project()
    resp = client.patch(f"{API}/projects/{project['id']}", json={})
    assert resp.status_code == 200
    assert resp.json() == project


def test_delete_project(client, make_project):
    project = make_project()
    resp = client.delete(f"{API}/projects/{project['id']}")
    assert resp.status_code == 204
    assert resp.content == b""
    assert client.get(f"{API}/projects/{project['id']}").status_code == 404


@pytest.mark.parametrize(
    "method, body",
    [("get", None), ("patch", {"name": "x"}), ("delete", None)],
)
def test_missing_project_returns_404(client, missing_id, method, body):
    kwargs = {"json": body} if body is not None else {}
    resp = getattr(client, method)(f"{API}/projects/{missing_id}", **kwargs)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Project not found"}


@pytest.mark.parametrize(
    "body",
    [
        {},  # name missing
        {"name": ""},  # below min_length
        {"name": "x" * 121},  # above max_length
        {"name": 123},  # wrong type
    ],
    ids=["missing-name", "empty-name", "name-too-long", "name-wrong-type"],
)
def test_create_project_invalid_body_returns_422(client, body):
    assert client.post(f"{API}/projects", json=body).status_code == 422


def test_create_project_non_json_body_returns_422(client):
    resp = client.post(
        f"{API}/projects",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_update_project_invalid_body_returns_422(client, make_project):
    project = make_project()
    resp = client.patch(f"{API}/projects/{project['id']}", json={"name": ""})
    assert resp.status_code == 422


def test_invalid_project_id_returns_422(client):
    assert client.get(f"{API}/projects/not-a-uuid").status_code == 422
