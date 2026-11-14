"""Characterization tests for Scans (/projects/{id}/scans and /scans/{id}).

Creating a Scan only inserts a database record (status "queued"); the current
implementation never runs a scanner, so these tests perform no network activity.
"""

import pytest

API = "/api/v1"


def test_create_scan(client, make_target):
    target = make_target(
        host="app.example.com", base_url="https://app.example.com", is_authorized=True
    )
    resp = client.post(
        f"{API}/projects/{target['project_id']}/scans",
        json={"target_id": target["id"]},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["project_id"] == target["project_id"]
    assert data["target_id"] == target["id"]
    assert data["target_url"] == "https://app.example.com"  # from base_url
    assert data["scanner"] == "pending"
    assert data["status"] == "queued"
    assert data["error_message"] is None
    assert data["started_at"] is None
    assert data["completed_at"] is None
    assert data["created_at"]


def test_create_scan_without_base_url_derives_https_host(client, make_target):
    target = make_target(host="example.org", base_url=None)
    resp = client.post(
        f"{API}/projects/{target['project_id']}/scans",
        json={"target_id": target["id"]},
    )
    assert resp.status_code == 201
    assert resp.json()["target_url"] == "https://example.org"


def test_create_scan_ignores_client_supplied_target_url(client, make_target):
    """Scope gate: a client cannot inject an arbitrary URL into a scan."""
    target = make_target()
    resp = client.post(
        f"{API}/projects/{target['project_id']}/scans",
        json={"target_id": target["id"], "target_url": "http://evil.invalid"},
    )
    assert resp.status_code == 201
    assert resp.json()["target_url"] == target["base_url"]


def test_create_scan_missing_project_returns_404(client, make_target, missing_id):
    target = make_target()
    resp = client.post(
        f"{API}/projects/{missing_id}/scans", json={"target_id": target["id"]}
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Project not found"}


def test_create_scan_missing_target_returns_404(client, make_project, missing_id):
    project = make_project()
    resp = client.post(
        f"{API}/projects/{project['id']}/scans", json={"target_id": missing_id}
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Target not found"}


def test_create_scan_target_from_other_project_returns_400(
    client, make_project, make_target
):
    project = make_project()
    foreign_target = make_target(project_id=make_project(name="Other")["id"])
    resp = client.post(
        f"{API}/projects/{project['id']}/scans",
        json={"target_id": foreign_target["id"]},
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "Target does not belong to this project"}
    assert client.get(f"{API}/projects/{project['id']}/scans").json() == []


def test_create_scan_unauthorized_target_returns_403(client, make_target):
    target = make_target(is_authorized=False)
    resp = client.post(
        f"{API}/projects/{target['project_id']}/scans",
        json={"target_id": target["id"]},
    )
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Target is not authorized for scanning"}
    assert client.get(f"{API}/projects/{target['project_id']}/scans").json() == []


@pytest.mark.parametrize(
    "body",
    [{}, {"target_id": "not-a-uuid"}, {"target_id": None}],
    ids=["missing-target-id", "malformed-target-id", "null-target-id"],
)
def test_create_scan_invalid_body_returns_422(client, make_project, body):
    project = make_project()
    resp = client.post(f"{API}/projects/{project['id']}/scans", json=body)
    assert resp.status_code == 422


def test_list_scans_scoped_to_project(client, make_target, make_scan):
    target = make_target()
    s1 = make_scan(target=target)
    s2 = make_scan(target=target)
    make_scan()  # scan in a different project

    resp = client.get(f"{API}/projects/{target['project_id']}/scans")
    assert resp.status_code == 200
    assert {s["id"] for s in resp.json()} == {s1["id"], s2["id"]}


def test_list_scans_for_missing_project_returns_404(client, missing_id):
    resp = client.get(f"{API}/projects/{missing_id}/scans")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Project not found"}


def test_get_scan(client, make_scan):
    scan = make_scan()
    resp = client.get(f"{API}/scans/{scan['id']}")
    assert resp.status_code == 200
    assert resp.json() == scan


def test_update_scan(client, make_scan):
    scan = make_scan()
    resp = client.patch(
        f"{API}/scans/{scan['id']}",
        json={"status": "failed", "error_message": "Connection refused"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert data["error_message"] == "Connection refused"
    assert data["target_url"] == scan["target_url"]  # untouched


def test_update_scan_status_does_not_set_timestamps(client, make_scan):
    """Current behavior: lifecycle timestamps are never populated by PATCH."""
    scan = make_scan()
    client.patch(f"{API}/scans/{scan['id']}", json={"status": "running"})
    data = client.patch(
        f"{API}/scans/{scan['id']}", json={"status": "completed"}
    ).json()
    assert data["status"] == "completed"
    assert data["started_at"] is None
    assert data["completed_at"] is None


def test_update_scan_invalid_status_returns_422(client, make_scan):
    scan = make_scan()
    resp = client.patch(f"{API}/scans/{scan['id']}", json={"status": "paused"})
    assert resp.status_code == 422


def test_delete_scan(client, make_scan):
    scan = make_scan()
    resp = client.delete(f"{API}/scans/{scan['id']}")
    assert resp.status_code == 204
    assert client.get(f"{API}/scans/{scan['id']}").status_code == 404
    # target and project are unaffected
    assert client.get(f"{API}/targets/{scan['target_id']}").status_code == 200


@pytest.mark.parametrize(
    "method, body",
    [("get", None), ("patch", {"status": "running"}), ("delete", None)],
)
def test_missing_scan_returns_404(client, missing_id, method, body):
    kwargs = {"json": body} if body is not None else {}
    resp = getattr(client, method)(f"{API}/scans/{missing_id}", **kwargs)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Scan not found"}


def test_invalid_scan_id_returns_422(client):
    assert client.get(f"{API}/scans/not-a-uuid").status_code == 422
