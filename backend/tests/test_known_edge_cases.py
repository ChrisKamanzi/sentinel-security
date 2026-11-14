"""Regression tests for the edge cases found in the backend audit.

These were strict-xfail tests in the characterization phase. They were fixed
in Phase 0, so the xfail markers have been removed and they are now ordinary
tests asserting the agreed behavior.
"""

import pytest

API = "/api/v1"


# ---------------------------------------------------------------------------
# 1. PATCH explicitly setting a NOT NULL column to null -> 422 (was 500).
# ---------------------------------------------------------------------------


@pytest.fixture
def resource_urls(make_finding, client):
    finding = make_finding()
    scan = client.get(f"{API}/scans/{finding['scan_id']}").json()
    return {
        "project": f"{API}/projects/{scan['project_id']}",
        "target": f"{API}/targets/{scan['target_id']}",
        "scan": f"{API}/scans/{scan['id']}",
        "finding": f"{API}/findings/{finding['id']}",
    }


@pytest.mark.parametrize(
    "resource, field",
    [
        ("project", "name"),
        ("target", "name"),
        ("target", "host"),
        ("target", "is_authorized"),
        ("scan", "status"),
        ("finding", "title"),
        ("finding", "severity"),
    ],
)
def test_patch_required_field_to_null_returns_422(
    client_no_raise, resource_urls, resource, field
):
    resp = client_no_raise.patch(resource_urls[resource], json={field: None})
    assert resp.status_code == 422, f"got {resp.status_code}"


def test_patch_nullable_field_to_null_still_allowed(client, make_project):
    project = make_project(description="x")
    resp = client.patch(f"{API}/projects/{project['id']}", json={"description": None})
    assert resp.status_code == 200
    assert resp.json()["description"] is None


# ---------------------------------------------------------------------------
# 2. Whitespace-only names / titles / hosts -> 422 (were accepted).
# ---------------------------------------------------------------------------


def test_create_project_whitespace_name_returns_422(client):
    resp = client.post(f"{API}/projects", json={"name": "   "})
    assert resp.status_code == 422, f"got {resp.status_code}"


def test_update_project_whitespace_name_returns_422(client, make_project):
    project = make_project()
    resp = client.patch(f"{API}/projects/{project['id']}", json={"name": "   "})
    assert resp.status_code == 422, f"got {resp.status_code}"


@pytest.mark.parametrize(
    "body",
    [
        {"name": "   ", "host": "example.com"},
        {"name": "Site", "host": "   "},
    ],
    ids=["whitespace-name", "whitespace-host"],
)
def test_create_target_whitespace_returns_422(client, make_project, body):
    project = make_project()
    resp = client.post(f"{API}/projects/{project['id']}/targets", json=body)
    assert resp.status_code == 422, f"got {resp.status_code}"


def test_create_finding_whitespace_title_returns_422(client, make_scan):
    scan = make_scan()
    resp = client.post(f"{API}/scans/{scan['id']}/findings", json={"title": "   "})
    assert resp.status_code == 422, f"got {resp.status_code}"


def test_names_are_stripped(client):
    resp = client.post(f"{API}/projects", json={"name": "  Acme  "})
    assert resp.status_code == 201
    assert resp.json()["name"] == "Acme"


# ---------------------------------------------------------------------------
# 3. Scope gate: base_url must be on the target host (was accepted).
# ---------------------------------------------------------------------------


def test_create_target_base_url_must_match_host(client, make_project):
    project = make_project()
    resp = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={
            "name": "Site",
            "host": "example.com",
            "base_url": "http://169.254.169.254/latest/meta-data/",
            "is_authorized": True,
        },
    )
    assert resp.status_code == 422, f"got {resp.status_code}"
