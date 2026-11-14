"""Characterization tests for Findings (/scans/{id}/findings and /findings/{id})."""

import pytest

API = "/api/v1"


def test_create_finding_minimal(client, make_scan):
    scan = make_scan()
    resp = client.post(
        f"{API}/scans/{scan['id']}/findings", json={"title": "Open port 22"}
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["scan_id"] == scan["id"]
    assert data["title"] == "Open port 22"
    assert data["severity"] == "info"  # default
    for field in ("description", "recommendation", "location", "evidence"):
        assert data[field] is None
    assert data["created_at"]


def test_create_finding_all_fields(client, make_scan):
    scan = make_scan()
    body = {
        "title": "Reflected XSS",
        "severity": "high",
        "description": "User input reflected unescaped.",
        "recommendation": "Encode output.",
        "location": "https://example.com/search?q=",
        "evidence": "<script>alert(1)</script>",
    }
    resp = client.post(f"{API}/scans/{scan['id']}/findings", json=body)
    assert resp.status_code == 201
    data = resp.json()
    for key, value in body.items():
        assert data[key] == value


def test_create_finding_for_missing_scan_returns_404(client, missing_id):
    resp = client.post(f"{API}/scans/{missing_id}/findings", json={"title": "x"})
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Scan not found"}


def test_list_findings_scoped_to_scan(client, make_scan, make_finding):
    scan = make_scan()
    f1 = make_finding(scan_id=scan["id"], title="One")
    f2 = make_finding(scan_id=scan["id"], title="Two")
    make_finding(title="Other scan")

    resp = client.get(f"{API}/scans/{scan['id']}/findings")
    assert resp.status_code == 200
    assert {f["id"] for f in resp.json()} == {f1["id"], f2["id"]}


def test_list_findings_for_missing_scan_returns_404(client, missing_id):
    resp = client.get(f"{API}/scans/{missing_id}/findings")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Scan not found"}


def test_get_finding(client, make_finding):
    finding = make_finding()
    resp = client.get(f"{API}/findings/{finding['id']}")
    assert resp.status_code == 200
    assert resp.json() == finding


def test_update_finding(client, make_finding):
    finding = make_finding(severity="low")
    resp = client.patch(
        f"{API}/findings/{finding['id']}",
        json={"severity": "critical", "recommendation": "Patch now"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["severity"] == "critical"
    assert data["recommendation"] == "Patch now"
    assert data["title"] == finding["title"]  # untouched


def test_delete_finding(client, make_finding):
    finding = make_finding()
    resp = client.delete(f"{API}/findings/{finding['id']}")
    assert resp.status_code == 204
    assert client.get(f"{API}/findings/{finding['id']}").status_code == 404
    assert client.get(f"{API}/scans/{finding['scan_id']}").status_code == 200


@pytest.mark.parametrize(
    "method, body",
    [("get", None), ("patch", {"title": "x"}), ("delete", None)],
)
def test_missing_finding_returns_404(client, missing_id, method, body):
    kwargs = {"json": body} if body is not None else {}
    resp = getattr(client, method)(f"{API}/findings/{missing_id}", **kwargs)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Finding not found"}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"title": ""},
        {"title": "x" * 256},
        {"title": "x", "severity": "urgent"},
        {"title": "x", "location": "l" * 2049},
    ],
    ids=[
        "missing-title",
        "empty-title",
        "title-too-long",
        "invalid-severity",
        "location-too-long",
    ],
)
def test_create_finding_invalid_body_returns_422(client, make_scan, body):
    scan = make_scan()
    resp = client.post(f"{API}/scans/{scan['id']}/findings", json=body)
    assert resp.status_code == 422


def test_update_finding_invalid_severity_returns_422(client, make_finding):
    finding = make_finding()
    resp = client.patch(
        f"{API}/findings/{finding['id']}", json={"severity": "urgent"}
    )
    assert resp.status_code == 422


def test_invalid_finding_id_returns_422(client):
    assert client.get(f"{API}/findings/not-a-uuid").status_code == 422
