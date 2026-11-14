"""Scope validation: host/base_url syntax, address policy, runtime authorization.

No real DNS lookups: tests use IP literals or monkeypatch the resolver.
"""

import ipaddress
import uuid

import pytest

from app.core import scope
from app.core.config import settings
from app.core.scope import (
    ScopeError,
    authorize_scan,
    check_ip_allowed,
    validate_base_url,
    validate_host,
)

API = "/api/v1"


# --- validate_host ------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("[::1]", "::1"),
        ("sub-domain.example.co.uk", "sub-domain.example.co.uk"),
        ("localhost", "localhost"),
    ],
)
def test_validate_host_accepts(value, expected):
    assert validate_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "-iL /etc/passwd",  # option injection
        "-sS",
        "http://example.com",  # scheme
        "example.com/path",
        "example.com:8000",  # port belongs in base_url
        "user@example.com",
        "exa mple.com",
        "-example.com",
        "example-.com",
        "",
        "169.254.169.254",  # metadata (always blocked)
        "0.0.0.0",
        "a" * 64 + ".com",  # label too long
    ],
)
def test_validate_host_rejects(value):
    with pytest.raises(ValueError):
        validate_host(value)


# --- validate_base_url ----------------------------------------------------------


@pytest.mark.parametrize(
    "url, host",
    [
        ("http://127.0.0.1:8000", "127.0.0.1"),
        ("https://Example.com/app", "example.com"),
        ("http://[::1]:8080/", "::1"),
    ],
)
def test_validate_base_url_accepts(url, host):
    assert validate_base_url(url, host) == url


@pytest.mark.parametrize(
    "url, host",
    [
        ("http://evil.example/", "example.com"),
        ("http://169.254.169.254/latest/meta-data/", "example.com"),
        ("ftp://example.com/", "example.com"),
        ("javascript:alert(1)", "example.com"),
        ("http://user:pw@example.com/", "example.com"),
        ("http://example.com:99999/", "example.com"),
        ("example.com", "example.com"),
    ],
)
def test_validate_base_url_rejects(url, host):
    with pytest.raises(ValueError):
        validate_base_url(url, host)


# --- address policy -------------------------------------------------------------


@pytest.mark.parametrize("ip", ["169.254.169.254", "fd00:ec2::254", "100.100.100.200", "224.0.0.1"])
@pytest.mark.parametrize("allow_private", [False, True])
def test_always_blocked_even_when_private_allowed(ip, allow_private):
    with pytest.raises(ScopeError):
        check_ip_allowed(ipaddress.ip_address(ip), allow_private)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.10", "::1"])
def test_private_blocked_unless_allowed(ip):
    with pytest.raises(ScopeError):
        check_ip_allowed(ipaddress.ip_address(ip), allow_private=False)
    check_ip_allowed(ipaddress.ip_address(ip), allow_private=True)  # no raise


def test_public_ip_allowed():
    check_ip_allowed(ipaddress.ip_address("8.8.8.8"), allow_private=False)


# --- authorize_scan (runtime check) --------------------------------------------


@pytest.fixture
def local_scan(client, make_project):
    project = make_project()
    target = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={"name": "Self", "host": "127.0.0.1",
              "base_url": "http://127.0.0.1:8000", "is_authorized": True},
    ).json()
    scan = client.post(f"{API}/projects/{project['id']}/scans",
                       json={"target_id": target["id"]}).json()
    return target, scan


def test_authorize_scan_private_target_blocked_by_default(db_session, local_scan):
    _, scan = local_scan
    with pytest.raises(ScopeError, match="ALLOW_PRIVATE_TARGETS"):
        authorize_scan(db_session, uuid.UUID(scan["id"]))


def test_authorize_scan_returns_checked_ips(db_session, local_scan, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", True)
    target, scan = local_scan
    result = authorize_scan(db_session, uuid.UUID(scan["id"]))
    assert result.ips == ["127.0.0.1"]
    assert result.host == "127.0.0.1"
    assert result.base_url == "http://127.0.0.1:8000"


def test_authorize_scan_sees_revoked_authorization(client, db_session, local_scan, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", True)
    target, scan = local_scan
    authorize_scan(db_session, uuid.UUID(scan["id"]))  # authorized now
    client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
    with pytest.raises(ScopeError, match="not authorized"):
        authorize_scan(db_session, uuid.UUID(scan["id"]))


def test_authorize_scan_rejects_hostname_resolving_to_metadata(
    client, db_session, make_project, monkeypatch
):
    """DNS that points an approved name at the metadata service is blocked."""
    monkeypatch.setattr(settings, "allow_private_targets", True)
    monkeypatch.setattr(
        scope, "resolve_host", lambda host: [ipaddress.ip_address("169.254.169.254")]
    )
    project = make_project()
    target = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={"name": "x", "host": "rebind.example", "is_authorized": True},
    ).json()
    scan = client.post(f"{API}/projects/{project['id']}/scans",
                       json={"target_id": target["id"]}).json()
    with pytest.raises(ScopeError, match="permanently blocked"):
        authorize_scan(db_session, uuid.UUID(scan["id"]))


# --- API-level target validation ------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"name": "x", "host": "-iL /etc/passwd"},
        {"name": "x", "host": "http://example.com"},
        {"name": "x", "host": "169.254.169.254"},
        {"name": "x", "host": "example.com", "base_url": "ftp://example.com"},
        {"name": "x", "host": "example.com", "base_url": "https://other.example"},
    ],
    ids=["option-injection", "scheme-in-host", "metadata-ip", "bad-scheme", "host-mismatch"],
)
def test_create_target_rejects_unsafe_values(client, make_project, body):
    project = make_project()
    resp = client.post(f"{API}/projects/{project['id']}/targets", json=body)
    assert resp.status_code == 422


def test_patch_host_must_still_match_base_url(client, make_target):
    target = make_target(host="example.com", base_url="https://example.com")
    resp = client.patch(f"{API}/targets/{target['id']}", json={"host": "other.example"})
    assert resp.status_code == 422
    # host + base_url changed together consistently is fine
    resp = client.patch(
        f"{API}/targets/{target['id']}",
        json={"host": "other.example", "base_url": "https://other.example/app"},
    )
    assert resp.status_code == 200


def test_patch_base_url_to_other_host_rejected(client, make_target):
    target = make_target(host="example.com", base_url="https://example.com")
    resp = client.patch(f"{API}/targets/{target['id']}",
                        json={"base_url": "http://169.254.169.254/"})
    assert resp.status_code == 422
