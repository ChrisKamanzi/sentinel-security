"""Target scope validation and authorization.

Two layers:

* Syntax validation (``validate_host`` / ``validate_base_url``) runs when a
  Target is created or updated. It guarantees that ``host`` is a bare hostname
  or IP (never something a CLI tool could parse as an option) and that
  ``base_url`` points at that same host.

* Runtime authorization (``authorize_scan``) runs immediately before EVERY
  scanner execution. It re-reads the Target from the database, requires
  ``is_authorized``, re-validates the host, resolves it, and checks every
  resolved IP against the address policy. Scanners are then given the checked
  IPs, so what was approved is exactly what gets scanned.
"""

import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.config import settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Blocked no matter what ALLOW_PRIVATE_TARGETS says: link-local (includes the
# 169.254.169.254 metadata service used by AWS, GCP, Azure, OCI, DigitalOcean),
# well-known metadata endpoints, and "this network".
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS over IPv6
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
]

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeError(Exception):
    """A target is not (or is no longer) eligible for scanning."""


def _is_always_blocked(ip: IPAddress) -> bool:
    return (
        any(ip in net for net in ALWAYS_BLOCKED_NETWORKS)
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.is_reserved and not ip.is_loopback)
    )


def _literal_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def validate_host(value: str) -> str:
    """Return a normalized hostname/IP or raise ValueError.

    Accepts only a bare DNS hostname or an IP literal: no scheme, port, path,
    credentials, whitespace or leading dash.
    """
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ValueError("host must not be empty")

    ip = _literal_ip(host)
    if ip is not None:
        if _is_always_blocked(ip):
            raise ValueError(f"{ip} is in a permanently blocked address range")
        return ip.compressed

    host = host.rstrip(".")
    if len(host) > 253 or not all(_LABEL.match(lbl) for lbl in host.split(".")):
        raise ValueError(
            "host must be a bare hostname or IP address "
            "(no scheme, port, path, spaces or leading '-')"
        )
    return host


def validate_base_url(url: str, host: str) -> str:
    """Require an http(s) URL whose hostname equals the Target's host."""
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("base_url must use http or https")
    if parts.username or parts.password:
        raise ValueError("base_url must not contain credentials")
    try:
        parts.port  # raises ValueError on an invalid port
    except ValueError as exc:
        raise ValueError("base_url has an invalid port") from exc
    if not parts.hostname:
        raise ValueError("base_url must include a hostname")
    if validate_host(parts.hostname) != validate_host(host):
        raise ValueError(
            f"base_url host '{parts.hostname}' does not match target host '{host}'"
        )
    return url


def resolve_host(host: str) -> list[IPAddress]:
    ip = _literal_ip(host)
    if ip is not None:
        return [ip]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"could not resolve host '{host}': {exc}") from exc
    return sorted({ipaddress.ip_address(info[4][0]) for info in infos}, key=str)


def check_ip_allowed(ip: IPAddress, allow_private: bool) -> None:
    if _is_always_blocked(ip):
        raise ScopeError(f"{ip} is in a permanently blocked address range")
    if not ip.is_global and not allow_private:
        raise ScopeError(
            f"{ip} is a private/non-public address; set ALLOW_PRIVATE_TARGETS=true "
            "to scan it (local development only)"
        )


@dataclass
class AuthorizedScope:
    scan_id: uuid.UUID
    target_id: uuid.UUID
    host: str
    base_url: str | None
    target_url: str
    ips: list[str] = field(default_factory=list)


def authorize_scan(db: Session, scan_id: uuid.UUID) -> AuthorizedScope:
    """Re-verify, from fresh database state, that a scan may run right now."""
    from app.models.scan import Scan
    from app.models.target import Target

    scan = db.get(Scan, scan_id, populate_existing=True)
    if scan is None:
        raise ScopeError("scan no longer exists")
    if scan.target_id is None:
        raise ScopeError("scan is not linked to an approved target")
    target = db.get(Target, scan.target_id, populate_existing=True)
    if target is None:
        raise ScopeError("target no longer exists")
    if target.project_id != scan.project_id:
        raise ScopeError("target does not belong to the scan's project")
    if not target.is_authorized:
        raise ScopeError("target is not authorized for scanning")

    try:
        host = validate_host(target.host)
        base_url = (
            validate_base_url(target.base_url, host) if target.base_url else None
        )
    except ValueError as exc:
        raise ScopeError(f"target failed validation: {exc}") from exc

    ips = resolve_host(host)
    if not ips:
        raise ScopeError(f"host '{host}' resolved to no addresses")
    for ip in ips:
        check_ip_allowed(ip, settings.allow_private_targets)

    return AuthorizedScope(
        scan_id=scan.id,
        target_id=target.id,
        host=host,
        base_url=base_url,
        target_url=scan.target_url,
        ips=[ip.compressed for ip in ips],
    )
