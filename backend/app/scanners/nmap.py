"""Nmap: TCP port discovery and service/version detection.

Conservative defaults: unprivileged TCP connect scan (-sT), normal timing
(-T3), at most the top 1000 ports (plus the target's base_url port), no NSE
scripts, no OS detection. Only the scope-checked IPs are passed to nmap, after
a ``--`` end-of-options marker.
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.scanners.base import (
    BaseScanner,
    NormalizedFinding,
    ScanContext,
    ScannerError,
    ScannerOutput,
)
from app.scanners.process import ProcessResult

_PORT_SPEC = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt"}

# When no nmap signature matches, nmap falls back to a port-table guess
# (e.g. 3000 -> "ppp") but still records the probe responses in `servicefp`.
# An HTTP status line in reply to its GetRequest/HTTPOptions probes means the
# port really speaks HTTP.
# nmap escapes fingerprints: HTTP/1\.1\x20200 (plain form accepted too).
_HTTP_FINGERPRINT = re.compile(
    r'r\((?:GetRequest|HTTPOptions|FourOhFourRequest),[0-9A-Fa-f]+,"HTTP/1\\?\.[01](?:\\x20| )\d{3}'
)

# Small, explicit heuristics. Nmap itself assigns no severity.
CLEARTEXT_ADMIN_SERVICES = {"telnet", "ftp", "rlogin", "rsh", "rexec", "vnc"}
DATASTORE_SERVICES = {
    "redis", "mongodb", "memcached", "elasticsearch", "mysql", "postgresql",
    "ms-sql-s", "oracle-tns", "couchdb", "cassandra",
}


class NmapOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # How many of nmap's most common TCP ports to scan (capped at 1000).
    top_ports: int = Field(default=1000, ge=1, le=1000)
    # Explicit port list instead of top_ports, e.g. "22,80,443,8000-8100".
    ports: str | None = Field(default=None, max_length=200)
    service_detection: bool = True

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.replace(" ", "")
        if not _PORT_SPEC.match(v):
            raise ValueError("ports must look like '22,80,443,8000-8100'")
        for part in v.split(","):
            lo, _, hi = part.partition("-")
            lo_i, hi_i = int(lo), int(hi or lo)
            if not (1 <= lo_i <= hi_i <= 65535):
                raise ValueError(f"invalid port or range: {part}")
        return v


def _services_file(executable_path: str) -> str | None:
    prefix = os.path.dirname(os.path.dirname(os.path.realpath(executable_path)))
    for candidate in (
        os.path.join(prefix, "share", "nmap", "nmap-services"),
        "/opt/homebrew/share/nmap/nmap-services",
        "/usr/local/share/nmap/nmap-services",
        "/usr/share/nmap/nmap-services",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


@lru_cache(maxsize=8)
def top_tcp_ports(services_file: str, count: int) -> tuple[int, ...]:
    """The `count` most frequent TCP ports according to nmap-services."""
    ranked: list[tuple[float, int]] = []
    with open(services_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1].endswith("/tcp"):
                try:
                    ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
                except ValueError:
                    continue
    ranked.sort(reverse=True)
    return tuple(port for _, port in ranked[:count])


def compress_ports(ports: set[int]) -> str:
    """{1,2,3,7} -> '1-3,7'"""
    out: list[str] = []
    ordered = sorted(ports)
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        out.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(out)


def base_url_port(base_url: str | None) -> int | None:
    if not base_url:
        return None
    parts = urlsplit(base_url)
    return parts.port or (443 if parts.scheme == "https" else 80)


class NmapScanner(BaseScanner):
    name = "nmap"
    display_name = "Nmap"
    executable_name = "nmap"
    Options = NmapOptions

    @classmethod
    def version(cls, path: str) -> str | None:
        try:
            out = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=10,
                stdin=subprocess.DEVNULL,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"Nmap version (\S+)", out)
        return match.group(1) if match else None

    def timeout_seconds(self, ctx: ScanContext) -> int:
        return settings.nmap_timeout_seconds

    def port_spec(self, ctx: ScanContext) -> str:
        opts: NmapOptions = ctx.options  # type: ignore[assignment]
        if opts.ports:
            return opts.ports
        ports: set[int] = set()
        services = _services_file(self.executable_path)
        if services:
            ports.update(top_tcp_ports(services, opts.top_ports))
        else:  # no data file: fall back to a small well-known set
            ports.update({21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306,
                          3389, 5432, 6379, 8000, 8080, 8443})
        extra = base_url_port(ctx.base_url)
        if extra:
            ports.add(extra)  # always include the target's own web port
        return compress_ports(ports)

    def build_command(self, ctx: ScanContext) -> list[str]:
        opts: NmapOptions = ctx.options  # type: ignore[assignment]
        if not ctx.ips:
            raise ScannerError("no scope-checked IP addresses to scan")
        argv = [
            self.executable_path,
            "-sT",              # TCP connect scan (no root needed)
            "-Pn",              # single authorized host: skip host discovery
            "-n",               # no DNS: we pass scope-checked IPs
            "-T3",              # normal timing
            "--max-retries", "2",
            "--host-timeout", f"{self.timeout_seconds(ctx)}s",
            "--open",           # report open ports only
            "-p", self.port_spec(ctx),
        ]
        if opts.service_detection:
            argv.append("-sV")
        argv += ["-oX", "-", "--", *ctx.ips]
        return argv

    # --- parsing --------------------------------------------------------------
    def parse(self, process: ProcessResult, ctx: ScanContext) -> ScannerOutput:
        if process.exit_code != 0:
            tail = process.stderr.strip()[-2000:] or "no error output"
            raise ScannerError(f"nmap exited with code {process.exit_code}: {tail}", process)
        try:
            root = ET.fromstring(process.stdout)
        except ET.ParseError as exc:
            raise ScannerError(f"could not parse nmap XML output: {exc}", process) from exc
        artifacts, findings = parse_nmap_xml(root, ctx.host)
        if process.truncated:
            artifacts["output_truncated"] = True
        return ScannerOutput(
            findings=findings,
            artifacts=artifacts,
            raw_output=process.stdout,
            exit_code=process.exit_code,
            command=process.argv,
        )


def _url_for(host: str, scheme: str, port: int) -> str:
    host_part = f"[{host}]" if ":" in host else host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host_part}" if default else f"{scheme}://{host_part}:{port}"


def parse_nmap_xml(root: ET.Element, target_host: str) -> tuple[dict[str, Any], list[NormalizedFinding]]:
    hosts: list[dict[str, Any]] = []
    http_services: dict[int, dict[str, Any]] = {}
    findings: dict[str, NormalizedFinding] = {}

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        address = addr_el.get("addr") if addr_el is not None else None
        status_el = host_el.find("status")
        ports: list[dict[str, Any]] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue
            svc = port_el.find("service")
            svc_attr = dict(svc.attrib) if svc is not None else {}
            # servicefp holds raw probe responses (can include page content):
            # use it for inference only, never store it.
            fingerprint = svc_attr.pop("servicefp", "")
            if svc_attr.get("method") == "table" and _HTTP_FINGERPRINT.search(fingerprint):
                svc_attr["port_table_guess"] = svc_attr.get("name")
                svc_attr["name"] = "http"
                svc_attr["method"] = "fingerprint"
            port = {
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": state,
                "reason": state_el.get("reason") if state_el is not None else None,
                "service": svc_attr.get("name"),
                "product": svc_attr.get("product"),
                "version": svc_attr.get("version"),
                "extrainfo": svc_attr.get("extrainfo"),
                "tunnel": svc_attr.get("tunnel"),
                "method": svc_attr.get("method"),
                "confidence": int(svc_attr["conf"]) if svc_attr.get("conf", "").isdigit() else None,
                "port_table_guess": svc_attr.get("port_table_guess"),
            }
            ports.append(port)

            name = (port["service"] or "").lower()
            if name in HTTP_SERVICE_NAMES or name.startswith("http"):
                scheme = "https" if port["tunnel"] == "ssl" or name.startswith("https") else "http"
                http_services.setdefault(port["port"], {
                    "url": _url_for(target_host, scheme, port["port"]),
                    "port": port["port"],
                    "scheme": scheme,
                    "service": port["service"],
                    "product": port["product"],
                    "version": port["version"],
                })

            nf = _finding_for_port(port, target_host, address)
            findings.setdefault(nf.dedup_key, nf)  # same port on several IPs -> one finding

        hosts.append({
            "address": address,
            "status": status_el.get("state") if status_el is not None else None,
            "ports": ports,
        })

    finished = root.find("runstats/finished")
    artifacts = {
        "nmap_version": root.get("version"),
        "args": root.get("args"),
        "elapsed_seconds": float(finished.get("elapsed")) if finished is not None and finished.get("elapsed") else None,
        "summary": finished.get("summary") if finished is not None else None,
        "hosts": hosts,
        "open_ports": sorted({p["port"] for h in hosts for p in h["ports"]}),
        "http_services": [http_services[p] for p in sorted(http_services)],
    }
    return artifacts, list(findings.values())


def _finding_for_port(port: dict[str, Any], host: str, address: str | None) -> NormalizedFinding:
    proto, number = port["protocol"], port["port"]
    service = port["service"] or "unknown"
    banner = " ".join(x for x in (port["product"], port["version"], port["extrainfo"]) if x)
    identified_by = {
        "probed": "a service probe response",
        "fingerprint": "an HTTP response to nmap's probes (no exact nmap signature matched)",
    }.get(port["method"], "port-number lookup only (not confirmed by a probe)")
    if port["method"] == "probed" and (port["confidence"] or 0) >= 8:
        confidence = "high"
    elif port["method"] == "fingerprint":
        confidence = "medium"
    else:
        confidence = "low"

    severity = FindingSeverity.INFO
    recommendation = (
        "Confirm this service is intended to be reachable from where the scan "
        "was run. Close or firewall it if not, and keep it patched."
    )
    note = ""
    name = service.lower()
    if name in CLEARTEXT_ADMIN_SERVICES:
        severity = FindingSeverity.LOW
        note = " This protocol transmits data, often including credentials, in cleartext."
        recommendation = "Disable this service or replace it with an encrypted alternative (e.g. SSH/SFTP)."
    elif name in DATASTORE_SERVICES:
        severity = FindingSeverity.LOW
        note = " Datastores are frequently deployed without authentication; verify access controls."
        recommendation = (
            "Ensure the datastore requires authentication, binds only to trusted "
            "interfaces, and is not reachable from untrusted networks."
        )

    evidence_lines = [
        f"port: {number}/{proto}",
        f"state: {port['state']} (reason: {port['reason']})",
        f"service: {service}",
    ]
    if banner:
        evidence_lines.append(f"banner: {banner}")
    if port["tunnel"]:
        evidence_lines.append(f"tunnel: {port['tunnel']}")
    evidence_lines.append(f"detection: {port['method'] or 'n/a'} (nmap conf {port['confidence']})")
    if port.get("port_table_guess"):
        evidence_lines.append(f"nmap port-table guess: {port['port_table_guess']} (overridden: HTTP response observed)")

    return NormalizedFinding(
        title=f"Open {proto.upper()} port {number} ({service})",
        severity=severity,
        dedup_key=f"open-port:{proto}/{number}",
        location=f"{host}:{number}/{proto}",
        description=(
            f"Nmap found {proto}/{number} open on {host}"
            f"{f' ({address})' if address and address != host else ''}. "
            f"Service '{service}'{f' identified as {banner}' if banner else ''} "
            f"via {identified_by}.{note}"
        ),
        recommendation=recommendation,
        evidence="\n".join(evidence_lines),
        original_severity=None,  # nmap does not assign severities
        confidence=confidence,
        source_id=f"nmap:{proto}/{number}",
        references=["https://nmap.org/book/man-port-scanning-basics.html"],
    )
