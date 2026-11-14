"""Nmap scanner: command construction, option validation and XML parsing.

No real scans: parsing uses a recorded fixture, and command tests only build argv.
"""

import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models.finding import FindingSeverity
from app.scanners.base import ScanContext, ScannerError
from app.scanners.nmap import NmapOptions, NmapScanner, compress_ports, parse_nmap_xml
from app.scanners.process import ProcessResult

FIXTURE = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()


def make_ctx(**overrides):
    defaults = dict(
        scan_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        host="127.0.0.1",
        ips=["127.0.0.1"],
        base_url="http://127.0.0.1:8000",
        target_url="http://127.0.0.1:8000",
        options=NmapOptions(),
    )
    defaults.update(overrides)
    return ScanContext(**defaults)


def proc(stdout="", stderr="", exit_code=0, truncated=False):
    return ProcessResult(argv=["/opt/homebrew/bin/nmap"], exit_code=exit_code, stdout=stdout,
                         stderr=stderr, timed_out=False, duration_seconds=1.0, truncated=truncated)


# --- command construction -----------------------------------------------------


def test_command_is_safe_argv():
    argv = NmapScanner("/opt/homebrew/bin/nmap").build_command(make_ctx())
    assert argv[0] == "/opt/homebrew/bin/nmap"
    assert all(isinstance(a, str) for a in argv)
    # conservative flags
    for flag in ("-sT", "-Pn", "-n", "-T3", "--open", "-sV"):
        assert flag in argv
    for forbidden in ("-sS", "-O", "-A", "-sC", "--script", "-T5", "-T4"):
        assert forbidden not in argv
    # only scope-checked IPs, after end-of-options marker
    assert argv[-2:] == ["--", "127.0.0.1"]
    assert argv[argv.index("-oX") + 1] == "-"


def test_default_ports_include_base_url_port():
    scanner = NmapScanner("/opt/homebrew/bin/nmap")
    spec = scanner.port_spec(make_ctx(base_url="http://127.0.0.1:59999"))
    assert spec.endswith("59999") or ",59999" in spec or "59999" in spec


def test_explicit_ports_used_verbatim():
    ctx = make_ctx(options=NmapOptions(ports="22,80,8000-8010"))
    argv = NmapScanner("/opt/homebrew/bin/nmap").build_command(ctx)
    assert argv[argv.index("-p") + 1] == "22,80,8000-8010"


def test_service_detection_can_be_disabled():
    ctx = make_ctx(options=NmapOptions(service_detection=False))
    assert "-sV" not in NmapScanner("/opt/homebrew/bin/nmap").build_command(ctx)


def test_no_ips_refuses_to_build():
    with pytest.raises(ScannerError):
        NmapScanner("/opt/homebrew/bin/nmap").build_command(make_ctx(ips=[]))


@pytest.mark.parametrize(
    "opts",
    [
        {"top_ports": 0},
        {"top_ports": 5000},  # capped at 1000 (conservative)
        {"ports": "1-70000"},
        {"ports": "80;rm -rf /"},
        {"ports": "--script=vuln"},
        {"ports": "100-10"},
        {"script": "vuln"},  # unknown option
    ],
)
def test_invalid_options_rejected(opts):
    with pytest.raises(ValidationError):
        NmapOptions.model_validate(opts)


def test_compress_ports():
    assert compress_ports({1, 2, 3, 7, 9, 10}) == "1-3,7,9-10"


# --- parsing --------------------------------------------------------------------


def test_parse_fixture_artifacts():
    artifacts, findings = parse_nmap_xml(ET.fromstring(FIXTURE), "127.0.0.1")
    assert artifacts["nmap_version"] == "7.98"
    assert artifacts["elapsed_seconds"] == 12.34
    assert artifacts["open_ports"] == [22, 23, 443, 3000, 5555, 6379, 8000]  # closed 80 excluded
    assert artifacts["http_services"] == [
        {"url": "https://127.0.0.1", "port": 443, "scheme": "https",
         "service": "http", "product": "nginx", "version": "1.27.0"},
        {"url": "http://127.0.0.1:3000", "port": 3000, "scheme": "http",
         "service": "http", "product": None, "version": None},
        {"url": "http://127.0.0.1:8000", "port": 8000, "scheme": "http",
         "service": "http", "product": "Uvicorn", "version": None},
    ]
    assert "servicefp" not in str(artifacts)  # raw probe responses never stored


def test_parse_fixture_findings():
    _, findings = parse_nmap_xml(ET.fromstring(FIXTURE), "127.0.0.1")
    by_port = {f.source_id: f for f in findings}
    assert set(by_port) == {"nmap:tcp/22", "nmap:tcp/23", "nmap:tcp/443", "nmap:tcp/3000",
                            "nmap:tcp/5555", "nmap:tcp/6379", "nmap:tcp/8000"}

    ssh = by_port["nmap:tcp/22"]
    assert ssh.severity == FindingSeverity.INFO
    assert ssh.title == "Open TCP port 22 (ssh)"
    assert ssh.location == "127.0.0.1:22/tcp"
    assert ssh.confidence == "high"
    assert ssh.original_severity is None
    assert "OpenSSH 9.8 protocol 2.0" in ssh.evidence
    assert ssh.dedup_key == "open-port:tcp/22"

    assert by_port["nmap:tcp/23"].severity == FindingSeverity.LOW  # telnet: cleartext
    assert by_port["nmap:tcp/23"].confidence == "low"  # table lookup only
    assert by_port["nmap:tcp/6379"].severity == FindingSeverity.LOW  # datastore


def test_unrecognized_service_answering_http_is_classified_http():
    """Juice Shop case: no nmap signature, port-table guess 'ppp', but HTTP replies."""
    _, findings = parse_nmap_xml(ET.fromstring(FIXTURE), "127.0.0.1")
    by_port = {f.source_id: f for f in findings}
    juice = by_port["nmap:tcp/3000"]
    assert juice.title == "Open TCP port 3000 (http)"
    assert juice.confidence == "medium"
    assert "port-table guess: ppp" in juice.evidence
    assert "X-Recruiting" not in juice.evidence  # response content not stored
    # a non-HTTP unrecognized service keeps nmap's guess
    assert by_port["nmap:tcp/5555"].title == "Open TCP port 5555 (freeciv)"
    assert by_port["nmap:tcp/5555"].confidence == "low"


def test_parse_nonzero_exit_raises():
    with pytest.raises(ScannerError, match="exited with code 1"):
        NmapScanner("/x/nmap").parse(proc(exit_code=1, stderr="boom"), make_ctx())


def test_parse_invalid_xml_raises():
    with pytest.raises(ScannerError, match="could not parse"):
        NmapScanner("/x/nmap").parse(proc(stdout="<nmaprun"), make_ctx())


def test_parse_returns_raw_output_and_command():
    out = NmapScanner("/x/nmap").parse(proc(stdout=FIXTURE), make_ctx())
    assert out.raw_output == FIXTURE
    assert out.command == ["/opt/homebrew/bin/nmap"]
    assert len(out.findings) == 7
