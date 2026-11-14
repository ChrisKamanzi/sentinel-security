"""Nuclei scanner: command safety, targets/scope, JSONL parsing, severity mapping,
failure handling. Nuclei is never executed: output is mocked."""

import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.scanners import nuclei as nuclei_mod
from app.scanners.base import ScanContext, ScannerError
from app.scanners.nuclei import (
    NucleiOptions,
    NucleiScanner,
    map_severity,
    normalize_result,
    parse_jsonl,
)
from app.scanners.process import ProcessResult

FIXTURE = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()
NUCLEI = "/opt/homebrew/bin/nuclei"


def make_ctx(previous=None, **overrides):
    defaults = dict(
        scan_id=uuid.uuid4(), target_id=uuid.uuid4(), host="127.0.0.1", ips=["127.0.0.1"],
        base_url="http://127.0.0.1:8000", target_url="http://127.0.0.1:8000",
        options=NucleiOptions(), previous=previous or {},
    )
    defaults.update(overrides)
    return ScanContext(**defaults)


def proc(stdout="", stderr="", exit_code=0, timed_out=False, argv=None):
    return ProcessResult(argv=argv or [NUCLEI], exit_code=exit_code, stdout=stdout,
                         stderr=stderr, timed_out=timed_out, duration_seconds=1.0, truncated=False)


# --- command / scope --------------------------------------------------------------


def test_command_has_conservative_safety_flags():
    argv = NucleiScanner(NUCLEI).build_command(make_ctx())
    assert argv[0] == NUCLEI
    for flag in ("-jsonl", "-omit-raw", "-no-interactsh", "-disable-redirects",
                 "-disable-update-check", "-disable-unsigned-templates", "-silent"):
        assert flag in argv
    assert argv[argv.index("-type") + 1] == "http"
    excluded = argv[argv.index("-exclude-tags") + 1].split(",")
    for tag in ("dos", "fuzz", "intrusive", "bruteforce", "default-login"):
        assert tag in excluded
    assert argv[argv.index("-rate-limit") + 1] == "50"
    assert "-code" not in argv and "-headless" not in argv
    assert "-tags" in argv  # quick profile by default


def test_standard_profile_has_no_tag_filter():
    argv = NucleiScanner(NUCLEI).build_command(make_ctx(options=NucleiOptions(profile="standard")))
    assert "-tags" not in argv


def test_local_network_restricted_when_private_targets_disallowed(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", False)
    assert "-restrict-local-network-access" in NucleiScanner(NUCLEI).build_command(make_ctx())
    monkeypatch.setattr(settings, "allow_private_targets", True)
    assert "-restrict-local-network-access" not in NucleiScanner(NUCLEI).build_command(make_ctx())


def test_targets_come_from_nmap_http_services():
    previous = {"nmap": {"http_services": [
        {"url": "http://127.0.0.1:8000"}, {"url": "https://127.0.0.1"}]}}
    argv = NucleiScanner(NUCLEI).build_command(make_ctx(previous=previous))
    targets = [argv[i + 1] for i, a in enumerate(argv) if a == "-target"]
    assert targets == ["http://127.0.0.1:8000", "https://127.0.0.1"]


def test_targets_fall_back_to_base_url_without_nmap():
    argv = NucleiScanner(NUCLEI).build_command(make_ctx())
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-target"] == ["http://127.0.0.1:8000"]


def test_out_of_scope_url_refused():
    previous = {"nmap": {"http_services": [{"url": "http://evil.example:8000"}]}}
    with pytest.raises(ScannerError, match="out-of-scope"):
        NucleiScanner(NUCLEI).build_command(make_ctx(previous=previous))


@pytest.mark.parametrize("opts", [
    {"rate_limit": 0}, {"rate_limit": 1000}, {"profile": "aggressive"},
    {"severities": ["urgent"]}, {"severities": []}, {"templates": "/tmp/evil.yaml"},
])
def test_invalid_options_rejected(opts):
    with pytest.raises(ValidationError):
        NucleiOptions.model_validate(opts)


# --- JSONL parsing / mapping ---------------------------------------------------------


def test_parse_jsonl_skips_invalid_and_stats_lines():
    results, invalid = parse_jsonl(FIXTURE)
    assert len(results) == 6
    assert invalid == 1


@pytest.mark.parametrize("raw, expected", [
    ("info", FindingSeverity.INFO), ("low", FindingSeverity.LOW),
    ("medium", FindingSeverity.MEDIUM), ("HIGH", FindingSeverity.HIGH),
    ("critical", FindingSeverity.CRITICAL), ("unknown", FindingSeverity.INFO),
    (None, FindingSeverity.INFO), ("", FindingSeverity.INFO),
])
def test_severity_mapping(raw, expected):
    assert map_severity(raw) == expected


def test_normalize_preserves_nuclei_fields():
    results, _ = parse_jsonl(FIXTURE)
    cve = normalize_result(next(r for r in results if r["template-id"] == "CVE-2099-0001"))
    assert cve.title == "Example App - Remote Code Execution (version)"
    assert cve.severity == FindingSeverity.CRITICAL
    assert cve.original_severity == "critical"
    assert cve.source_id == "CVE-2099-0001"
    assert cve.location == "http://127.0.0.1:8000/admin"  # matched URL
    assert cve.cwe == "CWE-78"
    assert cve.recommendation == "Upgrade Example App to 2.0."
    assert "Impact: Full server compromise." in cve.description
    assert cve.references == [
        "https://example.invalid/advisory", "https://example.invalid/patch",
        "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
    ]
    for piece in ("matched-at: http://127.0.0.1:8000/admin", "matcher: version",
                  "extracted: 1.2.3", "cve: cve-2099-0001",
                  "cvss: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"):
        assert piece in cve.evidence


def test_normalize_matchers_become_distinct_findings():
    results, _ = parse_jsonl(FIXTURE)
    headers = [normalize_result(r) for r in results if r["template-id"] == "http-missing-security-headers"]
    assert {h.title for h in headers} == {
        "HTTP Missing Security Headers (x-frame-options)",
        "HTTP Missing Security Headers (content-security-policy)",
    }
    assert len({h.dedup_key for h in headers}) == 2


def test_unknown_severity_kept_as_original():
    results, _ = parse_jsonl(FIXTURE)
    odd = normalize_result(next(r for r in results if r["template-id"] == "odd-severity"))
    assert odd.severity == FindingSeverity.INFO
    assert odd.original_severity == "unknown"


def test_extracted_results_are_capped():
    nf = normalize_result({"template-id": "t", "matched-at": "http://127.0.0.1/",
                           "info": {"name": "n", "severity": "info"},
                           "extracted-results": ["x" * 5000] * 50})
    assert nf.evidence.count("x" * 300) == 10
    assert "x" * 301 not in nf.evidence


def test_parse_drops_out_of_scope_results():
    out = NucleiScanner(NUCLEI).parse(proc(stdout=FIXTURE), make_ctx())
    ids = {f.source_id for f in out.findings}
    assert "offsite-result" not in ids
    assert out.artifacts["out_of_scope_dropped"] == 1
    assert len(out.findings) == 5
    assert out.raw_output == FIXTURE


# --- failures ---------------------------------------------------------------------------


def test_nonzero_exit_raises_with_stderr():
    with pytest.raises(ScannerError, match="exited with code 2.*no templates"):
        NucleiScanner(NUCLEI).parse(proc(exit_code=2, stderr="\x1b[31m[FTL]\x1b[0m no templates"), make_ctx())


def test_timeout_raises(monkeypatch):
    monkeypatch.setattr(nuclei_mod, "run_tool", lambda *a, **k: proc(timed_out=True, exit_code=None))
    with pytest.raises(ScannerError, match="timed out"):
        NucleiScanner(NUCLEI).run(make_ctx())


def test_progress_reported_from_stats(monkeypatch):
    reported = []

    def fake_run_tool(argv, timeout, max_output_bytes, on_line=None, on_tick=None, **kw):
        on_line("stderr", '{"percent":"40","requests":"10","total":"25"}')
        on_tick()
        on_line("stderr", "[INF] not json")  # ignored
        on_line("stdout", FIXTURE.splitlines()[0])  # a finding, not stats
        on_tick()
        return proc(stdout=FIXTURE, argv=argv)

    monkeypatch.setattr(nuclei_mod, "run_tool", fake_run_tool)
    out = NucleiScanner(NUCLEI).run(make_ctx(report_progress=reported.append))
    assert reported == [44, 44]  # 10 + 40% of 85
    assert out.artifacts["last_stats"]["percent"] == "40"
    assert out.artifacts["targets"] == ["http://127.0.0.1:8000"]


def test_nuclei_registered_in_pipeline_after_nmap():
    from app.scanners.registry import PIPELINE_ORDER, SCANNERS
    assert SCANNERS["nuclei"] is NucleiScanner
    assert PIPELINE_ORDER.index("nmap") < PIPELINE_ORDER.index("nuclei")
