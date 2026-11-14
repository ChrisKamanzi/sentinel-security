"""Nmap -> Nuclei pipeline through the real API, orchestrator and scanner classes.

Only the subprocess layer is mocked: recorded Nmap XML and Nuclei JSONL are
returned instead of running the tools.
"""

from pathlib import Path

import pytest

from app.core.config import settings
from app.scanners import base as base_mod
from app.scanners import nuclei as nuclei_mod
from app.scanners.nmap import NmapScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.process import ProcessResult

API = "/api/v1"
FIX = Path(__file__).parent / "fixtures"
NMAP_XML = (FIX / "nmap_sample.xml").read_text()
NUCLEI_JSONL = (FIX / "nuclei_sample.jsonl").read_text()


def _result(argv, stdout="", exit_code=0, timed_out=False, stderr=""):
    return ProcessResult(argv=argv, exit_code=exit_code, stdout=stdout, stderr=stderr,
                         timed_out=timed_out, duration_seconds=0.1, truncated=False)


@pytest.fixture
def tools(monkeypatch):
    """Mock both tools; record every argv that would have been executed."""
    calls = {"nmap": [], "nuclei": []}
    state = {"nuclei": lambda argv: _result(argv, NUCLEI_JSONL)}

    def fake_nmap_run_tool(argv, timeout, max_output_bytes, **kw):
        calls["nmap"].append(argv)
        return _result(argv, NMAP_XML)

    def fake_nuclei_run_tool(argv, timeout, max_output_bytes, **kw):
        calls["nuclei"].append(argv)
        return state["nuclei"](argv)

    monkeypatch.setattr(settings, "allow_private_targets", True)
    monkeypatch.setattr(NmapScanner, "locate", classmethod(lambda cls: "/opt/homebrew/bin/nmap"))
    monkeypatch.setattr(NucleiScanner, "locate", classmethod(lambda cls: "/opt/homebrew/bin/nuclei"))
    monkeypatch.setattr(base_mod, "run_tool", fake_nmap_run_tool)
    monkeypatch.setattr(nuclei_mod, "run_tool", fake_nuclei_run_tool)
    return calls, state


@pytest.fixture
def scan(client, make_project):
    project = make_project()
    target = client.post(f"{API}/projects/{project['id']}/targets", json={
        "name": "AutoPentest API", "host": "127.0.0.1",
        "base_url": "http://127.0.0.1:8000", "is_authorized": True}).json()
    s = client.post(f"{API}/projects/{project['id']}/scans", json={"target_id": target["id"]}).json()
    return target, s


def start(client, scan_id):
    return client.post(f"{API}/scans/{scan_id}/start", json={
        "scanners": ["nmap", "nuclei"],
        "options": {"nmap": {"ports": "8000"}, "nuclei": {"profile": "quick"}},
    })


def test_nmap_feeds_nuclei_and_findings_are_persisted(client, scan, tools):
    calls, _ = tools
    _, s = scan
    assert start(client, s["id"]).status_code == 202

    a = client.get(f"{API}/scans/{s['id']}/assessment").json()
    assert a["status"] == "completed", a
    assert [(r["scanner"], r["status"]) for r in a["runs"]] == [("nmap", "completed"), ("nuclei", "completed")]

    # Nmap was limited to the requested port; Nuclei got Nmap's HTTP services
    nmap_argv = calls["nmap"][0]
    assert nmap_argv[nmap_argv.index("-p") + 1] == "8000"
    nuclei_argv = calls["nuclei"][0]
    targets = [nuclei_argv[i + 1] for i, x in enumerate(nuclei_argv) if x == "-target"]
    assert targets == ["https://127.0.0.1", "http://127.0.0.1:3000", "http://127.0.0.1:8000"]

    nuclei_run = a["runs"][1]
    assert nuclei_run["findings_count"] == 5  # off-scope result dropped
    assert nuclei_run["artifacts"]["out_of_scope_dropped"] == 1
    assert a["findings_by_scanner"] == {"nmap": 7, "nuclei": 5}
    assert a["findings_by_severity"]["critical"] == 1

    findings = client.get(f"{API}/scans/{s['id']}/findings", params={"scanner": "nuclei"}).json()
    cve = next(f for f in findings if f["source_id"] == "CVE-2099-0001")
    assert cve["severity"] == "critical"
    assert cve["original_severity"] == "critical"
    assert cve["location"] == "http://127.0.0.1:8000/admin"
    assert cve["scanner"] == "nuclei" and cve["detected_by"] == ["nuclei"]
    assert cve["cwe"] == "CWE-78"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" in cve["references"]
    assert "extracted: 1.2.3" in cve["evidence"]
    assert cve["scanner_run_id"] == nuclei_run["id"]
    assert not any(f["source_id"] == "offsite-result" for f in findings)

    raw = client.get(f"{API}/scanner-runs/{nuclei_run['id']}/raw").text
    assert raw == NUCLEI_JSONL


def test_rerun_does_not_duplicate_findings(client, scan, tools):
    _, s = scan
    start(client, s["id"])
    first = client.get(f"{API}/scans/{s['id']}/findings").json()
    start(client, s["id"])
    second = client.get(f"{API}/scans/{s['id']}/findings").json()
    assert len(first) == len(second) == 12
    assert sorted(f["id"] for f in first) == sorted(f["id"] for f in second)


def test_nuclei_failure_recorded_and_nmap_results_kept(client, scan, tools):
    calls, state = tools
    state["nuclei"] = lambda argv: _result(argv, exit_code=1, stderr="[FTL] Could not load templates")
    _, s = scan
    start(client, s["id"])
    a = client.get(f"{API}/scans/{s['id']}/assessment").json()
    assert a["status"] == "partial"
    run = a["runs"][1]
    assert run["status"] == "failed"
    assert "Could not load templates" in run["error_message"]
    assert run["exit_code"] == 1
    assert run["command"][0] == "/opt/homebrew/bin/nuclei"
    assert a["findings_by_scanner"] == {"nmap": 7}


def test_nuclei_timeout_recorded(client, scan, tools):
    _, state = tools
    state["nuclei"] = lambda argv: _result(argv, timed_out=True, exit_code=None)
    _, s = scan
    start(client, s["id"])
    run = client.get(f"{API}/scans/{s['id']}/assessment").json()["runs"][1]
    assert run["status"] == "failed"
    assert "timed out" in run["error_message"]
    assert run["duration_seconds"] is not None


def test_unauthorized_target_rejected_and_nothing_executed(client, scan, tools):
    calls, _ = tools
    target, s = scan
    client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
    resp = start(client, s["id"])
    assert resp.status_code == 403
    assert calls == {"nmap": [], "nuclei": []}


def test_authorization_revoked_after_nmap_blocks_nuclei(client, scan, tools, monkeypatch):
    calls, _ = tools
    target, s = scan
    original = base_mod.run_tool

    def nmap_then_revoke(argv, timeout, max_output_bytes, **kw):
        result = original(argv, timeout, max_output_bytes, **kw)
        client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
        return result

    monkeypatch.setattr(base_mod, "run_tool", nmap_then_revoke)
    start(client, s["id"])
    a = client.get(f"{API}/scans/{s['id']}/assessment").json()
    assert [r["status"] for r in a["runs"]] == ["completed", "failed"]
    assert "Scope check failed" in a["runs"][1]["error_message"]
    assert calls["nuclei"] == []  # nuclei never executed


def test_invalid_nuclei_options_rejected(client, scan, tools):
    _, s = scan
    resp = client.post(f"{API}/scans/{s['id']}/start", json={
        "scanners": ["nuclei"], "options": {"nuclei": {"rate_limit": 9999}}})
    assert resp.status_code == 422
