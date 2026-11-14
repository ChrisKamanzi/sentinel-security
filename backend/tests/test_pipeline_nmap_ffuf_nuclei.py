"""Nmap -> FFUF -> Nuclei through the real API, orchestrator, scope checks and
scanner classes. Only the subprocess layer is mocked (recorded tool output).
"""

import ipaddress
from pathlib import Path

import pytest

from app.core import scope as scope_mod
from app.core.config import settings
from app.scanners import base as base_mod
from app.scanners import ffuf as ffuf_mod
from app.scanners import nuclei as nuclei_mod
from app.scanners.ffuf import FfufScanner
from app.scanners.nmap import NmapScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.process import ProcessResult

API = "/api/v1"
FIX = Path(__file__).parent / "fixtures"
NMAP_XML = (FIX / "nmap_sample.xml").read_text()
NUCLEI_JSONL = (FIX / "nuclei_sample.jsonl").read_text()
FFUF_JSONL = (FIX / "ffuf_sample.jsonl").read_text()


def _result(argv, stdout="", exit_code=0, timed_out=False, stderr=""):
    return ProcessResult(argv=argv, exit_code=exit_code, stdout=stdout, stderr=stderr,
                         timed_out=timed_out, duration_seconds=0.1, truncated=False)


def _ffuf_output_for(argv):
    """The recorded FFUF output, re-addressed to whatever URL FFUF was pointed at."""
    base = argv[argv.index("-u") + 1].removesuffix("/FUZZ")
    return FFUF_JSONL.replace("http://127.0.0.1:8000", base)


@pytest.fixture
def tools(monkeypatch):
    calls = {"nmap": [], "ffuf": [], "nuclei": []}
    order = []
    state = {
        "ffuf": lambda argv: _result(argv, _ffuf_output_for(argv)),
        "nuclei": lambda argv: _result(argv, NUCLEI_JSONL),
    }

    def fake_nmap(argv, timeout, max_output_bytes, **kw):
        calls["nmap"].append(argv)
        order.append("nmap")
        return _result(argv, NMAP_XML)

    def fake_ffuf(argv, timeout, max_output_bytes, **kw):
        calls["ffuf"].append({"argv": argv, "env": kw.get("env_overrides")})
        order.append("ffuf")
        return state["ffuf"](argv)

    def fake_nuclei(argv, timeout, max_output_bytes, **kw):
        calls["nuclei"].append(argv)
        order.append("nuclei")
        return state["nuclei"](argv)

    monkeypatch.setattr(settings, "allow_private_targets", True)
    for cls, path in ((NmapScanner, "nmap"), (FfufScanner, "ffuf"), (NucleiScanner, "nuclei")):
        monkeypatch.setattr(cls, "locate", classmethod(lambda c, p=path: f"/opt/homebrew/bin/{p}"))
    monkeypatch.setattr(base_mod, "run_tool", fake_nmap)
    monkeypatch.setattr(ffuf_mod, "run_tool", fake_ffuf)
    monkeypatch.setattr(nuclei_mod, "run_tool", fake_nuclei)
    return calls, state, order


def _make_scan(client, make_project, host="127.0.0.1", base_url="http://127.0.0.1:8000"):
    project = make_project()
    target = client.post(f"{API}/projects/{project['id']}/targets", json={
        "name": "Lab app", "host": host, "base_url": base_url, "is_authorized": True}).json()
    s = client.post(f"{API}/projects/{project['id']}/scans", json={"target_id": target["id"]}).json()
    return target, s


@pytest.fixture
def scan(client, make_project):
    return _make_scan(client, make_project)


def start(client, scan_id, scanners=("nmap", "ffuf", "nuclei")):
    options = {"nmap": {"ports": "443,3000,8000"}, "ffuf": {"rate_limit": 10},
               "nuclei": {"profile": "quick"}}
    return client.post(f"{API}/scans/{scan_id}/start", json={
        "scanners": list(scanners), "options": {k: v for k, v in options.items() if k in scanners}})


def _assessment(client, scan_id):
    return client.get(f"{API}/scans/{scan_id}/assessment").json()


def _findings(client, scan_id):
    return client.get(f"{API}/scans/{scan_id}/findings").json()


# --- happy path ----------------------------------------------------------------------------


def test_full_pipeline_runs_in_order_and_persists_ffuf_findings(client, scan, tools):
    calls, _, order = tools
    _, s = scan
    resp = start(client, s["id"], scanners=("nuclei", "ffuf", "nmap"))  # any order accepted
    assert resp.status_code == 202, resp.text

    a = _assessment(client, s["id"])
    assert a["status"] == "completed"
    assert [r["scanner"] for r in a["runs"]] == ["nmap", "ffuf", "nuclei"]
    assert order[0] == "nmap" and order[-1] == "nuclei" and set(order[1:-1]) == {"ffuf"}

    # FFUF ran once per HTTP service Nmap found, each pinned to the validated IP
    urls = [c["argv"][c["argv"].index("-u") + 1] for c in calls["ffuf"]]
    assert urls == ["https://127.0.0.1/FUZZ", "http://127.0.0.1:3000/FUZZ", "http://127.0.0.1:8000/FUZZ"]
    assert all(set(c["env"]) == {"HOME", "XDG_CONFIG_HOME"} for c in calls["ffuf"])

    ffuf_run = next(r for r in a["runs"] if r["scanner"] == "ffuf")
    assert ffuf_run["status"] == "completed"
    assert ffuf_run["artifacts"]["discovered_total"] == 21  # 7 paths x 3 services
    assert ffuf_run["artifacts"]["out_of_scope_dropped"] == 3
    assert len(ffuf_run["artifacts"]["commands"]) == 3

    ffuf_findings = [f for f in _findings(client, s["id"]) if f["scanner"] == "ffuf"]
    assert len(ffuf_findings) == 21
    assert {f["severity"] for f in ffuf_findings} == {"info", "low"}
    assert a["findings_by_scanner"]["ffuf"] == 21


def test_nuclei_behaviour_unchanged_by_ffuf(client, scan, tools):
    calls, _, _ = tools
    _, s = scan
    start(client, s["id"])
    nuclei_targets = [a for i, a in enumerate(calls["nuclei"][0]) if calls["nuclei"][0][i - 1] == "-target"]
    # Nuclei still gets exactly Nmap's HTTP services -- FFUF discoveries are not fed in
    assert nuclei_targets == ["https://127.0.0.1", "http://127.0.0.1:3000", "http://127.0.0.1:8000"]


def test_rerun_does_not_duplicate_ffuf_findings(client, scan, tools):
    _, s = scan
    start(client, s["id"])
    first = len(_findings(client, s["id"]))
    start(client, s["id"])
    assert len(_findings(client, s["id"])) == first


# --- failures and scope ----------------------------------------------------------------------


def test_ffuf_failure_recorded_and_other_scanners_kept(client, scan, tools):
    _, state, _ = tools
    _, s = scan
    state["ffuf"] = lambda argv: _result(argv, stderr="Encountered error(s): 1 errors occurred.", exit_code=1)
    start(client, s["id"])
    a = _assessment(client, s["id"])
    assert a["status"] == "partial"
    assert [r["status"] for r in a["runs"]] == ["completed", "failed", "completed"]
    assert "ffuf exited with code 1" in a["runs"][1]["error_message"]
    assert a["findings_by_scanner"].get("nmap") and a["findings_by_scanner"].get("nuclei")
    assert "ffuf" not in a["findings_by_scanner"]


def test_authorization_revoked_after_nmap_blocks_ffuf_and_nuclei(client, scan, tools, monkeypatch):
    calls, _, _ = tools
    target, s = scan
    original = base_mod.run_tool

    def nmap_then_revoke(argv, timeout, max_output_bytes, **kw):
        result = original(argv, timeout, max_output_bytes, **kw)
        client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
        return result

    monkeypatch.setattr(base_mod, "run_tool", nmap_then_revoke)
    start(client, s["id"])
    a = _assessment(client, s["id"])
    assert [r["status"] for r in a["runs"]] == ["completed", "failed", "skipped"]
    assert "Scope check failed" in a["runs"][1]["error_message"]
    assert calls["ffuf"] == [] and calls["nuclei"] == []


def test_hostname_target_is_pinned_to_validated_ip(client, make_project, tools, monkeypatch):
    calls, _, _ = tools
    monkeypatch.setattr(scope_mod, "resolve_host", lambda host: [ipaddress.ip_address("127.0.0.10")])
    _, s = _make_scan(client, make_project, host="app.test", base_url="http://app.test:8000")
    start(client, s["id"], scanners=("ffuf",))
    a = _assessment(client, s["id"])
    assert a["status"] == "completed", a
    argv = calls["ffuf"][0]["argv"]
    assert argv[argv.index("-u") + 1] == "http://127.0.0.10:8000/FUZZ"
    assert "Host: app.test:8000" in argv
    locations = {f["location"] for f in _findings(client, s["id"])}
    assert locations and all(loc.startswith("http://app.test:8000/") for loc in locations)


def test_dns_rebinding_after_scope_check_fails_closed(client, make_project, tools, monkeypatch):
    """DNS flips after the orchestrator's check but before FFUF runs: FFUF's own
    immediate re-check catches it, nothing is executed, later scanners skip."""
    calls, _, _ = tools
    dns = {"ip": "127.0.0.10", "locate_calls": 0}
    monkeypatch.setattr(scope_mod, "resolve_host", lambda host: [ipaddress.ip_address(dns["ip"])])

    def locate_then_rebind(cls):
        # 1st call: the API's pre-flight install check. 2nd call: the orchestrator,
        # right after its own scope check approved 127.0.0.10 -- rebind there.
        dns["locate_calls"] += 1
        if dns["locate_calls"] == 2:
            dns["ip"] = "127.0.0.99"
        return "/opt/homebrew/bin/ffuf"

    monkeypatch.setattr(FfufScanner, "locate", classmethod(locate_then_rebind))
    _, s = _make_scan(client, make_project, host="app.test", base_url="http://app.test:8000")
    start(client, s["id"], scanners=("ffuf", "nuclei"))
    a = _assessment(client, s["id"])
    assert [r["status"] for r in a["runs"]] == ["failed", "skipped"]
    assert "no longer resolves" in a["runs"][0]["error_message"]
    assert calls["ffuf"] == [] and calls["nuclei"] == []


def test_invalid_ffuf_options_rejected_before_anything_runs(client, scan, tools):
    calls, _, _ = tools
    _, s = scan
    for bad in ({"wordlist": "/etc/passwd"}, {"rate_limit": 9999}, {"extensions": ["bak"]}):
        resp = client.post(f"{API}/scans/{s['id']}/start", json={"scanners": ["ffuf"], "options": {"ffuf": bad}})
        assert resp.status_code == 422, bad
    assert calls["ffuf"] == []


def test_ffuf_methodology_reaches_ai_analyst_payload(client, scan, tools, db_session):
    import uuid
    from app.models.scan import Scan
    from app.services.ai_analyst import build_scan_data
    _, s = scan
    start(client, s["id"])
    payload, _, _ = build_scan_data(db_session, db_session.get(Scan, uuid.UUID(s["id"])))
    notes = " ".join(payload["assessment"]["methodology_notes"])
    assert "FFUF performed wordlist-based content discovery" in notes
    assert "no fuzzing" not in notes
