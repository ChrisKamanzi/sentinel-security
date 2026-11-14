"""OWASP ZAP baseline scanner: passive-only command, container hardening and
cleanup, scope re-check + DNS pinning, and JSON report normalization.

Docker is mocked: no container is ever started here.
"""

import json
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.core.scope import ScopeError
from app.models.finding import FindingSeverity
from app.scanners import zap as zap_mod
from app.scanners.base import ScanContext, ScannerError
from app.scanners.process import ProcessResult
from app.scanners.zap import ZapOptions, ZapScanner, html_to_text, parse_report

FIXTURE_TEXT = (Path(__file__).parent / "fixtures" / "zap_baseline_sample.json").read_text()
FIXTURE = json.loads(FIXTURE_TEXT)
DOCKER = "/opt/homebrew/bin/docker"
ORIGIN = "http://127.0.0.1:8000"


def make_ctx(previous=None, **overrides):
    defaults = dict(
        scan_id=uuid.uuid4(), target_id=uuid.uuid4(), host="127.0.0.1", ips=["127.0.0.1"],
        base_url=ORIGIN, target_url=ORIGIN, options=ZapOptions(), previous=previous or {},
        revalidate=lambda: SimpleNamespace(host="127.0.0.1", ips=["127.0.0.1"]),
    )
    defaults.update(overrides)
    return ScanContext(**defaults)


def _proc(argv, exit_code=0, stdout="", stderr="", timed_out=False):
    return ProcessResult(argv=argv, exit_code=exit_code, stdout=stdout, stderr=stderr,
                         timed_out=timed_out, duration_seconds=1.0, truncated=False)


def flag_value(argv, flag):
    return argv[argv.index(flag) + 1]


@pytest.fixture
def docker(monkeypatch):
    """Mock docker run/cp (run_tool) and rm/volume rm (_docker)."""
    calls = {"run": [], "cp": [], "cleanup": []}
    state = {"run_exit": 2, "run_timed_out": False, "report": FIXTURE_TEXT, "cp_ok": True}

    def fake_run_tool(argv, timeout, max_output_bytes, **kw):
        if argv[1] == "run":
            calls["run"].append(argv)
            return _proc(argv, exit_code=None if state["run_timed_out"] else state["run_exit"],
                         stderr="zap error", timed_out=state["run_timed_out"])
        if argv[1] == "cp":
            calls["cp"].append(argv)
            if state["cp_ok"]:
                Path(argv[-1]).write_text(state["report"])
                return _proc(argv)
            return _proc(argv, exit_code=1, stderr="No such container:path")
        raise AssertionError(f"unexpected docker command {argv}")

    def fake_docker(argv, timeout=30):
        calls["cleanup"].append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(zap_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(zap_mod, "_docker", fake_docker)
    return calls, state


# --- command: passive only, hardened container ---------------------------------------------------


def test_command_is_passive_baseline_in_hardened_container():
    argv = ZapScanner(DOCKER).build_command(make_ctx(), container="c1", volume="v1")
    assert argv[:2] == [DOCKER, "run"]
    for flag in ("--pull=never", "-I", "-s"):
        assert flag in argv
    assert flag_value(argv, "--cap-drop") == "ALL"
    assert flag_value(argv, "--security-opt") == "no-new-privileges"
    assert flag_value(argv, "--memory") == settings.zap_memory
    assert flag_value(argv, "--pids-limit") == "1024"
    assert flag_value(argv, "-v") == "v1:/zap/wrk:rw"  # named volume only, no host bind mount
    assert flag_value(argv, "--name") == "c1"
    assert argv[argv.index(settings.zap_docker_image) + 1] == "zap-baseline.py"
    assert flag_value(argv, "-t") == ORIGIN
    assert (flag_value(argv, "-m"), flag_value(argv, "-T"), flag_value(argv, "-J")) == ("1", "5", "zap-report.json")
    z = flag_value(argv, "-z")
    assert "spider.postForm=false" in z and "spider.processForm=false" in z


@pytest.mark.parametrize("forbidden", [
    "zap-full-scan.py", "zap-api-scan.py", "--privileged", "-j", "-a", "-c", "-u", "-P",
    "--network=host", "host", "--rm",
])
def test_command_never_contains_active_or_risky_options(forbidden):
    assert forbidden not in ZapScanner(DOCKER).build_command(make_ctx())


def test_default_network_unless_configured(monkeypatch):
    assert "--network" not in ZapScanner(DOCKER).build_command(make_ctx())
    monkeypatch.setattr(settings, "zap_docker_network", "container:juice-shop")
    assert flag_value(ZapScanner(DOCKER).build_command(make_ctx()), "--network") == "container:juice-shop"


def test_options_drive_spider_and_wait_minutes():
    argv = ZapScanner(DOCKER).build_command(make_ctx(options=ZapOptions(spider_minutes=3, passive_wait_minutes=2)))
    assert (flag_value(argv, "-m"), flag_value(argv, "-T")) == ("3", "2")


@pytest.mark.parametrize("opts", [
    {"spider_minutes": 0}, {"spider_minutes": 6}, {"passive_wait_minutes": 11},
    {"active_scan": True}, {"ajax_spider": True}, {"image": "evil/zap"}, {"network": "host"},
    {"config": "-config scanner.attackOnStart=true"},
])
def test_invalid_options_rejected(opts):
    with pytest.raises(ValidationError):
        ZapOptions.model_validate(opts)


def test_timeout_is_bounded(monkeypatch):
    monkeypatch.setattr(settings, "zap_timeout_seconds", 300)
    assert ZapScanner(DOCKER).timeout_seconds(make_ctx(options=ZapOptions(spider_minutes=5, passive_wait_minutes=10))) == 300
    assert ZapScanner(DOCKER).timeout_seconds(make_ctx()) == 300  # (1+5)*60+180 = 540 > 300
    monkeypatch.setattr(settings, "zap_timeout_seconds", 900)
    assert ZapScanner(DOCKER).timeout_seconds(make_ctx()) == 540


# --- scope, DNS pinning, revalidation ------------------------------------------------------------


def test_ip_literal_target_needs_no_add_host():
    assert "--add-host" not in ZapScanner(DOCKER).build_command(make_ctx(), pinned_ip="127.0.0.1")


def test_hostname_target_is_pinned_with_add_host():
    ctx = make_ctx(host="app.example", ips=["203.0.113.10"], base_url="http://app.example:8000",
                   target_url="http://app.example:8000")
    argv = ZapScanner(DOCKER).build_command(ctx, "http://app.example:8000", "203.0.113.10")
    assert flag_value(argv, "--add-host") == "app.example:203.0.113.10"
    assert flag_value(argv, "-t") == "http://app.example:8000"


def test_hostname_target_fails_closed_on_shared_container_network(monkeypatch, docker):
    calls, _ = docker
    monkeypatch.setattr(settings, "zap_docker_network", "container:juice-shop")
    ctx = make_ctx(host="app.example", ips=["203.0.113.10"], base_url="http://app.example:8000",
                   target_url="http://app.example:8000",
                   revalidate=lambda: SimpleNamespace(host="app.example", ips=["203.0.113.10"]))
    with pytest.raises(ScopeError, match="cannot pin"):
        ZapScanner(DOCKER).run(ctx)
    assert calls["run"] == []


def test_targets_from_nmap_and_out_of_scope_refused():
    previous = {"nmap": {"http_services": [{"url": "http://127.0.0.1:3000"}]}}
    assert ZapScanner(DOCKER).targets(make_ctx(previous=previous)) == ["http://127.0.0.1:3000"]
    with pytest.raises(ScannerError, match="out-of-scope"):
        ZapScanner(DOCKER).targets(make_ctx(previous={"nmap": {"http_services": [{"url": "http://evil.example"}]}}))


def test_scope_revalidated_before_each_execution(docker):
    calls, _ = docker
    events = []
    previous = {"nmap": {"http_services": [{"url": ORIGIN}, {"url": "http://127.0.0.1:3000"}]}}

    def revalidate():
        events.append(len(calls["run"]))
        return SimpleNamespace(host="127.0.0.1", ips=["127.0.0.1"])

    ZapScanner(DOCKER).run(make_ctx(previous=previous, revalidate=revalidate))
    assert events == [0, 1] and len(calls["run"]) == 2


def test_revoked_authorization_prevents_container_start(docker):
    calls, _ = docker

    def revalidate():
        raise ScopeError("target is not authorized for scanning")

    with pytest.raises(ScopeError):
        ZapScanner(DOCKER).run(make_ctx(revalidate=revalidate))
    assert calls["run"] == [] and calls["cleanup"] == []


def test_dns_change_fails_closed_without_container(docker):
    calls, _ = docker
    ctx = make_ctx(host="app.example", ips=["203.0.113.10"], base_url="http://app.example:8000",
                   target_url="http://app.example:8000",
                   revalidate=lambda: SimpleNamespace(host="app.example", ips=["198.51.100.7"]))
    with pytest.raises(ScopeError, match="no longer resolves"):
        ZapScanner(DOCKER).run(ctx)
    assert calls["run"] == []


# --- execution, exit codes, cleanup ----------------------------------------------------------------


@pytest.mark.parametrize("code", [0, 1, 2])
def test_baseline_pass_warn_fail_codes_are_success(docker, code):
    _, state = docker
    state["run_exit"] = code
    assert len(ZapScanner(DOCKER).run(make_ctx()).findings) == 4


@pytest.mark.parametrize("code", [3, 125])
def test_error_exit_codes_raise_and_still_clean_up(docker, code):
    calls, state = docker
    state["run_exit"] = code
    with pytest.raises(ScannerError, match=f"exited with code {code}"):
        ZapScanner(DOCKER).run(make_ctx())
    assert len(calls["cleanup"]) == 2


def test_timeout_removes_the_container(docker):
    calls, state = docker
    state["run_timed_out"] = True
    with pytest.raises(ScannerError, match="timed out"):
        ZapScanner(DOCKER).run(make_ctx())
    name = flag_value(calls["run"][0], "--name")
    assert [DOCKER, "rm", "-f", name] in calls["cleanup"]
    assert [DOCKER, "volume", "rm", "-f", name] in calls["cleanup"]


def test_missing_report_raises_and_cleans_up(docker):
    calls, state = docker
    state["cp_ok"] = False
    with pytest.raises(ScannerError, match="could not retrieve"):
        ZapScanner(DOCKER).run(make_ctx())
    assert len(calls["cleanup"]) == 2


def test_successful_run_copies_report_and_cleans_up(docker):
    calls, _ = docker
    out = ZapScanner(DOCKER).run(make_ctx())
    name = flag_value(calls["run"][0], "--name")
    assert name.startswith("autopentest-zap-")
    assert calls["cp"][0][2] == f"{name}:/zap/wrk/zap-report.json"
    assert calls["cleanup"] == [[DOCKER, "rm", "-f", name], [DOCKER, "volume", "rm", "-f", name]]
    t = out.artifacts["targets"][0]
    assert t["cleanup_ok"] is True and t["exit_code"] == 2 and t["pinned_ip"] == "127.0.0.1"
    assert out.artifacts["zap_version"] == "2.16.1"
    assert "passive" in out.artifacts["mode"]


def test_invalid_json_report_raises(docker):
    _, state = docker
    state["report"] = "<html>not json</html>"
    with pytest.raises(ScannerError, match="could not parse"):
        ZapScanner(DOCKER).run(make_ctx())


# --- normalization -------------------------------------------------------------------------------


def _findings():
    findings, stats = parse_report(FIXTURE, "127.0.0.1", ORIGIN)
    return {f.source_id: f for f in findings}, stats


def test_zap_risk_and_confidence_kept():
    f, _ = _findings()
    assert set(f) == {"zap:10038", "zap:10098", "zap:10054", "zap:10096"}
    assert (f["zap:10038"].severity, f["zap:10038"].confidence) == (FindingSeverity.MEDIUM, "high")
    assert (f["zap:10098"].severity, f["zap:10098"].confidence) == (FindingSeverity.MEDIUM, "medium")
    assert (f["zap:10054"].severity, f["zap:10054"].confidence) == (FindingSeverity.LOW, "medium")
    assert (f["zap:10096"].severity, f["zap:10096"].confidence) == (FindingSeverity.INFO, "low")
    assert f["zap:10038"].original_severity == "Medium (High)"


def test_false_positives_and_off_host_data_discarded():
    f, stats = _findings()
    assert "zap:10027" not in f  # ZAP confidence 0 = false positive
    assert "zap:10020" not in f  # only off-host instances
    assert stats["false_positives_discarded"] == 1
    assert stats["out_of_scope_sites"] == 1
    assert stats["out_of_scope_instances"] == 2
    assert all("evil.example" not in (x.evidence + (x.location or "")) for x in f.values())


def test_fields_mapped_without_invented_scores():
    f, _ = _findings()
    csp = f["zap:10038"]
    assert csp.title == "Content Security Policy (CSP) Header Not Set"
    assert csp.location == ORIGIN
    assert csp.dedup_key == "zap:10038:10038-1"
    assert csp.cwe == "CWE-693"
    assert f["zap:10096"].cwe is None  # cweid -1
    assert csp.description == "Content Security Policy (CSP) is an added layer of security & helps detect attacks."
    assert csp.recommendation == "Ensure that your web server sets the Content-Security-Policy header."
    assert csp.references == ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                              "https://owasp.org/www-project-cheat-sheets/"]
    for x in f.values():
        assert "cvss" not in (x.evidence + (x.description or "")).lower()


def test_instances_capped_and_evidence_redacted():
    f, _ = _findings()
    csp = f["zap:10038"]
    assert "instances: 14 (showing 10)" in csp.evidence
    assert csp.evidence.count("\n- GET ") == 10
    cookie = f["zap:10054"].evidence
    assert "eyJhbGciOiJIUzI1NiJ9" not in cookie and "[REDACTED]" in cookie
    assert "param: token" in cookie


def test_raw_output_redacted(docker):
    out = ZapScanner(DOCKER).run(make_ctx())
    assert "eyJhbGciOiJIUzI1NiJ9" not in out.raw_output
    assert out.artifacts["findings_by_risk"] == {"medium": 2, "low": 1, "info": 1}


def test_html_to_text():
    assert html_to_text("<p>a &amp; b</p><p>c</p>") == "a & b\n\nc"
    assert html_to_text("") is None


# --- discovery ---------------------------------------------------------------------------------------


def test_locate_requires_docker_and_the_image(monkeypatch):
    monkeypatch.setattr(zap_mod, "_docker_path", lambda: None)
    assert ZapScanner.locate() is None
    monkeypatch.setattr(zap_mod, "_docker_path", lambda: DOCKER)
    monkeypatch.setattr(zap_mod, "_docker", lambda argv, timeout=30: subprocess.CompletedProcess(argv, 1, "", "No such image"))
    assert ZapScanner.locate() is None
    monkeypatch.setattr(zap_mod, "_docker", lambda argv, timeout=30: subprocess.CompletedProcess(argv, 0, "sha256:abc\n", ""))
    assert ZapScanner.locate() == DOCKER


def test_version_from_image_label(monkeypatch):
    monkeypatch.setattr(zap_mod, "_docker", lambda argv, timeout=30: subprocess.CompletedProcess(argv, 0, "2.16.1|sha256:0123456789abcdef\n", ""))
    assert ZapScanner.version(DOCKER) == "2.16.1"
    monkeypatch.setattr(zap_mod, "_docker", lambda argv, timeout=30: subprocess.CompletedProcess(argv, 0, "<no value>|sha256:0123456789abcdef\n", ""))
    assert ZapScanner.version(DOCKER) == "0123456789ab"


def test_zap_registered_last_in_pipeline():
    from app.scanners.registry import PIPELINE_ORDER, SCANNERS
    assert SCANNERS["zap"] is ZapScanner
    assert PIPELINE_ORDER[-1] == "zap"


# --- full pipeline through the real API --------------------------------------------------------


def test_full_pipeline_nmap_ffuf_nuclei_zap(client, make_project, monkeypatch):
    from app.scanners import base as base_mod, ffuf as ffuf_mod, nuclei as nuclei_mod
    from app.scanners.ffuf import FfufScanner
    from app.scanners.nmap import NmapScanner
    from app.scanners.nuclei import NucleiScanner

    fix = Path(__file__).parent / "fixtures"
    nmap_xml, nuclei_jsonl, ffuf_jsonl = ((fix / n).read_text() for n in
                                          ("nmap_sample.xml", "nuclei_sample.jsonl", "ffuf_sample.jsonl"))
    order, zap_targets = [], []

    def tool(name, stdout_for):
        def fake(argv, timeout, max_output_bytes, **kw):
            order.append(name)
            return _proc(argv, stdout=stdout_for(argv))
        return fake

    def fake_zap_run_tool(argv, timeout, max_output_bytes, **kw):
        if argv[1] == "run":
            order.append("zap")
            zap_targets.append(flag_value(argv, "-t"))
            return _proc(argv, exit_code=2)
        base = zap_targets[-1]
        Path(argv[-1]).write_text(FIXTURE_TEXT.replace(ORIGIN, base))
        return _proc(argv)

    monkeypatch.setattr(settings, "allow_private_targets", True)
    for cls in (NmapScanner, FfufScanner, NucleiScanner, ZapScanner):
        monkeypatch.setattr(cls, "locate", classmethod(lambda c: DOCKER))
    monkeypatch.setattr(base_mod, "run_tool", tool("nmap", lambda a: nmap_xml))
    monkeypatch.setattr(ffuf_mod, "run_tool", tool("ffuf", lambda a: ffuf_jsonl.replace(
        ORIGIN, a[a.index("-u") + 1].removesuffix("/FUZZ"))))
    monkeypatch.setattr(nuclei_mod, "run_tool", tool("nuclei", lambda a: nuclei_jsonl))
    monkeypatch.setattr(zap_mod, "run_tool", fake_zap_run_tool)
    monkeypatch.setattr(zap_mod, "_docker", lambda argv, timeout=30: subprocess.CompletedProcess(argv, 0, "", ""))

    project = make_project()
    target = client.post(f"/api/v1/projects/{project['id']}/targets", json={
        "name": "Lab", "host": "127.0.0.1", "base_url": ORIGIN, "is_authorized": True}).json()
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", json={"target_id": target["id"]}).json()
    resp = client.post(f"/api/v1/scans/{scan['id']}/start", json={
        "scanners": ["zap", "nuclei", "ffuf", "nmap"],
        "options": {"nmap": {"ports": "443,3000,8000"}, "zap": {"spider_minutes": 1}}})
    assert resp.status_code == 202, resp.text

    a = client.get(f"/api/v1/scans/{scan['id']}/assessment").json()
    assert a["status"] == "completed", a
    assert [r["scanner"] for r in a["runs"]] == ["nmap", "ffuf", "nuclei", "zap"]
    assert order.index("nmap") < order.index("ffuf") < order.index("nuclei") < order.index("zap")
    assert zap_targets == ["https://127.0.0.1", "http://127.0.0.1:3000", ORIGIN]
    assert a["findings_by_scanner"]["zap"] == 12  # 4 alerts x 3 services
    assert {"nmap", "ffuf", "nuclei"} <= set(a["findings_by_scanner"])
