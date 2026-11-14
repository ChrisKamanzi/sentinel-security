"""Assessment API + orchestrator, using fake scanners (no tools are executed).

TestClient runs BackgroundTasks before returning, so after POST /start the
assessment has already finished and can be inspected.
"""

import uuid

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.models.scan import Scan, ScanStatus
from app.models.scanner_run import ScannerRun, ScannerRunStatus
from app.scanners import registry
from app.scanners.base import BaseScanner, NormalizedFinding, ScannerError, ScannerOutput
from app.services import orchestrator

API = "/api/v1"


def _finding(port: int, severity=FindingSeverity.INFO) -> NormalizedFinding:
    return NormalizedFinding(
        title=f"Open TCP port {port}", severity=severity,
        dedup_key=f"open-port:tcp/{port}", location=f"127.0.0.1:{port}/tcp",
        source_id=f"fake:{port}", confidence="high", references=["https://ref.example"],
    )


class FakeNmap(BaseScanner):
    name = "nmap"
    display_name = "Fake Nmap"
    executable_name = "nmap"
    calls: list = []

    @classmethod
    def locate(cls):
        return "/fake/nmap"

    def build_command(self, ctx):
        return [self.executable_path, "--", *ctx.ips]

    def parse(self, process, ctx):  # pragma: no cover - run() is overridden
        raise NotImplementedError

    def run(self, ctx):
        FakeNmap.calls.append(ctx)
        return ScannerOutput(
            findings=[_finding(22), _finding(8000)],
            artifacts={"http_services": [{"url": "http://127.0.0.1:8000"}]},
            raw_output="<nmaprun/>", exit_code=0, command=self.build_command(ctx),
        )


class FakeNuclei(FakeNmap):
    """Second stage: sees nmap's artifacts; re-reports port 8000 (duplicate)."""

    name = "nuclei"
    display_name = "Fake Nuclei"
    seen_previous: list = []

    def run(self, ctx):
        FakeNuclei.seen_previous.append(ctx.previous)
        return ScannerOutput(
            findings=[_finding(8000, FindingSeverity.MEDIUM)],
            artifacts={}, raw_output="", exit_code=0, command=[self.executable_path],
        )


class BrokenNmap(FakeNmap):
    def run(self, ctx):
        raise ScannerError("nmap exited with code 1: simulated failure")


@pytest.fixture(autouse=True)
def local_dev(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", True)
    monkeypatch.setattr(registry, "SCANNERS", {"nmap": FakeNmap})
    monkeypatch.setattr(orchestrator, "SCANNERS", registry.SCANNERS)
    import app.api.routes.assessments as routes
    monkeypatch.setattr(routes, "SCANNERS", registry.SCANNERS)
    FakeNmap.calls = []
    FakeNuclei.seen_previous = []


def use_scanners(monkeypatch, mapping):
    import app.api.routes.assessments as routes
    monkeypatch.setattr(registry, "SCANNERS", mapping)
    monkeypatch.setattr(orchestrator, "SCANNERS", mapping)
    monkeypatch.setattr(routes, "SCANNERS", mapping)


@pytest.fixture
def local_scan(client, make_project):
    project = make_project()
    target = client.post(
        f"{API}/projects/{project['id']}/targets",
        json={"name": "AutoPentest API", "host": "127.0.0.1",
              "base_url": "http://127.0.0.1:8000", "is_authorized": True},
    ).json()
    scan = client.post(f"{API}/projects/{project['id']}/scans",
                       json={"target_id": target["id"]}).json()
    return target, scan


def start(client, scan_id, body=None):
    return client.post(f"{API}/scans/{scan_id}/start", json=body or {"scanners": ["nmap"]})


# --- happy path -------------------------------------------------------------------


def test_start_runs_nmap_and_persists_findings(client, local_scan):
    _, scan = local_scan
    resp = start(client, scan["id"])
    assert resp.status_code == 202
    assert resp.json()["status"] == "queued"

    a = client.get(f"{API}/scans/{scan['id']}/assessment").json()
    assert a["status"] == "completed"
    assert a["scanners"] == ["nmap"]
    assert a["started_at"] and a["completed_at"]
    assert a["duration_seconds"] is not None
    assert a["findings_total"] == 2
    assert a["findings_by_severity"]["info"] == 2
    assert a["findings_by_scanner"] == {"nmap": 2}
    [run] = a["runs"]
    assert run["scanner"] == "nmap"
    assert run["status"] == "completed"
    assert run["progress"] == 100
    assert run["findings_count"] == 2
    assert run["command"] == ["/fake/nmap", "--", "127.0.0.1"]
    assert run["artifacts"]["http_services"][0]["url"] == "http://127.0.0.1:8000"
    assert run["duration_seconds"] is not None

    findings = client.get(f"{API}/scans/{scan['id']}/findings").json()
    f = next(x for x in findings if x["source_id"] == "fake:22")
    assert f["scanner"] == "nmap"
    assert f["detected_by"] == ["nmap"]
    assert f["scanner_run_id"] == run["id"]
    assert f["confidence"] == "high"
    assert f["references"] == ["https://ref.example"]

    raw = client.get(f"{API}/scanner-runs/{run['id']}/raw")
    assert raw.status_code == 200 and raw.text == "<nmaprun/>"


def test_scanner_receives_only_scope_checked_ips(client, local_scan):
    _, scan = local_scan
    start(client, scan["id"])
    [ctx] = FakeNmap.calls
    assert ctx.ips == ["127.0.0.1"]
    assert ctx.host == "127.0.0.1"
    assert ctx.base_url == "http://127.0.0.1:8000"


def test_rerun_deduplicates_findings(client, local_scan):
    _, scan = local_scan
    start(client, scan["id"])
    start(client, scan["id"])
    assert len(client.get(f"{API}/scans/{scan['id']}/findings").json()) == 2
    runs = client.get(f"{API}/scans/{scan['id']}/runs").json()
    assert len(runs) == 2  # both attempts kept for history
    assert len(client.get(f"{API}/scans/{scan['id']}/assessment").json()["runs"]) == 1


def test_pipeline_passes_artifacts_and_merges_duplicates(client, local_scan, monkeypatch):
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": FakeNuclei})
    _, scan = local_scan
    # given out of order on purpose: pipeline order is enforced
    assert start(client, scan["id"], {"scanners": ["nuclei", "nmap"]}).status_code == 202
    a = client.get(f"{API}/scans/{scan['id']}/assessment").json()
    assert [r["scanner"] for r in a["runs"]] == ["nmap", "nuclei"]
    assert FakeNuclei.seen_previous[0]["nmap"]["http_services"][0]["url"] == "http://127.0.0.1:8000"

    findings = client.get(f"{API}/scans/{scan['id']}/findings").json()
    assert len(findings) == 2  # port 8000 reported twice -> merged
    merged = next(f for f in findings if f["location"] == "127.0.0.1:8000/tcp")
    assert merged["detected_by"] == ["nmap", "nuclei"]
    assert merged["scanner"] == "nmap"  # first detector kept
    assert merged["severity"] == "medium"  # highest severity wins


def test_findings_filters(client, local_scan, monkeypatch):
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": FakeNuclei})
    _, scan = local_scan
    start(client, scan["id"], {"scanners": ["nmap", "nuclei"]})
    url = f"{API}/scans/{scan['id']}/findings"
    assert len(client.get(url, params={"severity": "medium"}).json()) == 1
    assert len(client.get(url, params={"scanner": "nmap"}).json()) == 2
    assert client.get(url, params={"severity": "bogus"}).status_code == 422


# --- failures ---------------------------------------------------------------------


def test_scanner_failure_recorded(client, local_scan, monkeypatch):
    use_scanners(monkeypatch, {"nmap": BrokenNmap})
    _, scan = local_scan
    start(client, scan["id"])
    a = client.get(f"{API}/scans/{scan['id']}/assessment").json()
    assert a["status"] == "failed"
    assert a["runs"][0]["status"] == "failed"
    assert "simulated failure" in a["runs"][0]["error_message"]
    assert "simulated failure" in a["error_message"]


def test_partial_when_one_scanner_fails(client, local_scan, monkeypatch):
    class BrokenNuclei(FakeNuclei):
        def run(self, ctx):
            raise RuntimeError("kaboom")

    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": BrokenNuclei})
    _, scan = local_scan
    start(client, scan["id"], {"scanners": ["nmap", "nuclei"]})
    a = client.get(f"{API}/scans/{scan['id']}/assessment").json()
    assert a["status"] == "partial"
    assert [r["status"] for r in a["runs"]] == ["completed", "failed"]
    assert "RuntimeError: kaboom" in a["runs"][1]["error_message"]


def test_scope_revoked_mid_assessment_aborts_remaining(client, local_scan, monkeypatch):
    """Authorization is re-checked before every scanner."""
    target, scan = local_scan

    class RevokingNmap(FakeNmap):
        def run(self, ctx):
            out = super().run(ctx)
            client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
            return out

    use_scanners(monkeypatch, {"nmap": RevokingNmap, "nuclei": FakeNuclei})
    start(client, scan["id"], {"scanners": ["nmap", "nuclei"]})
    a = client.get(f"{API}/scans/{scan['id']}/assessment").json()
    assert [r["status"] for r in a["runs"]] == ["completed", "failed"]
    assert "Scope check failed" in a["runs"][1]["error_message"]
    assert FakeNuclei.seen_previous == []  # nuclei never executed
    assert a["status"] == "partial"


# --- start validation -----------------------------------------------------------------


def test_start_unauthorized_target_403(client, local_scan):
    target, scan = local_scan
    client.patch(f"{API}/targets/{target['id']}", json={"is_authorized": False})
    resp = start(client, scan["id"])
    assert resp.status_code == 403
    assert "not authorized" in resp.json()["detail"]
    assert client.get(f"{API}/scans/{scan['id']}/runs").json() == []


def test_start_private_target_403_when_not_allowed(client, local_scan, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", False)
    _, scan = local_scan
    resp = start(client, scan["id"])
    assert resp.status_code == 403
    assert "ALLOW_PRIVATE_TARGETS" in resp.json()["detail"]


@pytest.mark.parametrize(
    "body, fragment",
    [
        ({"scanners": ["metasploit"]}, "Unknown scanner"),
        ({"scanners": ["zap"]}, "not implemented yet"),  # zap: Phase 5
        ({"scanners": []}, None),
        ({"scanners": ["nmap"], "options": {"nmap": {"top_ports": 99999}}}, None),
        ({"scanners": ["nmap"], "options": {"nmap": {"ports": "1;id"}}}, None),
        ({"scanners": ["nmap"], "options": {"zap": {}}}, "unselected"),
        ({"scanners": ["nmap"], "shell": "id"}, None),
    ],
    ids=["unknown", "not-implemented", "empty", "bad-top-ports", "bad-ports",
         "options-for-unselected", "extra-field"],
)
def test_start_invalid_request_422(client, local_scan, body, fragment):
    _, scan = local_scan
    resp = start(client, scan["id"], body)
    assert resp.status_code == 422
    if fragment:
        assert fragment in str(resp.json()["detail"])


def test_start_tool_not_installed_409(client, local_scan, monkeypatch):
    class MissingNmap(FakeNmap):
        @classmethod
        def locate(cls):
            return None

    use_scanners(monkeypatch, {"nmap": MissingNmap})
    _, scan = local_scan
    resp = start(client, scan["id"])
    assert resp.status_code == 409
    assert "Not installed" in resp.json()["detail"]


def test_start_missing_scan_404(client, missing_id):
    assert start(client, missing_id).status_code == 404


def test_only_one_assessment_at_a_time(client, local_scan, db_session):
    _, scan = local_scan
    db_session.add(ScannerRun(scan_id=uuid.UUID(scan["id"]), scanner="nmap",
                              status=ScannerRunStatus.RUNNING))
    db_session.commit()
    resp = start(client, scan["id"])
    assert resp.status_code == 409
    assert "already" in resp.json()["detail"]


def test_cannot_delete_scan_while_assessment_active(client, local_scan, db_session):
    _, scan = local_scan
    db_session.add(ScannerRun(scan_id=uuid.UUID(scan["id"]), scanner="nmap",
                              status=ScannerRunStatus.PENDING))
    db_session.commit()
    assert client.delete(f"{API}/scans/{scan['id']}").status_code == 409


def test_delete_scan_after_assessment_removes_runs(client, local_scan, db_session):
    _, scan = local_scan
    start(client, scan["id"])
    assert client.delete(f"{API}/scans/{scan['id']}").status_code == 204
    assert db_session.scalars(select(ScannerRun)).all() == []


# --- restart recovery ---------------------------------------------------------------


def test_recover_interrupted_assessments(local_scan, db_session, session_factory):
    _, scan = local_scan
    scan_obj = db_session.get(Scan, uuid.UUID(scan["id"]))
    scan_obj.status = ScanStatus.RUNNING
    db_session.add_all([
        ScannerRun(scan_id=scan_obj.id, scanner="nmap", status=ScannerRunStatus.RUNNING),
        ScannerRun(scan_id=scan_obj.id, scanner="nuclei", order=1, status=ScannerRunStatus.PENDING),
    ])
    db_session.commit()

    assert orchestrator.recover_interrupted_assessments(session_factory) == 1

    db_session.expire_all()
    assert db_session.get(Scan, scan_obj.id).status == ScanStatus.FAILED
    runs = db_session.scalars(select(ScannerRun)).all()
    assert {r.status for r in runs} == {ScannerRunStatus.FAILED}
    assert all("Interrupted" in r.error_message for r in runs)


# --- tools endpoint --------------------------------------------------------------------


def test_tools_endpoint_lists_all_planned_scanners(client):
    resp = client.get(f"{API}/tools")
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()}
    assert list(tools) == ["nmap", "ffuf", "nuclei", "zap"]
    assert tools["nmap"]["implemented"] is True
    assert tools["zap"]["implemented"] is False
    for t in tools.values():
        assert isinstance(t["available"], bool)
