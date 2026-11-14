"""Web UI adapter (app.api.routes.ui): the sentinel-security frontend contract.

Fake scanners only (no tools run), loopback targets with ALLOW_PRIVATE_TARGETS
patched on, and AI analyses inserted directly (no Claude calls). TestClient runs
BackgroundTasks before returning, so a created assessment has already finished.
"""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.core.config import settings
from app.models.ai_analysis import AIAnalysis, AnalysisStatus
from app.models.finding import FindingSeverity
from app.models.project import Project
from app.models.scan import Scan
from app.scanners import registry
from app.scanners.base import BaseScanner, NormalizedFinding, ScannerError, ScannerOutput
from app.services import orchestrator

API = "/api/v1"
APPROVED_URL = "http://127.0.0.1:8000"


# --- fake scanners ----------------------------------------------------------------

class FakeNmapOptions(BaseModel):
    top_ports: int = Field(default=1000, ge=1, le=1000)


class FakeNmap(BaseScanner):
    name = "nmap"
    display_name = "Fake Nmap"
    executable_name = "nmap"
    Options = FakeNmapOptions
    seen_options: list = []

    @classmethod
    def locate(cls):
        return "/fake/nmap"

    def build_command(self, ctx):
        return [self.executable_path, *ctx.ips]

    def parse(self, process, ctx):  # pragma: no cover - run() is overridden
        raise NotImplementedError

    def run(self, ctx):
        FakeNmap.seen_options.append(ctx.options)
        return ScannerOutput(
            findings=[NormalizedFinding(
                title="Open TCP port 8000", severity=FindingSeverity.INFO,
                dedup_key="open-port:tcp/8000", location="127.0.0.1:8000/tcp",
                evidence="8000/tcp open http", source_id="nmap:8000",
            )],
            artifacts={"http_services": [{"url": APPROVED_URL}, {"url": "http://127.0.0.1:8443"}]},
            raw_output="<nmaprun/>", exit_code=0, command=self.build_command(ctx),
        )


class FakeNucleiOptions(BaseModel):
    rate_limit: int = Field(default=50, ge=1, le=150)


class FakeNuclei(FakeNmap):
    name = "nuclei"
    display_name = "Fake Nuclei"
    executable_name = "nuclei"
    Options = FakeNucleiOptions

    def run(self, ctx):
        FakeNmap.seen_options.append(ctx.options)
        return ScannerOutput(
            findings=[
                NormalizedFinding(
                    title="Exposed admin panel", severity=FindingSeverity.HIGH,
                    dedup_key="nuclei:admin-panel", location=f"{APPROVED_URL}/admin",
                    description="Admin login is reachable.",
                    recommendation="Restrict access.\nAdd MFA.",
                    evidence="matched-at: /admin\ncvss: 7.5 (CVSS:3.1/AV:N)", source_id="admin-panel",
                    cwe="CWE-284",
                ),
                NormalizedFinding(
                    title="Outdated server", severity=FindingSeverity.CRITICAL,
                    dedup_key="nuclei:old-server", location=APPROVED_URL,
                    evidence="matched-at: /", cwe="1104", source_id="old-server",
                ),
            ],
            artifacts={}, raw_output="", exit_code=0, command=[self.executable_path],
        )


class FakeFfuf(FakeNmap):
    name = "ffuf"
    display_name = "Fake FFUF"
    executable_name = "ffuf"
    Options = FakeNucleiOptions

    def run(self, ctx):
        return ScannerOutput(findings=[], artifacts={"discovered_total": 5}, raw_output="",
                             exit_code=0, command=[self.executable_path])


class BrokenNuclei(FakeNuclei):
    def run(self, ctx):
        raise ScannerError("nuclei exited with code 2: simulated failure")


class BrokenNmap(FakeNmap):
    def run(self, ctx):
        raise ScannerError("nmap exited with code 1: simulated failure")


class MissingNuclei(FakeNuclei):
    @classmethod
    def locate(cls):
        return None


def use_scanners(monkeypatch, mapping):
    import app.api.routes.assessments as assessment_routes
    monkeypatch.setattr(registry, "SCANNERS", mapping)
    monkeypatch.setattr(orchestrator, "SCANNERS", mapping)
    monkeypatch.setattr(assessment_routes, "SCANNERS", mapping)


@pytest.fixture(autouse=True)
def local_dev(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", True)
    use_scanners(monkeypatch, {"nmap": FakeNmap, "ffuf": FakeFfuf, "nuclei": FakeNuclei})
    FakeNmap.seen_options = []


@pytest.fixture
def approved_target(client, make_project):
    project = make_project()
    resp = client.post(f"{API}/projects/{project['id']}/targets", json={
        "name": "Juice Shop", "host": "127.0.0.1", "base_url": APPROVED_URL, "is_authorized": True,
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def new_assessment(client, **overrides):
    body = {"target": APPROVED_URL, "name": "Juice Shop", "authorized": True, "profile": "quick",
            "modules": ["Cross-site scripting"], "maxRps": 10}
    body.update(overrides)
    return client.post(f"{API}/assessments", json=body)


def scan_count(db_session) -> int:
    return db_session.scalar(select(func.count()).select_from(Scan))


ASSESSMENT_KEYS = {"id", "target", "name", "status", "progress", "startedAt", "finishedAt",
                   "riskScore", "findings", "profile"}
FINDING_KEYS = {"id", "title", "severity", "category", "scanner", "assessmentId", "target", "endpoint",
                "cwe", "cvss", "status", "discoveredAt", "description", "evidence", "businessImpact",
                "remediation"}


# --- empty database ---------------------------------------------------------------

def test_empty_database(client):
    summary = client.get(f"{API}/dashboard/summary")
    assert summary.status_code == 200
    s = summary.json()
    assert s["riskScore"] == 0 and s["riskTrend"] == 0
    assert s["totalScans"] == 0 and s["activeScans"] == 0
    assert s["totalVulnerabilities"] == 0 and s["criticalFindings"] == 0
    assert s["breakdown"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert len(s["findingsOverTime"]) == 6 and all(p["critical"] == 0 for p in s["findingsOverTime"])
    assert len(s["scanActivity"]) == 7 and all(p["scans"] == 0 for p in s["scanActivity"])
    assert s["recentActivity"] == []
    for path in ("assessments", "findings", "reports"):
        resp = client.get(f"{API}/{path}")
        assert resp.status_code == 200 and resp.json() == []


# --- creating assessments ---------------------------------------------------------

def test_create_assessment_runs_existing_workflow(client, approved_target, db_session):
    resp = new_assessment(client)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert set(body) == ASSESSMENT_KEYS
    assert body["target"] == APPROVED_URL
    assert body["name"] == "Juice Shop"
    assert body["profile"] == "Quick"
    # The scan was created under the approved target's project, through the orchestrator.
    scan = db_session.get(Scan, uuid.UUID(body["id"]))
    assert scan.target_id == uuid.UUID(approved_target["id"])
    assert scan.project_id == uuid.UUID(approved_target["project_id"])
    assert scan.scanner == "nmap,nuclei"
    # Profile options reached the scanners (quick => top 100 ports, rate limit = maxRps).
    assert [o.model_dump() for o in FakeNmap.seen_options] == [{"top_ports": 100}, {"rate_limit": 10}]

    detail = client.get(f"{API}/assessments/{body['id']}").json()
    assert detail["status"] == "completed"
    assert detail["progress"] == 100
    assert detail["finishedAt"] is not None
    assert detail["findings"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert detail["riskScore"] == 60  # 40 per critical + 20 per high


def test_create_assessment_does_not_use_url_path_for_scope(client, approved_target):
    resp = new_assessment(client, target=f"{APPROVED_URL}/some/page?x=1")
    assert resp.status_code == 202, resp.text
    assert resp.json()["target"] == APPROVED_URL  # always the approved URL


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:3000",   # different port than approved
    "https://127.0.0.1:8000",  # different scheme
    "http://localhost:8000",   # different host string
])
def test_create_rejects_origin_not_approved(client, approved_target, db_session, url):
    resp = new_assessment(client, target=url)
    assert resp.status_code == 403
    assert "No approved target" in resp.json()["detail"]
    assert scan_count(db_session) == 0


def test_create_rejects_unauthorized_target(client, approved_target, db_session):
    client.patch(f"{API}/targets/{approved_target['id']}", json={"is_authorized": False})
    resp = new_assessment(client)
    assert resp.status_code == 403
    assert scan_count(db_session) == 0


def test_create_with_no_targets_creates_nothing(client, db_session):
    resp = new_assessment(client)
    assert resp.status_code == 403
    assert scan_count(db_session) == 0
    assert db_session.scalar(select(func.count()).select_from(Project)) == 0


def test_create_requires_authorization_confirmation(client, approved_target, db_session):
    resp = new_assessment(client, authorized=False)
    assert resp.status_code == 403
    assert "confirmation" in resp.json()["detail"]
    assert scan_count(db_session) == 0


def test_create_private_target_out_of_scope_leaves_no_scan(client, approved_target, db_session, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", False)
    resp = new_assessment(client)
    assert resp.status_code == 403
    assert "Out of scope" in resp.json()["detail"]
    assert scan_count(db_session) == 0


def test_create_scanner_not_installed_409_leaves_no_scan(client, approved_target, db_session, monkeypatch):
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": MissingNuclei})
    resp = new_assessment(client)
    assert resp.status_code == 409
    assert "Not installed" in resp.json()["detail"]
    assert scan_count(db_session) == 0


def test_create_profile_with_unimplemented_scanner_422(client, approved_target, db_session):
    resp = new_assessment(client, profile="deep")  # zap is not registered in this test
    assert resp.status_code == 422
    assert "zap" in resp.json()["detail"]
    assert scan_count(db_session) == 0


def test_create_conflicts_with_running_assessment(client, approved_target, db_session):
    running = Scan(project_id=uuid.UUID(approved_target["project_id"]),
                   target_id=uuid.UUID(approved_target["id"]),
                   target_url=APPROVED_URL, status="running")
    db_session.add(running)
    db_session.commit()
    resp = new_assessment(client)
    assert resp.status_code == 409
    assert scan_count(db_session) == 1  # only the pre-existing one


@pytest.mark.parametrize("override, fragment", [
    ({"authHeader": "Authorization: Bearer x"}, "not supported"),
    ({"target": "ftp://127.0.0.1:8000"}, "http(s)"),
    ({"target": "http://user:pw@127.0.0.1:8000"}, "credentials"),
    ({"target": "http://169.254.169.254"}, "blocked"),
    ({"profile": "insane"}, None),
    ({"maxRps": 0}, None),
    ({"shell": "id"}, None),
], ids=["auth-header", "scheme", "credentials", "metadata-ip", "profile", "rps", "extra-field"])
def test_create_invalid_input_422(client, approved_target, db_session, override, fragment):
    resp = new_assessment(client, **override)
    assert resp.status_code == 422, resp.text
    if fragment:
        assert fragment in str(resp.json()["detail"])
    assert scan_count(db_session) == 0


# --- listing and detail -----------------------------------------------------------

def test_list_assessments(client, approved_target):
    first = new_assessment(client).json()
    second = new_assessment(client, profile="standard").json()
    items = client.get(f"{API}/assessments").json()
    assert {a["id"] for a in items} == {first["id"], second["id"]}
    started = [a["startedAt"] for a in items]
    assert started == sorted(started, reverse=True)  # newest first (1 s ties allowed)
    assert all(set(a) == ASSESSMENT_KEYS for a in items)
    assert {a["id"]: a["profile"] for a in items}[second["id"]] == "Standard"


def test_detail_stages_log_and_endpoints(client, approved_target):
    created = new_assessment(client, profile="standard").json()
    d = client.get(f"{API}/assessments/{created['id']}").json()
    assert set(d) == ASSESSMENT_KEYS | {"stages", "log", "requestsSent", "endpointsDiscovered"}
    assert [s["key"] for s in d["stages"]] == ["nmap", "ffuf", "nuclei"]
    assert all(s["status"] == "done" for s in d["stages"])
    assert d["requestsSent"] is None  # not tracked: never invented
    assert d["endpointsDiscovered"] == 2 + 5  # nmap http services + ffuf discoveries
    messages = [entry["message"] for entry in d["log"]]
    assert any("completed" in m for m in messages)
    assert any(e["level"] == "finding" and "Outdated server" in e["message"] for e in d["log"])


def test_partial_assessment_is_not_reported_as_completed(client, approved_target, monkeypatch):
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": BrokenNuclei})
    created = new_assessment(client).json()
    d = client.get(f"{API}/assessments/{created['id']}").json()
    assert d["status"] == "partial"
    stages = {s["key"]: s for s in d["stages"]}
    assert stages["nmap"]["status"] == "done"
    assert stages["nuclei"]["status"] == "failed"
    assert "simulated failure" in stages["nuclei"]["description"]
    assert any(e["level"] == "warn" for e in d["log"])


def test_failed_assessment_status(client, approved_target, monkeypatch):
    use_scanners(monkeypatch, {"nmap": BrokenNmap, "nuclei": BrokenNuclei})
    created = new_assessment(client).json()
    d = client.get(f"{API}/assessments/{created['id']}").json()
    assert d["status"] == "failed"
    assert {s["status"] for s in d["stages"]} == {"failed"}


def test_queued_scan_without_runs(client, make_scan):
    scan = make_scan()  # created via the existing API, never started
    d = client.get(f"{API}/assessments/{scan['id']}").json()
    assert d["status"] == "queued"
    assert d["progress"] == 0
    assert d["finishedAt"] is None
    assert d["profile"] == "Not started"
    assert d["stages"] == [] and d["endpointsDiscovered"] is None


def test_assessment_detail_invalid_and_missing_ids(client, missing_id):
    assert client.get(f"{API}/assessments/not-a-uuid").status_code == 422
    resp = client.get(f"{API}/assessments/{missing_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Assessment not found"


# --- findings ---------------------------------------------------------------------

def test_findings_mapping(client, approved_target):
    created = new_assessment(client).json()
    findings = {f["title"]: f for f in client.get(f"{API}/findings").json()}
    assert set(findings) == {"Open TCP port 8000", "Exposed admin panel", "Outdated server"}
    assert all(set(f) == FINDING_KEYS for f in findings.values())

    admin = findings["Exposed admin panel"]
    assert admin["severity"] == "high"
    assert admin["assessmentId"] == created["id"]
    assert admin["target"] == "127.0.0.1"
    assert admin["endpoint"] == f"{APPROVED_URL}/admin"
    assert admin["cvss"] == 7.5  # parsed from Nuclei's own evidence
    assert admin["cwe"] == "CWE-284"
    assert admin["category"] == "Known vulnerabilities"
    assert admin["scanner"] == "nuclei"
    assert admin["status"] == "open"
    assert admin["evidence"] == {"request": "", "response": "matched-at: /admin\ncvss: 7.5 (CVSS:3.1/AV:N)"}
    assert admin["remediation"] == ["Restrict access.", "Add MFA."]
    assert admin["businessImpact"] == ""  # no AI analysis yet

    assert findings["Outdated server"]["cwe"] == "CWE-1104"
    assert findings["Outdated server"]["cvss"] is None  # no CVSS reported: not invented
    port = findings["Open TCP port 8000"]
    assert port["cvss"] is None and port["category"] == "Network exposure" and port["remediation"] == []


def test_findings_filters(client, approved_target):
    first = new_assessment(client).json()
    new_assessment(client)
    assert {f["severity"] for f in client.get(f"{API}/findings", params={"severity": "high"}).json()} == {"high"}
    scoped = client.get(f"{API}/findings", params={"assessmentId": first["id"]}).json()
    assert len(scoped) == 3 and {f["assessmentId"] for f in scoped} == {first["id"]}
    assert client.get(f"{API}/findings", params={"severity": "bogus"}).status_code == 422
    assert client.get(f"{API}/findings", params={"assessmentId": "nope"}).status_code == 422


def test_finding_detail_and_legacy_endpoint_unchanged(client, approved_target, missing_id):
    new_assessment(client)
    fid = next(f["id"] for f in client.get(f"{API}/findings").json() if f["title"] == "Exposed admin panel")
    detail = client.get(f"{API}/findings/{fid}/detail")
    assert detail.status_code == 200 and set(detail.json()) == FINDING_KEYS
    legacy = client.get(f"{API}/findings/{fid}").json()
    assert legacy["scan_id"] and legacy["location"] and isinstance(legacy["evidence"], str)
    assert client.get(f"{API}/findings/{missing_id}/detail").status_code == 404
    assert client.get(f"{API}/findings/xyz/detail").status_code == 422


def test_findings_use_completed_ai_analysis(client, approved_target, db_session):
    created = new_assessment(client).json()
    fid = next(f["id"] for f in client.get(f"{API}/findings").json() if f["title"] == "Exposed admin panel")
    db_session.add(AIAnalysis(
        scan_id=uuid.UUID(created["id"]), model="claude-test", status=AnalysisStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
        result={"findings": [{"finding_id": fid, "business_impact": "Account takeover risk.",
                              "remediation_steps": ["Put the panel behind VPN"]}]},
    ))
    db_session.commit()
    f = client.get(f"{API}/findings/{fid}/detail").json()
    assert f["businessImpact"] == "Account takeover risk."
    assert f["remediation"] == ["Put the panel behind VPN"]


# --- reports ----------------------------------------------------------------------

def test_reports_and_download(client, approved_target, make_scan):
    created = new_assessment(client).json()
    queued = make_scan()  # never started: must not appear as a report
    reports = client.get(f"{API}/reports").json()
    assert [r["id"] for r in reports] == [created["id"]]
    r = reports[0]
    assert set(r) == {"id", "assessmentId", "title", "target", "generatedAt", "format", "sizeKb", "findings"}
    assert r["assessmentId"] == created["id"]
    assert r["format"] == "md"
    assert r["findings"] == 3
    assert r["sizeKb"] > 0

    download = client.get(f"{API}/reports/{created['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/markdown")
    assert "attachment" in download.headers["content-disposition"]
    assert download.text.startswith("# Security Assessment Report")
    assert "Outdated server" in download.text

    blocked = client.get(f"{API}/reports/{queued['id']}/download")
    assert blocked.status_code == 409 and "queued" in blocked.json()["detail"]


def test_report_download_invalid_and_missing(client, missing_id):
    assert client.get(f"{API}/reports/{missing_id}/download").status_code == 404
    assert client.get(f"{API}/reports/abc/download").status_code == 422


def test_partial_assessment_still_has_report(client, approved_target, monkeypatch):
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": BrokenNuclei})
    created = new_assessment(client).json()
    assert [r["id"] for r in client.get(f"{API}/reports").json()] == [created["id"]]


# --- dashboard --------------------------------------------------------------------

def test_dashboard_with_real_records(client, approved_target, make_scan):
    new_assessment(client)
    make_scan()  # a queued scan counts as active
    s = client.get(f"{API}/dashboard/summary").json()
    assert s["totalScans"] == 2
    assert s["activeScans"] == 1
    assert s["breakdown"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert s["totalVulnerabilities"] == 2  # info findings (open ports) excluded
    assert s["criticalFindings"] == 1
    assert s["riskScore"] == 60
    assert s["riskTrend"] == 0  # only one finished assessment
    assert s["scanActivity"][-1]["scans"] == 2  # both created today
    assert s["findingsOverTime"][-1]["critical"] == 1
    kinds = {e["type"] for e in s["recentActivity"]}
    assert {"scan", "finding"} <= kinds
    assert all(set(e) == {"id", "time", "message", "type"} for e in s["recentActivity"])


def test_dashboard_risk_trend(client, approved_target, monkeypatch):
    new_assessment(client)  # score 60
    use_scanners(monkeypatch, {"nmap": FakeNmap, "nuclei": BrokenNuclei})
    new_assessment(client)  # partial, only an info finding: score 0
    s = client.get(f"{API}/dashboard/summary").json()
    assert s["riskTrend"] == -60
    assert s["riskScore"] == 0  # latest finished assessment for the only target


@pytest.mark.parametrize("profile, expected", [("quick", "quick"), ("standard", "standard"), ("deep", "standard")])
def test_ui_profile_selects_actual_nuclei_profile(profile, expected):
    from app.api.routes.ui import _profile_options
    from app.scanners.nuclei import NucleiOptions
    options = NucleiOptions.model_validate(_profile_options(profile, 10)["nuclei"])
    assert options.profile == expected
    assert options.rate_limit == 10
