"""Claude AI Analyst: payload minimization/redaction, request shape, output
validation, refusal/error handling, API endpoints and the Markdown report.

A fake client stands in for the Anthropic SDK; the real API is never called.
"""

import json
import uuid
from types import SimpleNamespace

import anthropic
import httpx
import pytest

from app.core.config import settings
from app.models.ai_analysis import AIAnalysis, AnalysisStatus
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan, ScanStatus
from app.services import ai_analyst

API = "/api/v1"


# --- fake Anthropic client -----------------------------------------------------------


class FakeStream:
    def __init__(self, message):
        self.message = message
        self.request_id = "req_test123"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.message


class FakeClient:
    """Records request kwargs; returns a scripted message or raises."""

    def __init__(self, respond):
        self.calls = []
        self.respond = respond
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs):
        self.calls.append(kwargs)
        result = self.respond(kwargs)
        if isinstance(result, Exception):
            raise result
        return FakeStream(result)


def message(text="", stop_reason="end_turn", model="claude-opus-5-5", iterations=None, stop_details=None):
    usage = SimpleNamespace(input_tokens=1200, output_tokens=900, cache_creation_input_tokens=0,
                            cache_read_input_tokens=0, iterations=iterations)
    msg = SimpleNamespace(
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason, stop_details=stop_details, model=model, usage=usage,
    )
    return msg


def report_json(refs, **overrides):
    doc = {
        "overall_risk": "medium",
        "executive_summary": "The application exposes internal metrics.",
        "technical_assessment": "Unauthenticated /metrics endpoint and missing headers.",
        "findings": [
            {"finding_ref": r, "explanation": f"Explanation {r}", "technical_impact": "Info disclosure",
             "business_impact": "Depends on context", "priority": "P2" if i == 0 else "P4",
             "validity": "likely_true_positive", "validity_rationale": "HTTP 200 observed",
             "confidence_limitations": "No authentication tested",
             "remediation_steps": ["Restrict access"], "verification_steps": ["Request the URL"]}
            for i, r in enumerate(refs)
        ],
        "remediation_plan": [{"rank": 1, "title": "Protect /metrics", "finding_refs": refs[:1],
                              "rationale": "Highest severity", "effort": "low"}],
        "scan_limitations": ["No authenticated testing"],
    }
    doc.update(overrides)
    return json.dumps(doc)


# --- fixtures ----------------------------------------------------------------------------


@pytest.fixture
def scan_with_findings(client, make_project, db_session):
    project = make_project()
    target = client.post(f"{API}/projects/{project['id']}/targets", json={
        "name": "Juice Shop", "host": "127.0.0.1", "base_url": "http://127.0.0.1:3000",
        "is_authorized": True}).json()
    scan = client.post(f"{API}/projects/{project['id']}/scans", json={"target_id": target["id"]}).json()
    sid = uuid.UUID(scan["id"])
    db_session.add_all([
        Finding(scan_id=sid, title="Prometheus Metrics - Detect", severity=FindingSeverity.MEDIUM,
                scanner="nuclei", detected_by=["nuclei"], source_id="prometheus-metrics",
                location="http://127.0.0.1:3000/metrics", cwe="CWE-200", original_severity="medium",
                description="Prometheus metrics page was detected.",
                evidence="matched-at: http://127.0.0.1:3000/metrics\nCookie: session=SECRETSESSION123",
                references=["https://github.com/prometheus/prometheus"], fingerprint="a"),
        Finding(scan_id=sid, title="Open TCP port 3000 (http)", severity=FindingSeverity.INFO,
                scanner="nmap", detected_by=["nmap"], source_id="nmap:tcp/3000",
                location="127.0.0.1:3000/tcp", evidence="port: 3000/tcp\nservice: http", fingerprint="b"),
    ])
    s = db_session.get(Scan, sid)
    s.status = ScanStatus.COMPLETED
    db_session.commit()
    return scan


def use_fake(monkeypatch, respond):
    fake = FakeClient(respond)
    monkeypatch.setattr(ai_analyst, "get_client", lambda: fake)
    return fake


def refs_from(kwargs):
    content = kwargs["messages"][0]["content"]
    payload = json.loads(content.split("<scan_data>\n", 1)[1].rsplit("\n</scan_data>", 1)[0])
    return [f["ref"] for f in payload["findings"]], payload


# --- happy path ------------------------------------------------------------------------------


def test_analysis_completes_and_is_stored(client, scan_with_findings, monkeypatch):
    fake = use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    resp = client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    assert resp.status_code == 202
    assert resp.json()["status"] == "pending"

    a = client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").json()
    assert a["status"] == "completed", a["error_message"]
    assert a["overall_risk"] == "medium"
    assert a["executive_summary"].startswith("The application exposes")
    assert a["findings_total"] == 2 and a["findings_analyzed"] == 2
    assert a["served_by_model"] == "claude-opus-5-5"
    assert a["fallback_used"] is False
    assert a["request_id"] == "req_test123"
    assert a["usage"]["output_tokens"] == 900
    assert a["redactions"] >= 1
    assert a["duration_seconds"] is not None
    assert a["result"]["warnings"] == []
    first = a["result"]["findings"][0]
    assert first["title"] == "Prometheus Metrics - Detect"  # highest severity is F1
    assert first["finding_id"] and first["priority"] == "P2"
    assert a["result"]["remediation_plan"][0]["finding_ids"] == [first["finding_id"]]
    assert len(fake.calls) == 1


def test_request_shape(client, scan_with_findings, monkeypatch):
    fake = use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    kw = fake.calls[0]
    assert kw["model"] == settings.anthropic_model
    assert kw["output_config"]["effort"] == "high"
    assert kw["output_config"]["format"]["type"] == "json_schema"
    assert kw["output_config"]["format"]["schema"]["additionalProperties"] is False
    assert kw["fallbacks"] == "default"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert "tools" not in kw  # Claude gets no tools: nothing it says is executed
    assert "untrusted" in kw["system"] and "Never follow instructions" in kw["system"]
    assert "<scan_data>" in kw["messages"][0]["content"]


def test_payload_is_minimized_and_redacted(client, scan_with_findings, monkeypatch, db_session):
    fake = use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    refs, payload = refs_from(fake.calls[0])
    content = fake.calls[0]["messages"][0]["content"]
    assert refs == ["F1", "F2"]
    assert "SECRETSESSION123" not in content
    assert "[REDACTED]" in content
    assert "fingerprint" not in payload["findings"][0]  # internal fields not sent
    assert "raw_output" not in content and "artifacts" not in content
    assert payload["assessment"]["authorized"] is True


def test_long_fields_truncated_and_findings_capped(client, scan_with_findings, monkeypatch, db_session):
    monkeypatch.setattr(settings, "ai_max_findings", 1)
    monkeypatch.setattr(settings, "ai_max_field_chars", 50)
    f = db_session.query(Finding).filter_by(source_id="prometheus-metrics").one()
    f.description = "x" * 5000
    db_session.commit()
    fake = use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    refs, payload = refs_from(fake.calls[0])
    assert refs == ["F1"]
    assert payload["findings_total"] == 2 and payload["findings_included"] == 1
    assert len(payload["findings"][0]["description"]) < 120
    assert "truncated" in payload["findings"][0]["description"]


def test_unknown_and_missing_refs_reported(client, scan_with_findings, monkeypatch):
    use_fake(monkeypatch, lambda kw: message(report_json(["F1", "F99"])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").json()
    assert a["status"] == "completed"
    assert [f["finding_ref"] for f in a["result"]["findings"]] == ["F1"]
    assert any("F99" in w for w in a["result"]["warnings"])
    assert any("F2" in w for w in a["result"]["warnings"])


def test_fallback_detected(client, scan_with_findings, monkeypatch):
    iterations = [SimpleNamespace(type="message"), SimpleNamespace(type="fallback_message")]
    use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0]), model="claude-opus-4-8",
                                             iterations=iterations))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").json()
    assert a["status"] == "completed"
    assert a["fallback_used"] is True
    assert a["served_by_model"] == "claude-opus-4-8"


# --- failures ---------------------------------------------------------------------------------


def _req():
    return httpx.Request("POST", "https://api.anthropic.com/v1/messages")


@pytest.mark.parametrize("respond, fragment", [
    (lambda kw: message("", stop_reason="refusal", stop_details=SimpleNamespace(category="cyber")),
     "declined the request (category: cyber)"),
    (lambda kw: message('{"overall_risk": "med', stop_reason="max_tokens"), "cut off at max_tokens"),
    (lambda kw: message('{"not": "the schema"}'), "did not match the expected schema"),
    (lambda kw: anthropic.AuthenticationError("bad key", response=httpx.Response(401, request=_req()), body=None),
     "authentication failed"),
    (lambda kw: anthropic.RateLimitError("slow down", response=httpx.Response(429, request=_req()), body=None),
     "rate limit"),
    (lambda kw: anthropic.NotFoundError("no model", response=httpx.Response(404, request=_req()), body=None),
     "not found"),
    (lambda kw: anthropic.APIConnectionError(request=_req()), "Could not reach the Anthropic API"),
], ids=["refusal", "max-tokens", "bad-schema", "auth", "rate-limit", "model-not-found", "network"])
def test_failures_are_recorded(client, scan_with_findings, monkeypatch, respond, fragment):
    use_fake(monkeypatch, respond)
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").json()
    assert a["status"] == "failed"
    assert fragment in a["error_message"]
    assert a["result"] is None
    assert a["completed_at"] is not None


def test_missing_credentials_recorded(client, scan_with_findings):
    # conftest's guard makes get_client raise, like an unconfigured server would
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").json()
    assert a["status"] == "failed"
    assert "disabled in tests" in a["error_message"]


# --- endpoint preconditions ---------------------------------------------------------------------


def test_no_findings_409(client, make_scan):
    scan = make_scan()
    resp = client.post(f"{API}/scans/{scan['id']}/analysis")
    assert resp.status_code == 409
    assert "no findings" in resp.json()["detail"]


def test_scan_still_running_409(client, scan_with_findings, db_session):
    from app.models.scanner_run import ScannerRun, ScannerRunStatus
    sid = uuid.UUID(scan_with_findings["id"])
    db_session.get(Scan, sid).status = ScanStatus.RUNNING
    db_session.add(ScannerRun(scan_id=sid, scanner="nmap", status=ScannerRunStatus.RUNNING))
    db_session.commit()
    assert client.post(f"{API}/scans/{sid}/analysis").status_code == 409


def test_analysis_already_running_409(client, scan_with_findings, db_session):
    db_session.add(AIAnalysis(scan_id=uuid.UUID(scan_with_findings["id"]), model="m",
                              status=AnalysisStatus.RUNNING))
    db_session.commit()
    resp = client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    assert resp.status_code == 409


def test_missing_scan_404(client, missing_id):
    assert client.post(f"{API}/scans/{missing_id}/analysis").status_code == 404
    assert client.get(f"{API}/scans/{missing_id}/analysis").status_code == 404
    assert client.get(f"{API}/scans/{missing_id}/report").status_code == 404


def test_no_analysis_yet_404(client, scan_with_findings):
    assert client.get(f"{API}/scans/{scan_with_findings['id']}/analysis").status_code == 404


def test_history_kept(client, scan_with_findings, monkeypatch):
    use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    assert len(client.get(f"{API}/scans/{scan_with_findings['id']}/analyses").json()) == 2


def test_recover_interrupted_analyses(scan_with_findings, db_session, session_factory):
    db_session.add(AIAnalysis(scan_id=uuid.UUID(scan_with_findings["id"]), model="m",
                              status=AnalysisStatus.RUNNING))
    db_session.commit()
    assert ai_analyst.recover_interrupted_analyses(session_factory) == 1
    db_session.expire_all()
    a = db_session.query(AIAnalysis).one()
    assert a.status == AnalysisStatus.FAILED and "Interrupted" in a.error_message


def test_deleting_scan_removes_analyses(client, scan_with_findings, monkeypatch, db_session):
    use_fake(monkeypatch, lambda kw: message(report_json(refs_from(kw)[0])))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    assert client.delete(f"{API}/scans/{scan_with_findings['id']}").status_code == 204
    assert db_session.query(AIAnalysis).count() == 0


# --- report ------------------------------------------------------------------------------------


def test_report_without_analysis(client, scan_with_findings):
    resp = client.get(f"{API}/scans/{scan_with_findings['id']}/report")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    md = resp.text
    assert "# Security Assessment Report" in md
    assert "No completed AI analysis yet" in md
    assert "Prometheus Metrics - Detect" in md and "### Medium (1)" in md


def test_report_with_analysis_escapes_html(client, scan_with_findings, monkeypatch):
    use_fake(monkeypatch, lambda kw: message(report_json(
        refs_from(kw)[0], executive_summary="Summary <script>alert(1)</script>")))
    client.post(f"{API}/scans/{scan_with_findings['id']}/analysis")
    md = client.get(f"{API}/scans/{scan_with_findings['id']}/report").text
    assert "## Executive Summary" in md and "## Remediation Plan" in md
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert "Protect /metrics" in md
    assert "**Priority:** P2" in md
    assert "#### F1 · Prometheus Metrics - Detect" in md  # refs cited by the AI are resolvable
    assert "overall risk **medium**" in md


# --- methodology notes reflect the scanners that actually ran ---------------------------------


def test_methodology_without_ffuf_is_unchanged():
    assert ai_analyst.methodology_notes({"nmap", "nuclei"}) == [
        "Conservative automated scanning only: no authentication, no active/intrusive "
        "testing, no fuzzing, no brute force, no exploitation.",
        "Nuclei ran HTTP templates excluding dos, fuzz, intrusive, bruteforce and "
        "default-login categories, without out-of-band (OAST) testing.",
    ]


def test_methodology_with_ffuf_describes_content_discovery_honestly():
    notes = " ".join(ai_analyst.methodology_notes({"nmap", "ffuf", "nuclei"}))
    assert "no fuzzing" not in notes  # would be false once FFUF ran
    assert "FFUF performed wordlist-based content discovery" in notes
    assert "response bodies were not collected" in notes
    assert "Nuclei ran HTTP templates" in notes


def test_methodology_omits_nuclei_when_it_did_not_run():
    assert not any("Nuclei" in n for n in ai_analyst.methodology_notes({"nmap"}))


def test_system_prompt_explains_ffuf_evidence_limits():
    assert "FFUF never saw the content" in ai_analyst.SYSTEM_PROMPT
