"""FFUF scanner: command safety, options, DNS pinning + revalidation, config
isolation, parsing, the evidence-based severity policy, and the wordlist.

The subprocess layer is mocked: FFUF is never executed here.
"""

import os
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.core.scope import ScopeError
from app.models.finding import FindingSeverity
from app.scanners import ffuf as ffuf_mod
from app.scanners.base import ScanContext, ScannerError
from app.scanners.ffuf import (
    MATCH_CODES,
    WORDLISTS,
    FfufOptions,
    FfufScanner,
    decode_input,
    parse_jsonl,
    parse_progress,
    pin_target,
)
from app.scanners.process import ProcessResult

FIXTURE = (Path(__file__).parent / "fixtures" / "ffuf_sample.jsonl").read_text()
FFUF = "/opt/homebrew/bin/ffuf"
WORDLIST = WORDLISTS["quick"]


def make_ctx(previous=None, **overrides):
    defaults = dict(
        scan_id=uuid.uuid4(), target_id=uuid.uuid4(), host="127.0.0.1", ips=["127.0.0.1"],
        base_url="http://127.0.0.1:8000", target_url="http://127.0.0.1:8000",
        options=FfufOptions(), previous=previous or {},
        # stands in for the orchestrator's authorize_scan(): scope still approved
        revalidate=lambda: SimpleNamespace(host="127.0.0.1", ips=["127.0.0.1"]),
    )
    defaults.update(overrides)
    return ScanContext(**defaults)


def proc(stdout="", stderr="", exit_code=0, timed_out=False, argv=None):
    return ProcessResult(argv=argv or [FFUF], exit_code=exit_code, stdout=stdout, stderr=stderr,
                         timed_out=timed_out, duration_seconds=1.0, truncated=False)


def flag_value(argv, flag):
    return argv[argv.index(flag) + 1]


def header_values(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]


@pytest.fixture
def fake_ffuf(monkeypatch):
    """Mock run_tool; record argv/kwargs and whether the isolated HOME existed."""
    calls = []
    state = {"respond": lambda argv: proc(FIXTURE, argv=argv)}

    def fake_run_tool(argv, timeout, max_output_bytes, **kw):
        env = kw.get("env_overrides") or {}
        calls.append({"argv": argv, "timeout": timeout, "env": dict(env),
                      "home_existed": bool(env) and os.path.isdir(env["HOME"])})
        return state["respond"](argv)

    monkeypatch.setattr(ffuf_mod, "run_tool", fake_run_tool)
    return calls, state


def run_fixture(**ctx_overrides):
    return FfufScanner(FFUF).run(make_ctx(**ctx_overrides))


# --- command -------------------------------------------------------------------------------


def test_command_has_conservative_safety_flags():
    argv = FfufScanner(FFUF).build_command(make_ctx())
    assert argv[0] == FFUF
    assert flag_value(argv, "-u") == "http://127.0.0.1:8000/FUZZ"
    assert flag_value(argv, "-w") == str(WORDLIST)
    for flag in ("-json", "-noninteractive", "-ic", "-ac"):
        assert flag in argv
    assert flag_value(argv, "-X") == "GET"
    assert flag_value(argv, "-mc") == MATCH_CODES and "500" not in MATCH_CODES
    assert (flag_value(argv, "-rate"), flag_value(argv, "-t")) == ("20", "5")
    assert (flag_value(argv, "-timeout"), flag_value(argv, "-maxtime")) == ("10", "300")
    assert any(h.startswith("User-Agent: AutoPentest-AI") for h in header_values(argv))


@pytest.mark.parametrize("forbidden", [
    "-r", "-recursion", "-x", "-replay-proxy", "-od", "-o", "-request", "-input-cmd",
    "-input-shell", "-D", "-d", "-b", "-audit-log", "-debug-log", "-config", "-http2",
])
def test_command_never_contains_risky_flags(forbidden):
    argv = FfufScanner(FFUF).build_command(make_ctx(options=FfufOptions(extensions=[".bak"])))
    assert forbidden not in argv


def test_ip_literal_target_has_no_host_header_or_sni():
    argv = FfufScanner(FFUF).build_command(make_ctx())
    assert not any(h.startswith("Host:") for h in header_values(argv))
    assert "-sni" not in argv


def test_extensions_passed_to_ffuf():
    argv = FfufScanner(FFUF).build_command(make_ctx(options=FfufOptions(extensions=[".BAK", ".txt", ".bak"])))
    assert flag_value(argv, "-e") == ".bak,.txt"


def test_options_limits_drive_command():
    opts = FfufOptions(rate_limit=7, threads=2, request_timeout=4, max_time=60)
    argv = FfufScanner(FFUF).build_command(make_ctx(options=opts))
    assert [flag_value(argv, f) for f in ("-rate", "-t", "-timeout", "-maxtime")] == ["7", "2", "4", "60"]


def test_process_timeout_never_exceeds_setting(monkeypatch):
    monkeypatch.setattr(settings, "ffuf_timeout_seconds", 120)
    scanner = FfufScanner(FFUF)
    assert scanner.timeout_seconds(make_ctx(options=FfufOptions(max_time=1800))) == 120
    assert scanner.timeout_seconds(make_ctx(options=FfufOptions(max_time=30))) == 90


# --- options -------------------------------------------------------------------------------


@pytest.mark.parametrize("opts", [
    {"wordlist": "/etc/passwd"},
    {"wordlist": "../../secret.txt"},
    {"wordlist_path": "/tmp/words.txt"},
    {"extensions": ["bak"]},
    {"extensions": [".b/k"]},
    {"extensions": [".toolongext"]},
    {"extensions": [".a", ".b", ".c", ".d", ".e", ".f"]},
    {"rate_limit": 0}, {"rate_limit": 101},
    {"threads": 0}, {"threads": 21},
    {"request_timeout": 31},
    {"max_time": 5}, {"max_time": 1801},
    {"recursion": True},
    {"follow_redirects": True},
])
def test_invalid_options_rejected(opts):
    with pytest.raises(ValidationError):
        FfufOptions.model_validate(opts)


# --- targets / DNS pinning -----------------------------------------------------------------


def test_targets_come_from_nmap_http_services():
    previous = {"nmap": {"http_services": [{"url": "http://127.0.0.1:3000"}, {"url": "https://127.0.0.1"}]}}
    assert FfufScanner(FFUF).targets(make_ctx(previous=previous)) == ["http://127.0.0.1:3000", "https://127.0.0.1"]


def test_targets_fall_back_to_base_url_without_nmap():
    assert FfufScanner(FFUF).targets(make_ctx()) == ["http://127.0.0.1:8000"]


def test_out_of_scope_url_refused():
    previous = {"nmap": {"http_services": [{"url": "http://evil.example"}]}}
    with pytest.raises(ScannerError, match="out-of-scope"):
        FfufScanner(FFUF).targets(make_ctx(previous=previous))


def test_hostname_target_is_pinned_to_validated_ip_with_host_header():
    t = pin_target("http://app.example:8080/shop/", "app.example", ["203.0.113.10"], ["203.0.113.10"])
    assert t.connect_base == "http://203.0.113.10:8080/shop"
    assert t.url == "http://app.example:8080/shop"
    assert t.host_header == "app.example:8080"
    assert t.sni is None


def test_https_hostname_target_sets_sni_and_omits_default_port():
    t = pin_target("https://app.example", "app.example", ["203.0.113.10"], ["203.0.113.10"])
    assert t.connect_base == "https://203.0.113.10"
    assert (t.host_header, t.sni) == ("app.example", "app.example")
    argv = FfufScanner(FFUF).build_command(make_ctx(host="app.example", ips=["203.0.113.10"]), t)
    assert flag_value(argv, "-u") == "https://203.0.113.10/FUZZ"
    assert "Host: app.example" in header_values(argv)
    assert flag_value(argv, "-sni") == "app.example"


def test_ipv6_pinned_address_is_bracketed():
    t = pin_target("http://app.example:3000", "app.example", ["2001:db8::5"], ["2001:db8::5"])
    assert t.connect_base == "http://[2001:db8::5]:3000"


def test_pins_only_to_an_address_both_fresh_and_approved():
    t = pin_target("http://app.example", "app.example",
                   approved_ips=["203.0.113.20"], fresh_ips=["203.0.113.10", "203.0.113.20"])
    assert t.ip == "203.0.113.20"


def test_dns_change_since_scope_check_fails_closed():
    with pytest.raises(ScopeError, match="no longer resolves"):
        pin_target("http://app.example", "app.example",
                   approved_ips=["203.0.113.10"], fresh_ips=["198.51.100.7"])


@pytest.mark.parametrize("url", ["ftp://127.0.0.1/", "http://evil.example/", "file:///etc/passwd"])
def test_pin_target_rejects_bad_urls(url):
    with pytest.raises(ScannerError):
        pin_target(url, "127.0.0.1", ["127.0.0.1"], ["127.0.0.1"])


# --- revalidation immediately before execution ---------------------------------------------------


def test_scope_revalidated_immediately_before_each_execution(fake_ffuf):
    calls, _ = fake_ffuf
    events = []
    previous = {"nmap": {"http_services": [{"url": "http://127.0.0.1:8000"}, {"url": "http://127.0.0.1:3000"}]}}

    def revalidate():
        events.append(("revalidate", len(calls)))
        return SimpleNamespace(host="127.0.0.1", ips=["127.0.0.1"])

    FfufScanner(FFUF).run(make_ctx(previous=previous, revalidate=revalidate))
    # one fresh check per target, each happening before that target's execution
    assert events == [("revalidate", 0), ("revalidate", 1)]
    assert len(calls) == 2


def test_revoked_authorization_stops_ffuf_before_execution(fake_ffuf):
    calls, _ = fake_ffuf

    def revalidate():
        raise ScopeError("target is not authorized for scanning")

    with pytest.raises(ScopeError):
        FfufScanner(FFUF).run(make_ctx(revalidate=revalidate))
    assert calls == []


def test_dns_rebinding_between_checks_fails_closed_without_execution(fake_ffuf):
    calls, _ = fake_ffuf
    ctx = make_ctx(host="app.example", ips=["203.0.113.10"], base_url="http://app.example:8000",
                   target_url="http://app.example:8000",
                   revalidate=lambda: SimpleNamespace(host="app.example", ips=["10.0.0.5"]))
    with pytest.raises(ScopeError, match="no longer resolves"):
        FfufScanner(FFUF).run(ctx)
    assert calls == []


def test_changed_target_host_fails_closed(fake_ffuf):
    calls, _ = fake_ffuf
    ctx = make_ctx(revalidate=lambda: SimpleNamespace(host="other.example", ips=["127.0.0.1"]))
    with pytest.raises(ScopeError, match="host changed"):
        FfufScanner(FFUF).run(ctx)
    assert calls == []


def test_without_orchestrator_hook_dns_and_ip_policy_still_checked(fake_ffuf, monkeypatch):
    import ipaddress
    calls, _ = fake_ffuf
    monkeypatch.setattr(ffuf_mod, "resolve_host", lambda host: [ipaddress.ip_address("169.254.169.254")])
    with pytest.raises(ScopeError, match="blocked"):
        FfufScanner(FFUF).run(make_ctx(revalidate=None))
    assert calls == []


def test_without_orchestrator_hook_private_ip_policy_enforced(fake_ffuf):
    calls, _ = fake_ffuf  # ALLOW_PRIVATE_TARGETS is false in tests
    with pytest.raises(ScopeError, match="private"):
        FfufScanner(FFUF).run(make_ctx(revalidate=None))
    assert calls == []


def test_hostname_pinning_used_in_executed_command(fake_ffuf):
    calls, state = fake_ffuf
    state["respond"] = lambda argv: proc(FIXTURE.replace("127.0.0.1:8000", "203.0.113.10:8000"), argv=argv)
    ctx = make_ctx(host="app.example", ips=["203.0.113.10"], base_url="http://app.example:8000",
                   target_url="http://app.example:8000",
                   revalidate=lambda: SimpleNamespace(host="app.example", ips=["203.0.113.10"]))
    out = FfufScanner(FFUF).run(ctx)
    argv = calls[0]["argv"]
    assert flag_value(argv, "-u") == "http://203.0.113.10:8000/FUZZ"
    assert "Host: app.example:8000" in header_values(argv)
    # findings are reported against the authorized hostname, not the IP
    assert all(f.location.startswith("http://app.example:8000/") for f in out.findings)
    assert out.artifacts["targets"][0]["pinned_ip"] == "203.0.113.10"


# --- config isolation ------------------------------------------------------------------------


def test_ffuf_runs_with_isolated_home_that_is_removed(fake_ffuf):
    calls, _ = fake_ffuf
    out = run_fixture()
    env = calls[0]["env"]
    assert set(env) == {"HOME", "XDG_CONFIG_HOME"}
    assert env["HOME"] != os.path.expanduser("~")
    assert env["XDG_CONFIG_HOME"] == env["HOME"] + "/.config"
    assert calls[0]["home_existed"] is True
    assert not os.path.exists(env["HOME"])  # cleaned up afterwards
    assert out.artifacts["config_isolated"] is True


def test_isolated_home_removed_even_when_ffuf_fails(fake_ffuf):
    calls, state = fake_ffuf
    state["respond"] = lambda argv: proc(stderr="boom", exit_code=1, argv=argv)
    with pytest.raises(ScannerError):
        run_fixture()
    assert not os.path.exists(calls[0]["env"]["HOME"])


def test_version_check_uses_isolated_home(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw)
        return SimpleNamespace(stdout="ffuf version: 2.1.0-dev\n", stderr="")

    monkeypatch.setattr(ffuf_mod.subprocess, "run", fake_run)
    assert FfufScanner.version(FFUF) == "2.1.0-dev"
    assert seen["env"]["HOME"] != os.path.expanduser("~")
    assert "ANTHROPIC_API_KEY" not in seen["env"]


# --- parsing ---------------------------------------------------------------------------------


def test_parse_jsonl_counts_invalid_lines():
    results, invalid = parse_jsonl(FIXTURE)
    assert len(results) == 8
    assert invalid == 2  # non-JSON line + record with a non-integer status


def test_decode_input_handles_base64_and_plain_text():
    assert decode_input("cm9ib3RzLnR4dA==") == "robots.txt"
    assert decode_input("admin panel") == "admin panel"
    assert decode_input(None) is None


def test_parse_progress_from_carriage_return_stream():
    stderr = ("\x1b[2K:: Progress: [10/255] :: Job [1/1] :: 5 req/sec :: Duration: [0:00:01] :: Errors: 0 ::"
              "\r\x1b[2K:: Progress: [255/255] :: Job [1/1] :: 20 req/sec :: Duration: [0:00:13] :: Errors: 3 ::")
    assert parse_progress(stderr) == {"requests_completed": 255, "requests_total": 255, "errors": 3}
    assert parse_progress("") == {"requests_completed": None, "requests_total": None, "errors": None}


def test_off_target_results_are_dropped(fake_ffuf):
    out = run_fixture()
    assert out.artifacts["out_of_scope_dropped"] == 1
    assert not any("evil.example" in (f.location or "") for f in out.findings)
    assert out.artifacts["invalid_lines"] == 2


def test_nonzero_exit_raises_with_clean_stderr(fake_ffuf):
    _, state = fake_ffuf
    state["respond"] = lambda argv: proc(stderr="\x1b[31mEncountered error(s): bad wordlist\x1b[0m\r",
                                         exit_code=1, argv=argv)
    with pytest.raises(ScannerError, match="code 1: Encountered error"):
        run_fixture()


def test_timeout_raises(fake_ffuf):
    _, state = fake_ffuf
    state["respond"] = lambda argv: proc(timed_out=True, exit_code=None, argv=argv)
    with pytest.raises(ScannerError, match="timed out"):
        run_fixture()


def test_progress_reported_per_target(fake_ffuf):
    seen = []
    previous = {"nmap": {"http_services": [{"url": "http://127.0.0.1:8000"}, {"url": "http://127.0.0.1:3000"}]}}
    FfufScanner(FFUF).run(make_ctx(previous=previous, report_progress=seen.append))
    assert seen == [52, 95]


# --- severity policy and metadata ----------------------------------------------------------------


def _by_path(out):
    return {f.location.removeprefix("http://127.0.0.1:8000"): f for f in out.findings}


def test_severity_policy_is_evidence_based(fake_ffuf):
    f = _by_path(run_fixture())
    assert set(f) == {"/robots.txt", "/ftp", "/metrics", "/.git/HEAD", "/backup.zip", "/assets", "/rest/admin"}
    # ordinary discovered paths: informational
    for path in ("/robots.txt", "/assets", "/rest/admin"):
        assert f[path].severity == FindingSeverity.INFO
        assert f[path].source_id == "ffuf:content-discovery"
    # sensitive-looking + non-empty 2xx: low, low confidence, never higher
    for path, category in (("/ftp", "file-listing"), ("/metrics", "debug")):
        assert f[path].severity == FindingSeverity.LOW
        assert f[path].confidence == "low"
        assert f[path].source_id == f"ffuf:sensitive-path-reachable:{category}"
        assert "NOT a confirmed exposure" in f[path].description
    # sensitive-looking but access-controlled (403) or empty (0 bytes): informational
    assert f["/.git/HEAD"].severity == FindingSeverity.INFO
    assert f["/.git/HEAD"].source_id == "ffuf:sensitive-path-restricted:version-control"
    assert f["/backup.zip"].severity == FindingSeverity.INFO
    assert f["/backup.zip"].source_id == "ffuf:sensitive-path-restricted:backup"


def test_never_above_low_and_no_invented_scores(fake_ffuf):
    for finding in run_fixture().findings:
        assert finding.severity in (FindingSeverity.INFO, FindingSeverity.LOW)
        assert finding.original_severity is None
        assert finding.cwe is None
        assert not re.search(r"cvss|CVE-\d", (finding.evidence or "") + (finding.description or ""), re.I)


def test_original_ffuf_metadata_preserved(fake_ffuf):
    out = run_fixture()
    ftp = _by_path(out)["/ftp"]
    for expected in ("status: 200", "length: 11072 bytes", "words: 1568, lines: 357",
                     "content-type: text/html; charset=utf-8", "response-time: 2.3 ms",
                     "wordlist-entry: ftp", "connected-to: 127.0.0.1", "path-category: file-listing"):
        assert expected in ftp.evidence
    record = next(r for r in out.artifacts["discovered"] if r["path"] == "/ftp")
    assert (record["status"], record["length"], record["words"], record["lines"]) == (200, 11072, 1568, 357)
    assert record["content_type"] == "text/html; charset=utf-8"
    assert out.artifacts["wordlist"]["name"] == "quick"
    assert len(out.artifacts["wordlist"]["sha256"]) == 64


def test_redirect_secrets_redacted_everywhere(fake_ffuf):
    out = run_fixture()
    assets = _by_path(out)["/assets"]
    assert "redirect-location: /assets/?api_key=[REDACTED]" in assets.evidence
    assert "0123456789abcdef" not in out.raw_output
    assert "0123456789abcdef" not in str(out.artifacts)


def test_no_response_body_fields_stored(fake_ffuf):
    _, state = fake_ffuf
    leaky = FIXTURE.replace('"scraper": {}', '"scraper": {"title": "top-secret-page-title"}')
    state["respond"] = lambda argv: proc(leaky, argv=argv)
    out = run_fixture()
    for record in out.artifacts["discovered"]:
        assert set(record) == {"url", "path", "word", "status", "length", "words", "lines", "content_type",
                               "redirect_location", "duration_ms", "connected_ip", "host_header", "category"}
    assert "top-secret-page-title" not in str(out.artifacts) + "".join(f.evidence for f in out.findings)


def test_dedup_key_is_the_path(fake_ffuf):
    out = run_fixture()
    assert _by_path(out)["/ftp"].dedup_key == "ffuf:path:/ftp"


def test_flood_guard_collapses_implausible_results(fake_ffuf):
    import json
    _, state = fake_ffuf
    lines = [json.dumps({"input": {"FUZZ": "eA=="}, "status": 200, "length": 1234, "words": 5, "lines": 1,
                         "content-type": "text/html", "redirectlocation": "", "duration": 1000,
                         "url": f"http://127.0.0.1:8000/p{i}"}) for i in range(60)]
    state["respond"] = lambda argv: proc("\n".join(lines), argv=argv)
    out = run_fixture()
    assert len(out.findings) == 1
    assert out.findings[0].source_id == "ffuf:flood-guard"
    assert out.findings[0].severity == FindingSeverity.INFO
    assert out.artifacts["targets"][0]["flood_guard_triggered"] is True
    assert out.artifacts["discovered_total"] == 60


# --- wordlist ---------------------------------------------------------------------------------------


def _entries():
    return WORDLIST.read_text(encoding="utf-8").splitlines()


def test_wordlist_size_is_about_250():
    assert 200 <= len(_entries()) <= 300


def test_wordlist_entries_are_clean_and_unique():
    entries = _entries()
    assert len({e.lower() for e in entries}) == len(entries)
    for e in entries:
        assert e and e == e.strip(), repr(e)
        assert not e.startswith(("#", "/")), e
        assert ".." not in e and "://" not in e, e
        assert re.fullmatch(r"[A-Za-z0-9._~/-]+", e), e


def test_wordlist_has_no_state_changing_endpoints():
    risky = {"logout", "signout", "install", "setup", "reset", "delete", "remove", "shutdown",
             "restart", "update", "upgrade", "drop", "kill", "purge", "clear"}
    for e in _entries():
        assert e.lower().split("/")[-1].split(".")[0] not in risky, e


def test_only_builtin_wordlists_are_selectable():
    assert set(WORDLISTS) == {"quick"}
    assert WORDLIST.parent == Path(ffuf_mod.__file__).resolve().parent / "wordlists"


def test_ffuf_registered_between_nmap_and_nuclei():
    from app.scanners.registry import PIPELINE_ORDER, SCANNERS
    assert SCANNERS["ffuf"] is FfufScanner
    assert PIPELINE_ORDER.index("nmap") < PIPELINE_ORDER.index("ffuf") < PIPELINE_ORDER.index("nuclei")


def test_tools_endpoint_reports_ffuf_implemented(client, monkeypatch):
    from app.scanners import registry
    monkeypatch.setattr(FfufScanner, "locate", classmethod(lambda cls: FFUF))
    monkeypatch.setattr(registry, "_cached_version", lambda name, path: "2.1.0-dev" if name == "ffuf" else None)
    tools = {t["name"]: t for t in client.get("/api/v1/tools").json()}
    assert tools["ffuf"] == {"name": "ffuf", "display_name": "FFUF", "implemented": True,
                             "available": True, "path": FFUF, "version": "2.1.0-dev"}


# --- wording (regression: "suggests a environment, key or credential file") -------------------


def _record(path, status=200, length=100):
    return {"url": f"http://127.0.0.1:8000{path}", "path": path, "word": path.lstrip("/"),
            "status": status, "length": length, "words": 1, "lines": 1, "content_type": "text/plain",
            "redirect_location": None, "duration_ms": 1.0, "connected_ip": "127.0.0.1",
            "host_header": None, "category": ffuf_mod.classify(path)[0] if ffuf_mod.classify(path) else None}


@pytest.mark.parametrize("status, length", [(200, 100), (403, 0)], ids=["reachable", "restricted"])
def test_secrets_description_wording(status, length):
    description = ffuf_mod.normalize_record(_record("/.env", status, length)).description
    assert "suggests an environment, key, or credential file" in description
    assert "a environment" not in description


def test_every_sensitive_label_uses_the_right_article():
    expected = {
        "version-control": "a version-control metadata directory",
        "secrets": "an environment, key, or credential file",
        "configuration": "a configuration or dependency manifest",
        "backup": "a backup, archive or database dump",
        "logs": "a log file or directory",
        "debug": "a debug, monitoring or diagnostics endpoint",
        "file-listing": "a file store",
        "ide-metadata": "an editor or OS metadata",
    }
    assert {cat: ffuf_mod.with_article(label) for cat, label, _, _ in ffuf_mod.SENSITIVE_RULES} == expected


@pytest.mark.parametrize("path", ["/.git/HEAD", "/.env", "/config.json", "/backup.zip", "/error.log",
                                  "/metrics", "/ftp", "/.idea"])
@pytest.mark.parametrize("status, length", [(200, 100), (403, 0)], ids=["reachable", "restricted"])
def test_no_description_uses_a_before_a_vowel(path, status, length):
    description = ffuf_mod.normalize_record(_record(path, status, length)).description
    assert ffuf_mod.classify(path) is not None, path
    assert not re.search(r"\ba [aeiou]", description, re.I), description
