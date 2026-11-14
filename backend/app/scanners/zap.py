"""OWASP ZAP baseline: spider + PASSIVE scanning only, in a throwaway container.

Uses the official ``zap-baseline.py`` from the ``zaproxy/zap-stable`` image.
No active scan rules run and no attack payloads are sent: ZAP only spiders the
target and passively inspects the responses it receives. Form submission by
the spider is disabled, so it only follows links with GET requests.

Execution:
* ``docker run`` with ``--pull=never`` (the image must already be present),
  all capabilities dropped, no-new-privileges, a memory and PID limit, and a
  per-run named volume for ZAP's report directory. The JSON report is copied
  out with ``docker cp``; the container and volume are always removed, also
  on timeout (killing the docker CLI alone would leave the container running).
* The Docker binary, image and network come from server settings only.

Scope:
* Targets are Nmap's HTTP services (else the Target's base_url), exactly like
  Nuclei/FFUF, and must be on the authorized host.
* Immediately before each run, the full authorization + scope check runs
  again (fresh database state, fresh DNS, IP policy).
* Hostname targets are pinned to the validated IP with ``--add-host``, so
  ZAP's own DNS lookups cannot be rebound. Docker forbids --add-host with a
  ``container:`` network; in that case hostname targets fail closed. IP-literal
  targets need no DNS at all.
* Alert instances on any other host are dropped before storage.

Findings keep ZAP's own risk (0-3 -> info/low/medium/high) and confidence;
ZAP's "false positive" confidence (0) is discarded. No CVSS is invented.
Evidence snippets are redacted and truncated.
"""

import html
import json
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.core.scope import ScopeError, check_ip_allowed, resolve_host, validate_host
from app.models.finding import FindingSeverity
from app.scanners.base import (
    BaseScanner,
    NormalizedFinding,
    ScanContext,
    ScannerError,
    ScannerOutput,
)
from app.scanners.ffuf import _same_host, pin_target
from app.scanners.process import SAFE_PATH, ProcessResult, _minimal_env, run_tool
from app.services.redaction import redact

REPORT_NAME = "zap-report.json"
WORK_DIR = "/zap/wrk"
# zap-baseline exit codes: 0 pass, 1 FAIL alerts, 2 WARN alerts, 3 other failure.
OK_EXIT_CODES = {0, 1, 2}
# Spider config: never submit forms (GET link-following only).
ZAP_CONFIG = [
    "-config", "spider.postForm=false",
    "-config", "spider.processForm=false",
]
RISK_MAP = {
    "0": FindingSeverity.INFO,
    "1": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
}
CONFIDENCE_MAP = {"1": "low", "2": "medium", "3": "high", "4": "high"}  # "0" = false positive
MAX_INSTANCES = 10
MAX_TEXT = 2000
MAX_SNIPPET = 200
_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"https?://[^\s<>\"']+")


class ZapOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Minutes the traditional spider may crawl before passive analysis finishes.
    spider_minutes: int = Field(default=1, ge=1, le=5)
    # Max minutes to wait for ZAP to start and the passive scanner to drain.
    passive_wait_minutes: int = Field(default=5, ge=1, le=10)


def _docker_path() -> str | None:
    configured = settings.zap_docker_path
    if configured:
        p = Path(configured)
        return configured if p.is_absolute() and p.is_file() else None
    return shutil.which("docker", path=SAFE_PATH)


def _docker(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, env=_minimal_env())


def html_to_text(value: str | None, limit: int = MAX_TEXT) -> str | None:
    if not value:
        return None
    text = html.unescape(_TAG.sub("\n", value))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return (text[:limit] + "...") if len(text) > limit else (text or None)


def _clip(value: Any, limit: int = MAX_SNIPPET) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    text, _ = redact(text)
    return (text[:limit] + "...") if len(text) > limit else text


class ZapScanner(BaseScanner):
    name = "zap"
    display_name = "OWASP ZAP"
    executable_name = "docker"
    Options = ZapOptions

    # --- discovery ----------------------------------------------------------------
    @classmethod
    def locate(cls) -> str | None:
        """Docker CLI path, but only if the ZAP image is already present locally."""
        docker = _docker_path()
        if docker is None:
            return None
        try:
            proc = _docker([docker, "image", "inspect", "--format", "{{.Id}}", settings.zap_docker_image])
        except (OSError, subprocess.TimeoutExpired):
            return None
        return docker if proc.returncode == 0 else None

    @classmethod
    def version(cls, path: str) -> str | None:
        try:
            proc = _docker([path, "image", "inspect", "--format",
                            '{{index .Config.Labels "org.opencontainers.image.version"}}|{{.Id}}',
                            settings.zap_docker_image])
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        label, _, image_id = proc.stdout.strip().partition("|")
        return label if label and label != "<no value>" else image_id.removeprefix("sha256:")[:12]

    def timeout_seconds(self, ctx: ScanContext) -> int:
        opts: ZapOptions = ctx.options  # type: ignore[assignment]
        budget = (opts.spider_minutes + opts.passive_wait_minutes) * 60 + 180
        return min(settings.zap_timeout_seconds, budget)

    # --- targets / scope ----------------------------------------------------------
    def targets(self, ctx: ScanContext) -> list[str]:
        urls = [svc["url"] for svc in (ctx.previous.get("nmap") or {}).get("http_services", [])
                if svc.get("url")]
        if not urls:
            urls.append(ctx.base_url or ctx.target_url)
        in_scope = []
        for url in dict.fromkeys(urls):
            if not _same_host(url, ctx.host):
                raise ScannerError(f"refusing out-of-scope URL for zap: {url}")
            in_scope.append(url)
        return in_scope

    def fresh_scope_ips(self, ctx: ScanContext) -> list[str]:
        if ctx.revalidate is not None:
            scope = ctx.revalidate()
            if validate_host(scope.host) != validate_host(ctx.host):
                raise ScopeError("target host changed since the assessment started")
            return list(scope.ips)
        ips = resolve_host(ctx.host)
        if not ips:
            raise ScopeError(f"host '{ctx.host}' resolved to no addresses")
        for ip in ips:
            check_ip_allowed(ip, settings.allow_private_targets)
        return [ip.compressed for ip in ips]

    # --- commands -----------------------------------------------------------------
    def build_command(self, ctx: ScanContext, url: str | None = None, pinned_ip: str | None = None,
                      container: str = "autopentest-zap", volume: str = "autopentest-zap") -> list[str]:
        opts: ZapOptions = ctx.options  # type: ignore[assignment]
        url = url or self.targets(ctx)[0]
        hostname = urlsplit(url).hostname or ""
        network = settings.zap_docker_network.strip()
        argv = [
            self.executable_path, "run",
            "--name", container,
            "--pull=never",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", settings.zap_memory,
            "--pids-limit", "1024",
            "-v", f"{volume}:{WORK_DIR}:rw",
        ]
        if network:
            argv += ["--network", network]
        if pinned_ip and pinned_ip != validate_host(hostname):
            if network.startswith("container:"):
                raise ScopeError(
                    "cannot pin a hostname target's DNS inside a shared container network "
                    f"({network}); refusing to run zap for '{hostname}'"
                )
            argv += ["--add-host", f"{hostname}:{pinned_ip}"]
        argv += [
            settings.zap_docker_image,
            "zap-baseline.py",
            "-t", url,
            "-m", str(opts.spider_minutes),
            "-T", str(opts.passive_wait_minutes),
            "-J", REPORT_NAME,
            "-I",          # warnings do not turn into a failing exit code
            "-s",          # short output
            "-z", " ".join(ZAP_CONFIG),
        ]
        return argv

    def _cleanup(self, container: str, volume: str) -> bool:
        ok = True
        for argv in ([self.executable_path, "rm", "-f", container],
                     [self.executable_path, "volume", "rm", "-f", volume]):
            try:
                ok = _docker(argv, timeout=60).returncode == 0 and ok
            except (OSError, subprocess.TimeoutExpired):
                ok = False
        return ok

    # --- execution ----------------------------------------------------------------
    def run(self, ctx: ScanContext) -> ScannerOutput:
        urls = self.targets(ctx)
        commands, target_reports, findings, raw_parts = [], [], [], []
        dropped_total = false_positives = 0
        zap_version = None

        for index, url in enumerate(urls):
            # Fresh authorization + DNS + IP policy check immediately before execution.
            target = pin_target(url, ctx.host, ctx.ips, self.fresh_scope_ips(ctx))
            run_id = uuid.uuid4().hex[:12]
            container, volume = f"autopentest-zap-{run_id}", f"autopentest-zap-{run_id}"
            argv = self.build_command(ctx, url, target.ip, container, volume)
            commands.append(argv)
            cleaned = False
            try:
                process = run_tool(argv, timeout=self.timeout_seconds(ctx),
                                   max_output_bytes=settings.max_tool_output_bytes)
                if process.timed_out:
                    raise ScannerError(f"ZAP timed out after {self.timeout_seconds(ctx)}s on {url}", process)
                if process.exit_code not in OK_EXIT_CODES:
                    tail = (process.stderr or process.stdout).strip()[-2000:] or "no output"
                    raise ScannerError(f"zap-baseline exited with code {process.exit_code}: {tail}", process)
                with tempfile.TemporaryDirectory(prefix="autopentest-zap-") as tmp:
                    dest = Path(tmp) / REPORT_NAME
                    copy = run_tool([self.executable_path, "cp", f"{container}:{WORK_DIR}/{REPORT_NAME}",
                                     str(dest)], timeout=60, max_output_bytes=100_000)
                    if copy.exit_code != 0 or not dest.is_file():
                        raise ScannerError(f"could not retrieve the ZAP report: {copy.stderr.strip()[-500:]}",
                                           process)
                    report_text = dest.read_text(encoding="utf-8", errors="replace")
            finally:
                cleaned = self._cleanup(container, volume)

            try:
                report = json.loads(report_text)
            except json.JSONDecodeError as exc:
                raise ScannerError(f"could not parse the ZAP JSON report: {exc}", process) from exc
            zap_version = report.get("@version") or zap_version
            target_findings, stats = parse_report(report, ctx.host, target.origin)
            findings.extend(target_findings)
            dropped_total += stats["out_of_scope_instances"]
            false_positives += stats["false_positives_discarded"]
            raw_parts.append(report_text)
            target_reports.append({
                "url": url, "container": container, "network": settings.zap_docker_network or "bridge",
                "pinned_ip": target.ip,
                "add_host": None if target.host_header is None else f"{urlsplit(url).hostname}:{target.ip}",
                "exit_code": process.exit_code, "cleanup_ok": cleaned, **stats,
            })
            ctx.report_progress(10 + int(85 * (index + 1) / len(urls)))

        raw_output, _ = redact("\n".join(raw_parts)[: settings.max_tool_output_bytes])
        artifacts = {
            "zap_version": zap_version,
            "image": settings.zap_docker_image,
            "mode": "baseline (spider + passive scan only; no active scan, no form submission)",
            "targets": target_reports,
            "commands": commands,
            "alerts": len(findings),
            "findings_by_risk": _count(f.severity.value for f in findings),
            "out_of_scope_instances_dropped": dropped_total,
            "false_positives_discarded": false_positives,
        }
        return ScannerOutput(findings=findings, artifacts=artifacts, raw_output=raw_output or "",
                             exit_code=0, command=commands[0] if commands else [self.executable_path])

    def parse(self, process: ProcessResult, ctx: ScanContext) -> ScannerOutput:
        """Parse a JSON report given as process stdout (run() normally does this)."""
        report = json.loads(process.stdout)
        origin = pin_target(self.targets(ctx)[0], ctx.host, ctx.ips, ctx.ips).origin
        findings, stats = parse_report(report, ctx.host, origin)
        return ScannerOutput(findings=findings, artifacts=stats, raw_output=process.stdout,
                             exit_code=process.exit_code, command=process.argv)


# --- parsing (module level so it can be unit-tested directly) ---------------------------


def _count(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def parse_report(report: dict[str, Any], host: str, origin: str) -> tuple[list[NormalizedFinding], dict[str, int]]:
    findings: list[NormalizedFinding] = []
    stats = {"sites": 0, "alerts_total": 0, "out_of_scope_instances": 0,
             "false_positives_discarded": 0, "out_of_scope_sites": 0}
    for site in report.get("site") or []:
        stats["sites"] += 1
        site_name = str(site.get("@name") or "")
        if not _same_host(site_name, host):
            stats["out_of_scope_sites"] += 1
            continue
        for alert in site.get("alerts") or []:
            stats["alerts_total"] += 1
            nf, dropped = normalize_alert(alert, host, origin)
            stats["out_of_scope_instances"] += dropped
            if nf is None:
                if str(alert.get("confidence")) == "0":
                    stats["false_positives_discarded"] += 1
                continue
            findings.append(nf)
    return findings, stats


def normalize_alert(alert: dict[str, Any], host: str, origin: str) -> tuple[NormalizedFinding | None, int]:
    """One ZAP alert -> finding. Returns (finding or None, out-of-scope instances dropped)."""
    plugin = str(alert.get("pluginid") or "").strip()
    name = (alert.get("alert") or alert.get("name") or "").strip()
    confidence_code = str(alert.get("confidence") or "")
    if not plugin or not name:
        return None, 0
    instances = alert.get("instances") or []
    in_scope = [i for i in instances if _same_host(str(i.get("uri") or ""), host)]
    dropped = len(instances) - len(in_scope)
    if confidence_code == "0" or (instances and not in_scope):
        return None, dropped  # ZAP-marked false positive, or nothing on our host

    risk_code = str(alert.get("riskcode") or "0")
    alert_ref = str(alert.get("alertRef") or plugin)
    evidence = [
        f"zap-plugin: {plugin} (alertRef {alert_ref})",
        f"risk (confidence): {alert.get('riskdesc') or risk_code}",
        f"instances: {len(in_scope)}" + (f" (showing {MAX_INSTANCES})" if len(in_scope) > MAX_INSTANCES else ""),
    ]
    for inst in in_scope[:MAX_INSTANCES]:
        line = f"- {inst.get('method') or 'GET'} {_clip(inst.get('uri'), 300)}"
        for key in ("param", "evidence", "otherinfo"):
            if inst.get(key):
                line += f" | {key}: {_clip(inst.get(key))}"
        evidence.append(line)
    if alert.get("otherinfo"):
        evidence.append(f"other-info: {_clip(html_to_text(alert.get('otherinfo')), 500)}")
    cwe = str(alert.get("cweid") or "").strip()
    references = list(dict.fromkeys(_URL.findall(str(alert.get("reference") or ""))))[:10]

    return NormalizedFinding(
        title=name,
        severity=RISK_MAP.get(risk_code, FindingSeverity.INFO),
        dedup_key=f"zap:{plugin}:{alert_ref}",
        location=origin,
        description=html_to_text(alert.get("desc")),
        recommendation=html_to_text(alert.get("solution")),
        evidence="\n".join(evidence),
        original_severity=(alert.get("riskdesc") or None),
        confidence=CONFIDENCE_MAP.get(confidence_code),
        source_id=f"zap:{plugin}",
        cwe=f"CWE-{cwe}" if cwe.isdigit() and int(cwe) > 0 else None,
        references=references,
    ), dropped
