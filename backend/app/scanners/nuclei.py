"""Nuclei: template-based vulnerability scanning of discovered web services.

Targets come from Nmap's HTTP services in the same assessment (falling back to
the Target's base_url). Every URL must be on the authorized host.

Conservative defaults:
* HTTP templates only (-pt http): no code/javascript/file/headless/network.
* Intrusive categories excluded (-etags dos,fuzz,intrusive,bruteforce,...).
* No out-of-band callbacks to public interactsh servers (-ni).
* No redirects (-dr), so a redirect can never lead the scan off-scope.
* Signed templates only (-dut); no update checks during scans (-duc).
* Rate limited (default 50 req/s), single host, modest concurrency.
* Request/response bodies are omitted from output (-or), keeping cookies and
  response data out of the database; evidence is matcher + extracted values.
* When private targets are NOT allowed, -lna additionally stops templates from
  reaching any local/private network address.
"""

import json
import re
import subprocess
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.core.scope import validate_host
from app.models.finding import FindingSeverity
from app.scanners.base import (
    BaseScanner,
    NormalizedFinding,
    ScanContext,
    ScannerError,
    ScannerOutput,
)
from app.scanners.process import ProcessResult, run_tool

EXCLUDED_TAGS = [
    "dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force",
    "default-login", "osint", "headless",
]
QUICK_PROFILE_TAGS = ["misconfig", "exposure", "tech", "panel", "headers"]

SEVERITY_MAP = {
    "info": FindingSeverity.INFO,
    "low": FindingSeverity.LOW,
    "medium": FindingSeverity.MEDIUM,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}
Severity = Literal["info", "low", "medium", "high", "critical"]
MAX_EXTRACTED = 10
MAX_EXTRACTED_CHARS = 300


class NucleiOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # quick: misconfiguration/exposure/technology/panel/header templates (demo-friendly)
    # standard: every non-intrusive HTTP template (~10k, slower)
    profile: Literal["quick", "standard"] = "quick"
    severities: list[Severity] = Field(
        default_factory=lambda: ["info", "low", "medium", "high", "critical"], min_length=1
    )
    rate_limit: int = Field(default=50, ge=1, le=150)  # requests per second
    request_timeout: int = Field(default=10, ge=1, le=30)  # seconds per request


class NucleiScanner(BaseScanner):
    name = "nuclei"
    display_name = "Nuclei"
    executable_name = "nuclei"
    Options = NucleiOptions

    def __init__(self, executable_path: str):
        super().__init__(executable_path)
        self._latest_percent: int | None = None
        self._latest_stats: dict[str, Any] = {}
        self._targets: list[str] = []

    @classmethod
    def version(cls, path: str) -> str | None:
        try:
            proc = subprocess.run(
                [path, "-version", "-duc"], capture_output=True, text=True,
                timeout=20, stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"Engine Version:\s*v?(\S+)", proc.stdout + proc.stderr)
        return match.group(1).replace("\x1b[0m", "") if match else None

    def timeout_seconds(self, ctx: ScanContext) -> int:
        return settings.nuclei_timeout_seconds

    # --- targets ----------------------------------------------------------------
    def targets(self, ctx: ScanContext) -> list[str]:
        """In-scope URLs: Nmap's HTTP services, else the Target's own URL."""
        urls: list[str] = []
        for svc in (ctx.previous.get("nmap") or {}).get("http_services", []):
            if svc.get("url"):
                urls.append(svc["url"])
        if not urls:
            urls.append(ctx.base_url or ctx.target_url)
        in_scope = []
        for url in dict.fromkeys(urls):  # dedupe, keep order
            if not _same_host(url, ctx.host):
                raise ScannerError(f"refusing out-of-scope URL for nuclei: {url}")
            in_scope.append(url)
        return in_scope

    def build_command(self, ctx: ScanContext) -> list[str]:
        opts: NucleiOptions = ctx.options  # type: ignore[assignment]
        argv = [
            self.executable_path,
            "-jsonl", "-omit-raw", "-omit-template", "-silent", "-no-color",
            "-disable-update-check", "-no-interactsh", "-disable-redirects",
            "-disable-unsigned-templates",
            "-type", "http",
            "-exclude-tags", ",".join(EXCLUDED_TAGS),
            "-severity", ",".join(opts.severities),
            "-rate-limit", str(opts.rate_limit),
            "-concurrency", "10",
            "-bulk-size", "1",
            "-timeout", str(opts.request_timeout),
            "-retries", "1",
            "-max-host-error", "30",
            "-stats", "-stats-json", "-stats-interval", "5",
        ]
        if opts.profile == "quick":
            argv += ["-tags", ",".join(QUICK_PROFILE_TAGS)]
        if not settings.allow_private_targets:
            argv.append("-restrict-local-network-access")
        self._targets = self.targets(ctx)
        for url in self._targets:
            argv += ["-target", url]
        return argv

    # --- execution with live progress -------------------------------------------
    def _on_line(self, stream: str, line: str) -> None:
        """Reader thread: remember the latest stats line (never touches the DB)."""
        if not line.startswith("{") or '"percent"' not in line:
            return
        stats = json.loads(line)
        if "template-id" in stats:  # a finding, not a stats line
            return
        self._latest_stats = stats
        self._latest_percent = int(float(stats.get("percent", 0)))

    def run(self, ctx: ScanContext) -> ScannerOutput:
        argv = self.build_command(ctx)

        def tick() -> None:  # calling thread: safe to persist progress
            if self._latest_percent is not None:
                ctx.report_progress(10 + int(self._latest_percent * 0.85))

        process = run_tool(
            argv,
            timeout=self.timeout_seconds(ctx),
            max_output_bytes=settings.max_tool_output_bytes,
            on_line=self._on_line,
            on_tick=tick,
        )
        if process.timed_out:
            raise ScannerError(
                f"Nuclei timed out after {self.timeout_seconds(ctx)}s", process
            )
        return self.parse(process, ctx)

    # --- parsing ------------------------------------------------------------------
    def parse(self, process: ProcessResult, ctx: ScanContext) -> ScannerOutput:
        if process.exit_code != 0:
            tail = _strip_ansi(process.stderr).strip()[-2000:] or "no error output"
            raise ScannerError(f"nuclei exited with code {process.exit_code}: {tail}", process)
        results, invalid = parse_jsonl(process.stdout)
        findings, dropped = [], 0
        for result in results:
            nf = normalize_result(result)
            if nf is None:
                continue
            if not _same_host(nf.location or "", ctx.host):
                dropped += 1  # defense in depth: never store off-scope results
                continue
            findings.append(nf)
        artifacts = {
            "targets": self._targets,
            "results": len(results),
            "findings_by_template": _count_by(findings, lambda f: f.source_id),
            "invalid_lines": invalid,
            "out_of_scope_dropped": dropped,
            "last_stats": self._latest_stats or None,
            "output_truncated": process.truncated,
        }
        return ScannerOutput(
            findings=findings,
            artifacts=artifacts,
            raw_output=process.stdout,
            exit_code=process.exit_code,
            command=process.argv,
        )


# --- helpers (module level so they can be unit-tested directly) -------------------

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def _same_host(url_or_host: str, host: str) -> bool:
    if not url_or_host:
        return False
    candidate = url_or_host if "://" in url_or_host else f"//{url_or_host}"
    hostname = urlsplit(candidate).hostname
    if not hostname:
        return False
    try:
        return validate_host(hostname) == validate_host(host)
    except ValueError:
        return False


def _count_by(items, key) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = key(item) or "unknown"
        out[k] = out.get(k, 0) + 1
    return out


def parse_jsonl(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse nuclei JSONL; returns (finding objects, count of invalid lines)."""
    results, invalid = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if isinstance(obj, dict) and obj.get("template-id"):
            results.append(obj)
    return results, invalid


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()] if "," in value else [value]
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def map_severity(raw: str | None) -> FindingSeverity:
    return SEVERITY_MAP.get((raw or "").strip().lower(), FindingSeverity.INFO)


def normalize_result(result: dict[str, Any]) -> NormalizedFinding | None:
    template_id = result.get("template-id")
    info = result.get("info") or {}
    location = result.get("matched-at") or result.get("url") or result.get("host")
    if not template_id or not location:
        return None
    raw_severity = info.get("severity")
    matcher = result.get("matcher-name")
    classification = info.get("classification") or {}

    cves = _as_list(classification.get("cve-id"))
    cwes = _as_list(classification.get("cwe-id"))
    extracted = [str(x)[:MAX_EXTRACTED_CHARS] for x in (result.get("extracted-results") or [])][:MAX_EXTRACTED]

    evidence = [f"matched-at: {location}", f"template: {template_id}"]
    if matcher:
        evidence.append(f"matcher: {matcher}")
    if extracted:
        evidence.append("extracted: " + "; ".join(extracted))
    if cves:
        evidence.append("cve: " + ", ".join(cves))
    if classification.get("cvss-score") is not None:
        metrics = classification.get("cvss-metrics")
        evidence.append(f"cvss: {classification['cvss-score']}" + (f" ({metrics})" if metrics else ""))
    if result.get("type"):
        evidence.append(f"protocol: {result['type']}")

    name = info.get("name") or template_id
    references = _as_list(info.get("reference"))
    references += [f"https://nvd.nist.gov/vuln/detail/{c.upper()}" for c in cves if c.upper().startswith("CVE-")]

    description = (info.get("description") or "").strip() or None
    if info.get("impact"):
        description = f"{description or ''}\n\nImpact: {info['impact'].strip()}".strip()

    return NormalizedFinding(
        title=f"{name} ({matcher})" if matcher else name,
        severity=map_severity(raw_severity),
        dedup_key=f"nuclei:{template_id}:{matcher or ''}",
        location=location,
        description=description,
        recommendation=(info.get("remediation") or "").strip() or None,
        evidence="\n".join(evidence),
        original_severity=raw_severity,
        confidence=None,  # nuclei reports matches, not confidence levels
        source_id=template_id,
        cwe=",".join(c.upper() for c in cwes) or None,
        references=list(dict.fromkeys(references)),
    )
