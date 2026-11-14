"""FFUF: conservative, wordlist-based content discovery on authorized web services.

Targets come from Nmap's HTTP services in the same assessment (falling back to
the Target's base_url), exactly like Nuclei. Every URL must be on the
authorized host.

Conservative by design:
* GET only, a curated built-in wordlist (no client-supplied files), no
  recursion, no redirects followed, rate limited, small thread count, hard
  per-run time limit (-maxtime) plus a process timeout.
* Auto-calibration (-ac) filters catch-all responses (e.g. single-page apps
  that answer 200 for every path), and a flood guard turns an implausible
  number of hits into one "inconclusive" finding instead of hundreds.
* Response bodies are never collected: FFUF's JSON records carry only status,
  size, word/line counts, content type and redirect location.

DNS-rebinding protection:
* Immediately before each FFUF execution the full authorization + scope check
  runs again (fresh database state, fresh DNS resolution, IP policy).
* FFUF is then pointed at the validated IP address itself, with the original
  hostname sent as the Host header and as TLS SNI (-sni). FFUF therefore never
  resolves DNS, and redirects are not followed, so it cannot be steered to a
  different address mid-scan. If the fresh resolution no longer overlaps the
  addresses approved for this run, the scan fails closed (ScopeError).
* IP-literal targets (e.g. 127.0.0.1) involve no DNS at all.

Isolation: FFUF reads ~/.config/ffuf (config, calibration) and writes scan
history there. Each run gets a throwaway HOME/XDG_CONFIG_HOME that is deleted
afterwards, so the user's own FFUF configuration and history are never read
or modified.

Severity policy: an ordinary discovered path is informational. A path that
merely *looks* sensitive is low at most, and only when it returned a non-empty
2xx response; it is informational when access-controlled, redirected or empty.
FFUF never sees content, so it never claims a confirmed exposure, never
assigns medium or higher, and never invents CVSS scores or CVEs.
"""

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
from app.scanners.process import ProcessResult, _minimal_env, run_tool
from app.services.redaction import redact

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
WORDLISTS: dict[str, Path] = {"quick": WORDLIST_DIR / "quick.txt"}
# FFUF's default matcher minus 500: server errors are noise for discovery.
MATCH_CODES = "200-299,301,302,307,401,403,405"
USER_AGENT = "AutoPentest-AI/0.4 (authorized security assessment)"
MAX_FINDINGS_PER_TARGET = 50  # more hits than this => calibration likely failed
MAX_DISCOVERED_ARTIFACTS = 500
_EXTENSION = re.compile(r"^\.[a-z0-9]{1,8}$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_PROGRESS = re.compile(r"Progress: \[(\d+)/(\d+)\].*?Errors: (\d+)")

# (category, human label, pattern on the lowercased URL path, remediation)
SENSITIVE_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("version-control", "version-control metadata directory",
     re.compile(r"/\.(git|svn|hg|bzr)(/|$)"),
     "Block web access to version-control directories and remove them from deployed web roots."),
    ("secrets", "environment, key, or credential file",
     re.compile(r"/(\.env[\w.-]*|\.htpasswd|\.npmrc|encryptionkeys|secrets?)(/|$)|\.(pem|key)$"),
     "Remove secret and credential files from the web root. If exposure is confirmed, rotate "
     "every secret they contained."),
    ("configuration", "configuration or dependency manifest",
     re.compile(r"/(web\.config|config\.(php|json|ya?ml)|wp-config\.php|application\.(properties|ya?ml)"
                r"|docker-compose\.ya?ml|dockerfile|composer\.(json|lock)|package(-lock)?\.json"
                r"|yarn\.lock|\.htaccess|\.dockerignore|\.gitignore)$"),
     "Do not serve configuration or build files; restrict them at the web server or remove them "
     "from the deployed web root."),
    ("backup", "backup, archive or database dump",
     re.compile(r"\.(bak|old|orig|backup|swp|sql|sqlite|db|tar|tgz|gz|zip|7z|rar)$"
                r"|/(backup|backups|dump|archive)(/|$)"),
     "Remove backups, archives and dumps from the web root and store them outside public paths."),
    ("logs", "log file or directory",
     re.compile(r"\.log$|/logs?(/|$)"),
     "Store logs outside the web root and deny HTTP access to them."),
    ("debug", "debug, monitoring or diagnostics endpoint",
     re.compile(r"/(server-status|server-info|phpinfo\.php|info\.php|actuator(/[\w-]+)?|metrics"
                r"|_?debug|trace\.axd|elmah\.axd|console|graphiql)$"),
     "Disable diagnostics endpoints in production or restrict them to trusted networks with "
     "authentication."),
    ("file-listing", "file store",
     re.compile(r"/ftp(/|$)"),
     "Disable directory listings and require authorization for file downloads."),
    ("ide-metadata", "editor or OS metadata",
     re.compile(r"/(\.idea|\.vscode|\.ds_store|\.bash_history)(/|$)"),
     "Remove editor, shell and OS metadata files from the deployed web root."),
]


class FfufOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Only named, built-in wordlists: API clients can never supply file paths.
    wordlist: Literal["quick"] = "quick"
    # Extra extensions appended to every word (each multiplies the request count).
    extensions: list[str] = Field(default_factory=list, max_length=5)
    rate_limit: int = Field(default=20, ge=1, le=100)  # requests per second
    threads: int = Field(default=5, ge=1, le=20)
    request_timeout: int = Field(default=10, ge=1, le=30)  # seconds per request
    max_time: int = Field(default=300, ge=10, le=1800)  # seconds per FFUF run

    @field_validator("extensions")
    @classmethod
    def _valid_extensions(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for ext in value:
            ext = ext.strip().lower()
            if not _EXTENSION.match(ext):
                raise ValueError("extensions must look like '.bak' (a dot and 1-8 letters/digits)")
            if ext not in out:
                out.append(ext)
        return out


@dataclass(frozen=True)
class PinnedTarget:
    """One web service, with the connection pinned to a validated IP."""

    url: str           # logical URL as authorized (hostname), no trailing slash
    origin: str        # scheme://host[:port] of the logical URL
    connect_base: str  # same URL with the host replaced by the validated IP
    ip: str
    host_header: str | None  # sent only when the URL host is a hostname
    sni: str | None          # https + hostname only


def isolated_env(home: str) -> dict[str, str]:
    return {"HOME": home, "XDG_CONFIG_HOME": f"{home}/.config"}


@lru_cache(maxsize=8)
def wordlist_info(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    entries = [ln for ln in data.decode("utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    return {"path_name": path.name, "entries": len(entries), "sha256": hashlib.sha256(data).hexdigest()}


def _same_host(url_or_host: str, host: str) -> bool:
    if not url_or_host:
        return False
    candidate = url_or_host if "://" in url_or_host else f"//{url_or_host}"
    try:
        hostname = urlsplit(candidate).hostname
        return bool(hostname) and validate_host(hostname) == validate_host(host)
    except ValueError:
        return False


def pin_target(url: str, host: str, approved_ips: list[str], fresh_ips: list[str]) -> PinnedTarget:
    """Bind a logical URL to an IP that is both freshly resolved and approved.

    Raises ScannerError for malformed/out-of-scope URLs and ScopeError when DNS
    no longer points at an address approved for this run (fail closed).
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScannerError(f"refusing non-http(s) URL for ffuf: {url}")
    if not _same_host(url, host):
        raise ScannerError(f"refusing out-of-scope URL for ffuf: {url}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScannerError(f"invalid port in URL for ffuf: {url}") from exc
    default_port = 443 if parts.scheme == "https" else 80
    port = port or default_port
    port_part = "" if port == default_port else f":{port}"
    path = parts.path.rstrip("/")
    hostname = validate_host(parts.hostname)
    origin = f"{parts.scheme}://{'[' + hostname + ']' if ':' in hostname else hostname}{port_part}"

    approved = {validate_host(ip) for ip in approved_ips}
    fresh = [validate_host(ip) for ip in fresh_ips]
    candidates = [ip for ip in fresh if ip in approved]
    if not candidates:
        raise ScopeError(
            f"'{hostname}' no longer resolves to an address approved for this run "
            "(possible DNS change/rebinding); refusing to run ffuf"
        )
    is_ip_literal = hostname in fresh and hostname in approved and _is_ip(hostname)
    ip = hostname if is_ip_literal else candidates[0]
    ip_host = f"[{ip}]" if ":" in ip else ip
    return PinnedTarget(
        url=f"{origin}{path}",
        origin=origin,
        connect_base=f"{parts.scheme}://{ip_host}{port_part}{path}",
        ip=ip,
        host_header=None if is_ip_literal else f"{hostname}{port_part}",
        sni=hostname if (parts.scheme == "https" and not is_ip_literal) else None,
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class FfufScanner(BaseScanner):
    name = "ffuf"
    display_name = "FFUF"
    executable_name = "ffuf"
    Options = FfufOptions

    @classmethod
    def version(cls, path: str) -> str | None:
        try:
            with tempfile.TemporaryDirectory(prefix="autopentest-ffuf-") as home:
                proc = subprocess.run(
                    [path, "-V"], capture_output=True, text=True, timeout=10,
                    stdin=subprocess.DEVNULL, env=_minimal_env(isolated_env(home)),
                )
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"ffuf version:\s*(\S+)", proc.stdout + proc.stderr)
        return match.group(1) if match else None

    def timeout_seconds(self, ctx: ScanContext) -> int:
        opts: FfufOptions = ctx.options  # type: ignore[assignment]
        return min(settings.ffuf_timeout_seconds, opts.max_time + 60)

    # --- targets ----------------------------------------------------------------
    def targets(self, ctx: ScanContext) -> list[str]:
        """In-scope URLs: Nmap's HTTP services, else the Target's own URL."""
        urls = [svc["url"] for svc in (ctx.previous.get("nmap") or {}).get("http_services", [])
                if svc.get("url")]
        if not urls:
            urls.append(ctx.base_url or ctx.target_url)
        in_scope = []
        for url in dict.fromkeys(urls):
            if not _same_host(url, ctx.host):
                raise ScannerError(f"refusing out-of-scope URL for ffuf: {url}")
            in_scope.append(url)
        return in_scope

    def fresh_scope_ips(self, ctx: ScanContext) -> list[str]:
        """Re-run authorization + scope checks right now; return validated IPs."""
        if ctx.revalidate is not None:
            scope = ctx.revalidate()  # raises ScopeError if no longer allowed
            if validate_host(scope.host) != validate_host(ctx.host):
                raise ScopeError("target host changed since the assessment started")
            return list(scope.ips)
        ips = resolve_host(ctx.host)
        if not ips:
            raise ScopeError(f"host '{ctx.host}' resolved to no addresses")
        for ip in ips:
            check_ip_allowed(ip, settings.allow_private_targets)
        return [ip.compressed for ip in ips]

    def build_command(self, ctx: ScanContext, target: PinnedTarget | None = None) -> list[str]:
        opts: FfufOptions = ctx.options  # type: ignore[assignment]
        if target is None:
            target = pin_target(self.targets(ctx)[0], ctx.host, ctx.ips, ctx.ips)
        wordlist = WORDLISTS[opts.wordlist]
        argv = [
            self.executable_path,
            "-u", f"{target.connect_base}/FUZZ",
            "-w", str(wordlist),
            "-json", "-noninteractive", "-ic",
            "-ac",                      # calibrate away catch-all responses
            "-X", "GET",
            "-t", str(opts.threads),
            "-rate", str(opts.rate_limit),
            "-timeout", str(opts.request_timeout),
            "-maxtime", str(opts.max_time),
            "-mc", MATCH_CODES,
            "-H", f"User-Agent: {USER_AGENT}",
        ]
        if target.host_header:
            argv += ["-H", f"Host: {target.host_header}"]
        if target.sni:
            argv += ["-sni", target.sni]
        if opts.extensions:
            argv += ["-e", ",".join(opts.extensions)]
        return argv

    # --- execution --------------------------------------------------------------
    def run(self, ctx: ScanContext) -> ScannerOutput:
        opts: FfufOptions = ctx.options  # type: ignore[assignment]
        wordlist = WORDLISTS[opts.wordlist]
        if not wordlist.is_file():
            raise ScannerError(f"built-in wordlist '{opts.wordlist}' is missing")
        urls = self.targets(ctx)

        commands: list[list[str]] = []
        raw_parts: list[str] = []
        target_reports: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        findings: list[NormalizedFinding] = []
        invalid_total = dropped_total = 0
        truncated = False

        for index, url in enumerate(urls):
            # Fresh authorization + DNS + IP-policy check immediately before execution.
            target = pin_target(url, ctx.host, ctx.ips, self.fresh_scope_ips(ctx))
            argv = self.build_command(ctx, target)
            commands.append(argv)
            with tempfile.TemporaryDirectory(prefix="autopentest-ffuf-") as home:
                process = run_tool(
                    argv,
                    timeout=self.timeout_seconds(ctx),
                    max_output_bytes=settings.max_tool_output_bytes,
                    env_overrides=isolated_env(home),
                )
            if process.timed_out:
                raise ScannerError(f"FFUF timed out after {self.timeout_seconds(ctx)}s on {target.url}", process)
            if process.exit_code != 0:
                tail = _clean_stderr(process.stderr)[-2000:] or "no error output"
                raise ScannerError(f"ffuf exited with code {process.exit_code}: {tail}", process)

            results, invalid = parse_jsonl(process.stdout)
            target_records, dropped = [], 0
            for result in results:
                record = to_record(result, target)
                if record is None:
                    dropped += 1  # defense in depth: never store off-target results
                    continue
                target_records.append(record)

            flood = len(target_records) > MAX_FINDINGS_PER_TARGET
            if flood:
                findings.append(flood_finding(target, target_records))
            else:
                findings.extend(normalize_record(r) for r in target_records)

            stats = parse_progress(process.stderr)
            target_reports.append({
                "url": target.url,
                "connect_url": target.connect_base,
                "pinned_ip": target.ip,
                "host_header": target.host_header,
                "sni": target.sni,
                "results": len(target_records),
                "flood_guard_triggered": flood,
                **stats,
            })
            records.extend(target_records)
            raw_parts.append(process.stdout)
            invalid_total += invalid
            dropped_total += dropped
            truncated = truncated or process.truncated
            ctx.report_progress(10 + int(85 * (index + 1) / len(urls)))

        artifacts = {
            "targets": target_reports,
            "commands": commands,
            "wordlist": {"name": opts.wordlist, **wordlist_info(wordlist)},
            "extensions": opts.extensions,
            "match_codes": MATCH_CODES,
            "discovered_total": len(records),
            "discovered": records[:MAX_DISCOVERED_ARTIFACTS],
            "findings_by_kind": _count_by(findings, lambda f: f.source_id),
            "invalid_lines": invalid_total,
            "out_of_scope_dropped": dropped_total,
            "output_truncated": truncated,
            "config_isolated": True,
        }
        # Redirect locations can carry tokens: redact the stored raw output too.
        raw_output, _ = redact("".join(raw_parts))
        return ScannerOutput(
            findings=findings,
            artifacts=artifacts,
            raw_output=raw_output or "",
            exit_code=0,
            command=commands[0] if commands else [self.executable_path],
        )

    def parse(self, process: ProcessResult, ctx: ScanContext) -> ScannerOutput:
        """Single-invocation parse (run() handles multiple targets itself)."""
        target = pin_target(self.targets(ctx)[0], ctx.host, ctx.ips, ctx.ips)
        if process.exit_code != 0:
            tail = _clean_stderr(process.stderr)[-2000:] or "no error output"
            raise ScannerError(f"ffuf exited with code {process.exit_code}: {tail}", process)
        results, invalid = parse_jsonl(process.stdout)
        records = [r for r in (to_record(x, target) for x in results) if r is not None]
        return ScannerOutput(
            findings=[normalize_record(r) for r in records],
            artifacts={"discovered": records, "invalid_lines": invalid},
            raw_output=process.stdout, exit_code=process.exit_code, command=process.argv,
        )


# --- helpers (module level so they can be unit-tested directly) -------------------


def _clean_stderr(text: str) -> str:
    return _ANSI.sub("", text).replace("\r", "\n").strip()


def _count_by(items, key) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = key(item) or "unknown"
        out[k] = out.get(k, 0) + 1
    return out


def parse_progress(stderr: str) -> dict[str, int | None]:
    """Final 'Progress: [done/total] ... Errors: n' line from FFUF's stderr."""
    matches = _PROGRESS.findall(_ANSI.sub("", stderr))
    if not matches:
        return {"requests_completed": None, "requests_total": None, "errors": None}
    done, total, errors = matches[-1]
    return {"requests_completed": int(done), "requests_total": int(total), "errors": int(errors)}


def parse_jsonl(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse FFUF -json output; returns (result objects, count of invalid lines)."""
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
        if isinstance(obj, dict) and obj.get("url") and isinstance(obj.get("status"), int):
            results.append(obj)
        else:
            invalid += 1
    return results, invalid


def decode_input(value: Any) -> str | None:
    """FFUF base64-encodes input words in JSON output; tolerate plain text too."""
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        if decoded.isprintable():
            return decoded
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return value


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def classify(path: str) -> tuple[str, str, str] | None:
    lowered = path.lower()
    for category, label, pattern, remediation in SENSITIVE_RULES:
        if pattern.search(lowered):
            return category, label, remediation
    return None


def to_record(result: dict[str, Any], target: PinnedTarget) -> dict[str, Any] | None:
    """FFUF result -> stored metadata (no body). None if not on the pinned target."""
    parts = urlsplit(str(result.get("url", "")))
    expected = urlsplit(target.connect_base)
    if parts.scheme != expected.scheme or parts.netloc.lower() != expected.netloc.lower():
        return None
    path = parts.path or "/"
    if not path.startswith(urlsplit(target.url).path or "/"):
        return None
    redirect, _ = redact(str(result.get("redirectlocation") or "")[:500])
    duration = _int_or_none(result.get("duration"))
    classification = classify(path)
    return {
        "url": f"{target.origin}{path}",
        "path": path,
        "word": decode_input((result.get("input") or {}).get("FUZZ")),
        "status": result["status"],
        "length": _int_or_none(result.get("length")),
        "words": _int_or_none(result.get("words")),
        "lines": _int_or_none(result.get("lines")),
        "content_type": str(result.get("content-type") or "")[:100] or None,
        "redirect_location": redirect or None,
        "duration_ms": round(duration / 1_000_000, 1) if duration is not None else None,
        "connected_ip": target.ip,
        "host_header": target.host_header,
        "category": classification[0] if classification else None,
    }


def with_article(label: str) -> str:
    """'an environment, key, or credential file' / 'a file store' (labels are lowercase words)."""
    return f"{'an' if label[:1].lower() in 'aeiou' else 'a'} {label}"


def assess(record: dict[str, Any]) -> tuple[FindingSeverity, str, str]:
    """(severity, confidence, kind) under the evidence-based severity policy."""
    status, length = record["status"], record["length"] or 0
    if record["category"] is None:
        return FindingSeverity.INFO, "medium", "content-discovery"
    if 200 <= status < 300 and length > 0:
        return FindingSeverity.LOW, "low", "sensitive-path-reachable"
    return FindingSeverity.INFO, "medium", "sensitive-path-restricted"


def normalize_record(record: dict[str, Any]) -> NormalizedFinding:
    severity, confidence, kind = assess(record)
    path, status = record["path"], record["status"]
    classification = classify(path)
    label, remediation = (classification[1], classification[2]) if classification else ("", "")

    observed = (
        f"FFUF content discovery received HTTP {status} for {path}"
        + (f" ({record['length']} bytes, {record['content_type']})" if record["length"] is not None
           and record["content_type"] else "")
        + ". Auto-calibration was active, so the server's catch-all responses were filtered out."
    )
    caveat = (" FFUF records only status, size and content type: the response body was "
              "deliberately not collected, so the content has not been verified.")
    if kind == "content-discovery":
        title = f"Discovered path: {path} (HTTP {status})"
        description = observed + " A reachable path is informational on its own." + caveat
        recommendation = ("Confirm this resource is meant to be publicly reachable; remove it or "
                          "restrict access if it is not.")
    elif kind == "sensitive-path-reachable":
        title = f"Potentially sensitive path reachable: {path} (HTTP {status})"
        description = (observed + f" The path name suggests {with_article(label)}. This is NOT a confirmed "
                       "exposure." + caveat + " Review the resource manually (read-only) to "
                       "confirm whether it exposes sensitive data.")
        recommendation = remediation
    else:
        title = f"Sensitive-looking path responds with HTTP {status}: {path}"
        description = (observed + f" The path name suggests {with_article(label)}, but the response was "
                       "access-controlled, a redirect or empty, so nothing indicates its "
                       "content is exposed." + caveat)
        recommendation = ("Verify that access to this resource is denied for unauthenticated users "
                          "and consider removing it from the web root. " + remediation)

    evidence = [
        f"url: {record['url']}",
        f"status: {status}",
        f"length: {record['length']} bytes" if record["length"] is not None else "length: unknown",
        f"words: {record['words']}, lines: {record['lines']}",
    ]
    if record["content_type"]:
        evidence.append(f"content-type: {record['content_type']}")
    if record["redirect_location"]:
        evidence.append(f"redirect-location: {record['redirect_location']}")
    if record["duration_ms"] is not None:
        evidence.append(f"response-time: {record['duration_ms']} ms")
    if record["word"]:
        evidence.append(f"wordlist-entry: {record['word']}")
    evidence.append(f"connected-to: {record['connected_ip']}"
                    + (f" (Host: {record['host_header']})" if record["host_header"] else ""))
    if record["category"]:
        evidence.append(f"path-category: {record['category']}")

    return NormalizedFinding(
        title=title,
        severity=severity,
        dedup_key=f"ffuf:path:{path}",
        location=record["url"],
        description=description,
        recommendation=recommendation,
        evidence="\n".join(evidence),
        original_severity=None,  # FFUF has no severity concept
        confidence=confidence,
        source_id=f"ffuf:{kind}" + (f":{record['category']}" if record["category"] else ""),
        cwe=None,
        references=[],
    )


def flood_finding(target: PinnedTarget, records: list[dict[str, Any]]) -> NormalizedFinding:
    statuses = _count_by(records, lambda r: str(r["status"]))
    sizes = _count_by(records, lambda r: str(r["length"]))
    top_sizes = sorted(sizes.items(), key=lambda kv: -kv[1])[:5]
    return NormalizedFinding(
        title=f"Content discovery inconclusive: {len(records)} paths matched on {target.url}",
        severity=FindingSeverity.INFO,
        dedup_key="ffuf:flood-guard",
        location=target.url,
        description=(f"FFUF matched {len(records)} paths, more than the plausibility limit of "
                     f"{MAX_FINDINGS_PER_TARGET}. The server most likely answers many unknown paths "
                     "with a non-error response that auto-calibration could not filter, so "
                     "individual paths were not reported as findings. The raw metadata is kept in "
                     "the scanner run artifacts."),
        recommendation=("Review the scanner run artifacts manually, or re-run with a different "
                        "wordlist once the catch-all behaviour is understood."),
        evidence="\n".join([
            f"matched paths: {len(records)}",
            "status distribution: " + ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())),
            "most common sizes: " + ", ".join(f"{k} bytes x{v}" for k, v in top_sizes),
        ]),
        confidence="low",
        source_id="ffuf:flood-guard",
    )
