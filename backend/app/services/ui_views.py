"""Read-side mapping from backend records to the web UI contract.

Everything here is derived from stored Scans, ScannerRuns, Findings and AI
analyses. Nothing is invented: values the backend does not track are None.
"""

import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysis, AnalysisStatus
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan, ScanStatus
from app.models.scanner_run import ScannerRun, ScannerRunStatus
from app.schemas.ui import (
    ActivityOut,
    AssessmentOut,
    DashboardSummaryOut,
    EvidenceOut,
    FindingOut,
    FindingsOverTimePoint,
    LogEntryOut,
    ReportOut,
    ScanActivityPoint,
    ScanDetailOut,
    ScanStageOut,
    SeverityCounts,
)
from app.services.report import build_markdown_report, latest_completed_analysis

# Scanner selection per UI profile (pipeline order is applied by the registry).
PROFILE_SCANNERS: dict[str, list[str]] = {
    "quick": ["nmap", "nuclei"],
    "standard": ["nmap", "ffuf", "nuclei"],
    "deep": ["nmap", "ffuf", "nuclei", "zap"],
}

STAGE_INFO: dict[str, tuple[str, str]] = {
    "nmap": ("Port & service discovery", "Nmap: open ports and HTTP services"),
    "ffuf": ("Content discovery", "FFUF: common paths and files"),
    "nuclei": ("Vulnerability templates", "Nuclei: known CVEs and misconfigurations"),
    "zap": ("Passive web scan", "OWASP ZAP baseline: spider and passive checks"),
}

# Grouping by the tool that found the issue (the backend stores no category).
CATEGORY_BY_SCANNER = {
    "nmap": "Network exposure",
    "ffuf": "Content discovery",
    "nuclei": "Known vulnerabilities",
    "zap": "Web application",
}

# Transparent, documented risk score: severity-weighted finding count, capped at 100.
RISK_WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 2}

FINISHED_SCAN = (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED)
ACTIVE_SCAN = (ScanStatus.QUEUED, ScanStatus.RUNNING)
FINISHED_RUN = (ScannerRunStatus.COMPLETED, ScannerRunStatus.FAILED, ScannerRunStatus.SKIPPED)

_CVSS = re.compile(r"^cvss:\s*([0-9]+(?:\.[0-9]+)?)", re.MULTILINE)


# --- small helpers ----------------------------------------------------------------

def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    # SQLite drops tzinfo; every timestamp the backend writes is UTC.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    value = _utc(dt)
    return value.isoformat().replace("+00:00", "Z") if value else None


def relative_time(dt: datetime | None, now: datetime) -> str:
    value = _utc(dt)
    if value is None:
        return ""
    seconds = max(0, int((now - value).total_seconds()))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    days = seconds // 86400
    return "1 day ago" if days == 1 else f"{days} days ago"


def risk_score(counts: SeverityCounts) -> int:
    total = sum(getattr(counts, sev) * weight for sev, weight in RISK_WEIGHTS.items())
    return min(100, total)


def _severity_counts(values: Iterable[str]) -> SeverityCounts:
    counter = Counter(values)
    return SeverityCounts(**{s: counter.get(s, 0) for s in ("critical", "high", "medium", "low")})


def latest_runs(scan: Scan) -> list[ScannerRun]:
    if not scan.runs:
        return []
    latest = max(r.attempt for r in scan.runs)
    return sorted((r for r in scan.runs if r.attempt == latest), key=lambda r: r.order)


def selected_scanners(scan: Scan) -> list[str]:
    return [s for s in (scan.scanner or "").split(",") if s and s != "pending"]


def profile_label(scan: Scan) -> str:
    chosen = selected_scanners(scan)
    if not chosen:
        return "Not started"
    for name, scanners in PROFILE_SCANNERS.items():
        if set(chosen) == set(scanners):
            return name.capitalize()
    return "Custom"


def progress(scan: Scan, runs: list[ScannerRun]) -> int:
    if not runs:
        return 100 if scan.status == ScanStatus.COMPLETED else 0
    parts = [100 if r.status in FINISHED_RUN else max(0, min(100, r.progress)) for r in runs]
    value = round(sum(parts) / len(parts))
    # Only a finished assessment may show 100%.
    return value if scan.status in FINISHED_SCAN else min(value, 99)


def endpoints_discovered(runs: list[ScannerRun]) -> int | None:
    total, seen = 0, False
    for run in runs:
        artifacts = run.artifacts or {}
        if run.scanner == "nmap" and "http_services" in artifacts:
            total += len(artifacts["http_services"] or [])
            seen = True
        elif run.scanner == "ffuf" and "discovered_total" in artifacts:
            total += int(artifacts["discovered_total"] or 0)
            seen = True
    return total if seen else None


def target_host(scan: Scan) -> str:
    if scan.target is not None:
        return scan.target.host
    return urlsplit(scan.target_url).hostname or scan.target_url


def assessment_name(scan: Scan) -> str:
    return scan.target.name if scan.target is not None else target_host(scan)


# --- assessments ------------------------------------------------------------------

def _counts_by_scan(db: Session, scan_ids: list[uuid.UUID]) -> dict[uuid.UUID, SeverityCounts]:
    if not scan_ids:
        return {}
    rows = db.execute(
        select(Finding.scan_id, Finding.severity, func.count())
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id, Finding.severity)
    ).all()
    per_scan: dict[uuid.UUID, Counter] = defaultdict(Counter)
    for scan_id, severity, count in rows:
        per_scan[scan_id][severity.value] += count
    return {sid: _severity_counts(per_scan[sid].elements()) for sid in scan_ids}


def assessment_out(scan: Scan, counts: SeverityCounts) -> AssessmentOut:
    runs = latest_runs(scan)
    return AssessmentOut(
        id=str(scan.id),
        target=scan.target_url,
        name=assessment_name(scan),
        status=scan.status.value,
        progress=progress(scan, runs),
        started_at=iso(scan.started_at or scan.created_at) or "",
        finished_at=iso(scan.completed_at) if scan.status in FINISHED_SCAN else None,
        risk_score=risk_score(counts),
        findings=counts,
        profile=profile_label(scan),
    )


def list_assessments(db: Session) -> list[AssessmentOut]:
    # SQLite timestamps have 1 s resolution; started_at breaks most same-second ties.
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc(), Scan.started_at.desc())).all()
    counts = _counts_by_scan(db, [s.id for s in scans])
    return [assessment_out(s, counts[s.id]) for s in scans]


def _stage(run: ScannerRun) -> ScanStageOut:
    label, description = STAGE_INFO.get(run.scanner, (run.scanner, run.scanner))
    status = {
        ScannerRunStatus.PENDING: "pending",
        ScannerRunStatus.RUNNING: "running",
        ScannerRunStatus.COMPLETED: "done",
        ScannerRunStatus.FAILED: "failed",
        ScannerRunStatus.SKIPPED: "skipped",
    }[run.status]
    if run.status in (ScannerRunStatus.FAILED, ScannerRunStatus.SKIPPED) and run.error_message:
        description = f"{status.capitalize()}: {run.error_message}"[:300]
    return ScanStageOut(key=run.scanner, label=label, description=description, status=status)


def _hms(dt: datetime | None) -> str:
    value = _utc(dt)
    return value.strftime("%H:%M:%S") if value else ""


def _log(db: Session, scan: Scan, runs: list[ScannerRun]) -> list[LogEntryOut]:
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    entries: list[tuple[datetime, LogEntryOut]] = []

    def add(dt: datetime | None, message: str, level: str) -> None:
        entries.append((_utc(dt) or epoch, LogEntryOut(time=_hms(dt), message=message, level=level)))

    add(scan.created_at, f"Assessment created for {scan.target_url}", "info")
    for run in runs:
        name = STAGE_INFO.get(run.scanner, (run.scanner,))[0]
        if run.started_at:
            add(run.started_at, f"{name} started", "info")
        if run.status == ScannerRunStatus.COMPLETED:
            add(run.completed_at, f"{name} completed: {run.findings_count} finding(s)", "info")
        elif run.status in (ScannerRunStatus.FAILED, ScannerRunStatus.SKIPPED):
            add(run.completed_at or run.started_at,
                f"{name} {run.status.value}: {run.error_message or 'no details'}"[:500], "warn")
    if not runs and scan.status == ScanStatus.FAILED and scan.error_message:
        add(scan.completed_at, f"Assessment failed: {scan.error_message}"[:500], "warn")

    notable = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id,
               Finding.severity.in_((FindingSeverity.CRITICAL, FindingSeverity.HIGH)))
        .order_by(Finding.created_at).limit(20)
    ).all()
    for f in notable:
        add(f.created_at, f"[{f.severity.value.upper()}] {f.title} ({f.location or '-'})", "finding")
    entries.sort(key=lambda item: item[0])
    return [entry for _, entry in entries]


def scan_detail(db: Session, scan: Scan) -> ScanDetailOut:
    counts = _counts_by_scan(db, [scan.id])[scan.id]
    base = assessment_out(scan, counts)
    runs = latest_runs(scan)
    return ScanDetailOut(
        **base.model_dump(),
        stages=[_stage(r) for r in runs],
        log=_log(db, scan, runs),
        requests_sent=None,
        endpoints_discovered=endpoints_discovered(runs),
    )


# --- findings ---------------------------------------------------------------------

def _analysis_by_finding(db: Session, scan_ids: Iterable[uuid.UUID]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for scan_id in set(scan_ids):
        analysis = latest_completed_analysis(db, scan_id)
        for item in ((analysis.result or {}).get("findings", []) if analysis else []):
            if item.get("finding_id"):
                out[item["finding_id"]] = item
    return out


def _cwe(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip()
    return f"CWE-{value}" if value.isdigit() else value


def _cvss(evidence: str | None) -> float | None:
    match = _CVSS.search(evidence or "")
    if not match:
        return None
    score = float(match.group(1))
    return score if 0.0 <= score <= 10.0 else None


def finding_out(f: Finding, scan: Scan, analysis: dict[str, Any] | None) -> FindingOut:
    if analysis and analysis.get("remediation_steps"):
        remediation = [str(s) for s in analysis["remediation_steps"]]
    else:
        remediation = [line.strip(" -*\t") for line in (f.recommendation or "").splitlines()]
        remediation = [line for line in remediation if line]
    return FindingOut(
        id=str(f.id),
        title=f.title,
        severity=f.severity.value,
        category=CATEGORY_BY_SCANNER.get(f.scanner or "", "Manual"),
        scanner=", ".join(f.detected_by or [f.scanner or "manual"]),
        assessment_id=str(f.scan_id),
        target=target_host(scan),
        endpoint=f.location or "",
        cwe=_cwe(f.cwe),
        cvss=_cvss(f.evidence) if f.scanner == "nuclei" else None,
        discovered_at=iso(f.created_at) or "",
        description=f.description or "",
        evidence=EvidenceOut(request="", response=f.evidence or ""),
        business_impact=(analysis or {}).get("business_impact") or "",
        remediation=remediation,
    )


def list_findings(
    db: Session,
    severity: FindingSeverity | None = None,
    assessment_id: uuid.UUID | None = None,
    limit: int = 500,
) -> list[FindingOut]:
    stmt = select(Finding).order_by(Finding.created_at.desc(), Finding.title).limit(limit)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if assessment_id is not None:
        stmt = stmt.where(Finding.scan_id == assessment_id)
    findings = db.scalars(stmt).all()
    scans = {f.scan_id: f.scan for f in findings}
    analyses = _analysis_by_finding(db, scans)
    return [finding_out(f, scans[f.scan_id], analyses.get(str(f.id))) for f in findings]


def finding_detail(db: Session, f: Finding) -> FindingOut:
    return finding_out(f, f.scan, _analysis_by_finding(db, [f.scan_id]).get(str(f.id)))


# --- reports ----------------------------------------------------------------------

def report_available(scan: Scan, finding_total: int) -> bool:
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL):
        return True
    return scan.status == ScanStatus.FAILED and finding_total > 0


def report_filename(scan: Scan) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", assessment_name(scan).lower()).strip("-")[:40] or "target"
    return f"assessment-{str(scan.id)[:8]}-{slug}.md"


def list_reports(db: Session) -> list[ReportOut]:
    scans = db.scalars(select(Scan).where(Scan.status.in_(FINISHED_SCAN))).all()
    totals = dict(db.execute(
        select(Finding.scan_id, func.count()).group_by(Finding.scan_id)
    ).all())
    reports = []
    for scan in scans:
        total = totals.get(scan.id, 0)
        if not report_available(scan, total):
            continue
        analysis = latest_completed_analysis(db, scan.id)
        generated = (analysis.completed_at if analysis else None) or scan.completed_at or scan.created_at
        size = len(build_markdown_report(db, scan).encode("utf-8"))
        reports.append(ReportOut(
            id=str(scan.id),
            assessment_id=str(scan.id),
            title=f"{assessment_name(scan)}: security assessment",
            target=target_host(scan),
            generated_at=iso(generated) or "",
            size_kb=round(size / 1024, 1),
            findings=total,
        ))
    reports.sort(key=lambda r: r.generated_at, reverse=True)
    return reports


# --- dashboard --------------------------------------------------------------------

def dashboard_summary(db: Session, now: datetime | None = None) -> DashboardSummaryOut:
    now = now or datetime.now(timezone.utc)
    scans = db.scalars(select(Scan)).all()
    counts = _counts_by_scan(db, [s.id for s in scans])

    totals = Counter()
    for c in counts.values():
        for sev in ("critical", "high", "medium", "low"):
            totals[sev] += getattr(c, sev)
    breakdown = SeverityCounts(**{s: totals.get(s, 0) for s in ("critical", "high", "medium", "low")})

    # Risk: worst current exposure = max over targets of their latest finished
    # (completed/partial) assessment. Trend = latest minus previous finished one.
    finished = sorted(
        (s for s in scans if s.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)),
        key=lambda s: _utc(s.completed_at or s.created_at),
    )
    latest_per_target: dict[Any, Scan] = {}
    for scan in finished:
        latest_per_target[scan.target_id or scan.target_url] = scan
    scores = [risk_score(counts[s.id]) for s in latest_per_target.values()]
    overall = max(scores, default=0)
    trend = 0
    if len(finished) >= 2:
        trend = risk_score(counts[finished[-1].id]) - risk_score(counts[finished[-2].id])

    # Findings per month (last 6 months, info excluded like the breakdown).
    months = []
    cursor = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for _ in range(6):
        months.append(cursor)
        cursor = (cursor - timedelta(days=1)).replace(day=1)
    months.reverse()
    month_counts: dict[str, Counter] = {m.strftime("%Y-%m"): Counter() for m in months}
    rows = db.execute(
        select(Finding.severity, Finding.created_at)
        .where(Finding.severity != FindingSeverity.INFO, Finding.created_at >= months[0].replace(tzinfo=None))
    ).all()
    for severity, created in rows:
        key = _utc(created).strftime("%Y-%m")
        if key in month_counts:
            month_counts[key][severity.value] += 1
    findings_over_time = [
        FindingsOverTimePoint(date=m.strftime("%b"), **{
            s: month_counts[m.strftime("%Y-%m")].get(s, 0) for s in ("critical", "high", "medium", "low")
        })
        for m in months
    ]

    # Scans created per day, last 7 days (today last).
    today = now.date()
    per_day = Counter(_utc(s.created_at).date() for s in scans)
    scan_activity = [
        ScanActivityPoint(day=(today - timedelta(days=i)).strftime("%a"),
                          scans=per_day.get(today - timedelta(days=i), 0))
        for i in range(6, -1, -1)
    ]

    return DashboardSummaryOut(
        risk_score=overall,
        risk_trend=trend,
        total_scans=len(scans),
        active_scans=sum(1 for s in scans if s.status in ACTIVE_SCAN),
        total_vulnerabilities=sum(totals.values()),
        critical_findings=breakdown.critical,
        breakdown=breakdown,
        findings_over_time=findings_over_time,
        scan_activity=scan_activity,
        recent_activity=_recent_activity(db, scans, now),
    )


def _recent_activity(db: Session, scans: list[Scan], now: datetime, limit: int = 10) -> list[ActivityOut]:
    events: list[tuple[datetime, ActivityOut]] = []

    def add(dt: datetime | None, key: str, message: str, kind: str) -> None:
        if dt is not None:
            events.append((_utc(dt), ActivityOut(id=key, time="", message=message, type=kind)))

    for scan in scans:
        host = target_host(scan)
        if scan.started_at:
            add(scan.started_at, f"scan-start-{scan.id}",
                f"{profile_label(scan)} assessment started on {host}", "scan")
        if scan.status in FINISHED_SCAN and scan.completed_at:
            add(scan.completed_at, f"scan-end-{scan.id}", f"Assessment {scan.status.value} on {host}", "scan")
    notable = db.scalars(
        select(Finding)
        .where(Finding.severity.in_((FindingSeverity.CRITICAL, FindingSeverity.HIGH)))
        .order_by(Finding.created_at.desc()).limit(limit)
    ).all()
    for f in notable:
        add(f.created_at, f"finding-{f.id}", f"{f.severity.value.capitalize()}: {f.title}", "finding")
    analyses = db.scalars(
        select(AIAnalysis).where(AIAnalysis.status == AnalysisStatus.COMPLETED)
        .order_by(AIAnalysis.completed_at.desc()).limit(limit)
    ).all()
    for a in analyses:
        add(a.completed_at, f"analysis-{a.id}", f"AI analysis report ready for {target_host(a.scan)}", "report")

    events.sort(key=lambda item: item[0], reverse=True)
    out = []
    for dt, event in events[:limit]:
        event.time = relative_time(dt, now)
        out.append(event)
    return out
