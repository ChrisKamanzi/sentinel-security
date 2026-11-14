"""Markdown assessment report from stored findings + the latest AI analysis.

All scanner- and AI-provided text is HTML-escaped (<, >, &) so a Markdown
renderer cannot be tricked into rendering active content from target data.
"""

import html
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysis, AnalysisStatus
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan
from app.models.target import Target

SEVERITIES = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM,
              FindingSeverity.LOW, FindingSeverity.INFO]


def _e(text) -> str:
    return html.escape(str(text), quote=False) if text not in (None, "") else "-"


def _cell(text) -> str:
    return _e(text).replace("|", "\\|").replace("\n", " ")


def latest_completed_analysis(db: Session, scan_id) -> AIAnalysis | None:
    return db.scalars(
        select(AIAnalysis)
        .where(AIAnalysis.scan_id == scan_id, AIAnalysis.status == AnalysisStatus.COMPLETED)
        .order_by(AIAnalysis.created_at.desc())
    ).first()


def build_markdown_report(db: Session, scan: Scan) -> str:
    target = db.get(Target, scan.target_id) if scan.target_id else None
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    findings = sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.title))
    analysis = latest_completed_analysis(db, scan.id)
    by_id = {a["finding_id"]: a for a in ((analysis.result or {}).get("findings", []) if analysis else [])}
    counts = Counter(f.severity for f in findings)
    runs = [r for r in scan.runs if r.attempt == max((x.attempt for x in scan.runs), default=0)]

    out: list[str] = []
    w = out.append
    w("# Security Assessment Report")
    w("")
    w(f"- **Target:** {_e(target.name if target else '-')} ({_e(scan.target_url)})")
    w(f"- **Assessment status:** {_e(scan.status.value)}")
    w(f"- **Started / completed:** {_e(scan.started_at)} / {_e(scan.completed_at)}")
    w(f"- **Scanners:** " + (", ".join(f"{_e(r.scanner)} ({_e(r.status.value)})" for r in sorted(runs, key=lambda r: r.order)) or "-"))
    w(f"- **Report generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    if analysis:
        w(f"- **AI analysis:** {_e(analysis.served_by_model or analysis.model)}"
          f"{' (fallback model)' if analysis.fallback_used else ''}, overall risk **{_e(analysis.overall_risk)}**")
    w("")
    w("| Critical | High | Medium | Low | Info | Total |")
    w("|---|---|---|---|---|---|")
    w("| " + " | ".join(str(counts.get(s, 0)) for s in SEVERITIES) + f" | {len(findings)} |")
    w("")

    if analysis:
        w("## Executive Summary")
        w("")
        w(_e(analysis.executive_summary))
        w("")
        w("## Technical Assessment")
        w("")
        w(_e(analysis.technical_assessment))
        w("")
        plan = (analysis.result or {}).get("remediation_plan", [])
        if plan:
            w("## Remediation Plan")
            w("")
            w("| # | Action | Effort | Findings | Rationale |")
            w("|---|---|---|---|---|")
            for item in plan:
                w(f"| {item['rank']} | {_cell(item['title'])} | {_cell(item['effort'])} | "
                  f"{_cell(', '.join(item.get('finding_refs', [])))} | {_cell(item['rationale'])} |")
            w("")
    else:
        w("> No completed AI analysis yet. Run `POST /api/v1/scans/{id}/analysis` to add one.")
        w("")

    w("## Findings")
    for severity in SEVERITIES:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        w("")
        w(f"### {severity.value.capitalize()} ({len(group)})")
        for f in group:
            a = by_id.get(str(f.id))
            w("")
            # the AI summary and remediation plan cite findings by these refs
            w(f"#### {_e(a['finding_ref']) + ' · ' if a else ''}{_e(f.title)}")
            w("")
            w(f"- **Location:** `{_e(f.location)}`")
            w(f"- **Scanner:** {_e(', '.join(f.detected_by or [f.scanner or 'manual']))} "
              f"(source: {_e(f.source_id)}, original severity: {_e(f.original_severity)})")
            if f.cwe:
                w(f"- **CWE:** {_e(f.cwe)}")
            if a:
                w(f"- **Priority:** {_e(a['priority'])} | **Validity:** {_e(a['validity'].replace('_', ' '))}")
                w("")
                w(f"{_e(a['explanation'])}")
                w("")
                w(f"**Technical impact:** {_e(a['technical_impact'])}")
                w("")
                w(f"**Business impact:** {_e(a['business_impact'])}")
                w("")
                w(f"**Validity rationale:** {_e(a['validity_rationale'])} "
                  f"_Limitations: {_e(a['confidence_limitations'])}_")
                if a.get("remediation_steps"):
                    w("")
                    w("**Remediation:**")
                    w("")
                    for step in a["remediation_steps"]:
                        w(f"1. {_e(step)}")
                if a.get("verification_steps"):
                    w("")
                    w("**Verification:**")
                    w("")
                    for step in a["verification_steps"]:
                        w(f"1. {_e(step)}")
            elif f.description:
                w("")
                w(_e(f.description))
            if f.evidence:
                w("")
                w("<details><summary>Evidence</summary>")
                w("")
                w("```")
                w(f.evidence.replace("```", "'''"))
                w("```")
                w("")
                w("</details>")
            if f.references:
                w("")
                w("References: " + ", ".join(_e(r) for r in f.references[:5]))

    if analysis and (analysis.result or {}).get("scan_limitations"):
        w("")
        w("## Assessment Limitations")
        w("")
        for item in analysis.result["scan_limitations"]:
            w(f"- {_e(item)}")
    w("")
    w("---")
    w("_Automated assessment by AutoPentest AI. AI analysis is advisory: verify findings "
      "before acting. No exploitation or intrusive testing was performed._")
    return "\n".join(out) + "\n"
