import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.ai_analysis import AnalysisStatus

# ---------------------------------------------------------------------------
# Structured output Claude must return (enforced via output_config.format and
# re-validated here). Descriptions double as instructions to the model.
# ---------------------------------------------------------------------------


class FindingAnalysis(BaseModel):
    finding_ref: str = Field(description="The finding's ref exactly as given in scan_data, e.g. 'F3'.")
    explanation: str = Field(description="What the issue is, in clear technical language (2-4 sentences).")
    technical_impact: str = Field(description="What an attacker could realistically do, given the evidence.")
    business_impact: str = Field(description="Plausible business consequence; say when it depends on unknown context.")
    priority: Literal["P1", "P2", "P3", "P4"] = Field(
        description="P1 fix immediately, P2 fix soon, P3 planned hardening, P4 informational/no action."
    )
    validity: Literal["likely_true_positive", "needs_verification", "likely_false_positive", "informational"]
    validity_rationale: str = Field(description="Why, based only on the provided evidence.")
    confidence_limitations: str = Field(description="What the evidence does not establish; scanner limits.")
    remediation_steps: list[str] = Field(description="Concrete fixes, most important first.")
    verification_steps: list[str] = Field(
        description="Safe, non-destructive steps an authorized tester can use to confirm the issue and the fix."
    )


class RemediationAction(BaseModel):
    rank: int = Field(description="1 = do first.")
    title: str
    finding_refs: list[str] = Field(description="Refs of the findings this action addresses.")
    rationale: str
    effort: Literal["low", "medium", "high"]


class AnalystReport(BaseModel):
    overall_risk: Literal["critical", "high", "medium", "low", "informational"]
    executive_summary: str = Field(description="For non-technical stakeholders; 1-3 short paragraphs.")
    technical_assessment: str = Field(description="For engineers: key weaknesses, attack surface, themes.")
    findings: list[FindingAnalysis] = Field(description="Exactly one entry per finding ref in scan_data.")
    remediation_plan: list[RemediationAction] = Field(description="Prioritized actions; group related findings.")
    scan_limitations: list[str] = Field(description="What this assessment could not cover or establish.")


# ---------------------------------------------------------------------------
# API schemas
# ---------------------------------------------------------------------------


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    status: AnalysisStatus
    model: str
    served_by_model: str | None
    fallback_used: bool
    findings_total: int
    findings_analyzed: int
    redactions: int
    overall_risk: str | None
    executive_summary: str | None
    technical_assessment: str | None
    result: dict[str, Any] | None
    usage: dict[str, Any] | None
    request_id: str | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
