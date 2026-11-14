export type Severity = "critical" | "high" | "medium" | "low" | "info";
/** Backend scan statuses. "partial": some scanners completed, others failed. */
export type ScanStatus = "queued" | "running" | "completed" | "partial" | "failed";
/** Per-scanner stage status; "failed"/"skipped" are never shown as done. */
export type StageStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface Assessment {
  id: string;
  target: string;
  name: string;
  status: ScanStatus;
  progress: number;
  startedAt: string;
  finishedAt?: string;
  riskScore: number;
  findings: Record<Exclude<Severity, "info">, number>;
  profile: string;
}

export interface ScanStage {
  key: string;
  label: string;
  description: string;
  status: StageStatus;
}

export interface ScanDetail extends Assessment {
  stages: ScanStage[];
  log: { time: string; message: string; level: "info" | "warn" | "finding" }[];
  /** null: not tracked by the backend. */
  requestsSent: number | null;
  /** null: no discovery scanner has reported yet. */
  endpointsDiscovered: number | null;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  scanner: string;
  assessmentId: string;
  target: string;
  endpoint: string;
  cwe: string;
  /** null: the scanner did not report a CVSS score. */
  cvss: number | null;
  status: "open" | "triaged" | "fixed";
  discoveredAt: string;
  description: string;
  /** Scanners store one evidence block (in `response`); `request` may be empty. */
  evidence: { request: string; response: string };
  businessImpact: string;
  remediation: string[];
}

export interface DashboardSummary {
  riskScore: number;
  riskTrend: number;
  totalScans: number;
  activeScans: number;
  totalVulnerabilities: number;
  criticalFindings: number;
  breakdown: Record<Exclude<Severity, "info">, number>;
  findingsOverTime: { date: string; critical: number; high: number; medium: number; low: number }[];
  scanActivity: { day: string; scans: number }[];
  recentActivity: { id: string; time: string; message: string; type: "scan" | "finding" | "report" }[];
}

export interface Report {
  id: string;
  assessmentId: string;
  title: string;
  target: string;
  generatedAt: string;
  format: "pdf" | "html" | "json" | "md";
  sizeKb: number;
  findings: number;
}

export interface NewAssessmentInput {
  target: string;
  name: string;
  authorized: boolean;
  profile: "quick" | "standard" | "deep";
  modules: string[];
  authHeader?: string | undefined;
  maxRps: number;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/*
 * AI analysis, as returned by the backend's existing endpoints
 * (POST/GET /scans/{id}/analysis). These keep the backend's snake_case keys.
 */
export type AnalysisStatus = "pending" | "running" | "completed" | "failed";
export type OverallRisk = "critical" | "high" | "medium" | "low" | "informational";

export interface FindingAnalysis {
  finding_id: string;
  finding_ref: string;
  title: string;
  severity: Severity;
  scanner: string | null;
  location: string | null;
  explanation: string;
  technical_impact: string;
  business_impact: string;
  priority: "P1" | "P2" | "P3" | "P4";
  validity: "likely_true_positive" | "needs_verification" | "likely_false_positive" | "informational";
  validity_rationale: string;
  confidence_limitations: string;
  remediation_steps: string[];
  verification_steps: string[];
}

export interface RemediationAction {
  rank: number;
  title: string;
  finding_refs: string[];
  finding_ids: string[];
  rationale: string;
  effort: "low" | "medium" | "high";
}

export interface AnalysisResult {
  overall_risk: OverallRisk;
  executive_summary: string;
  technical_assessment: string;
  findings: FindingAnalysis[];
  remediation_plan: RemediationAction[];
  scan_limitations: string[];
  warnings?: string[];
}

export interface ScanAnalysis {
  id: string;
  scan_id: string;
  status: AnalysisStatus;
  model: string;
  served_by_model: string | null;
  fallback_used: boolean;
  findings_total: number;
  findings_analyzed: number;
  redactions: number;
  overall_risk: OverallRisk | null;
  executive_summary: string | null;
  technical_assessment: string | null;
  result: AnalysisResult | null;
  error_message: string | null;
  /** Backend timestamps are UTC but may lack a zone suffix (SQLite); see asUtc(). */
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
}
