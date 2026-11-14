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
