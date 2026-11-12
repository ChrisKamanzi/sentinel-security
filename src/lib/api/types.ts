export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "queued" | "running" | "completed" | "failed";

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
  status: "pending" | "running" | "done";
}

export interface ScanDetail extends Assessment {
  stages: ScanStage[];
  log: { time: string; message: string; level: "info" | "warn" | "finding" }[];
  requestsSent: number;
  endpointsDiscovered: number;
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
  cvss: number;
  status: "open" | "triaged" | "fixed";
  discoveredAt: string;
  description: string;
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
  format: "pdf" | "html" | "json";
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
