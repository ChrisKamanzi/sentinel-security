import { queryOptions } from "@tanstack/react-query";
import { ApiError, apiFetch, apiRequest, apiUrl, isDemoMode } from "./client";
import { demoAssessments, demoFindings, demoReports, demoSummary, stageTemplate } from "./demo-data";
import type { Assessment, ChatMessage, DashboardSummary, Finding, NewAssessmentInput, Project, Target, ToolStatus, Report, ScanAnalysis, ScanDetail } from "./types";
import { validTargetUrl } from "./assessment-config";

/*
 * Service layer for the FastAPI backend. Each function maps to one endpoint.
 * In demo mode (no VITE_API_BASE_URL) bundled data is returned instead.
 */
const delay = <T,>(v: T, ms = 250) => new Promise<T>((r) => setTimeout(() => r(v), ms));

// Demo-only: deterministic sample state; never imply actual scanner progress.
function demoProgress(a: Assessment): Assessment {
  return a;
}

export const api = {
  /** GET /dashboard/summary */
  getDashboard: (): Promise<DashboardSummary> =>
    isDemoMode ? delay(demoSummary) : apiFetch("/dashboard/summary"),

  /** GET /assessments */
  listAssessments: (): Promise<Assessment[]> =>
    isDemoMode ? delay(demoAssessments.map(demoProgress)) : apiFetch("/assessments"),

  /** POST /assessments */
  createAssessment: (input: NewAssessmentInput): Promise<Assessment> => {
    if (!input.authorized) return Promise.reject(new Error("Authorization confirmation is required"));
    if (!validTargetUrl(input.target)) return Promise.reject(new Error("Enter a valid http(s) URL without credentials"));
    if (isDemoMode) return Promise.reject(new Error("Connect the FastAPI backend to launch an assessment. No scan was submitted."));
    return apiFetch("/assessments", { method: "POST", body: JSON.stringify(input) });
  },

  /** GET /assessments/{id} — poll for real-time progress */
  getScan: async (id: string): Promise<ScanDetail> => {
    if (!isDemoMode) return apiFetch(`/assessments/${id}`);
    const base = demoAssessments.find((a) => a.id === id);
    if (!base) throw new ApiError(404, "Assessment not found");
    const a = demoProgress(base);
    const per = 100 / stageTemplate.length;
    const stages = stageTemplate.map((s, i) => ({
      ...s,
      status: (a.progress >= (i + 1) * per ? "done" : a.progress >= i * per ? (a.status === "running" ? "running" : "pending") : "pending") as "pending" | "running" | "done",
    }));
    const logs = demoFindings.filter((f) => f.assessmentId === a.id).map((f) => ({ time: f.discoveredAt.slice(11, 19), message: `[${f.severity.toUpperCase()}] ${f.title} — ${f.endpoint}`, level: "finding" as const }));
    return delay({
      ...a,
      stages,
      requestsSent: Math.floor(a.progress * 412),
      endpointsDiscovered: Math.floor(a.progress * 1.9),
      log: [
        { time: "17:20:04", message: `Resolved ${new URL(a.target).host} → 104.18.22.91`, level: "info" },
        { time: "17:20:09", message: "TLS 1.3, certificate valid (Let's Encrypt R11)", level: "info" },
        { time: "17:21:30", message: "Rate limiting detected — throttling to 8 req/s", level: "warn" },
        ...logs,
      ],
    }, 150);
  },

  /** GET /findings */
  listFindings: (assessmentId?: string): Promise<Finding[]> => (isDemoMode ? delay(demoFindings.filter((f) => !assessmentId || f.assessmentId === assessmentId)) : apiFetch(`/findings${assessmentId ? `?assessmentId=${encodeURIComponent(assessmentId)}` : ""}`)),

  /** Existing project and target registration endpoints (no implicit authorization). */
  listProjects: (): Promise<Project[]> => isDemoMode ? delay([]) : apiFetch("/projects"),
  createProject: (name: string): Promise<Project> => isDemoMode ? Promise.reject(new Error("Target registration requires the FastAPI backend")) : apiFetch("/projects", { method: "POST", body: JSON.stringify({ name }) }),
  listTargets: (projectId: string): Promise<Target[]> => isDemoMode ? delay([]) : apiFetch(`/projects/${encodeURIComponent(projectId)}/targets`),
  createTarget: (projectId: string, input: Pick<Target, "name" | "host" | "base_url" | "is_authorized">): Promise<Target> => isDemoMode ? Promise.reject(new Error("Target registration requires the FastAPI backend")) : apiFetch(`/projects/${encodeURIComponent(projectId)}/targets`, { method: "POST", body: JSON.stringify(input) }),
  updateTarget: (id: string, isAuthorized: boolean): Promise<Target> => isDemoMode ? Promise.reject(new Error("Target management requires the FastAPI backend")) : apiFetch(`/targets/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ is_authorized: isAuthorized }) }),
  listTools: (): Promise<ToolStatus[]> => isDemoMode ? delay([]) : apiFetch("/tools"),

  /**
   * GET /findings/{id}/detail. (The backend's GET /findings/{id} is its older
   * snake_case API.) Unknown or malformed IDs resolve to null, i.e. "not found".
   */
  getFinding: async (id: string): Promise<Finding | null> => {
    if (!isDemoMode) {
      try {
        return await apiFetch<Finding>(`/findings/${encodeURIComponent(id)}/detail`);
      } catch (e) {
        if (e instanceof ApiError && (e.status === 404 || e.status === 422)) return null;
        throw e;
      }
    }
    return delay(demoFindings.find((f) => f.id === id) ?? null);
  },

  /** GET /reports */
  listReports: (): Promise<Report[]> => (isDemoMode ? delay(demoReports) : apiFetch("/reports")),

  /** URL for GET /reports/{id}/download */
  reportDownloadUrl: (id: string) => (isDemoMode ? null : apiUrl(`/reports/${id}/download`)),

  downloadReport: async (id: string): Promise<Blob> => {
    if (isDemoMode) throw new Error("Connect the FastAPI backend to download real reports");
    return (await apiRequest(`/reports/${encodeURIComponent(id)}/download`)).blob();
  },

  /**
   * Latest AI analysis of an assessment (any status): GET /scans/{id}/analysis.
   * Resolves to null when the assessment has never been analyzed.
   */
  getScanAnalysis: async (scanId: string): Promise<ScanAnalysis | null> => {
    if (isDemoMode) return null;
    try {
      return await apiFetch<ScanAnalysis>(`/scans/${encodeURIComponent(scanId)}/analysis`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  },

  /**
   * Queue a new AI analysis: POST /scans/{id}/analysis (202). Sends the scan's
   * redacted findings to Anthropic and uses API credits. The backend answers
   * 409 while the scan runs, when it has no findings, or when a run is active.
   */
  startScanAnalysis: (scanId: string): Promise<ScanAnalysis> =>
    isDemoMode
      ? Promise.reject(new Error("AI analysis needs the FastAPI backend"))
      : apiFetch(`/scans/${encodeURIComponent(scanId)}/analysis`, { method: "POST" }),

  /**
   * Demo-mode chat only. The FastAPI backend has no chat endpoint; with a
   * backend the analyst page uses getScanAnalysis/startScanAnalysis instead.
   */
  askAnalyst: async (messages: ChatMessage[], _findingId?: string): Promise<ChatMessage> => {
    if (!isDemoMode) throw new Error("Chat is only available in demo mode; use the per-assessment AI analysis");
    const q = messages[messages.length - 1]?.content.toLowerCase() ?? "";
    let content =
      "In your latest assessments, the two critical issues are **SQL injection in transaction search** (VULN-2201) and **broken object-level authorization on accounts** (VULN-2202). Both affect the Payments API and allow access to other customers' data. I'd fix VULN-2202 first — it's trivially exploitable by any logged-in user.";
    if (q.includes("sql")) content = "**VULN-2201 — SQL injection.** The `q` parameter on `GET /v2/transactions` is concatenated into a PostgreSQL query. A time-based payload (`pg_sleep(5)`) delayed the response by 5.02s, confirming injection.\n\n**Fix:** switch to parameterized queries, validate input length/characters, and reduce the DB user's privileges.";
    else if (q.includes("priorit") || q.includes("first")) content = "Suggested order:\n1. VULN-2202 BOLA on accounts (critical, trivial to exploit)\n2. VULN-2201 SQL injection (critical)\n3. VULN-2204 JWT 'none' algorithm (high, admin takeover)\n4. VULN-2208 SSTI in email preview (high, potential RCE)\n5. Medium configuration issues (CORS, cookies)";
    else if (q.includes("xss")) content = "**VULN-2203 — Reflected XSS.** The `next` parameter on `/login` is placed inside an inline `<script>` without encoding. Encode output for JavaScript context, restrict `next` to relative paths, and add a strict CSP.";
    return delay({ role: "assistant", content: content + "\n\n_Demo mode — connect the FastAPI backend for live analysis._" }, 900);
  },
};

export const dashboardQuery = queryOptions({ queryKey: ["dashboard"], queryFn: api.getDashboard });
export const assessmentsQuery = queryOptions({ queryKey: ["assessments"], queryFn: api.listAssessments });
export const findingsQuery = queryOptions({ queryKey: ["findings"], queryFn: () => api.listFindings() });
export const scanFindingsQuery = (id: string) => queryOptions({ queryKey: ["findings", id], queryFn: () => api.listFindings(id) });
export const projectsQuery = queryOptions({ queryKey: ["projects"], queryFn: api.listProjects });
export const findingQuery = (id: string) => queryOptions({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });
export const reportsQuery = queryOptions({ queryKey: ["reports"], queryFn: api.listReports });
export const scanAnalysisQuery = (scanId: string) =>
  queryOptions({ queryKey: ["analysis", scanId], queryFn: () => api.getScanAnalysis(scanId) });
