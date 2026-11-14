import { queryOptions } from "@tanstack/react-query";
import { apiFetch, apiUrl, isDemoMode } from "./client";
import { demoAssessments, demoFindings, demoReports, demoSummary, stageTemplate } from "./demo-data";
import type { Assessment, ChatMessage, DashboardSummary, Finding, NewAssessmentInput, Report, ScanDetail } from "./types";

/*
 * Service layer for the FastAPI backend. Each function maps to one endpoint.
 * In demo mode (no VITE_API_BASE_URL) bundled data is returned instead.
 */
const delay = <T,>(v: T, ms = 250) => new Promise<T>((r) => setTimeout(() => r(v), ms));

// Demo-only: simulated scan progress for running assessments.
const demoStart = Date.now();
function demoProgress(a: Assessment): Assessment {
  if (a.status !== "running") return a;
  const p = Math.min(99, Math.floor(((Date.now() - demoStart) / 1000) * 1.2) + 18);
  return { ...a, progress: p };
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
    return isDemoMode
      ? delay({ ...demoAssessments[0]!, name: input.name, target: input.target }, 600)
      : apiFetch("/assessments", { method: "POST", body: JSON.stringify(input) });
  },

  /** GET /assessments/{id} — poll for real-time progress */
  getScan: async (id: string): Promise<ScanDetail> => {
    if (!isDemoMode) return apiFetch(`/assessments/${id}`);
    const base = demoAssessments.find((a) => a.id === id) ?? demoAssessments[0]!;
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
  listFindings: (): Promise<Finding[]> => (isDemoMode ? delay(demoFindings) : apiFetch("/findings")),

  /** GET /findings/{id} */
  getFinding: async (id: string): Promise<Finding | null> => {
    if (!isDemoMode) return apiFetch(`/findings/${id}`);
    return delay(demoFindings.find((f) => f.id === id) ?? null);
  },

  /** GET /reports */
  listReports: (): Promise<Report[]> => (isDemoMode ? delay(demoReports) : apiFetch("/reports")),

  /** URL for GET /reports/{id}/download */
  reportDownloadUrl: (id: string) => (isDemoMode ? null : apiUrl(`/reports/${id}/download`)),

  /** POST /analyst/chat */
  askAnalyst: async (messages: ChatMessage[], findingId?: string): Promise<ChatMessage> => {
    if (!isDemoMode) return apiFetch("/analyst/chat", { method: "POST", body: JSON.stringify({ messages, finding_id: findingId }) });
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
export const findingsQuery = queryOptions({ queryKey: ["findings"], queryFn: api.listFindings });
export const findingQuery = (id: string) => queryOptions({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });
export const reportsQuery = queryOptions({ queryKey: ["reports"], queryFn: api.listReports });
