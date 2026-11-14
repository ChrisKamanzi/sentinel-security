import type { Assessment, DashboardSummary, Finding, Report, ScanStage } from "./types";

export const demoAssessments: Assessment[] = [
  { id: "asm-1042", name: "Customer Portal", target: "https://portal.northwind-bank.com", status: "running", progress: 18, startedAt: "2026-11-12T17:20:00Z", riskScore: 68, findings: { critical: 1, high: 3, medium: 5, low: 4 }, profile: "Deep" },
  { id: "asm-1041", name: "Payments API", target: "https://api.northwind-bank.com/v2", status: "completed", progress: 100, startedAt: "2026-11-11T09:12:00Z", finishedAt: "2026-11-11T10:48:00Z", riskScore: 82, findings: { critical: 2, high: 4, medium: 7, low: 9 }, profile: "Standard" },
  { id: "asm-1040", name: "Marketing Site", target: "https://www.northwind-bank.com", status: "completed", progress: 100, startedAt: "2026-11-10T14:00:00Z", finishedAt: "2026-11-10T14:31:00Z", riskScore: 24, findings: { critical: 0, high: 0, medium: 3, low: 6 }, profile: "Quick" },
  { id: "asm-1039", name: "Admin Console", target: "https://admin.northwind-bank.com", status: "completed", progress: 100, startedAt: "2026-11-08T08:20:00Z", finishedAt: "2026-11-08T11:02:00Z", riskScore: 71, findings: { critical: 1, high: 5, medium: 4, low: 2 }, profile: "Deep" },
  { id: "asm-1038", name: "Partner Gateway", target: "https://partners.northwind-bank.com", status: "failed", progress: 37, startedAt: "2026-11-06T16:45:00Z", riskScore: 0, findings: { critical: 0, high: 0, medium: 0, low: 0 }, profile: "Standard" },
];

export const stageTemplate: Omit<ScanStage, "status">[] = [
  { key: "recon", label: "Reconnaissance", description: "DNS, TLS and technology fingerprinting" },
  { key: "crawl", label: "Crawling & discovery", description: "Mapping endpoints, forms and parameters" },
  { key: "auth", label: "Authentication analysis", description: "Session handling and access control checks" },
  { key: "inject", label: "Injection testing", description: "SQLi, XSS, SSTI and command injection probes" },
  { key: "config", label: "Configuration review", description: "Headers, CORS, cookies and exposure" },
  { key: "ai", label: "AI triage", description: "Deduplication, validation and risk scoring" },
  { key: "report", label: "Report generation", description: "Compiling evidence and remediation" },
];

const ev = (method: string, path: string, body: string, status: string, resp: string) => ({
  request: `${method} ${path} HTTP/1.1\nHost: api.northwind-bank.com\nUser-Agent: AutoPentest/2.4\nCookie: session=eyJhbGciOi...\n\n${body}`,
  response: `HTTP/1.1 ${status}\nContent-Type: application/json\nServer: nginx/1.22\n\n${resp}`,
});

export const demoFindings: Finding[] = [
  { id: "VULN-2201", title: "SQL injection in transaction search", severity: "critical", category: "Injection", scanner: "SQLi Engine", assessmentId: "asm-1041", target: "api.northwind-bank.com", endpoint: "GET /v2/transactions?q=", cwe: "CWE-89", cvss: 9.8, status: "open", discoveredAt: "2026-11-11T10:02:00Z",
    description: "The `q` parameter is concatenated into a SQL query without parameterization. Boolean- and time-based payloads produced measurable differences, confirming blind SQL injection against a PostgreSQL backend.",
    evidence: ev("GET", "/v2/transactions?q=x'%20AND%20pg_sleep(5)--", "", "200 OK (5.02s)", '{"results":[],"took_ms":5021}'),
    businessImpact: "An attacker could read or modify any customer's transaction history, extract credentials, and potentially pivot to the core banking database. This exposes the organization to regulatory penalties (PCI DSS, GDPR) and severe reputational damage.",
    remediation: ["Use parameterized queries / prepared statements for all database access.", "Apply an allow-list for search input characters and length.", "Run the API database user with least privilege (read-only on reporting views).", "Add WAF rules for SQL metacharacters as defense in depth."] },
  { id: "VULN-2202", title: "Broken object level authorization on accounts", severity: "critical", category: "Access Control", scanner: "AuthZ Analyzer", assessmentId: "asm-1041", target: "api.northwind-bank.com", endpoint: "GET /v2/accounts/{id}", cwe: "CWE-639", cvss: 9.1, status: "triaged", discoveredAt: "2026-11-11T10:15:00Z",
    description: "Changing the numeric account ID returns other customers' account data while authenticated as a low-privileged user.",
    evidence: ev("GET", "/v2/accounts/100248", "", "200 OK", '{"id":100248,"owner":"J. Alvarez","balance":48210.55,"iban":"DE89 3704..."}'),
    businessImpact: "Any authenticated user can enumerate and view all customer accounts, including balances and IBANs — a reportable data breach.",
    remediation: ["Enforce ownership checks server-side on every object lookup.", "Use non-sequential, unguessable identifiers (UUIDv4).", "Add automated authorization tests to CI."] },
  { id: "VULN-2203", title: "Reflected cross-site scripting in login redirect", severity: "high", category: "XSS", scanner: "XSS Engine", assessmentId: "asm-1042", target: "portal.northwind-bank.com", endpoint: "GET /login?next=", cwe: "CWE-79", cvss: 7.4, status: "open", discoveredAt: "2026-11-12T17:10:00Z",
    description: "The `next` parameter is reflected into an inline script without encoding.",
    evidence: ev("GET", "/login?next=%22%3Balert(document.domain)%2F%2F", "", "200 OK", '<script>var next = "";alert(document.domain)//";</script>'),
    businessImpact: "Attackers can craft phishing links that execute script in the portal origin, stealing sessions or performing actions as the victim.",
    remediation: ["Context-encode all reflected values.", "Validate `next` against an allow-list of relative paths.", "Deploy a strict Content-Security-Policy without 'unsafe-inline'."] },
  { id: "VULN-2204", title: "JWT accepted with 'none' algorithm", severity: "high", category: "Authentication", scanner: "AuthZ Analyzer", assessmentId: "asm-1039", target: "admin.northwind-bank.com", endpoint: "POST /api/session/verify", cwe: "CWE-347", cvss: 8.1, status: "open", discoveredAt: "2026-11-08T09:40:00Z",
    description: "Tokens with `alg: none` and no signature are accepted as valid.",
    evidence: ev("POST", "/api/session/verify", '{"token":"eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}', "200 OK", '{"valid":true,"role":"admin"}'),
    businessImpact: "Full administrative access can be forged without credentials.",
    remediation: ["Pin accepted algorithms explicitly (e.g. RS256).", "Upgrade the JWT library to a version that rejects 'none' by default."] },
  { id: "VULN-2205", title: "Permissive CORS policy reflects arbitrary origins", severity: "medium", category: "Configuration", scanner: "Config Auditor", assessmentId: "asm-1041", target: "api.northwind-bank.com", endpoint: "OPTIONS /v2/*", cwe: "CWE-942", cvss: 5.9, status: "open", discoveredAt: "2026-11-11T09:50:00Z",
    description: "The API reflects any Origin header with credentials allowed.",
    evidence: ev("OPTIONS", "/v2/accounts", "", "204 No Content", "Access-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true"),
    businessImpact: "Malicious sites can read authenticated API responses from a victim's browser.",
    remediation: ["Allow-list trusted origins explicitly.", "Do not combine wildcard/reflected origins with credentials."] },
  { id: "VULN-2206", title: "Missing HSTS header", severity: "low", category: "Configuration", scanner: "Config Auditor", assessmentId: "asm-1040", target: "www.northwind-bank.com", endpoint: "GET /", cwe: "CWE-319", cvss: 3.1, status: "fixed", discoveredAt: "2026-11-10T14:12:00Z",
    description: "Strict-Transport-Security is not set.",
    evidence: ev("GET", "/", "", "200 OK", "(no Strict-Transport-Security header)"),
    businessImpact: "Users on hostile networks could be downgraded to HTTP.",
    remediation: ["Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`."] },
  { id: "VULN-2207", title: "Server version disclosure", severity: "low", category: "Information Disclosure", scanner: "Recon", assessmentId: "asm-1041", target: "api.northwind-bank.com", endpoint: "GET /", cwe: "CWE-200", cvss: 2.7, status: "open", discoveredAt: "2026-11-11T09:14:00Z",
    description: "Server header discloses nginx/1.22.",
    evidence: ev("GET", "/", "", "200 OK", "Server: nginx/1.22"),
    businessImpact: "Helps attackers target known CVEs for the exact version.",
    remediation: ["Set `server_tokens off;` in nginx."] },
  { id: "VULN-2208", title: "Server-side template injection in email preview", severity: "high", category: "Injection", scanner: "SSTI Engine", assessmentId: "asm-1039", target: "admin.northwind-bank.com", endpoint: "POST /api/templates/preview", cwe: "CWE-1336", cvss: 8.6, status: "open", discoveredAt: "2026-11-08T10:22:00Z",
    description: "Jinja2 expressions in the template body are evaluated server-side.",
    evidence: ev("POST", "/api/templates/preview", '{"body":"{{7*7}}"}', "200 OK", '{"html":"49"}'),
    businessImpact: "Can lead to remote code execution on the admin server.",
    remediation: ["Render user templates in a sandboxed environment.", "Restrict template features to a safe subset."] },
  { id: "VULN-2209", title: "Session cookie missing SameSite attribute", severity: "medium", category: "Session Management", scanner: "Config Auditor", assessmentId: "asm-1042", target: "portal.northwind-bank.com", endpoint: "POST /login", cwe: "CWE-1275", cvss: 4.3, status: "open", discoveredAt: "2026-11-12T17:15:00Z",
    description: "The session cookie lacks SameSite, increasing CSRF exposure.",
    evidence: ev("POST", "/login", "username=demo&password=****", "302 Found", "Set-Cookie: session=abc123; Secure; HttpOnly"),
    businessImpact: "Increases the chance of cross-site request forgery against logged-in users.",
    remediation: ["Set `SameSite=Lax` (or Strict) on session cookies.", "Use anti-CSRF tokens on state-changing forms."] },
  { id: "VULN-2210", title: "Verbose stack traces on error", severity: "medium", category: "Information Disclosure", scanner: "Recon", assessmentId: "asm-1039", target: "admin.northwind-bank.com", endpoint: "GET /api/users/abc", cwe: "CWE-209", cvss: 5.3, status: "triaged", discoveredAt: "2026-11-08T09:05:00Z",
    description: "Unhandled errors return full Python stack traces.",
    evidence: ev("GET", "/api/users/abc", "", "500 Internal Server Error", 'Traceback (most recent call last):\n  File "/srv/app/users.py", line 88...'),
    businessImpact: "Reveals internal paths, libraries and logic useful for further attacks.",
    remediation: ["Return generic error messages in production.", "Log details server-side only."] },
];

export const demoSummary: DashboardSummary = {
  riskScore: 72,
  riskTrend: -6,
  totalScans: 148,
  activeScans: 1,
  totalVulnerabilities: 263,
  criticalFindings: 9,
  breakdown: { critical: 9, high: 38, medium: 94, low: 122 },
  findingsOverTime: [
    { date: "Jun", critical: 4, high: 12, medium: 30, low: 41 },
    { date: "Jul", critical: 6, high: 15, medium: 28, low: 38 },
    { date: "Aug", critical: 3, high: 11, medium: 33, low: 45 },
    { date: "Sep", critical: 7, high: 18, medium: 36, low: 40 },
    { date: "Oct", critical: 5, high: 14, medium: 29, low: 36 },
    { date: "Nov", critical: 9, high: 16, medium: 24, low: 31 },
  ],
  scanActivity: [
    { day: "Mon", scans: 6 }, { day: "Tue", scans: 9 }, { day: "Wed", scans: 4 }, { day: "Thu", scans: 11 },
    { day: "Fri", scans: 7 }, { day: "Sat", scans: 2 }, { day: "Sun", scans: 3 },
  ],
  recentActivity: [
    { id: "a1", time: "6 min ago", message: "Deep scan started on portal.northwind-bank.com", type: "scan" },
    { id: "a2", time: "9 min ago", message: "High: Reflected XSS in login redirect", type: "finding" },
    { id: "a3", time: "1 day ago", message: "Report generated for Payments API", type: "report" },
    { id: "a4", time: "1 day ago", message: "Critical: SQL injection in transaction search", type: "finding" },
    { id: "a5", time: "2 days ago", message: "Quick scan completed on www.northwind-bank.com", type: "scan" },
  ],
};

export const demoReports: Report[] = [
  { id: "rpt-311", assessmentId: "asm-1041", title: "Payments API — Full Assessment", target: "api.northwind-bank.com", generatedAt: "2026-11-11T10:50:00Z", format: "pdf", sizeKb: 2480, findings: 22 },
  { id: "rpt-310", assessmentId: "asm-1040", title: "Marketing Site — Quick Scan", target: "www.northwind-bank.com", generatedAt: "2026-11-10T14:33:00Z", format: "pdf", sizeKb: 860, findings: 9 },
  { id: "rpt-309", assessmentId: "asm-1039", title: "Admin Console — Executive Summary", target: "admin.northwind-bank.com", generatedAt: "2026-11-08T11:05:00Z", format: "html", sizeKb: 412, findings: 12 },
  { id: "rpt-308", assessmentId: "asm-1039", title: "Admin Console — Raw Findings", target: "admin.northwind-bank.com", generatedAt: "2026-11-08T11:05:00Z", format: "json", sizeKb: 196, findings: 12 },
];
