# AutoPentest AI — integration and verification

## Inspected existing components

- TanStack Start routes, shared dashboard layout, charts, scan/finding views,
  assessment form, analyst, reports, API client/service contracts, demo data,
  Vite configuration and frontend tests.
- Existing FastAPI router and project/target/scan/finding/assessment/analysis/UI
  endpoints; Pydantic schemas; SQLAlchemy models/database setup and migrations.
- Existing Nmap, FFUF, Nuclei and ZAP adapters, orchestrator, scope checks,
  process execution, redaction, Claude analysis and Markdown report generation.
- Backend configuration, documented launch instructions and 520 backend tests.

Inspected the repository checkout supplied to this project, not a separate
GitHub API copy. Git connection status and remote branch state are not available
from this checkout inspection. No duplicate backend or scanning engine was created.

## Completed integration changes

- Added Targets: create/select projects, explicitly register authorized targets,
  list persisted targets, and revoke authorization through existing endpoints.
- Replaced misleading module, authenticated-scan and custom assessment-name
  inputs with actual backend scanner profiles and installed-tool readiness.
  Backend scan names already come from registered target names.
- Fixed standard/deep profiles to use Nuclei's existing standard template profile.
  Request limit is labeled FFUF/Nuclei rather than claiming a pipeline-wide cap.
- Added 30-second request/body timeouts, useful network/validation errors, safe
  download failures and no mutation retries or live-to-demo fallback.
- Scan pages now show their own findings, analyst/report actions and visible
  fetch errors rather than indefinite loading placeholders.
- Preserved live assessment-based Claude analysis; the backend has **no chat
  endpoint**. It reviews normalized actual findings and stores validated results.
- Reports download actual existing Markdown output through the service client.
- Demo mode cannot claim an assessment was submitted. Demo timestamps are
  deterministic; production relative API configuration fails clearly without
  a configured server origin rather than silently defaulting to localhost.
- Unexpected/provider analyst errors no longer expose arbitrary exception
  payloads in API results or unexpected-error logs.
- Kept existing branding and added individual page social metadata.

## Connected endpoints

All paths below are relative to configured `VITE_API_BASE_URL` ending `/api/v1`.

| Method | Path | UI purpose |
| --- | --- | --- |
| GET | `/dashboard/summary` | Stored-record dashboard |
| GET, POST | `/assessments` | Scan history and submit authorized assessment |
| GET | `/assessments/{id}` | Real status, stages, logs and progress |
| GET | `/findings` | Workspace findings |
| GET | `/findings?assessmentId={id}` | Findings for a particular scan |
| GET | `/findings/{id}/detail` | Camel-case UI evidence/remediation contract |
| GET, POST | `/projects` | Project selection/registration |
| GET, POST | `/projects/{id}/targets` | Target listing/explicit registration |
| PATCH | `/targets/{id}` | Revoke scanning authorization |
| GET | `/tools` | Real scanner availability |
| GET, POST | `/scans/{id}/analysis` | Latest analysis and confirmed new analysis |
| GET | `/reports` | Available real reports |
| GET | `/reports/{id}/download` | Actual Markdown report download |

Existing legacy scan/finding APIs, analysis history, raw scanner output and
`/scans/{id}/report` remain intact; not every existing endpoint needs a new UI.

## Tests and live verification

- **43 frontend tests passed**: existing routing/display/live analyst tests plus
  actual profile mapping, credential-free URL validation, timeout, validation
  errors, no mock fallback, no demo scan submission, and target/report paths.
- **520 backend tests passed** using isolated databases, fake scanners and fake
  provider responses. Four added regressions cover actual Nuclei profile mapping
  and secret-free unexpected analyst errors. These do not prove real scans or
  provider availability.
- Started the **existing FastAPI app**, loopback-only, against a temporary empty
  SQLite database. Health and `/tools` worked; all four tools were unavailable.
- Temporarily connected the actual preview to the API using an absolute local
  address and exact CORS origin. Created a project and explicitly authorized
  local target through the UI, then read it back from the real API through the UI.
- New Assessment correctly disabled launch with missing tools. A direct actual
  submission against the locally owned API returned **403**, because private
  targets remain blocked; no successful scan was claimed.
- Live analyst showed no assessments, reports showed no reports, and desktop
  1280×1800, current viewport 822×722 and mobile 390×844 had no page errors or
  document overflow. Screenshots were inspected.
- The sandbox strips custom Vite proxies; relative `/api/v1` requests did not
  reach FastAPI there. Absolute API configuration succeeded. Local non-sandbox
  Vite proxy configuration remains available; production needs HTTPS routing.
- Temporary local API configuration was removed after testing. The delivered
  preview remains explicitly demo mode until a deployed reachable API is supplied.
- Frontend build/TypeScript validation passed in platform diagnostics after fixes;
  no separate manual build was invoked. Demo scan progress is deterministic to
  prevent server/client hydration mismatches on fresh page loads.

**Not verified:** real scanner execution/completion, real findings flowing into
Claude, provider model/account access, paid analysis, or report download from an
actual completed scan. No real scan results were available in the checkout or
isolated API. No synthetic results were inserted into the live app to imply success.

## Remaining blockers and security findings

1. **Deployment address:** no deployed FastAPI URL was provided. Supply a reachable
   HTTPS API base ending `/api/v1`, exact frontend CORS origins, and redeploy.
2. **Runtime tools:** install Nmap, FFUF, Nuclei with signed templates, and Docker
   with the existing `zaproxy/zap-stable` image for deep scans. Confirm `/tools`.
3. **AI credentials/results:** configure `ANTHROPIC_API_KEY` only on the Python
   server, verify the configured model is available to that account, and run an
   authorized scan before invoking analysis. No key was available in the test runtime.
4. **Public release safety:** existing API has no user authentication or resource
   ownership enforcement; anyone able to reach it can register authorized targets.
   CORS is not authentication. Keep it private/loopback until access control,
   privileged approval and audit logging are implemented. No new identity system
   was invented or connected as part of this incremental integration.
5. **Scanner scope:** Nuclei uses hostname URLs without connection-time validated-IP
   pinning; enforce scoped egress or implement safe Host/SNI-preserving pinning
   before public deployment. Same-host discovered services may exceed a single
   registered origin; current target confirmation explicitly covers host services.
6. **Lifecycle/concurrency:** admission is check-then-write, locks are process-local,
   and restart recovery assumes one process. Existing mutation/deletion APIs do
   not guard every active analysis/ancestor operation. Keep one worker, no reload,
   and add transactional admission, active-job guards and a durable queue before
   broader deployment. These structural changes were not silently substituted.
7. **Database/process hardening:** production SQLite lacks the foreign-key pragma
   enabled by tests; subprocess unbounded `readline` may exceed intended memory
   limits on giant lines. Add database constraint setup and bounded chunk collection
   with integration coverage. Existing functionality was preserved.

## Modified/added source files

- `src/lib/api/{client,services,types,demo-data}.ts`
- `src/lib/api/assessment-config.ts` (new)
- `src/routes/targets.tsx` (new)
- `src/routes/{index,assessments.new,scans.$scanId,reports,analyst,scans.index,vulnerabilities.index,vulnerabilities.$findingId}.tsx`
- `src/components/app/AppShell.tsx`
- `src/test/api-client.test.ts`, `src/test/assessment-config.test.ts` (new)
- `backend/app/api/routes/ui.py`, `backend/app/services/ai_analyst.py`
- `backend/tests/test_ui_adapter.py`, `backend/tests/test_ai_analyst.py`
- `.env.example`, `README.md`, `backend/README.md`, `AGENTS.md`, `roadmap.md`, this report.
- `src/routeTree.gen.ts` regenerated automatically for Targets; not manually edited.

## Exact startup instructions

Follow the two-terminal commands in [README.md](README.md). Backend commands run
from `backend/`; frontend commands run from the repository root. Database and
Python `.env` locations depend on that working directory. Development is not a
production security configuration, and the Python backend is not deployed by
publishing the frontend in Lovable.