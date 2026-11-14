# AutoPentest AI

## Run the complete existing application

See [the integration report](INTEGRATION.md) for inspected components, connected
endpoints, test results, modified files, and remaining deployment/security blockers.

### Terminal 1: existing Python backend

```sh
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

In `backend/.env`, set `CORS_ORIGINS=http://localhost:8080` (replace this with
your actual frontend origin if different). Configure scanner executable paths
and server-only `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` as needed. Then:

```sh
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --workers 1
```

### Terminal 2: frontend, from repository root

```sh
bun install
cp .env.example .env.development.local
bun run dev -- --port 8080
```

Open `http://localhost:8080`. The example points **local development only** to
`http://127.0.0.1:8001/api/v1`. Register a project and explicitly authorized
target on **Targets**, install the required tools shown on **New Assessment**,
and launch a scan against a system you own or have written permission to test.
Private targets are blocked by default; `ALLOW_PRIVATE_TARGETS=true` is only for
your isolated, authorized local lab. It never permits cloud metadata/link-local targets.

After the backend confirms completion, open the scan's **AI analysis** action,
confirm the external provider call, and read the persisted result. Reports
download as Markdown; PDF/HTML/JSON generation is not implemented in this backend.

For deployment, host FastAPI and scanner tools separately and set the frontend's
`VITE_API_BASE_URL` to its reachable **HTTPS URL ending in `/api/v1`**, with exact
backend CORS origins. Rebuild/redeploy after changing the frontend variable.
Never deploy a localhost API address or rely on the Vite development proxy.
Do not expose the existing API publicly before implementing authentication,
ownership checks, and scoped scanner egress; see the release blockers below.

### Checks

```sh
bun run test
cd backend
.venv/bin/python -m pytest tests -q
```

Frontend production build/TypeScript checks run automatically in Lovable; for
your own local/CI environment the existing `bun run build` script is available.

---

Build a premium cybersecurity SaaS dashboard called AutoPentest AI.

Product: AI-powered automated web application security assessment platform.

Design direction:

Dark cybersecurity interface.

Professional enterprise SaaS appearance.

Navy, charcoal and subtle blue/purple accents.

Modern typography.

Clean cards, charts and tables.

Responsive design.

Pages:

Dashboard: overview, total scans, vulnerabilities, critical findings and recent activity.

New Assessment: URL input, authorization confirmation and scan configuration.

Scan Details: real-time progress and assessment stages.

Vulnerabilities: filterable findings by severity, category and scanner.

Finding Details: technical evidence, business impact and remediation.

AI Security Analyst: conversational interface for understanding findings.

Reports: downloadable assessment reports.

Dashboard must include:

Risk score.

Critical/high/medium/low vulnerability breakdown.

Recent assessments.

Scan activity.

Security findings chart.

Use reusable components and realistic demo data initially.

Architecture:
The frontend must communicate with a separate Python FastAPI backend. Do not implement the scanning engine in the frontend. Use API services that can later be connected to real endpoints.

Prioritize a polished, usable MVP over unnecessary animations and features.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/d929e189-549a-4b02-94b1-9c13b90a6f48).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
