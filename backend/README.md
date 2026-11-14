# AutoPentest AI — Existing FastAPI backend

## 1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

## 3. Configure the environment

```bash
cp .env.example .env
```

SQLite is the default development database. To use PostgreSQL later, install a PostgreSQL driver and set `DATABASE_URL` in `.env`.

## 4. Start the API

Run from the `backend/` directory so `.env` and the development database have
consistent locations. Do not use reload or multiple workers while jobs run:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --workers 1
```

Open:
- http://127.0.0.1:8001/
- http://127.0.0.1:8001/health
- http://127.0.0.1:8001/docs

Startup creates any missing tables and adds missing columns to an existing
SQLite database in place (additive only; existing rows are preserved).

## 5. Run the tests

```bash
.venv/bin/python -m pytest -v
```

Tests use an in-memory database and fake scanners: they never touch
`autopentest.db` and never run a real scan.

## Scanners

| Tool | Status |
|---|---|
| Nmap | Implemented (TCP connect scan, top 1000 ports + target port, service detection) |
| FFUF | Implemented (content discovery on Nmap-discovered web services; built-in `quick` wordlist) |
| Nuclei | Implemented (HTTP templates on Nmap-discovered web services; `quick`/`standard` profiles) |
| OWASP ZAP | Implemented (baseline: spider + passive scan only, via the `zaproxy/zap-stable` Docker image) |

Pipeline order is always Nmap -> FFUF -> Nuclei -> ZAP, whatever order is requested.

ZAP safety defaults: `zap-baseline.py` only (no active scan rules, no attack payloads), spider form
submission disabled, 1-minute spider, container with all capabilities dropped, no-new-privileges,
memory/PID limits, `--pull=never`, always removed afterwards (also on timeout). Image, Docker path and
network are server settings only. Hostname targets are DNS-pinned with `--add-host`; with a
`container:` network they fail closed. Setup: `docker pull zaproxy/zap-stable`. Lab setting for the
loopback Juice Shop: `ZAP_DOCKER_NETWORK=container:juice-shop`. Options: `{"zap": {"spider_minutes": 1}}`.

FFUF safety defaults: GET only, built-in curated wordlist (~250 paths; API clients cannot
supply file paths), no recursion, no redirects followed, 20 req/s and 5 threads by default,
300 s per run, auto-calibration plus a flood guard against catch-all responses. Response
bodies are never collected and redirect locations are redacted. Each run uses a throwaway
`HOME`/`XDG_CONFIG_HOME`, so your own `~/.config/ffuf` config and history are never touched.
DNS-rebinding protection: authorization, DNS and IP policy are re-checked immediately before
each FFUF execution, and FFUF connects to the validated IP (hostname sent as Host header and
TLS SNI), failing closed if DNS no longer matches. FFUF findings are `info`, or `low` for a
sensitive-looking path that returned content; never higher, since FFUF never sees content.
Example options: `{"ffuf": {"rate_limit": 20, "extensions": [".bak"]}}`.

Nuclei safety defaults: HTTP templates only, intrusive/DoS/fuzz/brute-force/default-login
templates excluded, no interactsh (OAST) callbacks, no redirects, signed templates only,
50 req/s, request/response bodies omitted from stored output. Nuclei does not receive
FFUF's discovered paths.

Workflow: project -> target (`is_authorized: true`) -> scan -> `POST /api/v1/scans/{id}/start`
-> poll `GET /api/v1/scans/{id}/assessment` -> `GET /api/v1/scans/{id}/findings`.

### Claude AI Analyst

`POST /api/v1/scans/{id}/analysis` (after the assessment finishes) queues a Claude analysis;
poll `GET /api/v1/scans/{id}/analysis`. `GET /api/v1/scans/{id}/report` returns a Markdown
report combining findings and the latest analysis.

- Model from `ANTHROPIC_MODEL` (default `claude-opus-5-5`), structured JSON output validated
  server-side, server-side refusal fallback enabled (`fallbacks: "default"`).
- Only normalized finding fields are sent; secrets are redacted and long fields truncated.
  Raw tool output is never sent. Scan data is marked as untrusted input in the prompt.
- Claude has no tools: its output is stored and displayed, never executed.
- Credentials stay on the server: `ANTHROPIC_API_KEY` from `.env` (or the environment) is
  passed explicitly to the SDK, so OAuth / `ant auth login` profiles are never used. Without
  a key, analyses fail with a clear error instead of falling back to other credentials.

Safety rules enforced by the backend:
- A target's `host` must be a bare hostname/IP and `base_url` must be on that host.
- Before **every** scanner execution the target is re-read, must be authorized, and every
  resolved IP is checked. Cloud metadata/link-local addresses are always blocked; private
  and loopback addresses require `ALLOW_PRIVATE_TARGETS=true` (local development only).
- Tools run without a shell, with absolute paths, a minimal environment and hard timeouts.
- One assessment runs at a time. Assessments interrupted by a restart are marked failed.

Run the API bound to localhost only and, for demos, without `--reload` (a reload
interrupts a running assessment). Set `CORS_ORIGINS` to your frontend's exact origin.

For production, replace `create_all()` with Alembic migrations and add authentication,
authorization, audit logging, and a durable worker queue.
