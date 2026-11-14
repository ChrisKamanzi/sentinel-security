# Sentinel Security

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
