# 🛡️ AutoPentest AI
### Automated Penetration Testing. Smarter Security. Stronger Applications.

**AutoPentest AI** is an AI-assisted automated penetration testing platform designed to simplify how organizations discover, assess, understand, and respond to web application security vulnerabilities.

By orchestrating established security testing tools and combining their findings into a centralized assessment workflow, AutoPentest AI aims to make penetration testing more accessible, efficient, and actionable.

Instead of manually switching between multiple security tools and interpreting disconnected outputs, security professionals and developers can work through a unified security assessment experience.

> Build fast. Test continuously. Stay secure.

---

## 🚀 The Problem

Modern software development moves quickly. Developers deploy new applications, launch features, and expose services to the internet every day.

However, security testing is often:
- Expensive for startups and small organizations.
- Time-consuming when performed entirely manually.
- Fragmented across multiple security tools.
- Difficult to interpret for developers without dedicated security expertise.
- Repetitive when assessments need to be performed regularly.

AutoPentest AI aims to bridge this gap by automating and coordinating different stages of the penetration testing process.

## 💡 The Solution

AutoPentest AI brings multiple penetration testing capabilities into one coordinated platform.

The platform follows a structured assessment workflow:

1. **Target Configuration** – Define the web application or infrastructure to assess.
2. **Reconnaissance** – Discover information and map the target's attack surface.
3. **Vulnerability Discovery** – Execute security scanning tools to identify potential weaknesses.
4. **AI-Assisted Analysis** – Help interpret findings, understand risks, and identify recommended next steps.
5. **Reporting** – Organize assessment results into structured security reports.

The objective is to reduce manual effort while making security findings easier to understand and act upon.

---

## ✨ Key Features

### 1. Centralized Security Dashboard
- Overview of security assessments.
- Vulnerability tracking.
- Assessment and scan status.
- Security findings visualization.

### 2. Automated Security Testing
Orchestrates established security tools through a coordinated testing workflow.

| Tool | Purpose |
|---|---|
| Nmap | Network discovery and service enumeration |
| FFUF | Web content and directory discovery |
| Nuclei | Vulnerability and security misconfiguration detection |
| OWASP ZAP | Web application security testing |

### 3. AI Security Analyst
An AI-assisted analysis experience designed to help users:
- Understand vulnerability findings.
- Interpret security assessment results.
- Explore potential attack paths.
- Receive remediation guidance.
- Identify appropriate next testing steps.

### 4. Vulnerability Management
- Centralized findings.
- Severity-based organization.
- Vulnerability evidence.
- Remediation recommendations.
- Finding investigation workflows.

### 5. Security Reporting
A reporting experience designed to consolidate assessment results and communicate security findings.

Supported report interface formats include:
- PDF
- HTML
- JSON

### 6. Assessment Management
Organize security testing activities through a centralized assessment interface.

---

## 🏗️ Architecture

AutoPentest AI uses a separated frontend and backend architecture.

```text
             USER
              |
              v
    +----------------------+
    |   React Frontend     |
    |  Lovable / TypeScript|
    +----------------------+
              |
              | REST API
              v
    +----------------------+
    |    FastAPI Backend   |
    |   Python / REST API  |
    +----------------------+
              |
       +------+------+
       |      |      |
       v      v      v
     Nmap    FFUF   Nuclei
       |      |      |
       +------+------+
              |
              v
       OWASP ZAP
              |
              v
    +----------------------+
    | Findings & Assessment|
    |       Storage        |
    +----------------------+
              |
              v
    +----------------------+
    | AI Analysis & Reports|
    +----------------------+
```

### Technology Stack

**Frontend**
- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- TanStack Start
- Bun

**Backend**
- Python
- FastAPI
- SQLite
- REST API

**Security Tools**
- Nmap
- FFUF
- Nuclei
- OWASP ZAP

**AI**
- Claude AI integration for assisted security analysis and reporting.

---

## 📂 Project Structure

The frontend and backend are maintained separately.

### Frontend Repository

```text
sentinel-security/
├── src/
│   ├── components/
│   ├── routes/
│   ├── hooks/
│   ├── lib/
│   └── ...
├── public/
├── package.json
├── vite.config.ts
└── README.md
```

### Backend Project

```text
autopentest-ai/
├── app/
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── services/
│   └── ...
├── tests/
├── requirements.txt
└── ...
```

*Directory structures are illustrative; see the individual repositories for the current implementation.*

---

## ⚙️ Getting Started

### Prerequisites

- Node.js
- Bun
- Python 3.11+
- Git

For actual security scanning, the backend also requires the relevant security tools to be installed and accessible.

### 1. Clone the frontend

```bash
git clone https://github.com/ChrisKamanzi/sentinel-security.git

cd sentinel-security
```

### 2. Install dependencies

```bash
bun install
```

### 3. Configure environment variables

Create a `.env` file in the frontend root:

```env
VITE_API_BASE_URL=http://127.0.0.1:8001/api/v1
```

When the API URL is not configured, the frontend can operate using its demonstration experience.

### 4. Start the frontend

```bash
bun run dev
```

Open the local URL displayed in your terminal.

### 5. Connect the backend

Start the separate FastAPI backend and ensure it is accessible at:

```text
http://127.0.0.1:8001/api/v1
```

The frontend requires compatible API endpoints and response formats to use live backend functionality.

---

## 🧪 Testing

The backend development and testing process includes automated tests for security scanning workflows and individual components.

The backend has previously passed a test suite of 481 tests.

OWASP ZAP integration also has dedicated unit tests.

Run the backend test suite from the backend project:

```bash
pytest
```

For integration testing, use a controlled environment containing applications specifically intended for security testing.

---

## 🎯 Target Users

AutoPentest AI is designed with the following users in mind:

- **Startups:** Understand potential security weaknesses before launching products.
- **Developers:** Incorporate security testing into development workflows.
- **Security Professionals:** Coordinate multiple security testing tools.
- **Small and Medium Businesses:** Improve visibility into application security.
- **Cybersecurity Students:** Learn and experiment with structured penetration testing workflows.

---

## 🔭 Roadmap

AutoPentest AI is an evolving project.

Future development priorities include:

- [ ] Complete frontend and backend API integration.
- [ ] Expand AI-assisted vulnerability analysis.
- [ ] Improve automated vulnerability prioritization.
- [ ] Enhance assessment reporting.
- [ ] Introduce continuous security assessment workflows.
- [ ] Support additional security testing tools.
- [ ] Improve scalability and multi-project management.
- [ ] Explore CI/CD security integration.

---

## 🔐 Responsible Use

AutoPentest AI is intended for authorized security assessments, educational purposes, and defensive security testing.

Users must only assess systems they own or have explicit permission to test.

The developers are not responsible for unauthorized or unlawful use of this software.

Always follow applicable laws, organizational policies, and responsible disclosure practices.

---

## 👨‍💻 Creator

**Chris Ibambe Kamanzi**

Cybersecurity Specialist | Certified Ethical Hacker (CEH v13)

Master's Student in Information Security at Vilnius Tech.

Interested in penetration testing, security automation, vulnerability research, and building practical cybersecurity solutions.

- GitHub: [@ChrisKamanzi](https://github.com/ChrisKamanzi)
- LinkedIn: [Chris Ibambe Kamanzi](https://www.linkedin.com/in/chris-ibambe-kamanzi-380178319/)

---

## ⭐ Support the Project

If you find AutoPentest AI interesting, consider giving the repository a ⭐ on GitHub.

Contributions, feedback, feature suggestions, and collaboration are welcome.

**AutoPentest AI — Automating the path from attack surface discovery to actionable security insights.**
