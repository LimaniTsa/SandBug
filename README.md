# SandBug
### AI-Assisted Malware & URL Threat Analysis Platform (Final Year Project)

SandBug is a web-based threat analysis platform that combines static file analysis, dynamic sandboxing, URL threat intelligence, and AI-powered report generation. It is designed to make malware analysis accessible to both technical security analysts and non-technical users by surfacing clear, actionable insights through a clean interface.

---

## Features

- **Static File Analysis:** PE header inspection, entropy analysis, section analysis, import table parsing, and YARA signature matching (generic malware, ransomware, and packer rules)
- **Dynamic Sandboxing:** Automated behavioural analysis via the Triage sandbox; captures network activity, process trees, dropped files, registry changes, and threat signatures
- **URL Analysis:** Redirect chain following, SSL certificate validation, IP reputation (AbuseIPDB), Google Safe Browsing lookup, heuristic scoring, and a dedicated IP grabber detection engine
- **AI-Generated Summaries:** Plain-English threat summaries powered by Claude Haiku (Anthropic), generated for both file and URL analyses
- **Risk Scoring:** Combined risk score (0-100) derived from static indicators, dynamic sandbox score, and URL threat signals, mapped to Low / Medium / High / Critical levels
- **PDF Report Export:** Downloadable PDF report for every analysis
- **Analysis History:** Registered users can view, filter, and revisit all previous analyses
- **Guest Mode:** Full analysis functionality available without an account; results are not persisted

---

## Technology Stack

### Backend
- **Framework:** Flask 3.0.0
- **Task Queue:** Redis + RQ (asynchronous analysis jobs)
- **Database:** PostgreSQL 14+
- **ORM:** Flask-SQLAlchemy 3.1.1
- **Migrations:** Flask-Migrate 4.0.5
- **Authentication:** Flask-JWT-Extended 4.6.0
- **Password Hashing:** Flask-Bcrypt 1.0.1
- **File Type Detection:** python-magic 0.4.27
- **PE Analysis:** pefile 2023.2.7, lief 0.13.2
- **Disassembly:** capstone 5.0.0
- **YARA Matching:** Custom rules (generic, ransomware, packers)
- **Dynamic Analysis:** Triage sandbox API (triage_client)
- **URL Analysis:** requests, socket, ssl, AbuseIPDB API, Google Safe Browsing API
- **AI Summaries:** Anthropic Claude Haiku via claude-sdk
- **PDF Generation:** report_generator service
- **API Architecture:** RESTful, Flask Blueprints

### Frontend
- **Framework:** React 19 (TypeScript)
- **Routing:** React Router DOM 7
- **HTTP Client:** Axios
- **Charts:** Recharts
- **Icons:** Lucide React
- **3D / Canvas:** OGL, Three.js (hero background effects)
- **Styling:** Plain CSS with CSS custom properties (light + dark theme)
- **Font:** Inter (Google Fonts)

### Infrastructure
- Git + GitHub
- PostgreSQL (via psycopg2-binary)
- Redis (job queue broker)
- Python venv + pip
- Node.js + npm

---


## File Structure

```
SandBug/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── analysis.py        # File upload, URL check, report download endpoints
│   │   │   ├── auth.py            # Register, login, JWT endpoints
│   │   │   └── info.py            # Features list, health check
│   │   ├── config/
│   │   │   └── __init__.py        # App config and environment loading
│   │   ├── models/
│   │   │   └── __init__.py        # SQLAlchemy models (Analysis, User)
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── ai_summarizer.py   # Claude Haiku summary generation
│   │   │   ├── dynamic_analyzer.py# Triage sandbox integration
│   │   │   ├── report_generator.py# PDF report builder
│   │   │   ├── static_analyzer.py # PE analysis, entropy, YARA matching
│   │   │   ├── triage_client.py   # Triage API client
│   │   │   ├── url_analyzer.py    # URL threat analysis engine
│   │   │   └── yara/
│   │   │       ├── __init__.py
│   │   │       ├── yara_engine.py
│   │   │       └── rules/
│   │   │           ├── generic.yar
│   │   │           ├── packers.yar
│   │   │           └── ransomware.yar
│   │   ├── tasks.py               # RQ background task definitions
│   │   └── __init__.py            # App factory
│   ├── run.py                     # Flask dev server entry point
│   ├── worker.py                  # RQ worker entry point
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── AnalysisOverview.tsx  # Main results renderer (file + URL)
│   │   │   │   ├── AnalysisProgress.tsx  # Polling progress indicator
│   │   │   │   ├── FeatureCard.tsx       # Landing page feature cards
│   │   │   │   ├── Iridescence.tsx       # Light mode hero background
│   │   │   │   └── LiquidEther.tsx       # Dark mode hero background
│   │   │   └── layout/
│   │   │       ├── Header.tsx
│   │   │       └── Footer.tsx
│   │   ├── hooks/
│   │   │   └── useAnalysisPoller.ts     # Polls analysis status until complete
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx            # File upload + URL check interface
│   │   │   ├── History.tsx              # User analysis history
│   │   │   ├── Landing.tsx
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   └── Results.tsx              # Analysis results page
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── styles/
│   │   │   └── globals.css
│   │   ├── types/
│   │   │   └── index.ts
│   │   ├── utils/
│   │   │   └── generateReport.ts        # PDF download helper
│   │   ├── App.tsx
│   │   ├── index.tsx
│   │   └── index.css
│   └── package.json
│
├── README.md
└── .gitignore
```
