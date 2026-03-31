# SandBug
### AI-Assisted Malware & URL Threat Analysis Platform (Final Year Project)

SandBug is a web-based threat analysis platform that combines static file analysis, dynamic sandboxing, URL threat intelligence, and AI-powered report generation. It is designed to make malware analysis accessible to both technical security analysts and non-technical users by surfacing clear, actionable insights through a clean interface.

---

## Features

- **Static File Analysis** — PE header inspection, entropy analysis, section analysis, import table parsing, and YARA signature matching (generic malware, ransomware, and packer rules)
- **Dynamic Sandboxing** — Automated behavioural analysis via the Triage sandbox; captures network activity, process trees, dropped files, registry changes, and threat signatures
- **URL Analysis** — Redirect chain following, SSL certificate validation, IP reputation (AbuseIPDB), Google Safe Browsing lookup, heuristic scoring, and a dedicated IP grabber detection engine
- **AI-Generated Summaries** — Plain-English threat summaries powered by Claude Haiku (Anthropic), generated for both file and URL analyses
- **Risk Scoring** — Combined risk score (0–100) derived from static indicators, dynamic sandbox score, and URL threat signals, mapped to Low / Medium / High / Critical levels
- **PDF Report Export** — Downloadable PDF report for every analysis
- **Analysis History** — Registered users can view, filter, and revisit all previous analyses
- **Guest Mode** — Full analysis functionality available without an account; results are not persisted

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

## Prerequisites

| Software   | Minimum Version |
|------------|-----------------|
| Python     | 3.9+            |
| Node.js    | 18.0+           |
| PostgreSQL | 14+             |
| Redis      | 6.0+            |
| Git        | 2.30+           |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/LimaniTsa/SandBug.git
cd SandBug
```

### 2. Backend setup

```bash
cd backend
```

**Create and activate a virtual environment**

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

Mac/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

**Install dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Configure environment variables**

Create a `.env` file in `backend/`:

```env
DATABASE_URL=postgresql://user:password@localhost/sandbug
JWT_SECRET_KEY=your-secret-key
ANTHROPIC_API_KEY=your-anthropic-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
SAFE_BROWSING_API_KEY=your-google-safe-browsing-key
TRIAGE_API_KEY=your-triage-key
REDIS_URL=redis://localhost:6379
```

**Run database migrations**

```bash
flask db upgrade
```

**Start the Flask API**

```bash
python run.py
```

**Start the RQ worker** (required for file analysis jobs)

```bash
python worker.py
```

### 3. Frontend setup

```bash
cd frontend
npm install
npm start
```

The app will be available at `http://localhost:3000`.

---

## File Structure

```
SandBug/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── analysis.py        # File upload, URL check, report download endpoints
│   │   │   ├── auth.py            # Register, login, JWT endpoints
│   │   │   └── info.py            # Features list, health check
│   │   ├── config/
│   │   │   └── __init__.py        # App config and environment loading
│   │   ├── models/
│   │   │   └── __init__.py        # SQLAlchemy models (Analysis, User)
│   │   ├── services/
│   │   │   ├── static_analyzer.py # PE analysis, entropy, YARA matching
│   │   │   ├── dynamic_analyzer.py# Triage sandbox integration
│   │   │   ├── url_analyzer.py    # URL threat analysis engine
│   │   │   ├── ai_summarizer.py   # Claude Haiku summary generation
│   │   │   ├── report_generator.py# PDF report builder
│   │   │   ├── triage_client.py   # Triage API client
│   │   │   └── yara/rules/        # YARA rule files (generic, ransomware, packers)
│   │   └── __init__.py            # App factory
│   ├── tasks.py                   # RQ background task definitions
│   ├── worker.py                  # RQ worker entry point
│   ├── run.py                     # Flask dev server entry point
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── AnalysisOverview.tsx  # Main results renderer (file + URL)
│   │   │   │   ├── AnalysisProgress.tsx  # Polling progress indicator
│   │   │   │   ├── FeatureCard.tsx       # Landing page feature cards
│   │   │   │   └── LiquidEther.tsx       # Dark mode hero background
│   │   │   └── layout/
│   │   │       ├── Header.tsx
│   │   │       └── Footer.tsx
│   │   ├── hooks/
│   │   │   └── useAnalysisPoller.ts     # Polls analysis status until complete
│   │   ├── pages/
│   │   │   ├── Landing.tsx
│   │   │   ├── Dashboard.tsx            # File upload + URL check interface
│   │   │   ├── Results.tsx              # Analysis results page
│   │   │   ├── History.tsx              # User analysis history
│   │   │   ├── Login.tsx
│   │   │   └── Register.tsx
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── utils/
│   │   │   └── generateReport.ts        # PDF download helper
│   │   └── styles/
│   │       └── globals.css
│   └── package.json
│
├── README.md
└── .gitignore
```
