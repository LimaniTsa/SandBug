# SandBug
### AI-Assisted Malware Analysis Sandbox (Final Year Project)

SandBug is a web-based malware analysis platform that combines traditional static and dynamic analysis techniques with AI-powered report generation. The system is designed to make malware analysis accessible to both technical security analysts and non-technical stakeholders by providing clear insights into potentially malicious files.

---

## 🚀 Technology Stack

### **Backend**
- **Framework:** Flask 3.0.0  
- **Database:** PostgreSQL 14+  
- **ORM:** SQLAlchemy 3.1.1  
- **Authentication:** Flask-JWT-Extended 4.6.0  
- **Password Hashing:** Flask-Bcrypt 1.0.1  
- **File Type Detection:** python-magic-bin 0.4.14  
- **API Architecture:** RESTful + Flask Blueprints  

### **Frontend**
- **Framework:** React 18.2.0 (TypeScript)  
- **Routing:** React Router DOM 
- **HTTP Client:** Axios  
- **Icons:** Lucide React 0.263.1  
- **Styling:** CSS 
- **Font:** Inter (Google Fonts)  

### **Development Tools**
- Git + GitHub  
- DBeaver (PostgreSQL GUI)  
- Visual Studio Code  
- Python venv, pip  
- Node.js + npm  

### **Static File Analysis**
- python-magic-bin (MIME detection)  
- hashlib (hashing)  
- PEfile  

---

## 📦 Prerequisites

| Software      | Minimum Version | Download Link |
|---------------|------------------|----------------|
| Python        | 3.9+            | https://python.org |
| Node.js       | 18.0+           | https://nodejs.org |
| PostgreSQL    | 14+             | https://postgresql.org |
| Git           | 2.30+           | https://git-scm.com |

---

# 🛠 Installation Guide

## Step 1 — Clone Repository

```bash
git clone https://github.com/LimaniTsa/SandBug.git
cd sandbug
```

## Step 1 — Backend Setup

```bash
cd backend
```

## Create & Activate Virtual Environment

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```
### Mac/Linux
```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Run the Backend

```bash
python run.py
```

## File Structure

```
SandBug/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── analysis.py
│   │   │   ├── auth.py
│   │   │   └── info.py
│   │   │
│   │   ├── config/
│   │   │   └── __init__.py
│   │   │
│   │   ├── models/
│   │   │   └── __init__.py
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   └── static_analyzer.py
│   │   │
│   │   └── __init__.py
│   │
│   ├── migrations/
│   │   ├── versions/
│   │   ├── README
│   │   ├── alembic.ini
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── __pycache__/
│   │
│   ├── run.py
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   │   ├── favicon.ico
│   │   ├── index.html
│   │   ├── logo192.png
│   │   ├── logo512.png
│   │   ├── manifest.json
│   │   └── robots.txt
│   │
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── FeatureCard.css
│   │   │   │   ├── FeatureCard.tsx
│   │   │   │   ├── Iridescence.css
│   │   │   │   ├── Iridescence.tsx
│   │   │   │   ├── StaticResults.css
│   │   │   │   └── StaticResults.tsx
│   │   │   │
│   │   │   └── layout/
│   │   │       ├── Footer.css
│   │   │       ├── Footer.tsx
│   │   │       ├── Header.css
│   │   │       └── Header.tsx
│   │
│   │   ├── pages/
│   │   │   ├── Auth.css
│   │   │   ├── Dashboard.css
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Landing.css
│   │   │   ├── Landing.tsx
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   ├── Results.css
│   │   │   └── Results.tsx
│   │
│   │   ├── services/
│   │   │   └── api.ts
│   │
│   │   ├── styles/
│   │   │   └── globals.css
│   │
│   │   ├── types/
│   │   │   ├── App.tsx
│   │   │   ├── index.css
│   │   │   └── index.tsx
│   │
│   │   ├── react-app-env.d.ts
│   │   ├── reportWebVitals.ts
│   │   └── App.tsx
│   │
│   ├── package.json
│   ├── package-lock.json
│   └── tsconfig.json
│
├── README.md
└── .gitignore
```
