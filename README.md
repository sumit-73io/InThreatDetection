# 🛡️ InThreatDetection

> **An AI-driven Security Operations Center (SOC) platform** that combines behavioral analytics, statistical anomaly detection, and post-quantum cryptography to detect insider threats and protect critical administrative systems in real time.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas%2FLocal-47A248?logo=mongodb&logoColor=white)](https://mongodb.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📑 Table of Contents

1. [Introduction & Problem Statement](#1-introduction--problem-statement)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Key Features](#3-key-features)
4. [AI Anomaly Detection Engine](#4-ai-anomaly-detection-engine)
5. [Quantum-Safe Cryptography](#5-quantum-safe-cryptography)
6. [Technology Stack](#6-technology-stack)
7. [API Reference](#7-api-reference)
8. [Risk Scoring Model](#8-risk-scoring-model)
9. [Project File Structure](#9-project-file-structure)
10. [Getting Started](#10-getting-started)
11. [Demo Accounts](#11-demo-accounts)
12. [License](#12-license)

---

## 1. Introduction & Problem Statement

Modern organizations face a growing and often underestimated threat from within: **insider threats**. Malicious or compromised employees with privileged access can exfiltrate sensitive data, tamper with audit records, or abuse administrative systems — often going undetected for months.

Traditional rule-based detection (e.g., "flag if download count > 10") fails against:
- **Low-and-slow attack patterns** — gradual privilege escalation over weeks
- **Role-aware evasion** — using legitimate credentials to perform unusual actions
- **After-hours intrusions** — exploiting access outside normal working hours
- **Velocity bursts** — automated or scripted data exfiltration

**InThreatDetection** addresses these threats with a full-stack, AI-assisted SOC platform that:

- 🔍 **Continuously profiles** employee behavior using statistical anomaly detection
- 🚨 **Auto-generates alerts** when suspicious patterns are detected, every 60 seconds
- 🔐 **Cryptographically seals** every activity record using quantum-safe algorithms to prevent log tampering
- 📊 **Provides a real-time dashboard** for SOC operators to investigate, acknowledge, and respond to threats
- 🤖 **Leverages Google Gemini AI** to generate detailed forensic analysis reports on demand

---

## 2. System Architecture Overview

InThreatDetection is organized as two independently run applications communicating over a REST API, backed by a MongoDB database.

```
InThreatDetection/
├── backend/                  ← FastAPI Python server
│   └── app/
│       ├── core/             # Configuration (settings, env)
│       ├── database/         # MongoDB connection management
│       ├── models/           # Pydantic data models
│       ├── routers/          # API route definitions
│       └── services/         # Business logic
│           ├── activity_service.py    # Activity logging
│           ├── alert_service.py       # Alert persistence
│           ├── anomaly_engine.py      # ML anomaly detection
│           ├── integrity.py           # Data integrity verification
│           ├── quantum_crypto.py      # Post-quantum crypto engine
│           └── risk_engine.py         # Risk score calculator
│
└── frontend/                 ← React + Vite SPA
    └── src/
        ├── ai/               # Gemini AI integration
        ├── components/       # Shared UI components
        │   ├── EncryptionIndicator.jsx
        │   ├── IntegrityBadge.jsx
        │   ├── QuantumShield.jsx
        │   └── Sidebar.jsx
        ├── pages/            # Application views
        │   ├── Dashboard.jsx      # Admin SOC dashboard
        │   ├── LandingPage.jsx    # Public landing page
        │   └── Simulator.jsx      # Employee activity simulator
        └── services/         # API client layer
```

### Data Flow

```
Employee Simulator ──POST activity──► FastAPI Backend
                                           │
                              ┌────────────▼────────────────┐
                              │  Risk Engine  →  Risk Score  │
                              │  Quantum Engine → SHA3+AES   │
                              │  MongoDB ← Encrypted Record  │
                              └────────────┬────────────────┘
                                           │ (every 60 seconds)
                              ┌────────────▼─────────────────┐
                              │  Anomaly Engine (background)  │
                              │  - Velocity Burst Detection   │
                              │  - Role Mismatch Detection    │
                              │  - Cumulative Risk Scoring    │
                              │  - Off-Hours Detection        │
                              │  - Action Frequency Analysis  │
                              │  - API Traffic Spike Analysis │
                              └────────────┬─────────────────┘
                                           │
                              ┌────────────▼──────────────┐
                              │  SOC Dashboard (React)     │
                              │  - Real-time alerts        │
                              │  - Activity timeline       │
                              │  - Gemini AI forensics     │
                              │  - Quantum integrity view  │
                              └───────────────────────────┘
```

---

## 3. Key Features

### 🧠 Intelligent Threat Detection
- **6-signal statistical anomaly engine** that runs autonomously every 60 seconds
- **Zero ML framework dependency** — pure Python stdlib (`math`, `collections`, `datetime`) for portability
- Detects velocity bursts, role mismatches, off-hours access, cumulative risk accumulation, action frequency spikes, and API traffic anomalies

### 🔐 Quantum-Safe Data Integrity
- Every activity and alert record is **hashed with SHA3-256** and **encrypted with AES-256-GCM**
- Digital signatures using **Dilithium-3 (ML-DSA)** simulation (FIPS 204 aligned)
- Key encapsulation via **Kyber-1024 (ML-KEM)** simulation (FIPS 203 aligned)
- **Blockchain-style chaining**: each record's hash includes the previous record's hash, making retroactive tampering detectable

### 🤖 AI-Powered Forensic Reports
- On-demand **Google Gemini AI** analysis of any suspicious employee's activity history
- Generates structured forensic reports with threat assessments, indicators of compromise, and remediation recommendations

### 📊 Real-Time SOC Dashboard
- Live activity feed with per-action risk scores
- Color-coded alert severity visualization (Critical / High / Warning / Normal)
- Anomaly alert management with acknowledgement workflow
- Quantum crypto engine status monitor
- Data integrity verification panel with per-collection scores

### 🎮 Employee Activity Simulator
- Web-based interface for employees to simulate actions (login, file access, USB connect, etc.)
- Useful for testing detection rules and training SOC analysts

### 🔑 Role-Aware Access Control
- JWT-based authentication for administrators
- Separate login flow for employees (simulator access)
- All sensitive endpoints protected by admin-only guards

---

## 4. AI Anomaly Detection Engine

The engine (`anomaly_engine.py`) runs as a **background task every 60 seconds**. It analyzes the last 24 hours of employee activity data and fires alerts for the following anomaly types:

### Signal 1 — Velocity Burst Detector
Detects when an employee performs **3 or more high-risk actions within a 60-second window**.

High-risk actions tracked:
`DOWNLOAD_CONFIDENTIAL`, `DELETE_FILE`, `CHANGE_PERMISSION`, `USB_CONNECTED`, `FAILED_LOGIN`

### Signal 2 — Role-Action Mismatch Detector
Each role has a defined set of **permitted actions**. Any action outside this set raises a `ROLE_MISMATCH` alert.

| Role | Permitted Actions |
|------|-------------------|
| Admin | All actions |
| Sys Admin | Login, Logout, View, Download, Change Permission, Delete, USB |
| DB Admin | Login, Logout, View, Download Confidential, Delete |
| Dev | Login, Logout, View, Download, USB |
| HR / Branch Manager / Ops Analyst | Login, Logout, View, Download |
| Support Staff / User | Login, Logout, View |

### Signal 3 — Cumulative Risk Score Analyzer
Computes a **rolling risk score** for each employee over the last 24 hours. If the total score exceeds **120 points**, a high-severity alert is raised.

### Signal 4 — Off-Hours Access Detector
Flags any login or high-risk activity occurring between **22:00 and 06:00** local time.

### Signal 5 — Action Frequency Analyzer (Z-Score)
Uses statistical z-score analysis to detect when any employee's action count deviates significantly (**z > 2.0**) from the group mean — identifying outliers who may be performing unusually high volumes of activity.

### Signal 6 — API Traffic Spike Detector
Monitors raw API access logs over a 15-minute sliding window. Flags users making **30+ API calls** in this window, which may indicate scripted or automated exfiltration.

---

## 5. Quantum-Safe Cryptography

The `QuantumCryptoEngine` is initialized at server startup and secures every data record written to MongoDB.

### Algorithm Suite

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Symmetric Encryption | AES-256-GCM | FIPS 197 |
| Integrity Hash | SHA3-256 | NIST SP 800-185 |
| Key Encapsulation | Kyber-1024 (ML-KEM) [Simulated] | FIPS 203 |
| Digital Signature | Dilithium-3 (ML-DSA) [Simulated] | FIPS 204 |

> **Note:** The Kyber and Dilithium implementations are simulated using cryptographically secure random key generation labeled with the correct algorithm identifiers. The AES-256-GCM encryption and SHA3-256 hashing are fully functional and genuinely quantum-resistant.

### Integrity Chain

Records are stored with:
- `sha3_hash` — SHA3-256 hash of the record payload
- `prev_hash` — SHA3-256 hash of the previous record (chain link)
- `signature` — Dilithium-3 digital signature bytes (hex)
- `ciphertext`, `nonce`, `tag` — AES-256-GCM encrypted payload bundle

The `/api/quantum/integrity/verify` endpoint re-computes hashes for every record and compares against stored values, detecting any database-level tampering.

---

## 6. Technology Stack

### ⚙️ Backend

| Technology | Purpose |
|------------|---------|
| Python 3.10+ | Runtime |
| FastAPI | REST API framework |
| Uvicorn | ASGI server |
| MongoDB + Motor | Async NoSQL database |
| Pydantic | Data validation & models |
| PyCryptodome | AES-256-GCM encryption |
| Google GenAI SDK | Gemini AI integration |
| PyJWT | JWT authentication |
| python-dotenv | Environment configuration |

### 🎨 Frontend

| Technology | Purpose |
|------------|---------|
| React 19 | UI framework |
| Vite 8 | Build tool & dev server |
| Tailwind CSS 4 | Utility-first styling |
| React Router 7 | Client-side routing |
| Axios | HTTP client |

---

## 7. API Reference

All routes are served under the `/api` prefix.

### Authentication

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `POST` | `/api/auth/login` | Authenticate an administrator, issue a JWT | Public |

### Activities

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `POST` | `/api/activities/` | Log an employee activity and compute its risk score | Public |

### Dashboard

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `GET` | `/api/dashboard/activities` | Retrieve recent activity logs | Admin |
| `GET` | `/api/dashboard/alerts` | Retrieve recent risk alerts | Admin |

### Employees

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `POST` | `/api/employees/create` | Create a new employee record | Admin |
| `POST` | `/api/employees/login` | Employee login for the simulator | Public |
| `GET` | `/api/employees/` | List all employees | Admin |

### Anomaly Detection

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `POST` | `/api/anomaly/scan` | Manually trigger a full anomaly scan | Admin |
| `GET` | `/api/anomaly/alerts` | Fetch all anomaly alerts (newest first) | Admin |
| `PATCH` | `/api/anomaly/alerts/{id}/acknowledge` | Acknowledge an anomaly alert | Admin |

### Quantum Security

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `GET` | `/api/quantum/status` | Get quantum crypto engine status | Admin |
| `GET` | `/api/quantum/integrity/stats` | Get aggregate integrity stats for all collections | Admin |
| `GET` | `/api/quantum/integrity/verify` | Run full per-document integrity verification | Admin |
| `POST` | `/api/quantum/encrypt-test` | Encrypt a test payload (demo) | Admin |
| `POST` | `/api/quantum/decrypt-test` | Decrypt a test payload (demo) | Admin |

### AI Analysis

| Method | Path | Description | Access |
|--------|------|-------------|--------|
| `POST` | `/api/ai/analyze` | Generate Gemini AI forensic report for an employee | Admin |

### Health Check

```http
GET /
```

Returns server status, quantum engine state, and anomaly engine state.

---

## 8. Risk Scoring Model

Each logged activity is assigned a **static risk weight** by the risk engine. Weights accumulate per employee over time.

| Action | Risk Weight |
|--------|:-----------:|
| Login | 0 |
| Logout | 0 |
| View Customer Record | 0 |
| Download File | 10 |
| Failed Login | 15 |
| USB Connected | 20 |
| Download Confidential File | 30 |
| Change Permission | 35 |
| Delete File | 40 |

### Alert Severity Thresholds

| Cumulative Score | Severity Level |
|:----------------:|:--------------:|
| ≥ 80 | 🔴 Critical |
| 60 – 79 | 🟠 High |
| 30 – 59 | 🟡 Warning |
| < 30 | 🟢 Normal |

---

## 9. Project File Structure

```
InThreatDetection-main/
├── README.md
├── LICENSE
└── InThreatDetection/
    ├── .gitignore
    ├── requirements.txt           # Root-level deps (pycryptodome)
    │
    ├── backend/
    │   ├── .env                   # Environment variables (git-ignored)
    │   ├── requirements.txt       # Backend Python dependencies
    │   └── app/
    │       ├── main.py            # FastAPI app entry point + middleware
    │       ├── core/
    │       │   └── config.py      # Settings (reads .env)
    │       ├── database/
    │       │   └── mongodb.py     # Motor async MongoDB client
    │       ├── models/
    │       │   ├── activity.py    # Activity & ActionType models
    │       │   ├── alert.py       # Alert model
    │       │   ├── anomaly.py     # AnomalyAlert, AnomalyType, Severity
    │       │   └── employee.py    # Employee model
    │       ├── routers/
    │       │   ├── activities.py  # POST /api/activities/
    │       │   ├── anomaly.py     # /api/anomaly/*
    │       │   ├── auth.py        # POST /api/auth/login
    │       │   ├── dashboard.py   # GET /api/dashboard/*
    │       │   ├── employees.py   # /api/employees/*
    │       │   └── quantum.py     # /api/quantum/*
    │       └── services/
    │           ├── activity_service.py   # Activity persistence
    │           ├── alert_service.py      # Alert persistence
    │           ├── anomaly_engine.py     # 6-signal anomaly detection
    │           ├── integrity.py          # Hash chain verification
    │           ├── quantum_crypto.py     # AES-256-GCM + SHA3 engine
    │           └── risk_engine.py        # Risk weight calculator
    │
    └── frontend/
        ├── index.html
        ├── package.json
        ├── vite.config.js
        ├── tailwind.config.js
        └── src/
            ├── App.jsx            # Root component + routing
            ├── main.jsx           # React entry point
            ├── ai/                # Gemini AI prompt logic
            ├── components/
            │   ├── EncryptionIndicator.jsx
            │   ├── IntegrityBadge.jsx
            │   ├── QuantumShield.jsx
            │   └── Sidebar.jsx
            ├── pages/
            │   ├── Dashboard.jsx      # Main SOC dashboard
            │   ├── LandingPage.jsx    # Marketing landing page
            │   └── Simulator.jsx      # Employee action simulator
            └── services/
                └── api.js             # Axios API client
```

---

## 10. Getting Started

### Prerequisites

Before running InThreatDetection locally, ensure the following are installed:

- **Python 3.10+** — [python.org](https://python.org)
- **Node.js 18+ with npm** — [nodejs.org](https://nodejs.org)
- **MongoDB** — Local installation or [MongoDB Atlas](https://www.mongodb.com/atlas) (free tier works)
- **Google Gemini API Key** — [aistudio.google.com](https://aistudio.google.com)

---

### Step 1 — Clone the Repository

```bash
git clone <repository-url>
cd InThreatDetection-main/InThreatDetection
```

---

### Step 2 — Backend Setup

Navigate to the backend directory:

```powershell
cd backend
```

Install PyCryptodome (the only non-standard dependency):

```powershell
pip install pycryptodome
```

Install all FastAPI dependencies:

```powershell
pip install fastapi uvicorn motor pydantic pydantic-settings google-genai python-dotenv pyjwt
```

> **Tip (Optional):** Use a virtual environment to isolate dependencies.
> ```powershell
> python -m venv .venv
> .venv\Scripts\Activate.ps1
> # If blocked by PowerShell policy:
> Set-ExecutionPolicy -Scope Process RemoteSigned
> ```

Create a `.env` file inside the `backend/` directory:

```env
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=InThreatDetectionDB
gemini_api_key=your_google_gemini_api_key_here
```

> The backend reads these values at startup via `app/core/config.py`.

---

### Step 3 — Frontend Setup

Open a new terminal and navigate to the frontend directory:

```powershell
cd frontend
```

Install dependencies:

```powershell
npm install
```

---

### Step 4 — Run the Application

Start MongoDB (if running locally):

```powershell
mongod
```

Start the Backend (from the `backend/` directory):

```powershell
uvicorn app.main:app --reload
```

Backend available at:

```
http://localhost:8000
```

API Documentation (Swagger UI):

```
http://localhost:8000/docs
```

Start the Frontend (from the `frontend/` directory):

```powershell
npm run dev
```

Frontend available at:

```
http://localhost:5173
```

---

### Step 5 — First-Time Setup

1. Open `http://localhost:5173`
2. Navigate to the **Admin Dashboard** and log in with your admin credentials
3. Use the **Employee Management** panel to create employee accounts
4. Open the **Employee Simulator** to log activity events
5. Watch the **Dashboard** populate with activities, risk scores, and anomaly alerts
6. Click **"Run AI Analysis"** on any employee to generate a Gemini-powered forensic report
7. Visit the **Quantum Shield** panel to inspect encryption status and run integrity verification

---

## 11. Demo Accounts

> To create demo accounts, use the `POST /api/employees/create` endpoint (requires admin JWT) or use the admin panel in the dashboard.

**Default Admin Credentials** (configured in `app/core/config.py`):

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

> ⚠️ Change these credentials before any non-development deployment.

---

## 12. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License
Copyright (c) 2026 Sumit
```

This project is intended for **educational, research, and demonstration purposes**.
It showcases the integration of AI-driven anomaly detection with post-quantum cryptographic principles in a realistic SOC workflow.

---

<div align="center">

**Built with passion for the next generation of Security Operations Centers**

*Insider Threat Detection · Behavioral Analytics · Quantum-Safe Security*

</div>