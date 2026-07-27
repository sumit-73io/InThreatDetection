# InThreatDetection — Deployment Guide

Operational guide for deploying the InThreatDetection insider-threat platform.

Everything below reflects the system as it actually is, including the parts that
are not production-ready. Section 12 is the hardening checklist and lists the
known gaps explicitly — read it before any deployment that handles real employee
data.

---

## Table of contents

1. [Architecture at a glance](#1-architecture-at-a-glance)
2. [Prerequisites](#2-prerequisites)
3. [Configuration](#3-configuration)
4. [MongoDB setup](#4-mongodb-setup)
5. [Backend deployment](#5-backend-deployment)
6. [Frontend deployment](#6-frontend-deployment)
7. [Reverse proxy and TLS](#7-reverse-proxy-and-tls)
8. [Process supervision](#8-process-supervision)
9. [First-run bootstrap](#9-first-run-bootstrap)
10. [Backup and recovery](#10-backup-and-recovery)
11. [Monitoring and health](#11-monitoring-and-health)
12. [Security hardening checklist](#12-security-hardening-checklist)
13. [Upgrade and rollback](#13-upgrade-and-rollback)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Architecture at a glance

Two independently deployed applications over a REST API, backed by MongoDB.

```
                    ┌──────────────────────────────┐
   Browser  ───────▶│  Frontend (static bundle)    │
                    │  React 19 + Vite 8 + TW4     │
                    └──────────────┬───────────────┘
                                   │ HTTPS / JSON
                    ┌──────────────▼───────────────┐
                    │  Backend (ASGI)              │
                    │  FastAPI + Uvicorn           │
                    │  ├─ RBAC + PAM enforcement   │
                    │  ├─ Risk / baseline engine    │
                    │  ├─ Anomaly engine (7 detectors)
                    │  ├─ Unsupervised ML (sklearn)│
                    │  ├─ AI Twin engine           │
                    │  └─ Enforcement service      │
                    └──────────────┬───────────────┘
                                   │ Motor (async)
                    ┌──────────────▼───────────────┐
                    │  MongoDB 6.0+                │
                    └──────────────────────────────┘
```

**Background work.** The backend starts one asyncio task at lifespan startup
(`periodic_anomaly_scan`) that runs a full anomaly scan every 60 seconds. It is
in-process, so it runs once **per worker**. See §5 on worker count — this is the
main reason not to naively scale workers.

**Request logging.** An HTTP middleware writes every non-health request to the
`api_access_logs` collection, including caller identity decoded from the JWT.
This is what feeds the API-traffic-spike detector. It is also unbounded growth —
see §10.

---

## 2. Prerequisites

| Component | Version | Notes |
|---|---|---|
| Python | 3.11+ | Developed and verified on 3.11.9 |
| Node.js | 20+ | Build-time only; not needed at runtime |
| MongoDB | 6.0+ | Local or Atlas |
| OS | Linux (prod) / Windows, macOS (dev) | |

Backend Python dependencies now include **scikit-learn, numpy and scipy** for the
unsupervised detector. These add roughly 150 MB to the environment — size your
image and disk accordingly. If you must avoid them, the detector fails soft
(`ImportError` is caught and the rule-based scan continues), but you lose that
detector entirely.

---

## 3. Configuration

### Required environment variables

`backend/app/core/config.py` defines these as **required**. The application will
not start without them.

| Variable | Example | Purpose |
|---|---|---|
| `MONGODB_URL` | `mongodb://127.0.0.1:27017` | Connection string |
| `DATABASE_NAME` | `InThreatDetectionDB` | Database name |
| `gemini_api_key` | `AIza...` | Declared required by the settings model. The forensic report generator currently runs fully offline in the browser, so this is not exercised on the request path — but it must still be **present** or startup fails. Set it to a placeholder if you are not using Gemini. |

### Optional environment variables

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET_KEY` | in-repo development value | HMAC key for signing tokens. **Set this in every non-development deployment.** Rotating it invalidates all issued tokens, which is the intended behaviour. |
| `JWT_TTL_HOURS` | `4` | Console token lifetime |

### `backend/.env`

```ini
MONGODB_URL=mongodb://127.0.0.1:27017
DATABASE_NAME=InThreatDetectionDB
gemini_api_key=not-in-use
JWT_SECRET_KEY=<64+ random chars, e.g. `openssl rand -hex 48`>
JWT_TTL_HOURS=4
```

Never commit `.env`. Confirm it is covered by `.gitignore` before your first
commit on a new machine.

### Frontend API base URL — must be changed

`frontend/src/services/api.js` hardcodes:

```js
const api = axios.create({ baseURL: 'http://localhost:8000/api' });
```

This is correct for local development and **wrong for every other
environment**. Before building for deployment, either:

- **Recommended** — serve the API under the same origin as the frontend behind a
  reverse proxy (§7) and change this to a relative `'/api'`. No CORS, no mixed
  content, no rebuild per environment.
- Or make it build-time configurable:
  ```js
  const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE ?? '/api' });
  ```
  then set `VITE_API_BASE` at build time. Note Vite inlines this at **build**
  time, so a per-environment value means a per-environment build.

---

## 4. MongoDB setup

### Collections

Created on first write; no migration step is required.

| Collection | Contents | Growth |
|---|---|---|
| `employees` | Employee records, block state | Bounded by headcount |
| `activities` | Activity audit log, hash-chained | High |
| `alerts` | Risk-level alerts | Medium |
| `anomaly_alerts` | Anomaly + baseline-deviation findings | Medium |
| `api_access_logs` | Every API request | **Very high** |
| `ai_twin_profiles` | Per-employee behavioural baselines | Bounded by headcount |
| `ai_twin_alerts` | AI Twin deviation alerts | Low |
| `behaviour_baselines` | Normal-environment baselines (employee + role) | Bounded |
| `enforcement_actions` | Automated freeze records | Low |
| `pam_elevation_requests` | Privileged elevation requests | Low |
| `pam_audit_log` | Privileged action audit trail | Medium |
| `enforcement_overrides` | Operator-authorised enforcement exceptions | Low |

### Recommended indexes

None are created by the application. On any dataset beyond a demo these matter,
because several code paths query by `employee_id` + `timestamp` range:

```js
use InThreatDetectionDB

db.activities.createIndex({ employee_id: 1, timestamp: -1 })
db.activities.createIndex({ timestamp: -1 })
db.employees.createIndex({ employee_id: 1 }, { unique: true })
db.anomaly_alerts.createIndex({ timestamp: -1 })
db.anomaly_alerts.createIndex({ employee_id: 1, anomaly_type: 1, timestamp: -1 })
db.api_access_logs.createIndex({ timestamp: -1 })
db.api_access_logs.createIndex({ identity: 1, timestamp: -1 })
db.ai_twin_profiles.createIndex({ employee_id: 1 }, { unique: true })
db.behaviour_baselines.createIndex({ key: 1 }, { unique: true })
db.pam_elevation_requests.createIndex({ subject: 1, status: 1 })
db.pam_audit_log.createIndex({ timestamp: -1 })
db.enforcement_actions.createIndex({ timestamp: -1 })
db.enforcement_overrides.createIndex({ employee_id: 1, status: 1 })
db.enforcement_overrides.createIndex({ created_at: -1 })
```

### Retention

`api_access_logs` grows with every request and is only read over a 15-minute
window by the traffic-spike detector. Cap it with a TTL index:

```js
db.api_access_logs.createIndex({ createdAt: 1 }, { expireAfterSeconds: 604800 })
```

Note: `timestamp` is stored as an **ISO string**, and MongoDB TTL requires a
BSON `Date`. To use a TTL index you must add a real `Date` field at write time in
`main.py`'s logging middleware. Until then, prune on a schedule instead:

```js
db.api_access_logs.deleteMany({ timestamp: { $lt: new Date(Date.now() - 7*864e5).toISOString() } })
```

**Do not apply retention to `activities` or `alerts` without a decision.** They
are hash-chained tamper-evident records; deleting from the middle breaks the
chain and every subsequent document reports as unverifiable. Archive rather than
delete.

---

## 5. Backend deployment

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Verify the app imports and every router registers before exposing a port:

```bash
python -c "from app.main import app; print(len(app.openapi()['paths']), 'paths')"
# expect 52
```

Run it:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Worker count — read this before scaling

The 60-second anomaly scan is an **in-process asyncio task**, so `--workers 4`
means four independent scans racing on the same collections. The scan
deduplicates alerts within a one-hour window, so you get suppression rather than
four times the alerts, but it is wasted work and a write-contention source.

Two supported shapes:

- **Single worker (default, recommended).** `uvicorn app.main:app --workers 1`.
  Everything works as designed. FastAPI is async; a single worker handles a SOC
  console's load comfortably.
- **Multiple workers.** Move the scan out of the app: delete the
  `scan_task = asyncio.create_task(...)` line from the `lifespan` handler in
  `main.py` and drive the scan externally on a cron/systemd timer against
  `POST /api/anomaly/scan`. Then scale workers freely.

Bind to `127.0.0.1`, not `0.0.0.0`, and let the reverse proxy be the only public
listener.

---

## 6. Frontend deployment

```bash
cd frontend
npm ci
npm run build      # emits dist/
```

`dist/` is a static bundle — serve it from Nginx, Caddy, S3+CDN, or any static
host. It needs no Node runtime.

Do the API base URL change from §3 **before** building.

---

## 7. Reverse proxy and TLS

Same-origin is the recommended topology: it removes CORS entirely and lets the
API base URL be a plain `/api`.

```nginx
server {
    listen 443 ssl http2;
    server_name soc.example.com;

    ssl_certificate     /etc/letsencrypt/live/soc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Frontend
    root /var/www/inthreatdetection;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;   # SPA fallback
    }

    # Backend
    location /api/ {
        proxy_pass         http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;             # integrity scans can be slow
    }

    # Do not expose interactive API docs publicly
    location ~ ^/(docs|redoc|openapi.json)$ { deny all; }
}

server {
    listen 80;
    server_name soc.example.com;
    return 301 https://$host$request_uri;
}
```

### CORS

`main.py` currently sets `allow_origins=["*"]` with `allow_credentials=True`.
That combination is rejected by browsers and is far wider than needed. With the
same-origin topology above you can drop the CORS middleware entirely. If you do
need cross-origin, pin it:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://soc.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## 8. Process supervision

`/etc/systemd/system/inthreatdetection.service`:

```ini
[Unit]
Description=InThreatDetection API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=itd
Group=itd
WorkingDirectory=/opt/inthreatdetection/backend
EnvironmentFile=/opt/inthreatdetection/backend/.env
ExecStart=/opt/inthreatdetection/backend/.venv/bin/uvicorn app.main:app \
          --host 127.0.0.1 --port 8000 --workers 1
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/inthreatdetection/backend
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now inthreatdetection
sudo journalctl -u inthreatdetection -f
```

---

## 9. First-run bootstrap

1. **Sign in as the built-in operator.** `admin` / `admin123`, which maps to the
   `Super Admin` console role. This account is intentionally retained as the
   bootstrap and break-glass identity. **Change the password before any real
   deployment** — see §12, it is currently a hardcoded literal in
   `app/routers/auth.py`.

2. **Provision employees.** Sidebar → Provision User. The job title chosen here
   determines console access via the role map in `app/core/rbac.py`:

   | Job title | Console role | Console access |
   |---|---|---|
   | Admin, Sys Admin | Security Admin | Yes |
   | Ops Analyst | SOC Analyst | Yes |
   | DB Admin, Branch Manager | Auditor | Read-only |
   | HR, Dev, Design, Support Staff, User | Employee | **None** — Simulator only |

3. **Generate baseline activity.** Employees sign in to the Employee Simulator
   and work normally. This is the only path that trains an AI Twin baseline; the
   AI Twin page's threat simulator is deliberately read-only so it cannot poison
   the model.

4. **Build behavioural baselines.** `POST /api/baseline/rebuild-all`. Expect
   three outcomes per subject and do not conflate them:
   - `built` — a baseline exists
   - `locked` — an operator-confirmed baseline was left untouched
   - `refused` — a guard rejected the window. **No baseline exists** and risk
     falls back to static action weights. The usual cause is
     `contaminated_window`: the window is already more than 35% high-risk
     activity, so treating it as "normal" would teach the system to ignore that
     activity. Resolve the outstanding alerts and re-baseline from a clean
     period.

5. **Lock the good baselines.** Once verified, lock them so automatic
   recomputation cannot silently replace a clean baseline with a poisoned one.
   Locking requires `baseline:manage` **plus** an active PAM elevation.

6. **Add the indexes** from §4.

---

## 10. Backup and recovery

```bash
mongodump --uri="$MONGODB_URL" --db=InThreatDetectionDB \
          --archive=/backups/itd-$(date +%F-%H%M).gz --gzip
```

Restore:

```bash
mongorestore --uri="$MONGODB_URL" --archive=/backups/itd-2026-07-26-0200.gz --gzip
```

Suggested cadence: hourly incremental-ish dumps for 48 h, daily for 30 days,
monthly for a year — then reconcile against your own retention policy.

**Integrity chain caveat.** `activities` and `alerts` are hash-chained: each
document's hash incorporates its predecessor's. A **partial** restore therefore
produces a chain break that the integrity scanner will correctly report as
tampering. Always restore these two collections whole, and re-run
`GET /api/quantum/integrity/verify` after any restore to confirm the chain.

Back up `backend/.env` separately and securely. Losing `JWT_SECRET_KEY` only
invalidates live sessions; losing the DB loses the audit trail.

---

## 11. Monitoring and health

### Health endpoint

`GET /` is unauthenticated and reports liveness only:

```json
{"status":"InThreatDetection API is running","quantum_security":"active","anomaly_engine":"active"}
```

It deliberately does **not** report the cryptographic configuration — it is
publicly reachable, so anything it returns is public. Detailed posture is behind
`GET /api/quantum/status` and requires `quantum:read`.

### What to alert on

| Signal | Source | Why |
|---|---|---|
| Process down / restart loop | systemd, journal | Availability |
| `Auto-Scan Error` in logs | journal | The 60 s scan is failing silently otherwise |
| Mongo connection failures | journal | Everything depends on it |
| `api_access_logs` collection size | Mongo | Unbounded growth (§4) |
| Integrity score below 100% | `GET /api/quantum/integrity/stats` | Possible tampering at the DB layer |
| `PRIVILEGE_DENIED_NO_ELEVATION` events | `GET /api/access/pam/audit` | Someone repeatedly attempting privileged actions without elevation |
| Break-glass approvals | same, `break_glass: true` | Self-approved elevation always warrants review |
| ML detector abstentions | journal, `ML detector abstained [guard]` | The model has no opinion; do not read silence as "all clear" |

### Log destinations

Application logs go to stdout/stderr and are captured by journald. The security
audit trail is in MongoDB (`pam_audit_log`, `enforcement_actions`), not in the
process log — ship those to your SIEM separately.

---

## 12. Security hardening checklist

Items marked **OPEN** are known gaps in the current codebase, not oversights in
this document. Address them before handling real employee data.

### Open issues

- [ ] **OPEN — Employee passwords are stored and compared in plaintext.**
  `app/routers/employees.py` writes `emp.password` as-is; `auth.py` and the
  Simulator login match on it directly. A database read discloses every
  credential. Fix: hash with bcrypt or Argon2 at provisioning, compare with a
  constant-time verify, and migrate existing rows. This was an accepted scope
  decision, not an accident.
- [ ] **OPEN — Built-in admin credentials are hardcoded.**
  `BUILTIN_ADMIN_USERNAME` / `BUILTIN_ADMIN_PASSWORD` are literals in
  `app/routers/auth.py`. Move them to environment variables, or better, seed a
  real hashed super-admin record and delete the branch.
- [ ] **OPEN — JWT secret has a working in-repo default.** If
  `JWT_SECRET_KEY` is unset the application starts with a publicly known key,
  meaning anyone can mint a valid Super Admin token. Set it explicitly, and
  consider making it required rather than defaulted.
- [ ] **OPEN — CORS allows all origins** (§7).
- [ ] **OPEN — No rate limiting on `/api/auth/login` or
  `/api/employees/login`.** Both are unauthenticated and brute-forceable. Add a
  limiter at the proxy or application layer.
- [ ] **OPEN — No account lockout on repeated failed console logins.**
  `FAILED_LOGIN` is scored for employees in the Simulator, but console login
  failures are not counted or throttled.

### Should be done at deploy time

- [ ] Set `JWT_SECRET_KEY` to 48+ random bytes; plan rotation
- [ ] Change the built-in admin password
- [ ] TLS terminated at the proxy; HTTP redirects to HTTPS
- [ ] `/docs`, `/redoc`, `/openapi.json` blocked publicly
- [ ] Backend bound to `127.0.0.1` only
- [ ] MongoDB requires authentication and is not internet-reachable
- [ ] MongoDB encryption at rest enabled
- [ ] Dedicated unprivileged service user; systemd hardening applied
- [ ] `.env` mode `0600`, owned by the service user
- [ ] Indexes from §4 created
- [ ] `api_access_logs` retention in place
- [ ] Backups running **and a restore rehearsed**
- [ ] PAM audit log shipped to a SIEM
- [ ] Baselines built, verified, and **locked**
- [ ] Enforcement-override caps reviewed (`MAX_DURATION_MINUTES`, `MAX_EVENTS`,
      `UNBLOCK_GRACE_MINUTES` in `services/override_service.py`) and
      `AUTHORIZED_BY_OVERRIDE` records forwarded to the SIEM — a granted
      exception is a deliberate reduction in enforcement and must be reviewable

### Access-control model as deployed

- 5 console roles, 21 permissions, 5 of which are privileged
- Privileged permissions (`employees:block`, `aitwin:reset`, `baseline:manage`,
  `rbac:manage`, `overrides:manage`) require the permission **and** an active PAM
  elevation window
- Elevation: justification of 15+ characters, maximum 60 minutes, no
  self-approval except Super Admin break-glass, every transition audited
- Employees with no console permissions cannot obtain a console token at all

---

## 13. Upgrade and rollback

```bash
# 1. Back up first — always
mongodump --uri="$MONGODB_URL" --db=InThreatDetectionDB --archive=/backups/pre-upgrade.gz --gzip

# 2. Fetch
cd /opt/inthreatdetection && git fetch && git checkout <tag>

# 3. Backend
cd backend && .venv/bin/pip install -r requirements.txt
.venv/bin/python -c "from app.main import app; print('import ok')"

# 4. Frontend
cd ../frontend && npm ci && npm run build
rsync -a --delete dist/ /var/www/inthreatdetection/

# 5. Restart
sudo systemctl restart inthreatdetection
curl -fsS https://soc.example.com/ | jq .
```

Rollback is `git checkout <previous-tag>` plus the same steps. There are no
schema migrations — documents are written by Pydantic models with defaults, so
new fields simply appear on newly written documents and read as their default on
older ones. Rolling **back** across a change that added a field is therefore
safe; the field is ignored.

---

## 14. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Startup fails with a `ValidationError` on settings | A required env var is missing | Confirm `MONGODB_URL`, `DATABASE_NAME`, `gemini_api_key` are all set (§3) |
| Every API call returns 401 | Token expired (4 h default) or `JWT_SECRET_KEY` changed | Sign in again |
| Privileged action returns 403 mentioning elevation | Working as designed | Request elevation via the UI prompt or `POST /api/access/pam/request` |
| Frontend loads, all data calls fail | API base URL still `localhost:8000` | §3 — rebuild with the correct base |
| Baseline build returns `refused` / `contaminated_window` | Window is >35% high-risk activity | Working as designed. Resolve alerts, re-baseline from a clean period |
| ML detect returns `abstained` | A false-learning guard refused to fit | Working as designed. Check `guard` and `message`; usually too few employees (<8) |
| Integrity score below 100% | Chain break or genuine tampering | Distinguish a partial restore (§10) from real tampering before escalating |
| An employee cannot sign in to the console | Their job title maps to `Employee` | Working as designed — they use the Simulator |
| Unblocked employee is re-frozen on their next action | Risk already accumulated in the rolling window is still above threshold | The unblock now auto-attaches a 30-min grace window. For longer, grant an override (`POST /api/overrides/grant`) |
| Override grant returns 400 "must be bounded" | No duration and no event budget supplied | Working as designed — set at least one limit |
| Alerts stop appearing | Background scan task died | `journalctl -u inthreatdetection | grep Auto-Scan`; restart |
| Duplicate scan work, high Mongo write load | Multiple uvicorn workers each running the scan | §5 — use one worker or externalise the scan |

---

*Companion document: `BANKING_INTEGRATION_ARCHITECTURE.md` covers integrating
this platform with a core banking system.*
