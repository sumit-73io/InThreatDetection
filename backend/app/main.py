from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from app.database.mongodb import connect_to_mongo, close_mongo_connection, db_instance
from app.routers import (
    activities, dashboard, auth, employees, quantum, anomaly, ai_twin, access, ml,
    baseline, overrides,
)
from app.core.security import decode_token_quiet
from app.services.quantum_crypto import quantum_engine


import asyncio
from app.services.anomaly_engine import run_anomaly_scan, persist_anomaly_alerts

async def periodic_anomaly_scan():
    """Background task to run anomaly scans periodically (e.g., every 60 seconds)."""
    while True:
        try:
            await asyncio.sleep(60)  # Wait for 60 seconds
            # Run scan
            alerts = await run_anomaly_scan()
            if alerts:
                inserted = await persist_anomaly_alerts(alerts)
                if inserted > 0:
                    print(f"Auto-Scan Complete: {len(alerts)} anomalies detected, {inserted} new alerts persisted.")
        except Exception as e:
            print(f"Auto-Scan Error: {str(e)}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    # Initialize the Quantum Crypto Engine at startup
    quantum_engine.initialize()
    # Ensure all existing employees have an AI Twin profile
    try:
        from app.services.ai_twin_service import ensure_all_employees_have_twins
        await ensure_all_employees_have_twins()
    except Exception as e:
        print(f"AI Twin startup init error: {e}")
    # Start the periodic anomaly scan
    scan_task = asyncio.create_task(periodic_anomaly_scan())
    yield
    scan_task.cancel()
    await close_mongo_connection()


app = FastAPI(title="InThreatDetection Core", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── API Access Logging Middleware ──────────────────────────────────────
# Logs every request (method, path, caller identity, timestamp) to MongoDB
# for the anomaly engine to analyze API traffic patterns.
@app.middleware("http")
async def log_api_access(request: Request, call_next):
    response = await call_next(request)
    
    # Skip logging for health checks, static files, and the access log reads themselves
    path = request.url.path
    skip_paths = ("/", "/docs", "/openapi.json", "/redoc", "/favicon.ico")
    if path in skip_paths or path.startswith("/api/anomaly/alerts"):
        return response

    try:
        # Extract identity from Authorization header if present.
        # Decoding goes through app.core.security so the secret and algorithm
        # stay in one place instead of being duplicated here.
        identity = "anonymous"
        role = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_token_quiet(token)
            if payload is None:
                identity = "invalid_token"
            else:
                identity = payload.get("sub", "unknown")
                role = payload.get("role")

        log_entry = {
            "method": request.method,
            "path": path,
            "identity": identity,
            "role": role,
            "status_code": response.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Fire-and-forget insert (don't slow down the response)
        if db_instance.db is not None:
            await db_instance.db["api_access_logs"].insert_one(log_entry)
    except Exception:
        pass  # Never let logging break the actual request

    return response


app.include_router(activities.router)
app.include_router(dashboard.router)
app.include_router(auth.router)
app.include_router(employees.router) 
app.include_router(quantum.router)
app.include_router(anomaly.router)
app.include_router(ai_twin.router)
app.include_router(access.router)
app.include_router(ml.router)
app.include_router(baseline.router)
app.include_router(overrides.router)

@app.get("/")
def health_check():
    # Unauthenticated endpoint - reports liveness only. The algorithm suite was
    # removed here deliberately: this route is reachable without a token, so
    # anything it returns is public. See the data minimization note in
    # app/routers/quantum.py.
    return {
        "status": "InThreatDetection API is running",
        "quantum_security": "active" if quantum_engine.is_initialized else "inactive",
        "anomaly_engine": "active",
    }