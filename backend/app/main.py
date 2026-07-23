from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.routers import activities, dashboard, auth, employees, quantum
from app.services.quantum_crypto import quantum_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    # Initialize the Quantum Crypto Engine at startup
    quantum_engine.initialize()
    yield
    await close_mongo_connection()


app = FastAPI(title="InThreatDetection Core", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(activities.router)
app.include_router(dashboard.router)
app.include_router(auth.router)
app.include_router(employees.router) 
app.include_router(quantum.router)

@app.get("/")
def health_check():
    # UPDATE HEALTH CHECK STRING HERE
    return {
        "status": "InThreatDetection API is running",
        "quantum_security": "active" if quantum_engine.is_initialized else "inactive",
        "algorithm_suite": "Kyber-1024 + AES-256-GCM + SHA3-256 + Dilithium-3"
    }