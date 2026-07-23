"""
Quantum Security API Router
============================

Provides endpoints for monitoring the quantum crypto engine status
and running data integrity verification scans.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from app.routers.auth import verify_admin
from app.services.quantum_crypto import quantum_engine
from app.services.integrity import verify_collection_integrity

router = APIRouter(prefix="/api/quantum", tags=["Quantum Security"])


# ─── Response Models ─────────────────────────────────────────────────

class EncryptTestRequest(BaseModel):
    plaintext: str


class DecryptTestRequest(BaseModel):
    ciphertext: str
    nonce: str
    tag: str
    sha3_hash: Optional[str] = None
    signature: Optional[str] = None


# ─── Endpoints ───────────────────────────────────────────────────────

@router.get("/status", dependencies=[Depends(verify_admin)])
async def get_quantum_status():
    """Returns the current status of the Quantum Crypto Engine."""
    return quantum_engine.get_status()


@router.get("/integrity/stats", dependencies=[Depends(verify_admin)])
async def get_integrity_stats():
    """
    Returns aggregate integrity statistics for both
    activities and alerts collections.
    """
    try:
        activities_result = await verify_collection_integrity("activities")
        alerts_result = await verify_collection_integrity("alerts")

        total_docs = activities_result["total_documents"] + alerts_result["total_documents"]
        total_verified = activities_result["verified"] + alerts_result["verified"]
        total_tampered = activities_result["tampered"] + alerts_result["tampered"]
        total_unverified = activities_result["unverified"] + alerts_result["unverified"]

        overall_score = round((total_verified / total_docs * 100), 1) if total_docs > 0 else 100.0

        return {
            "overall": {
                "total_documents": total_docs,
                "verified": total_verified,
                "tampered": total_tampered,
                "unverified": total_unverified,
                "integrity_score": overall_score,
                "chain_intact": activities_result["chain_intact"] and alerts_result["chain_intact"],
            },
            "activities": {
                "total": activities_result["total_documents"],
                "verified": activities_result["verified"],
                "tampered": activities_result["tampered"],
                "unverified": activities_result["unverified"],
                "integrity_score": activities_result["integrity_score"],
                "chain_intact": activities_result["chain_intact"],
            },
            "alerts": {
                "total": alerts_result["total_documents"],
                "verified": alerts_result["verified"],
                "tampered": alerts_result["tampered"],
                "unverified": alerts_result["unverified"],
                "integrity_score": alerts_result["integrity_score"],
                "chain_intact": alerts_result["chain_intact"],
            },
            "scan_timestamp": activities_result["scan_timestamp"],
            "engine_status": quantum_engine.get_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Integrity scan failed: {str(e)}")


@router.get("/integrity/verify", dependencies=[Depends(verify_admin)])
async def run_full_integrity_verification():
    """
    Runs a full integrity verification scan on all collections.
    Returns per-document verification results.
    """
    try:
        activities_result = await verify_collection_integrity("activities")
        alerts_result = await verify_collection_integrity("alerts")

        return {
            "activities": activities_result,
            "alerts": alerts_result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/encrypt-test", dependencies=[Depends(verify_admin)])
async def encrypt_test_payload(req: EncryptTestRequest):
    """Encrypts a test plaintext string for demonstration."""
    try:
        encrypted = quantum_engine.encrypt_payload({"test_data": req.plaintext})
        return {
            "status": "encrypted",
            "result": encrypted,
            "algorithm_suite": quantum_engine.ALGORITHM_SUITE
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")


@router.post("/decrypt-test", dependencies=[Depends(verify_admin)])
async def decrypt_test_payload(req: DecryptTestRequest):
    """Decrypts a test payload for demonstration."""
    try:
        encrypted_bundle = {
            "ciphertext": req.ciphertext,
            "nonce": req.nonce,
            "tag": req.tag,
            "sha3_hash": req.sha3_hash,
            "signature": req.signature
        }
        decrypted = quantum_engine.decrypt_payload(encrypted_bundle)
        return {
            "status": "decrypted",
            "result": decrypted
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")
