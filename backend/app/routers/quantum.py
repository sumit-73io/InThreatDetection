"""
Quantum Security API Router
============================

Reports the operational posture of the quantum crypto engine and the
tamper-evidence health of the audit collections.

Data minimization policy
------------------------
This router deliberately exposes STATUS ONLY. It does not return:
  - algorithm names, versions or NIST suite identifiers
  - the session key fingerprint or any key material
  - per-document integrity hashes

Rationale: the platform's value here is the assurance that records are sealed
and verifiable. The cryptographic configuration itself is reconnaissance
material, and a per-document hash is a stable identifier for a specific audit
record. Aggregate verified/tampered counts are retained because a SOC operator
genuinely needs to know whether the audit trail is intact.

The engine's full detail remains available in-process via
`quantum_engine.get_status()` for diagnostics, and must not be returned here.

The encrypt-test / decrypt-test demo endpoints were removed: they echoed the
algorithm suite and acted as an encryption oracle against the live session key.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.core.rbac import Permission
from app.core.security import require_permission
from app.services.integrity import verify_collection_integrity
from app.services.quantum_crypto import quantum_engine

router = APIRouter(prefix="/api/quantum", tags=["Quantum Security"])


def _summarise(result: dict) -> dict:
    """Aggregate counts for one collection, with per-document detail stripped."""
    return {
        "total": result["total_documents"],
        "verified": result["verified"],
        "tampered": result["tampered"],
        "unverified": result["unverified"],
        "integrity_score": result["integrity_score"],
        "chain_intact": result["chain_intact"],
    }


@router.get("/status", dependencies=[Depends(require_permission(Permission.QUANTUM_READ))])
async def get_quantum_posture():
    """Operational posture of the crypto engine. Status only, no configuration."""
    return quantum_engine.get_posture()


@router.get("/integrity/stats", dependencies=[Depends(require_permission(Permission.QUANTUM_READ))])
async def get_integrity_stats():
    """Aggregate tamper-evidence statistics across the audit collections."""
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
            "activities": _summarise(activities_result),
            "alerts": _summarise(alerts_result),
            "scan_timestamp": activities_result["scan_timestamp"],
            # Minimized posture rather than the full engine status.
            "engine_status": quantum_engine.get_posture(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Integrity scan failed: {str(e)}")


@router.get("/integrity/verify", dependencies=[Depends(require_permission(Permission.QUANTUM_READ))])
async def run_full_integrity_verification():
    """
    Run a full verification pass over the audit collections.

    Returns aggregate results per collection. Per-document hashes are withheld;
    when tampering is detected the operator gets the affected count and is
    directed to the activity timeline rather than raw hash values.
    """
    try:
        activities_result = await verify_collection_integrity("activities")
        alerts_result = await verify_collection_integrity("alerts")

        return {
            "activities": _summarise(activities_result),
            "alerts": _summarise(alerts_result),
            "scan_timestamp": activities_result["scan_timestamp"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")
