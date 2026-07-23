from fastapi import APIRouter, HTTPException, Depends
from app.database.mongodb import db_instance
from app.routers.auth import verify_admin  # <-- IMPORT NEW SECURITY CHECK
from app.services.quantum_crypto import quantum_engine
from app.services.integrity import verify_document_integrity

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


def decrypt_activity(act: dict) -> dict:
    """Decrypt encrypted fields in an activity document and add integrity status.

    ORDER MATTERS:
      1. Verify integrity on the RAW stored document first (before modifying anything).
         The integrity_hash was computed on the encrypted form, so we must verify
         it against the same form — otherwise decryption changes device_ip from
         "[ENCRYPTED]" to the real IP and the hash no longer matches.
      2. Then decrypt fields for display.
      3. Then clean up encrypted blobs from the response.
    """
    # ── Step 1: Verify integrity on the raw stored document ──────────
    integrity_result = verify_document_integrity(act)
    act["integrity_verified"] = integrity_result["status"]
    act["integrity_hash_short"] = (
        act.get("integrity_hash", "")[:16] + "..."
        if act.get("integrity_hash") else None
    )

    # ── Step 2: Decrypt fields for display ───────────────────────────
    if quantum_engine.is_initialized and act.get("device_ip_encrypted"):
        try:
            act["device_ip"] = quantum_engine.decrypt_field(act["device_ip_encrypted"])
        except Exception:
            act["device_ip"] = "[DECRYPTION_FAILED]"

    if quantum_engine.is_initialized and act.get("details_encrypted"):
        try:
            act["details"] = quantum_engine.decrypt_field(act["details_encrypted"])
        except Exception:
            act["details"] = "[DECRYPTION_FAILED]"

    # ── Step 3: Remove encrypted blobs from response ──────────────────
    act.pop("device_ip_encrypted", None)
    act.pop("details_encrypted", None)
    act.pop("action_encrypted", None)
    act.pop("previous_hash", None)

    return act


def decrypt_alert(alert: dict) -> dict:
    """Decrypt encrypted fields in an alert document and add integrity status."""
    # Verify integrity
    integrity_result = verify_document_integrity(alert)
    alert["integrity_verified"] = integrity_result["status"]
    alert["integrity_hash_short"] = alert.get("integrity_hash", "")[:16] + "..." if alert.get("integrity_hash") else None
    
    # Remove encrypted blobs from response
    alert.pop("action_encrypted", None)
    alert.pop("previous_hash", None)
    
    return alert


@router.get("/activities", dependencies=[Depends(verify_admin)])
async def get_all_activities():
    try:
        # INCREASED LIMIT FROM 50 TO 1000
        cursor = db_instance.db["activities"].find().sort("timestamp", -1).limit(1000)
        activities = await cursor.to_list(length=1000)
        for act in activities:
            act["_id"] = str(act["_id"])
            act = decrypt_activity(act)
        return activities
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# <-- ADD DEPENDENCY HERE
@router.get("/alerts", dependencies=[Depends(verify_admin)])
async def get_all_alerts():
    try:
        cursor = db_instance.db["alerts"].find().sort("timestamp", -1).limit(30)
        alerts = await cursor.to_list(length=30)
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
            alert = decrypt_alert(alert)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))