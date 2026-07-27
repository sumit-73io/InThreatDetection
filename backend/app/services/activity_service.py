from app.database.mongodb import db_instance
from app.models.activity import ActivityLog
from app.services.risk_engine import calculate_risk_score
from app.services.alert_service import process_activity_for_alert
from app.services.quantum_crypto import quantum_engine
from app.services.integrity import add_integrity_fields
from fastapi.encoders import jsonable_encoder
import asyncio
from datetime import datetime, timezone, timedelta

async def log_employee_activity(activity: ActivityLog):
    # 1. Evaluate Risk Score 
    risk_score = calculate_risk_score(activity.action)
    activity.risk_score = risk_score
    
    # 2. BULLETPROOF SERIALIZATION: Safely converts Datetimes and Enums
    activity_dict = jsonable_encoder(activity)
    
    # 3. Quantum Encryption: Encrypt sensitive fields before storage
    if quantum_engine.is_initialized:
        encrypted_fields = []
        
        # Encrypt device_ip if present
        if activity_dict.get("device_ip"):
            activity_dict["device_ip_encrypted"] = quantum_engine.encrypt_field(
                activity_dict["device_ip"]
            )
            activity_dict["device_ip"] = "[ENCRYPTED]"
            encrypted_fields.append("device_ip")
        
        # Encrypt details if present
        if activity_dict.get("details"):
            activity_dict["details_encrypted"] = quantum_engine.encrypt_field(
                activity_dict["details"]
            )
            activity_dict["details"] = "[ENCRYPTED]"
            encrypted_fields.append("details")
        
        activity_dict["encrypted_fields"] = encrypted_fields
    
    # 4. Add integrity hash and chain link
    activity_dict = await add_integrity_fields(activity_dict, "activities")
    
    # 5. Save Activity to MongoDB
    result = await db_instance.db["activities"].insert_one(activity_dict)
    
    # 6. Asynchronously Check & Generate Alert
    await process_activity_for_alert(activity.employee_id, activity.action, risk_score)
    
    # 6.5. Baseline deviation + automated enforcement.
    #
    # Replaces the previous inline "cumulative risk across all activity >= 100"
    # rule, which was unbounded in time and so guaranteed a false positive for
    # any long-tenured employee. enforcement_service is now the single decision
    # point for freezing an account and uses a rolling window instead.
    deviation = None
    enforcement = None
    try:
        from app.services.risk_engine import calculate_contextual_risk
        from app.services import enforcement_service

        deviation = await calculate_contextual_risk(
            employee_id=activity.employee_id,
            action=activity.action,
            timestamp=activity.timestamp,
        )

        enforcement = await enforcement_service.evaluate_and_enforce(
            employee_id=activity.employee_id,
            action=str(activity.action.value if hasattr(activity.action, "value") else activity.action),
            deviation=deviation,
        )
    except Exception as e:
        # Never let enforcement failures block activity logging - losing the
        # audit record is worse than a missed evaluation.
        print(f"Enforcement evaluation failed for {activity.employee_id}: {e}")

    # 7. Feed event to AI Twin (fire-and-forget — never block the response)
    try:
        from app.services.ai_twin_service import process_twin_event
        extra = {
            "device_ip": activity.device_ip,
            "details": activity.details,
            "risk_score": risk_score,
        }
        asyncio.create_task(
            process_twin_event(
                employee_id=activity.employee_id,
                action=str(activity.action.value if hasattr(activity.action, 'value') else activity.action),
                timestamp=activity.timestamp,
                extra=extra,
            )
        )
    except Exception:
        pass  # Never let AI Twin failures break activity logging
    
    return {
        "status": "success",
        "inserted_id": str(result.inserted_id),
        "action": activity.action,
        "risk_score": risk_score,
        "encryption_status": "quantum_encrypted" if quantum_engine.is_initialized else "plaintext",
        # The record is still sealed with an integrity hash in storage; the hash
        # value itself is not echoed back to the client (data minimization).
        "integrity_sealed": bool(activity_dict.get("integrity_hash")),
        # Deviation verdict and enforcement outcome, so the Simulator can show
        # the employee what the system concluded about this specific action
        # instead of only discovering a freeze on the next status poll.
        "deviation": {
            "baseline_scope": deviation.get("baseline_scope"),
            "base_risk": deviation.get("base_risk"),
            "deviation_premium": deviation.get("deviation_premium"),
            "contextual_risk": deviation.get("contextual_risk"),
            "is_deviation": deviation.get("is_deviation"),
            "reasons": deviation.get("reasons", []),
            "message": deviation.get("message"),
        } if deviation else None,
        "enforcement": {
            "alerted": enforcement.get("alerted"),
            "frozen": enforcement.get("frozen"),
            "trigger": enforcement.get("trigger"),
            "reason": enforcement.get("reason"),
            # Surfaced so the Simulator can tell the employee this action was
            # deliberately authorised rather than silently ignored.
            "override_applied": bool(enforcement.get("override_applied")),
            "override": enforcement.get("override"),
        } if enforcement else None,
    }