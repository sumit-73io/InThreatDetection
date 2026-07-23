from app.database.mongodb import db_instance
from app.models.activity import ActivityLog
from app.services.risk_engine import calculate_risk_score
from app.services.alert_service import process_activity_for_alert
from app.services.quantum_crypto import quantum_engine
from app.services.integrity import add_integrity_fields
from fastapi.encoders import jsonable_encoder

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
    
    return {
        "status": "success", 
        "inserted_id": str(result.inserted_id), 
        "action": activity.action,
        "risk_score": risk_score,
        "encryption_status": "quantum_encrypted" if quantum_engine.is_initialized else "plaintext",
        "integrity_hash": activity_dict.get("integrity_hash", "")[:16] + "..."
    }