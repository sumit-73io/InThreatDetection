from app.database.mongodb import db_instance
from app.models.alert import Alert, AlertLevel
from app.services.quantum_crypto import quantum_engine
from app.services.integrity import add_integrity_fields
from fastapi.encoders import jsonable_encoder

def determine_alert_level(score: int) -> AlertLevel:
    if score >= 80:
        return AlertLevel.CRITICAL
    elif score >= 60:
        return AlertLevel.HIGH
    elif score >= 30:
        return AlertLevel.WARNING
    else:
        return AlertLevel.NORMAL

async def process_activity_for_alert(employee_id: str, action, risk_score: int):
    level = determine_alert_level(risk_score)
    
    if level != AlertLevel.NORMAL:
        # Safely extract string if action arrives as an Enum object
        action_str = action.value if hasattr(action, 'value') else action
        
        # FIXED: Explicitly mapping names to values using keyword arguments
        alert_data = Alert(
            employee_id=employee_id,
            action=action_str,
            risk_score=risk_score,
            level=level
        )
        
        # Convert to database-safe JSON types
        alert_dict = jsonable_encoder(alert_data)
        
        # Quantum Encryption: Encrypt the action field for alerts
        if quantum_engine.is_initialized:
            encrypted_fields = []
            
            if alert_dict.get("action"):
                alert_dict["action_encrypted"] = quantum_engine.encrypt_field(
                    alert_dict["action"]
                )
                # Keep action readable for alerts (it's needed for display)
                encrypted_fields.append("action_backup")
            
            alert_dict["encrypted_fields"] = encrypted_fields
        
        # Add integrity hash and chain link
        alert_dict = await add_integrity_fields(alert_dict, "alerts")
        
        await db_instance.db["alerts"].insert_one(alert_dict)
        print(f"🚨 ALERT GENERATED: [{level.value}] Action: {action_str} by {employee_id} (Score: {risk_score}) [🔐 Quantum Secured]")