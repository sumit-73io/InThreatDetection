from fastapi import APIRouter, HTTPException, Depends
from app.routers.auth import verify_admin
from app.database.mongodb import db_instance
from app.services.anomaly_engine import run_anomaly_scan, persist_anomaly_alerts
from bson import ObjectId

router = APIRouter(prefix="/api/anomaly", tags=["Anomaly Detection"])


@router.post("/scan", dependencies=[Depends(verify_admin)])
async def trigger_anomaly_scan():
    """Run a full anomaly scan across all employees and persist new alerts."""
    try:
        alerts = await run_anomaly_scan()
        inserted = await persist_anomaly_alerts(alerts)
        return {
            "status": "success",
            "total_anomalies_detected": len(alerts),
            "new_alerts_created": inserted,
            "message": f"Scan complete. {len(alerts)} anomalies detected, {inserted} new alerts persisted."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Anomaly scan failed: {str(e)}")


@router.get("/alerts", dependencies=[Depends(verify_admin)])
async def get_anomaly_alerts():
    """Fetch all anomaly alerts, newest first."""
    try:
        cursor = db_instance.db["anomaly_alerts"].find().sort("timestamp", -1).limit(100)
        alerts = await cursor.to_list(length=100)
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/alerts/{alert_id}/acknowledge", dependencies=[Depends(verify_admin)])
async def acknowledge_alert(alert_id: str):
    """Mark an anomaly alert as acknowledged."""
    try:
        result = await db_instance.db["anomaly_alerts"].update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": "ACKNOWLEDGED"}}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "success", "message": "Alert acknowledged."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
