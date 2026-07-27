"""
AI Twin API Router
==================
REST endpoints for the AI Twin behavioural clone system.
All endpoints require admin JWT authentication.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel

from app.core.rbac import Permission
from app.core.security import require_permission
from app.services.ai_twin_service import (
    initialize_twin, reset_twin, get_profile, get_all_profile_summaries,
    get_twin_alerts, get_employee_threat_score, process_twin_event,
    score_only_event, run_twin_batch_scan, train_normal_baseline
)
from app.database.mongodb import db_instance

router = APIRouter(prefix="/api/ai-twin", tags=["AI Twin"])


# ── Request Models ───────────────────────────────────────────────────────

class SimulateEventRequest(BaseModel):
    employee_id: str
    action: str
    timestamp: Optional[datetime] = None
    # Behavioural telemetry fields (all optional for easy testing)
    wpm: Optional[float] = None
    keystroke_latency_ms: Optional[float] = None
    dwell_time_ms: Optional[float] = None
    backspace_rate: Optional[float] = None
    mouse_speed_px_s: Optional[float] = None
    click_frequency_per_min: Optional[float] = None
    idle_ratio: Optional[float] = None
    pointer_entropy: Optional[float] = None
    app_name: Optional[str] = None
    window_duration_s: Optional[float] = None
    clipboard_ops: Optional[int] = None
    print_count: Optional[int] = None
    download_size_mb: Optional[float] = None
    upload_size_mb: Optional[float] = None
    bandwidth_mb: Optional[float] = None
    is_sensitive_file: Optional[bool] = None
    is_confidential: Optional[bool] = None
    usb_connected: Optional[bool] = None
    is_bulk_operation: Optional[bool] = None
    is_external_connection: Optional[bool] = None
    is_cloud_upload: Optional[bool] = None
    is_failed_login: Optional[bool] = None
    is_privilege_escalation: Optional[bool] = None
    is_admin_command: Optional[bool] = None
    is_vpn: Optional[bool] = None
    session_duration_s: Optional[float] = None
    device_ip: Optional[str] = None


class TrainNormalRequest(BaseModel):
    employee_id: str
    num_events: int = 50
    base_wpm: float = 70.0
    base_mouse_speed: float = 350.0
    working_hours_start: int = 9
    working_hours_end: int = 17


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("/profiles", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def list_all_profiles():
    """
    Get lightweight summary of all employee AI Twin profiles.
    Used to populate the dashboard overview grid.
    """
    try:
        summaries = await get_all_profile_summaries()
        return {
            "status": "success",
            "count": len(summaries),
            "profiles": summaries
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch profiles: {str(e)}")


@router.get("/profile/{employee_id}", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def get_employee_profile(employee_id: str):
    """
    Get the full behavioural profile for a specific employee.
    Includes all domain statistics, embedding vector, and training status.
    """
    try:
        profile = await get_profile(employee_id)
        if not profile:
            raise HTTPException(status_code=404, detail=f"No AI Twin profile found for {employee_id}")
        return {"status": "success", "profile": profile}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/score/{employee_id}", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def get_threat_score(employee_id: str):
    """Get the current live threat score for a specific employee."""
    try:
        score = await get_employee_threat_score(employee_id)
        return {"status": "success", **score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def list_twin_alerts(limit: int = 100):
    """Fetch all AI Twin deviation alerts, newest first."""
    try:
        alerts = await get_twin_alerts(limit=limit)
        return {
            "status": "success",
            "count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/initialize/{employee_id}", dependencies=[Depends(require_permission(Permission.AITWIN_TRAIN))])
async def init_twin(employee_id: str):
    """
    Manually initialize an AI Twin for an employee.
    Normally called automatically on employee creation — this is the admin override.
    """
    try:
        # Fetch employee info for name/role
        emp = await db_instance.db["employees"].find_one({"employee_id": employee_id})
        if not emp:
            raise HTTPException(status_code=404, detail=f"Employee {employee_id} not found")
        profile = await initialize_twin(
            employee_id=employee_id,
            employee_name=emp.get("name", "Unknown"),
            role=emp.get("role", "Unknown")
        )
        return {
            "status": "success",
            "message": f"AI Twin initialized for {employee_id}",
            "training_start": profile.training_start.isoformat(),
            "status_value": profile.status.value
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset/{employee_id}", dependencies=[Depends(require_permission(Permission.AITWIN_RESET))])
async def reset_employee_twin(employee_id: str):
    """
    Reset an employee's AI Twin back to training mode.
    Wipes all learned statistics and restarts the training clock.
    USE WITH CAUTION — all baseline data is permanently erased.
    """
    try:
        profile = await reset_twin(employee_id)
        return {
            "status": "success",
            "message": f"AI Twin for {employee_id} has been reset. Training phase restarted.",
            "new_training_start": profile.training_start.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulate-event", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def simulate_behavioural_event(request: SimulateEventRequest):
    """
    Score a synthetic threat event against an employee's trained AI Twin baseline.

    IMPORTANT — This endpoint is READ-ONLY with respect to the AI Twin model:
      - The profile statistics are NEVER updated
      - No Welford learning occurs (training is NOT poisoned)
      - No EMA adaptation occurs
      - The baseline learned from the Employee Simulator is fully preserved

    This is purely a detection-testing tool. The AI Twin learns ONLY from
    genuine activities logged through the Employee Simulator.

    If the employee's twin is still in the training phase, a descriptive error
    is returned explaining how many more Employee Simulator events are needed.
    """
    try:
        extra = {k: v for k, v in request.dict().items()
                 if k not in ("employee_id", "action", "timestamp") and v is not None}

        # score_only_event — completely read-only, never modifies the profile
        result = await score_only_event(
            employee_id=request.employee_id,
            action=request.action,
            timestamp=request.timestamp,
            extra=extra,
        )

        # If employee is still training, return early with guidance
        if result.get("status") in ("NO_PROFILE", "STILL_TRAINING"):
            return {
                "status": "cannot_score",
                "reason": result.get("status"),
                "message": result.get("message"),
                "event_count": result.get("event_count", 0),
                "events_needed": result.get("events_needed", 50),
                "days_remaining": result.get("days_remaining", 14),
                "alert_generated": False,
                "alert": None,
            }

        threat_score = result.get("composite_threat_score", 0)
        is_alert = result.get("is_alert", False)
        severity = result.get("severity", "Normal")
        deviations = result.get("deviations", [])
        flagged = result.get("flagged_domains", [])

        return {
            "status": "success",
            "model_unchanged": True,   # ← confirms the profile was NOT modified
            "alert_generated": is_alert,
            "alert": {
                "threat_score": threat_score,
                "severity": severity,
                "confidence": min(99, int(50 + threat_score / 2)),
                "flagged_domains": flagged,
                "description": (
                    f"[SIMULATION ONLY — profile unchanged] "
                    f"Threat score {threat_score:.0f}/100 ({severity}). "
                    f"Flagged domains: {', '.join(flagged) if flagged else 'none'}. "
                    f"Based on baseline from {result.get('trained_on_events', 0)} training events."
                ),
                "feature_deviations": [
                    {
                        "feature_name": d.feature_name,
                        "domain": d.domain,
                        "baseline_mean": d.baseline_mean,
                        "z_score": d.z_score,
                        "severity": d.severity,
                    }
                    for d in deviations[:10]
                ],
                "embedding_drift": result.get("embedding_drift", 0),
                "trained_on_events": result.get("trained_on_events", 0),
            } if is_alert or threat_score > 0 else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/train-normal", dependencies=[Depends(require_permission(Permission.AITWIN_TRAIN))])
async def train_normal(request: TrainNormalRequest):
    """
    Generate a synthetic normal baseline for an employee to bypass manual training.
    This injects the requested number of events with configurable parameters,
    and backdates the training_start to instantly mark the profile as trained.
    """
    try:
        profile = await train_normal_baseline(
            employee_id=request.employee_id,
            num_events=request.num_events,
            base_wpm=request.base_wpm,
            base_mouse_speed=request.base_mouse_speed,
            working_hours_start=request.working_hours_start,
            working_hours_end=request.working_hours_end
        )
        return {
            "status": "success",
            "message": f"Successfully generated normal baseline for {request.employee_id}",
            "is_trained": profile.is_trained,
            "event_count": profile.event_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def run_batch_scan():
    """Run a manual batch scan across all trained profiles."""
    try:
        result = await run_twin_batch_scan()
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status", dependencies=[Depends(require_permission(Permission.AITWIN_READ))])
async def get_twin_system_status():
    """Get aggregate statistics about the AI Twin system."""
    try:
        total = await db_instance.db["ai_twin_profiles"].count_documents({})
        trained = await db_instance.db["ai_twin_profiles"].count_documents({"is_trained": True})
        training = await db_instance.db["ai_twin_profiles"].count_documents({"is_trained": False})
        alert_count = await db_instance.db["ai_twin_alerts"].count_documents({})
        open_alerts = await db_instance.db["ai_twin_alerts"].count_documents({"status": "OPEN"})

        return {
            "status": "active",
            "total_profiles": total,
            "trained_profiles": trained,
            "training_profiles": training,
            "total_alerts_generated": alert_count,
            "open_alerts": open_alerts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
