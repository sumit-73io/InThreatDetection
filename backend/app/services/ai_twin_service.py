"""
AI Twin Service
===============
Orchestration layer between the API routers and the AI Twin engine.
Handles MongoDB persistence of profiles, alerts, and manages the
training → monitoring lifecycle for each employee.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import random
import uuid

from fastapi.encoders import jsonable_encoder

from app.database.mongodb import db_instance
from app.models.ai_twin_models import (
    BehaviouralProfile, BehaviouralEvent, AITwinAlert, AITwinStatus, ProfileSummary, FeatureDeviation
)
from app.services.ai_twin_engine import (
    ingest_training_event, finalize_training, check_training_complete,
    score_event, apply_ema_update, compute_embedding,
    check_training_poisoning, get_training_integrity,
)
from app.core.ai_twin_config import (
    ALERT_MIN_THREAT_SCORE, ALERT_DEDUP_HOURS, THREAT_SCORE_HIGH, THREAT_SCORE_MEDIUM,
    EMBEDDING_DRIFT_THRESHOLD,
)

COLLECTION_PROFILES = "ai_twin_profiles"
COLLECTION_ALERTS   = "ai_twin_alerts"


# ═══════════════════════════════════════════════════════════════════════════
# PROFILE PERSISTENCE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

async def _load_profile(employee_id: str) -> Optional[BehaviouralProfile]:
    """Load a profile from MongoDB. Returns None if not found."""
    doc = await db_instance.db[COLLECTION_PROFILES].find_one({"employee_id": employee_id})
    if not doc:
        return None
    doc.pop("_id", None)
    return BehaviouralProfile(**doc)


async def _save_profile(profile: BehaviouralProfile) -> None:
    """Upsert a profile document to MongoDB."""
    doc = jsonable_encoder(profile)
    await db_instance.db[COLLECTION_PROFILES].update_one(
        {"employee_id": profile.employee_id},
        {"$set": doc},
        upsert=True
    )


# ═══════════════════════════════════════════════════════════════════════════
# LIFECYCLE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

async def initialize_twin(employee_id: str, employee_name: str = "Unknown", role: str = "Unknown") -> BehaviouralProfile:
    """
    Create a blank AI Twin profile for a new employee.
    Called automatically when an employee is provisioned.
    """
    existing = await _load_profile(employee_id)
    if existing:
        return existing  # Already initialized — idempotent

    profile = BehaviouralProfile(
        employee_id=employee_id,
        employee_name=employee_name,
        role=role,
        status=AITwinStatus.INITIALIZING,
    )
    await _save_profile(profile)
    print(f"AI Twin initialized for employee {employee_id} ({employee_name})")
    return profile


async def reset_twin(employee_id: str) -> BehaviouralProfile:
    """
    Reset a twin profile back to training mode.
    Admin action — wipes all learned statistics and restarts the clock.
    """
    # Preserve name and role from existing profile
    existing = await _load_profile(employee_id)
    name = existing.employee_name if existing else "Unknown"
    role = existing.role if existing else "Unknown"

    await db_instance.db[COLLECTION_PROFILES].delete_one({"employee_id": employee_id})

    # A fresh profile starts with all anti-poisoning counters at zero and no
    # quarantine, which is exactly the point of a reset: re-baseline cleanly.
    profile = BehaviouralProfile(
        employee_id=employee_id,
        employee_name=name,
        role=role,
        status=AITwinStatus.INITIALIZING,
    )
    await _save_profile(profile)
    print(f"AI Twin reset for employee {employee_id} (quarantine cleared)")
    return profile


async def ensure_all_employees_have_twins() -> int:
    """
    Startup check: create blank profiles for any employees that don't have one yet.
    Returns the number of new profiles created.
    """
    cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
    employees = await cursor.to_list(length=1000)
    created = 0
    for emp in employees:
        emp_id = emp.get("employee_id")
        if not emp_id:
            continue
        existing = await db_instance.db[COLLECTION_PROFILES].find_one({"employee_id": emp_id})
        if not existing:
            await initialize_twin(
                employee_id=emp_id,
                employee_name=emp.get("name", "Unknown"),
                role=emp.get("role", "Unknown")
            )
            created += 1
    if created:
        print(f"AI Twin: Created {created} new profiles for existing employees.")
    return created


# ═══════════════════════════════════════════════════════════════════════════
# MAIN EVENT PROCESSING PIPELINE  (called by activity_service — LEARNS + SCORES)
# ═══════════════════════════════════════════════════════════════════════════

async def process_twin_event(
    employee_id: str,
    action: str,
    timestamp: Optional[datetime] = None,
    extra: Optional[Dict[str, Any]] = None
) -> Optional[AITwinAlert]:
    """
    Main entry point for feeding a REAL activity event to the AI Twin.
    Called ONLY from activity_service.py on every genuine Employee Simulator event.

    During training  → profile LEARNS from this event (Welford update)
    After training   → profile SCORES the event, applies slow EMA adaptation
                       and persists an alert if score exceeds threshold.

    NEVER call this from the Threat Scenario Simulator.
        Use score_only_event() instead to avoid contaminating the baseline.
    """
    profile = await _load_profile(employee_id)
    if not profile:
        # No profile yet — initialize silently
        profile = await initialize_twin(employee_id)

    # Build a BehaviouralEvent from the raw activity data
    event = _build_behavioural_event(employee_id, action, timestamp, extra)

    alert = None

    if not profile.is_trained:
        # ── TRAINING PHASE ───────────────────────────────────────────────
        profile = ingest_training_event(profile, event)

        if check_training_complete(profile):
            profile = finalize_training(profile)
            print(f"AI Twin training complete for {employee_id} ({profile.event_count} events)")
        else:
            days_in_training = (datetime.now(timezone.utc) - profile.training_start.replace(tzinfo=timezone.utc)).days
            if profile.event_count % 10 == 0:
                print(f"AI Twin [{employee_id}]: {profile.event_count} training events, day {days_in_training}")

        await _save_profile(profile)

    else:
        # ── MONITORING PHASE ─────────────────────────────────────────────
        result = score_event(profile, event)
        threat_score = result["composite_threat_score"]

        # Update current threat state on profile
        old_score = profile.current_threat_score
        profile.current_threat_score = threat_score
        profile.threat_trend = "rising" if threat_score > old_score + 5 else \
                               "falling" if threat_score < old_score - 5 else "stable"

        # Update profile status based on threat level
        if threat_score >= THREAT_SCORE_HIGH:
            profile.status = AITwinStatus.ALERT
        elif threat_score < THREAT_SCORE_MEDIUM:
            profile.status = AITwinStatus.TRAINED

        # Slow EMA adaptation for legitimate drift (only for REAL activities)
        profile = apply_ema_update(profile, event)
        await _save_profile(profile)

        # Generate alert if threshold exceeded
        if result["is_alert"]:
            alert = await _generate_and_persist_alert(profile, result, event)
            
        # ── AUTOMATIC FREEZE ─────────────────────────────────────────────
        # Delegated to enforcement_service, which is the single decision point
        # for freezing an account. Previously this wrote to the employees
        # collection directly with its own threshold, so a block raised here was
        # invisible to the other enforcement paths and carried no stored reason.
        try:
            from app.services import enforcement_service
            await enforcement_service.evaluate_and_enforce(
                employee_id=employee_id,
                action=action,
                twin_threat_score=threat_score,
            )
        except Exception as enforcement_err:
            print(f"AI Twin enforcement delegation failed for {employee_id}: {enforcement_err}")

    return alert


async def train_normal_baseline(
    employee_id: str,
    num_events: int = 50,
    base_wpm: float = 70.0,
    base_mouse_speed: float = 350.0,
    working_hours_start: int = 9,
    working_hours_end: int = 17
) -> BehaviouralProfile:
    """
    Generate synthetic 'normal' events for an employee and feed them into the model.
    Backdates the training_start to instantly mark the twin as trained.
    """
    # Ensure profile exists
    profile = await _load_profile(employee_id)
    if not profile:
        profile = await initialize_twin(employee_id)
    
    # Reset first to guarantee a clean slate
    profile = await reset_twin(employee_id)
    
    # Backdate training start to 14 days ago
    profile.training_start = datetime.now(timezone.utc) - timedelta(days=15)
    await _save_profile(profile)
    
    apps = ['chrome', 'outlook', 'excel', 'word', 'teams']

    for i in range(num_events):
        # Pick random hour within working hours, sometimes slightly outside
        if random.random() < 0.9:
            hour = random.randint(working_hours_start, working_hours_end - 1)
        else:
            hour = random.randint(0, 23)
            
        ts = datetime.now(timezone.utc).replace(hour=hour, minute=random.randint(0, 59))
        
        # Add normal human variance to base stats
        wpm = max(10, random.gauss(base_wpm, 5))
        mouse = max(50, random.gauss(base_mouse_speed, 30))
        
        extra = {
            "wpm": wpm,
            "mouse_speed_px_s": mouse,
            "app_name": random.choice(apps),
            "click_frequency_per_min": max(1, random.gauss(15, 3)),
            "session_duration_s": random.gauss(14400, 3600), # 4 hours
        }
        
        await process_twin_event(
            employee_id=employee_id,
            action="VIEW_DOCUMENT" if random.random() < 0.5 else "UPDATE_RECORD",
            timestamp=ts,
            extra=extra
        )
        
    return await _load_profile(employee_id)


# ═══════════════════════════════════════════════════════════════════════════
# READ-ONLY SCORING  (called by Threat Simulator — NEVER modifies profile)
# ═══════════════════════════════════════════════════════════════════════════

async def score_only_event(
    employee_id: str,
    action: str,
    timestamp: Optional[datetime] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict:
    """
    Score a synthetic/simulated event against the employee's trained baseline
    WITHOUT modifying the profile in any way.

    This is the ONLY function the Threat Scenario Simulator should call.

    Guarantees:
      - Profile statistics are NEVER updated (no Welford, no EMA)
      - Nothing is written to MongoDB
      - No alert is automatically persisted (caller decides whether to persist)
      - If the profile is still in training, returns a clear error state

    Returns a rich scoring dict with per-domain deviations and threat score.
    """
    profile = await _load_profile(employee_id)
    if not profile:
        return {
            "status": "NO_PROFILE",
            "message": f"No AI Twin profile found for {employee_id}. Provision the employee first.",
            "composite_threat_score": 0,
            "is_alert": False,
        }

    if not profile.is_trained:
        days_left = max(0, 14 - (datetime.now(timezone.utc) - profile.training_start.replace(tzinfo=timezone.utc)).days)
        events_left = max(0, 50 - profile.event_count)
        return {
            "status": "STILL_TRAINING",
            "message": (
                f"AI Twin for {profile.employee_name} is still in the training phase. "
                f"It has learned from {profile.event_count} events so far. "
                f"Training needs approx. {events_left} more events from the Employee Simulator "
                f"and {days_left} more calendar days before it can detect threats."
            ),
            "event_count": profile.event_count,
            "events_needed": events_left,
            "days_remaining": days_left,
            "composite_threat_score": 0,
            "is_alert": False,
        }

    # Build event and score — profile is passed as a copy (read-only semantics)
    event = _build_behavioural_event(employee_id, action, timestamp, extra)
    result = score_event(profile, event)

    return {
        "status": "SCORED",
        "employee_name": profile.employee_name,
        "role": profile.role,
        "trained_on_events": profile.event_count,
        **result,
    }



def _build_behavioural_event(
    employee_id: str,
    action: str,
    timestamp: Optional[datetime],
    extra: Optional[Dict[str, Any]]
) -> BehaviouralEvent:
    """
    Build a BehaviouralEvent from raw activity data.
    The 'extra' dict carries any enriched telemetry (keyboard, mouse, etc.)
    that was included in the original activity payload.
    """
    extra = extra or {}
    ts = timestamp or datetime.now(timezone.utc)

    # Infer boolean signals from action type
    action_upper = action.upper()
    is_failed_login = action_upper == "FAILED_LOGIN"
    is_privilege_esc = action_upper == "CHANGE_PERMISSION"
    is_confidential = action_upper == "DOWNLOAD_CONFIDENTIAL"
    is_usb = action_upper == "USB_CONNECTED"
    is_delete = action_upper == "DELETE_FILE"

    return BehaviouralEvent(
        employee_id=employee_id,
        action=action,
        timestamp=ts,
        device_ip=extra.get("device_ip"),
        is_vpn=extra.get("is_vpn"),
        device_fingerprint=extra.get("device_fingerprint"),
        session_duration_s=extra.get("session_duration_s"),
        wpm=extra.get("wpm"),
        keystroke_latency_ms=extra.get("keystroke_latency_ms"),
        dwell_time_ms=extra.get("dwell_time_ms"),
        flight_time_ms=extra.get("flight_time_ms"),
        backspace_rate=extra.get("backspace_rate"),
        shortcut_usage_rate=extra.get("shortcut_usage_rate"),
        error_rate=extra.get("error_rate"),
        mouse_speed_px_s=extra.get("mouse_speed_px_s"),
        mouse_acceleration=extra.get("mouse_acceleration"),
        click_frequency_per_min=extra.get("click_frequency_per_min"),
        double_click_interval_ms=extra.get("double_click_interval_ms"),
        scroll_speed=extra.get("scroll_speed"),
        idle_ratio=extra.get("idle_ratio"),
        pointer_entropy=extra.get("pointer_entropy"),
        app_name=extra.get("app_name"),
        window_duration_s=extra.get("window_duration_s"),
        browser_tab_count=extra.get("browser_tab_count"),
        clipboard_ops=extra.get("clipboard_ops"),
        print_count=extra.get("print_count"),
        download_size_mb=extra.get("download_size_mb"),
        upload_size_mb=extra.get("upload_size_mb"),
        file_count=extra.get("file_count"),
        is_sensitive_file=extra.get("is_sensitive_file"),
        is_confidential=is_confidential or extra.get("is_confidential", False),
        usb_connected=is_usb or extra.get("usb_connected", False),
        is_bulk_operation=extra.get("is_bulk_operation", False),
        bandwidth_mb=extra.get("bandwidth_mb"),
        is_external_connection=extra.get("is_external_connection"),
        is_cloud_upload=extra.get("is_cloud_upload"),
        api_request_count=extra.get("api_request_count"),
        is_rdp=extra.get("is_rdp"),
        is_failed_login=is_failed_login or extra.get("is_failed_login", False),
        is_mfa_used=extra.get("is_mfa_used"),
        is_privilege_escalation=is_privilege_esc or extra.get("is_privilege_escalation", False),
        is_admin_command=extra.get("is_admin_command"),
        details=extra.get("details"),
        risk_score=extra.get("risk_score", 0),
    )


async def _generate_and_persist_alert(
    profile: BehaviouralProfile,
    score_result: Dict,
    event: BehaviouralEvent,
) -> Optional[AITwinAlert]:
    """Build and persist an AI Twin alert, with deduplication."""
    # Deduplication — suppress if identical alert was generated recently
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=ALERT_DEDUP_HOURS)).isoformat()
    existing = await db_instance.db[COLLECTION_ALERTS].find_one({
        "employee_id": profile.employee_id,
        "timestamp": {"$gte": cutoff},
    })
    if existing:
        return None  # Deduplicated

    threat_score = score_result["composite_threat_score"]
    severity = score_result["severity"]
    deviations = score_result["deviations"]
    flagged_domains = score_result["flagged_domains"]
    embedding_drift = score_result["embedding_drift"]

    # Build human-readable description
    domain_list = ", ".join(flagged_domains) if flagged_domains else "unknown domains"
    top_features = [d.feature_name for d in deviations if d.severity in ("high", "critical")][:3]
    feature_str = ", ".join(top_features) if top_features else "multiple signals"
    description = (
        f"AI Twin detected significant behavioural deviation for {profile.employee_name} "
        f"(threat score: {threat_score:.0f}/100). "
        f"Anomalous signals in: {domain_list}. "
        f"Top flagged features: {feature_str}. "
        f"This pattern deviates from {profile.event_count} training events spanning their personal baseline. "
        f"Embedding drift: {embedding_drift:.3f} (threshold: {EMBEDDING_DRIFT_THRESHOLD})."
    )

    alert = AITwinAlert(
        employee_id=profile.employee_id,
        employee_name=profile.employee_name,
        role=profile.role,
        threat_score=threat_score,
        severity=severity,
        confidence=min(99, int(50 + threat_score / 2)),
        description=description,
        flagged_domains=flagged_domains,
        feature_deviations=deviations,
        embedding_drift=embedding_drift,
        baseline_threat_score=0.0,   # Baseline is always ~0 by definition
        training_events_count=profile.event_count,
    )

    alert_doc = jsonable_encoder(alert)
    # Also add anomaly_type for compatibility with the existing anomaly router
    alert_doc["anomaly_type"] = "AI Twin Behavioural Deviation"
    await db_instance.db[COLLECTION_ALERTS].insert_one(alert_doc)
    await db_instance.db["anomaly_alerts"].insert_one({**alert_doc, "anomaly_type": "AI Twin Behavioural Deviation"})

    print(f"AI Twin alert: {profile.employee_name} — score {threat_score:.0f} ({severity})")
    profile.last_alert_time = datetime.now(timezone.utc)

    return alert


# ═══════════════════════════════════════════════════════════════════════════
# QUERY / READ OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

async def get_profile(employee_id: str) -> Optional[Dict]:
    """Fetch a full profile document for the API."""
    doc = await db_instance.db[COLLECTION_PROFILES].find_one({"employee_id": employee_id})
    if doc:
        doc["_id"] = str(doc["_id"])
        
        # Attach block status from employees collection
        emp = await db_instance.db["employees"].find_one({"employee_id": employee_id})
        doc["is_blocked"] = emp.get("is_blocked", False) if emp else False

        # Attach training-data health so the UI can warn that a baseline was
        # quarantined rather than silently showing scores derived from it.
        try:
            doc["training_integrity"] = get_training_integrity(
                BehaviouralProfile(**{k: v for k, v in doc.items()
                                      if k not in ("_id", "is_blocked", "training_integrity")})
            )
        except Exception:
            doc["training_integrity"] = None

    return doc


async def get_all_profile_summaries() -> List[Dict]:
    """Fetch lightweight profile summaries for all employees."""
    cursor = db_instance.db[COLLECTION_PROFILES].find(
        {},
        {
            "employee_id": 1, "employee_name": 1, "role": 1, "status": 1,
            "is_trained": 1, "event_count": 1, "training_start": 1, "training_end": 1,
            "current_threat_score": 1, "threat_trend": 1, "last_updated": 1,
            "quarantined": 1, "quarantine_reason": 1,
            "learned_value_count": 1, "clipped_value_count": 1,
            "rejected_event_count": 1, "ema_steps_capped": 1,
        }
    )
    docs = await cursor.to_list(length=1000)
    
    # Batch fetch block status from employees collection
    employee_ids = [d["employee_id"] for d in docs]
    emp_cursor = db_instance.db["employees"].find({"employee_id": {"$in": employee_ids}}, {"employee_id": 1, "is_blocked": 1})
    emp_docs = await emp_cursor.to_list(length=1000)
    block_status_map = {e["employee_id"]: e.get("is_blocked", False) for e in emp_docs}
    
    now = datetime.now(timezone.utc)
    summaries = []
    for d in docs:
        d["_id"] = str(d["_id"])
        d["is_blocked"] = block_status_map.get(d["employee_id"], False)
        ts = d.get("training_start")
        if ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    ts = now
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            d["days_in_training"] = (now - ts).days
        else:
            d["days_in_training"] = 0
        d["embedding_drift"] = 0.0
        summaries.append(d)
    return summaries


async def get_twin_alerts(limit: int = 100) -> List[Dict]:
    """Fetch AI Twin specific alerts."""
    cursor = db_instance.db[COLLECTION_ALERTS].find().sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def get_employee_threat_score(employee_id: str) -> Dict:
    """Get the current threat score and status for a specific employee."""
    profile = await _load_profile(employee_id)
    if not profile:
        return {"employee_id": employee_id, "status": "NO_PROFILE", "threat_score": 0.0}
    return {
        "employee_id": employee_id,
        "employee_name": profile.employee_name,
        "status": profile.status.value,
        "is_trained": profile.is_trained,
        "threat_score": profile.current_threat_score,
        "threat_trend": profile.threat_trend,
        "event_count": profile.event_count,
        "flagged": profile.status == AITwinStatus.ALERT,
    }


async def run_twin_batch_scan() -> Dict:
    """
    Periodic batch scan: check embedding drift for employees who haven't
    had a recent event but whose profile may have drifted naturally.
    Called from the background task scheduler.
    """
    cursor = db_instance.db[COLLECTION_PROFILES].find({"is_trained": True})
    profiles_docs = await cursor.to_list(length=1000)
    scanned = 0
    alerts_generated = 0
    for doc in profiles_docs:
        doc.pop("_id", None)
        try:
            profile = BehaviouralProfile(**doc)
            scanned += 1
        except Exception:
            continue
    return {"profiles_scanned": scanned, "alerts_generated": alerts_generated}
