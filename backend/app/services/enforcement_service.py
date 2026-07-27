"""
Automated Enforcement
=====================
The single source of truth for automatically freezing an account.

Why this module exists
----------------------
Auto-block logic previously lived in three places with three different, mutually
unaware thresholds:

  activity_service   cumulative risk >= 100 across ALL activity, ever
  ai_twin_service    AI Twin composite threat score >= 90
  employees router   manual operator action, 24h fixed

They could not see each other, so an employee could be blocked twice for
unrelated reasons with no single record of why, the "reason" was never stored,
and the Simulator could only discover the block by polling a bare boolean. The
"cumulative risk, ever" rule also meant any long-tenured employee eventually
crossed the threshold through ordinary work — a false positive guaranteed by
arithmetic.

This module replaces the two automated paths. Manual operator override stays in
the employees router, because that is a privileged human action that must go
through PAM; the system enforcing policy is not an operator and holds no session.

Enforcement decision
--------------------
Three independent triggers, evaluated in severity order:

  1. Baseline deviation   the action departs from the employee's established
                          normal environment by more than the block threshold
  2. AI Twin threat       the behavioural clone's composite score is critical
  3. Windowed risk        risk accumulated *within a rolling window*, not
                          for all time

Every freeze writes: reason, trigger, severity, the evidence behind it, and a
`session_revoked_at` stamp that the Simulator's status poll turns into a forced
logout.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import db_instance

# ── Thresholds ──────────────────────────────────────────────────────────

# Baseline deviation: contextual risk at or above this freezes the account.
DEVIATION_BLOCK_THRESHOLD = 60
# ...and at or above this raises an alert without freezing.
DEVIATION_ALERT_THRESHOLD = 30

# AI Twin composite threat score that constitutes a critical finding.
TWIN_CRITICAL_THRESHOLD = 90

# Windowed risk accumulation. Scoped to a window precisely so ordinary
# long-term activity cannot accumulate its way into a block.
RISK_WINDOW_HOURS = 24
RISK_WINDOW_BLOCK_THRESHOLD = 120

# How long an automated freeze lasts.
AUTO_BLOCK_HOURS = 24

# Trigger identifiers, recorded on the employee document and the alert.
TRIGGER_DEVIATION = "BASELINE_DEVIATION"
TRIGGER_TWIN = "AI_TWIN_CRITICAL"
TRIGGER_RISK_WINDOW = "WINDOWED_RISK_THRESHOLD"

COLLECTION_ENFORCEMENT = "enforcement_actions"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _is_already_blocked(employee_id: str) -> bool:
    """
    True if an active freeze is already in place.

    Prevents a second trigger from extending an existing block and from emitting
    a duplicate alert for the same underlying incident.
    """
    user = await db_instance.db["employees"].find_one({"employee_id": employee_id})
    if not user or not user.get("is_blocked"):
        return False

    blocked_until = user.get("blocked_until")
    if blocked_until is None:
        return True
    if isinstance(blocked_until, str):
        try:
            blocked_until = datetime.fromisoformat(blocked_until.replace("Z", "+00:00"))
        except ValueError:
            return True
    if blocked_until.tzinfo is None:
        blocked_until = blocked_until.replace(tzinfo=timezone.utc)
    return _now() < blocked_until


async def _windowed_risk(employee_id: str) -> int:
    """Risk accumulated inside the rolling window, not for all time."""
    cutoff = (_now() - timedelta(hours=RISK_WINDOW_HOURS)).isoformat()
    cursor = db_instance.db["activities"].find({
        "employee_id": employee_id,
        "timestamp": {"$gte": cutoff},
    }).limit(5000)
    activities = await cursor.to_list(length=5000)
    return sum(a.get("risk_score", 0) or 0 for a in activities)


async def freeze_account(
    employee_id: str,
    trigger: str,
    reason: str,
    severity: str = "Critical",
    evidence: Optional[Dict[str, Any]] = None,
    hours: int = AUTO_BLOCK_HOURS,
) -> Dict[str, Any]:
    """
    Freeze an account and revoke any live session.

    `session_revoked_at` is the mechanism that logs the employee out: the
    Simulator polls the status endpoint every few seconds and terminates its
    session when it sees an active block. Recording the reason alongside it is
    what lets the Simulator explain *why*, instead of dumping the user to a
    login screen with no context.
    """
    now = _now()
    blocked_until = now + timedelta(hours=hours)

    await db_instance.db["employees"].update_one(
        {"employee_id": employee_id},
        {"$set": {
            "is_blocked": True,
            "blocked_until": blocked_until,
            "block_source": "AUTOMATED",
            "block_trigger": trigger,
            "block_reason": reason,
            "block_severity": severity,
            "blocked_by": "enforcement_service",
            "session_revoked_at": now.isoformat(),
        }},
    )

    record = {
        "employee_id": employee_id,
        "action_taken": "ACCOUNT_FROZEN",
        "trigger": trigger,
        "reason": reason,
        "severity": severity,
        "evidence": evidence or {},
        "blocked_until": blocked_until.isoformat(),
        "hours": hours,
        "timestamp": now.isoformat(),
    }
    await db_instance.db[COLLECTION_ENFORCEMENT].insert_one(dict(record))

    print(f"ENFORCEMENT [{trigger}] {employee_id} frozen for {hours}h: {reason}")
    return record


async def raise_alert(
    employee_id: str,
    trigger: str,
    reason: str,
    severity: str,
    confidence: int,
    evidence: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Emit an anomaly alert without freezing the account.

    Written into `anomaly_alerts` so it appears in the existing notification
    bell and dashboard panel rather than in a parallel stream nobody watches.
    """
    emp = await db_instance.db["employees"].find_one({"employee_id": employee_id})
    await db_instance.db["anomaly_alerts"].insert_one({
        "employee_id": employee_id,
        "employee_name": emp.get("name", "Unknown") if emp else "Unknown",
        "role": emp.get("role", "Unknown") if emp else "Unknown",
        "anomaly_type": "Baseline Deviation",
        "severity": severity,
        "confidence": confidence,
        "description": reason,
        "trigger": trigger,
        "evidence": evidence or {},
        "timestamp": _now().isoformat(),
        "status": "OPEN",
    })


async def _record_authorized(
    employee_id: str,
    action: str,
    override: Dict[str, Any],
    trigger: str,
    detail: str,
) -> None:
    """
    Log that enforcement was suppressed by an operator-granted override.

    Written to the same collection as freezes so the enforcement history shows
    both what was punished and what was deliberately permitted — an override
    that leaves no trace is indistinguishable from a detection failure.
    """
    await db_instance.db[COLLECTION_ENFORCEMENT].insert_one({
        "employee_id": employee_id,
        "action_taken": "AUTHORIZED_BY_OVERRIDE",
        "trigger": trigger,
        "reason": detail,
        "severity": "Info",
        "evidence": {
            "action": action,
            "override_id": override.get("override_id"),
            "granted_by": override.get("granted_by"),
            "override_reason": override.get("reason"),
            "allowed_actions": override.get("allowed_actions"),
            "expires_at": override.get("expires_at"),
            "events_remaining": override.get("events_remaining"),
        },
        "timestamp": _iso(_now()),
    })


def _iso(dt: datetime) -> str:
    return dt.isoformat()


async def evaluate_and_enforce(
    employee_id: str,
    action: str,
    deviation: Optional[Dict[str, Any]] = None,
    twin_threat_score: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Evaluate every enforcement trigger for one event and act on the outcome.

    Called once per activity from activity_service, and by ai_twin_service when
    a critical threat score is produced. Idempotent with respect to an existing
    freeze: an already-blocked account is left alone rather than re-blocked.

    Operator-granted overrides are consulted BEFORE any freeze. An override
    never suppresses detection — the deviation is still scored and still
    recorded — it only suppresses the punishment, and only within the time or
    event budget the operator granted.

    Returns a summary describing what was evaluated and what was done, so the
    caller can surface it without re-deriving the decision.
    """
    from app.services import override_service

    outcome: Dict[str, Any] = {
        "employee_id": employee_id,
        "action": action,
        "alerted": False,
        "frozen": False,
        "trigger": None,
        "reason": None,
        "evaluated": [],
        "override_applied": False,
    }

    if await _is_already_blocked(employee_id):
        outcome["reason"] = "Account already frozen; no further action taken."
        outcome["already_blocked"] = True
        return outcome

    # Live override, if any. Self-expires inside get_active_override.
    override = await override_service.get_active_override(employee_id)
    action_authorized = override_service.authorizes_action(override, action)
    block_exempt = override_service.exempts_block(override)
    override_consumed = False

    if override:
        outcome["override"] = {
            "override_id": override.get("override_id"),
            "granted_by": override.get("granted_by"),
            "reason": override.get("reason"),
            "allowed_actions": override.get("allowed_actions"),
            "exempt_block": override.get("exempt_block"),
            "seconds_remaining": override.get("seconds_remaining"),
            "events_remaining": override.get("events_remaining"),
            "authorizes_this_action": action_authorized,
        }

    # ── Trigger 1: baseline deviation ────────────────────────────────────
    if deviation and deviation.get("baseline_scope") != "none":
        contextual = deviation.get("contextual_risk", 0)
        outcome["evaluated"].append({
            "trigger": TRIGGER_DEVIATION,
            "value": contextual,
            "block_threshold": DEVIATION_BLOCK_THRESHOLD,
        })

        if contextual >= DEVIATION_BLOCK_THRESHOLD:
            # An operator explicitly authorised this action to depart from the
            # baseline. Record it and stand down — this is the whole point of
            # the grant, and re-freezing here would make it useless.
            if action_authorized:
                detail = (
                    f"Action '{action}' deviated from baseline (contextual risk "
                    f"{contextual}) but is authorised by an override granted by "
                    f"{override.get('granted_by')}: {override.get('reason')}"
                )
                await _record_authorized(
                    employee_id, action, override, TRIGGER_DEVIATION, detail
                )
                if override.get("max_events") is not None and not override_consumed:
                    await override_service.consume_event(override["override_id"])
                    override_consumed = True
                outcome.update({
                    "override_applied": True,
                    "trigger": TRIGGER_DEVIATION,
                    "reason": detail,
                })
                return outcome

            reason = (
                f"Action '{action}' deviated from the established normal "
                f"environment with a contextual risk of {contextual} "
                f"(threshold {DEVIATION_BLOCK_THRESHOLD}). "
                + deviation.get("message", "")
            )

            # Block-exempt but not action-authorised: alert loudly, do not freeze.
            if block_exempt:
                detail = (
                    f"{reason} Automated freeze suppressed by a block exemption "
                    f"granted by {override.get('granted_by')} — review manually."
                )
                await _record_authorized(
                    employee_id, action, override, TRIGGER_DEVIATION, detail
                )
                await raise_alert(
                    employee_id, TRIGGER_DEVIATION, detail, "High",
                    confidence=min(95, 60 + contextual // 4),
                    evidence={"reasons": deviation.get("reasons", []),
                              "override_id": override.get("override_id")},
                )
                outcome.update({
                    "alerted": True, "override_applied": True,
                    "trigger": TRIGGER_DEVIATION, "reason": detail,
                })
                return outcome

            await freeze_account(
                employee_id, TRIGGER_DEVIATION, reason, "Critical",
                evidence={
                    "action": action,
                    "base_risk": deviation.get("base_risk"),
                    "deviation_premium": deviation.get("deviation_premium"),
                    "contextual_risk": contextual,
                    "baseline_scope": deviation.get("baseline_scope"),
                    "reasons": deviation.get("reasons", []),
                },
            )
            await raise_alert(
                employee_id, TRIGGER_DEVIATION, reason, "Critical",
                confidence=min(95, 60 + contextual // 4),
                evidence={"reasons": deviation.get("reasons", [])},
            )
            outcome.update({
                "frozen": True, "alerted": True,
                "trigger": TRIGGER_DEVIATION, "reason": reason,
            })
            return outcome

        if contextual >= DEVIATION_ALERT_THRESHOLD:
            reason = (
                f"Action '{action}' deviated from normal behaviour "
                f"(contextual risk {contextual}). " + deviation.get("message", "")
            )
            await raise_alert(
                employee_id, TRIGGER_DEVIATION, reason,
                "High" if contextual >= 45 else "Warning",
                confidence=min(90, 50 + contextual),
                evidence={"reasons": deviation.get("reasons", [])},
            )
            outcome.update({
                "alerted": True, "trigger": TRIGGER_DEVIATION, "reason": reason,
            })

    # ── Trigger 2: AI Twin critical threat ───────────────────────────────
    if twin_threat_score is not None:
        outcome["evaluated"].append({
            "trigger": TRIGGER_TWIN,
            "value": twin_threat_score,
            "block_threshold": TWIN_CRITICAL_THRESHOLD,
        })
        if twin_threat_score >= TWIN_CRITICAL_THRESHOLD:
            reason = (
                f"AI Twin composite threat score reached {twin_threat_score:.0f} "
                f"(critical threshold {TWIN_CRITICAL_THRESHOLD}), indicating "
                "behaviour materially unlike this employee's own trained baseline."
            )

            # A block exemption covers this trigger too. Note that an
            # action-scoped authorisation alone does NOT: a critical Twin score
            # is a whole-behaviour verdict rather than a judgement about one
            # action, so suppressing it needs the explicit block exemption.
            if block_exempt:
                detail = (
                    f"{reason} Automated freeze suppressed by a block exemption "
                    f"granted by {override.get('granted_by')} — review manually."
                )
                await _record_authorized(
                    employee_id, action, override, TRIGGER_TWIN, detail
                )
                await raise_alert(
                    employee_id, TRIGGER_TWIN, detail, "Critical",
                    confidence=min(99, int(50 + twin_threat_score / 2)),
                    evidence={"twin_threat_score": twin_threat_score,
                              "override_id": override.get("override_id")},
                )
                outcome.update({
                    "alerted": True, "override_applied": True,
                    "trigger": TRIGGER_TWIN, "reason": detail,
                })
                return outcome

            await freeze_account(
                employee_id, TRIGGER_TWIN, reason, "Critical",
                evidence={"twin_threat_score": twin_threat_score, "action": action},
            )
            outcome.update({
                "frozen": True, "alerted": True,
                "trigger": TRIGGER_TWIN, "reason": reason,
            })
            return outcome

    # ── Trigger 3: windowed risk accumulation ────────────────────────────
    windowed = await _windowed_risk(employee_id)
    outcome["evaluated"].append({
        "trigger": TRIGGER_RISK_WINDOW,
        "value": windowed,
        "block_threshold": RISK_WINDOW_BLOCK_THRESHOLD,
        "window_hours": RISK_WINDOW_HOURS,
    })

    if windowed >= RISK_WINDOW_BLOCK_THRESHOLD:
        reason = (
            f"Accumulated risk of {windowed} in the last {RISK_WINDOW_HOURS} hours "
            f"exceeded the {RISK_WINDOW_BLOCK_THRESHOLD} threshold. Scoped to a "
            "rolling window so ordinary long-term activity cannot accumulate into "
            "a block."
        )

        # This is the trigger that made manual unblocks look broken: the risk
        # that caused the original freeze is still inside the window, so the
        # next action re-freezes immediately. A block exemption — including the
        # grace window attached automatically on unblock — is what breaks that
        # loop and gives the account time to age out of the window.
        if block_exempt:
            detail = (
                f"{reason} Automated freeze suppressed by a block exemption "
                f"granted by {override.get('granted_by')}: {override.get('reason')}"
            )
            await _record_authorized(
                employee_id, action, override, TRIGGER_RISK_WINDOW, detail
            )
            if override.get("max_events") is not None and not override_consumed:
                await override_service.consume_event(override["override_id"])
                override_consumed = True
            outcome.update({
                "override_applied": True,
                "trigger": TRIGGER_RISK_WINDOW,
                "reason": detail,
            })
            return outcome

        await freeze_account(
            employee_id, TRIGGER_RISK_WINDOW, reason, "Critical",
            evidence={
                "windowed_risk": windowed,
                "window_hours": RISK_WINDOW_HOURS,
                "action": action,
            },
        )
        outcome.update({
            "frozen": True, "alerted": True,
            "trigger": TRIGGER_RISK_WINDOW, "reason": reason,
        })

    return outcome


async def get_enforcement_status(employee_id: str) -> Dict[str, Any]:
    """
    Current enforcement state for one employee.

    Backs the Simulator's status poll: `is_blocked` drives the forced logout and
    the reason/severity fields let the Simulator explain what happened.
    """
    user = await db_instance.db["employees"].find_one({"employee_id": employee_id})
    if not user:
        return {"employee_id": employee_id, "found": False, "is_blocked": False}

    is_blocked = await _is_already_blocked(employee_id)

    # A lapsed block is cleared here so state cannot drift between the
    # employees router and this service.
    if user.get("is_blocked") and not is_blocked:
        await db_instance.db["employees"].update_one(
            {"employee_id": employee_id},
            {"$set": {
                "is_blocked": False,
                "blocked_until": None,
                "block_reason": None,
                "block_trigger": None,
                "block_severity": None,
            }},
        )

    blocked_until = user.get("blocked_until")
    if isinstance(blocked_until, datetime):
        blocked_until = blocked_until.isoformat()

    return {
        "employee_id": employee_id,
        "found": True,
        "is_blocked": is_blocked,
        "blocked_until": blocked_until if is_blocked else None,
        "block_source": user.get("block_source") if is_blocked else None,
        "block_trigger": user.get("block_trigger") if is_blocked else None,
        "block_reason": user.get("block_reason") if is_blocked else None,
        "block_severity": user.get("block_severity") if is_blocked else None,
        "session_revoked_at": user.get("session_revoked_at") if is_blocked else None,
    }


async def get_recent_actions(limit: int = 100) -> List[Dict[str, Any]]:
    """Recent automated enforcement actions, newest first."""
    cursor = db_instance.db[COLLECTION_ENFORCEMENT].find({}) \
        .sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


def get_policy() -> Dict[str, Any]:
    """The active enforcement thresholds, for the admin UI and documentation."""
    return {
        "deviation_block_threshold": DEVIATION_BLOCK_THRESHOLD,
        "deviation_alert_threshold": DEVIATION_ALERT_THRESHOLD,
        "twin_critical_threshold": TWIN_CRITICAL_THRESHOLD,
        "risk_window_hours": RISK_WINDOW_HOURS,
        "risk_window_block_threshold": RISK_WINDOW_BLOCK_THRESHOLD,
        "auto_block_hours": AUTO_BLOCK_HOURS,
        "triggers": [TRIGGER_DEVIATION, TRIGGER_TWIN, TRIGGER_RISK_WINDOW],
    }
