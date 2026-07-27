"""
Enforcement Overrides (operator-authorised exceptions)
======================================================
Lets a Super Admin / Security Admin deliberately authorise behaviour that
automated enforcement would otherwise punish — bounded by TIME or by a COUNT OF
EVENTS, never open-ended.

Two problems this solves
------------------------

1. **"I unblocked them and they got re-blocked immediately."**
   Clearing `is_blocked` does nothing about the risk *already accumulated* in the
   rolling 24-hour window. An employee sitting at 210 windowed risk against a
   120 threshold is re-frozen by the very next action they take, so the manual
   unblock looks broken. A block exemption suppresses automated freezing for the
   granted window, giving the account real breathing room. Manual unblock now
   attaches a short one automatically (see UNBLOCK_GRACE_MINUTES).

2. **"This employee legitimately needs to do something outside their baseline."**
   A migration, an audit, quarter-end, covering a colleague. The baseline
   correctly flags it as deviation; the operator needs a way to say "yes, I know,
   I authorised it" without wiping the baseline (which would destroy the very
   history that makes future detection work) and without disabling detection
   globally.

Why bounded by design
---------------------
An unbounded exemption is a permanent hole in enforcement that nobody remembers
granting. Every override MUST carry at least one limit — an expiry, an event
budget, or both — and both are capped. When either limit is reached the override
closes itself. Granting one is a privileged action requiring PAM elevation, and
every grant, use, and expiry is audited.

An override never grants a *permission*. It only tells enforcement not to punish
behaviour an operator has explicitly accepted responsibility for.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import db_instance

COLLECTION = "enforcement_overrides"

# ── Policy caps ─────────────────────────────────────────────────────────
MAX_DURATION_MINUTES = 24 * 60      # no override outlives a day
MAX_EVENTS = 500                    # nor an event budget beyond this
DEFAULT_DURATION_MINUTES = 60
MIN_REASON_CHARS = 15               # forces a real justification

# Grace window automatically attached when an operator manually unblocks an
# account. Without it the accumulated windowed risk re-freezes them on their
# next action and the unblock appears to have failed.
UNBLOCK_GRACE_MINUTES = 30

# Lifecycle
STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_CONSUMED = "CONSUMED"
STATUS_REVOKED = "REVOKED"

# Sentinel meaning "any action" in `allowed_actions`.
ALL_ACTIONS = "*"


class OverrideError(Exception):
    """Policy violation. Routers translate to HTTP 400."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _public(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc = dict(doc)
    doc.pop("_id", None)
    return doc


def _remaining(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Annotate a doc with how much of each limit is left."""
    out = _public(doc)
    expires_at = _parse(doc.get("expires_at"))
    out["seconds_remaining"] = (
        max(0, int((expires_at - _now()).total_seconds())) if expires_at else None
    )
    out["events_remaining"] = (
        max(0, doc["max_events"] - doc.get("events_used", 0))
        if doc.get("max_events") is not None else None
    )
    return out


# ═══════════════════════════════════════════════════════════════════════
# GRANT / REVOKE
# ═══════════════════════════════════════════════════════════════════════

async def grant_override(
    employee_id: str,
    granted_by: str,
    granted_by_role: str,
    reason: str,
    exempt_block: bool = True,
    allowed_actions: Optional[List[str]] = None,
    duration_minutes: Optional[int] = DEFAULT_DURATION_MINUTES,
    max_events: Optional[int] = None,
    source: str = "MANUAL",
) -> Dict[str, Any]:
    """
    Grant a bounded enforcement override.

    exempt_block     suppress automated freezing while the override is live
    allowed_actions  actions authorised to deviate from the baseline.
                     None/[] means ALL actions; otherwise only those listed.
    duration_minutes time limit (None to rely purely on the event budget)
    max_events       event budget (None to rely purely on time)

    At least one of duration_minutes / max_events must be set.
    """
    emp = await db_instance.db["employees"].find_one({"employee_id": employee_id})
    if not emp:
        raise OverrideError(f"Employee {employee_id} not found.")

    reason = (reason or "").strip()
    if len(reason) < MIN_REASON_CHARS:
        raise OverrideError(
            f"Reason must be at least {MIN_REASON_CHARS} characters — it is the "
            "permanent record of why enforcement was weakened."
        )

    if duration_minutes is None and max_events is None:
        raise OverrideError(
            "An override must be bounded by a duration, an event budget, or both. "
            "An unbounded override is a permanent gap in enforcement."
        )

    if duration_minutes is not None:
        if duration_minutes < 1 or duration_minutes > MAX_DURATION_MINUTES:
            raise OverrideError(
                f"Duration must be between 1 and {MAX_DURATION_MINUTES} minutes."
            )
    if max_events is not None:
        if max_events < 1 or max_events > MAX_EVENTS:
            raise OverrideError(f"Event budget must be between 1 and {MAX_EVENTS}.")

    actions = sorted({a.strip().upper() for a in (allowed_actions or []) if a.strip()})
    if not actions:
        actions = [ALL_ACTIONS]

    # Supersede any existing live override for this employee so the effective
    # policy is always a single unambiguous document.
    superseded = await _close_active(
        employee_id, STATUS_REVOKED, granted_by, "Superseded by a newer override"
    )

    now = _now()
    doc = {
        "override_id": uuid.uuid4().hex,
        "employee_id": employee_id,
        "employee_name": emp.get("name", "Unknown"),
        "employee_role": emp.get("role", "Unknown"),
        "granted_by": granted_by,
        "granted_by_role": granted_by_role,
        "reason": reason,
        "source": source,
        "exempt_block": bool(exempt_block),
        "allowed_actions": actions,
        "duration_minutes": duration_minutes,
        "expires_at": _iso(now + timedelta(minutes=duration_minutes)) if duration_minutes else None,
        "max_events": max_events,
        "events_used": 0,
        "status": STATUS_ACTIVE,
        "created_at": _iso(now),
        "last_used_at": None,
        "closed_at": None,
        "closed_by": None,
        "close_reason": None,
        "superseded_count": superseded,
    }
    await db_instance.db[COLLECTION].insert_one(dict(doc))
    print(
        f"OVERRIDE GRANTED {employee_id} by {granted_by}: "
        f"block_exempt={exempt_block} actions={actions} "
        f"duration={duration_minutes}m events={max_events}"
    )
    return _remaining(doc)


async def _close_active(
    employee_id: str, status: str, actor: Optional[str], reason: str
) -> int:
    """Close every currently-active override for an employee. Returns the count."""
    result = await db_instance.db[COLLECTION].update_many(
        {"employee_id": employee_id, "status": STATUS_ACTIVE},
        {"$set": {
            "status": status,
            "closed_at": _iso(_now()),
            "closed_by": actor,
            "close_reason": reason,
        }},
    )
    return result.modified_count


async def revoke_override(
    override_id: str, actor: str, reason: str = ""
) -> Dict[str, Any]:
    """Close an override early."""
    doc = await db_instance.db[COLLECTION].find_one({"override_id": override_id})
    if not doc:
        raise OverrideError(f"Override {override_id} not found.")
    if doc["status"] != STATUS_ACTIVE:
        raise OverrideError(f"Override is already {doc['status']}.")

    await db_instance.db[COLLECTION].update_one(
        {"override_id": override_id},
        {"$set": {
            "status": STATUS_REVOKED,
            "closed_at": _iso(_now()),
            "closed_by": actor,
            "close_reason": reason or "Revoked by operator",
        }},
    )
    return {
        "override_id": override_id,
        "employee_id": doc["employee_id"],
        "status": STATUS_REVOKED,
    }


async def grant_unblock_grace(
    employee_id: str, actor: str, actor_role: str
) -> Optional[Dict[str, Any]]:
    """
    Attach the automatic post-unblock grace window.

    This is the fix for the manual unblock appearing not to work: without it, an
    account whose windowed risk is still above the threshold is re-frozen on its
    next action. Time-boxed and audited like any other override.
    """
    try:
        return await grant_override(
            employee_id=employee_id,
            granted_by=actor,
            granted_by_role=actor_role,
            reason=(
                f"Automatic {UNBLOCK_GRACE_MINUTES}-minute grace window attached on "
                "manual unblock, so risk already accumulated in the rolling window "
                "does not immediately re-freeze the account."
            ),
            exempt_block=True,
            allowed_actions=None,          # all actions
            duration_minutes=UNBLOCK_GRACE_MINUTES,
            max_events=None,
            source="AUTO_UNBLOCK_GRACE",
        )
    except OverrideError as exc:
        print(f"Could not attach unblock grace for {employee_id}: {exc}")
        return None


# ═══════════════════════════════════════════════════════════════════════
# ENFORCEMENT-TIME CHECKS
# ═══════════════════════════════════════════════════════════════════════

async def get_active_override(employee_id: str) -> Optional[Dict[str, Any]]:
    """
    The employee's live override, or None.

    Self-closes anything whose limits have been reached, so an expired override
    can never be mistaken for a live one.
    """
    cursor = db_instance.db[COLLECTION].find({
        "employee_id": employee_id,
        "status": STATUS_ACTIVE,
    }).sort("created_at", -1)
    docs = await cursor.to_list(length=20)

    now = _now()
    for doc in docs:
        expires_at = _parse(doc.get("expires_at"))
        time_up = expires_at is not None and expires_at <= now
        budget_up = (
            doc.get("max_events") is not None
            and doc.get("events_used", 0) >= doc["max_events"]
        )

        if time_up or budget_up:
            await db_instance.db[COLLECTION].update_one(
                {"override_id": doc["override_id"]},
                {"$set": {
                    "status": STATUS_EXPIRED if time_up else STATUS_CONSUMED,
                    "closed_at": _iso(now),
                    "closed_by": "system",
                    "close_reason": (
                        "Time limit reached" if time_up else "Event budget exhausted"
                    ),
                }},
            )
            continue

        return _remaining(doc)

    return None


def authorizes_action(override: Optional[Dict[str, Any]], action: str) -> bool:
    """Does this override cover the given action?"""
    if not override:
        return False
    allowed = override.get("allowed_actions") or [ALL_ACTIONS]
    return ALL_ACTIONS in allowed or (action or "").upper() in allowed


def exempts_block(override: Optional[Dict[str, Any]]) -> bool:
    """Does this override suppress automated freezing?"""
    return bool(override and override.get("exempt_block"))


async def consume_event(override_id: str) -> None:
    """
    Charge one event against an override's budget.

    Only called when an override actually authorised something — an override
    that never gets used should not silently burn down.
    """
    await db_instance.db[COLLECTION].update_one(
        {"override_id": override_id, "status": STATUS_ACTIVE},
        {"$inc": {"events_used": 1}, "$set": {"last_used_at": _iso(_now())}},
    )


# ═══════════════════════════════════════════════════════════════════════
# QUERIES
# ═══════════════════════════════════════════════════════════════════════

async def list_overrides(
    employee_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Override history, newest first."""
    query: Dict[str, Any] = {}
    if employee_id:
        query["employee_id"] = employee_id
    if status:
        query["status"] = status

    cursor = db_instance.db[COLLECTION].find(query).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [_remaining(d) for d in docs]


async def get_active_map() -> Dict[str, Dict[str, Any]]:
    """
    employee_id -> live override, for the dashboard.

    One pass so the users table can badge every overridden employee without a
    request per row.
    """
    cursor = db_instance.db[COLLECTION].find({"status": STATUS_ACTIVE})
    docs = await cursor.to_list(length=1000)

    now = _now()
    out: Dict[str, Dict[str, Any]] = {}
    for doc in docs:
        expires_at = _parse(doc.get("expires_at"))
        if expires_at is not None and expires_at <= now:
            continue
        if (doc.get("max_events") is not None
                and doc.get("events_used", 0) >= doc["max_events"]):
            continue
        # Newest wins if several somehow coexist.
        existing = out.get(doc["employee_id"])
        if not existing or doc["created_at"] > existing["created_at"]:
            out[doc["employee_id"]] = _remaining(doc)
    return out


async def get_policy() -> Dict[str, Any]:
    """Caps and counts, for the admin UI."""
    coll = db_instance.db[COLLECTION]
    return {
        "max_duration_minutes": MAX_DURATION_MINUTES,
        "max_events": MAX_EVENTS,
        "default_duration_minutes": DEFAULT_DURATION_MINUTES,
        "min_reason_chars": MIN_REASON_CHARS,
        "unblock_grace_minutes": UNBLOCK_GRACE_MINUTES,
        "counts": {
            "active": await coll.count_documents({"status": STATUS_ACTIVE}),
            "expired": await coll.count_documents({"status": STATUS_EXPIRED}),
            "consumed": await coll.count_documents({"status": STATUS_CONSUMED}),
            "revoked": await coll.count_documents({"status": STATUS_REVOKED}),
        },
    }
