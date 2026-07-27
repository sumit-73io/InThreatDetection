"""
Normal-Environment Behavioural Baseline
=======================================
Establishes what "normal" looks like, so risk can be expressed as *deviation
from normal* rather than as a fixed per-action weight.

Why this exists
---------------
`risk_engine.calculate_risk_score` maps an action to a constant: DELETE_FILE is
always 40, whoever does it and whenever. That cannot distinguish a DBA deleting
files at 2pm as part of their job from the same DBA deleting files at 3am for
the first time ever. Without a notion of normal, "abnormal" is not expressible.

Two baseline scopes are kept:

  employee-scope  what this specific person normally does. Most precise, needs
                  enough history to be meaningful.
  role-scope      what people in this job normally do. The fallback for new
                  joiners, who have no personal history but are not therefore
                  automatically suspicious.

Anti-poisoning
--------------
A baseline is only useful if it describes clean behaviour, and the same
false-learning risk applies here as in the AI Twin: compute it over a window
that contains an incident and the incident becomes normal. Guards:

  1. MIN_EVENTS_FOR_BASELINE - refuse to build from too little history.
  2. High-risk contamination ceiling - refuse a window already dominated by
     high-risk activity.
  3. Explicit LOCK - once an operator confirms a baseline is good it is frozen
     and automatic recomputation cannot silently overwrite it. Unlocking is a
     privileged action (baseline:manage).

Stored in the `behaviour_baselines` collection, one document per scope key.
"""

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.database.mongodb import db_instance

COLLECTION = "behaviour_baselines"

# ── Guards ──────────────────────────────────────────────────────────────
MIN_EVENTS_FOR_BASELINE = 15          # below this a baseline is noise
MIN_EVENTS_FOR_ROLE_BASELINE = 30     # role baselines pool several people
MAX_HIGH_RISK_FRACTION = 0.35         # refuse a contaminated window
HIGH_RISK_ACTION_THRESHOLD = 30       # per-action risk considered "high"

DEFAULT_WINDOW_DAYS = 30

# ── Deviation scoring weights ───────────────────────────────────────────
# How much each kind of deviation contributes to the contextual risk premium.
W_UNSEEN_ACTION   = 25    # an action never before performed
W_RARE_ACTION     = 12    # an action far above its normal frequency
W_OFF_HOURS       = 18    # activity outside the normal hours for this person
W_VOLUME_SPIKE    = 15    # far more actions than a normal day
W_RISK_RATE       = 20    # accumulating risk faster than normal

# Deviation is measured in standard deviations above the baseline mean.
VOLUME_SPIKE_SIGMA = 2.0
RISK_RATE_SIGMA    = 2.0

HIGH_RISK_ACTIONS = {
    "DOWNLOAD_CONFIDENTIAL", "DELETE_FILE", "CHANGE_PERMISSION",
    "USB_CONNECTED", "FAILED_LOGIN",
}

ACTION_RISK_WEIGHTS = {
    "LOGIN": 0, "LOGOUT": 0, "VIEW_CUSTOMER": 0,
    "DOWNLOAD_FILE": 10, "DOWNLOAD_CONFIDENTIAL": 30, "USB_CONNECTED": 20,
    "FAILED_LOGIN": 15, "CHANGE_PERMISSION": 35, "DELETE_FILE": 40,
}


class BaselineRefused(Exception):
    """A guard refused to build the baseline. Not an error - an abstention."""

    def __init__(self, guard: str, message: str):
        self.guard = guard
        self.message = message
        super().__init__(f"[{guard}] {message}")


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _action_of(activity: dict) -> str:
    action = activity.get("action", "")
    return action.value if hasattr(action, "value") else str(action)


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: List[float], mean_val: Optional[float] = None) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values) if mean_val is None else mean_val
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


def _risk_of(action: str) -> int:
    return ACTION_RISK_WEIGHTS.get(action, 0)


# ═══════════════════════════════════════════════════════════════════════════
# BASELINE CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════

def _profile_from_activities(activities: List[dict], min_events: int) -> Dict[str, Any]:
    """
    Derive a normal-environment profile from a list of activities.

    Raises BaselineRefused when a guard rejects the window.
    """
    if len(activities) < min_events:
        raise BaselineRefused(
            "insufficient_history",
            f"Only {len(activities)} events available; at least {min_events} are "
            "needed before a behavioural norm can be established. Until then, "
            "risk falls back to static action weights.",
        )

    actions = [_action_of(a) for a in activities]
    action_counts = Counter(actions)

    # Guard 2: contamination. If the window is already mostly high-risk, it is
    # not a description of normal.
    high_risk_events = sum(1 for a in actions if a in HIGH_RISK_ACTIONS)
    high_risk_fraction = high_risk_events / len(actions)
    if high_risk_fraction > MAX_HIGH_RISK_FRACTION:
        raise BaselineRefused(
            "contaminated_window",
            f"{high_risk_events} of {len(actions)} events ({high_risk_fraction:.0%}) "
            f"are high-risk actions, above the {MAX_HIGH_RISK_FRACTION:.0%} ceiling. "
            "Treating this window as 'normal' would teach the system that "
            "high-risk activity is expected and suppress future detection. "
            "Resolve the outstanding alerts, then re-baseline from a clean period.",
        )

    # Hour-of-day distribution.
    timestamps = [t for t in (_parse_ts(a.get("timestamp")) for a in activities) if t]
    hour_counts = Counter(t.hour for t in timestamps)
    normal_hours = sorted(h for h, c in hour_counts.items() if c >= 2)
    off_hours_events = sum(1 for t in timestamps if t.hour >= 22 or t.hour < 6)
    off_hours_rate = (off_hours_events / len(timestamps)) if timestamps else 0.0

    # Per-day volume and risk accumulation.
    by_day: Dict[str, List[dict]] = defaultdict(list)
    for act, ts in zip(activities, (_parse_ts(a.get("timestamp")) for a in activities)):
        if ts:
            by_day[ts.date().isoformat()].append(act)

    daily_volumes = [float(len(v)) for v in by_day.values()]
    daily_risks = [
        float(sum(a.get("risk_score", 0) or 0 for a in v)) for v in by_day.values()
    ]

    total_actions = len(actions)
    return {
        "event_count": total_actions,
        "distinct_actions": len(action_counts),
        "action_mix": {a: round(c / total_actions, 4) for a, c in action_counts.items()},
        "action_counts": dict(action_counts),
        "known_actions": sorted(action_counts.keys()),
        "normal_hours": normal_hours,
        "hour_distribution": {str(h): c for h, c in sorted(hour_counts.items())},
        "off_hours_rate": round(off_hours_rate, 4),
        "high_risk_fraction": round(high_risk_fraction, 4),
        "days_observed": len(by_day),
        "daily_volume_mean": round(_mean(daily_volumes), 2),
        "daily_volume_std": round(_stddev(daily_volumes), 2),
        "daily_risk_mean": round(_mean(daily_risks), 2),
        "daily_risk_std": round(_stddev(daily_risks), 2),
    }


async def _fetch_activities(
    window_days: int,
    employee_id: Optional[str] = None,
    role: Optional[str] = None,
) -> List[dict]:
    """Fetch the activity window for an employee or for a whole role."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
    query: Dict[str, Any] = {"timestamp": {"$gte": cutoff}}

    if employee_id:
        query["employee_id"] = employee_id
    elif role:
        emp_cursor = db_instance.db["employees"].find({"role": role}, {"employee_id": 1})
        emp_ids = [e["employee_id"] for e in await emp_cursor.to_list(length=1000)]
        if not emp_ids:
            return []
        query["employee_id"] = {"$in": emp_ids}

    cursor = db_instance.db["activities"].find(query).sort("timestamp", -1).limit(20000)
    return await cursor.to_list(length=20000)


# ═══════════════════════════════════════════════════════════════════════════
# PERSISTENCE  (with the lock)
# ═══════════════════════════════════════════════════════════════════════════

def _key(scope: str, identifier: str) -> str:
    return f"{scope}:{identifier}"


async def get_baseline(scope: str, identifier: str) -> Optional[Dict[str, Any]]:
    """Load a stored baseline, or None."""
    doc = await db_instance.db[COLLECTION].find_one({"key": _key(scope, identifier)})
    if doc:
        doc.pop("_id", None)
    return doc


async def build_baseline(
    scope: str,
    identifier: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Compute and store a normal-environment baseline.

    Guard 3 (the lock): a locked baseline is never silently overwritten. An
    operator locks a baseline they have confirmed is clean; automatic
    recomputation must not be able to replace it with a poisoned one. `force`
    bypasses the lock and is only reachable through the privileged
    baseline:manage permission.
    """
    existing = await get_baseline(scope, identifier)
    if existing and existing.get("locked") and not force:
        return {
            "status": "locked",
            "message": (
                f"Baseline {_key(scope, identifier)} is locked and was not "
                "recomputed. A locked baseline has been confirmed clean by an "
                "operator; unlocking requires the baseline:manage permission."
            ),
            "baseline": existing,
        }

    if scope == "employee":
        activities = await _fetch_activities(window_days, employee_id=identifier)
        min_events = MIN_EVENTS_FOR_BASELINE
    elif scope == "role":
        activities = await _fetch_activities(window_days, role=identifier)
        min_events = MIN_EVENTS_FOR_ROLE_BASELINE
    else:
        raise ValueError(f"Unknown baseline scope: {scope!r}")

    try:
        profile = _profile_from_activities(activities, min_events)
    except BaselineRefused as refusal:
        return {
            "status": "refused",
            "guard": refusal.guard,
            "message": refusal.message,
            "baseline": None,
        }

    doc = {
        "key": _key(scope, identifier),
        "scope": scope,
        "identifier": identifier,
        "window_days": window_days,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "locked": bool(existing.get("locked")) if existing else False,
        "locked_by": existing.get("locked_by") if existing else None,
        **profile,
    }

    await db_instance.db[COLLECTION].update_one(
        {"key": doc["key"]}, {"$set": doc}, upsert=True
    )
    return {"status": "built", "baseline": doc}


async def set_lock(
    scope: str, identifier: str, locked: bool, actor: str
) -> Dict[str, Any]:
    """Lock or unlock a baseline. Privileged (baseline:manage)."""
    existing = await get_baseline(scope, identifier)
    if not existing:
        raise BaselineRefused(
            "not_found",
            f"No baseline exists for {_key(scope, identifier)}; build it first.",
        )

    await db_instance.db[COLLECTION].update_one(
        {"key": _key(scope, identifier)},
        {"$set": {
            "locked": locked,
            "locked_by": actor if locked else None,
            "lock_changed_at": datetime.now(timezone.utc).isoformat(),
        }},
    )
    return {
        "status": "success",
        "key": _key(scope, identifier),
        "locked": locked,
        "actor": actor,
    }


async def list_baselines() -> List[Dict[str, Any]]:
    """All stored baselines, newest first."""
    cursor = db_instance.db[COLLECTION].find({}).sort("computed_at", -1).limit(500)
    docs = await cursor.to_list(length=500)
    for d in docs:
        d.pop("_id", None)
    return docs


async def rebuild_all(window_days: int = DEFAULT_WINDOW_DAYS) -> Dict[str, Any]:
    """
    Recompute baselines for every employee and role.

    Locked baselines are skipped, refusals are reported per key rather than
    aborting the sweep, and the summary distinguishes the three outcomes so a
    caller cannot mistake "refused" for "built".
    """
    emp_cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
    employees = await emp_cursor.to_list(length=1000)

    built, refused, locked = [], [], []

    for emp in employees:
        result = await build_baseline("employee", emp["employee_id"], window_days)
        if result["status"] == "built":
            built.append(emp["employee_id"])
        elif result["status"] == "locked":
            locked.append(emp["employee_id"])
        else:
            refused.append({
                "identifier": emp["employee_id"],
                "guard": result.get("guard"),
            })

    for role in sorted({e.get("role", "Unknown") for e in employees}):
        result = await build_baseline("role", role, window_days)
        if result["status"] == "built":
            built.append(f"role:{role}")
        elif result["status"] == "locked":
            locked.append(f"role:{role}")
        else:
            refused.append({"identifier": f"role:{role}", "guard": result.get("guard")})

    return {
        "status": "success",
        "window_days": window_days,
        "built": built,
        "built_count": len(built),
        "skipped_locked": locked,
        "refused": refused,
        "refused_count": len(refused),
        "note": (
            "Refused entries have no baseline and fall back to static action "
            "weights. This is not the same as a clean baseline."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# DEVIATION EVALUATION  (what the enforcement path calls)
# ═══════════════════════════════════════════════════════════════════════════

async def evaluate_deviation(
    employee_id: str,
    action: str,
    timestamp: Optional[datetime] = None,
    recent_activities: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """
    Score one action against the employee's normal environment.

    Returns a structured verdict with the base (static) risk, a deviation
    premium, the combined contextual risk, and human-readable reasons. Reasons
    matter as much as the number: the enforcement path puts them in the alert
    and the Simulator shows them to the person being blocked.

    Falls back to the role baseline when the employee has none, and to static
    weights when neither exists. `baseline_scope: "none"` in the result tells
    the caller that no deviation judgement was possible.
    """
    ts = timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    base_risk = _risk_of(action)

    baseline = await get_baseline("employee", employee_id)
    scope = "employee"
    if not baseline:
        emp = await db_instance.db["employees"].find_one({"employee_id": employee_id})
        role = emp.get("role") if emp else None
        baseline = await get_baseline("role", role) if role else None
        scope = "role" if baseline else "none"

    if not baseline:
        return {
            "employee_id": employee_id,
            "action": action,
            "baseline_scope": "none",
            "base_risk": base_risk,
            "deviation_premium": 0,
            "contextual_risk": base_risk,
            "deviation_score": 0,
            "reasons": [],
            "is_deviation": False,
            "message": (
                "No behavioural baseline exists for this employee or their role, "
                "so no deviation judgement was made. Risk is the static action "
                "weight only."
            ),
        }

    reasons: List[Dict[str, Any]] = []
    premium = 0

    # ── Unseen or rare action ────────────────────────────────────────────
    known = set(baseline.get("known_actions", []))
    mix = baseline.get("action_mix", {})

    if action not in known:
        premium += W_UNSEEN_ACTION
        reasons.append({
            "signal": "unseen_action",
            "weight": W_UNSEEN_ACTION,
            "detail": (
                f"'{action}' has never been performed by this "
                f"{'employee' if scope == 'employee' else 'role'} in the "
                f"{baseline.get('window_days', DEFAULT_WINDOW_DAYS)}-day baseline "
                f"window ({baseline.get('event_count', 0)} events observed)."
            ),
        })
    else:
        share = mix.get(action, 0.0)
        if 0 < share < 0.02:
            premium += W_RARE_ACTION
            reasons.append({
                "signal": "rare_action",
                "weight": W_RARE_ACTION,
                "detail": (
                    f"'{action}' accounts for only {share:.1%} of normal activity "
                    "for this baseline, making this an unusual choice of action."
                ),
            })

    # ── Off-hours activity ───────────────────────────────────────────────
    normal_hours = set(baseline.get("normal_hours", []))
    baseline_off_hours_rate = baseline.get("off_hours_rate", 0.0)
    is_off_hours = ts.hour >= 22 or ts.hour < 6

    if normal_hours and ts.hour not in normal_hours:
        # Only penalise off-hours when off-hours work is not itself normal here.
        if not (is_off_hours and baseline_off_hours_rate > 0.2):
            premium += W_OFF_HOURS
            reasons.append({
                "signal": "off_hours",
                "weight": W_OFF_HOURS,
                "detail": (
                    f"Activity at {ts.hour:02d}:00 falls outside the normal working "
                    f"hours for this baseline ({_describe_hours(sorted(normal_hours))}). "
                    f"Off-hours work is {baseline_off_hours_rate:.0%} of normal here."
                ),
            })

    # ── Volume and risk-rate spikes (need today's activity) ──────────────
    if recent_activities is None:
        recent_activities = await _fetch_today(employee_id, ts)

    today_count = float(len(recent_activities))
    today_risk = float(sum(a.get("risk_score", 0) or 0 for a in recent_activities))

    vol_mean = baseline.get("daily_volume_mean", 0.0)
    vol_std = baseline.get("daily_volume_std", 0.0)
    if vol_std > 0 and today_count > vol_mean + VOLUME_SPIKE_SIGMA * vol_std:
        premium += W_VOLUME_SPIKE
        reasons.append({
            "signal": "volume_spike",
            "weight": W_VOLUME_SPIKE,
            "detail": (
                f"{int(today_count)} actions so far today against a normal daily "
                f"average of {vol_mean:.1f} (±{vol_std:.1f}), more than "
                f"{VOLUME_SPIKE_SIGMA}σ above baseline."
            ),
        })

    risk_mean = baseline.get("daily_risk_mean", 0.0)
    risk_std = baseline.get("daily_risk_std", 0.0)
    projected_risk = today_risk + base_risk
    if risk_std > 0 and projected_risk > risk_mean + RISK_RATE_SIGMA * risk_std:
        premium += W_RISK_RATE
        reasons.append({
            "signal": "risk_rate",
            "weight": W_RISK_RATE,
            "detail": (
                f"Cumulative risk today would reach {projected_risk:.0f} against a "
                f"normal daily average of {risk_mean:.1f} (±{risk_std:.1f}), more "
                f"than {RISK_RATE_SIGMA}σ above baseline."
            ),
        })

    deviation_score = min(100, premium)
    return {
        "employee_id": employee_id,
        "action": action,
        "baseline_scope": scope,
        "baseline_key": baseline.get("key"),
        "baseline_events": baseline.get("event_count", 0),
        "baseline_locked": bool(baseline.get("locked")),
        "base_risk": base_risk,
        "deviation_premium": premium,
        "contextual_risk": base_risk + premium,
        "deviation_score": deviation_score,
        "reasons": reasons,
        "is_deviation": bool(reasons),
        "today_action_count": int(today_count),
        "today_risk": int(today_risk),
        "message": (
            _summarise_reasons(reasons, action)
            if reasons
            else f"'{action}' is consistent with the established normal environment."
        ),
    }


async def _fetch_today(employee_id: str, ts: datetime) -> List[dict]:
    """This employee's activity since midnight UTC on the day of `ts`."""
    day_start = ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    cursor = db_instance.db["activities"].find({
        "employee_id": employee_id,
        "timestamp": {"$gte": day_start},
    }).limit(5000)
    return await cursor.to_list(length=5000)


def _describe_hours(hours: List[int]) -> str:
    """Render an hour list compactly, e.g. '09:00-17:00' or '09:00, 14:00'."""
    if not hours:
        return "no established hours"
    if len(hours) == 1:
        return f"{hours[0]:02d}:00"
    contiguous = all(b - a == 1 for a, b in zip(hours, hours[1:]))
    if contiguous:
        return f"{hours[0]:02d}:00-{hours[-1]:02d}:00"
    return ", ".join(f"{h:02d}:00" for h in hours[:6]) + ("..." if len(hours) > 6 else "")


def _summarise_reasons(reasons: List[Dict[str, Any]], action: str) -> str:
    signals = ", ".join(r["signal"].replace("_", " ") for r in reasons)
    return (
        f"'{action}' deviates from the established normal environment "
        f"({signals}). "
        + " ".join(r["detail"] for r in reasons)
    )


async def get_summary() -> Dict[str, Any]:
    """Coverage counts for the baseline admin panel."""
    coll = db_instance.db[COLLECTION]
    total_employees = await db_instance.db["employees"].count_documents({})
    return {
        "baselines_total": await coll.count_documents({}),
        "employee_baselines": await coll.count_documents({"scope": "employee"}),
        "role_baselines": await coll.count_documents({"scope": "role"}),
        "locked": await coll.count_documents({"locked": True}),
        "employees_total": total_employees,
        "employees_without_baseline": max(
            0, total_employees - await coll.count_documents({"scope": "employee"})
        ),
        "policy": {
            "min_events_for_baseline": MIN_EVENTS_FOR_BASELINE,
            "min_events_for_role_baseline": MIN_EVENTS_FOR_ROLE_BASELINE,
            "max_high_risk_fraction": MAX_HIGH_RISK_FRACTION,
            "default_window_days": DEFAULT_WINDOW_DAYS,
            "volume_spike_sigma": VOLUME_SPIKE_SIGMA,
            "risk_rate_sigma": RISK_RATE_SIGMA,
        },
    }
