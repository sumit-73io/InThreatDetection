"""
Privileged Access Management (PAM)
==================================
Just-in-time, time-boxed elevation for the small set of actions that can change
the security posture of the platform (freezing an account, wiping an AI Twin
baseline, rewriting the behavioural baseline, editing the role matrix).

Model
-----
Holding a privileged permission via your role is necessary but not sufficient.
To actually use one you must additionally hold an *approved, unexpired
elevation session* covering that permission:

    request  ->  approve  ->  (window open)  ->  expire | revoke

Super Admin may self-approve ("break glass") so a lone operator is never locked
out of an incident response, but the session is still created, still time-boxed
and still written to the audit log with the break-glass flag set — which is the
whole point.

Every state transition and every actual use of a privileged permission is
appended to `pam_audit_log`.

This module intentionally imports neither FastAPI nor app.core.security, so the
enforcement layer can depend on it without a cycle.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.rbac import PRIVILEGED_PERMISSIONS, Permission, Role
from app.database.mongodb import db_instance

COLLECTION_REQUESTS = "pam_elevation_requests"
COLLECTION_AUDIT    = "pam_audit_log"

# ── Policy ──────────────────────────────────────────────────────────────
MAX_ELEVATION_MINUTES     = 60   # hard ceiling on a single elevation window
DEFAULT_ELEVATION_MINUTES = 15
MIN_JUSTIFICATION_CHARS   = 15   # forces a real reason, not "test"

# Request lifecycle states
STATUS_PENDING  = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_DENIED   = "DENIED"
STATUS_REVOKED  = "REVOKED"
STATUS_EXPIRED  = "EXPIRED"

# Audit event types
EVENT_REQUESTED   = "REQUESTED"
EVENT_APPROVED    = "APPROVED"
EVENT_BREAK_GLASS = "BREAK_GLASS_APPROVED"
EVENT_DENIED      = "DENIED"
EVENT_REVOKED     = "REVOKED"
EVENT_EXPIRED     = "EXPIRED"
EVENT_USED        = "PRIVILEGE_USED"
EVENT_BLOCKED     = "PRIVILEGE_DENIED_NO_ELEVATION"


class PamError(Exception):
    """Raised for policy violations. Routers translate these to HTTP 400/403."""


# ── Helpers ─────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse(value: Any) -> Optional[datetime]:
    """Parse a stored timestamp back into an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _normalise_permissions(permissions: List[str]) -> List[str]:
    """
    Validate the requested permissions and keep only privileged ones.

    Requesting elevation for a non-privileged permission is meaningless, so we
    reject rather than silently granting a no-op session that looks like it
    conferred something.
    """
    if not permissions:
        raise PamError("At least one permission must be requested.")

    valid = {p.value for p in Permission}
    privileged = {p.value for p in PRIVILEGED_PERMISSIONS}

    unknown = [p for p in permissions if p not in valid]
    if unknown:
        raise PamError(f"Unknown permission(s): {', '.join(sorted(unknown))}")

    non_privileged = [p for p in permissions if p not in privileged]
    if non_privileged:
        raise PamError(
            "These permissions do not require elevation: "
            f"{', '.join(sorted(non_privileged))}"
        )

    return sorted(set(permissions))


async def _audit(
    event: str,
    actor: str,
    actor_role: str,
    permissions: Optional[List[str]] = None,
    request_id: Optional[str] = None,
    target: Optional[str] = None,
    detail: Optional[str] = None,
    break_glass: bool = False,
) -> None:
    """Append an entry to the immutable-by-convention PAM audit log."""
    try:
        await db_instance.db[COLLECTION_AUDIT].insert_one({
            "timestamp": _iso(_now()),
            "event": event,
            "actor": actor,
            "actor_role": actor_role,
            "permissions": permissions or [],
            "request_id": request_id,
            "target": target,
            "detail": detail,
            "break_glass": break_glass,
        })
    except Exception as exc:  # pragma: no cover - logging must never break flow
        print(f"PAM audit write failed ({event} by {actor}): {exc}")


def _public(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Strip Mongo internals from a request document."""
    doc = dict(doc)
    doc.pop("_id", None)
    return doc


# ── Lifecycle ───────────────────────────────────────────────────────────

async def request_elevation(
    subject: str,
    display_name: str,
    role: str,
    permissions: List[str],
    justification: str,
    duration_minutes: int = DEFAULT_ELEVATION_MINUTES,
) -> Dict[str, Any]:
    """Open a PENDING elevation request. Does not grant anything by itself."""
    perms = _normalise_permissions(permissions)

    justification = (justification or "").strip()
    if len(justification) < MIN_JUSTIFICATION_CHARS:
        raise PamError(
            f"Justification must be at least {MIN_JUSTIFICATION_CHARS} characters."
        )

    if duration_minutes < 1 or duration_minutes > MAX_ELEVATION_MINUTES:
        raise PamError(
            f"Duration must be between 1 and {MAX_ELEVATION_MINUTES} minutes."
        )

    request_id = uuid.uuid4().hex
    doc = {
        "request_id": request_id,
        "subject": subject,
        "display_name": display_name,
        "role": role,
        "permissions": perms,
        "justification": justification,
        "duration_minutes": duration_minutes,
        "status": STATUS_PENDING,
        "requested_at": _iso(_now()),
        "approved_by": None,
        "approved_at": None,
        "expires_at": None,
        "break_glass": False,
        "closed_by": None,
        "closed_at": None,
        "close_reason": None,
    }
    await db_instance.db[COLLECTION_REQUESTS].insert_one(dict(doc))
    await _audit(
        EVENT_REQUESTED, subject, role,
        permissions=perms, request_id=request_id, detail=justification,
    )
    return doc


async def approve_elevation(
    request_id: str,
    approver: str,
    approver_role: str,
    approver_is_super_admin: bool = False,
) -> Dict[str, Any]:
    """
    Approve a pending request, opening the time-boxed window.

    Self-approval is refused unless the approver is Super Admin, in which case
    it is permitted as an explicit break-glass and flagged as such.
    """
    doc = await db_instance.db[COLLECTION_REQUESTS].find_one({"request_id": request_id})
    if not doc:
        raise PamError(f"Elevation request {request_id} not found.")
    if doc["status"] != STATUS_PENDING:
        raise PamError(
            f"Request is {doc['status']}, only PENDING requests can be approved."
        )

    is_self = doc["subject"] == approver
    if is_self and not approver_is_super_admin:
        raise PamError(
            "Self-approval is not permitted. A different approver holding "
            "pam:approve must authorise this elevation."
        )

    approved_at = _now()
    expires_at = approved_at + timedelta(minutes=doc["duration_minutes"])

    await db_instance.db[COLLECTION_REQUESTS].update_one(
        {"request_id": request_id},
        {"$set": {
            "status": STATUS_APPROVED,
            "approved_by": approver,
            "approved_at": _iso(approved_at),
            "expires_at": _iso(expires_at),
            "break_glass": is_self,
        }},
    )

    await _audit(
        EVENT_BREAK_GLASS if is_self else EVENT_APPROVED,
        approver, approver_role,
        permissions=doc["permissions"],
        request_id=request_id,
        target=doc["subject"],
        detail=(
            f"Elevation window {doc['duration_minutes']}m, "
            f"expires {_iso(expires_at)}"
        ),
        break_glass=is_self,
    )

    doc.update({
        "status": STATUS_APPROVED,
        "approved_by": approver,
        "approved_at": _iso(approved_at),
        "expires_at": _iso(expires_at),
        "break_glass": is_self,
    })
    return _public(doc)


async def deny_elevation(
    request_id: str, approver: str, approver_role: str, reason: str = ""
) -> Dict[str, Any]:
    """Deny a pending request."""
    doc = await db_instance.db[COLLECTION_REQUESTS].find_one({"request_id": request_id})
    if not doc:
        raise PamError(f"Elevation request {request_id} not found.")
    if doc["status"] != STATUS_PENDING:
        raise PamError(f"Request is {doc['status']}, only PENDING requests can be denied.")

    await db_instance.db[COLLECTION_REQUESTS].update_one(
        {"request_id": request_id},
        {"$set": {
            "status": STATUS_DENIED,
            "closed_by": approver,
            "closed_at": _iso(_now()),
            "close_reason": reason or "No reason given",
        }},
    )
    await _audit(
        EVENT_DENIED, approver, approver_role,
        permissions=doc["permissions"], request_id=request_id,
        target=doc["subject"], detail=reason,
    )
    return {"request_id": request_id, "status": STATUS_DENIED}


async def revoke_elevation(
    request_id: str, actor: str, actor_role: str, reason: str = ""
) -> Dict[str, Any]:
    """Close an approved window early."""
    doc = await db_instance.db[COLLECTION_REQUESTS].find_one({"request_id": request_id})
    if not doc:
        raise PamError(f"Elevation request {request_id} not found.")
    if doc["status"] != STATUS_APPROVED:
        raise PamError(f"Request is {doc['status']}, only APPROVED sessions can be revoked.")

    await db_instance.db[COLLECTION_REQUESTS].update_one(
        {"request_id": request_id},
        {"$set": {
            "status": STATUS_REVOKED,
            "closed_by": actor,
            "closed_at": _iso(_now()),
            "close_reason": reason or "Revoked by operator",
        }},
    )
    await _audit(
        EVENT_REVOKED, actor, actor_role,
        permissions=doc["permissions"], request_id=request_id,
        target=doc["subject"], detail=reason,
    )
    return {"request_id": request_id, "status": STATUS_REVOKED}


# ── Enforcement surface ─────────────────────────────────────────────────

async def expire_stale_sessions() -> int:
    """
    Flip APPROVED sessions whose window has closed to EXPIRED.

    `has_active_elevation` already treats a past `expires_at` as inactive, so
    this is bookkeeping for the UI and audit trail rather than a security
    control. Safe to call opportunistically.
    """
    now_iso = _iso(_now())
    cursor = db_instance.db[COLLECTION_REQUESTS].find({
        "status": STATUS_APPROVED,
        "expires_at": {"$lt": now_iso},
    })
    stale = await cursor.to_list(length=500)
    for doc in stale:
        await db_instance.db[COLLECTION_REQUESTS].update_one(
            {"request_id": doc["request_id"]},
            {"$set": {
                "status": STATUS_EXPIRED,
                "closed_at": now_iso,
                "close_reason": "Elevation window elapsed",
            }},
        )
        await _audit(
            EVENT_EXPIRED, doc["subject"], doc.get("role", "unknown"),
            permissions=doc.get("permissions", []),
            request_id=doc["request_id"],
        )
    return len(stale)


async def has_active_elevation(subject: str, permission: str) -> bool:
    """
    True if `subject` currently holds an approved, unexpired elevation session
    covering `permission`.

    The expiry comparison is done in Python on a parsed datetime rather than
    relying on string ordering in the query, so a document written with a
    different timestamp format can't accidentally look valid.
    """
    cursor = db_instance.db[COLLECTION_REQUESTS].find({
        "subject": subject,
        "status": STATUS_APPROVED,
        "permissions": permission,
    })
    candidates = await cursor.to_list(length=50)

    now = _now()
    for doc in candidates:
        expires_at = _parse(doc.get("expires_at"))
        if expires_at and expires_at > now:
            return True
    return False


async def active_elevation_for(subject: str) -> List[Dict[str, Any]]:
    """All currently-open elevation sessions for a subject, for the UI banner."""
    cursor = db_instance.db[COLLECTION_REQUESTS].find({
        "subject": subject,
        "status": STATUS_APPROVED,
    })
    docs = await cursor.to_list(length=50)

    now = _now()
    out = []
    for doc in docs:
        expires_at = _parse(doc.get("expires_at"))
        if not expires_at or expires_at <= now:
            continue
        entry = _public(doc)
        entry["seconds_remaining"] = int((expires_at - now).total_seconds())
        out.append(entry)
    return out


async def record_privileged_use(
    subject: str,
    role: str,
    permission: str,
    target: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Log an actual exercise of a privileged permission."""
    await _audit(
        EVENT_USED, subject, role,
        permissions=[permission], target=target, detail=detail,
    )


async def record_privileged_denial(
    subject: str, role: str, permission: str, detail: Optional[str] = None
) -> None:
    """Log a privileged call rejected for want of an elevation session."""
    await _audit(
        EVENT_BLOCKED, subject, role, permissions=[permission], detail=detail,
    )


# ── Queries ─────────────────────────────────────────────────────────────

async def list_requests(
    status: Optional[str] = None,
    subject: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List elevation requests, newest first."""
    await expire_stale_sessions()

    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    if subject:
        query["subject"] = subject

    cursor = db_instance.db[COLLECTION_REQUESTS].find(query) \
        .sort("requested_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)

    now = _now()
    out = []
    for doc in docs:
        entry = _public(doc)
        expires_at = _parse(doc.get("expires_at"))
        entry["seconds_remaining"] = (
            max(0, int((expires_at - now).total_seconds()))
            if expires_at and doc.get("status") == STATUS_APPROVED else 0
        )
        out.append(entry)
    return out


async def get_audit_log(limit: int = 200, actor: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read the PAM audit trail, newest first."""
    query = {"actor": actor} if actor else {}
    cursor = db_instance.db[COLLECTION_AUDIT].find(query) \
        .sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs


async def get_summary() -> Dict[str, Any]:
    """Counts for the access-control dashboard."""
    await expire_stale_sessions()
    coll = db_instance.db[COLLECTION_REQUESTS]
    return {
        "pending":  await coll.count_documents({"status": STATUS_PENDING}),
        "active":   await coll.count_documents({"status": STATUS_APPROVED}),
        "expired":  await coll.count_documents({"status": STATUS_EXPIRED}),
        "revoked":  await coll.count_documents({"status": STATUS_REVOKED}),
        "denied":   await coll.count_documents({"status": STATUS_DENIED}),
        "audit_entries": await db_instance.db[COLLECTION_AUDIT].count_documents({}),
        "max_elevation_minutes": MAX_ELEVATION_MINUTES,
        "privileged_permissions": sorted(p.value for p in PRIVILEGED_PERMISSIONS),
    }
