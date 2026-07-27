"""
Enforcement Override API Router
===============================
Grant, inspect and revoke operator-authorised exceptions to automated
enforcement.

Two operator intents, one mechanism:

  * "Let this frozen account work again" — a block exemption, so accumulated
    risk in the rolling window stops re-freezing them.
  * "Let this employee legitimately act outside their baseline" — an action
    allow-list, so authorised deviation is recorded but not punished.

Granting is PRIVILEGED (`overrides:manage` plus an active PAM elevation),
because it deliberately weakens enforcement. Reading is not, so analysts and
auditors can always see which exceptions are live.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from pydantic import BaseModel, Field

from app.core.rbac import Permission
from app.core.security import Principal, require_permission
from app.services import override_service, pam_service
from app.services.override_service import OverrideError

router = APIRouter(prefix="/api/overrides", tags=["Enforcement Overrides"])


class GrantRequest(BaseModel):
    employee_id: str
    reason: str = Field(
        ...,
        description=(
            "Why enforcement is being weakened. Minimum "
            f"{override_service.MIN_REASON_CHARS} characters; permanently audited."
        ),
    )
    exempt_block: bool = Field(
        True,
        description="Suppress automated freezing while the override is live.",
    )
    allowed_actions: Optional[List[str]] = Field(
        None,
        description=(
            "Actions authorised to deviate from the baseline. Omit or leave empty "
            "for ALL actions; otherwise only those listed, e.g. "
            "['DOWNLOAD_CONFIDENTIAL','DELETE_FILE']."
        ),
    )
    duration_minutes: Optional[int] = Field(
        override_service.DEFAULT_DURATION_MINUTES,
        description=(
            "Time limit. Null to rely purely on the event budget. Max "
            f"{override_service.MAX_DURATION_MINUTES}."
        ),
    )
    max_events: Optional[int] = Field(
        None,
        description=(
            "Event budget — the override closes after this many authorised "
            f"events. Null for no event limit. Max {override_service.MAX_EVENTS}."
        ),
    )


class RevokeRequest(BaseModel):
    reason: str = ""


# ── Grant / revoke (privileged) ─────────────────────────────────────────

@router.post("/grant", status_code=http_status.HTTP_201_CREATED)
async def grant(
    body: GrantRequest,
    principal: Principal = Depends(require_permission(Permission.OVERRIDES_MANAGE)),
):
    """
    Grant a bounded enforcement override.

    PRIVILEGED: needs `overrides:manage` plus an active PAM elevation window.
    Must be bounded by a duration, an event budget, or both — an unbounded
    override would be a permanent gap in enforcement.

    Any existing live override for the employee is superseded, so the effective
    policy is always a single unambiguous grant.
    """
    try:
        result = await override_service.grant_override(
            employee_id=body.employee_id,
            granted_by=principal.subject,
            granted_by_role=principal.role.value,
            reason=body.reason,
            exempt_block=body.exempt_block,
            allowed_actions=body.allowed_actions,
            duration_minutes=body.duration_minutes,
            max_events=body.max_events,
            source="MANUAL",
        )
    except OverrideError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )

    await pam_service.record_privileged_use(
        subject=principal.subject,
        role=principal.role.value,
        permission=Permission.OVERRIDES_MANAGE.value,
        target=body.employee_id,
        detail=(
            f"Override granted: block_exempt={body.exempt_block}, "
            f"actions={result.get('allowed_actions')}, "
            f"duration={body.duration_minutes}m, events={body.max_events}. "
            f"Reason: {body.reason}"
        ),
    )
    return result


@router.post("/{override_id}/revoke")
async def revoke(
    override_id: str,
    body: RevokeRequest,
    principal: Principal = Depends(require_permission(Permission.OVERRIDES_MANAGE)),
):
    """Close an override early. PRIVILEGED, same gate as granting."""
    try:
        result = await override_service.revoke_override(
            override_id=override_id,
            actor=principal.subject,
            reason=body.reason,
        )
    except OverrideError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )

    await pam_service.record_privileged_use(
        subject=principal.subject,
        role=principal.role.value,
        permission=Permission.OVERRIDES_MANAGE.value,
        target=result["employee_id"],
        detail=f"Override {override_id} revoked. Reason: {body.reason or 'none given'}",
    )
    return result


# ── Read (not privileged) ───────────────────────────────────────────────

@router.get("/policy", dependencies=[Depends(require_permission(Permission.OVERRIDES_READ))])
async def policy():
    """Caps, defaults and counts."""
    return await override_service.get_policy()


@router.get("/active", dependencies=[Depends(require_permission(Permission.OVERRIDES_READ))])
async def active():
    """
    Every live override keyed by employee_id.

    One call so the dashboard can badge overridden employees without a request
    per table row.
    """
    return {"active": await override_service.get_active_map()}


@router.get("/", dependencies=[Depends(require_permission(Permission.OVERRIDES_READ))])
async def history(
    employee_id: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(200, ge=1, le=500),
):
    """Override history, newest first."""
    return {
        "overrides": await override_service.list_overrides(
            employee_id=employee_id, status=status_filter, limit=limit
        )
    }


@router.get("/employee/{employee_id}", dependencies=[Depends(require_permission(Permission.OVERRIDES_READ))])
async def for_employee(employee_id: str):
    """The employee's live override (if any) plus their override history."""
    return {
        "employee_id": employee_id,
        "active": await override_service.get_active_override(employee_id),
        "history": await override_service.list_overrides(employee_id=employee_id, limit=50),
    }
