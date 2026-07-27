"""
Access Control API Router
=========================
Exposes the RBAC matrix and the PAM elevation workflow.

Elevation flow from the client's point of view:
    POST /api/access/pam/request              -> PENDING request
    POST /api/access/pam/{request_id}/approve -> window opens (approver)
    ... privileged calls now succeed ...
    POST /api/access/pam/{request_id}/revoke  -> window closes early
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.rbac import PRIVILEGED_PERMISSIONS, Permission, describe_roles
from app.core.security import Principal, get_current_principal, require_permission
from app.services import pam_service
from app.services.pam_service import PamError

router = APIRouter(prefix="/api/access", tags=["Access Control"])


# ── Request models ──────────────────────────────────────────────────────

class ElevationRequest(BaseModel):
    permissions: List[str] = Field(
        ...,
        description="Privileged permissions to elevate, e.g. ['employees:block']",
    )
    justification: str = Field(
        ...,
        description=(
            "Why this elevation is needed. Minimum "
            f"{pam_service.MIN_JUSTIFICATION_CHARS} characters."
        ),
    )
    duration_minutes: int = Field(
        pam_service.DEFAULT_ELEVATION_MINUTES,
        ge=1,
        le=pam_service.MAX_ELEVATION_MINUTES,
        description="Length of the elevation window.",
    )


class DecisionRequest(BaseModel):
    reason: str = ""


# ── RBAC introspection ──────────────────────────────────────────────────

@router.get("/roles")
async def get_role_matrix(principal: Principal = Depends(get_current_principal)):
    """The role/permission matrix plus the caller's own effective grants."""
    return {
        "roles": describe_roles(),
        "privileged_permissions": sorted(p.value for p in PRIVILEGED_PERMISSIONS),
        "caller": principal.to_public(),
    }


@router.get("/permissions")
async def get_permissions(_: Principal = Depends(get_current_principal)):
    """Every permission the system understands, flagged by privilege level."""
    return {
        "permissions": [
            {
                "permission": p.value,
                "privileged": p in PRIVILEGED_PERMISSIONS,
            }
            for p in sorted(Permission, key=lambda x: x.value)
        ]
    }


# ── PAM: request / decide ───────────────────────────────────────────────

@router.post("/pam/request", status_code=status.HTTP_201_CREATED)
async def create_elevation_request(
    body: ElevationRequest,
    principal: Principal = Depends(require_permission(Permission.PAM_REQUEST)),
):
    """
    Open an elevation request for one or more privileged permissions.

    The caller must already hold the permission through their role - elevation
    unlocks a permission you have, it never grants one you lack.
    """
    missing = [p for p in body.permissions if p not in principal.permissions]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{principal.role.value}' does not hold: "
                f"{', '.join(sorted(missing))}. Elevation cannot grant a "
                "permission your role lacks."
            ),
        )

    try:
        return await pam_service.request_elevation(
            subject=principal.subject,
            display_name=principal.display_name,
            role=principal.role.value,
            permissions=body.permissions,
            justification=body.justification,
            duration_minutes=body.duration_minutes,
        )
    except PamError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/pam/{request_id}/approve")
async def approve_elevation_request(
    request_id: str,
    principal: Principal = Depends(require_permission(Permission.PAM_APPROVE)),
):
    """
    Approve a pending request, opening its time-boxed window.

    Self-approval is refused unless the approver is Super Admin, where it is
    allowed as an audited break-glass action.
    """
    try:
        return await pam_service.approve_elevation(
            request_id=request_id,
            approver=principal.subject,
            approver_role=principal.role.value,
            approver_is_super_admin=principal.is_super_admin,
        )
    except PamError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/pam/{request_id}/deny")
async def deny_elevation_request(
    request_id: str,
    body: DecisionRequest,
    principal: Principal = Depends(require_permission(Permission.PAM_APPROVE)),
):
    """Deny a pending elevation request."""
    try:
        return await pam_service.deny_elevation(
            request_id=request_id,
            approver=principal.subject,
            approver_role=principal.role.value,
            reason=body.reason,
        )
    except PamError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/pam/{request_id}/revoke")
async def revoke_elevation_session(
    request_id: str,
    body: DecisionRequest,
    principal: Principal = Depends(get_current_principal),
):
    """
    Close an approved elevation window early.

    Permitted for the holder of the session (giving up your own elevation
    should never require approval) or for anyone holding pam:approve.
    """
    existing = await pam_service.list_requests(limit=500)
    match = next((r for r in existing if r.get("request_id") == request_id), None)
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Elevation request {request_id} not found.",
        )

    is_holder = match.get("subject") == principal.subject
    can_approve = Permission.PAM_APPROVE.value in principal.permissions
    if not (is_holder or can_approve):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the session holder or an approver can revoke this elevation.",
        )

    try:
        return await pam_service.revoke_elevation(
            request_id=request_id,
            actor=principal.subject,
            actor_role=principal.role.value,
            reason=body.reason,
        )
    except PamError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# ── PAM: queries ────────────────────────────────────────────────────────

@router.get("/pam/requests")
async def list_elevation_requests(
    principal: Principal = Depends(get_current_principal),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
):
    """
    List elevation requests.

    Approvers and auditors see everything; anyone else sees only their own, so
    the queue cannot be used to enumerate other operators' activity.
    """
    can_see_all = (
        Permission.PAM_APPROVE.value in principal.permissions
        or Permission.PAM_AUDIT_READ.value in principal.permissions
    )
    return {
        "requests": await pam_service.list_requests(
            status=status_filter,
            subject=None if can_see_all else principal.subject,
            limit=limit,
        ),
        "scope": "all" if can_see_all else "self",
    }


@router.get("/pam/active")
async def list_active_elevations(principal: Principal = Depends(get_current_principal)):
    """The caller's currently-open elevation sessions."""
    sessions = await pam_service.active_elevation_for(principal.subject)
    return {
        "active": sessions,
        "elevated_permissions": sorted({
            perm for s in sessions for perm in s.get("permissions", [])
        }),
    }


@router.get("/pam/audit")
async def read_audit_log(
    _: Principal = Depends(require_permission(Permission.PAM_AUDIT_READ)),
    limit: int = Query(200, ge=1, le=1000),
    actor: Optional[str] = None,
):
    """Read the PAM audit trail."""
    return {"entries": await pam_service.get_audit_log(limit=limit, actor=actor)}


@router.get("/pam/summary")
async def elevation_summary(_: Principal = Depends(get_current_principal)):
    """Counts and policy limits for the access-control dashboard."""
    return await pam_service.get_summary()
