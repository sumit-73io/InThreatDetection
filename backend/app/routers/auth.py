"""
Authentication router
=====================
Issues RBAC-aware JWTs for the SOC console.

Two identity sources:
  1. The built-in `admin` account, which maps to SUPER_ADMIN. Retained
     deliberately as the break-glass / bootstrap operator.
  2. Employee records in MongoDB, whose provisioning job title is mapped onto a
     console role via `rbac.console_role_for_job_title`. Job titles that carry
     no console permissions (most of them) are refused here and directed to the
     Employee Simulator instead.

Known limitation, carried intentionally: employee passwords are compared in
plaintext because that is how they are stored. See the hardening checklist in
docs/DEPLOYMENT.md.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.rbac import (
    Role,
    console_role_for_job_title,
    describe_roles,
    permission_strings_for_role,
)
from app.core.security import (  # noqa: F401  (verify_admin re-exported for legacy imports)
    Principal,
    create_access_token,
    get_current_principal,
    verify_admin,
)
from app.database.mongodb import db_instance
from app.services import pam_service

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# Built-in bootstrap operator.
BUILTIN_ADMIN_USERNAME = "admin"
BUILTIN_ADMIN_PASSWORD = "admin123"


class LoginRequest(BaseModel):
    username: str
    password: str


async def _authenticate_employee(username: str, password: str):
    """
    Resolve an employee credential pair into (employee_doc, console_role).
    Returns (None, None) when the credentials do not match.
    """
    if db_instance.db is None:
        return None, None

    user = await db_instance.db["employees"].find_one({
        "employee_id": username,
        "password": password,
    })
    if not user:
        return None, None

    return user, console_role_for_job_title(user.get("role", ""))


@router.post("/login")
async def login(req: LoginRequest):
    """Authenticate into the SOC console and receive an RBAC-scoped token."""
    # ── Built-in Super Admin ────────────────────────────────────────────
    if req.username == BUILTIN_ADMIN_USERNAME and req.password == BUILTIN_ADMIN_PASSWORD:
        token = create_access_token(
            subject=req.username,
            role=Role.SUPER_ADMIN,
            display_name="Platform Super Admin",
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "role": Role.SUPER_ADMIN.value,
            "display_name": "Platform Super Admin",
            "permissions": permission_strings_for_role(Role.SUPER_ADMIN),
        }

    # ── Employee-backed console login ───────────────────────────────────
    user, console_role = await _authenticate_employee(req.username, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # A frozen account must not be able to obtain a console session.
    if user.get("is_blocked"):
        blocked_until = user.get("blocked_until")
        if isinstance(blocked_until, datetime):
            if blocked_until.tzinfo is None:
                blocked_until = blocked_until.replace(tzinfo=timezone.utc)
            still_blocked = datetime.now(timezone.utc) < blocked_until
        else:
            still_blocked = True
        if still_blocked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is frozen due to a security alert. Contact the SOC.",
            )

    if console_role == Role.EMPLOYEE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Job role '{user.get('role', 'Unknown')}' has no SOC console access. "
                "Use the Employee Simulator portal instead."
            ),
        )

    token = create_access_token(
        subject=user["employee_id"],
        role=console_role,
        display_name=user.get("name", user["employee_id"]),
        extra_claims={"job_title": user.get("role", "Unknown")},
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": console_role.value,
        "job_title": user.get("role", "Unknown"),
        "display_name": user.get("name", user["employee_id"]),
        "permissions": permission_strings_for_role(console_role),
    }


@router.get("/me")
async def whoami(principal: Principal = Depends(get_current_principal)):
    """
    Identity, effective permissions and any open PAM elevation for the caller.

    The frontend uses this to decide which navigation entries and privileged
    controls to render, so it must stay cheap enough to poll.
    """
    elevations = await pam_service.active_elevation_for(principal.subject)
    return {
        **principal.to_public(),
        "active_elevations": elevations,
        "elevated_permissions": sorted({
            perm for e in elevations for perm in e.get("permissions", [])
        }),
    }


@router.get("/roles")
async def list_roles(principal: Principal = Depends(get_current_principal)):
    """The full role/permission matrix, for the access-control admin screen."""
    return {"roles": describe_roles(), "caller_role": principal.role.value}
