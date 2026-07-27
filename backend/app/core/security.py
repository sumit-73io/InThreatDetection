"""
Authentication and authorization enforcement
============================================
Token issuing/decoding, the `Principal` that represents an authenticated
caller, and the FastAPI dependency factories that enforce RBAC and PAM.

Layering:
    app.core.rbac        pure data (roles, permissions, matrix)
    app.services.pam...  elevation sessions + audit (DB only)
    app.core.security    THIS MODULE - enforcement, depends on both
    app.routers.*        declare `Depends(require_permission(...))`

`verify_admin` is retained as a backwards-compatible alias so existing routers
keep working while they are migrated.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.rbac import (
    Permission,
    Role,
    console_role_for_job_title,
    is_privileged,
    permission_strings_for_role,
)
from app.services import pam_service

# ── Token configuration ─────────────────────────────────────────────────
# Overridable by environment so a real deployment is not stuck with the
# in-repo development value. See docs/DEPLOYMENT.md - rotating this
# invalidates all issued tokens, which is the intended behaviour.
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "sentinel_ai_super_secret_hackathon_key")
ALGORITHM = "HS256"
TOKEN_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "4"))

security_scheme = HTTPBearer(auto_error=True)


# ── Principal ───────────────────────────────────────────────────────────

@dataclass
class Principal:
    """The authenticated caller behind the current request."""

    subject: str
    display_name: str
    role: Role
    permissions: Set[str] = field(default_factory=set)

    @property
    def is_super_admin(self) -> bool:
        return self.role == Role.SUPER_ADMIN

    def has(self, permission) -> bool:
        value = permission.value if isinstance(permission, Permission) else str(permission)
        return value in self.permissions

    def to_public(self) -> dict:
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "role": self.role.value,
            "permissions": sorted(self.permissions),
            "is_super_admin": self.is_super_admin,
        }


# ── Token issuing ───────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: Role,
    display_name: str = "",
    extra_claims: Optional[dict] = None,
) -> str:
    """Issue a signed JWT carrying the caller's role and resolved permissions."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "name": display_name or subject,
        # `role` stays a plain string for readability in logs and the UI.
        "role": role.value,
        "permissions": permission_strings_for_role(role),
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_TTL_HOURS),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT. Raises HTTPException on any failure so callers
    can use it directly inside a dependency.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


def decode_token_quiet(token: str) -> Optional[dict]:
    """Non-raising variant, for the request-logging middleware."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None


def _role_from_claim(raw_role: str) -> Role:
    """
    Resolve the `role` claim onto a console Role.

    Handles three shapes, in order:
      1. A console role value already ("Super Admin", "SOC Analyst", ...)
      2. The legacy lowercase "admin" claim from tokens issued before RBAC
      3. A provisioning job title ("Sys Admin", "Support Staff", ...)
    """
    if not raw_role:
        return Role.EMPLOYEE

    for role in Role:
        if role.value.lower() == raw_role.lower():
            return role

    # Legacy tokens minted by the pre-RBAC login endpoint.
    if raw_role.lower() == "admin":
        return Role.SUPER_ADMIN

    return console_role_for_job_title(raw_role)


# ── Core dependency ─────────────────────────────────────────────────────

def get_current_principal(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
) -> Principal:
    """Resolve the bearer token into a Principal."""
    payload = decode_token(credentials.credentials)

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing a subject claim",
        )

    role = _role_from_claim(payload.get("role", ""))

    # Prefer the permissions embedded in the token, but fall back to the role
    # matrix so tokens issued before RBAC existed still resolve correctly.
    claimed = payload.get("permissions")
    permissions = (
        set(claimed) if isinstance(claimed, list) and claimed
        else set(permission_strings_for_role(role))
    )

    return Principal(
        subject=subject,
        display_name=payload.get("name") or subject,
        role=role,
        permissions=permissions,
    )


# ── Authorization dependency factories ──────────────────────────────────

def require_permission(permission: Permission):
    """
    Dependency factory enforcing a single permission.

    For permissions marked privileged in `rbac.PRIVILEGED_PERMISSIONS` the
    caller must ALSO hold an active PAM elevation session. Refusals are written
    to the PAM audit log so an attempt to use a privileged action without
    elevation is itself a recorded security event.
    """
    required = permission.value

    async def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if required not in principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{principal.role.value}' does not hold the required "
                    f"permission '{required}'."
                ),
            )

        if is_privileged(permission):
            elevated = await pam_service.has_active_elevation(
                principal.subject, required
            )
            if not elevated:
                await pam_service.record_privileged_denial(
                    principal.subject, principal.role.value, required,
                    detail="No active elevation session",
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"'{required}' is a privileged action and requires an "
                        "active PAM elevation session. Request one via "
                        "POST /api/access/pam/request."
                    ),
                )

        return principal

    return dependency


def require_any_permission(*permissions: Permission):
    """Dependency factory satisfied by holding any one of several permissions.

    Only accepts non-privileged permissions - an 'any of' check would make the
    elevation requirement ambiguous, so privileged actions must be guarded
    individually with `require_permission`.
    """
    privileged = [p.value for p in permissions if is_privileged(p)]
    if privileged:
        raise ValueError(
            "require_any_permission cannot guard privileged permissions "
            f"({', '.join(privileged)}); use require_permission instead."
        )

    required = {p.value for p in permissions}

    async def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if not (required & principal.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{principal.role.value}' holds none of the required "
                    f"permissions: {', '.join(sorted(required))}."
                ),
            )
        return principal

    return dependency


def require_role(*roles: Role):
    """Dependency factory enforcing membership of specific console roles."""
    allowed = {r.value for r in roles}

    async def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if principal.role.value not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This endpoint is restricted to: {', '.join(sorted(allowed))}. "
                    f"You are '{principal.role.value}'."
                ),
            )
        return principal

    return dependency


def require_console_access():
    """
    Dependency asserting the caller has *any* console access at all.

    Plain employees authenticate against the Employee Simulator and hold no
    console permissions; this keeps them out of admin surfaces wholesale.
    """

    async def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if not principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{principal.role.value}' has no SOC console access."
                ),
            )
        return principal

    return dependency


# ── Backwards compatibility ─────────────────────────────────────────────

def verify_admin(
    principal: Principal = Depends(get_current_principal),
) -> dict:
    """
    Legacy guard, preserved so routers not yet migrated keep working.

    Previously this asserted `role == "admin"`. It now accepts any principal
    with administrative console reach (Super Admin or Security Admin), which is
    the closest equivalent under the role matrix.

    New code should depend on `require_permission(...)` instead.
    """
    if principal.role not in (Role.SUPER_ADMIN, Role.SECURITY_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized as admin",
        )
    return {
        "sub": principal.subject,
        "role": principal.role.value,
        "permissions": sorted(principal.permissions),
    }
