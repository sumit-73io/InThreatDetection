"""
Role-Based Access Control model
================================
Pure data layer for the access-control system: roles, permissions, the
role-to-permission matrix, and the mapping from the job titles used when
provisioning employees onto console roles.

Deliberately free of FastAPI and database imports so it can be imported from
anywhere (routers, services, scripts) without creating cycles. The enforcement
dependencies live in `app.core.security`.
"""

from enum import Enum
from typing import Dict, FrozenSet, Set


class Role(str, Enum):
    """Console roles, ordered from most to least privileged."""

    SUPER_ADMIN    = "Super Admin"
    SECURITY_ADMIN = "Security Admin"
    SOC_ANALYST    = "SOC Analyst"
    AUDITOR        = "Auditor"
    EMPLOYEE       = "Employee"


class Permission(str, Enum):
    """
    Fine-grained capabilities. Format is `resource:action` so the set is
    readable in a JWT payload and in the PAM audit log.
    """

    # Monitoring / read paths
    DASHBOARD_READ   = "dashboard:read"
    ACTIVITIES_READ  = "activities:read"
    EMPLOYEES_READ   = "employees:read"
    ANOMALY_READ     = "anomaly:read"
    AITWIN_READ      = "aitwin:read"
    QUANTUM_READ     = "quantum:read"
    ML_READ          = "ml:read"
    BASELINE_READ    = "baseline:read"

    # Operational actions
    ANOMALY_SCAN     = "anomaly:scan"
    ML_FIT           = "ml:fit"
    AITWIN_TRAIN     = "aitwin:train"
    EMPLOYEES_CREATE = "employees:create"

    # Privileged actions (see PRIVILEGED_PERMISSIONS below)
    EMPLOYEES_BLOCK  = "employees:block"
    AITWIN_RESET     = "aitwin:reset"
    BASELINE_MANAGE  = "baseline:manage"
    RBAC_MANAGE      = "rbac:manage"
    OVERRIDES_MANAGE = "overrides:manage"

    # Read-only view of granted overrides
    OVERRIDES_READ   = "overrides:read"

    # PAM itself
    PAM_REQUEST      = "pam:request"
    PAM_APPROVE      = "pam:approve"
    PAM_AUDIT_READ   = "pam:audit:read"


# ── Permission bundles ──────────────────────────────────────────────────

_READ_ONLY: Set[Permission] = {
    Permission.DASHBOARD_READ,
    Permission.ACTIVITIES_READ,
    Permission.EMPLOYEES_READ,
    Permission.ANOMALY_READ,
    Permission.AITWIN_READ,
    Permission.QUANTUM_READ,
    Permission.ML_READ,
    Permission.BASELINE_READ,
    Permission.OVERRIDES_READ,
}

_ANALYST: Set[Permission] = _READ_ONLY | {
    Permission.ANOMALY_SCAN,
    Permission.ML_FIT,
    Permission.AITWIN_TRAIN,
    Permission.PAM_REQUEST,
}

_SECURITY_ADMIN: Set[Permission] = _ANALYST | {
    Permission.EMPLOYEES_CREATE,
    Permission.EMPLOYEES_BLOCK,
    Permission.AITWIN_RESET,
    Permission.BASELINE_MANAGE,
    Permission.OVERRIDES_MANAGE,
    Permission.PAM_AUDIT_READ,
}

# Super Admin holds everything, including PAM approval and RBAC management.
_SUPER_ADMIN: Set[Permission] = set(Permission)


# ── Role → permission matrix ────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.SUPER_ADMIN:    frozenset(_SUPER_ADMIN),
    Role.SECURITY_ADMIN: frozenset(_SECURITY_ADMIN),
    Role.SOC_ANALYST:    frozenset(_ANALYST),
    Role.AUDITOR:        frozenset(_READ_ONLY | {Permission.PAM_AUDIT_READ}),
    # A plain employee has no console access at all. They authenticate against
    # the Employee Simulator, not the SOC console.
    Role.EMPLOYEE:       frozenset(),
}


# ── Privileged permissions (require an active PAM elevation) ────────────
# Holding the permission is necessary but NOT sufficient for these: the caller
# must also have an approved, unexpired elevation session. Super Admin is not
# exempt — it can self-approve (break-glass), but the session is still created
# and audited.
PRIVILEGED_PERMISSIONS: FrozenSet[Permission] = frozenset({
    Permission.EMPLOYEES_BLOCK,
    Permission.AITWIN_RESET,
    Permission.BASELINE_MANAGE,
    Permission.RBAC_MANAGE,
    Permission.OVERRIDES_MANAGE,
})


# ── Job title → console role ────────────────────────────────────────────
# The `role` field on an employee document is a job title chosen at
# provisioning time (see the Provision Employee form). Most job titles are
# monitored subjects with no console access; a few map onto console roles.
JOB_ROLE_TO_CONSOLE_ROLE: Dict[str, Role] = {
    "Admin":          Role.SECURITY_ADMIN,
    "Sys Admin":      Role.SECURITY_ADMIN,
    "Ops Analyst":    Role.SOC_ANALYST,
    "DB Admin":       Role.AUDITOR,
    "Branch Manager": Role.AUDITOR,
    "HR":             Role.EMPLOYEE,
    "Dev":            Role.EMPLOYEE,
    "Design":         Role.EMPLOYEE,
    "Support Staff":  Role.EMPLOYEE,
    "User":           Role.EMPLOYEE,
}

DEFAULT_CONSOLE_ROLE = Role.EMPLOYEE


def console_role_for_job_title(job_title: str) -> Role:
    """Map a provisioning job title onto a console role, defaulting to EMPLOYEE."""
    if not job_title:
        return DEFAULT_CONSOLE_ROLE
    return JOB_ROLE_TO_CONSOLE_ROLE.get(job_title.strip(), DEFAULT_CONSOLE_ROLE)


def permissions_for_role(role: Role) -> FrozenSet[Permission]:
    """Return the permission set granted by a console role."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def permission_strings_for_role(role: Role) -> list:
    """Permissions as plain strings, for embedding in a JWT payload."""
    return sorted(p.value for p in permissions_for_role(role))


def is_privileged(permission: Permission) -> bool:
    """True if the permission additionally requires a PAM elevation session."""
    return permission in PRIVILEGED_PERMISSIONS


def describe_roles() -> list:
    """
    Machine-readable description of the whole matrix, for the
    /api/access/roles endpoint and the admin UI.
    """
    return [
        {
            "role": role.value,
            "permissions": sorted(p.value for p in perms),
            "privileged_permissions": sorted(
                p.value for p in perms if p in PRIVILEGED_PERMISSIONS
            ),
            "console_access": len(perms) > 0,
        }
        for role, perms in ROLE_PERMISSIONS.items()
    ]
