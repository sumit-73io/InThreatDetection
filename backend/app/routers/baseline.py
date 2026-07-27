"""
Baseline & Enforcement API Router
=================================
Manage the normal-environment baselines that make deviation measurable, and
inspect the automated enforcement policy and its recent actions.

Note on `status` in build responses. Three distinct outcomes, which clients
must not conflate:
  "built"    a baseline was computed and stored
  "locked"   an operator-confirmed baseline was left untouched
  "refused"  a guard rejected the window; NO baseline exists and risk falls
             back to static action weights
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from pydantic import BaseModel, Field

from app.core.rbac import Permission
from app.core.security import Principal, require_permission
from app.services import baseline_service, enforcement_service, pam_service
from app.services.baseline_service import BaselineRefused

router = APIRouter(prefix="/api/baseline", tags=["Baseline & Enforcement"])


class BuildRequest(BaseModel):
    scope: str = Field("employee", description="'employee' or 'role'")
    identifier: str = Field(..., description="employee_id, or role name")
    window_days: int = Field(baseline_service.DEFAULT_WINDOW_DAYS, ge=1, le=365)


class LockRequest(BaseModel):
    scope: str = "employee"
    identifier: str
    locked: bool = True


# ── Read ────────────────────────────────────────────────────────────────

@router.get("/summary", dependencies=[Depends(require_permission(Permission.BASELINE_READ))])
async def summary():
    """Baseline coverage and the active policy thresholds."""
    return await baseline_service.get_summary()


@router.get("/", dependencies=[Depends(require_permission(Permission.BASELINE_READ))])
async def list_all():
    """Every stored baseline."""
    return {"baselines": await baseline_service.list_baselines()}


# NOTE ON ROUTE ORDER: this must be declared BEFORE "/{scope}/{identifier}".
# FastAPI matches in declaration order, so with the catch-all first a request to
# /baseline/evaluate/EMP-1 binds scope="evaluate" and never reaches this handler.
@router.get("/evaluate/{employee_id}", dependencies=[Depends(require_permission(Permission.BASELINE_READ))])
async def evaluate(
    employee_id: str,
    action: str = Query(..., description="Action to test against the baseline"),
):
    """
    Dry-run a deviation evaluation without logging an activity or enforcing.

    This is the read-only inspection path used for tuning thresholds and for
    previewing how an action would score before it is taken.
    """
    return await baseline_service.evaluate_deviation(
        employee_id=employee_id, action=action
    )



# ── Build (operational) ─────────────────────────────────────────────────

@router.post("/build", dependencies=[Depends(require_permission(Permission.ANOMALY_SCAN))])
async def build(body: BuildRequest):
    """Compute and store one baseline. Respects the lock."""
    try:
        return await baseline_service.build_baseline(
            scope=body.scope,
            identifier=body.identifier,
            window_days=body.window_days,
        )
    except ValueError as e:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/rebuild-all", dependencies=[Depends(require_permission(Permission.ANOMALY_SCAN))])
async def rebuild_all(
    window_days: int = Query(baseline_service.DEFAULT_WINDOW_DAYS, ge=1, le=365),
):
    """Recompute every employee and role baseline. Locked ones are skipped."""
    return await baseline_service.rebuild_all(window_days=window_days)


# ── Lock (privileged) ───────────────────────────────────────────────────

@router.post("/lock")
async def set_lock(
    body: LockRequest,
    principal: Principal = Depends(require_permission(Permission.BASELINE_MANAGE)),
):
    """
    Lock or unlock a baseline.

    PRIVILEGED: requires baseline:manage plus an active PAM elevation window.
    Locking is how an operator asserts "this baseline is clean" - and unlocking
    is how a poisoned one could be substituted, which is why both are gated and
    audited.
    """
    try:
        result = await baseline_service.set_lock(
            scope=body.scope,
            identifier=body.identifier,
            locked=body.locked,
            actor=principal.subject,
        )
    except BaselineRefused as e:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=e.message)

    await pam_service.record_privileged_use(
        subject=principal.subject,
        role=principal.role.value,
        permission=Permission.BASELINE_MANAGE.value,
        target=f"{body.scope}:{body.identifier}",
        detail=f"Baseline {'locked' if body.locked else 'unlocked'}",
    )
    return result


# ── Enforcement ─────────────────────────────────────────────────────────

@router.get("/enforcement/policy", dependencies=[Depends(require_permission(Permission.BASELINE_READ))])
async def enforcement_policy():
    """The thresholds that govern automated freezing."""
    return enforcement_service.get_policy()


@router.get("/enforcement/actions", dependencies=[Depends(require_permission(Permission.ANOMALY_READ))])
async def enforcement_actions(limit: int = Query(100, ge=1, le=500)):
    """Recent automated enforcement actions with their triggers and evidence."""
    return {"actions": await enforcement_service.get_recent_actions(limit=limit)}


# Catch-all: keep last so it cannot shadow the static-prefix routes above.
@router.get("/{scope}/{identifier}", dependencies=[Depends(require_permission(Permission.BASELINE_READ))])
async def get_one(scope: str, identifier: str):
    """One baseline by scope and identifier."""
    if scope not in ("employee", "role"):
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown baseline scope '{scope}'. Expected 'employee' or 'role'.",
        )

    doc = await baseline_service.get_baseline(scope, identifier)
    if not doc:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=(
                f"No baseline for {scope}:{identifier}. Build one, or accept that "
                "risk for this subject falls back to static action weights."
            ),
        )
    return doc
