from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from app.models.employee import Employee, EmployeeLogin
from app.database.mongodb import db_instance
from app.core.rbac import Permission
from app.core.security import Principal, require_permission
from app.services import enforcement_service, override_service, pam_service
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone, timedelta

# Default freeze duration for a manual operator block.
MANUAL_BLOCK_HOURS = 24


class BlockRequest(BaseModel):
    """Optional body for a manual block, so the reason lands in the audit log."""
    reason: str = ""
    hours: int = MANUAL_BLOCK_HOURS

router = APIRouter(prefix="/api/employees", tags=["Employees"])

# 1. ADMIN ROUTE: Create a new employee (Protected by JWT)
@router.post("/create", dependencies=[Depends(require_permission(Permission.EMPLOYEES_CREATE))])
async def create_employee(emp: Employee):
    try:
        # Check if employee already exists
        existing = await db_instance.db["employees"].find_one({"employee_id": emp.employee_id})
        if existing:
            raise HTTPException(status_code=400, detail="Employee ID already exists")
        
        # Save to database
        emp_dict = jsonable_encoder(emp)
        await db_instance.db["employees"].insert_one(emp_dict)
        
        # Auto-initialize AI Twin for the new employee
        try:
            from app.services.ai_twin_service import initialize_twin
            await initialize_twin(
                employee_id=emp.employee_id,
                employee_name=emp.name,
                role=emp.role
            )
        except Exception as twin_err:
            print(f"AI Twin init failed for {emp.employee_id}: {twin_err}")
        
        return {"status": "success", "message": f"Employee {emp.employee_id} provisioned."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 2. SIMULATOR ROUTE: Employee Login (Public)
@router.post("/login")
async def login_employee(emp: EmployeeLogin): 
    try:
        user = await db_instance.db["employees"].find_one({
            "employee_id": emp.employee_id, 
            "password": emp.password
        })
        if not user:
            raise HTTPException(status_code=401, detail="Invalid Employee ID or Password")
            
        # Check if account is blocked
        if user.get("is_blocked"):
            blocked_until = user.get("blocked_until")
            if blocked_until:
                # Ensure blocked_until is timezone-aware
                if blocked_until.tzinfo is None:
                    blocked_until = blocked_until.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) < blocked_until:
                    raise HTTPException(
                        status_code=403, 
                        detail="Account temporarily frozen due to critical security alert."
                    )
                else:
                    # Block expired, unblock automatically
                    await db_instance.db["employees"].update_one(
                        {"employee_id": emp.employee_id},
                        {"$set": {"is_blocked": False, "blocked_until": None}}
                    )
        
        return {"status": "success", "employee_id": user["employee_id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3. DIRECTORY ROUTE: Fetch all employees for the dashboard (Protected by JWT)
@router.get("/", dependencies=[Depends(require_permission(Permission.EMPLOYEES_READ))])
async def get_all_employees():
    try:
        # Fetch all employees, but exclude their passwords and MongoDB ObjectIds
        cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
        employees = await cursor.to_list(length=1000)
        return employees
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3b. SIMULATOR ROUTE: Check Employee Status (Public)
#
# This is the forced-logout channel: the Employee Simulator polls it every few
# seconds and terminates its session when `is_blocked` goes true. It now also
# returns why, so the employee sees an explanation instead of being dumped at a
# login screen with no context.
#
# Deliberately kept public and minimal - it is unauthenticated, so it exposes
# only what the account holder already knows about their own account, and never
# risk scores or other employees' data.
@router.get("/{employee_id}/status")
async def get_employee_status(employee_id: str):
    try:
        from app.services import enforcement_service

        status = await enforcement_service.get_enforcement_status(employee_id)
        if not status.get("found"):
            raise HTTPException(status_code=404, detail="Employee not found")

        return {
            "employee_id": employee_id,
            "is_blocked": status["is_blocked"],
            "blocked_until": status["blocked_until"],
            "block_source": status["block_source"],
            "block_trigger": status["block_trigger"],
            "block_reason": status["block_reason"],
            "block_severity": status["block_severity"],
            "session_revoked_at": status["session_revoked_at"],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 4. Manual operator override: freeze an account.
#    PRIVILEGED - requires employees:block AND an active PAM elevation window.
#    Automated enforcement does not come through here; the enforcement service
#    acts directly, because the system is not an operator and has no session.
@router.post("/{employee_id}/block")
async def block_employee(
    employee_id: str,
    body: BlockRequest | None = None,
    principal: Principal = Depends(require_permission(Permission.EMPLOYEES_BLOCK)),
):
    try:
        user = await db_instance.db["employees"].find_one({"employee_id": employee_id})
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")

        hours = (body.hours if body and body.hours else MANUAL_BLOCK_HOURS)
        reason = (body.reason if body else "") or "Manual operator override"
        blocked_until = datetime.now(timezone.utc) + timedelta(hours=hours)

        await db_instance.db["employees"].update_one(
            {"employee_id": employee_id},
            {"$set": {
                "is_blocked": True,
                "blocked_until": blocked_until,
                "block_source": "MANUAL",
                "block_reason": reason,
                "blocked_by": principal.subject,
                # Invalidates any live Simulator session on the next status poll.
                "session_revoked_at": datetime.now(timezone.utc).isoformat(),
            }}
        )

        await pam_service.record_privileged_use(
            subject=principal.subject,
            role=principal.role.value,
            permission=Permission.EMPLOYEES_BLOCK.value,
            target=employee_id,
            detail=f"Manual block for {hours}h. Reason: {reason}",
        )

        return {
            "status": "success",
            "message": f"Employee {employee_id} blocked for {hours} hours",
            "blocked_until": blocked_until.isoformat(),
            "reason": reason,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 5. Manual operator override: release an account.
#    PRIVILEGED - same gate as block.
@router.post("/{employee_id}/unblock")
async def unblock_employee(
    employee_id: str,
    body: BlockRequest | None = None,
    principal: Principal = Depends(require_permission(Permission.EMPLOYEES_BLOCK)),
):
    try:
        user = await db_instance.db["employees"].find_one({"employee_id": employee_id})
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")

        reason = (body.reason if body else "") or "Manual operator override"

        await db_instance.db["employees"].update_one(
            {"employee_id": employee_id},
            {"$set": {
                "is_blocked": False,
                "blocked_until": None,
                "block_source": None,
                "block_reason": None,
                "block_trigger": None,
                "block_severity": None,
                "session_revoked_at": None,
                "unblocked_by": principal.subject,
            }}
        )

        # Attach an automatic grace window.
        #
        # Clearing is_blocked alone is not enough: the risk that triggered the
        # freeze is still inside the rolling enforcement window, so the very next
        # action the employee takes re-freezes them and the unblock appears to
        # have failed. The grace window suppresses automated freezing long enough
        # for that risk to age out.
        grace = await override_service.grant_unblock_grace(
            employee_id=employee_id,
            actor=principal.subject,
            actor_role=principal.role.value,
        )

        await pam_service.record_privileged_use(
            subject=principal.subject,
            role=principal.role.value,
            permission=Permission.EMPLOYEES_BLOCK.value,
            target=employee_id,
            detail=(
                f"Manual unblock. Reason: {reason}. "
                f"Grace window: {override_service.UNBLOCK_GRACE_MINUTES}m"
                if grace else f"Manual unblock. Reason: {reason}. Grace window NOT attached."
            ),
        )

        windowed = await enforcement_service._windowed_risk(employee_id)
        return {
            "status": "success",
            "message": f"Employee {employee_id} unblocked",
            "reason": reason,
            "windowed_risk": windowed,
            "risk_window_hours": enforcement_service.RISK_WINDOW_HOURS,
            "grace_window_minutes": (
                override_service.UNBLOCK_GRACE_MINUTES if grace else None
            ),
            "grace_expires_at": grace.get("expires_at") if grace else None,
            "note": (
                f"Risk already accumulated in the rolling "
                f"{enforcement_service.RISK_WINDOW_HOURS}h window is {windowed} "
                f"(freeze threshold {enforcement_service.RISK_WINDOW_BLOCK_THRESHOLD}). "
                f"A {override_service.UNBLOCK_GRACE_MINUTES}-minute grace window was "
                "attached so this does not immediately re-freeze the account. Grant a "
                "longer override if the employee needs more time."
                if grace and windowed >= enforcement_service.RISK_WINDOW_BLOCK_THRESHOLD
                else "Account released."
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))