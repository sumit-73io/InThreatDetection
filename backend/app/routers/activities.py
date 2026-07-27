from fastapi import APIRouter, HTTPException
from app.models.activity import ActivityLog
from app.services.activity_service import log_employee_activity

router = APIRouter(prefix="/api/activities", tags=["Activities"])

@router.post("/")
async def create_activity(activity: ActivityLog):
    try:
        result = await log_employee_activity(activity)
        return result
    except Exception as e:
        print(f"Error logged in router: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))