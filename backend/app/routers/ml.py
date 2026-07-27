"""
Unsupervised ML API Router
==========================
Exposes the guarded IsolationForest + DBSCAN detector.

Important contract for clients: a 200 response with
`status: "abstained"` and an empty `findings` list does NOT mean "no
anomalies". It means a false-learning guard refused to fit, so the detector has
no opinion. The UI must render that differently from a clean result — see the
`guard` and `message` fields.
"""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.rbac import Permission
from app.core.security import Principal, require_permission
from app.services import ml_unsupervised

router = APIRouter(prefix="/api/ml", tags=["Unsupervised ML"])


@router.get("/config", dependencies=[Depends(require_permission(Permission.ML_READ))])
async def get_config():
    """The active caps and thresholds governing the detector."""
    return ml_unsupervised.get_configuration()


@router.get("/status", dependencies=[Depends(require_permission(Permission.ML_READ))])
async def get_status():
    """Most recent fit, its age, and whether it is stale."""
    return ml_unsupervised.get_last_run_status()


@router.post("/detect", dependencies=[Depends(require_permission(Permission.ML_FIT))])
async def run_detection(
    hours: int = Query(168, ge=1, le=2160, description="Lookback window in hours"),
):
    """
    Fit the models over the lookback window and return findings.

    Returns `status: "fitted"` with findings, or `status: "abstained"` with the
    guard that refused and why.
    """
    try:
        return await ml_unsupervised.run_detection(hours=hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.get("/features", dependencies=[Depends(require_permission(Permission.ML_READ))])
async def get_feature_matrix(
    hours: int = Query(168, ge=1, le=2160),
    _: Principal = Depends(require_permission(Permission.ML_READ)),
):
    """
    The extracted per-employee feature vectors, for inspecting what the model
    actually sees. Useful when a finding looks wrong and you need to know
    whether the features or the model are at fault.
    """
    employee_ids, matrix, context = await ml_unsupervised.build_dataset(hours=hours)
    return {
        "window_hours": hours,
        "sample_count": len(employee_ids),
        "min_samples_to_fit": ml_unsupervised.MIN_SAMPLES_TO_FIT,
        "sufficient_for_fit": len(employee_ids) >= ml_unsupervised.MIN_SAMPLES_TO_FIT,
        "feature_names": ml_unsupervised.FEATURE_NAMES,
        "employees": [
            {
                "employee_id": emp_id,
                "employee_name": context[emp_id]["name"],
                "role": context[emp_id]["role"],
                "features": context[emp_id]["features"],
            }
            for emp_id in employee_ids
        ],
    }
