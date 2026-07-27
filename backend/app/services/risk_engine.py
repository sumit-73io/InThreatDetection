"""
Risk Engine
===========
Two layers of risk scoring:

  calculate_risk_score(action)
      The original static, context-free weight. Retained unchanged because it is
      what gets persisted on the activity document and what the existing alert
      thresholds in alert_service are calibrated against.

  calculate_contextual_risk(employee_id, action, timestamp)
      Static weight PLUS a deviation premium measured against the employee's
      normal-environment baseline. This is what makes "abnormal" expressible:
      DELETE_FILE scores 40 for everyone, but DELETE_FILE at 3am by somebody who
      has never deleted a file scores considerably higher.

Falls back cleanly: with no baseline, contextual risk equals static risk, so
nothing breaks for a newly provisioned employee.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from app.models.activity import ActionType

# Sprint 2: Rule-Based Weights
RISK_WEIGHTS = {
    ActionType.LOGIN: 0,
    ActionType.VIEW_CUSTOMER: 0,
    ActionType.DOWNLOAD_FILE: 10,
    ActionType.DOWNLOAD_CONFIDENTIAL: 30,
    ActionType.USB_CONNECTED: 20,
    ActionType.FAILED_LOGIN: 15,
    ActionType.CHANGE_PERMISSION: 35,
    ActionType.DELETE_FILE: 40,
    ActionType.LOGOUT: 0
}


def calculate_risk_score(action: ActionType) -> int:
    """
    Evaluates the static risk score of a single action.

    Context-free by design: this value is stored on the activity record and the
    alert-level thresholds in alert_service are calibrated against it. For
    deviation-aware scoring use calculate_contextual_risk().
    """
    return RISK_WEIGHTS.get(action, 0)


async def calculate_contextual_risk(
    employee_id: str,
    action: Any,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Risk of an action *in context*, relative to the employee's normal environment.

    Returns the deviation verdict from baseline_service, carrying:
        base_risk           static weight
        deviation_premium   added for each way this departs from normal
        contextual_risk     base + premium
        reasons[]           structured, human-readable explanations
        is_deviation        whether anything abnormal was detected
        baseline_scope      "employee" | "role" | "none"

    `baseline_scope == "none"` means no judgement was possible, which the caller
    must not treat as "normal". Deliberately fails soft: if the baseline service
    errors, fall back to static risk rather than blocking activity logging.
    """
    action_str = action.value if hasattr(action, "value") else str(action)

    try:
        from app.services import baseline_service

        return await baseline_service.evaluate_deviation(
            employee_id=employee_id,
            action=action_str,
            timestamp=timestamp,
        )
    except Exception as exc:
        base = RISK_WEIGHTS.get(action, 0) if isinstance(action, ActionType) else 0
        return {
            "employee_id": employee_id,
            "action": action_str,
            "baseline_scope": "none",
            "base_risk": base,
            "deviation_premium": 0,
            "contextual_risk": base,
            "deviation_score": 0,
            "reasons": [],
            "is_deviation": False,
            "message": f"Baseline evaluation unavailable ({exc}); static risk used.",
        }
