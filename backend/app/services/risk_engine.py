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
    This functional layer acts as a placeholder for future ML integration.
    """
    return RISK_WEIGHTS.get(action, 0)