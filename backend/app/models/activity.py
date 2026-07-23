from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum

class ActionType(str, Enum):
    LOGIN = "LOGIN"
    VIEW_CUSTOMER = "VIEW_CUSTOMER"
    DOWNLOAD_FILE = "DOWNLOAD_FILE"
    DOWNLOAD_CONFIDENTIAL = "DOWNLOAD_CONFIDENTIAL"
    DELETE_FILE = "DELETE_FILE"
    USB_CONNECTED = "USB_CONNECTED"
    FAILED_LOGIN = "FAILED_LOGIN"
    CHANGE_PERMISSION = "CHANGE_PERMISSION"
    LOGOUT = "LOGOUT"

class ActivityLog(BaseModel):
    employee_id: str
    action: ActionType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    device_ip: Optional[str] = "192.168.1.100" 
    details: Optional[str] = None
    risk_score: int = 0  # NEW: Defaults to 0 before processing