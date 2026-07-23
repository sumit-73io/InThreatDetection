from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum

class AlertLevel(str, Enum):
    NORMAL = "Normal"
    WARNING = "Warning"
    HIGH = "High"
    CRITICAL = "Critical"

class Alert(BaseModel):
    employee_id: str
    action: str
    risk_score: int
    level: AlertLevel
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "OPEN"  # For admin triaging later