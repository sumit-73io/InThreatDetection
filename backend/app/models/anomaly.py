from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum


class AnomalyType(str, Enum):
    VELOCITY_BURST = "Velocity Burst"
    ROLE_MISMATCH = "Role-Action Mismatch"
    UNUSUAL_HOUR = "Unusual Hour Activity"
    ACTION_SPIKE = "Action Frequency Spike"
    CUMULATIVE_RISK = "Cumulative Risk Threshold"
    API_TRAFFIC_SPIKE = "API Traffic Spike"


class AnomalySeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    WARNING = "Warning"


class AnomalyAlert(BaseModel):
    employee_id: str
    employee_name: str = "Unknown"
    role: str = "Unknown"
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: int = Field(ge=0, le=100, description="Confidence percentage 0-100")
    description: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "OPEN"  # OPEN | ACKNOWLEDGED | RESOLVED
