"""
AI Twin Pydantic Models
=======================
Data models for the behavioural profile, enriched telemetry events,
and AI Twin deviation alerts.
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


# ── Welford Running Statistics (stored per feature inside profile) ──────
class RunningStats(BaseModel):
    """Numerically stable running mean + variance via Welford's algorithm."""
    count: int = 0
    mean: float = 0.0
    M2: float = 0.0        # Sum of squared deviations (for variance)
    min_val: float = float("inf")
    max_val: float = float("-inf")

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.M2 / self.count

    @property
    def std(self) -> float:
        import math
        return math.sqrt(self.variance)


# ── Domain-Level Behavioural Statistics ────────────────────────────────

class IdentityStats(BaseModel):
    """Login time patterns, session durations, workday habits."""
    login_hour_distribution: List[float] = Field(default_factory=lambda: [0.0] * 24)
    session_duration: RunningStats = Field(default_factory=RunningStats)
    typical_workdays: List[int] = Field(default_factory=list)  # 0=Mon..6=Sun
    ip_addresses_seen: List[str] = Field(default_factory=list)
    vpn_usage_rate: float = 0.0          # fraction of sessions using VPN
    device_fingerprints: List[str] = Field(default_factory=list)
    total_sessions: int = 0
    off_hours_session_rate: float = 0.0  # fraction of sessions outside 7AM–9PM


class KeyboardStats(BaseModel):
    """Typing dynamics — biometric-grade behavioural signal."""
    wpm: RunningStats = Field(default_factory=RunningStats)
    keystroke_latency_ms: RunningStats = Field(default_factory=RunningStats)
    dwell_time_ms: RunningStats = Field(default_factory=RunningStats)
    flight_time_ms: RunningStats = Field(default_factory=RunningStats)
    backspace_rate: RunningStats = Field(default_factory=RunningStats)  # backspaces/keystroke
    shortcut_usage_rate: RunningStats = Field(default_factory=RunningStats)
    error_rate: RunningStats = Field(default_factory=RunningStats)
    typing_rhythm_variance: RunningStats = Field(default_factory=RunningStats)


class MouseStats(BaseModel):
    """Mouse movement and click dynamics."""
    movement_speed_px_s: RunningStats = Field(default_factory=RunningStats)
    acceleration: RunningStats = Field(default_factory=RunningStats)
    click_frequency_per_min: RunningStats = Field(default_factory=RunningStats)
    double_click_interval_ms: RunningStats = Field(default_factory=RunningStats)
    scroll_speed: RunningStats = Field(default_factory=RunningStats)
    idle_ratio: RunningStats = Field(default_factory=RunningStats)  # fraction of time mouse idle
    pointer_entropy: RunningStats = Field(default_factory=RunningStats)
    pause_frequency: RunningStats = Field(default_factory=RunningStats)


class ApplicationStats(BaseModel):
    """Application usage patterns."""
    app_frequency: Dict[str, int] = Field(default_factory=dict)  # app_name → count
    top_apps: List[str] = Field(default_factory=list)            # sorted by usage
    switching_rate_per_hour: RunningStats = Field(default_factory=RunningStats)
    active_window_duration_s: RunningStats = Field(default_factory=RunningStats)
    browser_tab_count: RunningStats = Field(default_factory=RunningStats)
    clipboard_ops_per_hour: RunningStats = Field(default_factory=RunningStats)
    print_frequency_per_day: RunningStats = Field(default_factory=RunningStats)
    total_app_sessions: int = 0


class FileStats(BaseModel):
    """File system operation patterns."""
    downloads_per_session: RunningStats = Field(default_factory=RunningStats)
    uploads_per_session: RunningStats = Field(default_factory=RunningStats)
    deletes_per_session: RunningStats = Field(default_factory=RunningStats)
    renames_per_session: RunningStats = Field(default_factory=RunningStats)
    read_write_ratio: RunningStats = Field(default_factory=RunningStats)
    sensitive_file_accesses_per_day: RunningStats = Field(default_factory=RunningStats)
    usb_events_per_week: RunningStats = Field(default_factory=RunningStats)
    bulk_download_events: int = 0            # total count of bulk download events in training
    large_file_transfers_mb: RunningStats = Field(default_factory=RunningStats)
    archive_creation_rate: RunningStats = Field(default_factory=RunningStats)
    confidential_access_rate: RunningStats = Field(default_factory=RunningStats)
    folders_accessed: List[str] = Field(default_factory=list)


class NetworkStats(BaseModel):
    """Network activity patterns."""
    bandwidth_mb_per_hour: RunningStats = Field(default_factory=RunningStats)
    external_connections_per_day: RunningStats = Field(default_factory=RunningStats)
    cloud_uploads_per_day: RunningStats = Field(default_factory=RunningStats)
    vpn_connected_ratio: float = 0.0
    api_requests_per_minute: RunningStats = Field(default_factory=RunningStats)
    rdp_sessions_per_week: RunningStats = Field(default_factory=RunningStats)
    websites_per_day: RunningStats = Field(default_factory=RunningStats)


class SecurityStats(BaseModel):
    """Security-relevant behaviour."""
    failed_logins_per_week: RunningStats = Field(default_factory=RunningStats)
    mfa_compliance_rate: float = 1.0         # fraction of sessions with MFA
    privilege_events_per_week: RunningStats = Field(default_factory=RunningStats)
    password_change_frequency_days: RunningStats = Field(default_factory=RunningStats)
    admin_command_rate: RunningStats = Field(default_factory=RunningStats)
    total_failed_logins: int = 0


# ── Master Behavioural Profile ──────────────────────────────────────────

class AITwinStatus(str, Enum):
    INITIALIZING = "INITIALIZING"   # Just created, no events yet
    TRAINING = "TRAINING"            # Accumulating baseline data
    TRAINED = "TRAINED"              # Baseline established, monitoring active
    ALERT = "ALERT"                  # Currently in anomalous state
    SUSPENDED = "SUSPENDED"          # Manually paused
    QUARANTINED = "QUARANTINED"      # Training data failed the anti-poisoning
                                     # caps; baseline is not trustworthy and
                                     # must be reset from a clean window


class BehaviouralProfile(BaseModel):
    """
    The AI Twin's complete behavioural profile for one employee.
    Stored as a single document in MongoDB (ai_twin_profiles collection).
    """
    employee_id: str
    employee_name: str = "Unknown"
    role: str = "Unknown"

    # Training lifecycle
    status: AITwinStatus = AITwinStatus.INITIALIZING
    training_start: datetime = Field(default_factory=datetime.utcnow)
    training_end: Optional[datetime] = None
    is_trained: bool = False
    event_count: int = 0
    last_event_time: Optional[datetime] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    # ── Anti-poisoning bookkeeping ──────────────────────────────────────
    # How often the training caps had to intervene. A high ratio against
    # `learned_value_count` means the training window was not a clean baseline.
    learned_value_count: int = 0     # feature values offered to the baseline
    clipped_value_count: int = 0     # values learned only up to the z-boundary
    rejected_event_count: int = 0    # values discarded outright
    quarantined: bool = False        # baseline judged untrustworthy
    quarantine_reason: Optional[str] = None
    ema_steps_capped: int = 0        # post-training drift updates that hit the cap

    # Domain statistics
    identity: IdentityStats = Field(default_factory=IdentityStats)
    keyboard: KeyboardStats = Field(default_factory=KeyboardStats)
    mouse: MouseStats = Field(default_factory=MouseStats)
    application: ApplicationStats = Field(default_factory=ApplicationStats)
    file: FileStats = Field(default_factory=FileStats)
    network: NetworkStats = Field(default_factory=NetworkStats)
    security: SecurityStats = Field(default_factory=SecurityStats)

    # Embedding
    embedding_vector: List[float] = Field(default_factory=lambda: [0.0] * 64)
    embedding_updated_at: Optional[datetime] = None

    # Live threat state
    current_threat_score: float = 0.0
    threat_trend: str = "stable"    # "rising" | "falling" | "stable"
    last_alert_time: Optional[datetime] = None


# ── Enriched Behavioural Event ──────────────────────────────────────────

class BehaviouralEvent(BaseModel):
    """
    An enriched telemetry event feeding the AI Twin.
    This is a superset of ActivityLog — the extra fields are optional
    and default to None when not available (e.g. from simple simulator actions).
    """
    employee_id: str
    action: str                                          # mirrors ActionType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    device_ip: Optional[str] = None

    # Identity / Session
    is_vpn: Optional[bool] = None
    device_fingerprint: Optional[str] = None
    session_duration_s: Optional[float] = None

    # Keyboard dynamics
    wpm: Optional[float] = None
    keystroke_latency_ms: Optional[float] = None
    dwell_time_ms: Optional[float] = None
    flight_time_ms: Optional[float] = None
    backspace_rate: Optional[float] = None
    shortcut_usage_rate: Optional[float] = None
    error_rate: Optional[float] = None

    # Mouse behaviour
    mouse_speed_px_s: Optional[float] = None
    mouse_acceleration: Optional[float] = None
    click_frequency_per_min: Optional[float] = None
    double_click_interval_ms: Optional[float] = None
    scroll_speed: Optional[float] = None
    idle_ratio: Optional[float] = None
    pointer_entropy: Optional[float] = None

    # Application usage
    app_name: Optional[str] = None
    window_duration_s: Optional[float] = None
    browser_tab_count: Optional[int] = None
    clipboard_ops: Optional[int] = None
    print_count: Optional[int] = None

    # File behaviour
    download_size_mb: Optional[float] = None
    upload_size_mb: Optional[float] = None
    file_count: Optional[int] = None
    is_sensitive_file: Optional[bool] = None
    is_confidential: Optional[bool] = None
    usb_connected: Optional[bool] = None
    is_bulk_operation: Optional[bool] = None

    # Network behaviour
    bandwidth_mb: Optional[float] = None
    is_external_connection: Optional[bool] = None
    is_cloud_upload: Optional[bool] = None
    api_request_count: Optional[int] = None
    is_rdp: Optional[bool] = None

    # Security
    is_failed_login: Optional[bool] = None
    is_mfa_used: Optional[bool] = None
    is_privilege_escalation: Optional[bool] = None
    is_admin_command: Optional[bool] = None

    # Extra context
    details: Optional[str] = None
    risk_score: int = 0


# ── Deviation Detail (per-feature breakdown inside an alert) ────────────

class FeatureDeviation(BaseModel):
    """A single feature's deviation from baseline, included in AI Twin alerts."""
    feature_name: str
    domain: str
    baseline_mean: float
    baseline_std: float
    observed_value: float
    z_score: float
    severity: str   # "normal" | "elevated" | "high" | "critical"


# ── AI Twin Alert ───────────────────────────────────────────────────────

class AITwinAlert(BaseModel):
    """Alert generated when an employee's behaviour deviates from their AI Twin baseline."""
    employee_id: str
    employee_name: str = "Unknown"
    role: str = "Unknown"
    anomaly_type: str = "AI Twin Behavioural Deviation"
    threat_score: float = Field(ge=0, le=100)
    severity: str                                # "Warning" | "High" | "Critical"
    confidence: int = Field(ge=0, le=100)
    description: str
    flagged_domains: List[str] = Field(default_factory=list)
    feature_deviations: List[FeatureDeviation] = Field(default_factory=list)
    embedding_drift: float = 0.0                # cosine distance from baseline
    baseline_threat_score: float = 0.0         # normal baseline score for reference
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "OPEN"                        # OPEN | ACKNOWLEDGED | RESOLVED
    training_events_count: int = 0              # how many events the model was trained on


# ── Profile Summary (for dashboard listing) ────────────────────────────

class ProfileSummary(BaseModel):
    """Lightweight summary of a behavioural profile for dashboard overview cards."""
    employee_id: str
    employee_name: str
    role: str
    status: AITwinStatus
    is_trained: bool
    event_count: int
    training_start: datetime
    training_end: Optional[datetime]
    current_threat_score: float
    threat_trend: str
    last_updated: datetime
    days_in_training: int
    embedding_drift: float = 0.0
    is_blocked: bool = False
