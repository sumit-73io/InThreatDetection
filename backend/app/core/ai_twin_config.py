"""
AI Twin Configuration
=====================
All tunable constants for the AI Twin behavioural clone engine.
Adjust these values to tune sensitivity for your deployment context
(e.g. a commercial bank warrants tighter thresholds than a startup).
"""

# ── Training Phase ──────────────────────────────────────────────────────
TRAINING_PERIOD_DAYS: int = 14          # Minimum calendar days before twin is considered trained
MIN_TRAINING_EVENTS: int = 50           # Minimum events required to finalize training
EMA_ALPHA: float = 0.05                 # Exponential Moving Average learning rate (post-training drift adaptation)
                                        # Lower = slower adaptation (more resistant to sustained attack)

# ── Anti-Poisoning Caps (false-learning prevention) ────────────────────
# Without these the training phase accepts every value unconditionally, so an
# employee who is already compromised (or simply having an unusual fortnight)
# has that behaviour absorbed as their permanent "normal" — after which the
# twin can never flag it. These caps constrain what training is allowed to
# learn, and record when they intervene.

# Once a feature has this many samples we have enough of a partial baseline to
# judge whether the next value is plausible. Below it, everything is accepted:
# with 2 samples any "outlier" test is noise.
TRAINING_OUTLIER_MIN_SAMPLES: int = 10

# A training value further than this many standard deviations from the
# partial baseline is treated as suspect rather than as truth.
TRAINING_OUTLIER_Z_THRESHOLD: float = 4.0

# What to do with a suspect value:
#   "clip"   — learn it, but only up to the threshold boundary. Keeps the
#              sample (real drift still moves the mean) while denying an
#              extreme value the power to yank the baseline. Default.
#   "reject" — discard entirely. Stricter, but a genuine step-change in an
#              employee's role then never gets learned without a reset.
TRAINING_OUTLIER_MODE: str = "clip"

# If more than this fraction of training values had to be clipped or rejected,
# the training window itself is untrustworthy — the data is not a baseline, it
# is noise or an ongoing incident. The profile is quarantined rather than
# silently finalised into a bad baseline.
MAX_TRAINING_REJECT_RATE: float = 0.25

# Do not evaluate that rate until the profile has at least this many events,
# so an unlucky first few samples cannot quarantine a healthy profile.
TRAINING_QUARANTINE_MIN_EVENTS: int = 20

# ── Post-Training Drift Cap ─────────────────────────────────────────────
# EMA adaptation exists so a legitimate slow change in behaviour does not
# alarm forever. It is also the obvious channel for a patient attacker: move
# the baseline a little at a time until the anomalous is normal. Capping the
# per-update step in units of the feature's own standard deviation bounds how
# fast the baseline can be walked, no matter how extreme the injected values.
MAX_EMA_STEP_SIGMA: float = 0.5

# ── Embedding ───────────────────────────────────────────────────────────
EMBEDDING_DIMENSIONS: int = 64          # Total dimensions of the behavioural embedding vector
EMBEDDING_DRIFT_THRESHOLD: float = 0.35 # Cosine distance above which embedding drift is flagged

# ── Threat Scoring ──────────────────────────────────────────────────────
# Composite threat score = weighted sum of per-domain z-scores (0-100 scale)
THREAT_SCORE_LOW: int = 30              # Below this → Normal
THREAT_SCORE_MEDIUM: int = 55           # Below this → Elevated
THREAT_SCORE_HIGH: int = 75             # Below this → High Risk, above → Critical

# ── Z-Score Thresholds (per domain) ────────────────────────────────────
# Number of standard deviations from baseline before a domain is flagged.
# Bank context: tighter on file/security, looser on mouse/keyboard.
Z_THRESHOLD_IDENTITY: float = 2.5       # Login time, session duration
Z_THRESHOLD_KEYBOARD: float = 2.5       # WPM, latency, error rate
Z_THRESHOLD_MOUSE: float = 3.0          # Speed, click rate (more natural variance)
Z_THRESHOLD_APPLICATION: float = 2.0    # App usage patterns (very routine in banking)
Z_THRESHOLD_FILE: float = 2.0           # File operations (critical in banking)
Z_THRESHOLD_NETWORK: float = 2.5        # Bandwidth, external connections
Z_THRESHOLD_SECURITY: float = 1.5       # Privilege events, failed logins (zero-tolerance)

# ── Domain Weights (must sum to 1.0) ───────────────────────────────────
# Bank context: file exfiltration and identity spoofing are top risks
DOMAIN_WEIGHTS = {
    "identity":    0.20,    # Login time, session pattern, workday
    "keyboard":    0.15,    # Typing dynamics (biometric-grade signal)
    "mouse":       0.10,    # Mouse behaviour
    "application": 0.15,    # App usage (Excel/Outlook vs. PowerShell)
    "file":        0.20,    # File access, downloads, USB (highest risk for banks)
    "network":     0.10,    # Bandwidth, external connections
    "security":    0.10,    # Failed logins, privilege escalation
}

# ── Alert Persistence ───────────────────────────────────────────────────
ALERT_MIN_THREAT_SCORE: int = 40        # Minimum composite score to generate an alert
ALERT_DEDUP_HOURS: int = 2              # Suppress duplicate AI Twin alerts within this window

# ── Embedding Vector Slot Allocation (must total EMBEDDING_DIMENSIONS=64) ──
EMBEDDING_SLOTS = {
    "identity":    10,   # hour_of_day(24 bucketed→10), session_duration_bin(1 slot)
    "keyboard":    10,   # wpm_norm, latency_norm, dwell_norm, flight_norm, backspace_norm,
                         # shortcut_norm, error_norm, rhythm_norm, caps_norm, special_norm
    "mouse":       8,    # speed_norm, accel_norm, click_rate, dblclick_timing, scroll_norm,
                         # idle_ratio, entropy_norm, pause_norm
    "application": 12,   # top_app_1..5 (encoded), switching_rate, window_duration_norm,
                         # tab_count_norm, clipboard_norm, print_norm, browser_ratio
    "file":        12,   # download_rate, upload_rate, delete_rate, rename_rate, usb_norm,
                         # sensitive_file_norm, read_write_ratio, folder_entropy,
                         # large_file_norm, bulk_op_norm, confidential_norm, archive_norm
    "network":     6,    # bandwidth_norm, external_conn_norm, cloud_upload_norm,
                         # vpn_usage, api_rate_norm, rdp_norm
    "security":    6,    # failed_login_norm, mfa_norm, privilege_norm, pw_change_norm,
                         # admin_cmd_norm, sudo_norm
}

assert sum(EMBEDDING_SLOTS.values()) == EMBEDDING_DIMENSIONS, \
    f"Embedding slots {sum(EMBEDDING_SLOTS.values())} must equal EMBEDDING_DIMENSIONS {EMBEDDING_DIMENSIONS}"

assert TRAINING_OUTLIER_MODE in ("clip", "reject"), \
    f"TRAINING_OUTLIER_MODE must be 'clip' or 'reject', got {TRAINING_OUTLIER_MODE!r}"
