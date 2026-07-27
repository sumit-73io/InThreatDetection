"""
AI Twin Engine
==============
The core ML logic for the personalized behavioural clone system.

Algorithms used (all pure Python stdlib — zero pip dependencies):
  • Welford's online algorithm  — numerically stable incremental mean + variance
  • Exponential Moving Average  — slow post-training drift adaptation (α=0.05)
  • Z-score deviation scoring   — per-domain self-comparison
  • Cosine distance             — embedding drift detection
  • Weighted composite scoring  — 7-domain threat score (0–100)

Design philosophy:
  Every employee is compared ONLY against their own historical baseline.
  Global thresholds are only used as a fallback when an employee profile is
  brand-new and has fewer than MIN_TRAINING_EVENTS events.
"""

import math
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Tuple, Any

from app.models.ai_twin_models import (
    BehaviouralProfile, BehaviouralEvent, AITwinAlert, FeatureDeviation,
    RunningStats, AITwinStatus,
    IdentityStats, KeyboardStats, MouseStats, ApplicationStats,
    FileStats, NetworkStats, SecurityStats,
)
from app.core.ai_twin_config import (
    TRAINING_PERIOD_DAYS, MIN_TRAINING_EVENTS, EMA_ALPHA,
    EMBEDDING_DIMENSIONS, EMBEDDING_DRIFT_THRESHOLD,
    THREAT_SCORE_LOW, THREAT_SCORE_MEDIUM, THREAT_SCORE_HIGH,
    Z_THRESHOLD_IDENTITY, Z_THRESHOLD_KEYBOARD, Z_THRESHOLD_MOUSE,
    Z_THRESHOLD_APPLICATION, Z_THRESHOLD_FILE, Z_THRESHOLD_NETWORK,
    Z_THRESHOLD_SECURITY, DOMAIN_WEIGHTS, EMBEDDING_SLOTS,
    ALERT_MIN_THREAT_SCORE,
    TRAINING_OUTLIER_MIN_SAMPLES, TRAINING_OUTLIER_Z_THRESHOLD,
    TRAINING_OUTLIER_MODE, MAX_TRAINING_REJECT_RATE,
    TRAINING_QUARANTINE_MIN_EVENTS, MAX_EMA_STEP_SIGMA,
)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: WELFORD ONLINE ALGORITHM
# ═══════════════════════════════════════════════════════════════════════════

def welford_update(stats: RunningStats, value: float) -> RunningStats:
    """
    Update running mean and variance using Welford's online algorithm.
    Numerically stable — avoids catastrophic cancellation in naive sum-of-squares.
    
    Reference: Welford, B. P. (1962). "Note on a method for calculating corrected
    sums of squares and products." Technometrics. 4 (3): 419–420.
    """
    stats.count += 1
    delta = value - stats.mean
    stats.mean += delta / stats.count
    delta2 = value - stats.mean
    stats.M2 += delta * delta2
    stats.min_val = min(stats.min_val, value)
    stats.max_val = max(stats.max_val, value)
    return stats


def _guarded_learn(profile: BehaviouralProfile, stats: RunningStats, value: float) -> RunningStats:
    """
    Welford update with anti-poisoning caps applied.

    This is the single chokepoint through which every training value must pass.
    Plain `welford_update` accepts anything, which means a compromised or
    abnormal training window silently becomes the employee's permanent
    definition of normal — after which the twin is structurally unable to flag
    that behaviour.

    Policy:
      - Until the feature has TRAINING_OUTLIER_MIN_SAMPLES samples, accept
        everything. There is no baseline yet to judge against, and an outlier
        test on 2 points is noise.
      - Beyond that, compute the value's z-score against the partial baseline.
        Within TRAINING_OUTLIER_Z_THRESHOLD, accept normally.
      - Outside it, either clip to the boundary (default) or reject, per
        TRAINING_OUTLIER_MODE. Clipping still lets genuine drift move the mean
        over many samples; it only denies any single extreme value the power to
        yank the baseline.

    Interventions are counted on the profile so `check_training_poisoning` can
    later judge whether the window as a whole was trustworthy.
    """
    profile.learned_value_count += 1

    # Not enough history to judge — learn as-is.
    if stats.count < TRAINING_OUTLIER_MIN_SAMPLES:
        return welford_update(stats, value)

    std = math.sqrt(stats.M2 / stats.count) if stats.count > 0 else 0.0

    # A zero-variance feature has no scale against which to call something an
    # outlier. Accept, and let variance build up first.
    if std <= 0:
        return welford_update(stats, value)

    z = (value - stats.mean) / std
    if abs(z) <= TRAINING_OUTLIER_Z_THRESHOLD:
        return welford_update(stats, value)

    # Suspect value.
    if TRAINING_OUTLIER_MODE == "reject":
        profile.rejected_event_count += 1
        return stats

    boundary = stats.mean + math.copysign(TRAINING_OUTLIER_Z_THRESHOLD * std, z)
    profile.clipped_value_count += 1
    return welford_update(stats, boundary)


def check_training_poisoning(profile: BehaviouralProfile) -> BehaviouralProfile:
    """
    Decide whether a training window can be trusted as a baseline.

    If the caps had to intervene on more than MAX_TRAINING_REJECT_RATE of the
    values offered, the window was not a stable baseline — it was noise, a role
    change, or an incident in progress. Finalising it would produce a confident
    but wrong "normal", so the profile is quarantined instead and an operator is
    asked to re-baseline from a clean window.

    Quarantining deliberately does NOT delete the learned statistics: an analyst
    investigating why the twin was quarantined will want to see them.
    """
    if profile.event_count < TRAINING_QUARANTINE_MIN_EVENTS:
        return profile
    if profile.learned_value_count <= 0:
        return profile

    interventions = profile.clipped_value_count + profile.rejected_event_count
    rate = interventions / profile.learned_value_count

    if rate > MAX_TRAINING_REJECT_RATE:
        profile.quarantined = True
        profile.status = AITwinStatus.QUARANTINED
        profile.is_trained = False
        profile.quarantine_reason = (
            f"{interventions} of {profile.learned_value_count} training values "
            f"({rate:.0%}) exceeded the {TRAINING_OUTLIER_Z_THRESHOLD}σ plausibility "
            f"cap, above the {MAX_TRAINING_REJECT_RATE:.0%} ceiling. This training "
            "window is too unstable to serve as a behavioural baseline — it may "
            "cover a role change or an incident already in progress. Reset the "
            "twin and re-train from a known-clean period."
        )
    return profile


def get_training_integrity(profile: BehaviouralProfile) -> Dict[str, Any]:
    """Training-data health, for the API and the AI Twin UI."""
    offered = profile.learned_value_count
    interventions = profile.clipped_value_count + profile.rejected_event_count
    rate = (interventions / offered) if offered else 0.0
    return {
        "values_offered": offered,
        "values_clipped": profile.clipped_value_count,
        "values_rejected": profile.rejected_event_count,
        "intervention_rate": round(rate, 4),
        "intervention_ceiling": MAX_TRAINING_REJECT_RATE,
        "quarantined": profile.quarantined,
        "quarantine_reason": profile.quarantine_reason,
        "ema_steps_capped": profile.ema_steps_capped,
        "outlier_mode": TRAINING_OUTLIER_MODE,
        "outlier_z_threshold": TRAINING_OUTLIER_Z_THRESHOLD,
        "max_ema_step_sigma": MAX_EMA_STEP_SIGMA,
        "healthy": (not profile.quarantined) and rate <= MAX_TRAINING_REJECT_RATE,
    }


def ema_update(stats: RunningStats, value: float, alpha: float = EMA_ALPHA) -> RunningStats:
    """
    Post-training profile adaptation using Exponential Moving Average.
    Updates mean only — variance is preserved from training (more stable).
    Alpha=0.05 means the baseline adapts very slowly to legitimate drift.
    """
    if stats.count == 0:
        stats.mean = value
    else:
        stats.mean = (1 - alpha) * stats.mean + alpha * value
    stats.count += 1
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: Z-SCORE AND DEVIATION SCORING
# ═══════════════════════════════════════════════════════════════════════════

def compute_z_score(value: float, mean: float, std: float) -> float:
    """
    Compute z-score. Returns 0.0 when std is 0 (single-value baseline).
    Clamped to [-10, 10] to prevent runaway scores.
    """
    if std < 1e-9:
        # If there's no variance in the baseline, any deviation from mean is suspicious
        if abs(value - mean) > 1e-9:
            return 5.0  # Fixed "very unusual" score
        return 0.0
    return max(-10.0, min(10.0, (value - mean) / std))


def domain_score_from_z(z: float, threshold: float) -> float:
    """
    Convert a z-score into a 0–10 domain threat score.
    Below threshold → 0 (normal). Above → scales up to 10 at 3x threshold.
    """
    abs_z = abs(z)
    if abs_z <= threshold:
        return 0.0
    excess = abs_z - threshold
    return min(10.0, (excess / threshold) * 5.0)


def severity_from_z(z: float, threshold: float) -> str:
    abs_z = abs(z)
    if abs_z <= threshold:
        return "normal"
    if abs_z <= threshold * 1.5:
        return "elevated"
    if abs_z <= threshold * 2.5:
        return "high"
    return "critical"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: EMBEDDING VECTOR COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════

def _normalize(value: float, mean: float, std: float) -> float:
    """Normalize a value to roughly [0, 1] using tanh of z-score."""
    z = compute_z_score(value, mean, std)
    # tanh maps ℝ → (-1, 1); shift to (0, 1)
    return (math.tanh(z / 3.0) + 1.0) / 2.0


def _hour_to_embedding_slot(hour: int, distribution: List[float]) -> List[float]:
    """
    Compress 24-hour distribution into 10 slots:
    [midnight-2, 2-4, 4-6, 6-8, 8-10, 10-12, 12-14, 14-17, 17-20, 20-24]
    Returns normalized 10-element vector.
    """
    buckets = [0, 2, 4, 6, 8, 10, 12, 14, 17, 20, 24]
    result = []
    total = sum(distribution) or 1.0
    for i in range(10):
        bucket_val = sum(distribution[buckets[i]:buckets[i+1]]) / total
        result.append(bucket_val)
    return result


def compute_embedding(profile: BehaviouralProfile) -> List[float]:
    """
    Compute the 64-dimensional behavioural embedding vector from a trained profile.
    Each value is normalized to approximately [0, 1].
    
    Slot allocation:
      identity(10) + keyboard(10) + mouse(8) + application(12) + file(12) + network(6) + security(6)
    """
    vec: List[float] = []

    # ── Identity (10 slots) ──
    hour_embed = _hour_to_embedding_slot(0, profile.identity.login_hour_distribution)
    vec.extend(hour_embed)  # 10 slots

    # ── Keyboard (10 slots) ──
    kb = profile.keyboard
    def _kb_norm(stats: RunningStats, v: float = None) -> float:
        val = v if v is not None else stats.mean
        return _normalize(val, stats.mean, stats.std) if stats.count > 0 else 0.0

    vec.append(_normalize(kb.wpm.mean, kb.wpm.mean, kb.wpm.std) if kb.wpm.count > 0 else 0.5)
    vec.append(_normalize(kb.keystroke_latency_ms.mean, kb.keystroke_latency_ms.mean, kb.keystroke_latency_ms.std) if kb.keystroke_latency_ms.count > 0 else 0.5)
    vec.append(_normalize(kb.dwell_time_ms.mean, kb.dwell_time_ms.mean, kb.dwell_time_ms.std) if kb.dwell_time_ms.count > 0 else 0.5)
    vec.append(_normalize(kb.flight_time_ms.mean, kb.flight_time_ms.mean, kb.flight_time_ms.std) if kb.flight_time_ms.count > 0 else 0.5)
    vec.append(min(1.0, kb.backspace_rate.mean * 10) if kb.backspace_rate.count > 0 else 0.1)
    vec.append(min(1.0, kb.shortcut_usage_rate.mean) if kb.shortcut_usage_rate.count > 0 else 0.3)
    vec.append(min(1.0, kb.error_rate.mean * 5) if kb.error_rate.count > 0 else 0.1)
    vec.append(min(1.0, kb.typing_rhythm_variance.mean / 100.0) if kb.typing_rhythm_variance.count > 0 else 0.2)
    vec.extend([0.0, 0.0])  # reserved padding to reach 10 slots

    # ── Mouse (8 slots) ──
    ms = profile.mouse
    vec.append(min(1.0, ms.movement_speed_px_s.mean / 1000.0) if ms.movement_speed_px_s.count > 0 else 0.3)
    vec.append(min(1.0, ms.acceleration.mean / 500.0) if ms.acceleration.count > 0 else 0.3)
    vec.append(min(1.0, ms.click_frequency_per_min.mean / 60.0) if ms.click_frequency_per_min.count > 0 else 0.2)
    vec.append(min(1.0, ms.double_click_interval_ms.mean / 500.0) if ms.double_click_interval_ms.count > 0 else 0.5)
    vec.append(min(1.0, ms.scroll_speed.mean / 20.0) if ms.scroll_speed.count > 0 else 0.3)
    vec.append(ms.idle_ratio.mean if ms.idle_ratio.count > 0 else 0.2)
    vec.append(min(1.0, ms.pointer_entropy.mean) if ms.pointer_entropy.count > 0 else 0.5)
    vec.append(min(1.0, ms.pause_frequency.mean / 10.0) if ms.pause_frequency.count > 0 else 0.3)

    # ── Application (12 slots) ──
    ap = profile.application
    # Encode top 5 apps as index/frequency ratio
    top_apps_total = sum(ap.app_frequency.values()) or 1
    sorted_apps = sorted(ap.app_frequency.items(), key=lambda x: x[1], reverse=True)
    for i in range(5):
        if i < len(sorted_apps):
            vec.append(sorted_apps[i][1] / top_apps_total)
        else:
            vec.append(0.0)
    vec.append(min(1.0, ap.switching_rate_per_hour.mean / 20.0) if ap.switching_rate_per_hour.count > 0 else 0.3)
    vec.append(min(1.0, ap.active_window_duration_s.mean / 3600.0) if ap.active_window_duration_s.count > 0 else 0.3)
    vec.append(min(1.0, ap.browser_tab_count.mean / 20.0) if ap.browser_tab_count.count > 0 else 0.2)
    vec.append(min(1.0, ap.clipboard_ops_per_hour.mean / 50.0) if ap.clipboard_ops_per_hour.count > 0 else 0.1)
    vec.append(min(1.0, ap.print_frequency_per_day.mean / 10.0) if ap.print_frequency_per_day.count > 0 else 0.05)
    vec.append(0.0)  # reserved (browser_ratio)
    vec.append(0.0)  # reserved (total_app_sessions_norm)  ← slot 12 to reach 5+7=12

    # ── File (12 slots) ──
    fi = profile.file
    vec.append(min(1.0, fi.downloads_per_session.mean / 20.0) if fi.downloads_per_session.count > 0 else 0.1)
    vec.append(min(1.0, fi.uploads_per_session.mean / 20.0) if fi.uploads_per_session.count > 0 else 0.05)
    vec.append(min(1.0, fi.deletes_per_session.mean / 10.0) if fi.deletes_per_session.count > 0 else 0.02)
    vec.append(min(1.0, fi.renames_per_session.mean / 10.0) if fi.renames_per_session.count > 0 else 0.02)
    vec.append(fi.read_write_ratio.mean if fi.read_write_ratio.count > 0 else 0.7)
    vec.append(min(1.0, fi.sensitive_file_accesses_per_day.mean / 10.0) if fi.sensitive_file_accesses_per_day.count > 0 else 0.1)
    vec.append(min(1.0, fi.usb_events_per_week.mean / 5.0) if fi.usb_events_per_week.count > 0 else 0.0)
    vec.append(min(1.0, fi.large_file_transfers_mb.mean / 100.0) if fi.large_file_transfers_mb.count > 0 else 0.05)
    vec.append(min(1.0, fi.bulk_download_events / 5.0))
    vec.append(min(1.0, fi.archive_creation_rate.mean) if fi.archive_creation_rate.count > 0 else 0.02)
    vec.append(min(1.0, fi.confidential_access_rate.mean) if fi.confidential_access_rate.count > 0 else 0.05)
    vec.append(0.0)  # reserved

    # ── Network (6 slots) ──
    nw = profile.network
    vec.append(min(1.0, nw.bandwidth_mb_per_hour.mean / 1000.0) if nw.bandwidth_mb_per_hour.count > 0 else 0.1)
    vec.append(min(1.0, nw.external_connections_per_day.mean / 10.0) if nw.external_connections_per_day.count > 0 else 0.1)
    vec.append(min(1.0, nw.cloud_uploads_per_day.mean / 5.0) if nw.cloud_uploads_per_day.count > 0 else 0.05)
    vec.append(nw.vpn_connected_ratio)
    vec.append(min(1.0, nw.api_requests_per_minute.mean / 30.0) if nw.api_requests_per_minute.count > 0 else 0.1)
    vec.append(min(1.0, nw.rdp_sessions_per_week.mean / 3.0) if nw.rdp_sessions_per_week.count > 0 else 0.0)

    # ── Security (6 slots) ──
    sc = profile.security
    vec.append(min(1.0, sc.failed_logins_per_week.mean / 5.0) if sc.failed_logins_per_week.count > 0 else 0.05)
    vec.append(sc.mfa_compliance_rate)
    vec.append(min(1.0, sc.privilege_events_per_week.mean / 3.0) if sc.privilege_events_per_week.count > 0 else 0.0)
    vec.append(min(1.0, sc.password_change_frequency_days.mean / 90.0) if sc.password_change_frequency_days.count > 0 else 0.5)
    vec.append(min(1.0, sc.admin_command_rate.mean / 10.0) if sc.admin_command_rate.count > 0 else 0.0)
    vec.append(0.0)  # reserved (sudo_norm)

    # Ensure exactly 64 dimensions
    assert len(vec) == EMBEDDING_DIMENSIONS, f"Embedding vector length {len(vec)} != {EMBEDDING_DIMENSIONS}"
    return vec


def cosine_distance(v1: List[float], v2: List[float]) -> float:
    """
    Cosine distance = 1 - cosine_similarity.
    Returns 0 for identical vectors, 1 for orthogonal, 2 for opposite.
    """
    dot = sum(a * b for a, b in zip(v1, v2))
    mag1 = math.sqrt(sum(a * a for a in v1))
    mag2 = math.sqrt(sum(b * b for b in v2))
    if mag1 < 1e-9 or mag2 < 1e-9:
        return 0.0
    return 1.0 - dot / (mag1 * mag2)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: TRAINING PHASE — EVENT INGESTION
# ═══════════════════════════════════════════════════════════════════════════

def ingest_training_event(profile: BehaviouralProfile, event: BehaviouralEvent) -> BehaviouralProfile:
    """
    Update a profile's running statistics with a new training event.
    Uses Welford's algorithm for all numerical features.
    """
    now = datetime.now(timezone.utc)
    profile.event_count += 1
    profile.last_event_time = now
    profile.last_updated = now
    profile.status = AITwinStatus.TRAINING

    ts = event.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    hour = ts.hour
    weekday = ts.weekday()

    # ── Identity ──
    profile.identity.login_hour_distribution[hour] += 1.0
    if weekday not in profile.identity.typical_workdays:
        profile.identity.typical_workdays.append(weekday)
    profile.identity.total_sessions += 1

    if event.session_duration_s is not None:
        profile.identity.session_duration = _guarded_learn(profile, profile.identity.session_duration, event.session_duration_s)

    if event.device_ip and event.device_ip not in profile.identity.ip_addresses_seen:
        profile.identity.ip_addresses_seen.append(event.device_ip)

    if event.device_fingerprint and event.device_fingerprint not in profile.identity.device_fingerprints:
        profile.identity.device_fingerprints.append(event.device_fingerprint)

    is_off_hours = hour >= 22 or hour < 6
    off_hours_count = profile.identity.off_hours_session_rate * profile.identity.total_sessions
    profile.identity.off_hours_session_rate = (off_hours_count + (1 if is_off_hours else 0)) / profile.identity.total_sessions

    if event.is_vpn is not None:
        vpn_count = profile.identity.vpn_usage_rate * (profile.identity.total_sessions - 1)
        profile.identity.vpn_usage_rate = (vpn_count + (1.0 if event.is_vpn else 0.0)) / profile.identity.total_sessions

    # ── Keyboard ──
    if event.wpm is not None and event.wpm > 0:
        profile.keyboard.wpm = _guarded_learn(profile, profile.keyboard.wpm, event.wpm)
    if event.keystroke_latency_ms is not None:
        profile.keyboard.keystroke_latency_ms = _guarded_learn(profile, profile.keyboard.keystroke_latency_ms, event.keystroke_latency_ms)
    if event.dwell_time_ms is not None:
        profile.keyboard.dwell_time_ms = _guarded_learn(profile, profile.keyboard.dwell_time_ms, event.dwell_time_ms)
    if event.flight_time_ms is not None:
        profile.keyboard.flight_time_ms = _guarded_learn(profile, profile.keyboard.flight_time_ms, event.flight_time_ms)
    if event.backspace_rate is not None:
        profile.keyboard.backspace_rate = _guarded_learn(profile, profile.keyboard.backspace_rate, event.backspace_rate)
    if event.shortcut_usage_rate is not None:
        profile.keyboard.shortcut_usage_rate = _guarded_learn(profile, profile.keyboard.shortcut_usage_rate, event.shortcut_usage_rate)
    if event.error_rate is not None:
        profile.keyboard.error_rate = _guarded_learn(profile, profile.keyboard.error_rate, event.error_rate)

    # ── Mouse ──
    if event.mouse_speed_px_s is not None:
        profile.mouse.movement_speed_px_s = _guarded_learn(profile, profile.mouse.movement_speed_px_s, event.mouse_speed_px_s)
    if event.mouse_acceleration is not None:
        profile.mouse.acceleration = _guarded_learn(profile, profile.mouse.acceleration, event.mouse_acceleration)
    if event.click_frequency_per_min is not None:
        profile.mouse.click_frequency_per_min = _guarded_learn(profile, profile.mouse.click_frequency_per_min, event.click_frequency_per_min)
    if event.double_click_interval_ms is not None:
        profile.mouse.double_click_interval_ms = _guarded_learn(profile, profile.mouse.double_click_interval_ms, event.double_click_interval_ms)
    if event.scroll_speed is not None:
        profile.mouse.scroll_speed = _guarded_learn(profile, profile.mouse.scroll_speed, event.scroll_speed)
    if event.idle_ratio is not None:
        profile.mouse.idle_ratio = _guarded_learn(profile, profile.mouse.idle_ratio, event.idle_ratio)
    if event.pointer_entropy is not None:
        profile.mouse.pointer_entropy = _guarded_learn(profile, profile.mouse.pointer_entropy, event.pointer_entropy)

    # ── Application ──
    if event.app_name:
        profile.application.app_frequency[event.app_name] = profile.application.app_frequency.get(event.app_name, 0) + 1
        sorted_apps = sorted(profile.application.app_frequency.items(), key=lambda x: x[1], reverse=True)
        profile.application.top_apps = [a[0] for a in sorted_apps[:10]]
        profile.application.total_app_sessions += 1

    if event.window_duration_s is not None:
        profile.application.active_window_duration_s = _guarded_learn(profile, profile.application.active_window_duration_s, event.window_duration_s)
    if event.browser_tab_count is not None:
        profile.application.browser_tab_count = _guarded_learn(profile, profile.application.browser_tab_count, float(event.browser_tab_count))
    if event.clipboard_ops is not None:
        profile.application.clipboard_ops_per_hour = _guarded_learn(profile, profile.application.clipboard_ops_per_hour, float(event.clipboard_ops))
    if event.print_count is not None and event.print_count > 0:
        profile.application.print_frequency_per_day = _guarded_learn(profile, profile.application.print_frequency_per_day, float(event.print_count))

    # ── File ──
    action = event.action.upper()
    if action in ("DOWNLOAD_FILE", "DOWNLOAD_CONFIDENTIAL") and event.download_size_mb is not None:
        profile.file.downloads_per_session = _guarded_learn(profile, profile.file.downloads_per_session, event.download_size_mb)
        if event.download_size_mb > 50:
            profile.file.large_file_transfers_mb = _guarded_learn(profile, profile.file.large_file_transfers_mb, event.download_size_mb)
    if action == "DELETE_FILE":
        profile.file.deletes_per_session = _guarded_learn(profile, profile.file.deletes_per_session, 1.0)
    if event.is_sensitive_file:
        profile.file.sensitive_file_accesses_per_day = _guarded_learn(profile, profile.file.sensitive_file_accesses_per_day, 1.0)
    if event.is_confidential:
        profile.file.confidential_access_rate = _guarded_learn(profile, profile.file.confidential_access_rate, 1.0)
    if event.usb_connected:
        profile.file.usb_events_per_week = _guarded_learn(profile, profile.file.usb_events_per_week, 1.0)
    if event.is_bulk_operation:
        profile.file.bulk_download_events += 1
    if event.upload_size_mb is not None:
        profile.file.uploads_per_session = _guarded_learn(profile, profile.file.uploads_per_session, event.upload_size_mb)

    # ── Network ──
    if event.bandwidth_mb is not None:
        profile.network.bandwidth_mb_per_hour = _guarded_learn(profile, profile.network.bandwidth_mb_per_hour, event.bandwidth_mb)
    if event.is_external_connection:
        profile.network.external_connections_per_day = _guarded_learn(profile, profile.network.external_connections_per_day, 1.0)
    if event.is_cloud_upload:
        profile.network.cloud_uploads_per_day = _guarded_learn(profile, profile.network.cloud_uploads_per_day, 1.0)
    if event.api_request_count is not None:
        profile.network.api_requests_per_minute = _guarded_learn(profile, profile.network.api_requests_per_minute, float(event.api_request_count))
    if event.is_rdp:
        profile.network.rdp_sessions_per_week = _guarded_learn(profile, profile.network.rdp_sessions_per_week, 1.0)
    if event.is_vpn is not None:
        vpn_n = profile.network.vpn_connected_ratio * (profile.event_count - 1)
        profile.network.vpn_connected_ratio = (vpn_n + (1.0 if event.is_vpn else 0.0)) / profile.event_count

    # ── Security ──
    if event.is_failed_login:
        profile.security.failed_logins_per_week = _guarded_learn(profile, profile.security.failed_logins_per_week, 1.0)
        profile.security.total_failed_logins += 1
    if event.is_mfa_used is not None:
        mfa_n = profile.security.mfa_compliance_rate * (profile.event_count - 1)
        profile.security.mfa_compliance_rate = (mfa_n + (1.0 if event.is_mfa_used else 0.0)) / profile.event_count
    if event.is_privilege_escalation:
        profile.security.privilege_events_per_week = _guarded_learn(profile, profile.security.privilege_events_per_week, 1.0)
    if event.is_admin_command:
        profile.security.admin_command_rate = _guarded_learn(profile, profile.security.admin_command_rate, 1.0)

    return profile


def finalize_training(profile: BehaviouralProfile) -> BehaviouralProfile:
    """
    Called when training criteria are met. Generates the 64-dim embedding vector
    and transitions the profile to TRAINED status.

    The anti-poisoning check runs FIRST and can veto promotion. A window that
    needed constant capping is not a baseline, and shipping it as "trained"
    would give the operator false confidence in every subsequent score.
    """
    now = datetime.now(timezone.utc)

    profile = check_training_poisoning(profile)
    if profile.quarantined:
        # Keep the learned statistics for forensics, but do not mark trained and
        # do not build an embedding from data we have judged untrustworthy.
        profile.last_updated = now
        print(
            f"AI Twin QUARANTINED for {profile.employee_id}: "
            f"{profile.quarantine_reason}"
        )
        return profile

    profile.embedding_vector = compute_embedding(profile)
    profile.embedding_updated_at = now
    profile.training_end = now
    profile.is_trained = True
    profile.status = AITwinStatus.TRAINED
    profile.last_updated = now
    return profile


def check_training_complete(profile: BehaviouralProfile) -> bool:
    """Check whether the training criteria are satisfied."""
    now = datetime.now(timezone.utc)
    training_start = profile.training_start
    if training_start.tzinfo is None:
        training_start = training_start.replace(tzinfo=timezone.utc)
    days_elapsed = (now - training_start).days
    return profile.event_count >= MIN_TRAINING_EVENTS and days_elapsed >= TRAINING_PERIOD_DAYS


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: POST-TRAINING SCORING
# ═══════════════════════════════════════════════════════════════════════════

def score_event(profile: BehaviouralProfile, event: BehaviouralEvent) -> Dict:
    """
    Score a single event against the employee's trained behavioural profile.
    Returns a detailed deviation report with per-domain and composite scores.
    """
    deviations: List[FeatureDeviation] = []
    domain_scores: Dict[str, float] = {}

    now_ts = event.timestamp
    if now_ts.tzinfo is None:
        now_ts = now_ts.replace(tzinfo=timezone.utc)
    hour = now_ts.hour

    # ── IDENTITY DOMAIN ─────────────────────────────────────────────────
    identity_domain_score = 0.0

    # Login hour deviation — is this hour outside the employee's normal pattern?
    total_sessions = sum(profile.identity.login_hour_distribution) or 1.0
    expected_hour_prob = profile.identity.login_hour_distribution[hour] / total_sessions
    # Lower probability hour = higher deviation
    hour_deviation_score = max(0.0, (0.1 - expected_hour_prob) * 50)  # 0–5 range
    if expected_hour_prob < 0.01 and total_sessions > 10:
        # Employee has NEVER logged in at this hour
        dev = FeatureDeviation(
            feature_name="login_hour",
            domain="identity",
            baseline_mean=0.0,
            baseline_std=0.0,
            observed_value=float(hour),
            z_score=5.0,
            severity="high"
        )
        deviations.append(dev)
        identity_domain_score += 5.0

    # Off-hours flag
    is_off_hours = hour >= 22 or hour < 6
    expected_off_hours_rate = profile.identity.off_hours_session_rate
    if is_off_hours and expected_off_hours_rate < 0.05:
        dev = FeatureDeviation(
            feature_name="off_hours_access",
            domain="identity",
            baseline_mean=expected_off_hours_rate,
            baseline_std=0.0,
            observed_value=1.0,
            z_score=6.0,
            severity="high"
        )
        deviations.append(dev)
        identity_domain_score += 4.0

    # Session duration
    if event.session_duration_s is not None and profile.identity.session_duration.count >= 5:
        z = compute_z_score(event.session_duration_s, profile.identity.session_duration.mean, profile.identity.session_duration.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_IDENTITY)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="session_duration",
                domain="identity",
                baseline_mean=profile.identity.session_duration.mean,
                baseline_std=profile.identity.session_duration.std,
                observed_value=event.session_duration_s,
                z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_IDENTITY)
            ))
            identity_domain_score += ds

    domain_scores["identity"] = min(10.0, identity_domain_score)

    # ── KEYBOARD DOMAIN ─────────────────────────────────────────────────
    kb_score = 0.0
    kb = profile.keyboard

    def _check_kb(val, stats: RunningStats, name: str, threshold=Z_THRESHOLD_KEYBOARD):
        nonlocal kb_score
        if val is not None and stats.count >= 5:
            z = compute_z_score(val, stats.mean, stats.std)
            ds = domain_score_from_z(z, threshold)
            if ds > 0:
                deviations.append(FeatureDeviation(
                    feature_name=name, domain="keyboard",
                    baseline_mean=round(stats.mean, 3), baseline_std=round(stats.std, 3),
                    observed_value=round(val, 3), z_score=round(z, 2),
                    severity=severity_from_z(z, threshold)
                ))
                kb_score += ds

    _check_kb(event.wpm, kb.wpm, "wpm")
    _check_kb(event.keystroke_latency_ms, kb.keystroke_latency_ms, "keystroke_latency_ms")
    _check_kb(event.dwell_time_ms, kb.dwell_time_ms, "dwell_time_ms")
    _check_kb(event.backspace_rate, kb.backspace_rate, "backspace_rate")
    _check_kb(event.error_rate, kb.error_rate, "error_rate")
    domain_scores["keyboard"] = min(10.0, kb_score)

    # ── MOUSE DOMAIN ────────────────────────────────────────────────────
    ms_score = 0.0
    ms = profile.mouse

    def _check_ms(val, stats: RunningStats, name: str):
        nonlocal ms_score
        if val is not None and stats.count >= 5:
            z = compute_z_score(val, stats.mean, stats.std)
            ds = domain_score_from_z(z, Z_THRESHOLD_MOUSE)
            if ds > 0:
                deviations.append(FeatureDeviation(
                    feature_name=name, domain="mouse",
                    baseline_mean=round(stats.mean, 3), baseline_std=round(stats.std, 3),
                    observed_value=round(val, 3), z_score=round(z, 2),
                    severity=severity_from_z(z, Z_THRESHOLD_MOUSE)
                ))
                ms_score += ds

    _check_ms(event.mouse_speed_px_s, ms.movement_speed_px_s, "mouse_speed_px_s")
    _check_ms(event.click_frequency_per_min, ms.click_frequency_per_min, "click_frequency_per_min")
    _check_ms(event.idle_ratio, ms.idle_ratio, "idle_ratio")
    _check_ms(event.pointer_entropy, ms.pointer_entropy, "pointer_entropy")
    domain_scores["mouse"] = min(10.0, ms_score)

    # ── APPLICATION DOMAIN ──────────────────────────────────────────────
    ap_score = 0.0
    ap = profile.application

    # Flag use of suspicious/unusual applications
    if event.app_name and ap.total_app_sessions > 10:
        app_freq = ap.app_frequency.get(event.app_name, 0)
        total_app_events = sum(ap.app_frequency.values()) or 1
        app_rate = app_freq / total_app_events
        if app_rate < 0.01:
            # App never (or rarely) used by this employee
            severity = "critical" if event.app_name.lower() in ("powershell", "cmd", "wscript", "psexec", "netcat", "wireshark", "mimikatz") else "elevated"
            z_val = 6.0 if severity == "critical" else 3.5
            deviations.append(FeatureDeviation(
                feature_name="unusual_application",
                domain="application",
                baseline_mean=app_rate,
                baseline_std=0.0,
                observed_value=1.0,
                z_score=z_val,
                severity=severity
            ))
            ap_score += 5.0 if severity == "critical" else 2.5

    if event.window_duration_s is not None and ap.active_window_duration_s.count >= 5:
        z = compute_z_score(event.window_duration_s, ap.active_window_duration_s.mean, ap.active_window_duration_s.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_APPLICATION)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="window_duration_s", domain="application",
                baseline_mean=round(ap.active_window_duration_s.mean, 2),
                baseline_std=round(ap.active_window_duration_s.std, 2),
                observed_value=round(event.window_duration_s, 2),
                z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_APPLICATION)
            ))
            ap_score += ds

    if event.clipboard_ops is not None and ap.clipboard_ops_per_hour.count >= 5:
        z = compute_z_score(float(event.clipboard_ops), ap.clipboard_ops_per_hour.mean, ap.clipboard_ops_per_hour.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_APPLICATION)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="clipboard_ops", domain="application",
                baseline_mean=round(ap.clipboard_ops_per_hour.mean, 2),
                baseline_std=round(ap.clipboard_ops_per_hour.std, 2),
                observed_value=float(event.clipboard_ops),
                z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_APPLICATION)
            ))
            ap_score += ds

    domain_scores["application"] = min(10.0, ap_score)

    # ── FILE DOMAIN ─────────────────────────────────────────────────────
    fi_score = 0.0
    fi = profile.file

    if event.download_size_mb is not None and fi.downloads_per_session.count >= 5:
        z = compute_z_score(event.download_size_mb, fi.downloads_per_session.mean, fi.downloads_per_session.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_FILE)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="download_size_mb", domain="file",
                baseline_mean=round(fi.downloads_per_session.mean, 2),
                baseline_std=round(fi.downloads_per_session.std, 2),
                observed_value=round(event.download_size_mb, 2),
                z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_FILE)
            ))
            fi_score += ds

    if event.usb_connected and fi.usb_events_per_week.count >= 3:
        if fi.usb_events_per_week.mean < 0.2:
            deviations.append(FeatureDeviation(
                feature_name="usb_connected", domain="file",
                baseline_mean=fi.usb_events_per_week.mean,
                baseline_std=fi.usb_events_per_week.std,
                observed_value=1.0, z_score=5.0, severity="high"
            ))
            fi_score += 5.0

    if event.is_bulk_operation:
        normal_bulk = fi.bulk_download_events / max(profile.event_count, 1)
        if normal_bulk < 0.01:
            deviations.append(FeatureDeviation(
                feature_name="bulk_operation", domain="file",
                baseline_mean=normal_bulk, baseline_std=0.0,
                observed_value=1.0, z_score=6.0, severity="critical"
            ))
            fi_score += 6.0

    if event.is_confidential and fi.confidential_access_rate.count >= 5:
        z = compute_z_score(1.0, fi.confidential_access_rate.mean, fi.confidential_access_rate.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_FILE)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="confidential_file_access", domain="file",
                baseline_mean=round(fi.confidential_access_rate.mean, 3),
                baseline_std=round(fi.confidential_access_rate.std, 3),
                observed_value=1.0, z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_FILE)
            ))
            fi_score += ds

    domain_scores["file"] = min(10.0, fi_score)

    # ── NETWORK DOMAIN ──────────────────────────────────────────────────
    nw_score = 0.0
    nw = profile.network

    if event.bandwidth_mb is not None and nw.bandwidth_mb_per_hour.count >= 5:
        z = compute_z_score(event.bandwidth_mb, nw.bandwidth_mb_per_hour.mean, nw.bandwidth_mb_per_hour.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_NETWORK)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="bandwidth_mb", domain="network",
                baseline_mean=round(nw.bandwidth_mb_per_hour.mean, 2),
                baseline_std=round(nw.bandwidth_mb_per_hour.std, 2),
                observed_value=round(event.bandwidth_mb, 2),
                z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_NETWORK)
            ))
            nw_score += ds

    if event.is_external_connection and nw.external_connections_per_day.count >= 5:
        z = compute_z_score(1.0, nw.external_connections_per_day.mean, nw.external_connections_per_day.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_NETWORK)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="external_connection", domain="network",
                baseline_mean=round(nw.external_connections_per_day.mean, 2),
                baseline_std=round(nw.external_connections_per_day.std, 2),
                observed_value=1.0, z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_NETWORK)
            ))
            nw_score += ds

    if event.is_cloud_upload and nw.cloud_uploads_per_day.count >= 5:
        if nw.cloud_uploads_per_day.mean < 0.1:
            deviations.append(FeatureDeviation(
                feature_name="cloud_upload", domain="network",
                baseline_mean=nw.cloud_uploads_per_day.mean,
                baseline_std=nw.cloud_uploads_per_day.std,
                observed_value=1.0, z_score=5.0, severity="high"
            ))
            nw_score += 4.0

    domain_scores["network"] = min(10.0, nw_score)

    # ── SECURITY DOMAIN ─────────────────────────────────────────────────
    sc_score = 0.0
    sc = profile.security

    if event.is_failed_login and sc.failed_logins_per_week.count >= 3:
        # Even one failed login above baseline is suspicious
        z = compute_z_score(1.0, sc.failed_logins_per_week.mean, sc.failed_logins_per_week.std)
        ds = domain_score_from_z(z, Z_THRESHOLD_SECURITY)
        if ds > 0:
            deviations.append(FeatureDeviation(
                feature_name="failed_login", domain="security",
                baseline_mean=round(sc.failed_logins_per_week.mean, 3),
                baseline_std=round(sc.failed_logins_per_week.std, 3),
                observed_value=1.0, z_score=round(z, 2),
                severity=severity_from_z(z, Z_THRESHOLD_SECURITY)
            ))
            sc_score += ds

    if event.is_privilege_escalation:
        baseline_priv = sc.privilege_events_per_week.mean if sc.privilege_events_per_week.count >= 3 else 0.0
        if baseline_priv < 0.5:
            deviations.append(FeatureDeviation(
                feature_name="privilege_escalation", domain="security",
                baseline_mean=baseline_priv, baseline_std=0.0,
                observed_value=1.0, z_score=7.0, severity="critical"
            ))
            sc_score += 7.0

    if event.is_admin_command:
        baseline_admin = sc.admin_command_rate.mean if sc.admin_command_rate.count >= 3 else 0.0
        if baseline_admin < 0.2:
            deviations.append(FeatureDeviation(
                feature_name="admin_command", domain="security",
                baseline_mean=baseline_admin, baseline_std=0.0,
                observed_value=1.0, z_score=5.0, severity="high"
            ))
            sc_score += 4.0

    domain_scores["security"] = min(10.0, sc_score)

    # ── COMPOSITE THREAT SCORE ──────────────────────────────────────────
    composite = 0.0
    for domain, weight in DOMAIN_WEIGHTS.items():
        composite += domain_scores.get(domain, 0.0) * weight * 10.0  # scale 0–10 → 0–100
    composite = min(100.0, composite)

    # ── EMBEDDING DRIFT ─────────────────────────────────────────────────
    embedding_drift = 0.0
    if profile.is_trained and any(v != 0.0 for v in profile.embedding_vector):
        try:
            current_embedding = compute_embedding(profile)
            embedding_drift = cosine_distance(profile.embedding_vector, current_embedding)
        except Exception:
            embedding_drift = 0.0

    # ── SEVERITY CLASSIFICATION ─────────────────────────────────────────
    if composite >= THREAT_SCORE_HIGH:
        severity = "Critical"
    elif composite >= THREAT_SCORE_MEDIUM:
        severity = "High"
    elif composite >= THREAT_SCORE_LOW:
        severity = "Warning"
    else:
        severity = "Normal"

    flagged_domains = list({d.domain for d in deviations})

    return {
        "composite_threat_score": round(composite, 2),
        "domain_scores": {k: round(v, 2) for k, v in domain_scores.items()},
        "deviations": deviations,
        "flagged_domains": flagged_domains,
        "severity": severity,
        "embedding_drift": round(embedding_drift, 4),
        "is_alert": composite >= ALERT_MIN_THREAT_SCORE,
    }


def _capped_ema(profile: BehaviouralProfile, stats: RunningStats, value: float) -> RunningStats:
    """
    EMA update with a bounded step size (anti-poisoning).

    Uncapped EMA is the natural channel for a patient attacker: feed slightly
    abnormal values forever and the baseline follows, until the anomalous has
    become normal and detection is dead. Alpha alone does not prevent this — it
    only sets the pace, and an extreme enough value still moves the mean a long
    way in one step.

    Capping the movement to MAX_EMA_STEP_SIGMA standard deviations per update
    bounds the walk rate regardless of how extreme the injected value is. Real
    drift still gets learned; it just cannot be rushed.
    """
    before = stats.mean
    updated = ema_update(stats, value)

    std = math.sqrt(stats.M2 / stats.count) if stats.count > 0 else 0.0
    if std <= 0:
        return updated

    max_step = MAX_EMA_STEP_SIGMA * std
    delta = updated.mean - before
    if abs(delta) > max_step:
        updated.mean = before + math.copysign(max_step, delta)
        profile.ema_steps_capped += 1

    return updated


def apply_ema_update(profile: BehaviouralProfile, event: BehaviouralEvent) -> BehaviouralProfile:
    """
    Post-training profile adaptation using EMA.
    Only updates mean values, not variance — variance is preserved from training.

    Every adaptation goes through `_capped_ema` so the baseline cannot be walked
    arbitrarily fast by sustained abnormal input.
    """
    now = datetime.now(timezone.utc)
    profile.last_updated = now
    profile.event_count += 1

    # A quarantined baseline is already untrusted; continuing to adapt it would
    # only entrench the bad statistics.
    if profile.quarantined:
        return profile

    if event.wpm is not None and event.wpm > 0 and profile.keyboard.wpm.count > 0:
        profile.keyboard.wpm = _capped_ema(profile, profile.keyboard.wpm, event.wpm)
    if event.mouse_speed_px_s is not None and profile.mouse.movement_speed_px_s.count > 0:
        profile.mouse.movement_speed_px_s = _capped_ema(
            profile, profile.mouse.movement_speed_px_s, event.mouse_speed_px_s
        )
    if event.session_duration_s is not None and profile.identity.session_duration.count > 0:
        profile.identity.session_duration = _capped_ema(
            profile, profile.identity.session_duration, event.session_duration_s
        )

    return profile
