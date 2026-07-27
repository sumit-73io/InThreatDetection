"""
ML Anomaly Detection Engine
============================
A lightweight, fully offline anomaly detection engine using statistical
analysis (z-scores, frequency distributions, velocity heuristics) to flag
insider threats from employee activity data.

Zero external dependencies — uses only Python stdlib (math, collections, datetime).
Designed so the detection logic can later be swapped with scikit-learn or a local LLM.
"""

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from app.database.mongodb import db_instance
from app.models.anomaly import AnomalyAlert, AnomalyType, AnomalySeverity
from fastapi.encoders import jsonable_encoder


# ── Role-Action Compatibility Matrix ───────────────────────────────────
# Maps each role to the set of actions considered "normal" for them.
# Any action outside this set raises a ROLE_MISMATCH flag.
ROLE_NORMAL_ACTIONS = {
    "Admin":          {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE", "DOWNLOAD_CONFIDENTIAL", "CHANGE_PERMISSION", "DELETE_FILE", "USB_CONNECTED"},
    "Sys Admin":      {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE", "CHANGE_PERMISSION", "DELETE_FILE", "USB_CONNECTED"},
    "DB Admin":       {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE", "DOWNLOAD_CONFIDENTIAL", "DELETE_FILE"},
    "Dev":            {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE", "USB_CONNECTED"},
    "HR":             {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE"},
    "Design":         {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE", "USB_CONNECTED"},
    "Branch Manager": {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE"},
    "Ops Analyst":    {"LOGIN", "LOGOUT", "VIEW_CUSTOMER", "DOWNLOAD_FILE"},
    "Support Staff":  {"LOGIN", "LOGOUT", "VIEW_CUSTOMER"},
    "User":           {"LOGIN", "LOGOUT", "VIEW_CUSTOMER"},
}

# Risk weights for cumulative scoring
ACTION_RISK_WEIGHTS = {
    "LOGIN": 0,
    "LOGOUT": 0,
    "VIEW_CUSTOMER": 0,
    "DOWNLOAD_FILE": 10,
    "DOWNLOAD_CONFIDENTIAL": 30,
    "USB_CONNECTED": 20,
    "FAILED_LOGIN": 15,
    "CHANGE_PERMISSION": 35,
    "DELETE_FILE": 40,
}

# ── Thresholds ──────────────────────────────────────────────────────────
VELOCITY_WINDOW_SECONDS = 60        # Time window for burst detection
VELOCITY_HIGH_RISK_THRESHOLD = 3    # N high-risk actions in window = burst
CUMULATIVE_RISK_THRESHOLD = 120     # Total risk score threshold per employee
UNUSUAL_HOUR_START = 22             # 10 PM
UNUSUAL_HOUR_END = 6                # 6 AM
ACTION_SPIKE_ZSCORE = 2.0           # Z-score threshold for frequency anomaly


def _mean(values):
    """Calculate mean of a list of numbers."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values, mean_val=None):
    """Calculate population standard deviation."""
    if len(values) < 2:
        return 0.0
    if mean_val is None:
        mean_val = _mean(values)
    variance = sum((x - mean_val) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _z_score(value, mean_val, std_val):
    """Calculate z-score. Returns 0 if std is 0."""
    if std_val == 0:
        return 0.0
    return (value - mean_val) / std_val


async def _get_employee_map():
    """Build a map of employee_id -> {name, role} from the employees collection."""
    cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
    employees = await cursor.to_list(length=1000)
    return {e["employee_id"]: {"name": e.get("name", "Unknown"), "role": e.get("role", "Unknown")} for e in employees}


async def _get_recent_activities(hours=24):
    """Fetch activities from the last N hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cursor = db_instance.db["activities"].find(
        {"timestamp": {"$gte": cutoff.isoformat()}}
    ).sort("timestamp", -1).limit(5000)
    return await cursor.to_list(length=5000)

async def _get_recent_api_logs(minutes=15):
    """Fetch API logs from the last N minutes to detect high traffic spikes."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    cursor = db_instance.db["api_access_logs"].find(
        {"timestamp": {"$gte": cutoff.isoformat()}}
    ).sort("timestamp", -1).limit(10000)
    return await cursor.to_list(length=10000)


def _detect_velocity_bursts(activities_by_employee, emp_map):
    """Detect bursts of high-risk actions within short time windows."""
    alerts = []
    high_risk_actions = {"DOWNLOAD_CONFIDENTIAL", "DELETE_FILE", "CHANGE_PERMISSION", "USB_CONNECTED", "FAILED_LOGIN"}

    for emp_id, acts in activities_by_employee.items():
        # Filter to high-risk actions only
        high_risk = []
        for a in acts:
            action_str = a.get("action", "")
            if hasattr(action_str, "value"):
                action_str = action_str.value
            if action_str in high_risk_actions:
                high_risk.append(a)

        if len(high_risk) < VELOCITY_HIGH_RISK_THRESHOLD:
            continue

        # Sort by timestamp
        high_risk.sort(key=lambda x: x.get("timestamp", ""))

        # Sliding window check
        for i in range(len(high_risk) - VELOCITY_HIGH_RISK_THRESHOLD + 1):
            try:
                t_start = datetime.fromisoformat(str(high_risk[i]["timestamp"]).replace("Z", "+00:00"))
                t_end = datetime.fromisoformat(str(high_risk[i + VELOCITY_HIGH_RISK_THRESHOLD - 1]["timestamp"]).replace("Z", "+00:00"))
                delta = (t_end - t_start).total_seconds()
            except (ValueError, TypeError):
                continue

            if delta <= VELOCITY_WINDOW_SECONDS:
                emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
                action_names = [h.get("action", "UNKNOWN") for h in high_risk[i:i + VELOCITY_HIGH_RISK_THRESHOLD]]
                action_names = [a.value if hasattr(a, "value") else a for a in action_names]
                alerts.append(AnomalyAlert(
                    employee_id=emp_id,
                    employee_name=emp_info["name"],
                    role=emp_info["role"],
                    anomaly_type=AnomalyType.VELOCITY_BURST,
                    severity=AnomalySeverity.CRITICAL,
                    confidence=min(95, 70 + len(high_risk) * 5),
                    description=f"Detected {len(high_risk)} high-risk actions within {int(delta)}s window: {', '.join(action_names)}. This rapid succession strongly suggests automated or deliberate malicious activity."
                ))
                break  # One alert per employee per scan

    return alerts


def _detect_role_mismatches(activities_by_employee, emp_map):
    """Flag actions that are outside the employee's role-normal set."""
    alerts = []

    for emp_id, acts in activities_by_employee.items():
        emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
        role = emp_info.get("role", "Unknown")
        allowed = ROLE_NORMAL_ACTIONS.get(role, set())

        if not allowed:
            continue

        mismatched = []
        for a in acts:
            action_str = a.get("action", "")
            if hasattr(action_str, "value"):
                action_str = action_str.value
            if action_str not in allowed and action_str not in ("LOGIN", "LOGOUT", "FAILED_LOGIN"):
                mismatched.append(action_str)

        if mismatched:
            unique_mismatched = list(set(mismatched))
            alerts.append(AnomalyAlert(
                employee_id=emp_id,
                employee_name=emp_info["name"],
                role=emp_info["role"],
                anomaly_type=AnomalyType.ROLE_MISMATCH,
                severity=AnomalySeverity.HIGH if len(mismatched) > 2 else AnomalySeverity.WARNING,
                confidence=min(90, 50 + len(mismatched) * 10),
                description=f"Employee with role '{role}' performed {len(mismatched)} action(s) outside their authorized scope: {', '.join(unique_mismatched)}. This deviates from expected role-based behavior."
            ))

    return alerts


def _detect_unusual_hours(activities_by_employee, emp_map):
    """Flag activity occurring outside normal business hours."""
    alerts = []

    for emp_id, acts in activities_by_employee.items():
        off_hours_count = 0
        off_hours_actions = []

        for a in acts:
            try:
                ts = str(a.get("timestamp", "")).replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts)
                hour = dt.hour
                if hour >= UNUSUAL_HOUR_START or hour < UNUSUAL_HOUR_END:
                    off_hours_count += 1
                    action_str = a.get("action", "UNKNOWN")
                    if hasattr(action_str, "value"):
                        action_str = action_str.value
                    off_hours_actions.append(action_str)
            except (ValueError, TypeError):
                continue

        if off_hours_count >= 2:
            emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
            unique_actions = list(set(off_hours_actions))[:5]
            alerts.append(AnomalyAlert(
                employee_id=emp_id,
                employee_name=emp_info["name"],
                role=emp_info["role"],
                anomaly_type=AnomalyType.UNUSUAL_HOUR,
                severity=AnomalySeverity.HIGH if off_hours_count > 5 else AnomalySeverity.WARNING,
                confidence=min(85, 40 + off_hours_count * 8),
                description=f"Detected {off_hours_count} actions outside business hours (10 PM – 6 AM) including: {', '.join(unique_actions)}. Off-hours activity from this employee warrants investigation."
            ))

    return alerts


def _detect_action_spikes(activities_by_employee, emp_map):
    """Detect statistically anomalous action frequencies using z-scores."""
    alerts = []

    # Build global frequency baseline (how often each action occurs per employee on average)
    all_counts = defaultdict(list)
    for emp_id, acts in activities_by_employee.items():
        counter = Counter()
        for a in acts:
            action_str = a.get("action", "UNKNOWN")
            if hasattr(action_str, "value"):
                action_str = action_str.value
            counter[action_str] += 1
        for action_type in counter:
            all_counts[action_type].append(counter[action_type])

    # Check each employee against the baseline
    for emp_id, acts in activities_by_employee.items():
        counter = Counter()
        for a in acts:
            action_str = a.get("action", "UNKNOWN")
            if hasattr(action_str, "value"):
                action_str = action_str.value
            counter[action_str] += 1

        spiked_actions = []
        for action_type, count in counter.items():
            baseline = all_counts.get(action_type, [])
            if len(baseline) < 2:
                continue
            m = _mean(baseline)
            s = _stddev(baseline, m)
            z = _z_score(count, m, s)
            if z >= ACTION_SPIKE_ZSCORE and count >= 3:
                spiked_actions.append((action_type, count, round(z, 1)))

        if spiked_actions:
            emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
            spike_desc = ", ".join([f"{a[0]} ({a[1]}x, z={a[2]})" for a in spiked_actions])
            alerts.append(AnomalyAlert(
                employee_id=emp_id,
                employee_name=emp_info["name"],
                role=emp_info["role"],
                anomaly_type=AnomalyType.ACTION_SPIKE,
                severity=AnomalySeverity.HIGH,
                confidence=min(90, 55 + len(spiked_actions) * 10),
                description=f"Statistical anomaly detected in action frequency: {spike_desc}. These frequencies deviate significantly (>{ACTION_SPIKE_ZSCORE}σ) from the organizational baseline."
            ))

    return alerts


def _detect_cumulative_risk(activities_by_employee, emp_map):
    """Flag employees whose cumulative risk score exceeds the threshold."""
    alerts = []

    for emp_id, acts in activities_by_employee.items():
        total_risk = 0
        for a in acts:
            total_risk += a.get("risk_score", 0)

        if total_risk >= CUMULATIVE_RISK_THRESHOLD:
            emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
            severity = AnomalySeverity.CRITICAL if total_risk >= 200 else AnomalySeverity.HIGH
            alerts.append(AnomalyAlert(
                employee_id=emp_id,
                employee_name=emp_info["name"],
                role=emp_info["role"],
                anomaly_type=AnomalyType.CUMULATIVE_RISK,
                severity=severity,
                confidence=min(95, 60 + int(total_risk / 10)),
                description=f"Cumulative risk score of {total_risk} exceeds the safety threshold of {CUMULATIVE_RISK_THRESHOLD}. The aggregated weight of this employee's actions indicates a significant insider threat concern."
            ))

    return alerts


def _detect_api_spikes(api_logs_by_employee, emp_map):
    """Detect unusual volume of API requests from a single employee."""
    alerts = []
    # If a user makes more than 50 requests in 15 minutes, it's flagged as a traffic spike
    TRAFFIC_SPIKE_THRESHOLD = 50

    for emp_id, logs in api_logs_by_employee.items():
        if emp_id == "anonymous" or emp_id == "invalid_token":
            continue

        if len(logs) > TRAFFIC_SPIKE_THRESHOLD:
            emp_info = emp_map.get(emp_id, {"name": "Unknown", "role": "Unknown"})
            # Group by paths to provide better context
            path_counts = Counter(log.get("path", "UNKNOWN") for log in logs)
            top_paths = ", ".join([f"{p} ({c}x)" for p, c in path_counts.most_common(3)])
            alerts.append(AnomalyAlert(
                employee_id=emp_id,
                employee_name=emp_info["name"],
                role=emp_info["role"],
                anomaly_type=AnomalyType.API_TRAFFIC_SPIKE,
                severity=AnomalySeverity.HIGH if len(logs) > 100 else AnomalySeverity.WARNING,
                confidence=min(99, 60 + int(len(logs) / 2)),
                description=f"Detected massive API traffic spike ({len(logs)} requests in 15 mins). Top endpoints accessed: {top_paths}. This could indicate automated scraping or enumeration."
            ))
            
    return alerts


async def _detect_ml_outliers():
    """
    Run the guarded unsupervised detector and convert its findings to alerts.

    Fails soft on purpose: this is one detector among seven, and neither a
    missing scikit-learn install nor a guard abstention should take down the
    rule-based scan. An abstention produces no alerts by design - the guards
    exist precisely so the model stays quiet when the data cannot support a
    conclusion.
    """
    alerts = []
    try:
        from app.services import ml_unsupervised

        result = await ml_unsupervised.run_detection(hours=168)

        if result.get("status") != "fitted":
            # Abstained. Log which guard fired so the reason is visible, and
            # emit nothing - silence here means "insufficient evidence".
            print(
                f"ML detector abstained [{result.get('guard')}]: "
                f"{result.get('message', '')[:160]}"
            )
            return []

        for finding in result.get("findings", []):
            alerts.append(AnomalyAlert(
                employee_id=finding["employee_id"],
                employee_name=finding["employee_name"],
                role=finding["role"],
                anomaly_type=AnomalyType.ML_OUTLIER,
                severity=(
                    AnomalySeverity.CRITICAL if finding["severity"] == "Critical"
                    else AnomalySeverity.HIGH if finding["severity"] == "High"
                    else AnomalySeverity.WARNING
                ),
                confidence=finding["confidence"],
                description=finding["description"],
            ))
    except ImportError:
        print("ML detector unavailable: scikit-learn is not installed.")
    except Exception as exc:
        print(f"ML detector error (rule-based scan continues): {exc}")

    return alerts


async def run_anomaly_scan():
    """
    Execute a full anomaly scan across all employees.
    Returns a list of AnomalyAlert objects.
    """
    emp_map = await _get_employee_map()
    activities = await _get_recent_activities(hours=24)

    # Group activities by employee
    activities_by_employee = defaultdict(list)
    for act in activities:
        emp_id = act.get("employee_id", "UNKNOWN")
        activities_by_employee[emp_id].append(act)

    api_logs = await _get_recent_api_logs(minutes=15)
    api_logs_by_employee = defaultdict(list)
    for log in api_logs:
        emp_id = log.get("identity", "UNKNOWN")
        api_logs_by_employee[emp_id].append(log)

    # Run all detection modules
    all_alerts = []
    all_alerts.extend(_detect_velocity_bursts(activities_by_employee, emp_map))
    all_alerts.extend(_detect_role_mismatches(activities_by_employee, emp_map))
    all_alerts.extend(_detect_unusual_hours(activities_by_employee, emp_map))
    all_alerts.extend(_detect_action_spikes(activities_by_employee, emp_map))
    all_alerts.extend(_detect_cumulative_risk(activities_by_employee, emp_map))
    all_alerts.extend(_detect_api_spikes(api_logs_by_employee, emp_map))
    # Learned detector, guarded against false learning. Contributes nothing
    # when its guards abstain, which is the intended behaviour.
    all_alerts.extend(await _detect_ml_outliers())

    # Deduplicate: one alert per (employee, anomaly_type) — keep highest severity
    seen = {}
    for alert in all_alerts:
        key = (alert.employee_id, alert.anomaly_type)
        if key not in seen:
            seen[key] = alert
        else:
            severity_rank = {"Critical": 3, "High": 2, "Warning": 1}
            if severity_rank.get(alert.severity.value, 0) > severity_rank.get(seen[key].severity.value, 0):
                seen[key] = alert

    return list(seen.values())


async def persist_anomaly_alerts(alerts: list[AnomalyAlert]):
    """Store anomaly alerts in MongoDB, skipping duplicates from the last hour."""
    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    inserted = 0

    for alert in alerts:
        # Check for recent duplicate
        existing = await db_instance.db["anomaly_alerts"].find_one({
            "employee_id": alert.employee_id,
            "anomaly_type": alert.anomaly_type.value,
            "timestamp": {"$gte": one_hour_ago}
        })
        if not existing:
            alert_dict = jsonable_encoder(alert)
            await db_instance.db["anomaly_alerts"].insert_one(alert_dict)
            inserted += 1

    return inserted
