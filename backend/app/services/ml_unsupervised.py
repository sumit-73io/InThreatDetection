"""
Unsupervised Insider-Threat Detection
=====================================
Adds a learned detector alongside the hand-written rules in
`anomaly_engine.py`. Two complementary unsupervised models over per-employee
behavioural feature vectors:

  IsolationForest  ranks how easily a point is isolated from the rest of the
                   population. Good at global outliers ("this employee looks
                   unlike anyone else").
  DBSCAN           density clustering; points landing in no cluster are noise.
                   Good at local outliers ("this employee is not near any
                   recognisable behavioural group").

An employee is flagged only when BOTH agree, which is the cheapest available
defence against a single model's idiosyncrasies.

--------------------------------------------------------------------------
THE FALSE-LEARNING PROBLEM
--------------------------------------------------------------------------
Unsupervised models fit whatever you hand them and report confident structure
regardless of whether any exists. On this dataset the specific failure modes
are:

  1. Tiny samples. With 4 employees, "unlike the others" is meaningless -
     every point is an outlier in some direction.
  2. Contaminated baselines. If the training window already contains the
     attack, the attack becomes normal and the detector goes quiet exactly
     when it matters.
  3. Outlier-defined scale. One extreme value stretches the feature range so
     that every other point compresses toward zero and nothing looks unusual
     again.
  4. Degenerate features. A feature that is constant across the population
     carries no information but still consumes weight and can dominate a
     distance metric after scaling.
  5. Overconfidence. A model fit on 5 points will happily emit a maximal
     anomaly score, which downstream code then renders as "Critical".

Each numbered guard below addresses one of these. They are deliberately
conservative: the design goal is that this detector stays SILENT when it has
insufficient evidence, because a false "Critical" on an employee's record is
more costly here than a missed low-confidence signal that the rule engine will
likely catch anyway.
"""

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.database.mongodb import db_instance

# ═══════════════════════════════════════════════════════════════════════════
# CAPS AND THRESHOLDS  (the anti-false-learning controls)
# ═══════════════════════════════════════════════════════════════════════════

# Guard 1 - minimum population before fitting anything at all.
# Below this, "unusual relative to peers" has no statistical meaning.
MIN_SAMPLES_TO_FIT = 8

# Sample count below which the model may run but can never escalate.
# Between MIN_SAMPLES_TO_FIT and this, findings cap at "Warning".
LOW_CONFIDENCE_SAMPLE_FLOOR = 20

# Guard 2 - contamination ceiling. IsolationForest's `contamination` is the
# assumed outlier fraction. Left high it manufactures outliers to hit the quota.
CONTAMINATION = 0.10
MAX_CONTAMINATION = 0.15

# Guard 2b - refuse to fit when the training window is already dominated by
# high-risk activity. If most of the population is behaving badly, "normal"
# is not recoverable from this data and the honest answer is to abstain.
MAX_HIGH_RISK_FRACTION = 0.40
HIGH_RISK_SCORE_THRESHOLD = 60

# Guard 3 - winsorization. Clamp each feature to its own percentile band
# BEFORE scaling, so a single extreme value cannot define the scale.
WINSOR_LOWER_PCT = 5.0
WINSOR_UPPER_PCT = 95.0

# Guard 4 - variance-collapse detection. A feature whose post-scaling standard
# deviation is below this is dropped as non-informative.
MIN_FEATURE_STDDEV = 1e-6
# If fewer than this many features survive, the fit is abandoned.
MIN_INFORMATIVE_FEATURES = 3

# Guard 5 - score and confidence ceilings.
MAX_ANOMALY_SCORE = 95          # never claim certainty
MAX_CONFIDENCE_LOW_SAMPLE = 55  # ceiling while under LOW_CONFIDENCE_SAMPLE_FLOOR
MAX_CONFIDENCE = 90

# Consensus: only flag when both models agree.
REQUIRE_MODEL_CONSENSUS = True

# Guard 6 - staleness. A fit older than this is not trusted for reporting.
MODEL_STALE_AFTER_MINUTES = 60

# DBSCAN geometry. eps is in scaled-feature space; min_samples is the
# neighbourhood size needed to form a core point.
DBSCAN_EPS = 1.8
DBSCAN_MIN_SAMPLES = 3

RANDOM_STATE = 42  # deterministic fits, so results are reproducible

FEATURE_NAMES = [
    "event_count",
    "total_risk",
    "mean_risk",
    "max_risk",
    "distinct_actions",
    "high_risk_action_count",
    "off_hours_ratio",
    "night_action_count",
    "download_count",
    "delete_count",
    "usb_count",
    "permission_change_count",
    "failed_login_count",
    "confidential_access_count",
    "actions_per_active_hour",
    "action_entropy",
]

HIGH_RISK_ACTIONS = {
    "DOWNLOAD_CONFIDENTIAL", "DELETE_FILE", "CHANGE_PERMISSION",
    "USB_CONNECTED", "FAILED_LOGIN",
}

ACTION_RISK_WEIGHTS = {
    "LOGIN": 0, "LOGOUT": 0, "VIEW_CUSTOMER": 0,
    "DOWNLOAD_FILE": 10, "DOWNLOAD_CONFIDENTIAL": 30, "USB_CONNECTED": 20,
    "FAILED_LOGIN": 15, "CHANGE_PERMISSION": 35, "DELETE_FILE": 40,
}


class ModelAbstained(Exception):
    """
    Raised when a guard refuses the fit.

    Distinct from a crash: abstaining is a valid, expected outcome that the
    caller should report as "insufficient evidence", never as an error or as
    "no anomalies found".
    """

    def __init__(self, guard: str, message: str):
        self.guard = guard
        self.message = message
        super().__init__(f"[{guard}] {message}")


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _action_of(activity: dict) -> str:
    action = activity.get("action", "")
    return action.value if hasattr(action, "value") else str(action)


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _shannon_entropy(counts: List[int]) -> float:
    """Entropy of an action distribution. Low = repetitive, high = varied."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def extract_features(activities: List[dict]) -> List[float]:
    """Reduce one employee's activity list to a fixed-length feature vector."""
    if not activities:
        return [0.0] * len(FEATURE_NAMES)

    actions = [_action_of(a) for a in activities]
    counter = Counter(actions)
    risks = [a.get("risk_score", 0) or 0 for a in activities]

    timestamps = [t for t in (_parse_ts(a.get("timestamp")) for a in activities) if t]
    off_hours = sum(1 for t in timestamps if t.hour >= 22 or t.hour < 6)
    off_hours_ratio = (off_hours / len(timestamps)) if timestamps else 0.0

    # Activity density: actions per hour of actual observed span.
    if len(timestamps) >= 2:
        span_hours = max(
            (max(timestamps) - min(timestamps)).total_seconds() / 3600.0, 0.25
        )
    else:
        span_hours = 1.0

    return [
        float(len(activities)),
        float(sum(risks)),
        float(sum(risks) / len(risks)) if risks else 0.0,
        float(max(risks)) if risks else 0.0,
        float(len(counter)),
        float(sum(c for a, c in counter.items() if a in HIGH_RISK_ACTIONS)),
        float(off_hours_ratio),
        float(off_hours),
        float(counter.get("DOWNLOAD_FILE", 0) + counter.get("DOWNLOAD_CONFIDENTIAL", 0)),
        float(counter.get("DELETE_FILE", 0)),
        float(counter.get("USB_CONNECTED", 0)),
        float(counter.get("CHANGE_PERMISSION", 0)),
        float(counter.get("FAILED_LOGIN", 0)),
        float(counter.get("DOWNLOAD_CONFIDENTIAL", 0)),
        float(len(activities) / span_hours),
        float(_shannon_entropy(list(counter.values()))),
    ]


async def build_dataset(hours: int = 168) -> Tuple[List[str], np.ndarray, Dict[str, dict]]:
    """
    Build the per-employee feature matrix from recent activity.

    Returns (employee_ids, matrix, context) where context carries the
    per-employee metadata the caller needs to describe a finding.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    cursor = db_instance.db["activities"].find(
        {"timestamp": {"$gte": cutoff}}
    ).sort("timestamp", -1).limit(20000)
    activities = await cursor.to_list(length=20000)

    emp_cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
    employees = await emp_cursor.to_list(length=1000)
    emp_meta = {
        e["employee_id"]: {"name": e.get("name", "Unknown"), "role": e.get("role", "Unknown")}
        for e in employees
    }

    grouped: Dict[str, List[dict]] = {}
    for act in activities:
        grouped.setdefault(act.get("employee_id", "UNKNOWN"), []).append(act)

    employee_ids, rows, context = [], [], {}
    for emp_id, acts in grouped.items():
        meta = emp_meta.get(emp_id, {"name": "Unknown", "role": "Unknown"})
        features = extract_features(acts)
        employee_ids.append(emp_id)
        rows.append(features)
        context[emp_id] = {
            **meta,
            "event_count": len(acts),
            "total_risk": sum(a.get("risk_score", 0) or 0 for a in acts),
            "features": dict(zip(FEATURE_NAMES, features)),
        }

    matrix = np.array(rows, dtype=float) if rows else np.empty((0, len(FEATURE_NAMES)))
    return employee_ids, matrix, context


# ═══════════════════════════════════════════════════════════════════════════
# THE GUARDS
# ═══════════════════════════════════════════════════════════════════════════

def _guard_sample_count(matrix: np.ndarray) -> None:
    """Guard 1: refuse to fit on a population too small to have a 'normal'."""
    n = matrix.shape[0]
    if n < MIN_SAMPLES_TO_FIT:
        raise ModelAbstained(
            "min_samples",
            f"Only {n} employees with recent activity; at least "
            f"{MIN_SAMPLES_TO_FIT} are required before peer comparison means "
            "anything. No model was fitted and no anomalies are being reported "
            "- this is insufficient evidence, not a clean result.",
        )


def _guard_contamination(matrix: np.ndarray, context: Dict[str, dict],
                         employee_ids: List[str]) -> float:
    """
    Guard 2b: refuse to fit when the population is already mostly high-risk.

    If the majority of the training window is compromised, the model would
    learn the compromise as the norm. Returns the contamination value to use.
    """
    high_risk = sum(
        1 for emp_id in employee_ids
        if context[emp_id]["total_risk"] >= HIGH_RISK_SCORE_THRESHOLD
    )
    fraction = high_risk / len(employee_ids) if employee_ids else 0.0

    if fraction > MAX_HIGH_RISK_FRACTION:
        raise ModelAbstained(
            "contaminated_baseline",
            f"{high_risk}/{len(employee_ids)} employees ({fraction:.0%}) are "
            f"already above the high-risk threshold, exceeding the "
            f"{MAX_HIGH_RISK_FRACTION:.0%} ceiling. Fitting here would teach the "
            "model that this elevated activity is normal and suppress future "
            "detection. Investigate the outstanding alerts and re-baseline from "
            "a clean window instead.",
        )

    return min(MAX_CONTAMINATION, max(0.01, CONTAMINATION))


def _winsorize(matrix: np.ndarray) -> Tuple[np.ndarray, int]:
    """
    Guard 3: clamp each feature into its own percentile band.

    Prevents a single extreme value from setting the scale and compressing
    every other point toward zero. Returns (clamped matrix, values clamped).
    """
    clamped = matrix.copy()
    total_clamped = 0
    for col in range(matrix.shape[1]):
        values = matrix[:, col]
        lo = np.percentile(values, WINSOR_LOWER_PCT)
        hi = np.percentile(values, WINSOR_UPPER_PCT)
        if hi <= lo:
            continue
        before = values.copy()
        clamped[:, col] = np.clip(values, lo, hi)
        total_clamped += int(np.sum(before != clamped[:, col]))
    return clamped, total_clamped


def _guard_informative_features(scaled: np.ndarray) -> Tuple[np.ndarray, List[str], List[str]]:
    """
    Guard 4: drop variance-collapsed features and abandon the fit if too few
    informative ones remain.
    """
    keep, dropped = [], []
    for idx, name in enumerate(FEATURE_NAMES):
        if float(np.std(scaled[:, idx])) > MIN_FEATURE_STDDEV:
            keep.append(idx)
        else:
            dropped.append(name)

    if len(keep) < MIN_INFORMATIVE_FEATURES:
        raise ModelAbstained(
            "variance_collapse",
            f"Only {len(keep)} of {len(FEATURE_NAMES)} features carry any "
            f"variance across this population (need {MIN_INFORMATIVE_FEATURES}). "
            "The employees are behaviourally near-identical in the recorded "
            "signals, so any 'anomaly' would be numerical noise.",
        )

    return scaled[:, keep], [FEATURE_NAMES[i] for i in keep], dropped


# ═══════════════════════════════════════════════════════════════════════════
# FIT + SCORE
# ═══════════════════════════════════════════════════════════════════════════

def _severity_for(score: float, sample_count: int) -> str:
    """
    Map a capped anomaly score to a severity.

    Guard 5: a model fitted on a small population can never reach Critical,
    no matter how extreme the score looks.
    """
    if sample_count < LOW_CONFIDENCE_SAMPLE_FLOOR:
        return "Warning"
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    return "Warning"


def _confidence_for(score: float, sample_count: int, consensus: bool) -> int:
    """Confidence, ceilinged by sample count (Guard 5)."""
    base = 40 + score * 0.5
    if not consensus:
        base *= 0.7
    ceiling = (
        MAX_CONFIDENCE_LOW_SAMPLE
        if sample_count < LOW_CONFIDENCE_SAMPLE_FLOOR else MAX_CONFIDENCE
    )
    return int(max(10, min(ceiling, base)))


def fit_and_score(
    employee_ids: List[str],
    matrix: np.ndarray,
    context: Dict[str, dict],
) -> Dict[str, Any]:
    """
    Run every guard, then fit both models and score the population.

    Raises ModelAbstained if any guard refuses. Never returns a partially
    trusted result: either the fit passed all guards or it did not happen.
    """
    _guard_sample_count(matrix)
    contamination = _guard_contamination(matrix, context, employee_ids)

    winsorized, clamped_count = _winsorize(matrix)

    scaler = StandardScaler()
    scaled_all = scaler.fit_transform(winsorized)

    scaled, kept_features, dropped_features = _guard_informative_features(scaled_all)

    n_samples = scaled.shape[0]

    # ── IsolationForest ────────────────────────────────────────────────
    forest = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=RANDOM_STATE,
        # Bounded so a small population is not bootstrapped into false
        # confidence by repeatedly resampling the same few points.
        max_samples=min(n_samples, 256),
    )
    forest_labels = forest.fit_predict(scaled)          # -1 outlier, 1 inlier
    raw_scores = forest.score_samples(scaled)           # higher = more normal

    # ── DBSCAN ─────────────────────────────────────────────────────────
    dbscan = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES)
    cluster_labels = dbscan.fit_predict(scaled)         # -1 = noise

    # Normalise IsolationForest scores to a 0-100 anomaly scale. Guard against
    # a degenerate range where every point scores identically.
    lo, hi = float(np.min(raw_scores)), float(np.max(raw_scores))
    span = hi - lo

    findings = []
    for i, emp_id in enumerate(employee_ids):
        if span < 1e-9:
            anomaly_score = 0.0
        else:
            # Invert: low score_samples = more anomalous.
            anomaly_score = float((hi - raw_scores[i]) / span * 100.0)

        # Guard 5: hard ceiling, never claim certainty.
        anomaly_score = min(MAX_ANOMALY_SCORE, max(0.0, anomaly_score))

        forest_flag = forest_labels[i] == -1
        dbscan_flag = cluster_labels[i] == -1
        consensus = forest_flag and dbscan_flag
        flagged = consensus if REQUIRE_MODEL_CONSENSUS else (forest_flag or dbscan_flag)

        if not flagged:
            continue

        ctx = context[emp_id]
        contributors = _top_contributors(scaled[i], kept_features)

        findings.append({
            "employee_id": emp_id,
            "employee_name": ctx["name"],
            "role": ctx["role"],
            "anomaly_score": round(anomaly_score, 1),
            "severity": _severity_for(anomaly_score, n_samples),
            "confidence": _confidence_for(anomaly_score, n_samples, consensus),
            "isolation_forest_outlier": bool(forest_flag),
            "dbscan_noise": bool(dbscan_flag),
            "model_consensus": bool(consensus),
            "top_contributing_features": contributors,
            "event_count": ctx["event_count"],
            "total_risk": ctx["total_risk"],
            "description": _describe(ctx, anomaly_score, contributors, n_samples),
        })

    findings.sort(key=lambda f: f["anomaly_score"], reverse=True)

    return {
        "status": "fitted",
        "fitted_at": datetime.now(timezone.utc).isoformat(),
        "samples": n_samples,
        "contamination": contamination,
        "features_used": kept_features,
        "features_dropped": dropped_features,
        "values_winsorized": clamped_count,
        "clusters_found": int(len(set(cluster_labels) - {-1})),
        "dbscan_noise_points": int(np.sum(cluster_labels == -1)),
        "low_confidence_mode": n_samples < LOW_CONFIDENCE_SAMPLE_FLOOR,
        "consensus_required": REQUIRE_MODEL_CONSENSUS,
        "findings": findings,
        "guards": _guard_report(n_samples, contamination, clamped_count, dropped_features),
    }


def _top_contributors(scaled_row: np.ndarray, feature_names: List[str], k: int = 3) -> List[dict]:
    """The features pushing this employee furthest from the population mean."""
    order = np.argsort(-np.abs(scaled_row))[:k]
    return [
        {
            "feature": feature_names[idx],
            "z_score": round(float(scaled_row[idx]), 2),
            "direction": "above" if scaled_row[idx] > 0 else "below",
        }
        for idx in order
    ]


def _describe(ctx: dict, score: float, contributors: List[dict], n_samples: int) -> str:
    """Human-readable finding, honest about the confidence caps in play."""
    parts = ", ".join(
        f"{c['feature'].replace('_', ' ')} {c['direction']} peer norm "
        f"({c['z_score']:+.1f}σ)"
        for c in contributors
    )
    text = (
        f"Unsupervised models place {ctx['name']} outside the normal behavioural "
        f"cluster for this population (anomaly score {score:.0f}/100, agreed by "
        f"both Isolation Forest and DBSCAN). Strongest deviations: {parts}."
    )
    if n_samples < LOW_CONFIDENCE_SAMPLE_FLOOR:
        text += (
            f" Confidence is capped because the model was fitted on only "
            f"{n_samples} employees, which is below the "
            f"{LOW_CONFIDENCE_SAMPLE_FLOOR}-sample floor for full confidence; "
            "treat this as a lead to corroborate, not a conclusion."
        )
    return text


def _guard_report(n_samples: int, contamination: float,
                  clamped: int, dropped: List[str]) -> List[dict]:
    """Explicit record of which guards engaged, for the UI and the audit trail."""
    return [
        {
            "guard": "min_samples",
            "status": "passed",
            "detail": f"{n_samples} samples (floor {MIN_SAMPLES_TO_FIT})",
        },
        {
            "guard": "contamination_ceiling",
            "status": "passed",
            "detail": f"contamination capped at {contamination:.0%} (max {MAX_CONTAMINATION:.0%})",
        },
        {
            "guard": "winsorization",
            "status": "applied" if clamped else "no-op",
            "detail": (
                f"{clamped} feature values clamped to the "
                f"P{WINSOR_LOWER_PCT:.0f}-P{WINSOR_UPPER_PCT:.0f} band before scaling"
            ),
        },
        {
            "guard": "variance_collapse",
            "status": "applied" if dropped else "no-op",
            "detail": (
                f"dropped non-informative features: {', '.join(dropped)}"
                if dropped else "all features carried variance"
            ),
        },
        {
            "guard": "confidence_ceiling",
            "status": "active" if n_samples < LOW_CONFIDENCE_SAMPLE_FLOOR else "inactive",
            "detail": (
                f"severity capped at Warning and confidence at "
                f"{MAX_CONFIDENCE_LOW_SAMPLE}% below {LOW_CONFIDENCE_SAMPLE_FLOOR} samples"
                if n_samples < LOW_CONFIDENCE_SAMPLE_FLOOR
                else f"full confidence range available (max {MAX_CONFIDENCE}%)"
            ),
        },
        {
            "guard": "model_consensus",
            "status": "active" if REQUIRE_MODEL_CONSENSUS else "inactive",
            "detail": "a finding requires both Isolation Forest and DBSCAN to agree",
        },
    ]


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════

# Last successful run, so /status can report staleness without refitting.
_last_run: Optional[Dict[str, Any]] = None


async def run_detection(hours: int = 168) -> Dict[str, Any]:
    """
    Build the dataset, run the guarded fit and return findings.

    On abstention returns a structured `status: "abstained"` payload naming the
    guard and explaining what to do about it. Callers must distinguish this from
    an empty findings list: abstained means "we do not know", not "all clear".
    """
    global _last_run

    employee_ids, matrix, context = await build_dataset(hours=hours)

    if not employee_ids:
        return {
            "status": "abstained",
            "guard": "no_data",
            "message": (
                f"No employee activity in the last {hours} hours, so there is "
                "nothing to model."
            ),
            "findings": [],
            "samples": 0,
        }

    try:
        result = fit_and_score(employee_ids, matrix, context)
    except ModelAbstained as abstention:
        return {
            "status": "abstained",
            "guard": abstention.guard,
            "message": abstention.message,
            "findings": [],
            "samples": int(matrix.shape[0]),
            "window_hours": hours,
        }

    result["window_hours"] = hours
    _last_run = result
    return result


def get_last_run_status() -> Dict[str, Any]:
    """Report the most recent fit and whether it is stale (Guard 6)."""
    if _last_run is None:
        return {
            "status": "never_fitted",
            "message": "The unsupervised detector has not been run in this process yet.",
            "stale": True,
        }

    fitted_at = _parse_ts(_last_run["fitted_at"])
    age_minutes = (
        (datetime.now(timezone.utc) - fitted_at).total_seconds() / 60.0
        if fitted_at else float("inf")
    )
    stale = age_minutes > MODEL_STALE_AFTER_MINUTES

    return {
        "status": "fitted",
        "fitted_at": _last_run["fitted_at"],
        "age_minutes": round(age_minutes, 1),
        "stale": stale,
        "stale_after_minutes": MODEL_STALE_AFTER_MINUTES,
        "samples": _last_run["samples"],
        "findings_count": len(_last_run["findings"]),
        "low_confidence_mode": _last_run["low_confidence_mode"],
        "guards": _last_run["guards"],
        "message": (
            f"Last fit is {age_minutes:.0f} minutes old and considered stale; "
            "re-run before relying on these findings."
            if stale else "Model fit is current."
        ),
    }


def get_configuration() -> Dict[str, Any]:
    """The active caps, so the UI can show what the detector will and won't do."""
    return {
        "min_samples_to_fit": MIN_SAMPLES_TO_FIT,
        "low_confidence_sample_floor": LOW_CONFIDENCE_SAMPLE_FLOOR,
        "contamination": CONTAMINATION,
        "max_contamination": MAX_CONTAMINATION,
        "max_high_risk_fraction": MAX_HIGH_RISK_FRACTION,
        "winsor_band": [WINSOR_LOWER_PCT, WINSOR_UPPER_PCT],
        "min_informative_features": MIN_INFORMATIVE_FEATURES,
        "max_anomaly_score": MAX_ANOMALY_SCORE,
        "max_confidence": MAX_CONFIDENCE,
        "max_confidence_low_sample": MAX_CONFIDENCE_LOW_SAMPLE,
        "require_model_consensus": REQUIRE_MODEL_CONSENSUS,
        "model_stale_after_minutes": MODEL_STALE_AFTER_MINUTES,
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "models": ["IsolationForest", "DBSCAN"],
    }
