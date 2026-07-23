export const analyzeBehaviour = (sessionContext, patterns) => {
    const anomalies = [];

    if (sessionContext.activityDensity > 2) {
        anomalies.push('Rapid High-Risk Actions (Possible Automation)');
    }
    if (sessionContext.suspiciousActivities > (sessionContext.totalActivities * 0.4) && sessionContext.totalActivities > 5) {
        anomalies.push('High concentration of suspicious activity');
    }

    return {
        anomalies,
        isHighlyAbnormal: anomalies.length > 0 || patterns.length > 1
    };
};
