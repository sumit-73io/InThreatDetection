export const inferThreats = (patterns, anomalies, sessionContext) => {
    const threats = new Set();

    patterns.forEach(p => {
        if (p.includes('Data Exfiltration') || p.includes('Bulk Data')) {
            threats.add('Data Exfiltration');
            threats.add('Insider Threat');
        }
        if (p.includes('Privilege')) {
            threats.add('Privilege Escalation');
        }
        if (p.includes('Failed Logins')) {
            threats.add('Credential Theft');
            threats.add('Brute Force Attack');
        }
    });

    anomalies.forEach(a => {
        if (a.includes('Automation')) threats.add('Automated Malicious Behavior');
        if (a.includes('concentration')) threats.add('Policy Violation');
    });

    if (threats.size === 0) {
        if (sessionContext.suspiciousActivities > 0) {
            threats.add('Anomalous Usage');
        } else {
            threats.add('Normal Baseline Behavior');
        }
    }

    return Array.from(threats);
};
