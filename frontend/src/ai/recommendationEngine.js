import { getRandomItem } from './utilities';

export const generateRecommendations = (threats, sessionContext) => {
    const recs = new Set();
    
    threats.forEach(threat => {
        switch (threat) {
            case 'Data Exfiltration':
            case 'Insider Threat':
                recs.add('Isolate the endpoint immediately to prevent further data loss.');
                recs.add('Audit all recently downloaded and exported files.');
                recs.add('Inspect removable media activity and block external USBs.');
                break;
            case 'Privilege Escalation':
                recs.add('Review all recent permission modifications and role assignments.');
                recs.add('Suspend the user account pending an administrative review.');
                break;
            case 'Credential Theft':
            case 'Brute Force Attack':
                recs.add('Force an immediate password reset and invalidate active sessions.');
                recs.add('Verify multi-factor authentication (MFA) logs for bypass attempts.');
                break;
            case 'Automated Malicious Behavior':
                recs.add('Preserve forensic evidence for deeper malware analysis.');
                recs.add('Implement aggressive rate-limiting on this endpoint.');
                break;
            case 'Policy Violation':
            case 'Anomalous Usage':
                recs.add('Increase monitoring and logging for this specific user.');
                recs.add('Escalate the incident to the Security Operations Center (SOC) tier 2 analyst.');
                break;
            default:
                break;
        }
    });

    if (recs.size === 0) {
        recs.add('No immediate mitigation actions are required at this time. Standard background monitoring should continue.');
    }

    const finalRecs = Array.from(recs);
    for (let i = finalRecs.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [finalRecs[i], finalRecs[j]] = [finalRecs[j], finalRecs[i]];
    }
    
    return finalRecs.slice(0, 4);
};
