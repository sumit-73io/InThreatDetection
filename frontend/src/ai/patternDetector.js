export const detectPatterns = (timeline) => {
    const events = [...timeline].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const eventNames = events.map(e => e.action || '');
    const patterns = [];

    const hasConfidentialAccess = eventNames.some(e => e.includes('Confidential') || e.includes('Database'));
    const hasUSB = eventNames.some(e => e.includes('USB') || e.includes('Removable'));
    const hasDownload = eventNames.some(e => e.includes('Download') || e.includes('Export'));
    const hasFailedLogin = eventNames.filter(e => e.includes('Failed Login') || e.includes('Auth Error')).length > 2;
    const hasPermissionMod = eventNames.some(e => e.includes('Permission') || e.includes('Role') || e.includes('Privilege'));
    const hasLateNight = events.some(e => {
        const hour = new Date(e.timestamp).getHours();
        return hour < 6 || hour > 22;
    });

    if (hasUSB && (hasConfidentialAccess || hasDownload)) {
        patterns.push('Possible Data Exfiltration via USB');
    }
    if (eventNames.filter(e => e.includes('Confidential')).length > 3) {
        patterns.push('Repeated Confidential Access');
    }
    if (hasFailedLogin) {
        patterns.push('Multiple Failed Logins');
    }
    if (hasPermissionMod && eventNames.some(e => e.includes('Admin'))) {
        patterns.push('Possible Privilege Escalation');
    }
    if (eventNames.filter(e => e.includes('Download')).length > 4) {
        patterns.push('Bulk Data Collection');
    }
    if (hasLateNight) {
        patterns.push('Off-Hours Activity');
    }

    return patterns;
};
