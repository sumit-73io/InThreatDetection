import { calculateDuration, countSuspicious, formatDuration } from './utilities';

export const analyzeSession = (timeline, employee) => {
    const totalActivities = timeline.length;
    const suspiciousActivities = countSuspicious(timeline);
    const durationSecs = calculateDuration(timeline);
    
    // Determine highest risk action
    let highestRiskAction = null;
    let maxRisk = 0;
    timeline.forEach(event => {
        if ((event.risk_score || 0) > maxRisk) {
            maxRisk = event.risk_score;
            highestRiskAction = event.action || 'Unknown';
        }
    });

    const activityDensity = durationSecs > 0 ? (totalActivities / durationSecs) : totalActivities;

    return {
        totalActivities,
        suspiciousActivities,
        durationSecs,
        formattedDuration: formatDuration(durationSecs),
        highestRiskAction,
        activityDensity,
        employeeId: employee.id || employee.employee_id || 'Unknown',
        employeeName: employee.name || 'Unknown',
        role: employee.role || 'Employee',
        department: employee.department || 'General'
    };
};
