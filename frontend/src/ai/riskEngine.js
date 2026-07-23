export const calculateCumulativeRisk = (timeline) => {
    let totalRisk = 0;
    timeline.forEach(event => {
        totalRisk += event.risk_score || 0;
    });
    return totalRisk;
};
