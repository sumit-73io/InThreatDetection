import { getRandomItem } from './utilities';

const generateExecSummary = (ctx) => {
    const templates = [
        `During a ${ctx.formattedDuration} investigation window, employee ${ctx.employeeName} (${ctx.employeeId}) acting as a ${ctx.role} performed ${ctx.totalActivities} recorded activities. This included ${ctx.suspiciousActivities} suspicious events that triggered the security engine.`,
        `An investigation into the recent session of ${ctx.employeeName} (${ctx.role}, ID: ${ctx.employeeId}) reveals a total of ${ctx.totalActivities} actions over ${ctx.formattedDuration}. Notably, ${ctx.suspiciousActivities} of these activities exhibited elevated risk signatures.`,
        `Within a period of ${ctx.formattedDuration}, the system recorded ${ctx.totalActivities} total operations from ${ctx.employeeName} (${ctx.employeeId}). The analyst review notes that ${ctx.suspiciousActivities} actions were flagged as potentially suspicious.`
    ];
    return getRandomItem(templates);
};

const generateThreatAssessment = (ctx, patterns, threats, anomalies) => {
    if (threats.includes('Normal Baseline Behavior')) {
        return `The observed behavior aligns closely with standard operational patterns for a ${ctx.role}. There are no significant behavioral anomalies or indicators of compromise detected within this session.`;
    }

    let assessment = "";
    
    if (patterns.length > 0) {
        const pStr = patterns.join(', ').toLowerCase();
        const pTemplates = [
            `The sequence of activities indicates potential ${pStr}. `,
            `The collected evidence demonstrates patterns consistent with ${pStr}. `,
            `Behavioral analysis highlights actions strongly associated with ${pStr}. `
        ];
        assessment += getRandomItem(pTemplates);
    }

    if (anomalies.length > 0) {
        const aTemplates = [
            `Furthermore, the unusually compressed sequence of operations significantly deviates from expected employee behavior. `,
            `Additionally, the detection of rapid, high-risk actions suggests automated or highly anomalous execution. `,
            `The high concentration of suspicious activity further exacerbates the perceived risk. `
        ];
        assessment += getRandomItem(aTemplates);
    }

    const tStr = threats.slice(0, 2).join(' and ');
    if (tStr) {
        const tTemplates = [
            `These combined factors substantially increase the likelihood of ${tStr.toLowerCase()}.`,
            `Based on these indicators, there is a high probability of a ${tStr.toLowerCase()} incident.`,
            `The observed behavior strongly suggests attempted ${tStr.toLowerCase()}.`
        ];
        assessment += getRandomItem(tTemplates);
    }

    return assessment;
};

const generateRecommendationsText = (recommendations) => {
    if (recommendations.length === 0 || recommendations[0].includes('No immediate mitigation')) {
        return "SOC Recommendation: No immediate mitigation actions are required at this time. Standard background monitoring should continue.";
    }
    
    const introTemplates = [
        "To mitigate potential security impact, the following actions are recommended: ",
        "Based on the detected threat profile, the SOC should immediately execute the following steps: ",
        "The investigation engine recommends the following remediation procedures: "
    ];
    
    let text = getRandomItem(introTemplates);
    text += recommendations.join(" ");
    return text;
};

export const generateLanguage = (ctx, patterns, anomalies, threats, recommendations) => {
    return {
        paragraph1: generateExecSummary(ctx),
        paragraph2: generateThreatAssessment(ctx, patterns, threats, anomalies),
        paragraph3: generateRecommendationsText(recommendations)
    };
};
