import { analyzeSession } from './sessionAnalyzer';
import { detectPatterns } from './patternDetector';
import { analyzeBehaviour } from './behaviourAnalyzer';
import { inferThreats } from './threatInference';
import { generateRecommendations } from './recommendationEngine';
import { generateLanguage } from './languageEngine';

export const generateReport = (timeline, employee) => {
    // 1. Session Analysis
    const sessionContext = analyzeSession(timeline, employee);

    // 2. Pattern Detection
    const patterns = detectPatterns(timeline);

    // 3. Behaviour Analysis
    const behaviourContext = analyzeBehaviour(sessionContext, patterns);

    // 4. Threat Inference
    const threats = inferThreats(patterns, behaviourContext.anomalies, sessionContext);

    // 5. Recommendation Engine
    const recommendations = generateRecommendations(threats, sessionContext);

    // 6. Language Generation (NL generation)
    const reportParts = generateLanguage(sessionContext, patterns, behaviourContext.anomalies, threats, recommendations);

    // Compile the final 3-paragraph text
    return `${reportParts.paragraph1}\n\n${reportParts.paragraph2}\n\n${reportParts.paragraph3}`;
};
