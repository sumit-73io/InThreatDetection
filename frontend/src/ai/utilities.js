export const getRandomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];

export const formatDuration = (seconds) => {
    if (seconds < 60) return `${seconds} seconds`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return secs > 0 ? `${mins} minute${mins !== 1 ? 's' : ''} and ${secs} seconds` : `${mins} minute${mins !== 1 ? 's' : ''}`;
};

export const calculateDuration = (timeline) => {
    if (!timeline || timeline.length < 2) return 0;
    const sorted = [...timeline].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const first = new Date(sorted[0].timestamp);
    const last = new Date(sorted[sorted.length - 1].timestamp);
    return Math.max(0, Math.floor((last - first) / 1000));
};

export const countSuspicious = (timeline) => {
    return timeline.filter(event => (event.risk_score || 0) >= 30).length;
};
