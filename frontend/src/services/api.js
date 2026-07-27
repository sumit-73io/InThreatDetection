import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000/api',
});

// helper to grab token from local storage
const getAuthHeaders = () => {
    const token = localStorage.getItem('InthreatDetection_token'); 
    return { headers: { Authorization: `Bearer ${token}` } };
};

// Auth API call
export const loginAdmin = async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    return response.data;
};

// Manual operator override: freeze an account.
// PRIVILEGED — needs employees:block plus an active PAM elevation window,
// otherwise the server responds 403 with guidance to request elevation.
export const blockEmployee = async (employeeId, reason = '', hours = 24) => {
    const response = await api.post(
        `/employees/${employeeId}/block`,
        { reason, hours },
        getAuthHeaders()
    );
    return response.data;
};

// Manual operator override: release an account. Same privileged gate.
export const unblockEmployee = async (employeeId, reason = '') => {
    const response = await api.post(
        `/employees/${employeeId}/unblock`,
        { reason },
        getAuthHeaders()
    );
    return response.data;
};

// simulator checks if employee is blocked (public)
export const checkEmployeeStatus = async (employeeId) => {
    const response = await api.get(`/employees/${employeeId}/status`);
    return response.data;
};

// to protected routes
export const getActivities = async () => {
    const response = await api.get('/dashboard/activities', getAuthHeaders());
    return response.data;
};

export const getAlerts = async () => {
    const response = await api.get('/dashboard/alerts', getAuthHeaders());
    return response.data;
};

export const logActivity = async (action, employeeId) => {
    // We removed the default "EMP-001" - it now REQUIRES the logged-in ID
    const response = await api.post('/activities/', {
        employee_id: employeeId,
        action: action,
    });
    return response.data;
};

// admin creates an employee
export const createEmployee = async (employeeId, name, password, role) => {
    const response = await api.post('/employees/create', { 
        employee_id: employeeId, 
        name: name,
        password: password,
        role: role  //Pass the role to the backend
    }, getAuthHeaders());
    return response.data;
};

// fetch employee directory for role mapping
export const getEmployees = async () => {
    const response = await api.get('/employees/', getAuthHeaders());
    return response.data;
};

// employee logs into simulator
export const loginEmployee = async (employeeId, password) => {
    const response = await api.post('/employees/login', { 
        employee_id: employeeId, 
        password: password 
    });
    return response.data;
};



// ─── Quantum Security APIs ──────────────────────────────────────────

// Get quantum crypto engine status
export const getQuantumStatus = async () => {
    const response = await api.get('/quantum/status', getAuthHeaders());
    return response.data;
};

// Get aggregate integrity statistics
export const getIntegrityStats = async () => {
    const response = await api.get('/quantum/integrity/stats', getAuthHeaders());
    return response.data;
};

// Run full integrity verification scan
export const runIntegrityVerification = async () => {
    const response = await api.get('/quantum/integrity/verify', getAuthHeaders());
    return response.data;
};

// ─── Anomaly Detection APIs ─────────────────────────────────────────

// Fetch all anomaly alerts
export const getAnomalyAlerts = async () => {
    const response = await api.get('/anomaly/alerts', getAuthHeaders());
    return response.data;
};

// Trigger a full anomaly scan
export const triggerAnomalyScan = async () => {
    const response = await api.post('/anomaly/scan', {}, getAuthHeaders());
    return response.data;
};

// Acknowledge (dismiss) an anomaly alert
export const acknowledgeAnomalyAlert = async (alertId) => {
    const response = await api.patch(`/anomaly/alerts/${alertId}/acknowledge`, {}, getAuthHeaders());
    return response.data;
};


// ─── AI Twin APIs ───────────────────────────────────────────────────

// Fetch all AI Twin profile summaries
export const getAiTwinProfiles = async () => {
    const response = await api.get('/ai-twin/profiles', getAuthHeaders());
    return response.data;
};

// Fetch a single employee's full AI Twin profile
export const getAiTwinProfile = async (employeeId) => {
    const response = await api.get(`/ai-twin/profile/${employeeId}`, getAuthHeaders());
    return response.data;
};

// Fetch all AI Twin deviation alerts
export const getAiTwinAlerts = async () => {
    const response = await api.get('/ai-twin/alerts', getAuthHeaders());
    return response.data;
};

// Get threat score for a single employee
export const getAiTwinScore = async (employeeId) => {
    const response = await api.get(`/ai-twin/score/${employeeId}`, getAuthHeaders());
    return response.data;
};

// Initialize (or re-initialize) AI Twin for an employee
export const initializeAiTwin = async (employeeId) => {
    const response = await api.post(`/ai-twin/initialize/${employeeId}`, {}, getAuthHeaders());
    return response.data;
};

// Reset an employee's AI Twin back to training
export const resetAiTwin = async (employeeId) => {
    const response = await api.post(`/ai-twin/reset/${employeeId}`, {}, getAuthHeaders());
    return response.data;
};

// Inject a synthetic behavioural event (for testing / demo)
export const simulateAiTwinEvent = async (payload) => {
    const response = await api.post('/ai-twin/simulate-event', payload, getAuthHeaders());
    return response.data;
};

// Acknowledge an AI Twin alert
export const acknowledgeAiTwinAlert = async (alertId) => {
    const response = await api.patch(`/ai-twin/alerts/${alertId}/acknowledge`, {}, getAuthHeaders());
    return response.data;
};

// Get AI Twin system status
export const getAiTwinStatus = async () => {
    const response = await api.get('/ai-twin/status', getAuthHeaders());
    return response.data;
};

// Train Normal Behaviour Baseline
export const trainNormalAiTwin = async (payload) => {
    const response = await api.post('/ai-twin/train-normal', payload, getAuthHeaders());
    return response.data;
};


// ─── Identity, RBAC & PAM APIs ──────────────────────────────────────

// Who am I: role, effective permissions and any open elevation sessions
export const getMe = async () => {
    const response = await api.get('/auth/me', getAuthHeaders());
    return response.data;
};

// The full role/permission matrix plus the caller's own grants
export const getRoleMatrix = async () => {
    const response = await api.get('/access/roles', getAuthHeaders());
    return response.data;
};

// Open a just-in-time elevation request for privileged permissions
export const requestElevation = async (permissions, justification, durationMinutes = 15) => {
    const response = await api.post('/access/pam/request', {
        permissions,
        justification,
        duration_minutes: durationMinutes,
    }, getAuthHeaders());
    return response.data;
};

// Approve a pending elevation request (requires pam:approve)
export const approveElevation = async (requestId) => {
    const response = await api.post(`/access/pam/${requestId}/approve`, {}, getAuthHeaders());
    return response.data;
};

// Deny a pending elevation request (requires pam:approve)
export const denyElevation = async (requestId, reason = '') => {
    const response = await api.post(`/access/pam/${requestId}/deny`, { reason }, getAuthHeaders());
    return response.data;
};

// Give up / close an elevation window early
export const revokeElevation = async (requestId, reason = '') => {
    const response = await api.post(`/access/pam/${requestId}/revoke`, { reason }, getAuthHeaders());
    return response.data;
};

// List elevation requests (scoped server-side to self unless approver/auditor)
export const getElevationRequests = async (status) => {
    const response = await api.get('/access/pam/requests', {
        ...getAuthHeaders(),
        params: status ? { status } : {},
    });
    return response.data;
};

// The caller's currently-open elevation sessions
export const getActiveElevations = async () => {
    const response = await api.get('/access/pam/active', getAuthHeaders());
    return response.data;
};

// Read the PAM audit trail (requires pam:audit:read)
export const getPamAuditLog = async (limit = 200) => {
    const response = await api.get('/access/pam/audit', {
        ...getAuthHeaders(),
        params: { limit },
    });
    return response.data;
};

// Counts and policy limits for the access-control panel
export const getPamSummary = async () => {
    const response = await api.get('/access/pam/summary', getAuthHeaders());
    return response.data;
};


// ─── Baseline & Enforcement APIs ────────────────────────────────────

// Baseline coverage counts and active policy thresholds
export const getBaselineSummary = async () => {
    const response = await api.get('/baseline/summary', getAuthHeaders());
    return response.data;
};

// All stored normal-environment baselines
export const getBaselines = async () => {
    const response = await api.get('/baseline/', getAuthHeaders());
    return response.data;
};

// One baseline by scope ('employee' | 'role') and identifier
export const getBaseline = async (scope, identifier) => {
    const response = await api.get(`/baseline/${scope}/${identifier}`, getAuthHeaders());
    return response.data;
};

// Dry-run a deviation evaluation — does NOT log an activity or enforce
export const evaluateDeviation = async (employeeId, action) => {
    const response = await api.get(`/baseline/evaluate/${employeeId}`, {
        ...getAuthHeaders(),
        params: { action },
    });
    return response.data;
};

// Build one baseline. Response status is 'built' | 'locked' | 'refused'
export const buildBaseline = async (scope, identifier, windowDays = 30) => {
    const response = await api.post('/baseline/build', {
        scope, identifier, window_days: windowDays,
    }, getAuthHeaders());
    return response.data;
};

// Recompute every baseline; locked ones are skipped
export const rebuildAllBaselines = async (windowDays = 30) => {
    const response = await api.post('/baseline/rebuild-all', {}, {
        ...getAuthHeaders(),
        params: { window_days: windowDays },
    });
    return response.data;
};

// Lock/unlock a baseline. PRIVILEGED — needs baseline:manage plus elevation
export const setBaselineLock = async (scope, identifier, locked) => {
    const response = await api.post('/baseline/lock', {
        scope, identifier, locked,
    }, getAuthHeaders());
    return response.data;
};

// Thresholds governing automated freezing
export const getEnforcementPolicy = async () => {
    const response = await api.get('/baseline/enforcement/policy', getAuthHeaders());
    return response.data;
};

// Recent automated enforcement actions with triggers and evidence
export const getEnforcementActions = async (limit = 100) => {
    const response = await api.get('/baseline/enforcement/actions', {
        ...getAuthHeaders(),
        params: { limit },
    });
    return response.data;
};


// ─── Enforcement Override APIs ──────────────────────────────────────
// An override authorises behaviour that automated enforcement would otherwise
// punish, bounded by time and/or an event budget. It never grants a permission.

// Grant a bounded override. PRIVILEGED — needs overrides:manage + elevation.
// Pass allowedActions = null/[] to cover ALL actions.
export const grantOverride = async ({
    employeeId,
    reason,
    exemptBlock = true,
    allowedActions = null,
    durationMinutes = 60,
    maxEvents = null,
}) => {
    const response = await api.post('/overrides/grant', {
        employee_id: employeeId,
        reason,
        exempt_block: exemptBlock,
        allowed_actions: allowedActions,
        duration_minutes: durationMinutes,
        max_events: maxEvents,
    }, getAuthHeaders());
    return response.data;
};

// Close an override early. Same privileged gate as granting.
export const revokeOverride = async (overrideId, reason = '') => {
    const response = await api.post(`/overrides/${overrideId}/revoke`, { reason }, getAuthHeaders());
    return response.data;
};

// Every live override keyed by employee_id — one call for the whole table
export const getActiveOverrides = async () => {
    const response = await api.get('/overrides/active', getAuthHeaders());
    return response.data;
};

// Override history, optionally scoped to one employee
export const getOverrideHistory = async (employeeId) => {
    const response = await api.get('/overrides/', {
        ...getAuthHeaders(),
        params: employeeId ? { employee_id: employeeId } : {},
    });
    return response.data;
};

// Caps, defaults and counts
export const getOverridePolicy = async () => {
    const response = await api.get('/overrides/policy', getAuthHeaders());
    return response.data;
};


// ─── Unsupervised ML APIs ───────────────────────────────────────────

// Active caps and thresholds for the detector
export const getMlConfig = async () => {
    const response = await api.get('/ml/config', getAuthHeaders());
    return response.data;
};

// Last fit, its age, and whether it is stale
export const getMlStatus = async () => {
    const response = await api.get('/ml/status', getAuthHeaders());
    return response.data;
};

// Run detection. status is 'fitted' or 'abstained' — an abstention means the
// guards refused to fit, NOT that nothing was found.
export const runMlDetection = async (hours = 168) => {
    const response = await api.post('/ml/detect', {}, {
        ...getAuthHeaders(),
        params: { hours },
    });
    return response.data;
};

// The per-employee feature vectors the model actually sees
export const getMlFeatures = async (hours = 168) => {
    const response = await api.get('/ml/features', {
        ...getAuthHeaders(),
        params: { hours },
    });
    return response.data;
};