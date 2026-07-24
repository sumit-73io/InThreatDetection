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