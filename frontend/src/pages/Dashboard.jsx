import React, { useEffect, useState } from 'react';
import { getActivities, getAlerts, getEmployees, blockEmployee, unblockEmployee,
         getActiveOverrides, revokeOverride } from '../services/api';
import { triggerAnomalyScan } from '../services/api';
import { generateReport } from '../ai/reportGenerator';
import IntegrityBadge from '../components/IntegrityBadge';
import ElevationModal from '../components/ElevationModal';
import OverrideModal from '../components/OverrideModal';
import RiskCharts from '../components/RiskCharts';
import * as Icon from '../components/Icons';
import { useAuth } from '../contexts/AuthContext';

// Privileged permission behind the manual block/unblock override.
const BLOCK_PERMISSION = 'employees:block';
const OVERRIDE_PERMISSION = 'overrides:manage';

function timeAgo(dateParam) {
    if (!dateParam) return 'Unknown';
    let validDateString = dateParam;
    if (typeof validDateString === 'string' && !validDateString.endsWith('Z')) {
        validDateString += 'Z';
    }
    const date = new Date(validDateString);
    const today = new Date();
    const diffInSeconds = Math.floor((today - date) / 1000);
    if (diffInSeconds < 60) return 'Just now';
    const minutes = Math.floor(diffInSeconds / 60);
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} hr ago`;
    const days = Math.floor(hours / 24);
    return `${days} days ago`;
}

function formatTime(dateParam) {
    if (!dateParam) return '';
    let validDateString = dateParam;
    if (typeof validDateString === 'string' && !validDateString.endsWith('Z')) {
        validDateString += 'Z';
    }
    return new Date(validDateString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatActionString(actionStr) {
    if (!actionStr) return 'None';
    return actionStr.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()).join(' ');
}

export default function Dashboard({ isDark, anomalyAlerts = [], onAnomalyRefresh }) {
    // Core State
    const [activities, setActivities] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [employeeDirectory, setEmployeeDirectory] = useState({});
    const [loading, setLoading] = useState(true);
    
    // UI State
    const [selectedUser, setSelectedUser] = useState(null);
    const [isAnomalyExpanded, setIsAnomalyExpanded] = useState(true);
    
    // AI State
    const [aiLoading, setAiLoading] = useState(false);
    const [aiReport, setAiReport] = useState(null);

    // Metric Drill-Down State
    const [metricModal, setMetricModal] = useState(null); // { title, color, items, type }

    // Block / override state
    const [blockLoading, setBlockLoading] = useState(null); // employee_id in flight
    const [blockError, setBlockError] = useState(null);
    const [elevationPrompt, setElevationPrompt] = useState(null); // { permissions, reason }
    const [overrideTarget, setOverrideTarget] = useState(null);   // employee row
    const [activeOverrides, setActiveOverrides] = useState({});   // employee_id -> override

    // Authorization: `can` decides whether the override is rendered at all,
    // `isElevated` decides whether it is armed. Both are re-checked server-side.
    const { can, isElevated, activeElevations, refresh: refreshAuth } = useAuth();
    const mayBlock = can(BLOCK_PERMISSION);
    const blockArmed = isElevated(BLOCK_PERMISSION);
    const mayOverride = can(OVERRIDE_PERMISSION);
    const overrideArmed = isElevated(OVERRIDE_PERMISSION);
    const blockElevation = activeElevations.find(
        (e) => (e.permissions || []).includes(BLOCK_PERMISSION)
    );

    const fetchDashboardData = async () => {
        try {
            const actData = await getActivities();
            const alertData = await getAlerts();
            const empData = await getEmployees();
            
            const empMap = {};
            empData.forEach(emp => {
                empMap[emp.employee_id] = {
                    role: emp.role,
                    name: emp.name || 'Unknown Name',
                    is_blocked: emp.is_blocked || false
                };
            });
            
            setEmployeeDirectory(empMap);
            setActivities(actData);
            setAlerts(alertData);

            // Live enforcement overrides, so the table can show which employees
            // are operating under an authorised exception.
            try {
                const ov = await getActiveOverrides();
                setActiveOverrides(ov.active || {});
            } catch {
                // Non-fatal: the table just won't badge overrides.
            }
        } catch (err) {
            console.error("Failed to sync SOC feeds", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDashboardData();
        const interval = setInterval(fetchDashboardData, 3000); 
        return () => clearInterval(interval);
    }, []);

    /**
     * Manual operator override: freeze or release an account.
     *
     * Privileged, so there are three outcomes rather than two:
     *   - no elevation open  -> open the elevation dialog instead of calling
     *   - elevation open     -> perform the action
     *   - server still 403s  -> the window expired between render and click,
     *                           so re-prompt rather than showing a raw error
     */
    const handleToggleBlock = async (employeeId, isCurrentlyBlocked, userName) => {
        const verb = isCurrentlyBlocked ? 'unblock' : 'block';

        if (!blockArmed) {
            setElevationPrompt({
                reason: `Manual ${verb} of ${userName || employeeId} from the SOC dashboard`,
            });
            return;
        }

        setBlockError(null);
        setBlockLoading(employeeId);
        try {
            const reason = `Manual ${verb} by SOC operator from risk dashboard`;
            if (isCurrentlyBlocked) {
                await unblockEmployee(employeeId, reason);
            } else {
                await blockEmployee(employeeId, reason);
            }
            await fetchDashboardData();

            if (selectedUser && selectedUser.id === employeeId) {
                setSelectedUser(prev => ({ ...prev, is_blocked: !isCurrentlyBlocked }));
            }
        } catch (err) {
            if (err?.response?.status === 403) {
                // Elevation lapsed mid-interaction. Re-arm instead of erroring.
                await refreshAuth();
                setElevationPrompt({
                    reason: `Manual ${verb} of ${userName || employeeId} from the SOC dashboard`,
                });
            } else {
                setBlockError(
                    err?.response?.data?.detail || `Failed to ${verb} ${employeeId}.`
                );
            }
        } finally {
            setBlockLoading(null);
        }
    };

    /** Open the override dialog, elevating first if the window is closed. */
    const handleAuthorizeException = (user) => {
        if (!overrideArmed) {
            setElevationPrompt({
                permissions: [OVERRIDE_PERMISSION],
                reason: `Authorise an enforcement exception for ${user.name || user.id}`,
                then: () => setOverrideTarget(user),
            });
            return;
        }
        setOverrideTarget(user);
    };

    const handleRevokeOverride = async (user) => {
        const ov = activeOverrides[user.id];
        if (!ov) return;
        if (!overrideArmed) {
            setElevationPrompt({
                permissions: [OVERRIDE_PERMISSION],
                reason: `Revoke the enforcement exception for ${user.name || user.id}`,
                then: () => handleRevokeOverride(user),
            });
            return;
        }
        setBlockError(null);
        try {
            await revokeOverride(ov.override_id, 'Revoked from the SOC risk dashboard');
            await fetchDashboardData();
        } catch (err) {
            setBlockError(err?.response?.data?.detail || 'Failed to revoke the override.');
        }
    };

    const processUserData = () => {
        const usersMap = {};

        // Initialize all provisioned users
        Object.keys(employeeDirectory).forEach(empId => {
            usersMap[empId] = {
                id: empId,
                name: employeeDirectory[empId].name,
                role: employeeDirectory[empId].role,
                totalRisk: 0,
                lastActivityDate: null, 
                lastAction: 'No Activity',
                timeline: [],
                integrityStatus: 'unverified',
                is_blocked: employeeDirectory[empId].is_blocked
            };
        });

        // Add activity data
        activities.forEach(act => {
            if (!usersMap[act.employee_id]) {
                usersMap[act.employee_id] = {
                    id: act.employee_id,
                    name: employeeDirectory[act.employee_id]?.name || 'Unknown Name',
                    role: employeeDirectory[act.employee_id]?.role || 'Unknown Role',
                    totalRisk: 0,
                    lastActivityDate: null,
                    lastAction: 'No Activity',
                    timeline: [],
                    integrityStatus: 'unverified',
                    is_blocked: employeeDirectory[act.employee_id]?.is_blocked || false
                };
            }
            
            usersMap[act.employee_id].totalRisk += act.risk_score;
            usersMap[act.employee_id].timeline.push(act);
            
            // Track worst integrity status for the user
            if (act.integrity_verified === 'tampered') {
                usersMap[act.employee_id].integrityStatus = 'tampered';
            } else if (act.integrity_verified === 'verified' && usersMap[act.employee_id].integrityStatus !== 'tampered') {
                usersMap[act.employee_id].integrityStatus = 'verified';
            }
            
            if (!usersMap[act.employee_id].lastActivityDate || new Date(act.timestamp) > new Date(usersMap[act.employee_id].lastActivityDate)) {
                usersMap[act.employee_id].lastActivityDate = act.timestamp;
                usersMap[act.employee_id].lastAction = formatActionString(act.action);
                usersMap[act.employee_id].lastIntegrityStatus = act.integrity_verified;
            }
        });

        // Calculate Risk Levels & Sort
        return Object.values(usersMap).map(user => {
            let level = 'Low';
            if (user.totalRisk >= 60) level = 'High';
            else if (user.totalRisk >= 30) level = 'Medium';
            return { ...user, riskLevel: level, barWidth: Math.min(user.totalRisk, 100) };
        }).sort((a, b) => b.totalRisk - a.totalRisk);
    };

    const aggregatedUsers = processUserData();

    // Metric Calculations
    const totalEvents = activities.length;
    const blockedEscalatedItems = alerts.filter(a => a.level === 'Critical' || a.level === 'High');
    const stepUpAuthItems      = alerts.filter(a => a.level === 'Warning');
    const allowedEventItems    = activities.filter(a => a.risk_score < 30);
    const blockedEscalated = blockedEscalatedItems.length;
    const stepUpAuth       = stepUpAuthItems.length;
    const allowedEvents    = allowedEventItems.length;
    const usersMonitored   = aggregatedUsers.length;

    // Integrity metrics now live on the Quantum Security page. The per-row
    // IntegrityBadge stays here because record trustworthiness is relevant while
    // investigating a specific user.

    if (loading) return <div className={`p-8 font-medium min-h-screen ${isDark ? 'bg-[#15171e] text-gray-500' : 'bg-[#f8f9fa] text-gray-500'}`}>Loading Core Systems...</div>;

    // Theme Variables
    const themeBg = isDark ? "bg-[#15171e]" : "bg-[#f8f9fa]";
    const themeText = isDark ? "text-gray-200" : "text-gray-800";
    const headerBg = isDark ? "bg-[#1e222b] border-b border-[#2d3340]" : "bg-white border-b border-gray-200 shadow-sm";
    const cardBg = isDark ? "bg-[#1e222b] border border-[#2d3340] shadow-md" : "bg-white border border-gray-100 shadow-sm";
    const tableBg = isDark ? "bg-[#1e222b] border-[#2d3340]" : "bg-white border-gray-200 shadow-sm";
    const rowHover = isDark ? "hover:bg-[#262b36] border-[#2d3340]" : "hover:bg-gray-50 border-gray-100";
    const tableHeader = isDark ? "text-gray-400 border-[#2d3340]" : "text-gray-500 border-gray-200";

    return (
        <div className={`${themeBg} ${themeText} min-h-screen p-8 font-sans transition-colors duration-300`}>
            {/* Header */}
            <div className={`${headerBg} ${isDark ? 'text-white' : 'text-gray-800'} rounded-t-md px-6 py-4 flex justify-between items-center transition-colors duration-300`}>
                <div className="flex items-center space-x-2">
                    <h1 className="text-xl font-bold tracking-wide">Live Risk Dashboard</h1>
                </div>
                <div className="flex items-center space-x-6">
                    <span className={`text-sm font-medium border-l pl-6 ${isDark ? 'border-[#2d3340] text-blue-400' : 'border-gray-200 text-blue-600'}`}>Analyst View</span>
                </div>
            </div>

            <div className={`border-x border-b rounded-b-md shadow-sm p-6 mb-8 transition-colors duration-300 ${tableBg}`}>

                {/* ── Anomaly Intelligence Panel ──────────────────── */}
                {anomalyAlerts && anomalyAlerts.filter(a => a.status === 'OPEN').length > 0 && (
                    <div className="mb-6">
                        <div className="flex items-center justify-between mb-3">
                            <h2 
                                className={`text-sm font-bold uppercase tracking-wider flex items-center space-x-2 cursor-pointer select-none ${isDark ? 'text-red-400' : 'text-red-600'}`}
                                onClick={() => setIsAnomalyExpanded(!isAnomalyExpanded)}
                            >
                                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                                <span>Anomaly Intelligence ({anomalyAlerts.filter(a => a.status === 'OPEN').length} Active)</span>
                                <svg xmlns="http://www.w3.org/2000/svg" className={`h-4 w-4 transition-transform duration-300 ${isAnomalyExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                            </h2>
                            <button
                                onClick={async () => {
                                    try {
                                        await triggerAnomalyScan();
                                        if (onAnomalyRefresh) await onAnomalyRefresh();
                                    } catch (e) { console.error(e); }
                                }}
                                className="text-xs font-bold text-blue-500 hover:text-blue-400 transition flex items-center space-x-1"
                            >
                                <span>⟳</span>
                                <span>Run ML Scan</span>
                            </button>
                        </div>
                        
                        {isAnomalyExpanded && (
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {(() => {
                                const openAlerts = anomalyAlerts.filter(a => a.status === 'OPEN');
                                const alertsByEmployee = openAlerts.reduce((acc, alert) => {
                                    if (!acc[alert.employee_id]) {
                                        acc[alert.employee_id] = {
                                            employee_id: alert.employee_id,
                                            employee_name: alert.employee_name,
                                            role: alert.role,
                                            alerts: [],
                                            highest_severity: 'Warning',
                                            max_confidence: alert.confidence
                                        };
                                    }
                                    acc[alert.employee_id].alerts.push(alert);
                                    acc[alert.employee_id].max_confidence = Math.max(acc[alert.employee_id].max_confidence, alert.confidence);
                                    return acc;
                                }, {});

                                const groupedAlerts = Object.values(alertsByEmployee).map(emp => {
                                    const hasCritical = emp.alerts.some(a => a.severity === 'Critical');
                                    const hasHigh = emp.alerts.some(a => a.severity === 'High');
                                    emp.highest_severity = hasCritical ? 'Critical' : (hasHigh ? 'High' : 'Warning');
                                    return emp;
                                }).sort((a, b) => {
                                    const sevScore = { Critical: 3, High: 2, Warning: 1 };
                                    return sevScore[b.highest_severity] - sevScore[a.highest_severity];
                                }).slice(0, 6);

                                return groupedAlerts.map((emp) => {
                                    const sevBg = emp.highest_severity === 'Critical' ? (isDark ? 'border-red-500/40 bg-red-500/5' : 'border-red-300 bg-red-50') 
                                                : emp.highest_severity === 'High' ? (isDark ? 'border-orange-500/40 bg-orange-500/5' : 'border-orange-300 bg-orange-50')
                                                : (isDark ? 'border-yellow-500/40 bg-yellow-500/5' : 'border-yellow-300 bg-yellow-50');
                                    const sevDot = emp.highest_severity === 'Critical' ? 'bg-red-500' : emp.highest_severity === 'High' ? 'bg-orange-500' : 'bg-yellow-500';
                                    const sevText = emp.highest_severity === 'Critical' ? (isDark ? 'text-red-400' : 'text-red-600') 
                                                  : emp.highest_severity === 'High' ? (isDark ? 'text-orange-400' : 'text-orange-600') 
                                                  : (isDark ? 'text-yellow-400' : 'text-yellow-600');
                                    return (
                                        <div key={emp.employee_id} className={`rounded-lg border p-4 transition-all hover:shadow-md ${sevBg} flex flex-col`}>
                                            <div className="flex items-center justify-between mb-2">
                                                <div className="flex items-center space-x-2">
                                                    <span className={`w-2 h-2 rounded-full ${sevDot}`}></span>
                                                    <span className={`text-xs font-black uppercase tracking-wider ${sevText}`}>{emp.highest_severity}</span>
                                                </div>
                                                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${isDark ? 'bg-[#15171e] text-gray-400' : 'bg-gray-100 text-gray-500'}`}>Max Conf {emp.max_confidence}%</span>
                                            </div>
                                            <h4 className={`text-sm font-bold mb-1 ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>{emp.employee_name}</h4>
                                            <p className={`text-[10px] uppercase tracking-wider mb-2 font-semibold ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>{emp.employee_id} · {emp.role}</p>
                                            
                                            <div className="flex-1">
                                                <p className={`text-xs mb-1.5 font-bold ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>{emp.alerts.length} Active {emp.alerts.length === 1 ? 'Anomaly' : 'Anomalies'}:</p>
                                                <ul className={`text-[11px] list-disc pl-4 space-y-1 ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>
                                                    {emp.alerts.map(a => (
                                                        <li key={a._id}><span className="font-semibold">{a.anomaly_type}</span>: <span className="line-clamp-1 text-[10px]">{a.description}</span></li>
                                                    ))}
                                                </ul>
                                            </div>

                                            <button
                                                onClick={() => {
                                                    const matchedUser = aggregatedUsers.find(u => u.id === emp.employee_id);
                                                    if (matchedUser) setSelectedUser(matchedUser);
                                                }}
                                                className={`mt-4 text-[11px] font-bold transition self-start ${isDark ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-500'}`}
                                            >
                                                Investigate User →
                                            </button>
                                        </div>
                                    );
                                });
                            })()}
                        </div>
                        )}
                    </div>
                )}

                {/* 5-Column Metrics Grid — the Integrity Score card moved to the
                    Quantum Security page along with the rest of the crypto posture. */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">

                    {/* Total Events — clickable */}
                    <div
                        onClick={() => setMetricModal({
                            title: 'All Analysed Events',
                            color: 'blue',
                            items: activities,
                            type: 'activity'
                        })}
                        className={`${cardBg} rounded-lg px-5 py-4 shadow-sm cursor-pointer hover:ring-2 hover:ring-blue-500/40 transition-all group`}
                    >
                        <p className={`text-3xl font-bold mb-1 ${isDark ? 'text-white' : 'text-gray-800'} group-hover:text-blue-400 transition-colors`}>{totalEvents}</p>
                        <p className="text-gray-500 text-xs uppercase tracking-wider font-semibold">Total Events Analyzed</p>
                        <p className="text-[10px] text-blue-500 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity">Click to inspect →</p>
                    </div>

                    {/* Blocked & Escalated — clickable */}
                    <div
                        onClick={() => setMetricModal({
                            title: 'Blocked & Escalated Alerts',
                            color: 'red',
                            items: blockedEscalatedItems,
                            type: 'alert'
                        })}
                        className={`${cardBg} rounded-lg px-5 py-4 shadow-sm cursor-pointer hover:ring-2 hover:ring-red-500/40 transition-all group`}
                    >
                        <p className="text-3xl font-bold text-[#ef4444] mb-1 group-hover:scale-110 transition-transform origin-left">{blockedEscalated}</p>
                        <p className="text-gray-500 text-xs uppercase tracking-wider font-semibold">Blocked & Escalated</p>
                        <p className="text-[10px] text-red-500 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity">Click to inspect →</p>
                    </div>

                    {/* Step-Up Auth — clickable */}
                    <div
                        onClick={() => setMetricModal({
                            title: 'Step-Up Auth Required',
                            color: 'amber',
                            items: stepUpAuthItems,
                            type: 'alert'
                        })}
                        className={`${cardBg} rounded-lg px-5 py-4 shadow-sm cursor-pointer hover:ring-2 hover:ring-amber-500/40 transition-all group`}
                    >
                        <p className="text-3xl font-bold text-[#f59e0b] mb-1 group-hover:scale-110 transition-transform origin-left">{stepUpAuth}</p>
                        <p className="text-gray-500 text-xs uppercase tracking-wider font-semibold">Step-Up Auth Required</p>
                        <p className="text-[10px] text-amber-500 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity">Click to inspect →</p>
                    </div>

                    {/* Allowed Low Risk — clickable */}
                    <div
                        onClick={() => setMetricModal({
                            title: 'Allowed — Low Risk Events',
                            color: 'green',
                            items: allowedEventItems,
                            type: 'activity'
                        })}
                        className={`${cardBg} rounded-lg px-5 py-4 shadow-sm cursor-pointer hover:ring-2 hover:ring-emerald-500/40 transition-all group`}
                    >
                        <p className="text-3xl font-bold text-[#10b981] mb-1 group-hover:scale-110 transition-transform origin-left">{allowedEvents}</p>
                        <p className="text-gray-500 text-xs uppercase tracking-wider font-semibold">Allowed (Low Risk)</p>
                        <p className="text-[10px] text-emerald-500 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity">Click to inspect →</p>
                    </div>

                    {/* Users Monitored — not clickable (handled by the table below) */}
                    <div className={`${cardBg} rounded-lg px-5 py-4 shadow-sm`}>
                        <p className={`text-3xl font-bold mb-1 ${isDark ? 'text-white' : 'text-gray-800'}`}>{usersMonitored}</p>
                        <p className="text-gray-500 text-xs uppercase tracking-wider font-semibold">Users Monitored</p>
                    </div>
                </div>

                {/* ── Risk analytics: charts + derived recommendations ─── */}
                <RiskCharts isDark={isDark} activities={activities} users={aggregatedUsers} />

                {/* ── Privileged access banner ─────────────────────────
                    Only shown to operators who actually hold employees:block,
                    so it does not advertise a capability others cannot use. */}
                {mayBlock && (
                    <div className={`mb-4 flex items-center justify-between gap-3 rounded-lg border px-4 py-2.5 ${
                        blockArmed
                            ? (isDark ? 'bg-amber-500/10 border-amber-500/30' : 'bg-amber-50 border-amber-300')
                            : (isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-gray-50 border-gray-200')
                    }`}>
                        <div className="flex items-center gap-2.5">
                            <Icon.KeyRound className={`w-4 h-4 shrink-0 ${blockArmed ? 'text-amber-400' : (isDark ? 'text-gray-500' : 'text-gray-400')}`} />
                            <div>
                                <p className={`text-xs font-bold ${blockArmed ? 'text-amber-400' : (isDark ? 'text-gray-300' : 'text-gray-700')}`}>
                                    {blockArmed ? 'Privileged access active' : 'Account override locked'}
                                </p>
                                <p className={`text-[11px] ${isDark ? 'text-gray-500' : 'text-gray-500'}`}>
                                    {blockArmed
                                        ? `Manual block/unblock is armed${blockElevation ? ` for ${Math.max(0, Math.floor((blockElevation.seconds_remaining || 0) / 60))}m ${(blockElevation.seconds_remaining || 0) % 60}s` : ''}.`
                                        : 'Manual block/unblock requires a time-boxed PAM elevation.'}
                                </p>
                            </div>
                        </div>
                        {!blockArmed && (
                            <button
                                onClick={() => setElevationPrompt({ reason: 'Manual account override from the SOC risk dashboard' })}
                                className="shrink-0 text-xs font-bold px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white transition"
                            >
                                Request Elevation
                            </button>
                        )}
                    </div>
                )}

                {blockError && (
                    <div className={`mb-4 flex items-start gap-2 rounded-lg border px-4 py-2.5 text-xs ${isDark ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-red-50 border-red-200 text-red-700'}`}>
                        <Icon.Warning className="w-4 h-4 shrink-0 mt-px" />
                        <span>{blockError}</span>
                    </div>
                )}

                {/* Unified Table */}
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className={`border-b ${tableHeader}`}>
                            <th className="py-3 font-bold w-[14%]">User</th>
                            <th className="py-3 font-bold w-[11%]">Role</th>
                            <th className="py-3 font-bold w-[16%]">Risk Score</th>
                            <th className="py-3 font-bold w-[9%]">Risk Level</th>
                            <th className="py-3 font-bold w-[14%]">Last Action</th>
                            <th className="py-3 font-bold w-[11%]">Integrity</th>
                            <th className="py-3 font-bold text-right pr-4 w-[15%]">Last Activity</th>
                            {mayBlock && <th className="py-3 font-bold text-right w-[10%]">Access</th>}
                        </tr>
                    </thead>
                    <tbody>
                        {aggregatedUsers.length === 0 && (
                            <tr><td colSpan={mayBlock ? 8 : 7} className="py-8 text-center text-gray-500 italic">No user activity recorded yet.</td></tr>
                        )}
                        {aggregatedUsers.map((user) => (
                            <tr 
                                key={user.id} 
                                onClick={() => {
                                    setSelectedUser(user);
                                    setAiReport(null);
                                }} 
                                className={`border-b cursor-pointer transition-colors duration-200 ${rowHover}`}
                            >
                                <td className={`py-4 ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>
                                    <div className="font-bold">{user.name}</div>
                                    <div className={`text-xs font-mono mt-0.5 ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>{user.id}</div>
                                </td>
                                <td className={`py-4 ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>{user.role}</td>
                                <td className="py-4">
                                    <div className="flex items-center space-x-3">
                                        <div className={`w-32 h-2.5 rounded-full flex overflow-hidden ${isDark ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                            <div className={`h-full ${user.riskLevel === 'High' ? 'bg-[#ef4444]' : user.riskLevel === 'Medium' ? 'bg-[#f59e0b]' : 'bg-[#10b981]'}`} style={{ width: `${user.barWidth}%` }}></div>
                                        </div>
                                        <span className={`text-sm font-medium ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>{user.totalRisk}</span>
                                    </div>
                                </td>
                                <td className="py-4">
                                    <span className={`px-3 py-1 rounded-full text-xs font-bold text-white shadow-sm ${user.riskLevel === 'High' ? 'bg-[#ef4444]' : user.riskLevel === 'Medium' ? 'bg-[#f59e0b]' : 'bg-[#10b981]'}`}>
                                        {user.riskLevel}
                                    </span>
                                </td>
                                <td className={`py-4 text-sm font-medium ${user.lastAction !== 'No Activity' ? 'text-blue-400' : (isDark ? 'text-gray-500' : 'text-gray-400')}`}>
                                    {user.lastAction}
                                </td>
                                {/* NEW: Integrity Badge Column */}
                                <td className="py-4">
                                    <IntegrityBadge 
                                        status={user.lastIntegrityStatus || user.integrityStatus} 
                                        isDark={isDark}
                                    />
                                </td>
                                <td className={`py-4 text-sm text-right pr-4 ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>{timeAgo(user.lastActivityDate)}</td>

                                {/* ── Manual override toggle ────────────────
                                    Rendered only for holders of employees:block.
                                    Disabled-looking until a PAM window is open;
                                    clicking while locked opens the elevation
                                    dialog rather than failing with a 403. */}
                                {mayBlock && (
                                    <td className="py-4 text-right" onClick={(e) => e.stopPropagation()}>
                                        <button
                                            onClick={() => handleToggleBlock(user.id, user.is_blocked, user.name)}
                                            disabled={blockLoading === user.id}
                                            title={
                                                blockArmed
                                                    ? (user.is_blocked ? 'Release this account' : 'Freeze this account for 24h')
                                                    : 'Requires a PAM elevation window'
                                            }
                                            aria-label={`${user.is_blocked ? 'Unblock' : 'Block'} ${user.name}`}
                                            className={`relative inline-flex items-center h-6 w-11 rounded-full transition-colors disabled:opacity-40 ${
                                                user.is_blocked
                                                    ? 'bg-red-500'
                                                    : (isDark ? 'bg-[#3b4252]' : 'bg-gray-300')
                                            } ${blockArmed ? 'cursor-pointer' : 'cursor-pointer opacity-60'}`}
                                        >
                                            <span
                                                className={`inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform ${
                                                    user.is_blocked ? 'translate-x-6' : 'translate-x-1'
                                                }`}
                                            />
                                            {!blockArmed && (
                                                <Icon.Lock className="absolute -right-4 top-1 w-3 h-3 text-amber-500" />
                                            )}
                                        </button>
                                        <div className={`text-[10px] mt-1 font-bold ${user.is_blocked ? 'text-red-400' : (isDark ? 'text-gray-600' : 'text-gray-400')}`}>
                                            {blockLoading === user.id
                                                ? '...'
                                                : user.is_blocked ? 'BLOCKED' : 'ACTIVE'}
                                        </div>

                                        {/* Authorised-exception state. Shown when an
                                            override is live so an operator can see at a
                                            glance that this account is deliberately
                                            outside normal enforcement. */}
                                        {mayOverride && (
                                            activeOverrides[user.id] ? (
                                                <button
                                                    onClick={() => handleRevokeOverride(user)}
                                                    title={
                                                        `Override by ${activeOverrides[user.id].granted_by}: ` +
                                                        `${activeOverrides[user.id].reason}\n` +
                                                        `Actions: ${(activeOverrides[user.id].allowed_actions || []).join(', ')}\n` +
                                                        `Click to revoke.`
                                                    }
                                                    className={`mt-1.5 inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded border transition ${isDark ? 'bg-amber-500/10 border-amber-500/40 text-amber-400 hover:bg-amber-500/20' : 'bg-amber-50 border-amber-300 text-amber-700 hover:bg-amber-100'}`}
                                                >
                                                    <Icon.ShieldCheck className="w-2.5 h-2.5" />
                                                    {activeOverrides[user.id].events_remaining != null
                                                        ? `OVR ${activeOverrides[user.id].events_remaining}e`
                                                        : activeOverrides[user.id].seconds_remaining != null
                                                            ? `OVR ${Math.ceil(activeOverrides[user.id].seconds_remaining / 60)}m`
                                                            : 'OVR'}
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() => handleAuthorizeException(user)}
                                                    title="Authorise an exception to automated enforcement"
                                                    className={`mt-1.5 text-[9px] font-bold px-1.5 py-0.5 rounded border transition ${isDark ? 'border-[#2d3340] text-gray-500 hover:text-amber-400 hover:border-amber-500/40' : 'border-gray-300 text-gray-400 hover:text-amber-700 hover:border-amber-400'}`}
                                                >
                                                    + ALLOW
                                                </button>
                                            )
                                        )}
                                    </td>
                                )}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Drill-Down Modal Overlay */}
            {selectedUser && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
                    <div className={`rounded-lg shadow-2xl w-full max-w-2xl overflow-hidden flex flex-col max-h-[80vh] ${isDark ? 'bg-[#1e222b] border border-[#2d3340]' : 'bg-white'}`}>
                        {/* Modal Header */}
                        <div className={`${headerBg} ${isDark ? 'text-white' : 'text-gray-800'} px-6 py-4 flex justify-between items-center`}>
                            <div>
                                <h2 className="text-lg font-bold flex items-center gap-2">
                                    Investigation: {selectedUser.name}
                                    {selectedUser.is_blocked && (
                                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-500 border border-red-500/30">
                                            BLOCKED
                                        </span>
                                    )}
                                </h2>
                                <p className={`text-sm ${isDark ? 'opacity-80' : 'text-gray-500'}`}>{selectedUser.id} | {selectedUser.role} | Total Risk: {selectedUser.totalRisk}</p>
                            </div>
                            <div className="flex items-center gap-4">
                                {mayOverride && (
                                    activeOverrides[selectedUser.id] ? (
                                        <button
                                            onClick={() => handleRevokeOverride(selectedUser)}
                                            title={`Override by ${activeOverrides[selectedUser.id].granted_by}: ${activeOverrides[selectedUser.id].reason}`}
                                            className="px-3 py-1.5 rounded-lg text-xs font-bold shadow-sm transition-colors inline-flex items-center gap-1.5 bg-amber-600 hover:bg-amber-700 text-white"
                                        >
                                            <Icon.ShieldCheck className="w-3.5 h-3.5" />
                                            Revoke Exception
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => handleAuthorizeException(selectedUser)}
                                            title="Authorise an exception to automated enforcement"
                                            className={`px-3 py-1.5 rounded-lg text-xs font-bold shadow-sm transition-colors inline-flex items-center gap-1.5 border ${isDark ? 'border-amber-500/40 text-amber-400 hover:bg-amber-500/10' : 'border-amber-400 text-amber-700 hover:bg-amber-50'}`}
                                        >
                                            {!overrideArmed && <Icon.Lock className="w-3.5 h-3.5" />}
                                            Authorise Exception
                                        </button>
                                    )
                                )}
                                {mayBlock && (
                                    <button
                                        onClick={() => handleToggleBlock(selectedUser.id, selectedUser.is_blocked, selectedUser.name)}
                                        disabled={blockLoading === selectedUser.id}
                                        title={blockArmed ? undefined : 'Requires a PAM elevation window'}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-bold shadow-sm transition-colors disabled:opacity-50 inline-flex items-center gap-1.5 ${
                                            selectedUser.is_blocked
                                                ? 'bg-gray-600 text-white hover:bg-gray-700'
                                                : 'bg-red-600 text-white hover:bg-red-700'
                                        } ${blockArmed ? '' : 'opacity-70'}`}
                                    >
                                        {!blockArmed && <Icon.Lock className="w-3.5 h-3.5" />}
                                        {blockLoading === selectedUser.id
                                            ? 'Updating...'
                                            : selectedUser.is_blocked ? 'Unblock Account' : 'Block (24h)'}
                                    </button>
                                )}
                                <button 
                                    onClick={() => {
                                        setSelectedUser(null);
                                        setAiReport(null);
                                    }} 
                                    className={`${isDark ? 'text-white hover:text-gray-300' : 'text-gray-500 hover:text-gray-800'} font-bold text-2xl leading-none`}
                                >
                                    &times;
                                </button>
                            </div>
                        </div>
                        
                        {/* Modal Timeline */}
                        <div className={`p-6 overflow-y-auto flex-1 ${isDark ? 'bg-[#15171e]' : 'bg-gray-50'}`}>
                            <h3 className={`font-bold mb-4 border-b pb-2 ${isDark ? 'text-gray-200 border-gray-700' : 'text-gray-700 border-gray-200'}`}>Activity Timeline</h3>
                            <div className="space-y-4 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-400 before:to-transparent">
                                {selectedUser.timeline.map((act, index) => (
                                    <div key={index} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                                        <div className={`flex items-center justify-center w-10 h-10 rounded-full border shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 ${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-slate-200 border-white'}`}>
                                            <span className={`w-3 h-3 rounded-full ${act.risk_score > 0 ? 'bg-orange-500' : 'bg-gray-400'}`}></span>
                                        </div>
                                        <div className={`w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-lg shadow-sm border ${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-slate-200'}`}>
                                            <div className="flex justify-between items-center mb-1">
                                                <div className={`font-bold text-sm ${isDark ? 'text-gray-200' : 'text-slate-700'}`}>{formatActionString(act.action)}</div>
                                                <div className={`text-xs ${isDark ? 'text-gray-400' : 'text-slate-500'}`}>{formatTime(act.timestamp)}</div>
                                            </div>
                                            <div className="flex items-center justify-between mt-1">
                                                {act.risk_score > 0 && (
                                                    <div className="text-xs font-bold text-orange-500">+ {act.risk_score} Risk Added</div>
                                                )}
                                                <IntegrityBadge 
                                                    status={act.integrity_verified} 
                                                    isDark={isDark}
                                                />
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* AI Explanation Engine UI */}
                        <div className={`p-6 border-t ${isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-white border-gray-200'}`}>
                            
                            {/* AI Output Container */}
                            {aiReport && (
                                <div className={`mb-4 p-5 rounded-lg border shadow-inner ${isDark ? 'bg-[#1e222b] border-[#2d3340] text-gray-300' : 'bg-[#f8f9fa] border-gray-200 text-gray-800'}`}>
                                    <h4 className="font-bold text-sm mb-3 flex items-center space-x-2">
                                        <Icon.Brain className="w-4 h-4 text-blue-400" />
                                        <span>AI Forensic Analysis (Local Engine)</span>
                                    </h4>
                                    <div id="ai-report-content" className="text-sm space-y-4 whitespace-pre-wrap leading-relaxed">
                                        {aiReport}
                                    </div>
                                    
                                    {/* Report Action Buttons */}
                                    <div className={`mt-5 pt-4 border-t flex flex-wrap gap-2 ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                                        <button 
                                            onClick={() => {
                                                navigator.clipboard.writeText(aiReport);
                                                alert("Report copied to clipboard!");
                                            }}
                                            className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition inline-flex items-center gap-1.5 ${isDark ? 'bg-[#15171e] border-[#2d3340] hover:bg-[#262b36] text-gray-300' : 'bg-white border-gray-300 hover:bg-gray-50 text-gray-700'}`}
                                        >
                                            <Icon.Clipboard className="w-3.5 h-3.5" />
                                            Copy Report
                                        </button>
                                        <button 
                                            onClick={() => {
                                                const blob = new Blob([aiReport], { type: 'text/plain' });
                                                const url = window.URL.createObjectURL(blob);
                                                const a = document.createElement('a');
                                                a.href = url;
                                                a.download = `Forensic_Report_${selectedUser.id}.txt`;
                                                a.click();
                                            }}
                                            className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition inline-flex items-center gap-1.5 ${isDark ? 'bg-[#15171e] border-[#2d3340] hover:bg-[#262b36] text-gray-300' : 'bg-white border-gray-300 hover:bg-gray-50 text-gray-700'}`}
                                        >
                                            <Icon.Download className="w-3.5 h-3.5" />
                                            Download Report
                                        </button>
                                        <button 
                                            onClick={() => window.print()}
                                            className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition inline-flex items-center gap-1.5 ${isDark ? 'bg-[#15171e] border-[#2d3340] hover:bg-[#262b36] text-gray-300' : 'bg-white border-gray-300 hover:bg-gray-50 text-gray-700'}`}
                                        >
                                            <Icon.Document className="w-3.5 h-3.5" />
                                            Export PDF
                                        </button>
                                        <button 
                                            onClick={() => window.print()}
                                            className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition inline-flex items-center gap-1.5 ${isDark ? 'bg-[#15171e] border-[#2d3340] hover:bg-[#262b36] text-gray-300' : 'bg-white border-gray-300 hover:bg-gray-50 text-gray-700'}`}
                                        >
                                            <Icon.Printer className="w-3.5 h-3.5" />
                                            Print Report
                                        </button>
                                    </div>
                                </div>
                            )}

                            {/* Action Bar */}
                            <div className="flex justify-end space-x-3">
                                {aiLoading && <span className="flex items-center text-sm text-blue-500 font-bold animate-pulse mr-2">Synthesizing Security Intelligence...</span>}
                                
                                <button 
                                    disabled={aiLoading}
                                    onClick={() => {
                                        setAiLoading(true);
                                        // Simulate a small delay so the user sees the "Synthesizing Security Intelligence..." animation
                                        setTimeout(() => {
                                            try {
                                                const reportText = generateReport(selectedUser.timeline, selectedUser);
                                                setAiReport(reportText);
                                            } catch (err) {
                                                console.error("Local AI Engine Error:", err);
                                                alert(`AI Engine Failed!\n\nReason: ${err.message}`);
                                            } finally {
                                                setAiLoading(false);
                                            }
                                        }, 1000);
                                    }}
                                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md font-medium shadow flex items-center space-x-2 transition disabled:opacity-50"
                                >
                                    <Icon.Sparkles className="w-4 h-4" />
                                    <span>{aiReport ? 'Regenerate Analysis' : 'Generate AI Analysis'}</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Metric Drill-Down Modal ────────────────────────────── */}
            {metricModal && (
                <div
                    className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm"
                    onClick={() => setMetricModal(null)}
                >
                    <div
                        className={`rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col max-h-[80vh] ${isDark ? 'bg-[#1e222b] border border-[#2d3340]' : 'bg-white border border-gray-200'}`}
                        onClick={e => e.stopPropagation()}
                    >
                        {/* Modal Header */}
                        <div className={`px-6 py-4 flex justify-between items-center ${
                            metricModal.color === 'red'   ? 'bg-red-500/10 border-b border-red-500/20'    :
                            metricModal.color === 'amber' ? 'bg-amber-500/10 border-b border-amber-500/20' :
                            metricModal.color === 'green' ? 'bg-emerald-500/10 border-b border-emerald-500/20' :
                                                           'bg-blue-500/10 border-b border-blue-500/20'
                        }`}>
                            <div>
                                <h2 className={`text-lg font-bold ${
                                    metricModal.color === 'red'   ? 'text-red-400'    :
                                    metricModal.color === 'amber' ? 'text-amber-400'  :
                                    metricModal.color === 'green' ? 'text-emerald-400':
                                                                   'text-blue-400'
                                }`}>
                                    {metricModal.title}
                                </h2>
                                <p className={`text-xs mt-0.5 ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>
                                    {metricModal.items.length} {metricModal.type === 'alert' ? 'alert' : 'event'}{metricModal.items.length !== 1 ? 's' : ''} found
                                </p>
                            </div>
                            <button
                                onClick={() => setMetricModal(null)}
                                className={`text-2xl font-bold leading-none ${isDark ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-900'} transition`}
                            >&times;</button>
                        </div>

                        {/* Table */}
                        <div className="overflow-y-auto flex-1">
                            {metricModal.items.length === 0 ? (
                                <div className={`flex flex-col items-center py-16 ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>
                                    <Icon.Check className="w-10 h-10 mb-3 text-emerald-500" />
                                    <p className="font-medium">No events in this category</p>
                                </div>
                            ) : (
                                <table className="w-full text-left text-sm border-collapse">
                                    <thead>
                                        <tr className={`border-b text-xs uppercase tracking-wider font-bold ${isDark ? 'text-gray-500 border-[#2d3340] bg-[#15171e]' : 'text-gray-400 border-gray-200 bg-gray-50'}`}>
                                            <th className="px-6 py-3">Employee</th>
                                            <th className="px-6 py-3">Action</th>
                                            <th className="px-6 py-3">Risk Score</th>
                                            {metricModal.type === 'alert' && <th className="px-6 py-3">Alert Level</th>}
                                            {metricModal.type === 'activity' && <th className="px-6 py-3">Integrity</th>}
                                            <th className="px-6 py-3 text-right">Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {metricModal.items.map((item, idx) => {
                                            const alertLevelColor = {
                                                Critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
                                                High:     'bg-orange-500/20 text-orange-400 border border-orange-500/30',
                                                Warning:  'bg-amber-500/20 text-amber-400 border border-amber-500/30',
                                                Normal:   'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
                                            };
                                            const empName = employeeDirectory[item.employee_id]?.name || item.employee_id;
                                            return (
                                                <tr
                                                    key={idx}
                                                    className={`border-b transition-colors ${isDark ? 'border-[#2d3340] hover:bg-[#262b36]' : 'border-gray-100 hover:bg-gray-50'}`}
                                                >
                                                    {/* Employee */}
                                                    <td className="px-6 py-3">
                                                        <div className={`font-semibold ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>{empName}</div>
                                                        <div className={`text-xs font-mono ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>{item.employee_id}</div>
                                                    </td>

                                                    {/* Action */}
                                                    <td className={`px-6 py-3 font-medium ${isDark ? 'text-blue-400' : 'text-blue-600'}`}>
                                                        {formatActionString(item.action)}
                                                    </td>

                                                    {/* Risk Score */}
                                                    <td className="px-6 py-3">
                                                        <span className={`font-bold ${
                                                            item.risk_score >= 60 ? 'text-red-400' :
                                                            item.risk_score >= 30 ? 'text-amber-400' :
                                                            'text-emerald-400'
                                                        }`}>
                                                            {item.risk_score}
                                                        </span>
                                                    </td>

                                                    {/* Alert Level (alerts only) */}
                                                    {metricModal.type === 'alert' && (
                                                        <td className="px-6 py-3">
                                                            <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${alertLevelColor[item.level] || ''}`}>
                                                                {item.level}
                                                            </span>
                                                        </td>
                                                    )}

                                                    {/* Integrity Badge (activities only) */}
                                                    {metricModal.type === 'activity' && (
                                                        <td className="px-6 py-3">
                                                            <IntegrityBadge
                                                                status={item.integrity_verified}
                                                                isDark={isDark}
                                                            />
                                                        </td>
                                                    )}

                                                    {/* Timestamp */}
                                                    <td className={`px-6 py-3 text-right text-xs ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>
                                                        <div>{timeAgo(item.timestamp)}</div>
                                                        <div className="font-mono">{formatTime(item.timestamp)}</div>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                        </div>

                        {/* Footer */}
                        <div className={`px-6 py-3 text-xs border-t ${isDark ? 'text-gray-500 border-[#2d3340] bg-[#15171e]' : 'text-gray-400 border-gray-200 bg-gray-50'}`}>
                            Showing {metricModal.items.length} record{metricModal.items.length !== 1 ? 's' : ''} — click outside or × to dismiss
                        </div>
                    </div>
                </div>
            )}

            {/* ── PAM elevation dialog ───────────────────────────────── */}
            {elevationPrompt && (
                <ElevationModal
                    permissions={elevationPrompt.permissions || [BLOCK_PERMISSION]}
                    reason={elevationPrompt.reason}
                    isDark={isDark}
                    onClose={() => setElevationPrompt(null)}
                    onElevated={() => {
                        // Window is open. Close the dialog and continue whatever
                        // the operator was originally trying to do.
                        const next = elevationPrompt.then;
                        setElevationPrompt(null);
                        if (next) next();
                    }}
                />
            )}

            {/* ── Authorise-exception dialog ──────────────────────────── */}
            {overrideTarget && (
                <OverrideModal
                    employee={overrideTarget}
                    isDark={isDark}
                    onClose={() => setOverrideTarget(null)}
                    onGranted={async () => {
                        await fetchDashboardData();
                    }}
                />
            )}
        </div>
    );
}