import React, { useState, useEffect, useCallback } from 'react';
import { logActivity, loginEmployee, checkEmployeeStatus } from '../services/api';
import * as Icon from '../components/Icons';

/**
 * Employee Simulator / Endpoint Simulator.
 *
 * Two jobs:
 *   1. Generate genuine telemetry — this is the ONLY path that trains the AI
 *      Twin baseline. (The AI Twin page's threat simulator is read-only by
 *      design so it cannot poison the baseline.)
 *   2. Demonstrate enforcement. Each action returns the deviation verdict from
 *      the normal-environment baseline, and if enforcement freezes the account
 *      the session is terminated with the reason shown rather than silently
 *      dropping the user at a login screen.
 *
 * The 3-second status poll is the forced-logout channel: enforcement_service
 * stamps `session_revoked_at` server-side and this loop acts on it.
 */

const ACTIONS = [
    { label: 'View Customer', value: 'VIEW_CUSTOMER', color: 'bg-gray-500', risk: 0 },
    { label: 'Download File', value: 'DOWNLOAD_FILE', color: 'bg-yellow-500', risk: 10 },
    { label: 'Download Confidential', value: 'DOWNLOAD_CONFIDENTIAL', color: 'bg-orange-600', risk: 30 },
    { label: 'Delete File', value: 'DELETE_FILE', color: 'bg-red-500', risk: 40 },
    { label: 'USB Connected', value: 'USB_CONNECTED', color: 'bg-purple-500', risk: 20 },
    { label: 'Failed Login', value: 'FAILED_LOGIN', color: 'bg-red-700', risk: 15 },
    { label: 'Change Permission', value: 'CHANGE_PERMISSION', color: 'bg-pink-600', risk: 35 },
];

const POLL_INTERVAL_MS = 3000;

export default function Simulator({ isDark = true }) {
    const [activeEmployee, setActiveEmployee] = useState(
        () => localStorage.getItem('InthreatDetection_employee') || null
    );

    const [empIdInput, setEmpIdInput] = useState('');
    const [empPassInput, setEmpPassInput] = useState('');
    const [loginError, setLoginError] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [lastAction, setLastAction] = useState(null);
    const [lastDeviation, setLastDeviation] = useState(null);
    const [enforcementNotice, setEnforcementNotice] = useState(null);
    const [busy, setBusy] = useState(null);

    // ── Theme tokens ─────────────────────────────────────────────────
    const cardBg = isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200';
    const insetBg = isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-gray-50 border-gray-200';
    const inputBg = isDark
        ? 'bg-[#15171e] border-[#2d3340] text-white placeholder-gray-500'
        : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400';
    const headingText = isDark ? 'text-white' : 'text-gray-900';
    const bodyText = isDark ? 'text-gray-400' : 'text-gray-500';
    const mutedText = isDark ? 'text-gray-500' : 'text-gray-400';
    const dividerBorder = isDark ? 'border-[#2d3340]' : 'border-gray-200';

    /** Terminate the local session, optionally with an enforcement explanation. */
    const endSession = useCallback((notice) => {
        setActiveEmployee(null);
        setLastAction(null);
        setLastDeviation(null);
        localStorage.removeItem('InthreatDetection_employee');
        if (notice) setEnforcementNotice(notice);
    }, []);

    // ── Forced-logout poll ───────────────────────────────────────────
    useEffect(() => {
        if (!activeEmployee) return undefined;

        const check = async () => {
            try {
                const status = await checkEmployeeStatus(activeEmployee);
                if (status.is_blocked) {
                    endSession({
                        reason: status.block_reason
                            || 'Account frozen due to a critical security alert.',
                        trigger: status.block_trigger,
                        severity: status.block_severity || 'Critical',
                        source: status.block_source,
                        blockedUntil: status.blocked_until,
                    });
                }
            } catch (err) {
                // A transient failure must not log the user out — only an
                // affirmative is_blocked does.
                console.error('Failed to check enforcement status', err);
            }
        };

        check();
        const interval = setInterval(check, POLL_INTERVAL_MS);
        return () => clearInterval(interval);
    }, [activeEmployee, endSession]);

    const handleEmployeeLogin = async (e) => {
        e.preventDefault();
        setLoginError('');
        setEnforcementNotice(null);
        try {
            const result = await loginEmployee(empIdInput, empPassInput);
            setActiveEmployee(result.employee_id);
            localStorage.setItem('InthreatDetection_employee', result.employee_id);
            setEmpPassInput('');
            await logActivity('LOGIN', result.employee_id);
        } catch (err) {
            setLoginError(
                err?.response?.data?.detail
                || 'Authentication failed. Verify credentials with the SOC administrator.'
            );
        }
    };

    const handleAction = async (actionValue) => {
        setBusy(actionValue);
        try {
            const result = await logActivity(actionValue, activeEmployee);
            setLastAction({
                action: result.action,
                time: new Date().toLocaleTimeString(),
                riskScore: result.risk_score,
            });
            setLastDeviation(result.deviation || null);

            // The response tells us immediately if this action tripped
            // enforcement, so we do not have to wait for the next poll.
            if (result.enforcement?.frozen) {
                endSession({
                    reason: result.enforcement.reason,
                    trigger: result.enforcement.trigger,
                    severity: 'Critical',
                    source: 'AUTOMATED',
                });
                return;
            }

            if (actionValue === 'LOGOUT') endSession(null);
        } catch (err) {
            setLoginError('');
            alert('Failed to log activity. Check the backend connection.');
        } finally {
            setBusy(null);
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // View 1: login gate
    // ═══════════════════════════════════════════════════════════════
    if (!activeEmployee) {
        return (
            <div className="flex flex-col items-center justify-center pt-16 pb-10 px-4 font-sans">
                {/* Enforcement notice survives the logout it caused. */}
                {enforcementNotice && (
                    <div className={`w-full max-w-lg mb-6 rounded-xl border p-5 ${isDark ? 'bg-red-500/10 border-red-500/40' : 'bg-red-50 border-red-300'}`}>
                        <div className="flex items-start gap-3">
                            <Icon.Ban className="w-6 h-6 text-red-500 shrink-0 mt-0.5" />
                            <div className="flex-1">
                                <h3 className={`text-sm font-bold ${isDark ? 'text-red-400' : 'text-red-700'}`}>
                                    Session terminated — account frozen
                                </h3>
                                <p className={`text-xs mt-1.5 leading-5 ${bodyText}`}>
                                    {enforcementNotice.reason}
                                </p>
                                <div className={`flex flex-wrap gap-x-4 gap-y-1 mt-3 text-[10px] uppercase tracking-wider font-bold ${mutedText}`}>
                                    {enforcementNotice.trigger && (
                                        <span>Trigger: <span className="text-red-400">{enforcementNotice.trigger}</span></span>
                                    )}
                                    {enforcementNotice.source && <span>Source: {enforcementNotice.source}</span>}
                                    {enforcementNotice.blockedUntil && (
                                        <span>
                                            Until: {new Date(enforcementNotice.blockedUntil).toLocaleString()}
                                        </span>
                                    )}
                                </div>
                                <p className={`text-[11px] mt-3 ${mutedText}`}>
                                    Contact the SOC to review this action. An administrator can
                                    release the account manually.
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                <div className={`p-8 rounded-xl shadow-lg border w-96 text-center transition-colors duration-300 ${cardBg}`}>
                    <h1 className={`text-2xl font-bold mb-2 ${headingText}`}>Employee Portal</h1>
                    <p className={`text-sm mb-6 ${bodyText}`}>Enter your corporate credentials.</p>

                    {loginError && (
                        <div className={`text-xs py-2 px-3 rounded mb-4 border flex items-start gap-2 text-left ${isDark ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-red-50 border-red-200 text-red-600'}`}>
                            <Icon.Warning className="w-4 h-4 shrink-0 mt-px" />
                            <span>{loginError}</span>
                        </div>
                    )}

                    <form onSubmit={handleEmployeeLogin} className="space-y-4">
                        <input
                            required
                            type="text"
                            placeholder="Employee ID"
                            value={empIdInput}
                            onChange={(e) => setEmpIdInput(e.target.value)}
                            className={`w-full border rounded px-3 py-2 outline-none focus:border-blue-500 transition-colors ${inputBg}`}
                        />
                        <div className="relative">
                            <input
                                required
                                type={showPassword ? 'text' : 'password'}
                                placeholder="Password"
                                value={empPassInput}
                                onChange={(e) => setEmpPassInput(e.target.value)}
                                className={`w-full border rounded px-3 py-2 pr-10 outline-none focus:border-blue-500 transition-colors ${inputBg}`}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                                className={`absolute right-3 top-1/2 -translate-y-1/2 focus:outline-none ${isDark ? 'text-gray-500 hover:text-gray-300' : 'text-gray-500 hover:text-gray-700'}`}
                            >
                                {showPassword ? (
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                    </svg>
                                ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                    </svg>
                                )}
                            </button>
                        </div>
                        <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">
                            Sign In
                        </button>
                    </form>
                </div>
            </div>
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // View 2: telemetry generator + live deviation readout
    // ═══════════════════════════════════════════════════════════════
    const dev = lastDeviation;
    const hasBaseline = dev && dev.baseline_scope !== 'none';

    return (
        <div className="p-8 max-w-5xl mx-auto font-sans">
            <div className={`flex justify-between items-center mb-6 border-b pb-4 ${dividerBorder}`}>
                <div>
                    <h1 className={`text-3xl font-bold tracking-tight ${headingText}`}>Endpoint Simulator</h1>
                    <p className={`mt-1 ${bodyText}`}>
                        Generating live telemetry for{' '}
                        <span className="text-blue-500 font-mono font-bold">{activeEmployee}</span>
                    </p>
                </div>
                <button
                    onClick={() => handleAction('LOGOUT')}
                    className="bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 px-4 py-2 rounded text-sm font-bold transition"
                >
                    Terminate Session
                </button>
            </div>

            {/* Action buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                {ACTIONS.map((btn) => (
                    <button
                        key={btn.value}
                        onClick={() => handleAction(btn.value)}
                        disabled={busy === btn.value}
                        className={`${btn.color} text-white py-3 px-4 rounded shadow hover:opacity-90 transition active:scale-95 font-medium disabled:opacity-50 flex items-center justify-between`}
                    >
                        <span>{btn.label}</span>
                        <span className="text-[10px] font-bold bg-black/25 px-1.5 py-0.5 rounded">
                            +{btn.risk}
                        </span>
                    </button>
                ))}
            </div>

            {/* ── Last action + baseline deviation verdict ───────────── */}
            {lastAction && (
                <div className={`rounded-xl border shadow-sm overflow-hidden ${cardBg}`}>
                    <div className={`px-5 py-3 flex items-center justify-between border-b ${dividerBorder}`}>
                        <div className="flex items-center gap-2">
                            <Icon.Activity className="w-4 h-4 text-blue-500" />
                            <span className={`text-sm font-bold ${headingText}`}>
                                Telemetry sent: <code className="text-blue-500">{lastAction.action}</code>
                            </span>
                        </div>
                        <span className={`text-xs font-mono ${mutedText}`}>{lastAction.time}</span>
                    </div>

                    <div className="p-5">
                        {!hasBaseline ? (
                            <div className="flex items-start gap-2.5">
                                <Icon.Info className={`w-4 h-4 shrink-0 mt-0.5 ${mutedText}`} />
                                <div>
                                    <p className={`text-sm font-bold ${headingText}`}>
                                        No behavioural baseline yet
                                    </p>
                                    <p className={`text-xs mt-1 leading-5 ${bodyText}`}>
                                        {dev?.message
                                            || 'This employee has no established normal environment, so no deviation judgement was made. Risk is the static action weight only.'}
                                        {' '}Keep generating activity, then build a baseline from the
                                        SOC console to enable deviation detection.
                                    </p>
                                </div>
                            </div>
                        ) : (
                            <>
                                {/* Risk decomposition: static vs deviation premium */}
                                <div className="grid grid-cols-3 gap-3 mb-4">
                                    {[
                                        { label: 'Base Risk', value: dev.base_risk, tone: mutedText },
                                        {
                                            label: 'Deviation Premium',
                                            value: `+${dev.deviation_premium}`,
                                            tone: dev.deviation_premium > 0 ? 'text-amber-400' : mutedText,
                                        },
                                        {
                                            label: 'Contextual Risk',
                                            value: dev.contextual_risk,
                                            tone: dev.contextual_risk >= 60 ? 'text-red-400'
                                                : dev.contextual_risk >= 30 ? 'text-amber-400'
                                                : 'text-emerald-400',
                                        },
                                    ].map((m) => (
                                        <div key={m.label} className={`rounded-lg border px-3 py-2.5 ${insetBg}`}>
                                            <p className={`text-2xl font-bold ${m.tone}`}>{m.value}</p>
                                            <p className={`text-[10px] uppercase tracking-wider font-semibold mt-0.5 ${mutedText}`}>
                                                {m.label}
                                            </p>
                                        </div>
                                    ))}
                                </div>

                                {dev.is_deviation ? (
                                    <div className={`rounded-lg border p-4 ${isDark ? 'bg-amber-500/5 border-amber-500/30' : 'bg-amber-50 border-amber-300'}`}>
                                        <div className="flex items-center gap-2 mb-2.5">
                                            <Icon.Warning className="w-4 h-4 text-amber-500" />
                                            <span className={`text-sm font-bold ${isDark ? 'text-amber-400' : 'text-amber-700'}`}>
                                                Deviation from normal environment
                                            </span>
                                        </div>
                                        <ul className="space-y-2">
                                            {(dev.reasons || []).map((r, i) => (
                                                <li key={i} className="flex items-start gap-2">
                                                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 mt-px ${isDark ? 'bg-amber-500/15 text-amber-400' : 'bg-amber-100 text-amber-700'}`}>
                                                        +{r.weight}
                                                    </span>
                                                    <span className={`text-xs leading-5 ${bodyText}`}>{r.detail}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                ) : (
                                    <div className={`flex items-center gap-2 rounded-lg border px-4 py-3 ${isDark ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-emerald-50 border-emerald-300'}`}>
                                        <Icon.Check className="w-4 h-4 text-emerald-500 shrink-0" />
                                        <span className={`text-xs ${isDark ? 'text-emerald-400' : 'text-emerald-700'}`}>
                                            Consistent with the established normal environment for this
                                            employee.
                                        </span>
                                    </div>
                                )}

                                <p className={`text-[10px] mt-3 ${mutedText}`}>
                                    Compared against the{' '}
                                    <span className="font-bold">{dev.baseline_scope}</span> baseline
                                    {dev.baseline_events ? ` (${dev.baseline_events} events)` : ''}
                                    {dev.baseline_locked ? ' · locked' : ''}
                                    {' · '}{dev.today_action_count} actions today
                                </p>
                            </>
                        )}
                    </div>
                </div>
            )}

            {!lastAction && (
                <div className={`rounded-xl border p-6 text-center ${insetBg}`}>
                    <p className={`text-sm ${bodyText}`}>
                        Trigger an action above to generate telemetry and see it scored against
                        the behavioural baseline.
                    </p>
                </div>
            )}
        </div>
    );
}
