import { useEffect, useState } from 'react';
import { grantOverride } from '../services/api';
import * as Icon from './Icons';

const MIN_REASON = 15;
const MAX_MINUTES = 24 * 60;
const MAX_EVENTS = 500;

// The actions an operator can authorise a deviation for. Zero-weight actions are
// omitted — they never trigger enforcement, so authorising them is meaningless.
const AUTHORIZABLE_ACTIONS = [
    'DOWNLOAD_FILE',
    'DOWNLOAD_CONFIDENTIAL',
    'DELETE_FILE',
    'USB_CONNECTED',
    'CHANGE_PERMISSION',
    'FAILED_LOGIN',
];

const formatAction = (a) =>
    a.split('_').map((w) => w.charAt(0) + w.slice(1).toLowerCase()).join(' ');

/**
 * Grant a bounded enforcement override.
 *
 * Covers both operator intents with one form:
 *   · "Let this frozen account work" — block exemption
 *   · "Let them act outside their baseline" — action allow-list
 *
 * Bounds are mandatory. The UI refuses to submit without at least one limit,
 * mirroring the server rule, because an unbounded exemption is a permanent hole
 * in enforcement that nobody remembers granting.
 *
 * Props:
 *   employee   { id, name, role, totalRisk, riskLevel, is_blocked }
 *   isDark     bool
 *   onClose    fn
 *   onGranted  fn(result)
 */
export default function OverrideModal({ employee, isDark, onClose, onGranted }) {
    const [reason, setReason] = useState('');
    const [exemptBlock, setExemptBlock] = useState(true);
    const [scopeAll, setScopeAll] = useState(false);
    const [selected, setSelected] = useState([]);
    const [useTime, setUseTime] = useState(true);
    const [minutes, setMinutes] = useState(60);
    const [useEvents, setUseEvents] = useState(false);
    const [events, setEvents] = useState(5);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [done, setDone] = useState(null);

    useEffect(() => {
        const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose(); };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [onClose, busy]);

    const cardBg = isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200';
    const insetBg = isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-gray-50 border-gray-200';
    const inputBg = isDark
        ? 'bg-[#15171e] border-[#2d3340] text-white placeholder-gray-500'
        : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400';
    const headText = isDark ? 'text-white' : 'text-gray-900';
    const subText = isDark ? 'text-gray-400' : 'text-gray-500';
    const mutedText = isDark ? 'text-gray-500' : 'text-gray-400';

    const reasonShort = reason.trim().length < MIN_REASON;
    const noBound = !useTime && !useEvents;
    const noScope = !exemptBlock && !scopeAll && selected.length === 0;
    const blocked = reasonShort || noBound || noScope;

    const toggleAction = (a) =>
        setSelected((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]));

    const submit = async () => {
        if (blocked) return;
        setBusy(true);
        setError(null);
        try {
            const result = await grantOverride({
                employeeId: employee.id,
                reason: reason.trim(),
                exemptBlock,
                allowedActions: scopeAll ? null : selected,
                durationMinutes: useTime ? minutes : null,
                maxEvents: useEvents ? events : null,
            });
            setDone(result);
            onGranted?.(result);
        } catch (err) {
            setError(err?.response?.data?.detail || 'Failed to grant override.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div
            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[75] p-4"
            onClick={() => !busy && onClose()}
        >
            <div
                className={`w-full max-w-lg rounded-xl border shadow-2xl max-h-[88vh] overflow-y-auto ${cardBg}`}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className={`px-6 py-4 border-b flex items-start gap-3 ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                    <div className="text-amber-400 mt-0.5"><Icon.ShieldCheck className="w-5 h-5" /></div>
                    <div className="flex-1">
                        <h2 className={`text-base font-bold ${headText}`}>Authorise Exception</h2>
                        <p className={`text-xs mt-0.5 ${subText}`}>
                            {employee.name} ({employee.id}) &middot; {employee.role} &middot;{' '}
                            risk {employee.totalRisk}
                            {employee.is_blocked && (
                                <span className="ml-1.5 text-red-400 font-bold">currently frozen</span>
                            )}
                        </p>
                    </div>
                </div>

                {done ? (
                    <div className="px-6 py-6">
                        <div className={`flex items-start gap-2 rounded-lg border px-3 py-3 text-xs ${isDark ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-emerald-50 border-emerald-300 text-emerald-700'}`}>
                            <Icon.Check className="w-4 h-4 shrink-0 mt-px" />
                            <div>
                                <p className="font-bold">Override active</p>
                                <p className="mt-1 leading-5">
                                    {done.exempt_block && 'Automated freezing is suppressed. '}
                                    {done.allowed_actions?.[0] === '*'
                                        ? 'All actions are authorised to deviate from the baseline.'
                                        : `Authorised actions: ${done.allowed_actions.map(formatAction).join(', ')}.`}
                                </p>
                                <p className={`mt-2 ${mutedText}`}>
                                    Closes after{' '}
                                    {done.duration_minutes ? `${done.duration_minutes} minutes` : 'no time limit'}
                                    {done.max_events ? ` or ${done.max_events} authorised events` : ''}
                                    , whichever comes first. Detection continues throughout — only the
                                    enforcement action is suppressed.
                                </p>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="px-6 py-5 space-y-5">
                        {/* What it permits */}
                        <div>
                            <p className={`text-[10px] uppercase tracking-wider font-bold mb-2 ${subText}`}>
                                What this permits
                            </p>
                            <label className={`flex items-start gap-2.5 rounded-lg border px-3 py-2.5 cursor-pointer ${insetBg}`}>
                                <input
                                    type="checkbox"
                                    checked={exemptBlock}
                                    onChange={(e) => setExemptBlock(e.target.checked)}
                                    className="mt-0.5 accent-amber-600"
                                />
                                <span>
                                    <span className={`text-xs font-bold ${headText}`}>
                                        Suppress automated freezing
                                    </span>
                                    <span className={`block text-[11px] mt-0.5 leading-5 ${subText}`}>
                                        Needed to release an account whose accumulated risk is still
                                        above the threshold — otherwise the next action re-freezes it.
                                    </span>
                                </span>
                            </label>
                        </div>

                        {/* Action scope */}
                        <div>
                            <p className={`text-[10px] uppercase tracking-wider font-bold mb-2 ${subText}`}>
                                Actions authorised to deviate from baseline
                            </p>
                            <label className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 cursor-pointer mb-2 ${insetBg}`}>
                                <input
                                    type="checkbox"
                                    checked={scopeAll}
                                    onChange={(e) => setScopeAll(e.target.checked)}
                                    className="accent-amber-600"
                                />
                                <span className={`text-xs ${headText}`}>All actions</span>
                                <span className={`text-[10px] ml-auto ${mutedText}`}>broadest scope</span>
                            </label>
                            {!scopeAll && (
                                <div className="flex flex-wrap gap-1.5">
                                    {AUTHORIZABLE_ACTIONS.map((a) => (
                                        <button
                                            key={a}
                                            onClick={() => toggleAction(a)}
                                            className={`text-[11px] font-medium px-2.5 py-1 rounded-md border transition ${
                                                selected.includes(a)
                                                    ? 'bg-amber-600 border-amber-600 text-white'
                                                    : isDark
                                                        ? 'border-[#2d3340] text-gray-400 hover:border-amber-500/50'
                                                        : 'border-gray-300 text-gray-600 hover:border-amber-400'
                                            }`}
                                        >
                                            {formatAction(a)}
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Bounds */}
                        <div>
                            <p className={`text-[10px] uppercase tracking-wider font-bold mb-2 ${subText}`}>
                                Limits — at least one required
                            </p>
                            <div className="space-y-2">
                                <div className={`rounded-lg border px-3 py-2.5 ${insetBg}`}>
                                    <label className="flex items-center gap-2.5 cursor-pointer">
                                        <input type="checkbox" checked={useTime}
                                               onChange={(e) => setUseTime(e.target.checked)}
                                               className="accent-amber-600" />
                                        <span className={`text-xs font-bold ${headText}`}>
                                            Time limit: {minutes} min
                                        </span>
                                    </label>
                                    {useTime && (
                                        <input type="range" min="5" max={MAX_MINUTES} step="5"
                                               value={minutes}
                                               onChange={(e) => setMinutes(Number(e.target.value))}
                                               className="w-full mt-2 accent-amber-600" />
                                    )}
                                </div>
                                <div className={`rounded-lg border px-3 py-2.5 ${insetBg}`}>
                                    <label className="flex items-center gap-2.5 cursor-pointer">
                                        <input type="checkbox" checked={useEvents}
                                               onChange={(e) => setUseEvents(e.target.checked)}
                                               className="accent-amber-600" />
                                        <span className={`text-xs font-bold ${headText}`}>
                                            Event budget: {events} action{events === 1 ? '' : 's'}
                                        </span>
                                    </label>
                                    {useEvents && (
                                        <input type="range" min="1" max={Math.min(50, MAX_EVENTS)}
                                               value={events}
                                               onChange={(e) => setEvents(Number(e.target.value))}
                                               className="w-full mt-2 accent-amber-600" />
                                    )}
                                </div>
                            </div>
                            {noBound && (
                                <p className="text-[10px] mt-1.5 text-amber-500">
                                    An override must be bounded. Enable a time limit, an event budget,
                                    or both.
                                </p>
                            )}
                        </div>

                        {/* Reason */}
                        <div>
                            <label className={`block text-[10px] uppercase tracking-wider font-bold mb-1.5 ${subText}`}>
                                Reason
                            </label>
                            <textarea
                                value={reason}
                                onChange={(e) => setReason(e.target.value)}
                                rows={2}
                                placeholder="Why is this exception authorised? Reference a change ticket."
                                className={`w-full border rounded-lg px-3 py-2 text-sm outline-none focus:border-amber-500 transition-colors resize-none ${inputBg}`}
                            />
                            <p className={`text-[10px] mt-1 ${reasonShort ? 'text-amber-500' : mutedText}`}>
                                {reason.trim().length}/{MIN_REASON} characters minimum — permanently
                                recorded against your identity.
                            </p>
                        </div>

                        {noScope && (
                            <p className="text-[10px] text-amber-500">
                                This override would permit nothing. Enable freeze suppression or select
                                at least one action.
                            </p>
                        )}

                        {error && (
                            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${isDark ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-red-50 border-red-200 text-red-700'}`}>
                                <Icon.Warning className="w-4 h-4 shrink-0 mt-px" />
                                <span>{error}</span>
                            </div>
                        )}
                    </div>
                )}

                {/* Footer */}
                <div className={`px-6 py-4 border-t flex justify-end gap-2 ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                    <button
                        onClick={onClose}
                        disabled={busy}
                        className={`px-4 py-2 rounded-lg text-sm font-bold transition disabled:opacity-50 ${isDark ? 'text-gray-300 hover:bg-[#2d3340]' : 'text-gray-600 hover:bg-gray-100'}`}
                    >
                        {done ? 'Close' : 'Cancel'}
                    </button>
                    {!done && (
                        <button
                            onClick={submit}
                            disabled={busy || blocked}
                            className="px-4 py-2 rounded-lg text-sm font-bold bg-amber-600 hover:bg-amber-700 text-white transition disabled:opacity-50"
                        >
                            {busy ? 'Granting...' : 'Grant Override'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
