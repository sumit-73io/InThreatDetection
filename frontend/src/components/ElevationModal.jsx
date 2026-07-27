import { useEffect, useState } from 'react';
import { requestElevation, approveElevation } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import * as Icon from './Icons';

const MIN_JUSTIFICATION = 15;
const MAX_MINUTES = 60;

/**
 * Just-in-time elevation dialog.
 *
 * Opened when an operator tries to use a privileged action without an open PAM
 * window. It requests the elevation, and — for a Super Admin, who holds
 * pam:approve — immediately self-approves as an audited break-glass so a lone
 * responder is never stuck waiting for a second operator who does not exist.
 *
 * Anyone else lands in a PENDING state and is told plainly that a separate
 * approver is required. That is separation of duties working, not a bug.
 *
 * Props:
 *   permissions  string[]  privileged permissions to elevate
 *   reason       string    what the operator is trying to do, prefilled context
 *   isDark       bool
 *   onClose      fn
 *   onElevated   fn        called once a window is actually open
 */
export default function ElevationModal({ permissions, reason, isDark, onClose, onElevated }) {
    const { isSuperAdmin, refresh } = useAuth();
    const [justification, setJustification] = useState(reason || '');
    const [minutes, setMinutes] = useState(15);
    const [busy, setBusy] = useState(false);
    const [status, setStatus] = useState(null); // null | 'pending' | 'granted'
    const [error, setError] = useState(null);

    useEffect(() => {
        const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose(); };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [onClose, busy]);

    const cardBg = isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200';
    const inputBg = isDark
        ? 'bg-[#15171e] border-[#2d3340] text-white placeholder-gray-500'
        : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400';
    const headText = isDark ? 'text-white' : 'text-gray-900';
    const subText = isDark ? 'text-gray-400' : 'text-gray-500';

    const tooShort = justification.trim().length < MIN_JUSTIFICATION;

    const handleSubmit = async () => {
        if (tooShort) return;
        setBusy(true);
        setError(null);
        try {
            const req = await requestElevation(permissions, justification.trim(), minutes);

            if (isSuperAdmin) {
                // Break-glass: approve our own request. Recorded as such server-side.
                await approveElevation(req.request_id);
                await refresh();
                setStatus('granted');
                onElevated?.();
            } else {
                setStatus('pending');
                await refresh();
            }
        } catch (err) {
            setError(err?.response?.data?.detail || 'Elevation request failed.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div
            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[70] p-4"
            onClick={() => !busy && onClose()}
        >
            <div
                className={`w-full max-w-md rounded-xl border shadow-2xl ${cardBg}`}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className={`px-6 py-4 border-b flex items-start gap-3 ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                    <div className="text-amber-400 mt-0.5">
                        <Icon.KeyRound className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                        <h2 className={`text-base font-bold ${headText}`}>Privileged Access Required</h2>
                        <p className={`text-xs mt-0.5 ${subText}`}>
                            This action needs a time-boxed elevation window.
                        </p>
                    </div>
                </div>

                <div className="px-6 py-5">
                    {/* What is being unlocked */}
                    <div className={`mb-4 rounded-lg border px-3 py-2.5 ${isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-gray-50 border-gray-200'}`}>
                        <p className={`text-[10px] uppercase tracking-wider font-bold mb-1.5 ${subText}`}>
                            Permissions
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                            {permissions.map((p) => (
                                <code
                                    key={p}
                                    className={`text-[11px] font-mono px-2 py-0.5 rounded ${isDark ? 'bg-amber-500/10 text-amber-400' : 'bg-amber-50 text-amber-700'}`}
                                >
                                    {p}
                                </code>
                            ))}
                        </div>
                    </div>

                    {status === 'granted' && (
                        <div className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs ${isDark ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-emerald-50 border-emerald-300 text-emerald-700'}`}>
                            <Icon.Check className="w-4 h-4 shrink-0 mt-px" />
                            <span>
                                Elevation granted for {minutes} minute{minutes === 1 ? '' : 's'} as an
                                audited break-glass action. The privileged control is now armed.
                            </span>
                        </div>
                    )}

                    {status === 'pending' && (
                        <div className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs ${isDark ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-amber-50 border-amber-300 text-amber-700'}`}>
                            <Icon.Info className="w-4 h-4 shrink-0 mt-px" />
                            <span>
                                Request submitted and awaiting approval. Self-approval is not
                                permitted for your role, so a separate operator holding
                                <code className="mx-1 font-mono">pam:approve</code> must authorise it.
                            </span>
                        </div>
                    )}

                    {status === null && (
                        <>
                            <label className={`block text-[10px] uppercase tracking-wider font-bold mb-1.5 ${subText}`}>
                                Justification
                            </label>
                            <textarea
                                value={justification}
                                onChange={(e) => setJustification(e.target.value)}
                                rows={3}
                                placeholder="Why is this access needed? Reference an incident or ticket."
                                className={`w-full border rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 transition-colors resize-none ${inputBg}`}
                            />
                            <p className={`text-[10px] mt-1 ${tooShort ? 'text-amber-500' : subText}`}>
                                {justification.trim().length}/{MIN_JUSTIFICATION} characters minimum
                                — recorded permanently in the PAM audit log.
                            </p>

                            <label className={`block text-[10px] uppercase tracking-wider font-bold mt-4 mb-1.5 ${subText}`}>
                                Window: {minutes} minutes
                            </label>
                            <input
                                type="range"
                                min="1"
                                max={MAX_MINUTES}
                                value={minutes}
                                onChange={(e) => setMinutes(Number(e.target.value))}
                                className="w-full accent-blue-600"
                            />
                            <div className={`flex justify-between text-[10px] ${subText}`}>
                                <span>1 min</span>
                                <span>{MAX_MINUTES} min max</span>
                            </div>
                        </>
                    )}

                    {error && (
                        <div className={`mt-4 flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${isDark ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-red-50 border-red-200 text-red-700'}`}>
                            <Icon.Warning className="w-4 h-4 shrink-0 mt-px" />
                            <span>{error}</span>
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className={`px-6 py-4 border-t flex justify-end gap-2 ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                    <button
                        onClick={onClose}
                        disabled={busy}
                        className={`px-4 py-2 rounded-lg text-sm font-bold transition disabled:opacity-50 ${isDark ? 'text-gray-300 hover:bg-[#2d3340]' : 'text-gray-600 hover:bg-gray-100'}`}
                    >
                        {status ? 'Close' : 'Cancel'}
                    </button>
                    {status === null && (
                        <button
                            onClick={handleSubmit}
                            disabled={busy || tooShort}
                            className="px-4 py-2 rounded-lg text-sm font-bold bg-amber-600 hover:bg-amber-700 text-white transition disabled:opacity-50"
                        >
                            {busy
                                ? 'Requesting...'
                                : isSuperAdmin ? 'Elevate (Break Glass)' : 'Submit Request'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
