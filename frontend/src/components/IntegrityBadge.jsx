/**
 * IntegrityBadge — per-row inline badge showing document integrity status.
 *
 * Props:
 *   - status: "verified" | "tampered" | "unverified" | undefined
 *   - isDark: theme flag
 *
 * Data minimization: this badge previously revealed the document's SHA3-256
 * integrity hash in a hover tooltip. The hash is no longer sent by the API and
 * is no longer displayed — the verdict is what an operator can act on, and the
 * hash is a stable identifier for a specific audit record. See the policy note
 * in backend/app/routers/quantum.py.
 */
export default function IntegrityBadge({ status, isDark }) {
    const config = {
        verified: {
            label: 'Verified',
            bg: isDark ? 'bg-emerald-500/10' : 'bg-emerald-50',
            border: 'border-emerald-500/30',
            text: isDark ? 'text-emerald-400' : 'text-emerald-600',
            dot: 'bg-emerald-400',
        },
        tampered: {
            label: 'Tampered',
            bg: isDark ? 'bg-red-500/10' : 'bg-red-50',
            border: 'border-red-500/30',
            text: isDark ? 'text-red-400' : 'text-red-600',
            dot: 'bg-red-400',
        },
        unverified: {
            label: 'Unverified',
            bg: isDark ? 'bg-amber-500/10' : 'bg-amber-50',
            border: 'border-amber-500/30',
            text: isDark ? 'text-amber-400' : 'text-amber-600',
            dot: 'bg-amber-400',
        },
    };

    const current = config[status] || config.unverified;

    return (
        <span
            title={`Record integrity: ${current.label}`}
            className={`
                inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold
                border ${current.bg} ${current.border} ${current.text}
                transition-all duration-300 cursor-default
            `}
        >
            <span className={`w-1.5 h-1.5 rounded-full ${current.dot} ${status === 'verified' ? '' : 'animate-pulse'}`}></span>
            <span>{current.label}</span>
        </span>
    );
}
