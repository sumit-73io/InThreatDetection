import React, { useState } from 'react';

/**
 * IntegrityBadge — Per-row inline badge showing document integrity status.
 * 
 * Props:
 *   - status: "verified" | "tampered" | "unverified" | undefined
 *   - hash: short hash string for tooltip display
 *   - isDark: theme toggle
 */
export default function IntegrityBadge({ status, hash, isDark }) {
    const [showTooltip, setShowTooltip] = useState(false);

    const config = {
        verified: {
            icon: '✅',
            label: 'Verified',
            bg: isDark ? 'bg-emerald-500/10' : 'bg-emerald-50',
            border: 'border-emerald-500/30',
            text: 'text-emerald-400',
            dot: 'bg-emerald-400',
        },
        tampered: {
            icon: '🚨',
            label: 'Tampered',
            bg: isDark ? 'bg-red-500/10' : 'bg-red-50',
            border: 'border-red-500/30',
            text: 'text-red-400',
            dot: 'bg-red-400',
        },
        unverified: {
            icon: '⚠️',
            label: 'Unverified',
            bg: isDark ? 'bg-amber-500/10' : 'bg-amber-50',
            border: 'border-amber-500/30',
            text: 'text-amber-400',
            dot: 'bg-amber-400',
        }
    };

    const current = config[status] || config.unverified;

    return (
        <div 
            className="relative inline-flex items-center"
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
        >
            <span className={`
                inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold 
                border ${current.bg} ${current.border} ${current.text}
                transition-all duration-300 cursor-default
            `}>
                <span className={`w-1.5 h-1.5 rounded-full ${current.dot} ${status === 'verified' ? '' : 'animate-pulse'}`}></span>
                <span>{current.label}</span>
            </span>

            {/* Tooltip with SHA3 Hash */}
            {showTooltip && hash && (
                <div className={`
                    absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 rounded-lg 
                    text-[10px] font-mono whitespace-nowrap z-50 shadow-xl
                    ${isDark ? 'bg-gray-800 text-gray-300 border border-gray-600' : 'bg-gray-900 text-gray-200'}
                `}
                    style={{ animation: 'fadeInUp 0.15s ease-out' }}
                >
                    <div className="text-[9px] uppercase tracking-wider text-gray-500 mb-0.5">SHA3-256</div>
                    <div className="font-bold">{hash}</div>
                    <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px">
                        <div className={`border-4 border-transparent ${isDark ? 'border-t-gray-800' : 'border-t-gray-900'}`}></div>
                    </div>
                </div>
            )}

            <style>{`
                @keyframes fadeInUp {
                    from { opacity: 0; transform: translate(-50%, 4px); }
                    to { opacity: 1; transform: translate(-50%, 0); }
                }
            `}</style>
        </div>
    );
}
