import { useCallback, useEffect, useState } from 'react';
import { getQuantumStatus, getIntegrityStats, runIntegrityVerification } from '../services/api';
import * as Icon from '../components/Icons';

/**
 * Quantum Security page.
 *
 * Moved off the SOC dashboard onto its own sidebar destination so the dashboard
 * stays focused on employee risk, and so the cryptographic posture can be
 * presented under a strict data-minimization policy.
 *
 * What this page shows: whether each subsystem is Active, and whether the audit
 * trail is intact.
 *
 * What it deliberately does NOT show, matching the backend policy in
 * app/routers/quantum.py: algorithm names or NIST suite identifiers, the
 * session key fingerprint, key strength, operation counters, or per-document
 * integrity hashes. The API no longer returns any of it.
 */

function StatusPill({ active, isDark, children }) {
    const tone = active
        ? (isDark ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-300')
        : (isDark ? 'bg-red-500/10 text-red-400 border-red-500/30'
                  : 'bg-red-50 text-red-700 border-red-300');
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] font-bold ${tone}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
            {children}
        </span>
    );
}

/** Hand-rolled SVG progress ring — no chart dependency. */
function IntegrityRing({ score, isDark }) {
    const radius = 54;
    const stroke = 10;
    const circumference = 2 * Math.PI * radius;
    const clamped = Math.max(0, Math.min(100, score));
    const offset = circumference - (clamped / 100) * circumference;
    const colour = clamped >= 95 ? 'var(--color-risk-low)'
        : clamped >= 70 ? 'var(--color-risk-medium)'
        : 'var(--color-risk-high)';

    return (
        <svg
            width="140"
            height="140"
            viewBox="0 0 140 140"
            role="img"
            aria-label={`Audit trail integrity ${clamped} percent`}
        >
            <circle
                cx="70" cy="70" r={radius}
                fill="none"
                stroke={isDark ? '#2d3340' : '#e5e7eb'}
                strokeWidth={stroke}
            />
            <circle
                cx="70" cy="70" r={radius}
                fill="none"
                stroke={colour}
                strokeWidth={stroke}
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={offset}
                transform="rotate(-90 70 70)"
                style={{ transition: 'stroke-dashoffset 700ms ease' }}
            />
            <text
                x="70" y="66"
                textAnchor="middle"
                fontSize="26"
                fontWeight="700"
                fill={colour}
            >
                {clamped}%
            </text>
            <text
                x="70" y="86"
                textAnchor="middle"
                fontSize="9.5"
                letterSpacing="1.2"
                fill={isDark ? '#9ca3af' : '#6b7280'}
            >
                INTEGRITY
            </text>
        </svg>
    );
}

export default function QuantumPage({ isDark }) {
    const [posture, setPosture] = useState(null);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState(false);
    const [lastScan, setLastScan] = useState(null);
    const [error, setError] = useState(null);

    const load = useCallback(async () => {
        try {
            const [p, s] = await Promise.all([getQuantumStatus(), getIntegrityStats()]);
            setPosture(p);
            setStats(s);
            setError(null);
        } catch {
            setError('Unable to reach the quantum security service.');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        load();
        const interval = setInterval(load, 15000);
        return () => clearInterval(interval);
    }, [load]);

    const handleVerify = async () => {
        setScanning(true);
        try {
            const result = await runIntegrityVerification();
            setLastScan(result);
            await load();
        } catch {
            setError('Verification scan failed.');
        } finally {
            setScanning(false);
        }
    };

    // ── Theme tokens ─────────────────────────────────────────────────
    const pageBg = isDark ? 'bg-[#15171e]' : 'bg-[#f8f9fa]';
    const cardBg = isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200';
    const insetBg = isDark ? 'bg-[#15171e] border-[#2d3340]' : 'bg-gray-50 border-gray-200';
    const headText = isDark ? 'text-white' : 'text-gray-900';
    const subText = isDark ? 'text-gray-400' : 'text-gray-500';
    const mutedText = isDark ? 'text-gray-500' : 'text-gray-400';

    const isActive = posture?.status === 'active';
    const overall = stats?.overall;
    const chainIntact = overall?.chain_intact;

    if (loading) {
        return (
            <div className={`${pageBg} min-h-screen p-8`}>
                <div className={subText}>Loading quantum security posture...</div>
            </div>
        );
    }

    return (
        <div className={`${pageBg} min-h-screen p-8 font-sans transition-colors duration-300`}>
            {/* Header */}
            <div className="flex items-start justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-xl ${isActive ? 'text-emerald-400' : 'text-red-400'} ${isDark ? 'bg-[#1e222b]' : 'bg-white border border-gray-200'}`}>
                        <Icon.ShieldCheck className="w-7 h-7" />
                    </div>
                    <div>
                        <h1 className={`text-xl font-bold tracking-tight ${headText}`}>Quantum Security</h1>
                        <p className={`text-xs mt-0.5 ${subText}`}>
                            Post-quantum cryptographic posture and audit-trail tamper evidence
                        </p>
                    </div>
                </div>
                <StatusPill active={isActive} isDark={isDark}>
                    {isActive ? 'Active' : 'Inactive'}
                </StatusPill>
            </div>

            {error && (
                <div className={`mb-6 flex items-center gap-2 px-4 py-3 rounded-lg border text-sm ${isDark ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-red-50 border-red-200 text-red-700'}`}>
                    <Icon.Warning className="w-4 h-4 shrink-0" />
                    {error}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* ── Subsystem posture ──────────────────────────────── */}
                <div className={`lg:col-span-2 rounded-xl border shadow-sm p-6 ${cardBg}`}>
                    <h2 className={`text-xs font-bold uppercase tracking-widest mb-4 ${subText}`}>
                        Subsystem Posture
                    </h2>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {(posture?.subsystems ?? []).map((sub) => (
                            <div
                                key={sub.name}
                                className={`flex items-center justify-between rounded-lg border px-4 py-3 ${insetBg}`}
                            >
                                <span className={`text-sm font-medium ${headText}`}>{sub.name}</span>
                                <StatusPill active={sub.status === 'Active'} isDark={isDark}>
                                    {sub.status}
                                </StatusPill>
                            </div>
                        ))}
                    </div>

                    {/* The minimization policy, stated in the UI rather than hidden. */}
                    <div className={`mt-5 flex items-start gap-2 rounded-lg border px-4 py-3 ${insetBg}`}>
                        <Icon.Lock className={`w-4 h-4 mt-0.5 shrink-0 ${mutedText}`} />
                        <p className={`text-[11px] leading-5 ${subText}`}>
                            <span className="font-bold">Configuration withheld by policy.</span>{' '}
                            Algorithm identifiers, key fingerprints, key strength and
                            per-record integrity hashes are not exposed through the API or
                            this interface. Operational status is reported; cryptographic
                            configuration is not, because it serves no operator decision and
                            aids reconnaissance.
                        </p>
                    </div>
                </div>

                {/* ── Audit trail integrity ──────────────────────────── */}
                <div className={`rounded-xl border shadow-sm p-6 flex flex-col items-center ${cardBg}`}>
                    <h2 className={`text-xs font-bold uppercase tracking-widest mb-4 self-start ${subText}`}>
                        Audit Trail
                    </h2>
                    <IntegrityRing score={Math.round(overall?.integrity_score ?? 100)} isDark={isDark} />

                    <div className={`mt-4 w-full flex items-center justify-between px-3 py-2 rounded-lg border ${insetBg}`}>
                        <span className={`text-xs font-medium ${subText}`}>Hash chain</span>
                        <StatusPill active={!!chainIntact} isDark={isDark}>
                            {chainIntact ? 'Intact' : 'Broken'}
                        </StatusPill>
                    </div>

                    <button
                        onClick={handleVerify}
                        disabled={scanning}
                        className="mt-4 w-full inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-bold py-2.5 rounded-lg transition"
                    >
                        <Icon.Refresh className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
                        {scanning ? 'Verifying...' : 'Run Verification'}
                    </button>
                </div>
            </div>

            {/* ── Record counts ──────────────────────────────────────── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
                {[
                    { label: 'Sealed Records', value: overall?.total_documents ?? 0, tone: headText },
                    { label: 'Verified', value: overall?.verified ?? 0, tone: 'text-emerald-400' },
                    { label: 'Tampered', value: overall?.tampered ?? 0, tone: 'text-red-400' },
                    { label: 'Unverified', value: overall?.unverified ?? 0, tone: 'text-amber-400' },
                ].map((m) => (
                    <div key={m.label} className={`rounded-xl border shadow-sm px-5 py-4 ${cardBg}`}>
                        <p className={`text-3xl font-bold mb-1 ${m.tone}`}>{m.value}</p>
                        <p className={`text-xs uppercase tracking-wider font-semibold ${mutedText}`}>
                            {m.label}
                        </p>
                    </div>
                ))}
            </div>

            {/* ── Tamper finding: the one place we escalate ───────────── */}
            {overall?.tampered > 0 && (
                <div className={`mt-6 rounded-xl border p-5 ${isDark ? 'bg-red-500/5 border-red-500/40' : 'bg-red-50 border-red-300'}`}>
                    <div className="flex items-start gap-3">
                        <Icon.AlertOctagon className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                        <div>
                            <h3 className={`text-sm font-bold ${isDark ? 'text-red-400' : 'text-red-700'}`}>
                                Tamper evidence detected in {overall.tampered} record
                                {overall.tampered === 1 ? '' : 's'}
                            </h3>
                            <p className={`text-xs mt-1 leading-5 ${subText}`}>
                                Recorded hashes no longer match the stored content, so the audit
                                trail can no longer be relied on as evidence. Treat this as a
                                potential compromise of the database layer rather than an
                                employee-behaviour finding: review database access logs and
                                administrative credentials before acting on any risk score
                                derived from these records.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Per-collection breakdown ───────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                {['activities', 'alerts'].map((name) => {
                    const c = stats?.[name];
                    if (!c) return null;
                    const score = c.integrity_score ?? 100;
                    const barColour = score >= 95 ? 'bg-emerald-400' : score >= 70 ? 'bg-amber-400' : 'bg-red-400';
                    return (
                        <div key={name} className={`rounded-xl border shadow-sm p-5 ${cardBg}`}>
                            <div className="flex justify-between items-center mb-3">
                                <span className={`text-xs font-bold uppercase tracking-wider ${subText}`}>
                                    {name}
                                </span>
                                <span className={`text-xs font-bold ${score >= 95 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                                    {score}%
                                </span>
                            </div>
                            <div className={`w-full h-2 rounded-full ${isDark ? 'bg-[#2d3340]' : 'bg-gray-200'}`}>
                                <div
                                    className={`h-full rounded-full transition-all duration-700 ${barColour}`}
                                    style={{ width: `${score}%` }}
                                />
                            </div>
                            <div className={`flex gap-4 mt-3 text-[11px] ${subText}`}>
                                <span>{c.total} sealed</span>
                                <span className="text-emerald-400">{c.verified} verified</span>
                                {c.tampered > 0 && <span className="text-red-400">{c.tampered} tampered</span>}
                            </div>
                        </div>
                    );
                })}
            </div>

            {lastScan && (
                <p className={`mt-6 text-[11px] ${mutedText}`}>
                    Last verification scan: {new Date(lastScan.scan_timestamp).toLocaleString()}
                </p>
            )}
        </div>
    );
}
